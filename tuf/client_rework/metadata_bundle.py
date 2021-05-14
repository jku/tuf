# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client bundle-of-metadata

MetadataBundle keeps track of current valid set of metadata for the client,
and handles almost every step of the "Detailed client workflow"
(https://theupdateframework.github.io/specification/latest/#detailed-client-workflow)
in the TUF specification (the remaining steps are download related). The bundle
takes care of persisting valid metadata on disk, loading local metadata from
disk.

Loaded metadata can be accessed via the index access with rolename as key
or, in the case of top-level metadata using the helper properties like
'MetadataBundle.root'

The rules for top-level metadata are
 * Metadata is loadable only if metadata it depends on is loaded
 * Metadata is immutable if any metadata depending on it has been loaded
 * Metadata must be loaded/updated in order:
   root -> timestamp -> snapshot -> targets -> (other delegated targets)
 * For each metadata either local load or the remote update must succeed
 * Caller should try loading local version before updating metadata from remote
   (the exception is root where local data is loaded at MetadataBundle
   initialization: the initialization fails if local data cannot be loaded)

Exceptions are raised if metadata fails to load in any way. The exception
to this is local loads -- only local root metadata needs to be valid:
other local metadata is allowed to be invalid (e.g. no longer signed):
it won't be loaded but there will not be an exception.

Example (with hypothetical download function):

>>> # Load local root
>>> bundle = MetadataBundle("path/to/metadata")
>>>
>>> # update root until no more are available from remote
>>> with download("root", bundle.root.signed.version + 1) as f:
>>>     bundle.update_root(f.read())
>>> # ...
>>> bundle.root_update_finished()
>>>
>>> # load timestamp, then update from remote
>>> bundle.load_local_timestamp()
>>> with download("timestamp") as f:
>>>     bundle.update_timestamp(f.read())
>>>
>>> # load snapshot, update from remote if needed
>>> if not bundle.load_local_snapshot():
>>>     # TODO get version from timestamp
>>>     with download("snapshot", version) as f:
>>>         bundle.update_snapshot(f.read())
>>>
>>> # load local targets, update from remote if needed
>>> if not bundle.load_local_targets():
>>>     # TODO get version from snapshot
>>>     with download("targets", version) as f:
>>>         bundle.update_targets(f.read())
>>>
>>> # load local delegated role, update from remote if needed
>>> if not bundle.load_local_delegated_targets("rolename", "targets"):
>>>     # TODO get version from snapshot
>>>     with download("rolename", version) as f:
>>>         bundle.update_targets(f.read(), "rolename", "targets")


TODO:
 * exceptions are all over the place: the idea is that client could just handle
   a generic RepositoryError that covers every issue that server provided
   metadata could inflict (other errors would be user errors), but this is not
   yet the case
 * usefulness of root_update_finished() can be debated: it could be done
   in the beginning of load_timestamp()...
 * there are some divergences from spec: in general local metadata files are
   not deleted (they just won't succesfully load)
 * a bit of repetition
 * No tests!
 * Naming maybe not final?
 * some metadata interactions might work better in Metadata itself
 * Progress through Specification update process should be documented
   (not sure yet how: maybe a spec_logger that logs specification events?)
"""

import logging
import os
from collections import abc
from datetime import datetime
from typing import Dict, Iterator, Optional

from securesystemslib import hash as sslib_hash
from securesystemslib import keys as sslib_keys

from tuf import exceptions
from tuf.api.metadata import Metadata, Root, Targets
from tuf.api.serialization import SerializationError

# TODO: Either enaable old-style logging in pylintc (issue #1334)
# or change this file to use f-strings for logging
# pylint: disable=logging-too-many-args

# TODO: signed._type really does not work issue #1375:
# pylint: disable=protected-access

logger = logging.getLogger(__name__)

# This is a placeholder until ...
# TODO issue 1306: implement this in Metadata API
def verify_with_threshold(
    delegator: Metadata, role_name: str, unverified: Metadata
) -> bool:
    """Verify 'unverified' with keys and threshold defined in delegator"""
    role = None
    keys = {}
    if isinstance(delegator.signed, Root):
        keys = delegator.signed.keys
        role = delegator.signed.roles.get(role_name)
    elif isinstance(delegator.signed, Targets):
        if delegator.signed.delegations:
            keys = delegator.signed.delegations.keys
            # role names are unique: first match is enough
            roles = delegator.signed.delegations.roles
            role = next((r for r in roles if r.name == role_name), None)
    else:
        raise ValueError("Call is valid only on delegator metadata")

    if role is None:
        raise exceptions.UnknownRoleError

    # verify that delegate is signed by correct threshold of unique keys
    unique_keys = set()
    for keyid in role.keyids:
        key_dict = keys[keyid].to_dict()
        key, dummy = sslib_keys.format_metadata_to_key(key_dict)

        try:
            if unverified.verify(key):
                unique_keys.add(key["keyval"]["public"])
        except Exception as e:  # pylint: disable=broad-except
            # TODO specify the Exceptions (see issue #1351)
            logger.info("verify failed: %s", e)

    return len(unique_keys) >= role.threshold


class MetadataBundle(abc.Mapping):
    """Internal class to keep track of valid metadata in Updater

    MetadataBundle ensures that metadata is valid. It provides easy ways to
    update the metadata with the caller making decisions on what is updated.
    """

    def __init__(self, repository_path: str):
        """Initialize by loading root metadata from disk"""
        self._path = repository_path
        self._bundle = {}  # type: Dict[str: Metadata]
        self.reference_time = None

        # Load and validate the local root metadata
        # Valid root metadata is required
        logger.debug("Loading local root")
        try:
            with open(os.path.join(self._path, "root.json"), "rb") as f:
                self._load_intermediate_root(f.read())
        except (OSError, exceptions.RepositoryError) as e:
            raise exceptions.RepositoryError(
                "Failed to load local root metadata"
            ) from e

    # Implement Mapping
    def __getitem__(self, key: str) -> Metadata:
        return self._bundle[key]

    def __len__(self) -> int:
        return len(self._bundle)

    def __iter__(self) -> Iterator[Metadata]:
        return iter(self._bundle)

    # Helper properties for top level metadata
    @property
    def root(self) -> Optional[Metadata]:
        return self._bundle.get("root")

    @property
    def timestamp(self) -> Optional[Metadata]:
        return self._bundle.get("timestamp")

    @property
    def snapshot(self) -> Optional[Metadata]:
        return self._bundle.get("snapshot")

    @property
    def targets(self) -> Optional[Metadata]:
        return self._bundle.get("targets")

    # Public methods
    def update_root(self, data: bytes):
        """Update root metadata with data from remote repository."""
        logger.debug("Updating root")

        self._load_intermediate_root(data)
        self.root.to_file(os.path.join(self._path, "root.json"))

    def root_update_finished(self):
        """Mark root metadata as final."""
        if self.reference_time is not None:
            raise ValueError("Root update is already finished")

        # Store our reference "now", verify root expiry
        self.reference_time = datetime.utcnow()
        if self.root.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("New root.json is expired")

        logger.debug("Verified final root.json")

    def load_local_timestamp(self) -> bool:
        """Load cached timestamp metadata from local storage.

        Returns True if timestamp was succesfully loaded"""
        logger.debug("Loading local timestamp")

        try:
            with open(os.path.join(self._path, "timestamp.json"), "rb") as f:
                self._load_timestamp(f.read())
            return True
        except (OSError, exceptions.RepositoryError) as e:
            logger.debug("Failed to load local timestamp: %s", e)
            return False

    def update_timestamp(self, data: bytes):
        """Update timestamp metadata with data from remote repository."""
        logger.debug("Updating timestamp")

        self._load_timestamp(data)
        self.timestamp.to_file(os.path.join(self._path, "timestamp.json"))

    def load_local_snapshot(self) -> bool:
        """Load cached snapshot metadata from local storage.

        Returns True if snapshot was succesfully loaded"""
        logger.debug("Loading local snapshot")

        try:
            with open(os.path.join(self._path, "snapshot.json"), "rb") as f:
                self._load_snapshot(f.read())
            return True
        except (OSError, exceptions.RepositoryError) as e:
            logger.debug("Failed to load local snapshot: %s", e)
            return False

    def update_snapshot(self, data: bytes):
        """Update snapshot metadata with data from remote repository."""
        logger.debug("Updating snapshot")

        self._load_snapshot(data)
        self.snapshot.to_file(os.path.join(self._path, "snapshot.json"))

    def load_local_targets(self) -> bool:
        """Load cached targets metadata from local storage.

        Returns True if targets was succesfully loaded"""
        return self.load_local_delegated_targets("targets", "root")

    def update_targets(self, data: bytes):
        """Update targets metadata with data from remote repository."""
        self.update_delegated_targets(data, "targets", "root")

    def load_local_delegated_targets(
        self, role_name: str, delegator_name: str
    ) -> bool:
        """Load cached metadata for 'role_name' from local storage.

        Metadata for 'delegator_name' must be loaded already.

        Returns True if metadata was succesfully loaded"""
        if self.get(role_name):
            logger.debug("Local %s already loaded", role_name)
            return True

        logger.debug("Loading local %s", role_name)

        try:
            with open(os.path.join(self._path, f"{role_name}.json"), "rb") as f:
                self._load_delegated_targets(
                    f.read(), role_name, delegator_name
                )
            return True
        except (OSError, exceptions.RepositoryError) as e:
            logger.debug("Failed to load local %s: %s", role_name, e)
            return False

    def update_delegated_targets(
        self, data: bytes, role_name: str, delegator_name: str = None
    ):
        """Update 'rolename' metadata with data from remote repository.

        Metadata for 'delegator_name' must be loaded already."""
        logger.debug("Updating %s", role_name)

        self._load_delegated_targets(data, role_name, delegator_name)
        self[role_name].to_file(os.path.join(self._path, f"{role_name}.json"))

    def _load_intermediate_root(self, data: bytes):
        """Verifies and loads 'data' as new root metadata.

        Note that an expired intermediate root is considered valid: expiry is
        only checked for the final root in root_update_finished()."""
        if self.reference_time is not None:
            raise ValueError("Cannot update root after root update is finished")

        try:
            new_root = Metadata.from_bytes(data)
        except SerializationError as e:
            raise exceptions.RepositoryError("Failed to load root") from e

        if new_root.signed._type != "root":
            raise exceptions.RepositoryError(
                f"Expected 'root', got '{new_root.signed._type}'"
            )

        if self.root is not None:
            if not verify_with_threshold(self.root, "root", new_root):
                raise exceptions.UnsignedMetadataError(
                    "New root is not signed by root", new_root.signed
                )

            if new_root.signed.version != self.root.signed.version + 1:
                raise exceptions.ReplayedMetadataError(
                    "root", new_root.signed.version, self.root.signed.version
                )

        if not verify_with_threshold(new_root, "root", new_root):
            raise exceptions.UnsignedMetadataError(
                "New root is not signed by itself", new_root.signed
            )

        self._bundle["root"] = new_root
        logger.debug("Loaded root")

    def _load_timestamp(self, data: bytes):
        """Verifies and loads 'data' as new timestamp metadata."""
        if self.reference_time is None:
            # root_update_finished() not called
            raise ValueError("Cannot update timestamp before root")
        if self.snapshot is not None:
            raise ValueError("Cannot update timestamp after snapshot")

        try:
            new_timestamp = Metadata.from_bytes(data)
        except SerializationError as e:
            raise exceptions.RepositoryError("Failed to load timestamp") from e

        if new_timestamp.signed._type != "timestamp":
            raise exceptions.RepositoryError(
                f"Expected 'timestamp', got '{new_timestamp.signed._type}'"
            )

        if not verify_with_threshold(self.root, "timestamp", new_timestamp):
            raise exceptions.UnsignedMetadataError(
                "New timestamp is not signed by root", new_timestamp.signed
            )

        if self.timestamp is not None:
            # Prevent rolling back timestamp version
            if new_timestamp.signed.version < self.timestamp.signed.version:
                raise exceptions.ReplayedMetadataError(
                    "timestamp",
                    new_timestamp.signed.version,
                    self.timestamp.signed.version,
                )
            # Prevent rolling back snapshot version
            if (
                new_timestamp.signed.meta["snapshot.json"]["version"]
                < self.timestamp.signed.meta["snapshot.json"]["version"]
            ):
                # TODO not sure about the correct exception here
                raise exceptions.ReplayedMetadataError(
                    "snapshot",
                    new_timestamp.signed.meta["snapshot.json"]["version"],
                    self.timestamp.signed.meta["snapshot.json"]["version"],
                )

        if new_timestamp.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("New timestamp is expired")

        self._bundle["timestamp"] = new_timestamp
        logger.debug("Loaded timestamp")

    # TODO: remove pylint disable once the hash verification is in metadata.py
    def _load_snapshot(self, data: bytes):  # pylint: disable=too-many-branches
        """Verifies and loads 'data' as new snapshot metadata."""

        if self.timestamp is None:
            raise ValueError("Cannot update snapshot before timestamp")
        if self.targets is not None:
            raise ValueError("Cannot update snapshot after targets")

        meta = self.timestamp.signed.meta["snapshot.json"]

        # Verify against the hashes in timestamp, if any
        hashes = meta.get("hashes") or {}
        for algo, stored_hash in hashes.items():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            observed_hash = digest_object.hexdigest()
            if observed_hash != stored_hash:
                raise exceptions.BadHashError(stored_hash, observed_hash)

        try:
            new_snapshot = Metadata.from_bytes(data)
        except SerializationError as e:
            raise exceptions.RepositoryError("Failed to load snapshot") from e

        if new_snapshot.signed._type != "snapshot":
            raise exceptions.RepositoryError(
                f"Expected 'snapshot', got '{new_snapshot.signed._type}'"
            )

        if not verify_with_threshold(self.root, "snapshot", new_snapshot):
            raise exceptions.UnsignedMetadataError(
                "New snapshot is not signed by root", new_snapshot.signed
            )

        if (
            new_snapshot.signed.version
            != self.timestamp.signed.meta["snapshot.json"]["version"]
        ):
            raise exceptions.BadVersionNumberError(
                f"Expected snapshot version"
                f"{self.timestamp.signed.meta['snapshot.json']['version']},"
                f"got {new_snapshot.signed.version}"
            )

        if self.snapshot:
            for filename, fileinfo in self.snapshot.signed.meta.items():
                new_fileinfo = new_snapshot.signed.meta.get(filename)

                # Prevent removal of any metadata in meta
                if new_fileinfo is None:
                    raise exceptions.RepositoryError(
                        f"New snapshot is missing info for '{filename}'"
                    )

                # Prevent rollback of any metadata versions
                if new_fileinfo["version"] < fileinfo["version"]:
                    raise exceptions.BadVersionNumberError(
                        f"Expected {filename} version"
                        f"{new_fileinfo['version']}, got {fileinfo['version']}"
                    )

        if new_snapshot.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("New snapshot is expired")

        self._bundle["snapshot"] = new_snapshot
        logger.debug("Loaded snapshot")

    def _load_delegated_targets(
        self, data: bytes, role_name: str, delegator_name: str
    ):
        """Verifies and loads 'data' as new metadata for target 'role_name'.

        Raises if verification fails
        """
        if self.snapshot is None:
            raise ValueError("Cannot load targets before snapshot")

        delegator = self.get(delegator_name)
        if delegator is None:
            raise ValueError("Cannot load targets before delegator")

        # Verify against the hashes in snapshot, if any
        meta = self.snapshot.signed.meta.get(f"{role_name}.json")
        if meta is None:
            raise exceptions.RepositoryError(
                f"Snapshot does not contain information for '{role_name}'"
            )

        hashes = meta.get("hashes") or {}
        for algo, stored_hash in hashes.items():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            observed_hash = digest_object.hexdigest()
            if observed_hash != stored_hash:
                raise exceptions.BadHashError(stored_hash, observed_hash)

        try:
            new_delegate = Metadata.from_bytes(data)
        except SerializationError as e:
            raise exceptions.RepositoryError("Failed to load snapshot") from e

        if new_delegate.signed._type != "targets":
            raise exceptions.RepositoryError(
                f"Expected 'targets', got '{new_delegate.signed._type}'"
            )

        if not verify_with_threshold(delegator, role_name, new_delegate):
            raise exceptions.UnsignedMetadataError(
                f"New {role_name} is not signed by {delegator_name}",
                new_delegate,
            )

        if new_delegate.signed.version != meta["version"]:
            raise exceptions.BadVersionNumberError(
                f"Expected {role_name} version"
                f"{meta['version']}, got {new_delegate.signed.version}"
            )

        if new_delegate.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError(f"New {role_name} is expired")

        self._bundle[role_name] = new_delegate
        logger.debug("Loaded %s delegated by %s", role_name, delegator_name)
