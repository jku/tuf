#!/usr/bin/env python

# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
""" Unit tests for api/metadata.py

"""

import json
import sys
import logging
import os
import shutil
import tempfile
import unittest
import copy

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

from tests import utils

import tuf.exceptions
from tuf.api.metadata import (
    Metadata,
    Snapshot,
    Timestamp,
    Targets
)

from tuf.api.serialization import (
    DeserializationError
)

from tuf.api.serialization.json import (
    JSONSerializer,
    JSONDeserializer,
    CanonicalJSONSerializer
)

from securesystemslib.interface import (
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file
)

from securesystemslib.keys import (
    format_keyval_to_metadata
)

from securesystemslib.signer import (
    SSlibSigner
)

logger = logging.getLogger(__name__)


class TestMetadata(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a temporary directory to store the repository, metadata, and
        # target files.  'temporary_directory' must be deleted in
        # TearDownClass() so that temporary files are always removed, even when
        # exceptions occur.
        cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

        test_repo_data = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), 'repository_data')

        cls.repo_dir = os.path.join(cls.temporary_directory, 'repository')
        shutil.copytree(
                os.path.join(test_repo_data, 'repository'), cls.repo_dir)

        cls.keystore_dir = os.path.join(cls.temporary_directory, 'keystore')
        shutil.copytree(
                os.path.join(test_repo_data, 'keystore'), cls.keystore_dir)

        # Load keys into memory
        cls.keystore = {}
        for role in ['delegation', 'snapshot', 'targets', 'timestamp']:
            cls.keystore[role] = {
                'private': import_ed25519_privatekey_from_file(
                        os.path.join(cls.keystore_dir, role + '_key'),
                        password="password"),
                'public': import_ed25519_publickey_from_file(
                        os.path.join(cls.keystore_dir, role + '_key.pub'))
            }


    @classmethod
    def tearDownClass(cls):
        # Remove the temporary repository directory, which should contain all
        # the metadata, targets, and key files generated for the test cases.
        shutil.rmtree(cls.temporary_directory)


    def test_generic_read(self):
        for metadata, inner_metadata_cls in [
                ('snapshot', Snapshot),
                ('timestamp', Timestamp),
                ('targets', Targets)]:

            # Load JSON-formatted metdata of each supported type from file
            # and from out-of-band read JSON string
            path = os.path.join(self.repo_dir, 'metadata', metadata + '.json')
            metadata_obj = Metadata.from_file(path)
            with open(path, 'rb') as f:
                metadata_str = f.read()
            metadata_obj2 = JSONDeserializer().deserialize(metadata_str)

            # Assert that both methods instantiate the right inner class for
            # each metadata type and ...
            self.assertTrue(
                    isinstance(metadata_obj.signed, inner_metadata_cls))
            self.assertTrue(
                    isinstance(metadata_obj2.signed, inner_metadata_cls))

            # ... and return the same object (compared by dict representation)
            self.assertDictEqual(
                    metadata_obj.to_dict(), metadata_obj2.to_dict())


        # Assert that it chokes correctly on an unknown metadata type
        bad_metadata_path = 'bad-metadata.json'
        bad_metadata = {'signed': {'_type': 'bad-metadata'}}
        with open(bad_metadata_path, 'wb') as f:
            f.write(json.dumps(bad_metadata).encode('utf-8'))

        with self.assertRaises(DeserializationError):
            Metadata.from_file(bad_metadata_path)

        os.remove(bad_metadata_path)


    def test_compact_json(self):
        path = os.path.join(self.repo_dir, 'metadata', 'targets.json')
        metadata_obj = Metadata.from_file(path)
        self.assertTrue(
                len(JSONSerializer(compact=True).serialize(metadata_obj)) <
                len(JSONSerializer().serialize(metadata_obj)))


    def test_read_write_read_compare(self):
        for metadata in ['snapshot', 'timestamp', 'targets']:
            path = os.path.join(self.repo_dir, 'metadata', metadata + '.json')
            metadata_obj = Metadata.from_file(path)

            path_2 = path + '.tmp'
            metadata_obj.to_file(path_2)
            metadata_obj_2 = Metadata.from_file(path_2)

            self.assertDictEqual(
                    metadata_obj.to_dict(),
                    metadata_obj_2.to_dict())

            os.remove(path_2)


    def test_sign_verify(self):
        # Load sample metadata (targets) and assert ...
        path = os.path.join(self.repo_dir, 'metadata', 'targets.json')
        metadata_obj = Metadata.from_file(path)

        # ... it has a single existing signature,
        self.assertTrue(len(metadata_obj.signatures) == 1)
        # ... which is valid for the correct key.
        self.assertTrue(metadata_obj.verify(
                self.keystore['targets']['public']))

        sslib_signer = SSlibSigner(self.keystore['snapshot']['private'])
        # Append a new signature with the unrelated key and assert that ...
        metadata_obj.sign(sslib_signer, append=True)
        # ... there are now two signatures, and
        self.assertTrue(len(metadata_obj.signatures) == 2)
        # ... both are valid for the corresponding keys.
        self.assertTrue(metadata_obj.verify(
                self.keystore['targets']['public']))
        self.assertTrue(metadata_obj.verify(
                self.keystore['snapshot']['public']))

        sslib_signer.key_dict = self.keystore['timestamp']['private']
        # Create and assign (don't append) a new signature and assert that ...
        metadata_obj.sign(sslib_signer, append=False)
        # ... there now is only one signature,
        self.assertTrue(len(metadata_obj.signatures) == 1)
        # ... valid for that key.
        self.assertTrue(metadata_obj.verify(
                self.keystore['timestamp']['public']))

        # Assert exception if there are more than one signatures for a key
        metadata_obj.sign(sslib_signer, append=True)
        with self.assertRaises(tuf.exceptions.Error) as ctx:
            metadata_obj.verify(self.keystore['timestamp']['public'])
        self.assertTrue(
                '2 signatures for key' in str(ctx.exception),
                str(ctx.exception))

        # Assert exception if there is no signature for a key
        with self.assertRaises(tuf.exceptions.Error) as ctx:
            metadata_obj.verify(self.keystore['targets']['public'])
        self.assertTrue(
                'no signature for' in str(ctx.exception),
                str(ctx.exception))


    def test_metadata_base(self):
        # Use of Snapshot is arbitrary, we're just testing the base class features
        # with real data
        snapshot_path = os.path.join(
                self.repo_dir, 'metadata', 'snapshot.json')
        md = Metadata.from_file(snapshot_path)

        self.assertEqual(md.signed.version, 1)
        md.signed.bump_version()
        self.assertEqual(md.signed.version, 2)
        self.assertEqual(md.signed.expires, datetime(2030, 1, 1, 0, 0))
        md.signed.bump_expiration()
        self.assertEqual(md.signed.expires, datetime(2030, 1, 2, 0, 0))
        md.signed.bump_expiration(timedelta(days=365))
        self.assertEqual(md.signed.expires, datetime(2031, 1, 2, 0, 0))


    def test_metadata_snapshot(self):
        snapshot_path = os.path.join(
                self.repo_dir, 'metadata', 'snapshot.json')
        snapshot = Metadata.from_file(snapshot_path)

        # Create a dict representing what we expect the updated data to be
        fileinfo = copy.deepcopy(snapshot.signed.meta)
        hashes = {'sha256': 'c2986576f5fdfd43944e2b19e775453b96748ec4fe2638a6d2f32f1310967095'}
        fileinfo['role1.json']['version'] = 2
        fileinfo['role1.json']['hashes'] = hashes
        fileinfo['role1.json']['length'] = 123


        self.assertNotEqual(snapshot.signed.meta, fileinfo)
        snapshot.signed.update('role1', 2, 123, hashes)
        self.assertEqual(snapshot.signed.meta, fileinfo)


    def test_metadata_timestamp(self):
        timestamp_path = os.path.join(
                self.repo_dir, 'metadata', 'timestamp.json')
        timestamp = Metadata.from_file(timestamp_path)

        self.assertEqual(timestamp.signed.version, 1)
        timestamp.signed.bump_version()
        self.assertEqual(timestamp.signed.version, 2)

        self.assertEqual(timestamp.signed.expires, datetime(2030, 1, 1, 0, 0))
        timestamp.signed.bump_expiration()
        self.assertEqual(timestamp.signed.expires, datetime(2030, 1, 2, 0, 0))
        timestamp.signed.bump_expiration(timedelta(days=365))
        self.assertEqual(timestamp.signed.expires, datetime(2031, 1, 2, 0, 0))

        # Test whether dateutil.relativedelta works, this provides a much
        # easier to use interface for callers
        delta = relativedelta(days=1)
        timestamp.signed.bump_expiration(delta)
        self.assertEqual(timestamp.signed.expires, datetime(2031, 1, 3, 0, 0))
        delta = relativedelta(years=5)
        timestamp.signed.bump_expiration(delta)
        self.assertEqual(timestamp.signed.expires, datetime(2036, 1, 3, 0, 0))

        hashes = {'sha256': '0ae9664468150a9aa1e7f11feecb32341658eb84292851367fea2da88e8a58dc'}
        fileinfo = copy.deepcopy(timestamp.signed.meta['snapshot.json'])
        fileinfo['hashes'] = hashes
        fileinfo['version'] = 2
        fileinfo['length'] = 520

        self.assertNotEqual(timestamp.signed.meta['snapshot.json'], fileinfo)
        timestamp.signed.update(2, 520, hashes)
        self.assertEqual(timestamp.signed.meta['snapshot.json'], fileinfo)


    def test_metadata_root(self):
        root_path = os.path.join(
                self.repo_dir, 'metadata', 'root.json')
        root = Metadata.from_file(root_path)

        # Add a second key to root role
        root_key2 =  import_ed25519_publickey_from_file(
                    os.path.join(self.keystore_dir, 'root_key2.pub'))

        keyid = root_key2['keyid']
        key_metadata = format_keyval_to_metadata(
            root_key2['keytype'], root_key2['scheme'], root_key2['keyval'])

        # Assert that root does not contain the new key
        self.assertNotIn(keyid, root.signed.roles['root']['keyids'])
        self.assertNotIn(keyid, root.signed.keys)

        # Add new root key
        root.signed.add_key('root', keyid, key_metadata)

        # Assert that key is added
        self.assertIn(keyid, root.signed.roles['root']['keyids'])
        self.assertIn(keyid, root.signed.keys)

        # Remove the key
        root.signed.remove_key('root', keyid)

        # Assert that root does not contain the new key anymore
        self.assertNotIn(keyid, root.signed.roles['root']['keyids'])
        self.assertNotIn(keyid, root.signed.keys)



    def test_metadata_targets(self):
        targets_path = os.path.join(
                self.repo_dir, 'metadata', 'targets.json')
        targets = Metadata.from_file(targets_path)

        # Create a fileinfo dict representing what we expect the updated data to be
        filename = 'file2.txt'
        hashes = {
            "sha256": "141f740f53781d1ca54b8a50af22cbf74e44c21a998fa2a8a05aaac2c002886b",
            "sha512": "ef5beafa16041bcdd2937140afebd485296cd54f7348ecd5a4d035c09759608de467a7ac0eb58753d0242df873c305e8bffad2454aa48f44480f15efae1cacd0"
        },

        fileinfo = {
            'hashes': hashes,
            'length': 28
        }

        # Assert that data is not aleady equal
        self.assertNotEqual(targets.signed.targets[filename], fileinfo)
        # Update an already existing fileinfo
        targets.signed.update(filename, fileinfo)
        # Verify that data is updated
        self.assertEqual(targets.signed.targets[filename], fileinfo)


    def test_metadata_root_delegator(self):
        root_path = os.path.join(self.repo_dir, 'metadata', 'root.json')
        root = Metadata.from_file(root_path)
        snapshot_path = os.path.join(
                self.repo_dir, 'metadata', 'snapshot.json')
        snapshot = Metadata.from_file(snapshot_path)

        verified = root.verify_delegate_with_threshold('root', root)
        self.assertTrue(verified)
        verified = root.verify_delegate_with_threshold('snapshot', snapshot)
        self.assertTrue(verified)

        # only root and targets can verify delegates
        with self.assertRaises(ValueError):
            snapshot.verify_delegate_with_threshold('snapshot', snapshot)
        # cannot verify with non-existing role
        with self.assertRaises(tuf.exceptions.UnknownRoleError):
            root.verify_delegate_with_threshold('foo', snapshot)

        # modified delegate content should fail verification
        expires = snapshot.signed.expires
        snapshot.signed.bump_expiration()
        verified = root.verify_delegate_with_threshold('snapshot', snapshot)
        self.assertFalse(verified)
        snapshot.signed.expires = expires

        # different delegation keys should fail verification
        verified = root.verify_delegate_with_threshold('timestamp', snapshot)
        self.assertFalse(verified)

        # Higher threshold should fail verification
        root.signed.roles['snapshot']['threshold'] += 1
        verified = root.verify_delegate_with_threshold('snapshot', snapshot)
        self.assertFalse(verified)

        # TODO test higher thresholds

    def test_metadata_targets_delegator(self):
        targets_path = os.path.join(
                self.repo_dir, 'metadata', 'targets.json')
        targets = Metadata.from_file(targets_path)
        delegate_path = os.path.join(
                self.repo_dir, 'metadata', 'role1.json')
        delegate = Metadata.from_file(delegate_path)

        verified = targets.verify_delegate_with_threshold('role1', delegate)
        self.assertTrue(verified)

        with self.assertRaises(tuf.exceptions.UnknownRoleError):
            targets.verify_delegate_with_threshold('foo', delegate)

        # modified delegate content should fail verification
        expires = delegate.signed.expires
        delegate.signed.bump_expiration()
        verified = targets.verify_delegate_with_threshold('role1', delegate)
        self.assertFalse(verified)
        delegate.signed.expires = expires

        # Higher threshold should fail verification
        targets.signed.delegations["roles"][0]['threshold'] += 1
        verified = targets.verify_delegate_with_threshold('role1', delegate)
        self.assertFalse(verified)


# Run unit test.
if __name__ == '__main__':
    utils.configure_test_logging(sys.argv)
    unittest.main()
