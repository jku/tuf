# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

""" Unit tests testing tuf/api/metadata.py classes
serialization and deserialization.

"""

import json
import sys
import logging
import os
import shutil
import tempfile
import unittest
import copy

from typing import Any, Dict, List

from tests import utils

from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    Timestamp,
    Targets,
    Key,
    Role,
    MetaFile,
    TargetFile,
    Delegations,
    DelegatedRole,
)

logger = logging.getLogger(__name__)

def run_sub_tests_with_dataset(dataset):
    def real_decorator(function):
        def wrapper(test):
            for case, data in dataset.items():
                with test.subTest(case=case):
                    function(test, data)
        return wrapper
    return real_decorator

def copy_recur(input_dict: Dict[str, Any], ignore_attr_list: List[str]):
    """Recursivly make a deep copy of the input_dict ignoring the attributes in
    ignore_attr_list."""
    res_dict = {}
    # Iterate over all items in the dict.
    # If an item is a dict, recursivly call copy_recur to iterate its items,
    # otherwise save it in res_dict.
    for valname, value in input_dict.items():
        if valname in ignore_attr_list:
            continue
        if isinstance(value, dict):
            res_dict[valname] = copy_recur(value, ignore_attr_list)
        else:
            res_dict[valname] = value

    return res_dict


def _get_metadata_dict(tmp_directory, metadata):
    metadata_path = os.path.join(tmp_directory, "metadata", metadata + ".json")
    with open(metadata_path) as f:
        data = json.loads(f.read())
    return data["signed"]


class TestSerialization(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a temporary directory to store the repository, metadata, and
        # target files. 'temporary_directory' must be deleted in
        # tearDownClass() so that temporary files are always removed, even when
        # exceptions occur.
        cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

        test_repo_data = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), 'repository_data')

        cls.repo_dir = os.path.join(cls.temporary_directory, 'repository')
        shutil.copytree(
                os.path.join(test_repo_data, 'repository'), cls.repo_dir)

        # Preparare root valid cases
        root = _get_metadata_dict(cls.repo_dir, "root")
        cls.valid_root_cases = {
            "all_attributes": root,
            "no_consistent_snapshot": copy_recur(root, ["consistent_snapshot"])
        }
        # Preparare timestamp valid cases
        cls.valid_timestamp_cases = {
            "all_attributes": _get_metadata_dict(cls.repo_dir, "timestamp")
        }
        # Preparare snapshot valid cases
        cls.valid_snapshot_cases = {
            "all_attributes": _get_metadata_dict(cls.repo_dir, "snapshot")
        }
        # Preparare targets valid cases
        targets =  _get_metadata_dict(cls.repo_dir, "targets")
        empty_targets = copy.deepcopy(targets)
        empty_targets["targets"] = {}
        cls.valid_targets_cases = {
            "all_attributes": targets,
            "empty_targets": empty_targets,
            "no_delegations": copy_recur(targets, ["delegations"])
        }

    @classmethod
    def tearDownClass(cls):
        # Remove the temporary repository directory, which should contain all
        # the metadata, targets, and key files generated for the test cases.
        shutil.rmtree(cls.temporary_directory)


    def test_key_serialization(self):
        keys = self.valid_root_cases["all_attributes"]["keys"]
        valid_key_cases = {
            "all_attributes": keys
        }
        for case, data in valid_key_cases.items():
            with self.subTest(case=case):
                for key_dict in data.values():
                    key_obj = Key.from_dict(copy.deepcopy(key_dict))
                    self.assertDictEqual(key_obj.to_dict(), key_dict)

                    # Test creating a Key instance with wrong keyval format.
                    tmp_dict = copy.deepcopy(key_dict)
                    tmp_dict["keyval"] = {}
                    with self.assertRaises(ValueError):
                        Key.from_dict(tmp_dict)


    def test_role_serialization(self):
        roles = self.valid_root_cases["all_attributes"]["roles"]
        valid_role_cases = {
            "all_attributes": roles,
        }
        for case, data in valid_role_cases.items():
            with self.subTest(case=case):
                for role_dict in data.values():
                    role_obj = Role.from_dict(copy.deepcopy(role_dict))
                    self.assertDictEqual(role_obj.to_dict(), role_dict)

                    # Test creating a Role instance with keyid dublicates.
                    # for keyid in role_dict["keyids"]:
                    test_dict = copy.deepcopy(role_dict)
                    test_dict["keyids"].append(test_dict["keyids"][0])
                    with self.assertRaises(ValueError):
                        Role.from_dict(test_dict)


    def test_root_serialization(self):
        for case, data in self.valid_root_cases.items():
            with self.subTest(case=case):
                root = Root.from_dict(copy.deepcopy(data))
                self.assertDictEqual(root.to_dict(), data)

    def test_metafile_serialization(self):
        meta = self.valid_timestamp_cases["all_attributes"]["meta"]
        metafiles = meta["snapshot.json"]
        valid_meta_file_cases = {
            "all_attributes": metafiles,
            "no_length": copy_recur(metafiles, ["length"]),
            "no_hashes": copy_recur(metafiles, ["hashes"])
        }
        for case, data in valid_meta_file_cases.items():
            with self.subTest(case=case):
                metafile = MetaFile.from_dict(copy.deepcopy(data))
                self.assertDictEqual(metafile.to_dict(), data)

    def test_timestamp_serialization(self):
        for case, data in self.valid_timestamp_cases.items():
            with self.subTest(case=case):
                timestamp = Timestamp.from_dict(copy.deepcopy(data))
                self.assertDictEqual(timestamp.to_dict(), data)

    def test_snapshot_serialization(self):
        for case, data in self.valid_snapshot_cases.items():
            with self.subTest(case=case):
                snapshot = Snapshot.from_dict(copy.deepcopy(data))
                self.assertDictEqual(snapshot.to_dict(), data)

    def test_delegation_serialization(self):
        delegations = self.valid_targets_cases["all_attributes"]["delegations"]
        valid_delegation_cases = {
            "all_attributes": delegations
        }
        for case, data in valid_delegation_cases.items():
            with self.subTest(case=case):
                delegations = Delegations.from_dict(copy.deepcopy(data))
                self.assertDictEqual(delegations.to_dict(), data)


    def _setup_delegated_role(
        self,
        delegations: Dict[str, Any],
        ignore_attr: List[str]
    ):
        delegated_roles = delegations["roles"]
        # Delegated roles is a list of dictionaries.
        # That's why when setting up a new valid case we have to iterate
        # through the different roles in the list.
        delegated_roles_res = []
        for role in delegated_roles:
            delegated_roles_res.append(copy_recur(role, ignore_attr))
        return delegated_roles_res


    def test_delegated_role_serialization(self):
        delegations = self.valid_targets_cases["all_attributes"]["delegations"]
        delegated_roles = delegations["roles"]
        delegated_roles_no_paths = self._setup_delegated_role(
            delegations, "paths"
        )
        delegated_roles_no_path_hash_prefixes = self._setup_delegated_role(
            delegations, ["path_hash_prefixes"]
        )

        for role in delegated_roles_no_path_hash_prefixes:
            role["paths"] = "foo"
        delegated_no_optional_attr = self._setup_delegated_role(
            delegations, ["paths", "path_hash_prefixes"]
        )
        valid_delegatedrole_cases = {
            "all_attributes": delegated_roles,
            "no_paths": delegated_roles_no_paths,
            "no_path_hash_prefixes": delegated_roles_no_path_hash_prefixes,
            "no_optional_attributes": delegated_no_optional_attr
        }
        for case, data in valid_delegatedrole_cases.items():
            for role_d in data:
                with self.subTest(case=case):
                    delegatedroles = DelegatedRole.from_dict(
                        copy.deepcopy(role_d)
                    )
                    self.assertDictEqual(delegatedroles.to_dict(), role_d)


    def test_targetfile_serialization(self):
        targets = self.valid_targets_cases["all_attributes"]["targets"]
        valid_targetfile_cases = {
            "all_attributes": targets,
            "targetfiles_no_custom": copy_recur(targets, ["custom"])
        }
        for case, data in valid_targetfile_cases.items():
            for targetfile in data.values():
                with self.subTest(case=case):
                    targetfile_obj = TargetFile.from_dict(
                        copy.deepcopy(targetfile)
                    )
                    self.assertDictEqual(targetfile_obj.to_dict(), targetfile)


    def test_targets_serialization(self):
        for case, data in self.valid_targets_cases.items():
            with self.subTest(case=case):
                targets = Targets.from_dict(copy.deepcopy(data))
                self.assertDictEqual(targets.to_dict(), data)

# Run unit test.
if __name__ == '__main__':
    utils.configure_test_logging(sys.argv)
    unittest.main()
