import unittest

from typing import Any, Dict , Callable, Type

# DataSet is only here so type hints can be used:
# It is a dict of name to test dict
DataSet = Dict[str, Dict[str, Any]]

# Test runner decorator: Runs the test as a set of N SubTests,
# (where N is number of items in dataset), feeding the actual test
# function one data item at a time
def run_sub_tests_with_dataset(dataset: Type[DataSet]):
    def real_decorator(function: Callable[[unittest.TestCase, DataSet], None]):
        def wrapper(test: unittest.TestCase):
            for case, data in dataset.items():
                with test.subTest(case=case):
                    function(test, data)
        return wrapper
    return real_decorator




class TestExample(unittest.TestCase):

    # Test data defined here -- outside the test code
    valid_data: DataSet = {
        "case 1": {"data": 1},
        "case 3": {"data": 2},
        "case 4": {"data": ""},
        "case 5": {"data": 9},
        "case 6": {"data": object()},
    }

    @run_sub_tests_with_dataset(valid_data)
    def test_data_field_is_not_none(self, test_case):
        if test_case["data"] is None:
            raise self.fail("oh no")


# Run unit test.
if __name__ == '__main__':
    unittest.main()
