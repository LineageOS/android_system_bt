#!/usr/bin/env python3
#
#   Copyright 2019 - The Android Open Source Project
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
import enum
import functools

from mobly import asserts

from acts.base_test import BaseTestClass


@enum.unique
class MetadataKey(enum.Enum):
    """Enums used for recording UserData section for Gd Cert Tests"""
    # TEST_CLASS + TEST_NAME should uniquely define a test
    TEST_NAME = 'Test Name'
    TEST_CLASS = 'Test Class'
    # A fully qualified PTS test ID such as L2CAP/COS/IEX/BV-01-C
    PTS_TEST_ID = 'PTS Test ID'

    def __str__(self):
        """
        :return: str representation of |value| instead of "Class.Enum"
        """
        return repr(self)

    def __repr__(self):
        """
        :return: the same str representation since |value| is unique
        """
        return str(self.value)


def metadata(_do_not_use=None, pts_test_id=None):
    """
    Record a piece of test metadata in the UserData section of the test summary
    file. The metadata will come with a timestamp, but there is no guarantee
    on the order of when the metadata will be written

    Note:
    - Metadata is recorded per test case as key-value pairs.
    - TEST_CLASS and TEST_NAME combination can be used to correlate a piece of
      metadata with the ACTS or Mobly generated test run record in the same
      YAML file
    - Metadata is only guaranteed to be written when the test result is PASS,
      FAIL or SKIPPED. When there are test infrastructural errors, metadata
      might not be written successfully
    :param _do_not_use: a positional argument with default value. This argument
                        is only used when @metadata is used instead of
                        @metadata()
    :param pts_test_id: A fully qualified PTS test ID such as
                        L2CAP/COS/IEX/BV-01-C, see MetadataKey.PTS_TEST_ID
    :return: decorated test case function
    """

    def real_decorator(test_case_function):

        @functools.wraps(test_case_function)
        def wrapper(self: BaseTestClass):
            try:
                test_case_function(self)
            finally:
                content = {
                    str(MetadataKey.TEST_NAME): test_case_function.__name__,
                    str(MetadataKey.TEST_CLASS): self.__class__.__name__
                }
                if pts_test_id:
                    content[str(MetadataKey.PTS_TEST_ID)] = str(pts_test_id)
                self.record_data(content)

        return wrapper

    if _do_not_use is not None:
        asserts.assert_true(
            callable(_do_not_use), "No real positional argument is allowed for"
            " @metadata")
        asserts.assert_true(
            pts_test_id is None,
            "No additional positional argument is allowed for"
            " @metadata")
        return real_decorator(_do_not_use)

    return real_decorator
