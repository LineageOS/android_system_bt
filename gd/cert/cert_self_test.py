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

from datetime import datetime, timedelta
import logging
from threading import Timer
import time
import traceback

from mobly import asserts

from acts import signals
from acts.base_test import BaseTestClass

from bluetooth_packets_python3 import hci_packets
from bluetooth_packets_python3 import l2cap_packets
from cert.event_stream import EventStream, FilteringEventStream
from cert.truth import assertThat
from cert.metadata import metadata
from cert.behavior import when, wait_until
from cert.behavior import IHasBehaviors
from cert.behavior import anything
from cert.behavior import SingleArgumentBehavior
from cert.behavior import ReplyStage
from cert.cert_self_test_lib import *


class CertSelfTest(BaseTestClass):

    def setup_test(self):
        return True

    def teardown_test(self):
        return True

    def test_assert_occurs_at_least_passes(self):
        test_assert_occurs_at_least_passes_core()

    def test_assert_occurs_passes(self):
        test_assert_occurs_passes_core()

    def test_assert_occurs_fails(self):
        test_assert_occurs_fails_core()

    def test_assert_occurs_at_most_passes(self):
        test_assert_occurs_at_most_passes_core()

    def test_assert_occurs_at_most_fails(self):
        test_assert_occurs_at_most_fails_core()

    def test_skip_a_test(self):
        test_skip_a_test_core()

    def test_nested_packets(self):
        test_nested_packets_core()

    def test_l2cap_config_options(self):
        test_l2cap_config_options_core()

    def test_assertThat_boolean_success(self):
        test_assertThat_boolean_success_core()

    def test_assertThat_boolean_falseIsTrue(self):
        test_assertThat_boolean_falseIsTrue_core()

    def test_assertThat_boolean_trueIsFalse(self):
        test_assertThat_boolean_trueIsFalse_core()

    def test_assertThat_object_success(self):
        test_assertThat_object_success_core()

    def test_assertThat_object_isEqualToFails(self):
        test_assertThat_object_isEqualToFails_core()

    def test_assertThat_object_isNotEqualToFails(self):
        test_assertThat_object_isNotEqualToFails_core()

    def test_assertThat_object_isNoneFails(self):
        test_assertThat_object_isNoneFails_core()

    def test_assertThat_object_isNotNoneFails(self):
        test_assertThat_object_isNotNoneFails_core()

    def test_assertThat_eventStream_emits_passes(self):
        test_assertThat_eventStream_emits_passes_core()

    def test_assertThat_eventStream_emits_then_passes(self):
        test_assertThat_eventStream_emits_then_passes_core()

    def test_assertThat_eventStream_emits_fails(self):
        test_assertThat_eventStream_emits_fails_core()

    def test_assertThat_eventStream_emits_then_fails(self):
        test_assertThat_eventStream_emits_then_fails_core()

    def test_assertThat_eventStream_emitsInOrder_passes(self):
        test_assertThat_eventStream_emitsInOrder_passes_core()

    def test_assertThat_eventStream_emitsInAnyOrder_passes(self):
        test_assertThat_eventStream_emitsInAnyOrder_passes_core()

    def test_assertThat_eventStream_emitsInOrder_fails(self):
        test_assertThat_eventStream_emitsInOrder_fails_core()

    def test_assertThat_eventStream_emitsInAnyOrder_fails(self):
        test_assertThat_eventStream_emitsInAnyOrder_fails_core()

    def test_assertThat_emitsNone_passes(self):
        test_assertThat_emitsNone_passes_core()

    def test_assertThat_emitsNone_passes_after_1_second(self):
        test_assertThat_emitsNone_passes_after_1_second_core()

    def test_assertThat_emitsNone_fails(self):
        test_assertThat_emitsNone_fails_core()

    def test_assertThat_emitsNone_zero_passes(self):
        test_assertThat_emitsNone_zero_passes_core()

    def test_assertThat_emitsNone_zero_passes_after_one_second(self):
        test_assertThat_emitsNone_zero_passes_after_one_second_core()

    def test_assertThat_emitsNone_zero_fails(self):
        test_assertThat_emitsNone_zero_fails_core()

    def test_filtering_event_stream_none_filter_function(self):
        test_filtering_event_stream_none_filter_function_core()

    def test_metadata_empty(self):

        @metadata()
        def simple_pass_test(arg):
            pass

        try:
            simple_pass_test(1)
        except signals.TestFailure:
            pass
        except Exception as e:
            asserts.fail("@metadata() should only raise signals.TestFailure, "
                         "but raised %s with msg %s instead" % (e.__class__.__name__, str(e)))
        else:
            asserts.fail("@metadata() should not work")

    def test_metadata_empty_no_function_call(self):

        @metadata
        def simple_pass_test(arg):
            pass

        try:
            simple_pass_test(1)
        except signals.TestFailure:
            pass
        except Exception as e:
            asserts.fail("@metadata should only raise signals.TestFailure, "
                         "but raised %s with msg %s instead" % (e.__class__.__name__, str(e)))
        else:
            asserts.fail("@metadata should not work")

    def test_metadata_pts_missing_id(self):

        @metadata(pts_test_name="Hello world")
        def simple_pass_test(arg):
            pass

        try:
            simple_pass_test(1)
        except signals.TestFailure:
            pass
        except Exception as e:
            asserts.fail("should only raise signals.TestFailure, "
                         "but raised %s with msg %s instead" % (e.__class__.__name__, str(e)))
        else:
            asserts.fail("missing pts_test_id should not work")

    def test_metadata_pts_missing_name(self):

        @metadata(pts_test_id="A/B/C")
        def simple_pass_test(arg):
            pass

        try:
            simple_pass_test(1)
        except signals.TestFailure:
            pass
        except Exception as e:
            asserts.fail("should only raise signals.TestFailure, "
                         "but raised %s with msg %s instead" % (e.__class__.__name__, str(e)))
        else:
            asserts.fail("missing pts_test_name should not work")

    def test_metadata_pts_test_id_and_description(self):

        @metadata(pts_test_id="A/B/C", pts_test_name="Hello world")
        def simple_pass_test(arg):
            pass

        try:
            simple_pass_test(1)
        except signals.TestPass as e:
            asserts.assert_true("pts_test_id" in e.extras, msg=("pts_test_id not in extra: %s" % str(e.extras)))
            asserts.assert_equal(e.extras["pts_test_id"], "A/B/C")
            asserts.assert_true("pts_test_name" in e.extras, msg=("pts_test_name not in extra: %s" % str(e.extras)))
            asserts.assert_equal(e.extras["pts_test_name"], "Hello world")
        else:
            asserts.fail("Must throw an exception using @metadata decorator")

    def test_metadata_test_with_exception_stacktrace(self):

        @metadata(pts_test_id="A/B/C", pts_test_name="Hello world")
        def simple_fail_test(failure_argument):
            raise ValueError(failure_argument)

        try:
            simple_fail_test("BEEFBEEF")
        except signals.TestError as e:
            asserts.assert_true("pts_test_id" in e.extras, msg=("pts_test_id not in extra: %s" % str(e.extras)))
            asserts.assert_equal(e.extras["pts_test_id"], "A/B/C")
            asserts.assert_true("pts_test_name" in e.extras, msg=("pts_test_name not in extra: %s" % str(e.extras)))
            asserts.assert_equal(e.extras["pts_test_name"], "Hello world")
            trace_str = traceback.format_exc()
            asserts.assert_true(
                "raise ValueError(failure_argument)" in trace_str,
                msg="Failed test method not in error stack trace: %s" % trace_str)
        else:
            asserts.fail("Must throw an exception using @metadata decorator")

    def test_fluent_behavior_simple(self):
        test_fluent_behavior_simple_core()

    def test_fluent_behavior__then_single__captures_one(self):
        test_fluent_behavior__then_single__captures_one_core()

    def test_fluent_behavior__then_times__captures_all(self):
        test_fluent_behavior__then_times__captures_all_core()

    def test_fluent_behavior__always__captures_all(self):
        test_fluent_behavior__always__captures_all_core()

    def test_fluent_behavior__matcher__captures_relevant(self):
        test_fluent_behavior__matcher__captures_relevant_core()

    def test_fluent_behavior__then_repeated__captures_relevant(self):
        test_fluent_behavior__then_repeated__captures_relevant_core()

    def test_fluent_behavior__fallback__captures_relevant(self):
        test_fluent_behavior__fallback__captures_relevant_core()

    def test_fluent_behavior__default_unhandled_crash(self):
        test_fluent_behavior__default_unhandled_crash_core()

    def test_fluent_behavior__set_default_works(self):
        test_fluent_behavior__set_default_works_core()

    def test_fluent_behavior__wait_until_done(self):
        test_fluent_behavior__wait_until_done_core()

    def test_fluent_behavior__wait_until_done_different_lambda(self):
        test_fluent_behavior__wait_until_done_different_lambda_core()

    def test_fluent_behavior__wait_until_done_anything(self):
        test_fluent_behavior__wait_until_done_anything_core()

    def test_fluent_behavior__wait_until_done_not_happened(self):
        test_fluent_behavior__wait_until_done_not_happened_core()

    def test_fluent_behavior__wait_until_done_with_default(self):
        test_fluent_behavior__wait_until_done_with_default_core()

    def test_fluent_behavior__wait_until_done_two_events_AA(self):
        test_fluent_behavior__wait_until_done_two_events_AA_core()

    def test_fluent_behavior__wait_until_done_two_events_AB(self):
        test_fluent_behavior__wait_until_done_two_events_AB_core()

    def test_fluent_behavior__wait_until_done_only_one_event_is_done(self):
        test_fluent_behavior__wait_until_done_only_one_event_is_done_core()
