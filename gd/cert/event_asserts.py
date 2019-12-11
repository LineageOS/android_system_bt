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
from queue import SimpleQueue, Empty

from acts import asserts

from google.protobuf import text_format

from cert.event_callback_stream import EventCallbackStream


class EventAsserts(object):
    """
    A class that handles various asserts with respect to a gRPC unary stream

    This class must be created before an event happens as events in a
    EventCallbackStream is not sticky and will be lost if you don't subscribe
    to them before generating those events.

    When asserting on sequential events, a single EventAsserts object is enough

    When asserting on simultaneous events, you would need multiple EventAsserts
    objects as each EventAsserts object owns a separate queue that is actively
    being popped as asserted events happen
    """
    DEFAULT_TIMEOUT_SECONDS = 3
    DEFAULT_INCREMENTAL_TIMEOUT_SECONDS = 0.1

    def __init__(self, event_callback_stream):
        if event_callback_stream is None:
            raise ValueError("event_callback_stream cannot be None")
        self.event_callback_stream = event_callback_stream
        self.event_queue = SimpleQueue()
        self.callback = lambda event: self.event_queue.put(event)
        self.event_callback_stream.register_callback(self.callback)

    def __del__(self):
        self.event_callback_stream.unregister_callback(self.callback)

    def assert_none(self, timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
        """
        Assert no event happens within timeout period

        :param timeout: a timedelta object
        :return:
        """
        logging.debug("assert_none")
        try:
            event = self.event_queue.get(timeout=timeout.seconds)
            asserts.assert_equal(
                event,
                None,
                msg=("Expected None, but got %s" % text_format.MessageToString(
                    event, as_one_line=True)))
        except Empty:
            return

    def assert_none_matching(
            self, match_fn, timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
        """
        Assert no events where match_fn(event) is True happen within timeout
        period

        :param match_fn: return True/False on match_fn(event)
        :param timeout: a timedelta object
        :return:
        """
        logging.debug("assert_none_matching")
        event = None
        iter_count = 0
        timeout_seconds = timeout.seconds
        while timeout_seconds > 0:
            iter_count += 1
            logging.debug("Waiting for event iteration %d" % iter_count)
            try:
                time_before = datetime.now()
                current_event = self.event_queue.get(timeout=timeout_seconds)
                time_elapsed = datetime.now() - time_before
                timeout_seconds -= time_elapsed.seconds
                if match_fn(current_event):
                    event = current_event
            except Empty:
                continue
        logging.debug("Done waiting for event, got %s" %
                      text_format.MessageToString(event, as_one_line=True))
        asserts.assert_equal(
            event,
            None,
            msg=("Expected None matching, but got %s" %
                 text_format.MessageToString(event, as_one_line=True)))

    def assert_event_occurs(self,
                            match_fn,
                            at_least_times=1,
                            timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
        """
        Assert at least |at_least_times| instances of events happen where
        match_fn(event) returns True within timeout period

        :param match_fn: returns True/False on match_fn(event)
        :param timeout: a timedelta object
        :param at_least_times: how many times at least a matching event should
                               happen
        :return:
        """
        logging.debug("assert_event_occurs")
        event = []
        iter_count = 0
        timeout_seconds = timeout.seconds
        while len(event) < at_least_times and timeout_seconds > 0:
            iter_count += 1
            logging.debug("Waiting for event iteration %d" % iter_count)
            try:
                time_before = datetime.now()
                current_event = self.event_queue.get(timeout=timeout_seconds)
                time_elapsed = datetime.now() - time_before
                timeout_seconds -= time_elapsed.seconds
                if match_fn(current_event):
                    event.append(current_event)
            except Empty:
                continue
        logging.debug("Done waiting for event, got %s" %
                      text_format.MessageToString(event, as_one_line=True))
        asserts.assert_true(
            len(event) == at_least_times,
            msg=("Expected at least %d events, but got %d" % at_least_times,
                 len(event)))

    def assert_event_occurs_at_most(
            self,
            match_fn,
            at_most_times,
            timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
        """
        Assert at most |at_most_times| instances of events happen where
        match_fn(event) returns True within timeout period

        :param match_fn: returns True/False on match_fn(event)
        :param at_most_times: how many times at most a matching event should
                               happen
        :param timeout:a timedelta object
        :return:
        """
        logging.debug("assert_event_occurs_at_most")
        event = []
        iter_count = 0
        timeout_seconds = timeout.seconds
        while timeout_seconds > 0:
            iter_count += 1
            logging.debug("Waiting for event iteration %d" % iter_count)
            try:
                time_before = datetime.now()
                current_event = self.event_queue.get(timeout=timeout_seconds)
                time_elapsed = datetime.now() - time_before
                timeout_seconds -= time_elapsed.seconds
                if match_fn(current_event):
                    event.append(current_event)
            except Empty:
                continue
        logging.debug("Done waiting for event, got %s" %
                      text_format.MessageToString(event, as_one_line=True))
        asserts.assert_true(
            len(event) <= at_most_times,
            msg=("Expected at most %d events, but got %d" % at_most_times,
                 len(event)))
