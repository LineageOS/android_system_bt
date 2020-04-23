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

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import logging
from queue import SimpleQueue, Empty

from mobly import asserts

from google.protobuf import text_format

from grpc import RpcError

from cert.closable import Closable


class IEventStream(ABC):

    @abstractmethod
    def get_event_queue(self):
        pass


class FilteringEventStream(IEventStream):

    def __init__(self, stream, filter_fn):
        self.filter_fn = filter_fn if filter_fn else lambda x: x
        self.event_queue = SimpleQueue()
        self.stream = stream

        self.stream.register_callback(
            self.__event_callback,
            lambda packet: self.filter_fn(packet) is not None)

    def __event_callback(self, event):
        self.event_queue.put(self.filter_fn(event))

    def get_event_queue(self):
        return self.event_queue

    def unregister(self):
        self.stream.unregister(self.__event_callback)


def pretty_print(proto_event):
    return '{} {}'.format(
        type(proto_event).__name__,
        text_format.MessageToString(proto_event, as_one_line=True))


DEFAULT_TIMEOUT_SECONDS = 3


class EventStream(IEventStream, Closable):
    """
    A class that streams events from a gRPC stream, which you can assert on.

    Don't use these asserts directly, use the ones from cert.truth.
    """

    def __init__(self, server_stream_call):
        if server_stream_call is None:
            raise ValueError("server_stream_call cannot be None")

        self.server_stream_call = server_stream_call
        self.event_queue = SimpleQueue()
        self.handlers = []
        self.executor = ThreadPoolExecutor()
        self.future = self.executor.submit(EventStream._event_loop, self)

    def get_event_queue(self):
        return self.event_queue

    def close(self):
        """
        Stop the gRPC lambda so that event_callback will not be invoked after th
        method returns.

        This object will be useless after this call as there is no way to restart
        the gRPC callback. You would have to create a new EventStream

        :return: None on success, exception object on failure
        """
        while not self.server_stream_call.done():
            self.server_stream_call.cancel()
        exception_for_return = None
        try:
            result = self.future.result()
            if result:
                logging.warning("Inner loop error %s" % result)
                raise result
        except Exception as exp:
            logging.warning("Exception: %s" % (exp))
            exception_for_return = exp
        self.executor.shutdown()
        return exception_for_return

    def register_callback(self, callback, matcher_fn=None):
        """
        Register a callback to handle events. Event will be handled by callback
        if matcher_fn(event) returns True

        callback and matcher are registered as a tuple. Hence the same callback
        with different matcher are considered two different handler units. Same
        matcher, but different callback are also considered different handling
        unit

        Callback will be invoked on a ThreadPoolExecutor owned by this
        EventStream

        :param callback: Will be called as callback(event)
        :param matcher_fn: A boolean function that returns True or False when
                           calling matcher_fn(event), if None, all event will
                           be matched
        """
        if callback is None:
            raise ValueError("callback must not be None")
        self.handlers.append((callback, matcher_fn))

    def unregister_callback(self, callback, matcher_fn=None):
        """
        Unregister callback and matcher_fn from the event stream. Both objects
        must match exactly the ones when calling register_callback()

        :param callback: callback used in register_callback()
        :param matcher_fn: matcher_fn used in register_callback()
        :raises ValueError when (callback, matcher_fn) tuple is not found
        """
        if callback is None:
            raise ValueError("callback must not be None")
        self.handlers.remove((callback, matcher_fn))

    def _event_loop(self):
        """
        Main loop for consuming the gRPC stream events.
        Blocks until computation is cancelled
        :return: None on success, exception object on failure
        """
        try:
            for event in self.server_stream_call:
                self.event_queue.put(event)
                for (callback, matcher_fn) in self.handlers:
                    if not matcher_fn or matcher_fn(event):
                        callback(event)
            return None
        except RpcError as exp:
            if self.server_stream_call.cancelled():
                logging.debug("Cancelled")
                return None
            else:
                logging.warning("Some RPC error not due to cancellation")
            return exp

    def assert_none(self, timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
        """
        Assert no event happens within timeout period

        :param timeout: a timedelta object
        :return:
        """
        NOT_FOR_YOU_assert_none(self, timeout)

    def assert_none_matching(
            self, match_fn, timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
        """
        Assert no events where match_fn(event) is True happen within timeout
        period

        :param match_fn: return True/False on match_fn(event)
        :param timeout: a timedelta object
        :return:
        """
        NOT_FOR_YOU_assert_none_matching(self, match_fn, timeout)

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
        NOT_FOR_YOU_assert_event_occurs(self, match_fn, at_least_times, timeout)

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
        event_list = []
        end_time = datetime.now() + timeout
        while len(event_list) <= at_most_times and datetime.now() < end_time:
            remaining = static_remaining_time_delta(end_time)
            logging.debug("Waiting for event iteration (%fs remaining)" %
                          (remaining.total_seconds()))
            try:
                current_event = self.event_queue.get(
                    timeout=remaining.total_seconds())
                if match_fn(current_event):
                    event_list.append(current_event)
            except Empty:
                continue
        logging.debug("Done waiting, got %d events" % len(event_list))
        asserts.assert_true(
            len(event_list) <= at_most_times,
            msg=("Expected at most %d events, but got %d" % (at_most_times,
                                                             len(event_list))))

    def assert_all_events_occur(
            self,
            match_fns,
            order_matters,
            timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
        NOT_FOR_YOU_assert_all_events_occur(self, match_fns, order_matters,
                                            timeout)


def static_remaining_time_delta(end_time):
    remaining = end_time - datetime.now()
    if remaining < timedelta(milliseconds=0):
        remaining = timedelta(milliseconds=0)
    return remaining


def NOT_FOR_YOU_assert_event_occurs(
        istream,
        match_fn,
        at_least_times=1,
        timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
    logging.debug("assert_event_occurs %d %fs" % (at_least_times,
                                                  timeout.total_seconds()))
    event_list = []
    end_time = datetime.now() + timeout
    while len(event_list) < at_least_times and datetime.now() < end_time:
        remaining = static_remaining_time_delta(end_time)
        logging.debug(
            "Waiting for event (%fs remaining)" % (remaining.total_seconds()))
        try:
            current_event = istream.get_event_queue().get(
                timeout=remaining.total_seconds())
            logging.debug("current_event: %s", current_event)
            if match_fn(current_event):
                event_list.append(current_event)
        except Empty:
            continue
    logging.debug("Done waiting for event, received %d", len(event_list))
    asserts.assert_true(
        len(event_list) >= at_least_times,
        msg=("Expected at least %d events, but got %d" % (at_least_times,
                                                          len(event_list))))


def NOT_FOR_YOU_assert_all_events_occur(
        istream,
        match_fns,
        order_matters,
        timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
    logging.debug("assert_all_events_occur %fs" % timeout.total_seconds())
    pending_matches = list(match_fns)
    matched_order = []
    end_time = datetime.now() + timeout
    while len(pending_matches) > 0 and datetime.now() < end_time:
        remaining = static_remaining_time_delta(end_time)
        logging.debug(
            "Waiting for event (%fs remaining)" % (remaining.total_seconds()))
        try:
            current_event = istream.get_event_queue().get(
                timeout=remaining.total_seconds())
            for match_fn in pending_matches:
                if match_fn(current_event):
                    pending_matches.remove(match_fn)
                    matched_order.append(match_fn)
        except Empty:
            continue
    logging.debug("Done waiting for event")
    asserts.assert_true(
        len(matched_order) == len(match_fns),
        msg=("Expected at least %d events, but got %d" % (len(match_fns),
                                                          len(matched_order))))
    if order_matters:
        correct_order = True
        i = 0
        while i < len(match_fns):
            if match_fns[i] is not matched_order[i]:
                correct_order = False
                break
            i += 1
        asserts.assert_true(
            correct_order, "Events not received in correct order %s %s" %
            (match_fns, matched_order))


def NOT_FOR_YOU_assert_none_matching(
        istream, match_fn, timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
    logging.debug("assert_none_matching %fs" % (timeout.total_seconds()))
    event = None
    end_time = datetime.now() + timeout
    while event is None and datetime.now() < end_time:
        remaining = static_remaining_time_delta(end_time)
        logging.debug(
            "Waiting for event (%fs remaining)" % (remaining.total_seconds()))
        try:
            current_event = istream.get_event_queue().get(
                timeout=remaining.total_seconds())
            if match_fn(current_event):
                event = current_event
        except Empty:
            continue
    logging.debug("Done waiting for an event")
    if event is None:
        return  # Avoid an assert in MessageToString(None, ...)
    asserts.assert_true(
        event is None,
        msg='Expected None matching, but got {}'.format(pretty_print(event)))


def NOT_FOR_YOU_assert_none(istream,
                            timeout=timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)):
    logging.debug("assert_none %fs" % (timeout.total_seconds()))
    try:
        event = istream.get_event_queue().get(timeout=timeout.total_seconds())
        asserts.assert_true(
            event is None,
            msg='Expected None, but got {}'.format(pretty_print(event)))
    except Empty:
        return
