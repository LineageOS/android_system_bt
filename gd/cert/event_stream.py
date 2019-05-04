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

from acts import asserts

from facade import common_pb2
from datetime import datetime
from datetime import timedelta
from grpc import RpcError
from grpc import StatusCode

class EventStream(object):

  event_buffer = []

  def __init__(self, stream_stub_fn):
    self.stream_stub_fn = stream_stub_fn

  def clear_event_buffer(self):
    self.event_buffer.clear()

  def subscribe(self):
    return self.stream_stub_fn(
        common_pb2.EventStreamRequest(
          subscription_mode=common_pb2.SUBSCRIBE,
          fetch_mode=common_pb2.NONE
        )
    )

  def unsubscribe(self):
    return self.stream_stub_fn(
        common_pb2.EventStreamRequest(
            subscription_mode=common_pb2.UNSUBSCRIBE,
            fetch_mode=common_pb2.NONE
        )
    )

  def assert_none(self):
    response = self.stream_stub_fn(
        common_pb2.EventStreamRequest(
            subscription_mode=common_pb2.NONE,
            fetch_mode=common_pb2.ALL_CURRENT
        )
    )

    try:
      for event in response:
        self.event_buffer.append(event)
    except RpcError:
        pass

    if len(self.event_buffer) != 0:
      asserts.fail("event_buffer is not empty \n%s" % self.event_buffer)

  def assert_none_matching(self, match_fn):
    response = self.stream_stub_fn(
        common_pb2.EventStreamRequest(
            subscription_mode=common_pb2.NONE,
            fetch_mode=common_pb2.ALL_CURRENT
        )
    )

    try:
      for event in response:
        self.event_buffer.append(event)
    except RpcError:
      pass

    for event in self.event_buffer:
      if match_fn(event):
        asserts.fail("event %s occurs" % event)

  def assert_event_occurs(self, match_fn, timeout=timedelta(seconds=3)):
    expiration_time = datetime.now() + timeout

    while len(self.event_buffer):
      element = self.event_buffer.pop(0)
      if match_fn(element):
        return

    while (True):
      if datetime.now() > expiration_time:
        asserts.fail("timeout of %s exceeded" % str(timeout))

      response = self.stream_stub_fn(
          common_pb2.EventStreamRequest(
              subscription_mode=common_pb2.NONE,
              fetch_mode=common_pb2.AT_LEAST_ONE,
              timeout_ms = int((expiration_time - datetime.now()).total_seconds() * 1000)
          )
      )

      try:
        for event in response:
          if (match_fn(event)):
            for remain_event in response:
              self.event_buffer.append(remain_event)
            return
      except RpcError:
        if response.code() == StatusCode.DEADLINE_EXCEEDED:
          continue
        raise
