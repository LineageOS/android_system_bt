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
  def __init__(self, stream_stub_fn):
    self.stream_stub_fn = stream_stub_fn

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

  def assert_event_occurs(self, match_fn, timeout=timedelta(seconds=3)):
    expiration_time = datetime.now() + timeout
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
            return
      except RpcError:
        if response.code() == StatusCode.DEADLINE_EXCEEDED:
          continue
        raise
