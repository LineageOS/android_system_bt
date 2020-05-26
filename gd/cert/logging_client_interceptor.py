#!/usr/bin/env python3
#
#   Copyright 2020 - The Android Open Source Project
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

import logging

import grpc

from google.protobuf import text_format


def pretty_print(request):
    return '{} {}'.format(type(request).__name__, text_format.MessageToString(request, as_one_line=True))


class LoggingClientInterceptor(grpc.UnaryUnaryClientInterceptor):

    TAG_MIN_WIDTH = 24

    def __init__(self, name):
        self.name = name
        self.loggableTag = "[host ▶▶▶▶▶ %s]" % self.name
        tagLength = len(re.sub('[^\w\s]', '', self.loggableTag)) + 11
        if tagLength < self.TAG_MIN_WIDTH:
            self.loggableTag += " " * (self.TAG_MIN_WIDTH - tagLength)

    def _intercept_call(self, continuation, client_call_details, request_or_iterator):
        return continuation(client_call_details, request_or_iterator)

    def intercept_unary_unary(self, continuation, client_call_details, request):
        print("%s%s %s" % (self.loggableTag, client_call_details.method, pretty_print(request)))
        return self._intercept_call(continuation, client_call_details, request)
