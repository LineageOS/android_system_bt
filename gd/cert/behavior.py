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

from abc import ABC, abstractmethod
from mobly import signals

from cert.truth import assertThat


class IHasBehaviors(ABC):

    @abstractmethod
    def get_behaviors(self):
        pass


def anything():
    return lambda obj: True


def when(has_behaviors):
    assertThat(isinstance(has_behaviors, IHasBehaviors)).isTrue()
    return has_behaviors.get_behaviors()


def IGNORE_UNHANDLED(obj):
    pass


class SingleArgumentBehavior(object):

    def __init__(self, reply_stage_factory):
        self._reply_stage_factory = reply_stage_factory
        self._instances = []
        self.set_default_to_crash()

    def begin(self, matcher):
        return PersistenceStage(self, matcher, self._reply_stage_factory)

    def append(self, behavior_instance):
        self._instances.append(behavior_instance)

    def set_default(self, fn):
        assertThat(fn).isNotNone()
        self._default_fn = fn

    def set_default_to_crash(self):
        self._default_fn = None

    def set_default_to_ignore(self):
        self._default_fn = IGNORE_UNHANDLED

    def run(self, obj):
        for instance in self._instances:
            if instance.try_run(obj):
                return
        if self._default_fn is not None:
            self._default_fn(obj)
        else:
            raise signals.TestFailure(
                "%s: behavior for %s went unhandled" %
                (self._reply_stage_factory().__class__.__name__, obj),
                extras=None)


class PersistenceStage(object):

    def __init__(self, behavior, matcher, reply_stage_factory):
        self._behavior = behavior
        self._matcher = matcher
        self._reply_stage_factory = reply_stage_factory

    def then(self, times=1):
        reply_stage = self._reply_stage_factory()
        reply_stage.init(self._behavior, self._matcher, times)
        return reply_stage

    def always(self):
        return self.then(times=-1)


class ReplyStage(object):

    def init(self, behavior, matcher, persistence):
        self._behavior = behavior
        self._matcher = matcher
        self._persistence = persistence

    def _commit(self, fn):
        self._behavior.append(
            BehaviorInstance(self._matcher, self._persistence, fn))


class BehaviorInstance(object):

    def __init__(self, matcher, persistence, fn):
        self._matcher = matcher
        self._persistence = persistence
        self._fn = fn
        self._called_count = 0

    def try_run(self, obj):
        if not self._matcher(obj):
            return False
        if self._persistence >= 0:
            if self._called_count >= self._persistence:
                return False
        self._called_count += 1
        self._fn(obj)
        return True
