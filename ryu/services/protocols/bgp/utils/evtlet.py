# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
 Concurrent networking library - Eventlet, based utilities classes.
"""
from ryu.lib import hub
import logging

LOG = logging.getLogger('utils.evtlet')


class EventletIOFactory(object):

    @staticmethod
    def create_custom_event():
        LOG.debug('Create CustomEvent called')
        return hub.Event()

    @staticmethod
    def create_looping_call(funct, *args, **kwargs):
        LOG.debug('create_looping_call called')
        return LoopingCall(funct, *args, **kwargs)


# TODO: improve Timer service and move it into framework
class LoopingCall(object):
    """Call a function repeatedly.
    """

    def __init__(self, funct, *args, **kwargs):
        self._funct = funct
        self._args = args
        self._kwargs = kwargs
        self._running = False
        self._interval = 0
        self._self_thread = None

    @property
    def running(self):
        return self._running

    @property
    def interval(self):
        return self._interval

    def __call__(self):
        if self._running:
            # Schedule next iteration of the call.
            self._self_thread = hub.spawn_after(self._interval, self)
        self._funct(*self._args, **self._kwargs)

    def start(self, interval, now=True):
        """Start running pre-set function every interval seconds.
        """
        if interval < 0:
            raise ValueError('interval must be >= 0')

        if self._running:
            self.stop()

        self._running = True
        self._interval = interval
        if now:
            self._self_thread = hub.spawn_after(0, self)
        else:
            self._self_thread = hub.spawn_after(self._interval, self)

    def stop(self):
        """Stop running scheduled function.
        """
        self._running = False
        if self._self_thread is not None:
            self._self_thread.cancel()
            self._self_thread = None

    def reset(self):
        """Skip the next iteration and reset timer.
        """
        if self._self_thread is not None:
            # Cancel currently scheduled call
            self._self_thread.cancel()
            self._self_thread = None
        # Schedule a new call
        self._self_thread = hub.spawn_after(self._interval, self)
