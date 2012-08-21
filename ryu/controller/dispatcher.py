# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

import copy
import logging

from gevent.queue import Queue

from ryu.lib.track_instances import TrackInstances
from . import event

LOG = logging.getLogger('ryu.controller.dispatcher')


class EventQueue(TrackInstances):
    _ev_q = None

    def set_ev_q(self):
        # Be careful: circular reference
        # It is assumed that event queue for EventQueue is never freed.
        self.__class__._ev_q = self

    @classmethod
    def _get_ev_q(cls):
        return cls._ev_q

    def _queue_q_ev(self, ev):
        ev_q = self._get_ev_q()
        if ev_q is not None:
            ev_q.queue(ev)

    def __init__(self, name, dispatcher, aux=None):
        super(EventQueue, self).__init__()
        self.name = name
        self._dispatcher = dispatcher.clone()
        self.is_dispatching = False
        self.ev_q = Queue()
        self.aux = aux  # for EventQueueCreate event

        self._queue_q_ev(EventQueueCreate(self, True))

    def __del__(self):
        # This can be called when python interpreter exiting.
        # At that time, other object like EventQueueCreate can be
        # already destructed. So we can't call it blindly.
        assert self.aux is None
        ev_q = self._get_ev_q()
        if ev_q is not None and self != ev_q:
            self._queue_q_ev(EventQueueCreate(self, False))
        self._dispatcher.close()

    @property
    def dispatcher(self):
        return self._dispatcher

    def close(self):
        """
        Call this function before discarding this object.
        This function unset self.aux in order to break potential circular
        reference.

        Sometimes self.aux results in cyclic reference.
        So we need to break it explicitly. (Or use weakref)
        """
        self.aux = None

    def set_dispatcher(self, dispatcher):
        old = self._dispatcher
        new = dispatcher.clone()
        self._dispatcher = new
        self._queue_q_ev(EventDispatcherChange(self, old, new))
        old.close()

    def queue_raw(self, ev):
        self.ev_q.put(ev)

    class _EventQueueGuard(object):
        def __init__(self, ev_q):
            self.ev_q = ev_q

        def __enter__(self):
            self.ev_q.is_dispatching = True

        def __exit__(self, type_, value, traceback):
            self.ev_q.is_dispatching = False
            return False

    def queue(self, ev):
        if self.is_dispatching:
            self.queue_raw(ev)
            return

        with self._EventQueueGuard(self):
            assert self.ev_q.empty()

            self._dispatcher(ev)
            while not self.ev_q.empty():
                ev = self.ev_q.get()
                self._dispatcher(ev)


class EventDispatcher(TrackInstances):
    def __init__(self, name):
        super(EventDispatcher, self).__init__()
        self.parent = None
        self.children = set()
        self.name = name
        self.events = {}
        self.all_handlers = []

    def close(self):
        if self.parent is None:
            return
        self.parent.children.remove(self)
        self.parent = None

    def clone(self):
        cloned = EventDispatcher(self.name)
        for ev_cls, h in self.events.items():
            cloned.events[ev_cls] = copy.copy(h)
        cloned.all_handlers = copy.copy(self.all_handlers)

        cloned.parent = self
        self.children.add(cloned)

        return cloned

    def _foreach_children(self, call, *args, **kwargs):
        for c in self.children:
            call(c, *args, **kwargs)

    def register_all_handler(self, all_handler):
        assert callable(all_handler)
        self.all_handlers.append(all_handler)
        self._foreach_children(EventDispatcher.register_all_handler,
                               all_handler)

    def register_handler(self, ev_cls, handler):
        assert callable(handler)
        self.events.setdefault(ev_cls, [])
        self.events[ev_cls].append(handler)
        self._foreach_children(EventDispatcher.register_handler,
                               ev_cls, handler)

    def register_handlers(self, handlers):
        for ev_cls, h in handlers:
            self.register_handler(ev_cls, h)

    def register_static(self, ev_cls):
        '''helper decorator to statically register handler for event class'''
        def register(handler):
            '''helper decorator to register handler statically '''
            if isinstance(handler, staticmethod):
                # class staticmethod is not callable.
                handler = handler.__func__
            self.register_handler(ev_cls, handler)
            return handler
        return register

    def __call__(self, ev):
        self.dispatch(ev)

    @staticmethod
    def _dispatch(ev, handlers):
        if not handlers:
            return False

        for h in handlers:
            ret = h(ev)
            if ret is False:
                break
        return True

    def dispatch(self, ev):
        #LOG.debug('dispatch %s', ev)
        self._dispatch(ev, self.all_handlers)

        handled = self._dispatch(ev, self.events.get(ev.__class__, []))
        if not handled:
            LOG.info('unhandled event %s', ev)


class EventQueueBase(event.EventBase):
    def __init__(self, ev_q):
        super(EventQueueBase, self).__init__()
        self.ev_q = ev_q
        self.aux = ev_q.aux


class EventQueueCreate(EventQueueBase):
    def __init__(self, ev_q, create):
        super(EventQueueCreate, self).__init__(ev_q)
        self.create = bool(create)    # True:  queue is created
                                      # False: queue is destroyed
        self.dispatcher = ev_q.dispatcher


class EventDispatcherChange(EventQueueBase):
    def __init__(self, ev_q, old_dispatcher, new_dispatcher):
        super(EventDispatcherChange, self).__init__(ev_q)
        self.old_dispatcher = old_dispatcher
        self.new_dispatcher = new_dispatcher


DISPATCHER_NAME_QUEUE_EV = 'queue_event'
QUEUE_EV_DISPATCHER = EventDispatcher(DISPATCHER_NAME_QUEUE_EV)
QUEUE_NAME_QEV_Q = 'queue_event'
QUEUE_EV_Q = EventQueue(QUEUE_NAME_QEV_Q, QUEUE_EV_DISPATCHER)
QUEUE_EV_Q.set_ev_q()
