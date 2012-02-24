# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import copy
import logging
import weakref

from gevent.queue import Queue

from ryu.lib.track_instances import TrackInstances
from . import event

LOG = logging.getLogger('ryu.controller.dispatcher')

# WeakSet is supported by python 2.7+. So WeakValueDictionary is used
# instead for python 2.6 which is used by REHL6
# e.g.
# wvd = WeakValueDictionary()           ws = WeakSet()
# wvd[id(value)] = value                ws = value
# wvd.values()                          ws: iterator


class EventQueue(TrackInstances):
    # weakref: break circular reference
    #          self._ev_q_weakref == weakref.ref(self)
    _ev_q_weakref = None

    def set_ev_q(self):
        self.__class__._ev_q_weakref = weakref.ref(self)

    def _get_ev_q(self):
        ev_q = self._ev_q_weakref
        if ev_q is not None:
            ev_q = ev_q()
        return ev_q

    def _queue_q_ev(self, ev):
        ev_q = self._get_ev_q()
        if ev_q is not None:
            ev_q.queue(ev)

    def __init__(self, name, dispatcher, aux=None):
        self.name = name
        self.dispatcher = dispatcher.clone()
        self.is_dispatching = False
        self.ev_q = Queue()
        self.aux = aux  # for EventQueueCreate event

        self._queue_q_ev(EventQueueCreate(self, True))

    def __del__(self):
        # This can be called when python interpreter exiting.
        # At that time, other object like EventQueueCreate can be
        # already destructed. So we can't call it blindly.
        ev_q = self._get_ev_q()
        if ev_q is not None and self != ev_q:
            self._queue_q_ev(EventQueueCreate(self, False))

    def set_dispatcher(self, dispatcher):
        old = self.dispatcher
        new = dispatcher.clone()
        self.dispatcher = new
        self._queue_q_ev(EventDispatcherChange(self, old, new))

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

            self.dispatcher(ev)
            while not self.ev_q.empty():
                ev = self.ev_q.get()
                self.dispatcher(ev)


class EventDispatcher(TrackInstances):
    def __init__(self, name):
        # WeakValueDictionary: In order to let child to go away.
        #                      We are interested only in alive children.
        self.children = weakref.WeakValueDictionary()
        self.name = name
        self.events = {}
        self.all_handlers = []

    def clone(self):
        cloned = EventDispatcher(self.name)
        for ev_cls, h in self.events.items():
            cloned.events[ev_cls] = copy.copy(h)
        cloned.all_handlers = copy.copy(self.all_handlers)
        self.children[id(cloned)] = cloned

        return cloned

    def _foreach_children(self, call, *args, **kwargs):
        for c in self.children.values():
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
