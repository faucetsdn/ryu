# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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
from gevent.queue import Queue

LOG = logging.getLogger('ryu.controller.dispatcher')


class EventQueue(object):
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.is_dispatching = False
        self.ev_q = Queue()

    def set_dispatcher(self, dispatcher):
        self.dispatcher = dispatcher

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


class EventDispatcher(object):
    def __init__(self, name):
        self.name = name
        self.events = {}
        self.all_handlers = []

    def register_all_handler(self, all_handler):
        self.all_handlers.append(all_handler)

    def unregister_all_handler(self, all_handler):
        del self.all_handlers[all_handler]

    def register_handler(self, ev_cls, handler):
        assert callable(handler)
        self.events.setdefault(ev_cls, [])
        self.events[ev_cls].append(handler)

    def register_handlers(self, handlers):
        for ev_cls, h in handlers:
            self.register_handler(ev_cls, h)

    def unregister_handler(self, ev_cls, handler):
        del self.events[ev_cls][handler]

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

    def dispatch(self, ev):
        #LOG.debug('dispatch %s', ev)

        # copy handler list because the list is not stable.
        # event handler may block/switch thread execution
        # and un/register other handlers. And more,
        # handler itself may un/register handlers.
        all_handlers = copy.copy(self.all_handlers)
        for h in all_handlers:
            ret = h(ev)
            if ret is False:
                break

        if ev.__class__ not in self.events:
            LOG.info('unhandled event %s', ev)
            return

        # Is this necessary?
        #
        # copy handler list because the list is not stable.
        # event handler may block/switch thread execution
        # and un/register other handlers.
        #
        handlers = copy.copy(self.events[ev.__class__])

        for h in handlers:
            ret = h(ev)
            if ret is False:
                break
