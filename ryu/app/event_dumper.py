# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import gflags
import logging

from ryu.controller import dispatcher
from ryu.controller.handler import set_ev_cls

LOG = logging.getLogger('ryu.app.event_dumper')

FLAGS = gflags.FLAGS
gflags.DEFINE_multistring('dump_queue', [],
                          'list of dispatcher name to dump event: default any')
gflags.DEFINE_multistring('dump_dispatcher', [],
                          'list of dispatcher name to dump event: default any')


class EventDumper(object):
    def __init__(self, *_args, **_kwargs):
        # EventDispatcher can be created and cloned before us.
        # So register it explicitly
        for ev_q in dispatcher.EventQueue.event_queues:
            if ev_q == dispatcher.QUEUE_EV_Q:
                continue
            LOG.info('%s: registering q %s dispatcher %s',
                     __name__, ev_q.name, ev_q.dispatcher.name)
            self._register_dump_handler(ev_q, ev_q.dispatcher)

    @staticmethod
    def _need_dump(name, name_list):
        return len(name_list) == 0 or name in name_list

    def _register_dump_handler(self, ev_q, dispatcher):
        if (self._need_dump(ev_q.name, FLAGS.dump_queue) or
            self._need_dump(dispatcher.name, FLAGS.dump_dispatcher)):
            dispatcher.register_all_handler(self._dump_event)

    @set_ev_cls(dispatcher.EventQueueCreate, dispatcher.QUEUE_EV_DISPATCHER)
    def queue_create(self, ev):
        if ev.create:
            LOG.info('%s: queue created %s', __name__, ev.ev_q.name)
        else:
            LOG.info('%s: queue deleted %s', __name__, ev.ev_q.name)

        self._dump_event(ev)
        self._register_dump_handler(ev.ev_q, ev.dispatcher)

    @set_ev_cls(dispatcher.EventDispatcherChange,
                dispatcher.QUEUE_EV_DISPATCHER)
    def dispatcher_change(self, ev):
        LOG.info('%s: dispatcher change q %s dispatcher %s -> %s', __name__,
                 ev.ev_q.name, ev.old_dispatcher.name, ev.new_dispatcher.name)

        self._dump_event(ev)
        self._register_dump_handler(ev.ev_q, ev.new_dispatcher)

    def _dump_event(self, ev):
        LOG.info('%s: event %s', __name__, ev)
