# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>
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


import gflags
import logging

from ryu.base import app_manager
from ryu.controller import dispatcher
from ryu.controller.handler import set_ev_cls

LOG = logging.getLogger('ryu.app.event_dumper')

FLAGS = gflags.FLAGS
gflags.DEFINE_multistring('dump_queue', [],
                          'list of dispatcher name to dump event: default any')
gflags.DEFINE_multistring('dump_dispatcher', [],
                          'list of dispatcher name to dump event: default any')


class EventDumper(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(EventDumper, self).__init__(*args, **kwargs)
        # EventDispatcher can be created and cloned before us.
        # So register it explicitly
        for ev_q in dispatcher.EventQueue.all_instances():
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
