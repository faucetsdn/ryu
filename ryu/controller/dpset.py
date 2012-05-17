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

import logging

from ryu.controller import event
from ryu.controller import dispatcher
from ryu.controller import dp_type
from ryu.controller import handler
from ryu.controller.handler import set_ev_cls

LOG = logging.getLogger('ryu.controller.dpset')


QUEUE_NAME_DPSET = 'dpset'
DISPATCHER_NAME_DPSET = 'dpset'
DPSET_EV_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_DPSET)


class EventDPBase(event.EventBase):
    def __init__(self, dp):
        super(EventDPBase, self).__init__()
        self.dp = dp


class EventDP(EventDPBase):
    def __init__(self, dp, enter_leave):
        # enter_leave
        # True: dp entered
        # False: dp leaving
        super(EventDP, self).__init__(dp)
        self.enter = enter_leave


# this depends on controller::Datapath and dispatchers in handler
class DPSet(object):
    def __init__(self):
        super(DPSet, self).__init__()

        # dp registration and type setting can be occur in any order
        # Sometimes the sw_type is set before dp connection
        self.dp_types = {}

        self.dps = {}   # datapath_id => class Datapath
        self.ev_q = dispatcher.EventQueue(QUEUE_NAME_DPSET,
                                          DPSET_EV_DISPATCHER)
        handler.register_instance(self)

    def register(self, dp):
        assert dp.id is not None
        assert dp.id not in self.dps

        dp_type_ = self.dp_types.pop(dp.id, None)
        if dp_type_ is not None:
            dp.dp_type = dp_type_

        self.ev_q.queue(EventDP(dp, True))
        self.dps[dp.id] = dp

    def unregister(self, dp):
        if dp.id in self.dps:
            del self.dps[dp.id]
            assert dp.id not in self.dp_types
            self.dp_types[dp.id] = getattr(dp, 'dp_type', dp_type.UNKNOWN)

            self.ev_q.queue(EventDP(dp, False))

    def set_type(self, dp_id, dp_type_=dp_type.UNKNOWN):
        if dp_id in self.dps:
            dp = self.dps[dp_id]
            dp.dp_type = dp_type_
        else:
            assert dp_id not in self.dp_types
            self.dp_types[dp_id] = dp_type_

    def get(self, dp_id):
        return self.dps.get(dp_id, None)

    def get_all(self):
        return self.dps.items()

    @set_ev_cls(dispatcher.EventDispatcherChange,
                dispatcher.QUEUE_EV_DISPATCHER)
    def dispacher_change(self, ev):
        LOG.debug('dispatcher change q %s dispatcher %s',
                  ev.ev_q.name, ev.new_dispatcher.name)
        if ev.ev_q.name != handler.QUEUE_NAME_OFP_MSG:
            return

        datapath = ev.ev_q.aux
        assert datapath is not None
        if ev.new_dispatcher.name == handler.DISPATCHER_NAME_OFP_MAIN:
            LOG.debug('DPSET: register datapath %s', datapath)
            self.register(datapath)
        elif ev.new_dispatcher.name == handler.DISPATCHER_NAME_OFP_DEAD:
            LOG.debug('DPSET: unregister datapath %s', datapath)
            self.unregister(datapath)
