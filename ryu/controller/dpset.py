# Copyright (C) 2012, 2013 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
import ryu.exception as ryu_exc

from ryu.lib.dpid import dpid_to_str

LOG = logging.getLogger('ryu.controller.dpset')

DPSET_EV_DISPATCHER = "dpset"


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
        self.ports = []  # port list when enter or leave


class EventPortBase(EventDPBase):
    def __init__(self, dp, port):
        super(EventPortBase, self).__init__(dp)
        self.port = port


class EventPortAdd(EventPortBase):
    def __init__(self, dp, port):
        super(EventPortAdd, self).__init__(dp, port)


class EventPortDelete(EventPortBase):
    def __init__(self, dp, port):
        super(EventPortDelete, self).__init__(dp, port)


class EventPortModify(EventPortBase):
    def __init__(self, dp, new_port):
        super(EventPortModify, self).__init__(dp, new_port)


class PortState(dict):
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port_no, port):
        self[port_no] = port

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, port):
        self[port_no] = port


# this depends on controller::Datapath and dispatchers in handler
class DPSet(app_manager.RyuApp):
    def __init__(self):
        super(DPSet, self).__init__()
        self.name = 'dpset'

        self.dps = {}   # datapath_id => class Datapath
        self.port_state = {}  # datapath_id => ports

    def _register(self, dp):
        assert dp.id is not None
        assert dp.id not in self.dps

        self.dps[dp.id] = dp
        self.port_state[dp.id] = PortState()
        ev = EventDP(dp, True)
        for port in dp.ports.values():
            self._port_added(dp, port)
            ev.ports.append(port)
        self.send_event_to_observers(ev)

    def _unregister(self, dp):
        # Now datapath is already dead, so port status change event doesn't
        # interfere us.
        ev = EventDP(dp, False)
        for port in self.port_state.get(dp.id, {}).values():
            self._port_deleted(dp, port)
            ev.ports.append(port)

        self.send_event_to_observers(ev)

        if dp.id in self.dps:
            del self.dps[dp.id]
            del self.port_state[dp.id]

    def get(self, dp_id):
        return self.dps.get(dp_id)

    def get_all(self):
        return self.dps.items()

    def _port_added(self, datapath, port):
        self.port_state[datapath.id].add(port.port_no, port)

    def _port_deleted(self, datapath, port):
        self.port_state[datapath.id].remove(port.port_no)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        datapath = ev.datapath
        assert datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            LOG.debug('DPSET: register datapath %s', datapath)
            self._register(datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            LOG.debug('DPSET: unregister datapath %s', datapath)
            self._unregister(datapath)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, handler.CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        # ofp_handler.py does the following so we could remove...
        if datapath.ofproto.OFP_VERSION < 0x04:
            datapath.ports = msg.ports

    @set_ev_cls(ofp_event.EventOFPPortStatus, handler.MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        datapath = msg.datapath
        port = msg.desc
        ofproto = datapath.ofproto

        if reason == ofproto.OFPPR_ADD:
            LOG.debug('DPSET: A port was added.' +
                      '(datapath id = %s, port number = %s)',
                      dpid_to_str(datapath.id), port.port_no)
            self._port_added(datapath, port)
            self.send_event_to_observers(EventPortAdd(datapath, port))
        elif reason == ofproto.OFPPR_DELETE:
            LOG.debug('DPSET: A port was deleted.' +
                      '(datapath id = %s, port number = %s)',
                      dpid_to_str(datapath.id), port.port_no)
            self._port_deleted(datapath, port)
            self.send_event_to_observers(EventPortDelete(datapath, port))
        else:
            assert reason == ofproto.OFPPR_MODIFY
            LOG.debug('DPSET: A port was modified.' +
                      '(datapath id = %s, port number = %s)',
                      dpid_to_str(datapath.id), port.port_no)
            self.port_state[datapath.id].modify(port.port_no, port)
            self.send_event_to_observers(EventPortModify(datapath, port))

    def get_port(self, dpid, port_no):
        try:
            return self.port_state[dpid][port_no]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=port_no,
                                       network_id=None)

    def get_ports(self, dpid):
        return self.port_state[dpid].values()
