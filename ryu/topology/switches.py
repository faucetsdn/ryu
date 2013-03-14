# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

from ryu.topology import event
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER

LOG = logging.getLogger(__name__)


class Port(object):
    # This is data class passed by EventPortXXX
    def __init__(self, dpid, ofproto, ofpport):
        super(Port, self).__init__()

        self.dpid = dpid
        self._ofproto = ofproto
        self._config = ofpport.config
        self._state = ofpport.state

        self.port_no = ofpport.port_no
        self.hw_addr = ofpport.hw_addr
        self.name = ofpport.name

    def is_reserved(self):
        return self.port_no > self._ofproto.OFPP_MAX

    def is_down(self):
        return (self._state & self._ofproto.OFPPS_LINK_DOWN) > 0 \
            or (self._config & self._ofproto.OFPPC_PORT_DOWN) > 0

    def is_live(self):
        # NOTE: OF1.2 has OFPPS_LIVE state
        #       return (self._state & self._ofproto.OFPPS_LIVE) > 0
        return not self.is_down()

    # for Switch.del_port()
    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        return 'Port<dpid=%s, port_no=%s, %s>' % \
            (self.dpid, self.port_no, LIVE_MSG[self.is_live()])


class Switch(object):
    # This is data class passed by EventSwitchXXX
    def __init__(self, dp):
        super(Switch, self).__init__()

        self.dp = dp
        self.ports = []

    def add_port(self, ofpport):
        port = Port(self.dp.id, self.dp.ofproto, ofpport)
        if not port.is_reserved():
            self.ports.append(port)

    def del_port(self, ofpport):
        self.ports.remove(Port(ofpport))

    def __str__(self):
        msg = 'Switch<dpid=%s, ' % self.dp.id
        for port in self.ports:
            msg += str(port) + ' '

        msg += '>'
        return msg


class PortState(dict):
    # dict: int port_no -> OFPPort port
    # OFPPort is defined in ryu.ofproto.ofproto_v1_X_parser
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port_no, port):
        self[port_no] = port

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, port):
        self[port_no] = port


class Switches(app_manager.RyuApp):
    _EVENTS = [event.EventSwitchEnter, event.EventSwitchLeave,
               event.EventPortAdd, event.EventPortDelete,
               event.EventPortModify]

    def __init__(self):
        super(Switches, self).__init__()

        self.name = 'switches'
        self.dps = {}   # datapath_id => class Datapath
        self.port_state = {}  # datapath_id => ports

    def _register(self, dp):
        assert dp.id is not None
        assert dp.id not in self.dps

        self.dps[dp.id] = dp
        self.port_state[dp.id] = PortState()
        for port in dp.ports.values():
            self.port_state[dp.id].add(port.port_no, port)

    def _unregister(self, dp):
        if dp.id in self.dps:
            del self.dps[dp.id]
            del self.port_state[dp.id]

    def _get_switch(self, dp):
        switch = Switch(dp)
        for ofpport in self.port_state[dp.id].itervalues():
            switch.add_port(ofpport)
        return switch

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        assert dp is not None
        LOG.debug(dp)

        if ev.state == MAIN_DISPATCHER:
            self._register(dp)
            switch = self._get_switch(dp)
            LOG.debug('register %s', switch)
            self.send_event_to_observers(event.EventSwitchEnter(switch))

        elif ev.state == DEAD_DISPATCHER:
            # dp.id is None when datapath dies before handshake
            if dp.id is None:
                return
            switch = self._get_switch(dp)
            self._unregister(dp)
            LOG.debug('unregister %s', switch)
            self.send_event_to_observers(event.EventSwitchLeave(switch))

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        dp = msg.datapath
        ofpport = msg.desc

        if reason == dp.ofproto.OFPPR_ADD:
            #LOG.debug('A port was added.' +
            #          '(datapath id = %s, port number = %s)',
            #          dp.id, ofpport.port_no)
            self.port_state[dp.id].add(ofpport.port_no, ofpport)
            self.send_event_to_observers(
                event.EventPortAdd(Port(dp.id, dp.ofproto, ofpport)))

        elif reason == dp.ofproto.OFPPR_DELETE:
            #LOG.debug('A port was deleted.' +
            #          '(datapath id = %s, port number = %s)',
            #          dp.id, ofpport.port_no)
            self.port_state[dp.id].remove(ofpport.port_no)
            self.send_event_to_observers(
                event.EventPortDelete(Port(dp.id, dp.ofproto, ofpport)))

        else:
            assert reason == dp.ofproto.OFPPR_MODIFY
            #LOG.debug('A port was modified.' +
            #          '(datapath id = %s, port number = %s)',
            #          dp.id, ofpport.port_no)
            self.port_state[dp.id].modify(ofpport.port_no, ofpport)
            self.send_event_to_observers(
                event.EventPortModify(Port(dp.id, dp.ofproto, ofpport)))

    @set_ev_cls(event.EventSwitchRequest)
    def switch_request_handler(self, req):
        LOG.debug(req)
        dpid = req.dpid

        switches = []
        if dpid is None:
            # reply all list
            for dp in self.dps.itervalues():
                switches.append(self._get_switch(dp))
        elif dpid in self.dps:
            switches.append(self._get_switch(self.dps[dpid]))

        rep = event.EventSwitchReply(req.src, switches)
        if req.sync:
            self.send_reply(rep)
        else:
            self.send_event(req.src, rep)


def get(app, dpid=None):
    return app.send_request(event.EventSwitchRequest(dpid))


def get_all(app):
    return get(app)
