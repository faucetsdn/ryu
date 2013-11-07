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

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import addrconv
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import slow


LAG_EV_DISPATCHER = "lacplib"


class EventPacketIn(event.EventBase):
    """a PacketIn event class using except LACP."""
    def __init__(self, msg):
        """initialization."""
        super(EventPacketIn, self).__init__()
        self.msg = msg


class EventSlaveStateChanged(event.EventBase):
    """a event class that notifies the changes of the statuses of the
    slave i/fs."""
    def __init__(self, datapath, port, enabled):
        """initialization."""
        super(EventSlaveStateChanged, self).__init__()
        self.datapath = datapath
        self.port = port
        self.enabled = enabled


class LacpLib(app_manager.RyuApp):
    """LACP exchange library. this works only in a PASSIVE mode."""

    #-------------------------------------------------------------------
    # PUBLIC METHODS
    #-------------------------------------------------------------------
    def __init__(self):
        """initialization."""
        super(LacpLib, self).__init__()
        self.name = 'lacplib'
        self._bonds = []
        self._add_flow = {
            ofproto_v1_0.OFP_VERSION: self._add_flow_v1_0,
            ofproto_v1_2.OFP_VERSION: self._add_flow_v1_2,
            ofproto_v1_3.OFP_VERSION: self._add_flow_v1_2,
        }
        self._set_logger()

    def add(self, dpid, ports):
        """add a setting of a bonding i/f.
        'add' method takes the corresponding args in this order.

        ========= =====================================================
        Attribute Description
        ========= =====================================================
        dpid      datapath id.

        ports     a list of integer values that means the ports face
                  with the slave i/fs.
        ========= =====================================================

        if you want to use multi LAG, call 'add' method more than once.
        """
        assert isinstance(ports, list)
        assert 2 <= len(ports)
        ifs = {}
        for port in ports:
            ifs[port] = {'enabled': False, 'timeout': 0}
        bond = {}
        bond[dpid] = ifs
        self._bonds.append(bond)

    #-------------------------------------------------------------------
    # PUBLIC METHODS ( EVENT HANDLERS )
    #-------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, evt):
        """PacketIn event handler. when the received packet was LACP,
        proceed it. otherwise, send a event."""
        req_pkt = packet.Packet(evt.msg.data)
        if slow.lacp in req_pkt:
            (req_lacp, ) = req_pkt.get_protocols(slow.lacp)
            (req_eth, ) = req_pkt.get_protocols(ethernet.ethernet)
            self._do_lacp(req_lacp, req_eth.src, evt.msg)
        else:
            self.send_event_to_observers(EventPacketIn(evt.msg))

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, evt):
        """FlowRemoved event handler. when the removed flow entry was
        for LACP, set the status of the slave i/f to disabled, and
        send a event."""
        msg = evt.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        match = msg.match
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            port = match.in_port
            dl_type = match.dl_type
        else:
            port = match['in_port']
            dl_type = match['eth_type']
        if ether.ETH_TYPE_SLOW != dl_type:
            return
        self.logger.info(
            "SW=%s PORT=%d LACP exchange timeout has occurred.",
            dpid_to_str(dpid), port)
        self._set_slave_enabled(dpid, port, False)
        self._set_slave_timeout(dpid, port, 0)
        self.send_event_to_observers(
            EventSlaveStateChanged(datapath, port, False))

    #-------------------------------------------------------------------
    # PRIVATE METHODS ( RELATED TO LACP )
    #-------------------------------------------------------------------
    def _do_lacp(self, req_lacp, src, msg):
        """packet-in process when the received packet is LACP."""
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            port = msg.in_port
        else:
            port = msg.match['in_port']

        self.logger.info("SW=%s PORT=%d LACP received.",
                         dpid_to_str(dpid), port)
        self.logger.debug(str(req_lacp))

        # when LACP arrived at disabled port, update the status of
        # the slave i/f to enabled, and send a event.
        if not self._get_slave_enabled(dpid, port):
            self.logger.info(
                "SW=%s PORT=%d the slave i/f has just been up.",
                dpid_to_str(dpid), port)
            self._set_slave_enabled(dpid, port, True)
            self.send_event_to_observers(
                EventSlaveStateChanged(datapath, port, True))

        # set the idle_timeout time using the actor state of the
        # received packet.
        if req_lacp.LACP_STATE_SHORT_TIMEOUT == \
           req_lacp.actor_state_timeout:
            idle_timeout = req_lacp.SHORT_TIMEOUT_TIME
        else:
            idle_timeout = req_lacp.LONG_TIMEOUT_TIME

        # when the timeout time has changed, update the timeout time of
        # the slave i/f and re-enter a flow entry for the packet from
        # the slave i/f with idle_timeout.
        if idle_timeout != self._get_slave_timeout(dpid, port):
            self.logger.info(
                "SW=%s PORT=%d the timeout time has changed.",
                dpid_to_str(dpid), port)
            self._set_slave_timeout(dpid, port, idle_timeout)
            func = self._add_flow.get(ofproto.OFP_VERSION)
            assert func
            func(src, port, idle_timeout, datapath)

        # create a response packet.
        res_pkt = self._create_response(datapath, port, req_lacp)

        # packet-out the response packet.
        out_port = ofproto.OFPP_IN_PORT
        actions = [parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            data=res_pkt.data, in_port=port, actions=actions)
        datapath.send_msg(out)

    def _create_response(self, datapath, port, req):
        """create a packet including LACP."""
        src = datapath.ports[port].hw_addr
        res_ether = ethernet.ethernet(
            slow.SLOW_PROTOCOL_MULTICAST, src, ether.ETH_TYPE_SLOW)
        res_lacp = self._create_lacp(datapath, port, req)
        res_pkt = packet.Packet()
        res_pkt.add_protocol(res_ether)
        res_pkt.add_protocol(res_lacp)
        res_pkt.serialize()
        return res_pkt

    def _create_lacp(self, datapath, port, req):
        """create a LACP packet."""
        actor_system = datapath.ports[datapath.ofproto.OFPP_LOCAL].hw_addr
        res = slow.lacp(
            actor_system_priority=0xffff,
            actor_system=actor_system,
            actor_key=req.actor_key,
            actor_port_priority=0xff,
            actor_port=port,
            actor_state_activity=req.LACP_STATE_PASSIVE,
            actor_state_timeout=req.actor_state_timeout,
            actor_state_aggregation=req.actor_state_aggregation,
            actor_state_synchronization=req.actor_state_synchronization,
            actor_state_collecting=req.actor_state_collecting,
            actor_state_distributing=req.actor_state_distributing,
            actor_state_defaulted=req.LACP_STATE_OPERATIONAL_PARTNER,
            actor_state_expired=req.LACP_STATE_NOT_EXPIRED,
            partner_system_priority=req.actor_system_priority,
            partner_system=req.actor_system,
            partner_key=req.actor_key,
            partner_port_priority=req.actor_port_priority,
            partner_port=req.actor_port,
            partner_state_activity=req.actor_state_activity,
            partner_state_timeout=req.actor_state_timeout,
            partner_state_aggregation=req.actor_state_aggregation,
            partner_state_synchronization=req.actor_state_synchronization,
            partner_state_collecting=req.actor_state_collecting,
            partner_state_distributing=req.actor_state_distributing,
            partner_state_defaulted=req.actor_state_defaulted,
            partner_state_expired=req.actor_state_expired,
            collector_max_delay=0)
        self.logger.info("SW=%s PORT=%d LACP sent.",
                         dpid_to_str(datapath.id), port)
        self.logger.debug(str(res))
        return res

    def _get_slave_enabled(self, dpid, port):
        """get whether a slave i/f at some port of some datapath is
        enable or not."""
        slave = self._get_slave(dpid, port)
        if slave:
            return slave['enabled']
        else:
            return False

    def _set_slave_enabled(self, dpid, port, enabled):
        """set whether a slave i/f at some port of some datapath is
        enable or not."""
        slave = self._get_slave(dpid, port)
        if slave:
            slave['enabled'] = enabled

    def _get_slave_timeout(self, dpid, port):
        """get the timeout time at some port of some datapath."""
        slave = self._get_slave(dpid, port)
        if slave:
            return slave['timeout']
        else:
            return 0

    def _set_slave_timeout(self, dpid, port, timeout):
        """set the timeout time at some port of some datapath."""
        slave = self._get_slave(dpid, port)
        if slave:
            slave['timeout'] = timeout

    def _get_slave(self, dpid, port):
        """get slave i/f at some port of some datapath."""
        result = None
        for bond in self._bonds:
            if dpid in bond:
                if port in bond[dpid]:
                    result = bond[dpid][port]
                    break
        return result

    #-------------------------------------------------------------------
    # PRIVATE METHODS ( RELATED TO OPEN FLOW PROTOCOL )
    #-------------------------------------------------------------------
    def _add_flow_v1_0(self, src, port, timeout, datapath):
        """enter a flow entry for the packet from the slave i/f
        with idle_timeout. for OpenFlow ver1.0."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=port, dl_src=addrconv.mac.text_to_bin(src),
            dl_type=ether.ETH_TYPE_SLOW)
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, 65535)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=timeout,
            priority=65535, flags=ofproto.OFPFF_SEND_FLOW_REM,
            actions=actions)
        datapath.send_msg(mod)

    def _add_flow_v1_2(self, src, port, timeout, datapath):
        """enter a flow entry for the packet from the slave i/f
        with idle_timeout. for OpenFlow ver1.2 and ver1.3."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=port, eth_src=src, eth_type=ether.ETH_TYPE_SLOW)
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_MAX)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_ADD,
            idle_timeout=timeout, priority=65535,
            flags=ofproto.OFPFF_SEND_FLOW_REM, match=match,
            instructions=inst)
        datapath.send_msg(mod)

    #-------------------------------------------------------------------
    # PRIVATE METHODS ( OTHERS )
    #-------------------------------------------------------------------
    def _set_logger(self):
        """change log format."""
        self.logger.propagate = False
        hdl = logging.StreamHandler()
        fmt_str = '[LACP][%(levelname)s] %(message)s'
        hdl.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdl)
