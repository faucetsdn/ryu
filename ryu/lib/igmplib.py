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
import struct

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import addrconv
from ryu.lib import hub
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import igmp


class EventPacketIn(event.EventBase):
    """a PacketIn event class using except IGMP."""

    def __init__(self, msg):
        """initialization."""
        super(EventPacketIn, self).__init__()
        self.msg = msg


MG_GROUP_ADDED = 1
MG_MEMBER_CHANGED = 2
MG_GROUP_REMOVED = 3


class EventMulticastGroupStateChanged(event.EventBase):
    """a event class that notifies the changes of the statuses of the
    multicast groups."""

    def __init__(self, reason, address, src, dsts):
        """
        ========= =====================================================
        Attribute Description
        ========= =====================================================
        reason    why the event occurs. use one of MG_*.
        address   a multicast group address.
        src       a port number in which a querier exists.
        dsts      a list of port numbers in which the members exist.
        ========= =====================================================
        """
        super(EventMulticastGroupStateChanged, self).__init__()
        self.reason = reason
        self.address = address
        self.src = src
        self.dsts = dsts


class IgmpLib(app_manager.RyuApp):
    """IGMP snooping library."""

    # -------------------------------------------------------------------
    # PUBLIC METHODS
    # -------------------------------------------------------------------
    def __init__(self):
        """initialization."""
        super(IgmpLib, self).__init__()
        self.name = 'igmplib'
        self._querier = IgmpQuerier()
        self._snooper = IgmpSnooper(self.send_event_to_observers)

    def set_querier_mode(self, dpid, server_port):
        """set a datapath id and server port number to the instance
        of IgmpQuerier.

        ============ ==================================================
        Attribute    Description
        ============ ==================================================
        dpid         the datapath id that will operate as a querier.
        server_port  the port number linked to the multicasting server.
        ============ ==================================================
        """
        self._querier.set_querier_mode(dpid, server_port)

    # -------------------------------------------------------------------
    # PUBLIC METHODS ( EVENT HANDLERS )
    # -------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, evt):
        """PacketIn event handler. when the received packet was IGMP,
        proceed it. otherwise, send a event."""
        msg = evt.msg
        dpid = msg.datapath.id

        req_pkt = packet.Packet(msg.data)
        req_igmp = req_pkt.get_protocol(igmp.igmp)
        if req_igmp:
            if self._querier.dpid == dpid:
                self._querier.packet_in_handler(req_igmp, msg)
            else:
                self._snooper.packet_in_handler(req_pkt, req_igmp, msg)
        else:
            self.send_event_to_observers(EventPacketIn(msg))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, evt):
        """StateChange event handler."""
        datapath = evt.datapath
        assert datapath is not None
        if datapath.id == self._querier.dpid:
            if evt.state == MAIN_DISPATCHER:
                self._querier.start_loop(datapath)
            elif evt.state == DEAD_DISPATCHER:
                self._querier.stop_loop()


class IgmpBase(object):
    """IGMP abstract class library."""

    # -------------------------------------------------------------------
    # PUBLIC METHODS
    # -------------------------------------------------------------------
    def __init__(self):
        self._set_flow_func = {
            ofproto_v1_0.OFP_VERSION: self._set_flow_entry_v1_0,
            ofproto_v1_2.OFP_VERSION: self._set_flow_entry_v1_2,
            ofproto_v1_3.OFP_VERSION: self._set_flow_entry_v1_2,
        }
        self._del_flow_func = {
            ofproto_v1_0.OFP_VERSION: self._del_flow_entry_v1_0,
            ofproto_v1_2.OFP_VERSION: self._del_flow_entry_v1_2,
            ofproto_v1_3.OFP_VERSION: self._del_flow_entry_v1_2,
        }

    # -------------------------------------------------------------------
    # PROTECTED METHODS ( RELATED TO OPEN FLOW PROTOCOL )
    # -------------------------------------------------------------------
    def _set_flow_entry_v1_0(self, datapath, actions, in_port, dst,
                             src=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            dl_type=ether.ETH_TYPE_IP, in_port=in_port,
            nw_src=self._ipv4_text_to_int(src),
            nw_dst=self._ipv4_text_to_int(dst))
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, actions=actions)
        datapath.send_msg(mod)

    def _set_flow_entry_v1_2(self, datapath, actions, in_port, dst,
                             src=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP, in_port=in_port, ipv4_dst=dst)
        if src is not None:
            match.append_field(ofproto.OXM_OF_IPV4_SRC, src)
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_ADD,
            priority=65535, match=match, instructions=inst)
        datapath.send_msg(mod)

    def _set_flow_entry(self, datapath, actions, in_port, dst, src=None):
        """set a flow entry."""
        set_flow = self._set_flow_func.get(datapath.ofproto.OFP_VERSION)
        assert set_flow
        set_flow(datapath, actions, in_port, dst, src)

    def _del_flow_entry_v1_0(self, datapath, in_port, dst, src=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            dl_type=ether.ETH_TYPE_IP, in_port=in_port,
            nw_src=self._ipv4_text_to_int(src),
            nw_dst=self._ipv4_text_to_int(dst))
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

    def _del_flow_entry_v1_2(self, datapath, in_port, dst, src=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP, in_port=in_port, ipv4_dst=dst)
        if src is not None:
            match.append_field(ofproto.OXM_OF_IPV4_SRC, src)
        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=match)
        datapath.send_msg(mod)

    def _del_flow_entry(self, datapath, in_port, dst, src=None):
        """remove a flow entry."""
        del_flow = self._del_flow_func.get(datapath.ofproto.OFP_VERSION)
        assert del_flow
        del_flow(datapath, in_port, dst, src)

    def _do_packet_out(self, datapath, data, in_port, actions):
        """send a packet."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            data=data, in_port=in_port, actions=actions)
        datapath.send_msg(out)

    # -------------------------------------------------------------------
    # PROTECTED METHODS ( OTHERS )
    # -------------------------------------------------------------------
    def _ipv4_text_to_int(self, ip_text):
        """convert ip v4 string to integer."""
        if ip_text is None:
            return None
        assert isinstance(ip_text, str)
        return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]


class IgmpQuerier(IgmpBase):
    """IGMP querier emulation class library.

    this querier is a simplified implementation, and is not based on RFC,
    for example as following points:
    - ignore some constant values
    - does not send a specific QUERY in response to LEAVE
    - and so on
    """

    # -------------------------------------------------------------------
    # PUBLIC METHODS
    # -------------------------------------------------------------------
    def __init__(self):
        """initialization."""
        super(IgmpQuerier, self).__init__()
        self.name = "IgmpQuerier"
        self.logger = logging.getLogger(self.name)
        self.dpid = None
        self.server_port = None

        self._datapath = None
        self._querier_thread = None

        # the structure of self._macst
        #
        # +-------+------------------+
        # | group | port: True/False |
        # |       +------------------+
        # |       |...               |
        # +-------+------------------+
        # | ...                      |
        # +--------------------------+
        #
        # group       multicast address.
        # port        a port number which connect to the group member.
        #             the value indicates that whether a flow entry
        #             was registered.
        self._mcast = {}

        self._set_logger()

    def set_querier_mode(self, dpid, server_port):
        """set the datapath to work as a querier. note that you can set
        up only the one querier. when you called this method several
        times, only the last one becomes effective."""
        self.dpid = dpid
        self.server_port = server_port
        if self._querier_thread:
            hub.kill(self._querier_thread)
            self._querier_thread = None

    def packet_in_handler(self, req_igmp, msg):
        """the process when the querier received IGMP."""
        ofproto = msg.datapath.ofproto
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            in_port = msg.in_port
        else:
            in_port = msg.match['in_port']
        if (igmp.IGMP_TYPE_REPORT_V1 == req_igmp.msgtype or
                igmp.IGMP_TYPE_REPORT_V2 == req_igmp.msgtype):
            self._do_report(req_igmp, in_port, msg)
        elif igmp.IGMP_TYPE_LEAVE == req_igmp.msgtype:
            self._do_leave(req_igmp, in_port, msg)

    def start_loop(self, datapath):
        """start QUERY thread."""
        self._datapath = datapath
        self._querier_thread = hub.spawn(self._send_query)
        self.logger.info("started a querier.")

    def stop_loop(self):
        """stop QUERY thread."""
        hub.kill(self._querier_thread)
        self._querier_thread = None
        self._datapath = None
        self.logger.info("stopped a querier.")

    # -------------------------------------------------------------------
    # PRIVATE METHODS ( RELATED TO IGMP )
    # -------------------------------------------------------------------
    def _send_query(self):
        """ send a QUERY message periodically."""
        timeout = 60
        ofproto = self._datapath.ofproto
        parser = self._datapath.ofproto_parser
        if ofproto_v1_0.OFP_VERSION == ofproto.OFP_VERSION:
            send_port = ofproto.OFPP_NONE
        else:
            send_port = ofproto.OFPP_ANY

        # create a general query.
        res_igmp = igmp.igmp(
            msgtype=igmp.IGMP_TYPE_QUERY,
            maxresp=igmp.QUERY_RESPONSE_INTERVAL * 10,
            csum=0,
            address='0.0.0.0')
        res_ipv4 = ipv4.ipv4(
            total_length=len(ipv4.ipv4()) + len(res_igmp),
            proto=inet.IPPROTO_IGMP, ttl=1,
            src='0.0.0.0',
            dst=igmp.MULTICAST_IP_ALL_HOST)
        res_ether = ethernet.ethernet(
            dst=igmp.MULTICAST_MAC_ALL_HOST,
            src=self._datapath.ports[ofproto.OFPP_LOCAL].hw_addr,
            ethertype=ether.ETH_TYPE_IP)
        res_pkt = packet.Packet()
        res_pkt.add_protocol(res_ether)
        res_pkt.add_protocol(res_ipv4)
        res_pkt.add_protocol(res_igmp)
        res_pkt.serialize()

        flood = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        while True:
            # reset reply status.
            for status in self._mcast.values():
                for port in status.keys():
                    status[port] = False

            # send a general query to the host that sent this message.
            self._do_packet_out(
                self._datapath, res_pkt.data, send_port, flood)
            hub.sleep(igmp.QUERY_RESPONSE_INTERVAL)

            # QUERY timeout expired.
            del_groups = []
            for group, status in self._mcast.items():
                del_ports = []
                actions = []
                for port in status.keys():
                    if not status[port]:
                        del_ports.append(port)
                    else:
                        actions.append(parser.OFPActionOutput(port))
                if len(actions) and len(del_ports):
                    self._set_flow_entry(
                        self._datapath, actions, self.server_port, group)
                if not len(actions):
                    self._del_flow_entry(
                        self._datapath, self.server_port, group)
                    del_groups.append(group)
                if len(del_ports):
                    for port in del_ports:
                        self._del_flow_entry(self._datapath, port, group)
                for port in del_ports:
                    del status[port]
            for group in del_groups:
                del self._mcast[group]

            rest_time = timeout - igmp.QUERY_RESPONSE_INTERVAL
            hub.sleep(rest_time)

    def _do_report(self, report, in_port, msg):
        """the process when the querier received a REPORT message."""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            size = 65535
        else:
            size = ofproto.OFPCML_MAX

        update = False
        self._mcast.setdefault(report.address, {})
        if in_port not in self._mcast[report.address]:
            update = True
        self._mcast[report.address][in_port] = True

        if update:
            actions = []
            for port in self._mcast[report.address]:
                actions.append(parser.OFPActionOutput(port))
            self._set_flow_entry(
                datapath, actions, self.server_port, report.address)
            self._set_flow_entry(
                datapath,
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, size)],
                in_port, report.address)

    def _do_leave(self, leave, in_port, msg):
        """the process when the querier received a LEAVE message."""
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        self._mcast.setdefault(leave.address, {})
        if in_port in self._mcast[leave.address]:
            self._del_flow_entry(
                datapath, in_port, leave.address)
            del self._mcast[leave.address][in_port]
            actions = []
            for port in self._mcast[leave.address]:
                actions.append(parser.OFPActionOutput(port))
            if len(actions):
                self._set_flow_entry(
                    datapath, actions, self.server_port, leave.address)
            else:
                self._del_flow_entry(
                    datapath, self.server_port, leave.address)

    # -------------------------------------------------------------------
    # PRIVATE METHODS ( OTHERS )
    # -------------------------------------------------------------------
    def _set_logger(self):
        """change log format."""
        self.logger.propagate = False
        hdl = logging.StreamHandler()
        fmt_str = '[querier][%(levelname)s] %(message)s'
        hdl.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdl)


class IgmpSnooper(IgmpBase):
    """IGMP snooping class library."""

    # -------------------------------------------------------------------
    # PUBLIC METHODS
    # -------------------------------------------------------------------
    def __init__(self, send_event):
        """initialization."""
        super(IgmpSnooper, self).__init__()
        self.name = "IgmpSnooper"
        self.logger = logging.getLogger(self.name)
        self._send_event = send_event

        # the structure of self._to_querier
        #
        # +------+--------------+
        # | dpid | 'port': port |
        # |      +--------------+
        # |      | 'ip': ip     |
        # |      +--------------+
        # |      | 'mac': mac   |
        # +------+--------------+
        # | ...                 |
        # +---------------------+
        #
        # dpid        datapath id.
        # port        a port number which connect to the querier.
        # ip          IP address of the querier.
        # mac         MAC address of the querier.
        self._to_querier = {}

        # the structure of self._to_hosts
        #
        # +------+-------+---------------------------------+
        # | dpid | group | 'replied': True/False           |
        # |      |       +---------------------------------+
        # |      |       | 'leave': leave                  |
        # |      |       +-----------+--------+------------+
        # |      |       | 'ports'   | portno | 'out': out |
        # |      |       |           |        +------------+
        # |      |       |           |        | 'in': in   |
        # |      |       |           +--------+------------+
        # |      |       |           | ...                 |
        # |      +-------+-----------+---------------------+
        # |      | ...                                     |
        # +------+-----------------------------------------+
        # | ...                                            |
        # +------------------------------------------------+
        #
        # dpid        datapath id.
        # group       multicast address.
        # replied     the value indicates whether a REPORT message was
        #             replied.
        # leave       a LEAVE message.
        # portno      a port number which has joined to the multicast
        #             group.
        # out         the value indicates whether a flow entry for the
        #             packet outputted to the port was registered.
        # in          the value indicates whether a flow entry for the
        #             packet inputted from the port was registered.
        self._to_hosts = {}

        self._set_logger()

    def packet_in_handler(self, req_pkt, req_igmp, msg):
        """the process when the snooper received IGMP."""
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            in_port = msg.in_port
        else:
            in_port = msg.match['in_port']

        log = "SW=%s PORT=%d IGMP received. " % (
            dpid_to_str(dpid), in_port)
        self.logger.debug(str(req_igmp))
        if igmp.IGMP_TYPE_QUERY == req_igmp.msgtype:
            self.logger.info(log + "[QUERY]")
            (req_ipv4, ) = req_pkt.get_protocols(ipv4.ipv4)
            (req_eth, ) = req_pkt.get_protocols(ethernet.ethernet)
            self._do_query(req_igmp, req_ipv4, req_eth, in_port, msg)
        elif (igmp.IGMP_TYPE_REPORT_V1 == req_igmp.msgtype or
              igmp.IGMP_TYPE_REPORT_V2 == req_igmp.msgtype):
            self.logger.info(log + "[REPORT]")
            self._do_report(req_igmp, in_port, msg)
        elif igmp.IGMP_TYPE_LEAVE == req_igmp.msgtype:
            self.logger.info(log + "[LEAVE]")
            self._do_leave(req_igmp, in_port, msg)
        elif igmp.IGMP_TYPE_REPORT_V3 == req_igmp.msgtype:
            self.logger.info(log + "V3 is not supported yet.")
            self._do_flood(in_port, msg)
        else:
            self.logger.info(log + "[unknown type:%d]",
                             req_igmp.msgtype)
            self._do_flood(in_port, msg)

    # -------------------------------------------------------------------
    # PRIVATE METHODS ( RELATED TO IGMP )
    # -------------------------------------------------------------------
    def _do_query(self, query, iph, eth, in_port, msg):
        """the process when the snooper received a QUERY message."""
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # learn the querier.
        self._to_querier[dpid] = {
            'port': in_port,
            'ip': iph.src,
            'mac': eth.src
        }

        # set the timeout time.
        timeout = igmp.QUERY_RESPONSE_INTERVAL
        if query.maxresp:
            timeout = query.maxresp / 10

        self._to_hosts.setdefault(dpid, {})
        if query.address == '0.0.0.0':
            # general query. reset all reply status.
            for group in self._to_hosts[dpid].values():
                group['replied'] = False
                group['leave'] = None
        else:
            # specific query. reset the reply status of the specific
            # group.
            group = self._to_hosts[dpid].get(query.address)
            if group:
                group['replied'] = False
                group['leave'] = None

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._do_packet_out(
            datapath, msg.data, in_port, actions)

        # wait for REPORT messages.
        hub.spawn(self._do_timeout_for_query, timeout, datapath)

    def _do_report(self, report, in_port, msg):
        """the process when the snooper received a REPORT message."""
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            size = 65535
        else:
            size = ofproto.OFPCML_MAX

        # check whether the querier port has been specified.
        outport = None
        value = self._to_querier.get(dpid)
        if value:
            outport = value['port']

        # send a event when the multicast group address is new.
        self._to_hosts.setdefault(dpid, {})
        if not self._to_hosts[dpid].get(report.address):
            self._send_event(
                EventMulticastGroupStateChanged(
                    MG_GROUP_ADDED, report.address, outport, []))
            self._to_hosts[dpid].setdefault(
                report.address,
                {'replied': False, 'leave': None, 'ports': {}})

        # set a flow entry from a host to the controller when
        # a host sent a REPORT message.
        if not self._to_hosts[dpid][report.address]['ports'].get(
                in_port):
            self._to_hosts[dpid][report.address]['ports'][
                in_port] = {'out': False, 'in': False}
            self._set_flow_entry(
                datapath,
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, size)],
                in_port, report.address)

        if not self._to_hosts[dpid][report.address]['ports'][
                in_port]['out']:
            self._to_hosts[dpid][report.address]['ports'][
                in_port]['out'] = True

        if not outport:
            self.logger.info("no querier exists.")
            return

        # set a flow entry from a multicast server to hosts.
        if not self._to_hosts[dpid][report.address]['ports'][
                in_port]['in']:
            actions = []
            ports = []
            for port in self._to_hosts[dpid][report.address]['ports']:
                actions.append(parser.OFPActionOutput(port))
                ports.append(port)
            self._send_event(
                EventMulticastGroupStateChanged(
                    MG_MEMBER_CHANGED, report.address, outport, ports))
            self._set_flow_entry(
                datapath, actions, outport, report.address)
            self._to_hosts[dpid][report.address]['ports'][
                in_port]['in'] = True

        # send a REPORT message to the querier if this message arrived
        # first after a QUERY message was sent.
        if not self._to_hosts[dpid][report.address]['replied']:
            actions = [parser.OFPActionOutput(outport, size)]
            self._do_packet_out(datapath, msg.data, in_port, actions)
            self._to_hosts[dpid][report.address]['replied'] = True

    def _do_leave(self, leave, in_port, msg):
        """the process when the snooper received a LEAVE message."""
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # check whether the querier port has been specified.
        if not self._to_querier.get(dpid):
            self.logger.info("no querier exists.")
            return

        # save this LEAVE message and reset the condition of the port
        # that received this message.
        self._to_hosts.setdefault(dpid, {})
        self._to_hosts[dpid].setdefault(
            leave.address,
            {'replied': False, 'leave': None, 'ports': {}})
        self._to_hosts[dpid][leave.address]['leave'] = msg
        self._to_hosts[dpid][leave.address]['ports'][in_port] = {
            'out': False, 'in': False}

        # create a specific query.
        timeout = igmp.LAST_MEMBER_QUERY_INTERVAL
        res_igmp = igmp.igmp(
            msgtype=igmp.IGMP_TYPE_QUERY,
            maxresp=timeout * 10,
            csum=0,
            address=leave.address)
        res_ipv4 = ipv4.ipv4(
            total_length=len(ipv4.ipv4()) + len(res_igmp),
            proto=inet.IPPROTO_IGMP, ttl=1,
            src=self._to_querier[dpid]['ip'],
            dst=igmp.MULTICAST_IP_ALL_HOST)
        res_ether = ethernet.ethernet(
            dst=igmp.MULTICAST_MAC_ALL_HOST,
            src=self._to_querier[dpid]['mac'],
            ethertype=ether.ETH_TYPE_IP)
        res_pkt = packet.Packet()
        res_pkt.add_protocol(res_ether)
        res_pkt.add_protocol(res_ipv4)
        res_pkt.add_protocol(res_igmp)
        res_pkt.serialize()

        # send a specific query to the host that sent this message.
        actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        self._do_packet_out(datapath, res_pkt.data, in_port, actions)

        # wait for REPORT messages.
        hub.spawn(self._do_timeout_for_leave, timeout, datapath,
                  leave.address, in_port)

    def _do_flood(self, in_port, msg):
        """the process when the snooper received a message of the
        outside for processing. """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._do_packet_out(datapath, msg.data, in_port, actions)

    def _do_timeout_for_query(self, timeout, datapath):
        """the process when the QUERY from the querier timeout expired."""
        dpid = datapath.id

        hub.sleep(timeout)
        outport = self._to_querier[dpid]['port']

        remove_dsts = []
        for dst in self._to_hosts[dpid]:
            if not self._to_hosts[dpid][dst]['replied']:
                # if no REPORT message sent from any members of
                # the group, remove flow entries about the group and
                # send a LEAVE message if exists.
                self._remove_multicast_group(datapath, outport, dst)
                remove_dsts.append(dst)

        for dst in remove_dsts:
            del self._to_hosts[dpid][dst]

    def _do_timeout_for_leave(self, timeout, datapath, dst, in_port):
        """the process when the QUERY from the switch timeout expired."""
        parser = datapath.ofproto_parser
        dpid = datapath.id

        hub.sleep(timeout)
        outport = self._to_querier[dpid]['port']

        if self._to_hosts[dpid][dst]['ports'][in_port]['out']:
            return

        del self._to_hosts[dpid][dst]['ports'][in_port]
        self._del_flow_entry(datapath, in_port, dst)
        actions = []
        ports = []
        for port in self._to_hosts[dpid][dst]['ports']:
            actions.append(parser.OFPActionOutput(port))
            ports.append(port)

        if len(actions):
            self._send_event(
                EventMulticastGroupStateChanged(
                    MG_MEMBER_CHANGED, dst, outport, ports))
            self._set_flow_entry(
                datapath, actions, outport, dst)
            self._to_hosts[dpid][dst]['leave'] = None
        else:
            self._remove_multicast_group(datapath, outport, dst)
            del self._to_hosts[dpid][dst]

    def _remove_multicast_group(self, datapath, outport, dst):
        """remove flow entries about the group and send a LEAVE message
        if exists."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self._send_event(
            EventMulticastGroupStateChanged(
                MG_GROUP_REMOVED, dst, outport, []))
        self._del_flow_entry(datapath, outport, dst)
        for port in self._to_hosts[dpid][dst]['ports']:
            self._del_flow_entry(datapath, port, dst)
        leave = self._to_hosts[dpid][dst]['leave']
        if leave:
            if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                in_port = leave.in_port
            else:
                in_port = leave.match['in_port']
            actions = [parser.OFPActionOutput(outport)]
            self._do_packet_out(
                datapath, leave.data, in_port, actions)

    # -------------------------------------------------------------------
    # PRIVATE METHODS ( OTHERS )
    # -------------------------------------------------------------------
    def _set_logger(self):
        """change log format."""
        self.logger.propagate = False
        hdl = logging.StreamHandler()
        fmt_str = '[snoop][%(levelname)s] %(message)s'
        hdl.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdl)
