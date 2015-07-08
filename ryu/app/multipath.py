# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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
#
# Author:muzixing
# Time:2014/10/19
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu import utils
import socket

from ryu.lib import addrconv
import struct
import socket

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
IPV4 = ipv4.ipv4.__name__
DST_IPADDR = "10.0.0.2"
SRC_IPADDR = "10.0.0.1"


def ip2long(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


class MULTIPATH_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MULTIPATH_13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, 0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, hard_timeout, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        #print mod.__dict__
        datapath.send_msg(mod)

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug(
            'OFPErrorMsg received: type=0x%02x code=0x%02x '
            'message=%s', msg.type, msg.code, utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        header_list = dict(
            (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            self.arp_table[header_list[ARP].src_ip] = src  # ARP learning
            #print "ARP"

        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            if self.arp_handler(header_list, datapath, in_port, msg.buffer_id):
                # 1:reply or drop;  0: flood
                print "ARP_PROXY_13"
                return None
            else:
                out_port = ofproto.OFPP_FLOOD
                print 'OFPP_FLOOD'

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check the ethertype
            if IPV4 in header_list and dpid == 1:
                src_ip = header_list[IPV4].src
                dst_ip = header_list[IPV4].dst
                if in_port == 1:
                    # src_ip == SRC_IPADDR and dst_ip == DST_IPADDR:
                    self.send_group_mod(datapath)
                    print "send_group_mod"

                    actions = [parser.OFPActionGroup(group_id=50)]
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=eth.ethertype,
                        ipv4_src=src_ip)

                    self.add_flow(datapath, 0, 3, match, actions)
                    actions = []
                    # We know outputs at dpid=1
                    actions.append(parser.OFPActionOutput(2))
                    actions.append(parser.OFPActionOutput(3))

                    self.send_packet_out(msg, actions)
                    #print "send_packet_out"
                    return None

            #Normal flows
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst,
                eth_type=eth.ethertype)
            if IPV4 in header_list and not ICMP in header_list:
                self.add_flow(datapath, 0, 1, match, actions)
            else:
                self.add_flow(datapath, 10, 1, match, actions)

        self.send_packet_out(msg, actions)

    def send_packet_out(self, msg, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def arp_handler(self, header_list, datapath, in_port, msg_buffer_id):
        header_list = header_list
        datapath = datapath
        in_port = in_port

        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                    datapath.send_msg(out)
                    print "\ndrop\n"
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        if ARP in header_list:
            hwtype = header_list[ARP].hwtype
            proto = header_list[ARP].proto
            hlen = header_list[ARP].hlen
            plen = header_list[ARP].plen
            opcode = header_list[ARP].opcode

            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip

            actions = []

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  # arp reply
                    actions.append(datapath.ofproto_parser.OFPActionOutput(
                        in_port)
                    )

                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        #print "flase"
        return False

    def send_group_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        port_1 = 3
        queue_1 = ofp_parser.OFPActionSetQueue(0)
        actions_1 = [queue_1, ofp_parser.OFPActionOutput(port_1)]

        port_2 = 2
        queue_2 = ofp_parser.OFPActionSetQueue(0)
        actions_2 = [queue_2, ofp_parser.OFPActionOutput(port_2)]

        weight_1 = 50
        weight_2 = 50

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        buckets = [
            ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
            ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

        group_id = 50
        req = ofp_parser.OFPGroupMod(
            datapath, ofp.OFPFC_ADD,
            ofp.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)
