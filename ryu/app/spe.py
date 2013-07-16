# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# OpenFlow 1.2 upgrade, modified for peering exchanges by Sam Russell 2013
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
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import set_ev_handler
from ryu.ofproto import ofproto_v1_2, ofproto_v1_2_parser, ether
from ryu.lib.mac import haddr_to_str
from ryu.lib import ip
from ryu.lib.packet import packet
import spe_config



# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


class SPE(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPE, self).__init__(*args, **kwargs)
        self.dps = {}
        self.mac_to_port = {}

    def add_flow(self, datapath, table_id, match, instructions, priority=0x8000, buffer_id=ofproto_v1_2.OFP_NO_BUFFER):
        ofproto = datapath.ofproto

        #wildcards = ofproto_v1_2.OFPFW_ALL
        #wildcards &= ~ofproto_v1_2.OFPFW_IN_PORT
        #wildcards &= ~ofproto_v1_2.OFPFW_DL_DST
        # old standard matching - deprecated from 1.2 onwards

        #match = datapath.ofproto_parser.OFPMatch(
        #    wildcards, in_port, 0, dst,
        #    0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        #datapath, cookie, cookie_mask, table_id, command,
        #         idle_timeout, hard_timeout, priority, buffer_id, out_port,
        #         out_group, flags, match, instructions)
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=table_id,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0x8000, buffer_id=buffer_id,
            out_port=ofproto_v1_2.OFPP_ANY, out_group=ofproto_v1_2.OFPG_ANY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, match=match, instructions=instructions)
        datapath.send_msg(mod)
    
    def add_arp_reply_catcher(self, datapath, ipaddr, port, table_id=0):
        match = datapath.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        match.set_arp_opcode(2)
        if port:
            match.set_in_port(port)
        if ipaddr:
            match.set_arp_spa(ipaddr)
        ofproto = datapath.ofproto
        instructions = [datapath.ofproto_parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath, table_id, match, instructions, priority=0x8000)
    
    def add_arp_request_forwarder(self, datapath, ipaddr, port, table_id=0):
        match = datapath.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        match.set_arp_opcode(1)
        match.set_arp_tpa(ipaddr)
        ofproto = datapath.ofproto
        actions = [datapath.ofproto_parser.OFPActionOutput(port, 1500)]
        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, table_id, match, instructions, priority=0x8000)
    
    
    def init_flows(self, datapath):
        ofproto = datapath.ofproto
        for port, ipaddr in spe_config.ports.iteritems():
            self.add_arp_reply_catcher(datapath, ipaddr=ip.ipv4_to_bin(ipaddr), port=port, table_id=1)
            self.add_arp_request_forwarder(datapath, ipaddr=ip.ipv4_to_bin(ipaddr), port=port, table_id=1)
        
        # make a flow to send all ARP packets to table 1
        match = datapath.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        instructions = [datapath.ofproto_parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath, 0, match, instructions)
    

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_enter_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.logger.info("Switch entered: %s", dp.id)
            self.init_flows(dp)
            
        elif ev.state == DEAD_DISPATCHER:
            if dp.id is None:
                return
            self.logger.info("Switch left: %s", dp.id)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        match = msg.match
        in_port = 0
        ethtype = 0
        #iterate through fields - parser should handle this
        #packet in dpid 20015998343868 from 08:00:27:15:d4:53 to ff:ff:ff:ff:ff:ff log_port 0 phy_port 0
        #Field MTInPort(header=2147483652,length=8,n_bytes=4,value=2)
        #Field MTEthType(header=2147486210,length=6,n_bytes=2,value=2054)
        #Field MTArpOp(header=2147494402,length=6,n_bytes=2,value=1)
        #Field MTMetadata(header=2147484680,length=12,n_bytes=8,value=18446744073709551615L)
        #Field MTArpSha(header=2147495942,length=10,n_bytes=6,value="\x08\x00'\x15\xd4S")
        #Field MTEthDst(header=2147485190,length=10,n_bytes=6,value='\xff\xff\xff\xff\xff\xff')
        #Field MTArpSpa(header=2147494916,length=8,n_bytes=4,value=167772161)
        #Field MTArpTha(header=2147496454,length=10,n_bytes=6,value='\x00\x00\x00\x00\x00\x00')
        
        # we should build a dictionary of MTXXXX class names to speed this up
        for o in match.fields:
            self.logger.info("Field %s", str(o))
            if isinstance(o, ofproto_v1_2_parser.MTInPort):
                in_port = o.value
                break

        self.logger.info("packet in dpid %s from %s to %s log_port %s",
                         dpid, haddr_to_str(src), haddr_to_str(dst),
                         in_port)
        
        # parse packet
        
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.next()
        ethtype = eth_pkt.ethertype
        
        # if ARP (request) then flood and don't make a flow
        if ethtype == ether.ETH_TYPE_ARP:
            # if ARP reply then drop
            arp_pkt = pkt.next()
            if arp_pkt.opcode == 2:
                # check config
                if ip.ipv4_to_bin(spe_config.ports[in_port]) != arp_pkt.src_ip:
                    self.logger.info("Dropping spoofed ARP from port %d IP %s (expected IP %s)", in_port, ip.ipv4_to_str(arp_pkt.src_ip), spe_config.ports[in_port])
                    return
            out_port = ofproto_v1_2.OFPP_FLOOD
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 1500)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions)
            datapath.send_msg(out)
        
        # do we know the mac?
        #if src not in self.mac_to_port[dpid]:
        #    # learn the mac address to avoid FLOOD next time.
        #    self.mac_to_port[dpid][src] = in_port
        #    # set a flow to table 0 to allow packets through to table 1
        #    match = datapath.ofproto_parser.OFPMatch()
        #    match.set_in_port(in_port)
        #    match.set_dl_src(src)
        #    match.set_dl_type(ethtype)
        #    instructions = [datapath.ofproto_parser.OFPInstructionGotoTable(2)]
        #    self.add_flow(datapath, 0, match, instructions)
        #    
        #
        #if dst in self.mac_to_port[dpid]:
        #    out_port = self.mac_to_port[dpid][dst]
        #    match = datapath.ofproto_parser.OFPMatch()
        #    match.set_dl_dst(dst)
        #    actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 1500)]
        #    instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        #    self.add_flow(datapath, 2, match, instructions, buffer_id=msg.buffer_id)
        #else:
        #    out_port = ofproto_v1_2.OFPP_FLOOD
        #    actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 1500)]
        #    out = datapath.ofproto_parser.OFPPacketOut(
        #        datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
        #        actions=actions)
        #    datapath.send_msg(out)
        
        # new way of handling this
        # if packet got to us then we probably don't know the MAC
        # so add table->2 flow to first table, and out action on table 2
        
        # learn the mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        # set a flow to table 0 to allow packets through to table 1
        match = datapath.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        match.set_dl_src(src)
        match.set_dl_type(ethtype)
        instructions = [datapath.ofproto_parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath, 0, match, instructions)
        
        match = datapath.ofproto_parser.OFPMatch()
        match.set_dl_dst(src)
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port, 1500)]
        instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 2, match, instructions)
        
        # then, just in case there's no out flow, we'll do that too
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            match = datapath.ofproto_parser.OFPMatch()
            match.set_dl_dst(dst)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 1500)]
            instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, 2, match, instructions, buffer_id=msg.buffer_id)
        else:
            out_port = ofproto_v1_2.OFPP_FLOOD
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 1500)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)
