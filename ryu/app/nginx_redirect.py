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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.ofproto import ether

from ryu.lib import addrconv
import struct
import socket


ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__



CACHE_IP='1.0.0.5'       #Nginx IP
CACHE_MAC='00:00:00:00:00:05'#Nginx MAC

NGNIX_REDIRECT_TABLE = 1
NGNIX_PORT = 80

Assigned_IP='192.168.0.2'     #Host who has the priority.

def tableid(buf):
    return struct.unpack_from('15x B', buffer(buf))

def ip2long(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

class Ngnix_Redirect(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Ngnix_Redirect, self).__init__(*args, **kwargs)
        self.IPinService = ['1.0.0.1', '1.0.0.2']
        self.agent_table={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.set_default_flow(datapath)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.

    def add_flow(self, datapath, priority, idle_timeout, hard_timeout, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=NGNIX_REDIRECT_TABLE, 
                                idle_timeout = idle_timeout, hard_timeout = hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def set_default_flow(self, datapath, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        inst = []
        inst.append(parser.OFPInstructionGotoTable(NGNIX_REDIRECT_TABLE + 1))
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, table_id=NGNIX_REDIRECT_TABLE, match=match, instructions=inst)
        datapath.send_msg(mod)
        
        match = parser.OFPMatch()
        match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, 0x0800)
        match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO, 6)
        match.append_field(ofproto_v1_3.OXM_OF_TCP_DST, NGNIX_PORT)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = []
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(datapath=datapath, priority=1, table_id=NGNIX_REDIRECT_TABLE, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch()
        match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, 0x0800)
        match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO, 6)
        match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC, NGNIX_PORT)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = []
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(datapath=datapath, priority=1, table_id=NGNIX_REDIRECT_TABLE, match=match, instructions=inst)
        datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        table_id = tableid(msg.buf)[0]

        if table_id == NGNIX_REDIRECT_TABLE:
            print "Enter Redirect!"
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            header_list = dict((p.protocol_name, p)
                   for p in packet.Packet(msg.data).protocols if type(p) != str)

            in_port= msg.match['in_port']
            eth_dst= header_list[ETHERNET].dst
            eth_src= header_list[ETHERNET].src 
            ipv4_src = header_list[IPV4].src
            ip_proto = header_list[IPV4].proto
            print ipv4_src
            print type(ipv4_src)
            ipv4_dst = header_list[IPV4].dst
            tcp_src = header_list[TCP].src_port
            tcp_dst = header_list[TCP].dst_port
            eth_type = header_list[ETHERNET].ethertype
            #print type(addrconv.ipv4.text_to_bin(ipv4_dst))
            
            match = parser.OFPMatch()
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, 0x0800)
            match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST_W, ip2long(ipv4_dst),0xffffffff)
            match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC_W, ip2long(ipv4_src),0xffffffff)
            match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO, 6)
            match.append_field(ofproto_v1_3.OXM_OF_TCP_DST, tcp_dst)
            match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC, tcp_src)

            #match = parser.OFPMatch(eth_type=0x8000, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, ip_proto=ip_proto, tcp_src=tcp_src, tcp_dst=tcp_src)

            actions = []

            if tcp_dst == 80 and ipv4_src in self.IPinService and eth_src != CACHE_MAC and ipv4_dst != CACHE_IP:
                
                self.agent_table[(header_list[ETHERNET].src, header_list[TCP].src_port)] = (msg.match['in_port'], header_list[IPV4].dst, header_list[ETHERNET].dst)
                print "\nredirect\n"

                actions.append(parser.OFPActionSetField(ipv4_dst = CACHE_IP))
                actions.append(parser.OFPActionSetField(eth_dst = CACHE_MAC))

                #print "actions:", actions

                #print '\n',actions

                #self.add_flow(msg.datapath, 1, match, actions)
        
            elif tcp_src == 80 and ipv4_dst in self.IPinService and eth_dst != CACHE_MAC:
                
                print "\n Message return from Nginx \n"

                if (header_list[ETHERNET].dst, header_list[TCP].dst_port) in self.agent_table:
                    #build the correctly flow_mod

                    ipv4_src_ = self.agent_table[(header_list[ETHERNET].dst, header_list[TCP].dst_port)][1]
                    eth_src_ = self.agent_table[(header_list[ETHERNET].dst, header_list[TCP].dst_port)][2]


                    actions.append(parser.OFPActionSetField(ipv4_src = ipv4_src_))
                    actions.append(parser.OFPActionSetField(eth_src = eth_src_))

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(NGNIX_REDIRECT_TABLE + 1)]

            mod = parser.OFPFlowMod(datapath=datapath, priority=2, table_id=NGNIX_REDIRECT_TABLE, idle_timeout = 0, hard_timeout = 10, match=match, instructions=inst)
            #print "mod:", mod.__dict__
            datapath.send_msg(mod)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
    
        else: 
            pass
