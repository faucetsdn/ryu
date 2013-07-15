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
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import set_ev_handler
from ryu.ofproto import ofproto_v1_2, ofproto_v1_2_parser
from ryu.lib.mac import haddr_to_str


# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


class SPE(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPE, self).__init__(*args, **kwargs)
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
    
    # taken from gre_tunnel.py
    @set_ev_handler(dpset.EventDP)
    def dp_handler(self, ev):
        self.logger.info('SPE.dp_handler()')
        self.send_event_to_observers(ev)
        enter_leave = ev.enter
        if not enter_leave:
            # TODO:XXX
            # What to do on datapath disconnection?
            self.logger.info('dp disconnection ev:%s', ev)
        else:
            self.logger.info('dp connection ev:%s', ev)
        
        # will handle ports later
        
        #dpid = ev.dp.id
        #ports = set(port.port_no for port in ev.ports)
        #ports.update(port.port_no for port in self.nw.get_ports(dpid))
        #for port_no in ports:
        #    self._port_handler(dpid, port_no, enter_leave)

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

        for o in match.fields:
            if isinstance(o, ofproto_v1_2_parser.MTInPort):
                in_port = o.value
                break

        self.logger.info("packet in dpid %s from %s to %s log_port %s",
                         dpid, haddr_to_str(src), haddr_to_str(dst),
                         in_port)
        
        
        # do we know the mac?
        if src not in self.mac_to_port[dpid]:
            # learn the mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            # set a flow to table 0 to allow packets through to table 1
            match = datapath.ofproto_parser.OFPMatch()
            match.set_in_port(in_port)
            match.set_dl_src(src)
            instructions = [datapath.ofproto_parser.OFPInstructionGotoTable(1)]
            self.add_flow(datapath, 0, match, instructions)
            

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 1500)]
            match = datapath.ofproto_parser.OFPMatch()
            match.set_dl_dst(dst)
            instructions = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, 1, match, instructions, buffer_id=msg.buffer_id)
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
            self.logger.info("Illeagal port state %s %s", port_no, reason)
