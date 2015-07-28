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
from ryu.lib.packet import vlan

import struct

VLAN = vlan.vlan.__name__

QosSimpleSwitch13_TABLE = 2

dpid_table = { 's1':1, 's2':2, 's3':3, 's4':4, 's5':5}

def tableid(buf):
    return struct.unpack_from('15x B', buffer(buf))


class QosSimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(QosSimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
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
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id = QosSimpleSwitch13_TABLE, 
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        table_id = tableid(msg.buf)[0]
        
        if table_id == QosSimpleSwitch13_TABLE:    
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)

            dst = eth.dst
            src = eth.src

            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            actions = []
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                
                if dpid == dpid_table['s1']:
                    if src == '00:00:00:00:00:01' :
                        actions.append(parser.OFPActionPushVlan())
                        actions.append(parser.OFPActionSetField(vlan_vid=2))
                    if src == '00:00:00:00:00:02' :
                        actions.append(parser.OFPActionPushVlan())
                        actions.append(parser.OFPActionSetField(vlan_vid=3))
                    if dst == '00:00:00:00:00:01' or dst == '00:00:00:00:00:01' :
                        actions.append(parser.OFPActionPopVlan())
                if dpid == dpid_table['s3']:
                    if src == '00:00:00:00:00:03' :
                        actions.append(parser.OFPActionPushVlan())
                        actions.append(parser.OFPActionSetField(vlan_vid=3))
                    if dst == '00:00:00:00:00:03' :
                        if VLAN in header_list:
                            actions.append(parser.OFPActionPopVlan())
                if dpid == dpid_table['s4']:
                    if src == '00:00:00:00:00:04' :
                        actions.append(parser.OFPActionPushVlan())
                        actions.append(parser.OFPActionSetField(vlan_vid=2))
                    if dst == '00:00:00:00:00:04' :
                        if VLAN in header_list:
                            actions.append(parser.OFPActionPopVlan())
                if dpid == dpid_table['s5']:
                    if dst == '00:00:00:00:00:05' or dst == '00:00:00:00:00:06' :
                        if VLAN in header_list:
                            actions.append(parser.OFPActionPopVlan())
                
            else:
                out_port = ofproto.OFPP_FLOOD

            actions.append(parser.OFPActionOutput(out_port))

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
