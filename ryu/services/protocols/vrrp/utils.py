# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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

from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.ofproto import ether
from ryu.topology import api as topo_api


def may_add_vlan(packet, vlan_id):
    """
    :type packet: ryu.lib.packet.packet.Packet
    :param packet:
    :type vlan_id: int (0 <= vlan_id <= 4095) or None (= No VLAN)
    :param vlan_id:
    """
    if vlan_id is None:
        return

    e = packet.protocols[0]
    assert isinstance(e, ethernet.ethernet)
    v = vlan.vlan(0, 0, vlan_id, e.ethertype)
    e.ethertype = ether.ETH_TYPE_8021Q
    packet.add_protocol(v)


def get_dp(app, dpid):
    """
    :type dpid: datapath id
    :param dpid:
    :rtype: ryu.controller.controller.Datapatyh
    :returns: datapath corresponding to dpid
    """
    switches = topo_api.get_switch(app, dpid)
    if not switches:
        return None
    assert len(switches) == 1
    return switches[0].dp


def dp_packet_out(dp, port_no, data):
    # OF 1.2
    ofproto = dp.ofproto
    ofproto_parser = dp.ofproto_parser
    actions = [ofproto_parser.OFPActionOutput(port_no,
                                              ofproto.OFPCML_NO_BUFFER)]
    packet_out = ofproto_parser.OFPPacketOut(
        dp, 0xffffffff, ofproto.OFPP_CONTROLLER, actions, data)
    dp.send_msg(packet_out)


def dp_flow_mod(dp, table, command, priority, match, instructions,
                out_port=None):
    # OF 1.2
    ofproto = dp.ofproto
    ofproto_parser = dp.ofproto_parser
    if out_port is None:
        out_port = ofproto.OFPP_ANY
    flow_mod = ofproto_parser.OFPFlowMod(
        dp, 0, 0, table, command, 0, 0,
        priority, 0xffffffff, out_port, ofproto.OFPG_ANY,
        ofproto.OFPFF_CHECK_OVERLAP, match, instructions)
    dp.send_msg(flow_mod)
