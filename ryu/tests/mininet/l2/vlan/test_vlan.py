# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.mac import haddr_to_str


LOG = logging.getLogger(__name__)


class RunTestMininet(app_manager.RyuApp):

    _CONTEXTS = {'dpset': dpset.DPSet}
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RunTestMininet, self).__init__(*args, **kwargs)

    def _add_flow(self, dp, match, actions):
        inst = [dp.ofproto_parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = dp.ofproto_parser.OFPFlowMod(
            dp, cookie=0, cookie_mask=0, table_id=0,
            command=dp.ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0xff, buffer_id=0xffffffff,
            out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)

        dp.send_msg(mod)

    def _define_flow(self, dp):
        in_port = 1
        out_port = 2

        eth_IP = ether.ETH_TYPE_IP
        eth_VLAN = ether.ETH_TYPE_8021Q
        ip_ICMP = inet.IPPROTO_ICMP

        # VLAN(8) -> PopVLAN
        LOG.debug("--- add_flow VLAN(8) to PopVLAN")
        m_vid = 8
        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        match.set_dl_type(eth_IP)
        match.set_vlan_vid(m_vid)
        actions = [dp.ofproto_parser.OFPActionPopVlan(),
                   dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        self._add_flow(dp, match, actions)

        # ICMP -> PushVLAN(9)
        LOG.debug("--- add_flow ICMP to PushVLAN(9)")
        s_vid = 9
        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        match.set_dl_type(eth_IP)
        match.set_ip_proto(ip_ICMP)
        f = dp.ofproto_parser.OFPMatchField.make(
            dp.ofproto.OXM_OF_VLAN_VID, s_vid)
        actions = [dp.ofproto_parser.OFPActionPushVlan(eth_VLAN),
                   dp.ofproto_parser.OFPActionSetField(f),
                   dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        self._add_flow(dp, match, actions)

        # VLAN(10) -> PushVLAN(20)
        # LOG.debug("--- add_flow VLAN(10) to PushVLAN(100)")
        # SKIP: ovs not supported
        m_vid = 10
        s_vid = 20
        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        match.set_dl_type(eth_IP)
        match.set_vlan_vid(m_vid)
        f = dp.ofproto_parser.OFPMatchField.make(
            dp.ofproto.OXM_OF_VLAN_VID, s_vid)
        actions = [dp.ofproto_parser.OFPActionPushVlan(eth_VLAN),
                   dp.ofproto_parser.OFPActionSetField(f),
                   dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        # self._add_flow(dp, match, actions)

        # VLAN(100):VLAN -> PopVLAN
        LOG.debug("--- add_flow VLAN(100):VLAN to PopVLAN")
        m_vid = 100
        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        match.set_dl_type(eth_VLAN)
        match.set_vlan_vid(m_vid)
        actions = [dp.ofproto_parser.OFPActionPopVlan(),
                   dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        self._add_flow(dp, match, actions)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self._define_flow(ev.dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dst, src, eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        in_port = msg.match.fields[0].value

        LOG.info("----------------------------------------")
        LOG.info("* PacketIn")
        LOG.info("in_port=%d, eth_type: %s", in_port, hex(eth_type))
        LOG.info("packet reason=%d buffer_id=%d", msg.reason, msg.buffer_id)
        LOG.info("packet in datapath_id=%s src=%s dst=%s",
                 msg.datapath.id, haddr_to_str(src), haddr_to_str(dst))
