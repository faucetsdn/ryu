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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import logging
import array
import netaddr

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import mac
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp


LOG = logging.getLogger(__name__)


class RunTestMininet(app_manager.RyuApp):

    _CONTEXTS = {'dpset': dpset.DPSet}
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    ZERO_MAC = mac.haddr_to_bin('00:00:00:00:00:00')
    BROADCAST_MAC = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')
    RYU_MAC = mac.haddr_to_bin('fe:ee:ee:ee:ee:ef')
    HOST_MAC = mac.haddr_to_bin('00:00:00:00:00:01')
    RYU_IP = int(netaddr.IPAddress('10.0.0.100'))
    HOST_IP = int(netaddr.IPAddress('10.0.0.1'))

    def __init__(self, *args, **kwargs):
        super(RunTestMininet, self).__init__(*args, **kwargs)

    def _send_msg(self, dp, data):
        buffer_id = 0xffffffff
        in_port = dp.ofproto.OFPP_LOCAL
        actions = [dp.ofproto_parser.OFPActionOutput(1, 0)]
        msg = dp.ofproto_parser.OFPPacketOut(
            dp, buffer_id, in_port, actions, data)
        dp.send_msg(msg)

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

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def _get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols

    def _build_ether(self, ethertype, dst_mac=HOST_MAC):
        e = ethernet.ethernet(dst_mac, self.RYU_MAC, ethertype)
        return e

    def _build_arp(self, opcode, dst_ip=HOST_IP):
        if opcode == arp.ARP_REQUEST:
            _eth_dst_mac = self.BROADCAST_MAC
            _arp_dst_mac = self.ZERO_MAC
        elif opcode == arp.ARP_REPLY:
            _eth_dst_mac = self.HOST_MAC
            _arp_dst_mac = self.HOST_MAC

        e = self._build_ether(ether.ETH_TYPE_ARP, _eth_dst_mac)
        a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                    opcode=opcode, src_mac=self.RYU_MAC, src_ip=self.RYU_IP,
                    dst_mac=_arp_dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        return p

    def _build_echo(self, _type, echo):
        e = self._build_ether(ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=84,
                       identification=0, flags=0, offset=0, ttl=64,
                       proto=inet.IPPROTO_ICMP, csum=0,
                       src=self.RYU_IP, dst=self.HOST_IP)
        ping = icmp.icmp(_type, code=0, csum=0, data=echo)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(ping)
        p.serialize()
        return p

    def _garp(self):
        p = self._build_arp(arp.ARP_REQUEST, self.RYU_IP)
        return p.data

    def _arp_request(self):
        p = self._build_arp(arp.ARP_REQUEST, self.HOST_IP)
        return p.data

    def _arp_reply(self):
        p = self._build_arp(arp.ARP_REPLY, self.HOST_IP)
        return p.data

    def _echo_request(self, echo):
        p = self._build_echo(icmp.ICMP_ECHO_REQUEST, echo)
        return p.data

    def _echo_reply(self, echo):
        p = self._build_echo(icmp.ICMP_ECHO_REPLY, echo)
        return p.data

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        pkt = packet.Packet(array.array('B', msg.data))
        p_arp = self._find_protocol(pkt, "arp")
        p_icmp = self._find_protocol(pkt, "icmp")
        p_ipv4 = self._find_protocol(pkt, "ipv4")

        if p_arp:
            src_ip = str(netaddr.IPAddress(p_arp.src_ip))
            dst_ip = str(netaddr.IPAddress(p_arp.dst_ip))
            if p_arp.opcode == arp.ARP_REQUEST:
                LOG.debug("--- PacketIn: ARP_Request: %s->%s", src_ip, dst_ip)
                if p_arp.dst_ip == self.RYU_IP:
                    LOG.debug("--- send Pkt: ARP_Reply")
                    data = self._arp_reply()
                    self._send_msg(dp, data)
                elif p_arp.dst_ip == self.HOST_IP:
                    LOG.debug("    PacketIn: GARP")
                    LOG.debug("--- send Pkt: ARP_Request")
                    data = self._arp_request()
                    self._send_msg(dp, data)
            elif p_arp.opcode == arp.ARP_REPLY:
                LOG.debug("--- PacketIn: ARP_Reply: %s->%s", src_ip, dst_ip)
                LOG.debug("--- send Pkt: Echo_Request")
                echo = icmp.echo(id_=66, seq=1)
                data = self._echo_request(echo)
                self._send_msg(dp, data)

        if p_icmp:
            src = str(netaddr.IPAddress(p_ipv4.src))
            dst = str(netaddr.IPAddress(p_ipv4.dst))
            if p_icmp.type == icmp.ICMP_ECHO_REQUEST:
                LOG.debug("--- PacketIn: Echo_Request: %s->%s", src, dst)
                if p_ipv4.dst == self.RYU_IP:
                    LOG.debug("--- send Pkt: Echo_Reply")
                    echo = p_icmp.data
                    echo.data = bytearray(echo.data)
                    data = self._echo_reply(echo)
                    self._send_msg(dp, data)
            elif p_icmp.type == icmp.ICMP_ECHO_REPLY:
                LOG.debug("--- PacketIn: Echo_Reply: %s->%s", src, dst)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            dp = ev.dp

            LOG.debug("--- send Pkt: Gratuitous ARP_Request")
            data = self._garp()
            self._send_msg(dp, data)
