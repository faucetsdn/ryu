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
import itertools

from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.tests.integrated import tester

LOG = logging.getLogger(__name__)


class RunTest(tester.TestFlowBase):
    """ Test case for add flows of Matches
    """
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RunTest, self).__init__(*args, **kwargs)

        self._verify = []

    def add_matches(self, dp, match):
        m = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, 0,
                                         dp.ofproto.OFPFC_ADD,
                                         0, 0, 0, 0xffffffff,
                                         dp.ofproto.OFPP_ANY,
                                         0xffffffff, 0, match, [])
        dp.send_msg(m)

    def verify_default(self, dp, stats):
        verify = self._verify
        self._verify = []

        headers = value = mask = None
        if len(verify) == 3:
            (headers, value, mask, ) = verify
        else:
            return "self._verify is invalid."

        f_value = f_mask = None
        for f in stats[0].match.fields:
            if f.header in headers:
                f_value = f.value
                if len(headers) == 2:
                    f_mask = f.mask
                break

        if f_value == value and f_mask == mask:
            return True
        elif value is None:
            return "Field[%s] is setting." % (headers, )
        else:
            return "Value error. send: (%s/%s), val:(%s/%s)" \
                % (value, mask, f_value, f_mask)

    def test_rule_set_dl_dst(self, dp):
        dl_dst = 'e2:7a:09:79:0b:0f'
        dl_dst_bin = self.haddr_to_bin(dl_dst)

        self._verify = [(dp.ofproto.OXM_OF_ETH_DST,
                         dp.ofproto.OXM_OF_ETH_DST_W, ),
                        dl_dst_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst(dl_dst_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_dst_masked_ff(self, dp):
        dl_dst = 'd0:98:79:b4:75:b5'
        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)

        self._verify = [(dp.ofproto.OXM_OF_ETH_DST,
                         dp.ofproto.OXM_OF_ETH_DST_W, ),
                        dl_dst_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_dst_masked_f0(self, dp):
        dl_dst = 'e2:7a:09:79:0b:0f'
        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask = 'ff:ff:ff:ff:ff:00'
        mask_bin = self.haddr_to_bin(mask)

        self._verify = [(dp.ofproto.OXM_OF_ETH_DST,
                         dp.ofproto.OXM_OF_ETH_DST_W, ),
                        dl_dst_bin[:-1] + '\x00', mask_bin]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_dst_masked_00(self, dp):
        dl_dst = 'e2:7a:09:79:0b:0f'
        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask = '00:00:00:00:00:00'
        mask_bin = self.haddr_to_bin(mask)

        self._verify = [(dp.ofproto.OXM_OF_ETH_DST,
                         dp.ofproto.OXM_OF_ETH_DST_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)

        self._verify = [(dp.ofproto.OXM_OF_ETH_SRC,
                         dp.ofproto.OXM_OF_ETH_SRC_W, ),
                        dl_src_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src(dl_src_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src_masked_ff(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)
        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)

        self._verify = [(dp.ofproto.OXM_OF_ETH_SRC,
                         dp.ofproto.OXM_OF_ETH_SRC_W, ),
                        dl_src_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src_masked_f0(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)
        mask = 'ff:ff:ff:ff:ff:00'
        mask_bin = self.haddr_to_bin(mask)

        self._verify = [(dp.ofproto.OXM_OF_ETH_SRC,
                         dp.ofproto.OXM_OF_ETH_SRC_W, ),
                        dl_src_bin[:-1] + '\x00', mask_bin]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src_masked_00(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)
        mask = '00:00:00:00:00:00'
        mask_bin = self.haddr_to_bin(mask)

        self._verify = [(dp.ofproto.OXM_OF_ETH_SRC,
                         dp.ofproto.OXM_OF_ETH_SRC_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_ip(self, dp):
        dl_type = ether.ETH_TYPE_IP
        self._verify = [(dp.ofproto.OXM_OF_ETH_TYPE, ),
                        dl_type, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_arp(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        self._verify = [(dp.ofproto.OXM_OF_ETH_TYPE, ),
                        dl_type, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_vlan(self, dp):
        dl_type = ether.ETH_TYPE_8021Q
        self._verify = [(dp.ofproto.OXM_OF_ETH_TYPE, ),
                        dl_type, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_ipv6(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        self._verify = [(dp.ofproto.OXM_OF_ETH_TYPE, ),
                        dl_type, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_lacp(self, dp):
        dl_type = ether.ETH_TYPE_SLOW
        self._verify = [(dp.ofproto.OXM_OF_ETH_TYPE, ),
                        dl_type, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_ip_dscp(self, dp):
        ip_dscp = 36
        dl_type = ether.ETH_TYPE_IP
        self._verify = [(dp.ofproto.OXM_OF_IP_DSCP, ),
                        ip_dscp, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_dscp(ip_dscp)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid(self, dp):
        vlan_vid = 0x4ef
        self._verify = [(dp.ofproto.OXM_OF_VLAN_VID,
                         dp.ofproto.OXM_OF_VLAN_VID_W, ),
                        vlan_vid, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid(vlan_vid)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid_masked_ff(self, dp):
        vlan_vid = 0x4ef
        mask = 0xfff
        self._verify = [(dp.ofproto.OXM_OF_VLAN_VID,
                         dp.ofproto.OXM_OF_VLAN_VID_W, ),
                        vlan_vid, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid_masked_f0(self, dp):
        vlan_vid = 0x4ef
        mask = 0xff0
        self._verify = [(dp.ofproto.OXM_OF_VLAN_VID,
                         dp.ofproto.OXM_OF_VLAN_VID_W, ),
                        vlan_vid & mask, mask]

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid_masked_00(self, dp):
        vlan_vid = 0x4ef
        mask = 0x000
        self._verify = [(dp.ofproto.OXM_OF_VLAN_VID,
                         dp.ofproto.OXM_OF_VLAN_VID_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        self.add_matches(dp, match)

    def test_rule_set_vlan_pcp(self, dp):
        vlan_vid = 0x4ef
        vlan_pcp = 5
        self._verify = [(dp.ofproto.OXM_OF_VLAN_PCP, ),
                        vlan_pcp, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid(vlan_vid)
        match.set_vlan_pcp(vlan_pcp)
        self.add_matches(dp, match)

    def test_rule_set_ip_ecn(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_ecn = 3
        self._verify = [(dp.ofproto.OXM_OF_IP_ECN, ),
                        ip_ecn, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_ecn(ip_ecn)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_icmp(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_ICMP
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_tcp(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_TCP
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_udp(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_UDP
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_route(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ROUTING
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_frag(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_FRAGMENT
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_icmp(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_none(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_NONE
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_dstopts(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_DSTOPTS
        self._verify = [(dp.ofproto.OXM_OF_IP_PROTO, ),
                        ip_proto, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_src(self, dp):
        dl_type = ether.ETH_TYPE_IP
        src = '192.168.196.250'
        src_int = self.ipv4_to_int(src)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_SRC,
                         dp.ofproto.OXM_OF_IPV4_SRC_W, ),
                        src_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src(src_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_src_masked_32(self, dp):
        dl_type = ether.ETH_TYPE_IP
        src = '192.168.196.250'
        src_int = self.ipv4_to_int(src)
        mask = '255.255.255.255'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_SRC,
                         dp.ofproto.OXM_OF_IPV4_SRC_W, ),
                        src_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src_masked(src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_src_masked_24(self, dp):
        dl_type = ether.ETH_TYPE_IP
        src = '192.168.196.250'
        src_int = self.ipv4_to_int(src)
        mask = '255.255.255.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_SRC,
                         dp.ofproto.OXM_OF_IPV4_SRC_W, ),
                        src_int & mask_int, mask_int]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src_masked(src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_src_masked_0(self, dp):
        dl_type = ether.ETH_TYPE_IP
        src = '192.168.196.250'
        src_int = self.ipv4_to_int(src)
        mask = '0.0.0.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_SRC,
                         dp.ofproto.OXM_OF_IPV4_SRC_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src_masked(src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_dst(self, dp):
        dl_type = ether.ETH_TYPE_IP
        dst = '192.168.54.155'
        dst_int = self.ipv4_to_int(dst)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_DST,
                         dp.ofproto.OXM_OF_IPV4_DST_W, ),
                        dst_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst(dst_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_dst_masked_32(self, dp):
        dl_type = ether.ETH_TYPE_IP
        dst = '192.168.54.155'
        dst_int = self.ipv4_to_int(dst)
        mask = '255.255.255.255'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_DST,
                         dp.ofproto.OXM_OF_IPV4_DST_W, ),
                        dst_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst_masked(dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_dst_masked_24(self, dp):
        dl_type = ether.ETH_TYPE_IP
        dst = '192.168.54.155'
        dst_int = self.ipv4_to_int(dst)
        mask = '255.255.255.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_DST,
                         dp.ofproto.OXM_OF_IPV4_DST_W, ),
                        dst_int & mask_int, mask_int]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst_masked(dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_dst_masked_0(self, dp):
        dl_type = ether.ETH_TYPE_IP
        dst = '192.168.54.155'
        dst_int = self.ipv4_to_int(dst)
        mask = '0.0.0.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV4_DST,
                         dp.ofproto.OXM_OF_IPV4_DST_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst_masked(dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_tcp_src(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_TCP
        tp_src = 1103
        self._verify = [(dp.ofproto.OXM_OF_TCP_SRC, ),
                        tp_src, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_tcp_src(tp_src)
        self.add_matches(dp, match)

    def test_rule_set_tcp_dst(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_TCP
        tp_dst = 236
        self._verify = [(dp.ofproto.OXM_OF_TCP_DST, ),
                        tp_dst, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_tcp_dst(tp_dst)
        self.add_matches(dp, match)

    def test_rule_set_udp_src(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_UDP
        tp_src = 56617
        self._verify = [(dp.ofproto.OXM_OF_UDP_SRC, ),
                        tp_src, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_udp_src(tp_src)
        self.add_matches(dp, match)

    def test_rule_set_udp_dst(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_UDP
        tp_dst = 61278
        self._verify = [(dp.ofproto.OXM_OF_UDP_DST, ),
                        tp_dst, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_udp_dst(tp_dst)
        self.add_matches(dp, match)

    def test_rule_set_icmpv4_type(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_ICMP
        icmp_type = 8
        self._verify = [(dp.ofproto.OXM_OF_ICMPV4_TYPE, ),
                        icmp_type, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv4_type(icmp_type)
        self.add_matches(dp, match)

    def test_rule_set_icmpv4_code(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_ICMP
        icmp_type = 9
        icmp_code = 16
        self._verify = [(dp.ofproto.OXM_OF_ICMPV4_CODE, ),
                        icmp_code, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv4_type(icmp_type)
        match.set_icmpv4_code(icmp_code)
        self.add_matches(dp, match)

    def test_rule_set_arp_opcode(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_op = 1
        self._verify = [(dp.ofproto.OXM_OF_ARP_OP, ),
                        arp_op, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_opcode(arp_op)
        self.add_matches(dp, match)

    def test_rule_set_arp_spa(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        nw_src_int = self.ipv4_to_int(nw_src)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SPA,
                         dp.ofproto.OXM_OF_ARP_SPA_W, ),
                        nw_src_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa(nw_src_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_spa_masked_32(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        nw_src_int = self.ipv4_to_int(nw_src)
        mask = '255.255.255.255'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SPA,
                         dp.ofproto.OXM_OF_ARP_SPA_W, ),
                        nw_src_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa_masked(nw_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_spa_masked_24(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        nw_src_int = self.ipv4_to_int(nw_src)
        mask = '255.255.255.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SPA,
                         dp.ofproto.OXM_OF_ARP_SPA_W, ),
                        nw_src_int & mask_int, mask_int]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa_masked(nw_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_spa_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        nw_src_int = self.ipv4_to_int(nw_src)
        mask = '0.0.0.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SPA,
                         dp.ofproto.OXM_OF_ARP_SPA_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa_masked(nw_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_tpa(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        self._verify = [(dp.ofproto.OXM_OF_ARP_TPA,
                         dp.ofproto.OXM_OF_ARP_TPA_W, ),
                        nw_dst_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa(nw_dst_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_tpa_masked_32(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        mask = '255.255.255.255'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_TPA,
                         dp.ofproto.OXM_OF_ARP_TPA_W, ),
                        nw_dst_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa_masked(nw_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_tpa_masked_24(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        mask = '255.255.255.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_TPA,
                         dp.ofproto.OXM_OF_ARP_TPA_W, ),
                        nw_dst_int & mask_int, mask_int]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa_masked(nw_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_tpa_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        mask = '0.0.0.0'
        mask_int = self.ipv4_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_TPA,
                         dp.ofproto.OXM_OF_ARP_TPA_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa_masked(nw_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_sha(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SHA,
                         dp.ofproto.OXM_OF_ARP_SHA_W, ),
                        arp_sha_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha(arp_sha_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_sha_masked_ff(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SHA,
                         dp.ofproto.OXM_OF_ARP_SHA_W, ),
                        arp_sha_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha_masked(arp_sha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_sha_masked_f0(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        mask = 'ff:ff:ff:ff:ff:00'
        mask_bin = self.haddr_to_bin(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SHA,
                         dp.ofproto.OXM_OF_ARP_SHA_W, ),
                        arp_sha_bin[:-1] + '\x00', mask_bin]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha_masked(arp_sha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_sha_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        mask = '00:00:00:00:00:00'
        mask_bin = self.haddr_to_bin(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_SHA,
                         dp.ofproto.OXM_OF_ARP_SHA_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha_masked(arp_sha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_tha(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_tha = '83:6c:21:52:49:68'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        self._verify = [(dp.ofproto.OXM_OF_ARP_THA,
                         dp.ofproto.OXM_OF_ARP_THA_W, ),
                        arp_tha_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha(arp_tha_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_tha_masked_ff(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_tha = '83:6c:21:52:49:68'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_THA,
                         dp.ofproto.OXM_OF_ARP_THA_W, ),
                        arp_tha_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha_masked(arp_tha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_tha_masked_f0(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_tha = '83:6c:21:52:49:68'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        mask = 'ff:ff:ff:ff:ff:00'
        mask_bin = self.haddr_to_bin(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_THA,
                         dp.ofproto.OXM_OF_ARP_THA_W, ),
                        arp_tha_bin[:-1] + '\x00', mask_bin]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha_masked(arp_tha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_tha_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_tha = '83:6c:21:52:49:68'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        mask = '00:00:00:00:00:00'
        mask_bin = self.haddr_to_bin(mask)
        self._verify = [(dp.ofproto.OXM_OF_ARP_THA,
                         dp.ofproto.OXM_OF_ARP_THA_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha_masked(arp_tha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_src(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_SRC,
                         dp.ofproto.OXM_OF_IPV6_SRC_W, ),
                        ipv6_src_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src(ipv6_src_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_src_masked_ff(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        mask_int = self.ipv6_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_SRC,
                         dp.ofproto.OXM_OF_IPV6_SRC_W, ),
                        ipv6_src_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src_masked(ipv6_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_src_masked_f0(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:0'
        mask_int = self.ipv6_to_int(mask)
        ipv6_src_masked = [x & y for (x, y) in
                           itertools.izip(ipv6_src_int, mask_int)]
        self._verify = [(dp.ofproto.OXM_OF_IPV6_SRC,
                         dp.ofproto.OXM_OF_IPV6_SRC_W, ),
                        ipv6_src_masked, mask_int]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src_masked(ipv6_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_src_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        mask = '0:0:0:0:0:0:0:0'
        mask_int = self.ipv6_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_SRC,
                         dp.ofproto.OXM_OF_IPV6_SRC_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src_masked(ipv6_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_dst(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_DST,
                         dp.ofproto.OXM_OF_IPV6_DST_W, ),
                        ipv6_dst_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst(ipv6_dst_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_dst_masked_ff(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        mask_int = self.ipv6_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_DST,
                         dp.ofproto.OXM_OF_IPV6_DST_W, ),
                        ipv6_dst_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst_masked(ipv6_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_dst_masked_f0(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:0'
        mask_int = self.ipv6_to_int(mask)
        ipv6_dst_masked = [x & y for (x, y) in
                           itertools.izip(ipv6_dst_int, mask_int)]
        self._verify = [(dp.ofproto.OXM_OF_IPV6_DST,
                         dp.ofproto.OXM_OF_IPV6_DST_W, ),
                        ipv6_dst_masked, mask_int]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst_masked(ipv6_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_dst_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        mask = '0:0:0:0:0:0:0:0'
        mask_int = self.ipv6_to_int(mask)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_DST,
                         dp.ofproto.OXM_OF_IPV6_DST_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst_masked(ipv6_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        self._verify = [(dp.ofproto.OXM_OF_IPV6_FLABEL,
                         dp.ofproto.OXM_OF_IPV6_FLABEL_W, ),
                        ipv6_label, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel(ipv6_label)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel_masked_ff(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0xfffff
        self._verify = [(dp.ofproto.OXM_OF_IPV6_FLABEL,
                         dp.ofproto.OXM_OF_IPV6_FLABEL_W, ),
                        ipv6_label, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel_masked_f0(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0xffff0
        self._verify = [(dp.ofproto.OXM_OF_IPV6_FLABEL,
                         dp.ofproto.OXM_OF_IPV6_FLABEL_W, ),
                        ipv6_label & mask, mask]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0x0
        self._verify = [(dp.ofproto.OXM_OF_IPV6_FLABEL,
                         dp.ofproto.OXM_OF_IPV6_FLABEL_W, ),
                        None, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        self.add_matches(dp, match)

    def test_rule_set_icmpv6_type(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6
        icmp_type = 129
        self._verify = [(dp.ofproto.OXM_OF_ICMPV6_TYPE, ),
                        icmp_type, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        self.add_matches(dp, match)

    def test_rule_set_icmpv6_code(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6
        icmp_type = 138
        icmp_code = 1
        self._verify = [(dp.ofproto.OXM_OF_ICMPV6_CODE, ),
                        icmp_code, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_icmpv6_code(icmp_code)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_nd_target(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6
        icmp_type = 135
        target = "5420:db3f:921b:3e33:2791:98f:dd7f:2e19"
        target_int = self.ipv6_to_int(target)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_ND_TARGET, ),
                        target_int, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_ipv6_nd_target(target_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_nd_sll(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6
        icmp_type = 135
        nd_sll = "93:6d:d0:d4:e8:36"
        nd_sll_bin = self.haddr_to_bin(nd_sll)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_ND_SLL, ),
                        nd_sll_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_ipv6_nd_sll(nd_sll_bin)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_nd_tll(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6
        icmp_type = 136
        nd_tll = "18:f6:66:b6:f1:b3"
        nd_tll_bin = self.haddr_to_bin(nd_tll)
        self._verify = [(dp.ofproto.OXM_OF_IPV6_ND_TLL, ),
                        nd_tll_bin, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_ipv6_nd_tll(nd_tll_bin)
        self.add_matches(dp, match)

    def test_rule_set_mpls_label(self, dp):
        dl_type = 0x8847
        label = 2144
        self._verify = [(dp.ofproto.OXM_OF_MPLS_LABEL, ),
                        label, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_mpls_label(label)
        self.add_matches(dp, match)

    def test_rule_set_mpls_tc(self, dp):
        dl_type = 0x8847
        tc = 3
        self._verify = [(dp.ofproto.OXM_OF_MPLS_TC, ),
                        tc, None]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_mpls_tc(tc)
        self.add_matches(dp, match)
