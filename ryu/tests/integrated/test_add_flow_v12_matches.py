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

        self._verify = {}

    def add_matches(self, dp, match):
        m = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, 0,
                                         dp.ofproto.OFPFC_ADD,
                                         0, 0, 0, 0xffffffff,
                                         dp.ofproto.OFPP_ANY,
                                         0xffffffff, 0, match, [])
        dp.send_msg(m)

    def _set_verify(self, headers, value, mask=None,
                    all_bits_masked=False, type_='int'):
        self._verify = {}
        self._verify['headers'] = headers
        self._verify['value'] = value
        self._verify['mask'] = mask
        self._verify['all_bits_masked'] = all_bits_masked
        self._verify['type'] = type_

    def verify_default(self, dp, stats):
        type_ = self._verify['type']
        headers = self._verify['headers']
        value = self._verify['value']
        mask = self._verify['mask']
        value_masked = self._masked(type_, value, mask)
        all_bits_masked = self._verify['all_bits_masked']

        field = None
        for s in stats:
            for f in s.match.fields:
                if f.header in headers:
                    field = f
                    break

        if field is None:
            if self._is_all_zero_bit(type_, mask):
                return True
            return 'Field not found.'

        f_value = field.value
        if hasattr(field, 'mask'):
            f_mask = field.mask
        else:
            f_mask = None

        if (f_value == value) or (f_value == value_masked):
            if (f_mask == mask) or (all_bits_masked and f_mask is None):
                return True

        return "send: %s/%s, reply: %s/%s" \
            % (self._cnv_to_str(type_, value, mask, f_value, f_mask))

    def _masked(self, type_, value, mask):
        if mask is None:
            v = value
        elif type_ == 'int':
            v = value & mask
        elif type_ == 'mac':
            v = self.haddr_masked(value, mask)
        elif type_ == 'ipv4':
            v = self.ipv4_masked(value, mask)
        elif type_ == 'ipv6':
            v = self.ipv6_masked(value, mask)
        else:
            raise 'Unknown type'
        return v

    def _is_all_zero_bit(self, type_, val):
        if type_ == 'int' or type_ == 'ipv4':
            return val == 0
        elif type_ == 'mac':
            for v in val:
                if v != '\x00':
                    return False
            return True
        elif type_ == 'ipv6':
            for v in val:
                if v != 0:
                    return False
            return True
        else:
            raise 'Unknown type'

    def _cnv_to_str(self, type_, value, mask, f_value, f_mask):
        func = None
        if type_ == 'int':
            pass
        elif type_ == 'mac':
            func = self.haddr_to_str
        elif type_ == 'ipv4':
            func = self.ipv4_to_str
        elif type_ == 'ipv6':
            func = self.ipv6_to_str
        else:
            raise 'Unknown type'

        if func:
            value = func(value)
            f_value = func(f_value)
            if mask:
                mask = func(mask)
            if f_mask:
                f_mask = func(f_mask)

        return value, mask, f_value, f_mask

    def test_rule_set_dl_dst(self, dp):
        dl_dst = 'e2:7a:09:79:0b:0f'
        dl_dst_bin = self.haddr_to_bin(dl_dst)

        headers = [dp.ofproto.OXM_OF_ETH_DST, dp.ofproto.OXM_OF_ETH_DST_W]
        self._set_verify(headers, dl_dst_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst(dl_dst_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_dst_masked_ff(self, dp):
        dl_dst = 'd0:98:79:b4:75:b5'
        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)

        headers = [dp.ofproto.OXM_OF_ETH_DST, dp.ofproto.OXM_OF_ETH_DST_W]
        self._set_verify(headers, dl_dst_bin, mask_bin, True, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_dst_masked_f0(self, dp):
        dl_dst = 'e2:7a:09:79:0b:0f'
        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask = 'ff:ff:ff:ff:ff:00'
        mask_bin = self.haddr_to_bin(mask)

        headers = [dp.ofproto.OXM_OF_ETH_DST, dp.ofproto.OXM_OF_ETH_DST_W]
        self._set_verify(headers, dl_dst_bin, mask_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_dst_masked_00(self, dp):
        dl_dst = 'e2:7a:09:79:0b:0f'
        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask = '00:00:00:00:00:00'
        mask_bin = self.haddr_to_bin(mask)

        headers = [dp.ofproto.OXM_OF_ETH_DST, dp.ofproto.OXM_OF_ETH_DST_W]
        self._set_verify(headers, dl_dst_bin, mask_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)

        headers = [dp.ofproto.OXM_OF_ETH_SRC, dp.ofproto.OXM_OF_ETH_SRC_W]
        self._set_verify(headers, dl_src_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src(dl_src_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src_masked_ff(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)
        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)

        headers = [dp.ofproto.OXM_OF_ETH_SRC, dp.ofproto.OXM_OF_ETH_SRC_W]
        self._set_verify(headers, dl_src_bin, mask_bin, True, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src_masked_f0(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)
        mask = 'ff:ff:ff:ff:ff:00'
        mask_bin = self.haddr_to_bin(mask)

        headers = [dp.ofproto.OXM_OF_ETH_SRC, dp.ofproto.OXM_OF_ETH_SRC_W]
        self._set_verify(headers, dl_src_bin, mask_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_src_masked_00(self, dp):
        dl_src = 'e2:7a:09:79:0b:0f'
        dl_src_bin = self.haddr_to_bin(dl_src)
        mask = '00:00:00:00:00:00'
        mask_bin = self.haddr_to_bin(mask)

        headers = [dp.ofproto.OXM_OF_ETH_SRC, dp.ofproto.OXM_OF_ETH_SRC_W]
        self._set_verify(headers, dl_src_bin, mask_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_ip(self, dp):
        dl_type = ether.ETH_TYPE_IP

        headers = [dp.ofproto.OXM_OF_ETH_TYPE]
        self._set_verify(headers, dl_type)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_arp(self, dp):
        dl_type = ether.ETH_TYPE_ARP

        headers = [dp.ofproto.OXM_OF_ETH_TYPE]
        self._set_verify(headers, dl_type)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_vlan(self, dp):
        dl_type = ether.ETH_TYPE_8021Q

        headers = [dp.ofproto.OXM_OF_ETH_TYPE]
        self._set_verify(headers, dl_type)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_ipv6(self, dp):
        dl_type = ether.ETH_TYPE_IPV6

        headers = [dp.ofproto.OXM_OF_ETH_TYPE]
        self._set_verify(headers, dl_type)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_dl_type_lacp(self, dp):
        dl_type = ether.ETH_TYPE_SLOW

        headers = [dp.ofproto.OXM_OF_ETH_TYPE]
        self._set_verify(headers, dl_type)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        self.add_matches(dp, match)

    def test_rule_set_ip_dscp(self, dp):
        ip_dscp = 36
        dl_type = ether.ETH_TYPE_IP

        headers = [dp.ofproto.OXM_OF_IP_DSCP]
        self._set_verify(headers, ip_dscp)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_dscp(ip_dscp)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid(self, dp):
        vlan_vid = 0x4ef

        headers = [dp.ofproto.OXM_OF_VLAN_VID, dp.ofproto.OXM_OF_VLAN_VID_W]
        self._set_verify(headers, vlan_vid)

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid(vlan_vid)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid_masked_ff(self, dp):
        vlan_vid = 0x4ef
        mask = 0xfff

        headers = [dp.ofproto.OXM_OF_VLAN_VID, dp.ofproto.OXM_OF_VLAN_VID_W]
        self._set_verify(headers, vlan_vid, mask, True)

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid_masked_f0(self, dp):
        vlan_vid = 0x4ef
        mask = 0xff0

        headers = [dp.ofproto.OXM_OF_VLAN_VID, dp.ofproto.OXM_OF_VLAN_VID_W]
        self._set_verify(headers, vlan_vid, mask)

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        self.add_matches(dp, match)

    def test_rule_set_vlan_vid_masked_00(self, dp):
        vlan_vid = 0x4ef
        mask = 0x000

        headers = [dp.ofproto.OXM_OF_VLAN_VID, dp.ofproto.OXM_OF_VLAN_VID_W]
        self._set_verify(headers, vlan_vid, mask)

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        self.add_matches(dp, match)

    def test_rule_set_vlan_pcp(self, dp):
        vlan_vid = 0x4ef
        vlan_pcp = 5

        headers = [dp.ofproto.OXM_OF_VLAN_PCP]
        self._set_verify(headers, vlan_pcp)

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid(vlan_vid)
        match.set_vlan_pcp(vlan_pcp)
        self.add_matches(dp, match)

    def test_rule_set_ip_ecn(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_ecn = 3

        headers = [dp.ofproto.OXM_OF_IP_ECN]
        self._set_verify(headers, ip_ecn)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_ecn(ip_ecn)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_icmp(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_ICMP

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_tcp(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_TCP

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_udp(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_UDP

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_route(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ROUTING

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_frag(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_FRAGMENT

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_icmp(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_none(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_NONE

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ip_proto_ipv6_dstopts(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_DSTOPTS

        headers = [dp.ofproto.OXM_OF_IP_PROTO]
        self._set_verify(headers, ip_proto)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_src(self, dp):
        dl_type = ether.ETH_TYPE_IP
        src = '192.168.196.250'
        src_int = self.ipv4_to_int(src)

        headers = [dp.ofproto.OXM_OF_IPV4_SRC, dp.ofproto.OXM_OF_IPV4_SRC_W]
        self._set_verify(headers, src_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_IPV4_SRC, dp.ofproto.OXM_OF_IPV4_SRC_W]
        self._set_verify(headers, src_int, mask_int, True, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_IPV4_SRC, dp.ofproto.OXM_OF_IPV4_SRC_W]
        self._set_verify(headers, src_int, mask_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_IPV4_SRC, dp.ofproto.OXM_OF_IPV4_SRC_W]
        self._set_verify(headers, src_int, mask_int, type_='ipv4')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src_masked(src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv4_dst(self, dp):
        dl_type = ether.ETH_TYPE_IP
        dst = '192.168.54.155'
        dst_int = self.ipv4_to_int(dst)

        headers = [dp.ofproto.OXM_OF_IPV4_DST, dp.ofproto.OXM_OF_IPV4_DST_W]
        self._set_verify(headers, dst_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_IPV4_DST, dp.ofproto.OXM_OF_IPV4_DST_W]
        self._set_verify(headers, dst_int, mask_int, True, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_IPV4_DST, dp.ofproto.OXM_OF_IPV4_DST_W]
        self._set_verify(headers, dst_int, mask_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_IPV4_DST, dp.ofproto.OXM_OF_IPV4_DST_W]
        self._set_verify(headers, dst_int, mask_int, type_='ipv4')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst_masked(dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_tcp_src(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_TCP
        tp_src = 1103

        headers = [dp.ofproto.OXM_OF_TCP_SRC]
        self._set_verify(headers, tp_src)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_tcp_src(tp_src)
        self.add_matches(dp, match)

    def test_rule_set_tcp_dst(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_TCP
        tp_dst = 236

        headers = [dp.ofproto.OXM_OF_TCP_DST]
        self._set_verify(headers, tp_dst)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_tcp_dst(tp_dst)
        self.add_matches(dp, match)

    def test_rule_set_udp_src(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_UDP
        tp_src = 56617

        headers = [dp.ofproto.OXM_OF_UDP_SRC]
        self._set_verify(headers, tp_src)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_udp_src(tp_src)
        self.add_matches(dp, match)

    def test_rule_set_udp_dst(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_UDP
        tp_dst = 61278

        headers = [dp.ofproto.OXM_OF_UDP_DST]
        self._set_verify(headers, tp_dst)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_udp_dst(tp_dst)
        self.add_matches(dp, match)

    def test_rule_set_icmpv4_type(self, dp):
        dl_type = ether.ETH_TYPE_IP
        ip_proto = inet.IPPROTO_ICMP
        icmp_type = 8

        headers = [dp.ofproto.OXM_OF_ICMPV4_TYPE]
        self._set_verify(headers, icmp_type)

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

        headers = [dp.ofproto.OXM_OF_ICMPV4_CODE]
        self._set_verify(headers, icmp_code)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv4_type(icmp_type)
        match.set_icmpv4_code(icmp_code)
        self.add_matches(dp, match)

    def test_rule_set_arp_opcode(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_op = 1

        headers = [dp.ofproto.OXM_OF_ARP_OP]
        self._set_verify(headers, arp_op)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_opcode(arp_op)
        self.add_matches(dp, match)

    def test_rule_set_arp_spa(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        nw_src_int = self.ipv4_to_int(nw_src)

        headers = [dp.ofproto.OXM_OF_ARP_SPA, dp.ofproto.OXM_OF_ARP_SPA_W]
        self._set_verify(headers, nw_src_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_ARP_SPA, dp.ofproto.OXM_OF_ARP_SPA_W]
        self._set_verify(headers, nw_src_int, mask_int, True, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_ARP_SPA, dp.ofproto.OXM_OF_ARP_SPA_W]
        self._set_verify(headers, nw_src_int, mask_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_ARP_SPA, dp.ofproto.OXM_OF_ARP_SPA_W]
        self._set_verify(headers, nw_src_int, mask_int, type_='ipv4')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa_masked(nw_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_tpa(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        nw_dst_int = self.ipv4_to_int(nw_dst)

        headers = [dp.ofproto.OXM_OF_ARP_TPA, dp.ofproto.OXM_OF_ARP_TPA_W]
        self._set_verify(headers, nw_dst_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_ARP_TPA, dp.ofproto.OXM_OF_ARP_TPA_W]
        self._set_verify(headers, nw_dst_int, mask_int, True, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_ARP_TPA, dp.ofproto.OXM_OF_ARP_TPA_W]
        self._set_verify(headers, nw_dst_int, mask_int, type_='ipv4')

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

        headers = [dp.ofproto.OXM_OF_ARP_TPA, dp.ofproto.OXM_OF_ARP_TPA_W]
        self._set_verify(headers, nw_dst_int, mask_int, type_='ipv4')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa_masked(nw_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_arp_sha(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        arp_sha_bin = self.haddr_to_bin(arp_sha)

        headers = [dp.ofproto.OXM_OF_ARP_SHA, dp.ofproto.OXM_OF_ARP_SHA_W]
        self._set_verify(headers, arp_sha_bin, type_='mac')

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

        headers = [dp.ofproto.OXM_OF_ARP_SHA, dp.ofproto.OXM_OF_ARP_SHA_W]
        self._set_verify(headers, arp_sha_bin, mask_bin, True, type_='mac')

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

        headers = [dp.ofproto.OXM_OF_ARP_SHA, dp.ofproto.OXM_OF_ARP_SHA_W]
        self._set_verify(headers, arp_sha_bin, mask_bin, type_='mac')

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

        headers = [dp.ofproto.OXM_OF_ARP_SHA, dp.ofproto.OXM_OF_ARP_SHA_W]
        self._set_verify(headers, arp_sha_bin, mask_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha_masked(arp_sha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_arp_tha(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        arp_tha = '83:6c:21:52:49:68'
        arp_tha_bin = self.haddr_to_bin(arp_tha)

        headers = [dp.ofproto.OXM_OF_ARP_THA, dp.ofproto.OXM_OF_ARP_THA_W]
        self._set_verify(headers, arp_tha_bin, type_='mac')

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

        headers = [dp.ofproto.OXM_OF_ARP_THA, dp.ofproto.OXM_OF_ARP_THA_W]
        self._set_verify(headers, arp_tha_bin, mask_bin, True, type_='mac')

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

        headers = [dp.ofproto.OXM_OF_ARP_THA, dp.ofproto.OXM_OF_ARP_THA_W]
        self._set_verify(headers, arp_tha_bin, mask_bin, type_='mac')

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

        headers = [dp.ofproto.OXM_OF_ARP_THA, dp.ofproto.OXM_OF_ARP_THA_W]
        self._set_verify(headers, arp_tha_bin, mask_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha_masked(arp_tha_bin, mask_bin)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_src(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)

        headers = [dp.ofproto.OXM_OF_IPV6_SRC, dp.ofproto.OXM_OF_IPV6_SRC_W]
        self._set_verify(headers, ipv6_src_int, type_='ipv6')

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

        headers = [dp.ofproto.OXM_OF_IPV6_SRC, dp.ofproto.OXM_OF_IPV6_SRC_W]
        self._set_verify(headers, ipv6_src_int, mask_int, True, type_='ipv6')

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

        headers = [dp.ofproto.OXM_OF_IPV6_SRC, dp.ofproto.OXM_OF_IPV6_SRC_W]
        self._set_verify(headers, ipv6_src_int, mask_int, type_='ipv6')

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

        headers = [dp.ofproto.OXM_OF_IPV6_SRC, dp.ofproto.OXM_OF_IPV6_SRC_W]
        self._set_verify(headers, ipv6_src_int, mask_int, type_='ipv6')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src_masked(ipv6_src_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_dst(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)

        headers = [dp.ofproto.OXM_OF_IPV6_DST, dp.ofproto.OXM_OF_IPV6_DST_W]
        self._set_verify(headers, ipv6_dst_int, type_='ipv6')

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

        headers = [dp.ofproto.OXM_OF_IPV6_DST, dp.ofproto.OXM_OF_IPV6_DST_W]
        self._set_verify(headers, ipv6_dst_int, mask_int, True, type_='ipv6')

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

        headers = [dp.ofproto.OXM_OF_IPV6_DST, dp.ofproto.OXM_OF_IPV6_DST_W]
        self._set_verify(headers, ipv6_dst_int, mask_int, type_='ipv6')

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

        headers = [dp.ofproto.OXM_OF_IPV6_DST, dp.ofproto.OXM_OF_IPV6_DST_W]
        self._set_verify(headers, ipv6_dst_int, mask_int, type_='ipv6')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst_masked(ipv6_dst_int, mask_int)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384

        headers = [dp.ofproto.OXM_OF_IPV6_FLABEL,
                   dp.ofproto.OXM_OF_IPV6_FLABEL_W]
        self._set_verify(headers, ipv6_label)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel(ipv6_label)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel_masked_ff(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0xfffff

        headers = [dp.ofproto.OXM_OF_IPV6_FLABEL,
                   dp.ofproto.OXM_OF_IPV6_FLABEL_W]
        self._set_verify(headers, ipv6_label, mask, True)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel_masked_f0(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0xffff0

        headers = [dp.ofproto.OXM_OF_IPV6_FLABEL,
                   dp.ofproto.OXM_OF_IPV6_FLABEL_W]
        self._set_verify(headers, ipv6_label, mask)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        self.add_matches(dp, match)

    def test_rule_set_ipv6_flabel_masked_00(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0x0

        headers = [dp.ofproto.OXM_OF_IPV6_FLABEL,
                   dp.ofproto.OXM_OF_IPV6_FLABEL_W]
        self._set_verify(headers, ipv6_label, mask)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        self.add_matches(dp, match)

    def test_rule_set_icmpv6_type(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        ip_proto = inet.IPPROTO_ICMPV6
        icmp_type = 129

        headers = [dp.ofproto.OXM_OF_ICMPV6_TYPE]
        self._set_verify(headers, icmp_type)

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

        headers = [dp.ofproto.OXM_OF_ICMPV6_CODE]
        self._set_verify(headers, icmp_code)

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

        headers = [dp.ofproto.OXM_OF_IPV6_ND_TARGET]
        self._set_verify(headers, target_int, type_='ipv6')

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

        headers = [dp.ofproto.OXM_OF_IPV6_ND_SLL]
        self._set_verify(headers, nd_sll_bin, type_='mac')

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

        headers = [dp.ofproto.OXM_OF_IPV6_ND_TLL]
        self._set_verify(headers, nd_tll_bin, type_='mac')

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_ipv6_nd_tll(nd_tll_bin)
        self.add_matches(dp, match)

    def test_rule_set_mpls_label(self, dp):
        dl_type = 0x8847
        label = 2144

        headers = [dp.ofproto.OXM_OF_MPLS_LABEL]
        self._set_verify(headers, label)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_mpls_label(label)
        self.add_matches(dp, match)

    def test_rule_set_mpls_tc(self, dp):
        dl_type = 0x8847
        tc = 3

        headers = [dp.ofproto.OXM_OF_MPLS_TC]
        self._set_verify(headers, tc)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_mpls_tc(tc)
        self.add_matches(dp, match)

    def is_supported(self, t):
        unsupported = [
            'test_rule_set_mpls_tc',
        ]
        for u in unsupported:
            if t.find(u) != -1:
                return False

        return True
