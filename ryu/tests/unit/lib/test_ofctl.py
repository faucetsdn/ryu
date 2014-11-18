# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

import unittest
import logging
import struct
import socket
import netaddr
import functools
import new
import itertools

from nose.tools import *

from ryu.lib import ofctl_v1_2
from ryu.ofproto import ofproto_v1_2, ofproto_v1_2_parser
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.ofproto import ofproto_protocol
from ryu.lib import mac
from ryu.lib import ip

LOG = logging.getLogger('test_ofctl_v1_2, v1_3')

""" Common Functions """


def _to_match_eth(value):
    eth_mask = value.split('/')
    # MAC address
    eth = mac.haddr_to_bin(eth_mask[0])
    # mask
    mask = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')
    if len(eth_mask) == 2:
        mask = mac.haddr_to_bin(eth_mask[1])
    return eth, mask


def _to_match_tpsrc(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_src,
                    inet.IPPROTO_UDP: match.set_udp_src}
    nw_proto = rest.get('nw_proto', rest.get('ip_proto', 0))
    if nw_proto in match_append:
        match_append[nw_proto](value)
    return match


def _to_match_tpdst(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_dst,
                    inet.IPPROTO_UDP: match.set_udp_dst}
    nw_proto = rest.get('nw_proto', rest.get('ip_proto', 0))
    if nw_proto in match_append:
        match_append[nw_proto](value)
    return match


def _to_match_ip(value):
    ip_mask = value.split('/')
    # IP address
    ipv4 = struct.unpack('!I', socket.inet_aton(ip_mask[0]))[0]
    # netmask
    netmask = ofproto_v1_2_parser.UINT32_MAX
    if len(ip_mask) == 2:
        # Check the mask is CIDR or not.
        if ip_mask[1].isdigit():
            netmask &= ofproto_v1_2_parser.UINT32_MAX << 32 - int(ip_mask[1])
        else:
            netmask = struct.unpack('!I', socket.inet_aton(ip_mask[1]))[0]
    return ipv4, netmask


def _to_match_ipv6(value):
    ip_mask = value.split('/')
    if len(ip_mask) == 2 and ip_mask[1].isdigit() is False:
        # Both address and netmask are colon-hexadecimal.
        ipv6 = netaddr.IPAddress(ip_mask[0]).words
        netmask = netaddr.IPAddress(ip_mask[1]).words
    else:
        # For other formats.
        network = netaddr.IPNetwork(value)
        ipv6 = network.ip.words
        netmask = network.netmask.words
    return ipv6, netmask


def _to_match_metadata(value):
    if '/' in value:
        metadata = value.split('/')
        return _str_to_int(metadata[0]), _str_to_int(metadata[1])
    else:
        return _str_to_int(value), ofproto_v1_2_parser.UINT64_MAX


def _str_to_int(src):
    if isinstance(src, str):
        if src.startswith("0x") or src.startswith("0X"):
            dst = int(src, 16)
        else:
            dst = int(src)
    else:
        dst = src
    return dst


conv_dict = {
    'eth_src': 'dl_src',
    'eth_dst': 'dl_dst',
    'eth_type': 'dl_type',
    'ipv4_dst': 'nw_dst',
    'ipv4_src': 'nw_src',
    'ip_proto': 'nw_proto',
    'vlan_vid': 'dl_vlan',
    'tcp_src': 'tp_src',
    'tcp_dst': 'tp_dst',
    'udp_src': 'tp_src',
    'udp_dst': 'tp_dst',
}

""" Test_ofctl """


class Test_ofctl(unittest.TestCase):

    def __init__(self, methodName):
        super(Test_ofctl, self).__init__(methodName)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _test_actions(self, act, test):
        act_type = act["type"]
        to_actions = test.to_actions
        actions_to_str = test.actions_to_str
        dp = ofproto_protocol.ProtocolDesc(version=test.ver)
        act_list = []
        act_list.append(act)
        # str -> action
        result = to_actions(dp, act_list)
        insts = result[0]
        if act_type in test.supported_action:
            cls = test.supported_action[act_type]
        else:
            cls = None
        if act_type == 'GOTO_TABLE':
            ok_(isinstance(insts, cls))
            eq_(insts.table_id, act["table_id"])
        elif act_type == 'WRITE_METADATA':
            ok_(isinstance(insts, cls))
            eq_(insts.metadata, act["metadata"])
            eq_(insts.metadata_mask, act["metadata_mask"])
        elif act_type == 'METER':
            ok_(isinstance(insts, cls))
            eq_(insts.meter_id, act["meter_id"])
        else:
            ok_(isinstance(insts.actions[0], cls))
            if act_type == 'OUTPUT':
                eq_(insts.actions[0].port, act["port"])
            elif act_type == 'SET_MPLS_TTL':
                eq_(insts.actions[0].mpls_ttl, act["mpls_ttl"])
            elif act_type in ['PUSH_VLAN', 'PUSH_MPLS',
                              'POP_MPLS', 'PUSH_PBB']:
                eq_(insts.actions[0].ethertype, act["ethertype"])
            elif act_type == 'SET_QUEUE':
                eq_(insts.actions[0].queue_id, act["queue_id"])
            elif act_type == 'GROUP':
                eq_(insts.actions[0].group_id, act["group_id"])
            elif act_type == 'SET_NW_TTL':
                eq_(insts.actions[0].nw_ttl, act["nw_ttl"])
        # action -> str
        action_str = actions_to_str(result)
        action_str_list = action_str[0].split(':')
        eq_(action_str_list[0], act_type)
        if act_type == 'GOTO_TABLE':
            eq_(int(action_str_list[1]), act["table_id"])
        elif act_type == 'WRITE_METADATA':
            met = action_str_list[1].split('/')
            eq_(int(met[0], 16), act["metadata"])
            eq_(int(met[1], 16), act["metadata_mask"])
        elif act_type == 'METER':
            eq_(int(action_str_list[1]), act["meter_id"])
        else:
            if act_type == 'OUTPUT':
                eq_(int(action_str_list[1]), act["port"])
            elif act_type == 'SET_MPLS_TTL':
                eq_(int(action_str_list[1]), act["mpls_ttl"])
            elif act_type == 'PUSH_VLAN':
                eq_(int(action_str_list[1]), act["ethertype"])
            elif act_type == 'PUSH_MPLS':
                eq_(int(action_str_list[1]), act["ethertype"])
            elif act_type == 'POP_MPLS':
                eq_(int(action_str_list[1]), act["ethertype"])
            elif act_type == 'SET_QUEUE':
                eq_(int(action_str_list[1]), act["queue_id"])
            elif act_type == 'GROUP':
                eq_(int(action_str_list[1]), act["group_id"])
            elif act_type == 'SET_NW_TTL':
                eq_(int(action_str_list[1]), act["nw_ttl"])
            elif act_type == 'SET_FIELD':
                eq_(action_str_list[1].strip(' {'), act["field"])
                eq_(action_str_list[2].strip('} '), act["value"])
            elif act_type == 'PUSH_PBB':
                eq_(int(action_str_list[1]), act["ethertype"])

    def _test_to_match(self, attrs, test):
        to_match = test.to_match
        match_to_str = test.match_to_str
        dp = ofproto_protocol.ProtocolDesc(version=test.ver)
        # str -> match
        match = to_match(dp, attrs)
        buf = bytearray()
        match.serialize(buf, 0)
        match = match.__class__.parser(str(buf), 0)

        def equal_match(key, value, cls_name, fields):
            for field in fields:
                if cls_name in str(field):
                    if key in ['dl_src', 'dl_dst', 'arp_sha', 'arp_tha',
                               'eth_src', 'eth_dst']:
                        eth, mask = _to_match_eth(value)
                        str_eth = mac.haddr_to_str(eth)
                        str_mask = mac.haddr_to_str(mask)
                        str_value = mac.haddr_to_str(field.value)
                        for i in range(0, 17):
                            if str_mask[i] == 'f':
                                eq_(str_eth[i], str_value[i])
                            else:
                                continue
                        eq_(mask, field.mask)
                        return
                    elif key in ['nw_src', 'nw_dst', 'ipv4_src', 'ipv4_dst',
                                 'arp_spa', 'arp_tpa']:
                        ipv4, mask = _to_match_ip(value)
                        if mask == (1 << 32) - 1:
                            mask = None
                        eq_(ipv4, field.value)
                        eq_(mask, field.mask)
                        return
                    elif key in ['ipv6_src', 'ipv6_dst']:
                        ipv6, mask = _to_match_ipv6(value)
                        for i in range(0, 8):
                            if mask[i] == 65535:
                                eq_(ipv6[i], field.value[i])
                            else:
                                continue
                        eq_(list(mask), field.mask)
                        return
                    elif key == 'ipv6_nd_target':
                        ipv6, mask = _to_match_ipv6(value)
                        for i in range(0, 8):
                            if mask[i] == 65535:
                                eq_(ipv6[i], field.value[i])
                            else:
                                continue
                        return
                    elif key == 'ipv6_nd_sll' or key == 'ipv6_nd_tll':
                        eq_(mac.haddr_to_bin(value), field.value)
                        return
                    elif key == 'metadata':
                        metadata, mask = _to_match_metadata(value)
                        metadata = metadata & mask
                        if mask == (1 << 64) - 1:
                            mask = None
                        eq_(metadata, field.value)
                        eq_(mask, field.mask)
                        return
                    else:
                        eq_(value, field.value)
                        return
            assert False

        for key, value in attrs.items():
            if key.startswith('tp_'):
                cls = test.supported_match[key][attrs["ip_proto"]]
            elif key in test.supported_match:
                cls = test.supported_match[key]
            else:
                cls = None
            equal_match(key, value, cls.__name__, match.fields)

        # match -> str
        match_str = match_to_str(match)

        def equal_str(key, value, match_str):
            if key in ['dl_src', 'dl_dst', 'arp_sha', 'arp_tha']:
                eth_1, mask_1 = _to_match_eth(value)
                eth_2, mask_2 = _to_match_eth(match_str[key])
                str_eth_1 = mac.haddr_to_str(eth_1)
                str_mask_1 = mac.haddr_to_str(mask_1)
                str_eth_2 = mac.haddr_to_str(eth_2)
                for i in range(0, 17):
                    if str_mask_1[i] == 'f':
                        eq_(str_eth_1[i], str_eth_2[i])
                    else:
                        continue
                eq_(mask_1, mask_2)
                return
            elif key in['nw_src', 'nw_dst', 'arp_spa', 'arp_tpa']:
                ipv4_1, ip_mask_1 = _to_match_ip(value)
                ipv4_2, ip_mask_2 = _to_match_ip(match_str[key])
                eq_(ipv4_1, ipv4_2)
                eq_(ip_mask_1, ip_mask_2)
                return
            elif key in ['ipv6_src', 'ipv6_dst']:
                ipv6_1, netmask_1 = _to_match_ipv6(value)
                ipv6_2, netmask_2 = _to_match_ipv6(match_str[key])
                for i in range(0, 8):
                    if netmask_1[i] == 65535:
                        eq_(ipv6_1[i], ipv6_2[i])
                    else:
                        continue
                eq_(netmask_1, netmask_2)
                return
            elif key == 'ipv6_nd_target':
                ipv6_1, netmask_1 = _to_match_ipv6(value)
                ipv6_2, netmask_2 = _to_match_ipv6(match_str[key])
                for i in range(0, 8):
                    if netmask_1[i] == 65535:
                        eq_(ipv6_1[i], ipv6_2[i])
                    else:
                        continue
                return
            elif key == 'metadata':
                metadata_1, mask_1 = _to_match_metadata(value)
                metadata_1 = metadata_1 & mask_1
                metadata_2, mask_2 = _to_match_metadata(match_str[key])
                eq_(metadata_1, metadata_2)
                eq_(mask_1, mask_2)
                return
            eq_(value, match_str[key])

        for key, value in attrs.items():
            if key in conv_dict:
                key = conv_dict[key]
            equal_str(key, value, match_str)

""" Test_data for of_v1_2 """


class test_data_v1_2():

    def __init__(self):
        self.supported_action = {}
        self.supported_match = {}
        self.act_list = [
            {'type': 'OUTPUT', 'port': 3},
            {'type': 'COPY_TTL_OUT'},
            {'type': 'COPY_TTL_IN'},
            {'type': 'SET_MPLS_TTL', 'mpls_ttl': 64},
            {'type': 'DEC_MPLS_TTL'},
            {'type': 'PUSH_VLAN', 'ethertype': 0x0800},
            {'type': 'POP_VLAN'},
            {'type': 'PUSH_MPLS', 'ethertype': 0x0800},
            {'type': 'POP_MPLS', 'ethertype': 0x0800},
            {'type': 'SET_QUEUE', 'queue_id': 7},
            {'type': 'GROUP', 'group_id': 5},
            {'type': 'SET_NW_TTL', 'nw_ttl': 64},
            {'type': 'DEC_NW_TTL'},
            {'type': 'GOTO_TABLE', 'table_id': 8},
            {'type': 'WRITE_METADATA', 'metadata': 8,
             'metadata_mask': (1 << 64) - 1},
        ]
        self.attr_list = [
            {'in_port': 7},
            {'in_phy_port': 5, 'in_port': 3},
            {'metadata': '0x1212121212121212'},
            {'metadata': '0x19af28be37fa91b/0x1010101010101010'},
            {'dl_src': "aa:bb:cc:11:22:33"},
            {'dl_src': "aa:bb:cc:11:22:33/00:00:00:00:ff:ff"},
            {'dl_dst': "aa:bb:cc:11:22:33"},
            {'dl_dst': "aa:bb:cc:11:22:33/00:00:00:00:ff:ff"},
            {'dl_type': 123},
            {'eth_src': "aa:bb:cc:11:22:33"},
            {'eth_src': "aa:bb:cc:11:22:33/00:00:00:00:ff:ff"},
            {'eth_dst': "aa:bb:cc:11:22:33"},
            {'eth_dst': "aa:bb:cc:11:22:33/00:00:00:00:ff:ff"},
            {'eth_type': 0x800},
            {'dl_vlan': 5},
            {'vlan_pcp': 3, 'vlan_vid': 3},
            {'ip_dscp': 3, 'eth_type': 0x0800},
            {'ip_ecn': 4, 'eth_type': 0x86dd},
            {'nw_src': "192.168.0.1", 'eth_type': 0x0800},
            {'nw_src': "192.168.0.1/24", 'eth_type': 0x0800},
            {'nw_src': "192.168.10.10/255.255.0.0", 'eth_type': 0x0800},
            {'nw_dst': "192.168.0.1", 'eth_type': 0x0800},
            {'nw_dst': "192.168.0.1/24", 'eth_type': 0x0800},
            {'nw_dst': "192.168.10.10/255.255.255.0"},
            {'nw_proto': 5, 'eth_type': 0x0800},
            {'ip_proto': 5, 'eth_type': 0x86dd},
            {'ipv4_src': "192.168.0.1", 'eth_type': 0x0800},
            {'ipv4_src': "192.168.0.1/24", 'eth_type': 0x0800},
            {'ipv4_src': "192.168.10.10/255.255.0.0", 'eth_type': 0x0800},
            {'ipv4_dst': "192.168.0.1", 'eth_type': 0x0800},
            {'ipv4_dst': "192.168.0.1/24", 'eth_type': 0x0800},
            {'ipv4_dst': "192.168.10.10/255.255.255.0", 'eth_type': 0x0800},
            {'tp_src': 1, 'ip_proto': 6},
            {'tp_dst': 2, 'ip_proto': 6},
            {'tp_src': 3, 'ip_proto': 17},
            {'tp_dst': 4, 'ip_proto': 17},
            {'vlan_vid': 3},
            {'tcp_src': 3, 'ip_proto': 6},
            {'tcp_dst': 5, 'ip_proto': 6},
            {'udp_src': 2, 'ip_proto': 17},
            {'udp_dst': 6, 'ip_proto': 17},
            {'sctp_src': 99, 'ip_proto': 132},
            {'sctp_dst': 99, 'ip_proto': 132},
            {'icmpv4_type': 5, 'ip_proto': 1},
            {'icmpv4_code': 6, 'ip_proto': 1},
            {'arp_op': 3, 'eth_type': 0x0806},
            {'arp_spa': "192.168.0.11", 'eth_type': 0x0806},
            {'arp_spa': "192.168.0.22/24", 'eth_type': 0x0806},
            {'arp_tpa': "192.168.0.33", 'eth_type': 0x0806},
            {'arp_tpa': "192.168.0.44/24", 'eth_type': 0x0806},
            {'arp_sha': "aa:bb:cc:11:22:33", 'eth_type': 0x0806},
            {'arp_sha': "aa:bb:cc:11:22:33/00:00:00:00:ff:ff",
                'eth_type': 0x0806},
            {'arp_tha': "aa:bb:cc:11:22:33", 'eth_type': 0x0806},
            {'arp_tha': "aa:bb:cc:11:22:33/00:00:00:00:ff:ff",
                'eth_type': 0x0806},
            {'ipv6_src': '2001::aaaa:bbbb:cccc:1111', 'eth_type': 0x86dd},
            {'ipv6_src': '2001::aaaa:bbbb:cccc:1111/64', 'eth_type': 0x86dd},
            {'ipv6_dst': '2001::ffff:cccc:bbbb:1111', 'eth_type': 0x86dd},
            {'ipv6_dst': '2001::ffff:cccc:bbbb:1111/64', 'eth_type': 0x86dd},
            {'ipv6_flabel': 2, 'eth_type': 0x86dd},
            {'icmpv6_type': 3, 'ip_proto': 58},
            {'icmpv6_code': 4, 'ip_proto': 58},
            {'ipv6_nd_target': '2001::ffff:cccc:bbbb:1111',
                'icmpv6_type': 135, 'ip_proto': 58},
            {'ipv6_nd_sll': "aa:bb:cc:11:22:33",
                'icmpv6_type': 135, 'ip_proto': 58},
            {'ipv6_nd_tll': "aa:bb:cc:11:22:33",
                'icmpv6_type': 136, 'ip_proto': 58},
            {'mpls_label': 3, 'eth_type': 0x8848},
            {'mpls_tc': 2, 'eth_type': 0x8848}
        ]

    def set_ver(self, ver):
        self.ver = ver

    def set_attr(self, ofctl):
        self.to_match = getattr(ofctl, "to_match")
        self.match_to_str = getattr(ofctl, "match_to_str")
        self.to_actions = getattr(ofctl, "to_actions")
        self.actions_to_str = getattr(ofctl, "actions_to_str")

    def set_action_v1_2(self, parser):
        self.supported_action.update(
            {
                'OUTPUT': getattr(parser, "OFPActionOutput"),
                'COPY_TTL_OUT': getattr(parser, "OFPActionCopyTtlOut"),
                'COPY_TTL_IN': getattr(parser, "OFPActionCopyTtlIn"),
                'SET_MPLS_TTL': getattr(parser, "OFPActionSetMplsTtl"),
                'DEC_MPLS_TTL': getattr(parser, "OFPActionDecMplsTtl"),
                'PUSH_VLAN': getattr(parser, "OFPActionPushVlan"),
                'POP_VLAN': getattr(parser, "OFPActionPopVlan"),
                'PUSH_MPLS': getattr(parser, "OFPActionPushMpls"),
                'POP_MPLS': getattr(parser, "OFPActionPopMpls"),
                'SET_QUEUE': getattr(parser, "OFPActionSetQueue"),
                'GROUP': getattr(parser, "OFPActionGroup"),
                'SET_NW_TTL': getattr(parser, "OFPActionSetNwTtl"),
                'DEC_NW_TTL': getattr(parser, "OFPActionDecNwTtl"),
                'SET_FIELD': getattr(parser, "OFPActionSetField"),
                'GOTO_TABLE': getattr(parser, "OFPInstructionGotoTable"),
                'WRITE_METADATA': getattr(parser,
                                          "OFPInstructionWriteMetadata"),
            })

    def set_match_v1_2(self, parser):
        self.supported_match.update(
            {
                'in_port': getattr(parser, "MTInPort"),
                'in_phy_port': getattr(parser, "MTInPhyPort"),
                'metadata': getattr(parser, "MTMetadata"),
                'eth_dst': getattr(parser, "MTEthDst"),
                'dl_dst': getattr(parser, "MTEthDst"),
                'eth_src': getattr(parser, "MTEthSrc"),
                'dl_src': getattr(parser, "MTEthSrc"),
                'dl_type': getattr(parser, "MTEthType"),
                'eth_type': getattr(parser, "MTEthType"),
                'dl_vlan': getattr(parser, "MTVlanVid"),
                'vlan_vid': getattr(parser, "MTVlanVid"),
                'vlan_pcp': getattr(parser, "MTVlanPcp"),
                'ip_dscp': getattr(parser, "MTIPDscp"),
                'ip_ecn': getattr(parser, "MTIPECN"),
                'nw_proto': getattr(parser, "MTIPProto"),
                'ip_proto': getattr(parser, "MTIPProto"),
                'nw_src': getattr(parser, "MTIPV4Src"),
                'nw_dst': getattr(parser, "MTIPV4Dst"),
                'ipv4_src': getattr(parser, "MTIPV4Src"),
                'ipv4_dst': getattr(parser, "MTIPV4Dst"),
                'tp_src': {6: getattr(parser, "MTTCPSrc"),
                           17: getattr(parser, "MTUDPSrc")},
                'tp_dst': {6: getattr(parser, "MTTCPDst"),
                           17: getattr(parser, "MTUDPDst")},
                'tcp_src': getattr(parser, "MTTCPSrc"),
                'tcp_dst': getattr(parser, "MTTCPDst"),
                'udp_src': getattr(parser, "MTUDPSrc"),
                'udp_dst': getattr(parser, "MTUDPDst"),
                'sctp_src': getattr(parser, "MTSCTPSrc"),
                'sctp_dst': getattr(parser, "MTSCTPDst"),
                'icmpv4_type': getattr(parser, "MTICMPV4Type"),
                'icmpv4_code': getattr(parser, "MTICMPV4Code"),
                'arp_op': getattr(parser, "MTArpOp"),
                'arp_spa': getattr(parser, "MTArpSpa"),
                'arp_tpa': getattr(parser, "MTArpTpa"),
                'arp_sha': getattr(parser, "MTArpSha"),
                'arp_tha': getattr(parser, "MTArpTha"),
                'ipv6_src': getattr(parser, "MTIPv6Src"),
                'ipv6_dst': getattr(parser, "MTIPv6Dst"),
                'ipv6_flabel': getattr(parser, "MTIPv6Flabel"),
                'icmpv6_type': getattr(parser, "MTICMPV6Type"),
                'icmpv6_code': getattr(parser, "MTICMPV6Code"),
                'ipv6_nd_target': getattr(parser, "MTIPv6NdTarget"),
                'ipv6_nd_sll': getattr(parser, "MTIPv6NdSll"),
                'ipv6_nd_tll': getattr(parser, "MTIPv6NdTll"),
                'mpls_label': getattr(parser, "MTMplsLabel"),
                'mpls_tc': getattr(parser, "MTMplsTc"),
            })

""" Test_data for of_v1_3 """


class test_data_v1_3(test_data_v1_2):

    def __init__(self):
        test_data_v1_2.__init__(self)
        self.act_list.extend(
            [
                {'type': 'PUSH_PBB', 'ethertype': 0x0800},
                {'type': 'POP_PBB'},
                {'type': 'METER', 'meter_id': 3},
            ]
        )
        self.attr_list.extend(
            [
                {'mpls_bos': 3, 'eth_type': 0x8848},
                {'pbb_isid': 5, 'eth_type': 0x88E7},
                {'tunnel_id': 7},
                {'ipv6_exthdr': 3, 'eth_type': 0x86dd},
            ]
        )

    def set_action_v1_3(self, parser):
        self.set_action_v1_2(parser)
        self.supported_action.update(
            {
                'PUSH_PBB': getattr(parser, "OFPActionPushPbb"),
                'POP_PBB': getattr(parser, "OFPActionPopPbb"),
                'METER': getattr(parser, "OFPInstructionMeter"),
            })

    def set_match_v1_3(self, parser):
        self.set_match_v1_2(parser)
        self.supported_match.update(
            {
                'mpls_bos': getattr(parser, "MTMplsBos"),
                'pbb_isid': getattr(parser, "MTPbbIsid"),
                'tunnel_id': getattr(parser, "MTTunnelId"),
                'ipv6_exthdr': getattr(parser, "MTIPv6ExtHdr"),
            })

""" Test_data for of_v1_4 """

# class test_data_v1_4(test_data_v1_3):
    # def __init__(self):
        # test_data_v1_3.__init__(self)

    # def set_action_v1_4(self, parser):
        # self.set_action_v1_3(parser)

    # def set_match_v1_4(self, parser):
        # self.set_match_v1_3(parser)


def _add_tests_actions(cls):
    for act in cls.act_list:
        method_name = 'test_' + str(cls.ver) + '_' + act["type"] + '_action'

        def _run(self, name, act, cls):
            print ('processing %s ...' % name)
            cls_ = Test_ofctl(name)
            cls_._test_actions(act, cls)
        print ('adding %s ...' % method_name)
        func = functools.partial(_run, name=method_name, act=act, cls=cls)
        func.func_name = method_name
        func.__name__ = method_name
        im = new.instancemethod(func, None, Test_ofctl)
        setattr(Test_ofctl, method_name, im)


def _add_tests_match(cls):
    for attr in cls.attr_list:
        for key, value in attr.items():
            method_name = 'test_' + \
                str(cls.ver) + '_' + key + '_' + str(value) + '_match'

            def _run(self, name, attr, cls):
                print ('processing %s ...' % name)
                cls_ = Test_ofctl(name)
                cls_._test_to_match(attr, cls)
            print ('adding %s ...' % method_name)
            func = functools.partial(
                _run, name=method_name, attr=attr, cls=cls)
            func.func_name = method_name
            func.__name__ = method_name
            im = new.instancemethod(func, None, Test_ofctl)
            setattr(Test_ofctl, method_name, im)

""" Test case """

# for of12
cls = test_data_v1_2()
cls.set_action_v1_2(ofproto_v1_2_parser)
cls.set_match_v1_2(ofproto_v1_2_parser)
cls.set_ver(ofproto_v1_2.OFP_VERSION)
cls.set_attr(ofctl_v1_2)
_add_tests_actions(cls)
_add_tests_match(cls)

# for of13
cls = test_data_v1_3()
cls.set_action_v1_3(ofproto_v1_3_parser)
cls.set_match_v1_3(ofproto_v1_3_parser)
cls.set_ver(ofproto_v1_3.OFP_VERSION)
cls.set_attr(ofctl_v1_3)
_add_tests_actions(cls)
_add_tests_match(cls)

# for of14
# cls = test_data_v1_4()
# cls.set_action_v1_4(ofproto_v1_4_parser)
# cls.set_match_v1_4(ofproto_v1_4_parser)
# cls.set_ver(ofproto_v1_4.OFP_VERSION)
# cls.set_attr(ofctl_v1_4)
# _add_tests_actions(cls)
# _add_tests_match(cls)
