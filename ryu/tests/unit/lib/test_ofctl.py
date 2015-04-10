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
import netaddr
import functools

from nose.tools import *

from ryu.lib import ofctl_v1_2
from ryu.ofproto import ofproto_v1_2, ofproto_v1_2_parser
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import inet

LOG = logging.getLogger('test_ofctl_v1_2, v1_3')

""" Common Functions """


def _str_to_int(src):
    if isinstance(src, str):
        if src.startswith("0x") or src.startswith("0X"):
            dst = int(src, 16)
        else:
            dst = int(src)
    else:
        dst = src
    return dst


def _to_match_eth(value):
    if '/' in value:
        value = value.split('/')
        return value[0], value[1]
    else:
        return value, None


def _to_match_ip(value):
    if '/' in value:
        ip = netaddr.ip.IPNetwork(value)
        ip_addr = str(ip.network)
        ip_mask = str(ip.netmask)
        return ip_addr, ip_mask
    else:
        return value, None


def _to_match_masked_int(value):
    if isinstance(value, str) and '/' in value:
        value = value.split('/')
        return _str_to_int(value[0]), _str_to_int(value[1])
    else:
        return _str_to_int(value), None


conv_of10_to_of12_dict = {
    'dl_dst': 'eth_dst',
    'dl_src': 'eth_src',
    'dl_type': 'eth_type',
    'dl_vlan': 'vlan_vid',
    'nw_src': 'ipv4_src',
    'nw_dst': 'ipv4_dst',
    'nw_proto': 'ip_proto'
}


conv_of12_to_of10_dict = {
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
    'udp_dst': 'tp_dst'
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
        ofproto = dp.ofproto

        vid_present = dp.ofproto.OFPVID_PRESENT
        expected_value = {
            "vlan_vid": {
                0: {"to_match": 0 | vid_present, "to_str": "0"},
                3: {"to_match": 3 | vid_present, "to_str": "3"},
                4095: {"to_match": 4095 | vid_present, "to_str": "4095"},
                "0": {"to_match": 0 | vid_present, "to_str": "0"},
                "3": {"to_match": 3 | vid_present, "to_str": "3"},
                "4095": {"to_match": 4095 | vid_present, "to_str": "4095"},
                "0x0000": {"to_match": 0x0000, "to_str": "0x0000"},
                "0x0003": {"to_match": 0x0003, "to_str": "0x0003"},
                "0x0fff": {"to_match": 0x0fff, "to_str": "0x0fff"},
                "0x1000": {"to_match": 0x1000, "to_str": "0"},
                "0x1003": {"to_match": 0x1003, "to_str": "3"},
                "0x1fff": {"to_match": 0x1fff, "to_str": "4095"},
                "4096/4096": {"to_match": (4096, 4096),
                              "to_str": "0x1000/0x1000"},
                "4096/4097": {"to_match": (4096, 4097),
                              "to_str": "0x1000/0x1001"},
                "2744/2748": {"to_match": (2744, 2748),
                              "to_str": "0x0ab8/0x0abc"},
                "2748/2748": {"to_match": (2748, 2748),
                              "to_str": "0x0abc/0x0abc"},
                "2748/2749": {"to_match": (2748, 2749),
                              "to_str": "0x0abc/0x0abd"},
                "0x1000/0x1000": {"to_match": (0x1000, 0x1000),
                                  "to_str": "0x1000/0x1000"},
                "0x1000/0x1001": {"to_match": (0x1000, 0x1001),
                                  "to_str": "0x1000/0x1001"},
                "0x0ab8/0x0abc": {"to_match": (0x0ab8, 0x0abc),
                                  "to_str": "0x0ab8/0x0abc"},
                "0x0abc/0x0abc": {"to_match": (0x0abc, 0x0abc),
                                  "to_str": "0x0abc/0x0abc"},
                "0x0abc/0x0abd": {"to_match": (0x0abc, 0x0abd),
                                  "to_str": "0x0abc/0x0abd"}
            }
        }

        # str -> match
        match = to_match(dp, attrs)

        def equal_match(key, value, match):
            field_value = match[key]
            if key in ['eth_src', 'eth_dst', 'arp_sha', 'arp_tha']:
                # MAC address
                eth, mask = _to_match_eth(value)
                if mask is not None:
                    # with mask
                    for i in range(0, len(mask)):
                        if mask[i] == 'f':
                            eq_(eth[i], field_value[0][i])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(eth, field_value)
                return
            elif key in ['ipv4_src', 'ipv4_dst', 'arp_spa', 'arp_tpa']:
                # IPv4 address
                ipv4, mask = _to_match_ip(value)
                if mask is not None:
                    # with mask
                    eq_(ipv4, field_value[0])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(ipv4, field_value)
                return
            elif key in ['ipv6_src', 'ipv6_dst']:
                # IPv6 address
                ipv6, mask = _to_match_ip(value)
                if mask is not None:
                    # with mask
                    eq_(ipv6, field_value[0])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(ipv6, field_value)
                return
            elif key == 'vlan_vid':
                eq_(expected_value['vlan_vid'][value]['to_match'], field_value)
                return
            elif key == 'metadata' or key == 'ipv6_exthdr':
                # Metadata or IPv6 Extension Header pseudo-field
                value, mask = _to_match_masked_int(value)
                if mask is not None:
                    # with mask
                    value &= mask
                    eq_(value, field_value[0])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(value, field_value)
                return
            else:
                eq_(value, field_value)
                return

        for key, value in attrs.items():
            if key in conv_of10_to_of12_dict:
                # For old field name
                key_new = conv_of10_to_of12_dict[key]
            elif key == 'tp_src' or key == 'tp_dst':
                # TCP/UDP port
                conv = {inet.IPPROTO_TCP: {'tp_src': 'tcp_src',
                                           'tp_dst': 'tcp_dst'},
                        inet.IPPROTO_UDP: {'tp_src': 'udp_src',
                                           'tp_dst': 'udp_dst'}}
                ip_proto = attrs.get('nw_proto', attrs.get('ip_proto', 0))
                key_new = conv[ip_proto][key]
            else:
                key_new = key
            equal_match(key_new, value, match)

        # match -> str
        match_str = match_to_str(match)

        def equal_str(key, value, match_str):
            field_value = match_str[key]
            if key in ['dl_src', 'dl_dst', 'arp_sha', 'arp_tha']:
                # MAC address
                eth, mask = _to_match_eth(value)
                if mask is not None:
                    # with mask
                    field_value = field_value.split('/')
                    for i in range(0, len(mask)):
                        if mask[i] == 'f':
                            eq_(eth[i], field_value[0][i])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(eth, field_value)
                return
            elif key in['nw_src', 'nw_dst', 'arp_spa', 'arp_tpa']:
                # IPv4 address
                ipv4, mask = _to_match_ip(value)
                if mask is not None:
                    # with mask
                    field_value = field_value.split('/')
                    eq_(ipv4, field_value[0])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(ipv4, field_value)
                return
            elif key in ['ipv6_src', 'ipv6_dst']:
                # IPv6 address
                ipv6, mask = _to_match_ip(value)
                if mask is not None:
                    # with mask
                    field_value = field_value.split('/')
                    eq_(ipv6, field_value[0])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(ipv6, field_value)
                return
            elif key == 'dl_vlan':
                eq_(expected_value['vlan_vid'][value]['to_str'], field_value)
                return
            elif key == 'metadata' or key == 'ipv6_exthdr':
                # Metadata or IPv6 Extension Header pseudo-field
                value, mask = _to_match_masked_int(value)
                if mask is not None:
                    # with mask
                    field_value = field_value.split('/')
                    value &= mask
                    eq_(str(value), field_value[0])
                    eq_(str(mask), field_value[1])
                else:
                    # without mask
                    eq_(str(value), field_value)
                return
            else:
                eq_(value, field_value)
                return

        for key, value in attrs.items():
            if key in conv_of12_to_of10_dict:
                key_old = conv_of12_to_of10_dict[key]
            else:
                key_old = key
            equal_str(key_old, value, match_str)

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
            {'dl_vlan': 0},
            {'dl_vlan': 3},
            {'dl_vlan': 4095},
            {'dl_vlan': "0"},
            {'dl_vlan': "3"},
            {'dl_vlan': "4095"},
            {'dl_vlan': "0x0000"},
            {'dl_vlan': "0x0003"},
            {'dl_vlan': "0x0fff"},
            {'dl_vlan': "0x1000"},
            {'dl_vlan': "0x1003"},
            {'dl_vlan': "0x1fff"},
            {'dl_vlan': "4096/4096"},
            {'dl_vlan': "4096/4097"},
            {'dl_vlan': "2744/2748"},
            {'dl_vlan': "2748/2748"},
            {'dl_vlan': "2748/2749"},
            {'dl_vlan': "0x1000/0x1000"},
            {'dl_vlan': "0x1000/0x1001"},
            {'dl_vlan': "0x0ab8/0x0abc"},
            {'dl_vlan': "0x0abc/0x0abc"},
            {'dl_vlan': "0x0abc/0x0abd"},
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
            {'vlan_vid': 0},
            {'vlan_vid': 3},
            {'vlan_vid': 4095},
            {'vlan_vid': "0"},
            {'vlan_vid': "3"},
            {'vlan_vid': "4095"},
            {'vlan_vid': "0x0000"},
            {'vlan_vid': "0x0003"},
            {'vlan_vid': "0x0fff"},
            {'vlan_vid': "0x1000"},
            {'vlan_vid': "0x1003"},
            {'vlan_vid': "0x1fff"},
            {'vlan_vid': "4096/4096"},
            {'vlan_vid': "4096/4097"},
            {'vlan_vid': "2744/2748"},
            {'vlan_vid': "2748/2748"},
            {'vlan_vid': "2748/2749"},
            {'vlan_vid': "0x1000/0x1000"},
            {'vlan_vid': "0x1000/0x1001"},
            {'vlan_vid': "0x0ab8/0x0abc"},
            {'vlan_vid': "0x0abc/0x0abc"},
            {'vlan_vid': "0x0abc/0x0abd"},
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
                {'ipv6_exthdr': "0x40", 'eth_type': 0x86dd},
                {'ipv6_exthdr': "0x40/0x1F0", 'eth_type': 0x86dd},
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
            print('processing %s ...' % name)
            cls_ = Test_ofctl(name)
            cls_._test_actions(act, cls)
        print('adding %s ...' % method_name)
        func = functools.partial(_run, name=method_name, act=act, cls=cls)
        func.func_name = method_name
        func.__name__ = method_name
        setattr(Test_ofctl, method_name, func)


def _add_tests_match(cls):
    for attr in cls.attr_list:
        for key, value in attr.items():
            method_name = 'test_' + \
                str(cls.ver) + '_' + key + '_' + str(
                    value) + str(type(value)) + '_match'

            def _run(self, name, attr, cls):
                print('processing %s ...' % name)
                cls_ = Test_ofctl(name)
                cls_._test_to_match(attr, cls)
            print('adding %s ...' % method_name)
            func = functools.partial(
                _run, name=method_name, attr=attr, cls=cls)
            func.func_name = method_name
            func.__name__ = method_name
            setattr(Test_ofctl, method_name, func)


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
