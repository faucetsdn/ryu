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
import inspect

from nose.tools import *

from ryu.lib import addrconv
from ryu.lib import ofctl_v1_0
from ryu.ofproto import ofproto_v1_0, ofproto_v1_0_parser
from ryu.lib import ofctl_v1_2
from ryu.ofproto import ofproto_v1_2, ofproto_v1_2_parser
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import inet
from ryu.tests import test_lib

LOG = logging.getLogger('test_ofctl_v1_2, v1_3')

""" Common Functions """


def _str_to_int(v):
    try:
        return int(v, 0)
    except (ValueError, TypeError):
        return v


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


def _to_masked_int_str(value):
    v, m = _to_match_masked_int(value)
    v &= m
    return '%d/%d' % (v, m)


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
        dp = ofproto_protocol.ProtocolDesc(version=test.ver)
        act_type = act["type"]

        # str -> action
        insts = test.to_actions(dp, [act])

        if test.ver == ofproto_v1_0.OFP_VERSION:
            action = insts[0]
            self._equal_str_to_act(action, act, act_type, test)
        else:
            inst = insts[0]
            self._equal_str_to_inst(inst, act, act_type, test)

        # action -> str
        inst_str = test.actions_to_str(insts)
        if test.ver == ofproto_v1_0.OFP_VERSION:
            act_str = inst_str
            self._equal_act_to_str(act_str, act, act_type, test)
        else:
            self._equal_inst_to_str(inst_str, act, act_type, test)

    def _test_match(self, attrs, test):
        dp = ofproto_protocol.ProtocolDesc(version=test.ver)

        # str -> match
        match = test.to_match(dp, attrs)

        for key, value in attrs.items():
            key = self._conv_key(test, key, attrs)
            self._equal_str_to_match(key, value, match, test)

        # match -> str
        match_str = test.match_to_str(match)

        for key, value in attrs.items():
            if key in conv_of12_to_of10_dict:
                key_old = conv_of12_to_of10_dict[key]
            else:
                key_old = key
            self._equal_match_to_str(key_old, value, match_str, test)

    def _equal_str_to_inst(self, inst, act, act_type, test):
        if act_type in test.supported_action:
            cls = test.supported_action[act_type]
        else:
            cls = None
        if act_type == 'GOTO_TABLE':
            ok_(isinstance(inst, cls))
            eq_(inst.table_id, act["table_id"])
        elif act_type == 'WRITE_METADATA':
            ok_(isinstance(inst, cls))
            eq_(inst.metadata, act["metadata"])
            eq_(inst.metadata_mask, act["metadata_mask"])
        elif act_type == 'METER':
            ok_(isinstance(inst, cls))
            eq_(inst.meter_id, act["meter_id"])
        elif act_type == 'WRITE_ACTIONS':
            ok_(isinstance(inst, cls))
            eq_(inst.type, test._ofproto.OFPIT_WRITE_ACTIONS)
            self._equal_str_to_act(inst.actions[0],
                                   act["actions"][0],
                                   act["actions"][0]["type"],
                                   test)
        elif act_type == 'CLEAR_ACTIONS':
            ok_(isinstance(inst, cls))
            eq_(inst.type, test._ofproto.OFPIT_CLEAR_ACTIONS)
        else:
            # APPLY_ACTIONS or Uknown Action Type
            ok_(isinstance(inst, test._parser.OFPInstructionActions))
            eq_(inst.type, test._ofproto.OFPIT_APPLY_ACTIONS)
            self._equal_str_to_act(inst.actions[0], act,
                                   act_type, test)

    def _equal_str_to_act(self, action, act, act_type, test):
        if act_type in test.supported_action:
            cls = test.supported_action[act_type]
        else:
            cls = None
        ok_(isinstance(action, cls))
        if act_type == 'OUTPUT':
            eq_(action.port, act["port"])
        elif act_type == 'SET_VLAN_VID':
            eq_(action.vlan_vid, act["vlan_vid"])
        elif act_type == 'SET_VLAN_PCP':
            eq_(action.vlan_pcp, act["vlan_pcp"])
        elif act_type == 'SET_DL_SRC':
            eq_(addrconv.mac.bin_to_text(action.dl_addr),
                act["dl_src"])
        elif act_type == 'SET_DL_DST':
            eq_(addrconv.mac.bin_to_text(action.dl_addr),
                act["dl_dst"])
        elif act_type == 'SET_NW_SRC':
            ip = netaddr.ip.IPAddress(action.nw_addr)
            eq_(str(ip), act["nw_src"])
        elif act_type == 'SET_NW_DST':
            ip = netaddr.ip.IPAddress(action.nw_addr)
            eq_(str(ip), act["nw_dst"])
        elif act_type == 'SET_NW_TOS':
            eq_(action.tos, act["nw_tos"])
        elif act_type == 'SET_TP_SRC':
            eq_(action.tp, act["tp_src"])
        elif act_type == 'SET_TP_DST':
            eq_(action.tp, act["tp_dst"])
        elif act_type == 'ENQUEUE':
            eq_(action.queue_id, act["queue_id"])
            eq_(action.port, act["port"])
        elif act_type == 'SET_MPLS_TTL':
            eq_(action.mpls_ttl, act["mpls_ttl"])
        elif act_type in ['PUSH_VLAN', 'PUSH_MPLS',
                          'POP_MPLS', 'PUSH_PBB']:
            eq_(action.ethertype, act["ethertype"])
        elif act_type == 'SET_QUEUE':
            eq_(action.queue_id, act["queue_id"])
        elif act_type == 'GROUP':
            eq_(action.group_id, act["group_id"])
        elif act_type == 'SET_NW_TTL':
            eq_(action.nw_ttl, act["nw_ttl"])
        elif act_type == 'SET_FIELD':
            eq_(action.key, act['field'])
            eq_(action.value, act['value'])
        elif act_type in ['STRIP_VLAN', 'COPY_TTL_OUT',
                          'COPY_TTL_IN', 'DEC_MPLS_TTL',
                          'POP_VLAN', 'DEC_NW_TTL', 'POP_PBB']:
            pass
        else:  # Uknown Action Type
            assert False

    def _equal_inst_to_str(self, inst_str, act, act_type, test):
        if act_type == 'WRITE_ACTIONS':
            act_str = inst_str[0]["WRITE_ACTIONS"]
            act = act["actions"][0]
            act_type = act["type"]
            self._equal_act_to_str(act_str, act, act_type, test)
        else:
            inst_str_list = inst_str[0].split(':', 1)
            eq_(inst_str_list[0], act_type)
            if act_type == 'GOTO_TABLE':
                eq_(int(inst_str_list[1]), act["table_id"])
            elif act_type == 'WRITE_METADATA':
                met = inst_str_list[1].split('/')
                eq_(int(met[0], 16), act["metadata"])
                eq_(int(met[1], 16), act["metadata_mask"])
            elif act_type == 'METER':
                eq_(int(inst_str_list[1]), act["meter_id"])
            elif act_type == 'CLEAR_ACTIONS':
                pass
            else:
                # APPLY_ACTIONS
                act_str = inst_str
                self._equal_act_to_str(act_str, act, act_type, test)

    def _equal_act_to_str(self, act_str, act, act_type, test):
        act_str_list = act_str[0].split(':', 1)
        eq_(act_str_list[0], act_type)
        if act_type == 'OUTPUT':
            eq_(int(act_str_list[1]), act["port"])
        elif act_type == 'SET_VLAN_VID':
            eq_(int(act_str_list[1]), act["vlan_vid"])
        elif act_type == 'SET_VLAN_PCP':
            eq_(int(act_str_list[1]), act["vlan_pcp"])
        elif act_type == 'SET_DL_SRC':
            eq_(act_str_list[1], act["dl_src"])
        elif act_type == 'SET_DL_DST':
            eq_(act_str_list[1], act["dl_dst"])
        elif act_type == 'SET_NW_SRC':
            eq_(act_str_list[1], act["nw_src"])
        elif act_type == 'SET_NW_DST':
            eq_(act_str_list[1], act["nw_dst"])
        elif act_type == 'SET_NW_TOS':
            eq_(int(act_str_list[1]), act["nw_tos"])
        elif act_type == 'SET_TP_SRC':
            eq_(int(act_str_list[1]), act["tp_src"])
        elif act_type == 'SET_TP_DST':
            eq_(int(act_str_list[1]), act["tp_dst"])
        elif act_type == 'ENQUEUE':
            enq = act_str_list[1].split(':')
            eq_(int(enq[0], 10), act["port"])
            eq_(int(enq[1], 10), act["queue_id"])
        elif act_type == 'SET_MPLS_TTL':
            eq_(int(act_str_list[1]), act["mpls_ttl"])
        elif act_type == 'PUSH_VLAN':
            eq_(int(act_str_list[1]), act["ethertype"])
        elif act_type == 'PUSH_MPLS':
            eq_(int(act_str_list[1]), act["ethertype"])
        elif act_type == 'POP_MPLS':
            eq_(int(act_str_list[1]), act["ethertype"])
        elif act_type == 'SET_QUEUE':
            eq_(int(act_str_list[1]), act["queue_id"])
        elif act_type == 'GROUP':
            eq_(int(act_str_list[1]), act["group_id"])
        elif act_type == 'SET_NW_TTL':
            eq_(int(act_str_list[1]), act["nw_ttl"])
        elif act_type == 'SET_FIELD':
            field, value = act_str_list[1].split(':')
            eq_(field.strip(' {'), act["field"])
            eq_(int(value.strip('} ')), act["value"])
        elif act_type == 'PUSH_PBB':
            eq_(int(act_str_list[1]), act["ethertype"])
        elif act_type in ['STRIP_VLAN', 'COPY_TTL_OUT',
                          'COPY_TTL_IN', 'DEC_MPLS_TTL',
                          'POP_VLAN', 'DEC_NW_TTL', 'POP_PBB']:
            pass
        else:
            assert False

    def _equal_str_to_match(self, key, value, match, test):
        field_value = self._get_field_value(test, key, match)

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
        elif key in ['dl_src', 'dl_dst']:
            eth, mask = _to_match_eth(value)
            field_value = addrconv.mac.bin_to_text(field_value)
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
        elif key in ['nw_src', 'nw_dst']:
            # IPv4 address
            ipv4, mask = _to_match_ip(value)
            field_value = _to_match_ip(field_value)
            if mask is not None:
                # with mask
                eq_(ipv4, field_value[0])
                eq_(mask, field_value[1])
            else:
                # without mask
                eq_(ipv4, field_value[0])
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
            if test.ver == ofproto_v1_0.OFP_VERSION:
                eq_(value, field_value)
            else:
                eq_(test.expected_value['vlan_vid'][
                    value]['to_match'], field_value)
            return
        else:
            if isinstance(value, str) and '/' in value:
                # with mask
                value, mask = _to_match_masked_int(value)
                value &= mask
                eq_(value, field_value[0])
                eq_(mask, field_value[1])
            else:
                # without mask
                eq_(_str_to_int(value), field_value)
            return

    def _equal_match_to_str(self, key, value, match_str, test):
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
            if test.ver == ofproto_v1_0.OFP_VERSION:
                ipv4, mask = _to_match_ip(value)
                field_value = _to_match_ip(field_value)
                if mask is not None:
                    # with mask
                    eq_(ipv4, field_value[0])
                    eq_(mask, field_value[1])
                else:
                    # without mask
                    eq_(ipv4, field_value[0])
            else:
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
            if test.ver == ofproto_v1_0.OFP_VERSION:
                eq_(value, field_value)
            else:
                eq_(test.expected_value['vlan_vid'][
                    value]['to_str'], field_value)
            return
        else:
            if isinstance(value, str) and '/' in value:
                # with mask
                value = _to_masked_int_str(value)
                eq_(value, field_value)
            else:
                # without mask
                eq_(_str_to_int(value), field_value)
            return

    def _conv_key(self, test, key, attrs):
        if test.ver != ofproto_v1_0.OFP_VERSION:
            if key in conv_of10_to_of12_dict:
                # For old field name
                key = conv_of10_to_of12_dict[key]
            elif key == 'tp_src' or key == 'tp_dst':
                # TCP/UDP port
                conv = {inet.IPPROTO_TCP: {'tp_src': 'tcp_src',
                                           'tp_dst': 'tcp_dst'},
                        inet.IPPROTO_UDP: {'tp_src': 'udp_src',
                                           'tp_dst': 'udp_dst'}}
                ip_proto = attrs.get('nw_proto', attrs.get('ip_proto', 0))
                key = conv[ip_proto][key]

        return key

    def _get_field_value(self, test, key, match):
        if test.ver == ofproto_v1_0.OFP_VERSION:
            members = inspect.getmembers(match)
            for member in members:
                if member[0] == key:
                    field_value = member[1]
                elif member[0] == 'wildcards':
                    wildcards = member[1]
            if key == 'nw_src':
                field_value = test.nw_src_to_str(wildcards, field_value)
            elif key == 'nw_dst':
                field_value = test.nw_dst_to_str(wildcards, field_value)
        else:
            field_value = match[key]

        return field_value


class test_data_base(object):
    # followings must be an attribute of subclass.
    # _ofctl
    # _ofproto

    def __init__(self):
        self.ver = self._ofproto.OFP_VERSION
        self.to_match = self._ofctl.to_match
        self.match_to_str = self._ofctl.match_to_str
        self.to_actions = self._ofctl.to_actions
        self.actions_to_str = self._ofctl.actions_to_str


class test_data_v1_0(test_data_base):
    """ Test_data for of_v1_0 """
    _ofctl = ofctl_v1_0
    _ofproto = ofproto_v1_0
    _parser = ofproto_v1_0_parser

    def __init__(self):
        super(test_data_v1_0, self).__init__()
        self.nw_src_to_str = self._ofctl.nw_src_to_str
        self.nw_dst_to_str = self._ofctl.nw_dst_to_str
        self.supported_action = {}
        self.act_list = [
            {'type': 'OUTPUT', 'port': 3},
            {'type': 'SET_VLAN_VID', 'vlan_vid': 5},
            {'type': 'SET_VLAN_PCP', 'vlan_pcp': 3},
            {'type': 'STRIP_VLAN'},
            {'type': 'SET_DL_SRC', 'dl_src': 'aa:bb:cc:11:22:33'},
            {'type': 'SET_DL_DST', 'dl_dst': 'aa:bb:cc:11:22:33'},
            {'type': 'SET_NW_SRC', 'nw_src': '10.0.0.1'},
            {'type': 'SET_NW_DST', 'nw_dst': '10.0.0.1'},
            {'type': 'SET_NW_TOS', 'nw_tos': 184},
            {'type': 'SET_TP_SRC', 'tp_src': 8080},
            {'type': 'SET_TP_DST', 'tp_dst': 8080},
            {'type': 'ENQUEUE', 'queue_id': 3, 'port': 1}
        ]
        self.attr_list = [
            {'in_port': 7},
            {'dl_src': 'aa:bb:cc:11:22:33'},
            {'dl_dst': 'aa:bb:cc:11:22:33'},
            {'dl_vlan': 5},
            {'dl_vlan_pcp': 3},
            {'dl_type': 123},
            {'nw_tos': 16},
            {'nw_proto': 5},
            {'nw_src': '192.168.0.1'},
            {'nw_src': '192.168.0.1/24'},
            {'nw_dst': '192.168.0.1'},
            {'nw_dst': '192.168.0.1/24'},
            {'tp_src': 1},
            {'tp_dst': 2}
        ]
        self.set_action()

    def set_action(self):
        self.supported_action.update(
            {
                'OUTPUT': self._parser.OFPActionOutput,
                'SET_VLAN_VID': self._parser.OFPActionVlanVid,
                'SET_VLAN_PCP': self._parser.OFPActionVlanPcp,
                'STRIP_VLAN': self._parser.OFPActionStripVlan,
                'SET_DL_SRC': self._parser.OFPActionSetDlSrc,
                'SET_DL_DST': self._parser.OFPActionSetDlDst,
                'SET_NW_SRC': self._parser.OFPActionSetNwSrc,
                'SET_NW_DST': self._parser.OFPActionSetNwDst,
                'SET_NW_TOS': self._parser.OFPActionSetNwTos,
                'SET_TP_SRC': self._parser.OFPActionSetTpSrc,
                'SET_TP_DST': self._parser.OFPActionSetTpDst,
                'ENQUEUE': self._parser.OFPActionEnqueue
            })


class test_data_v1_2(test_data_base):
    """ Test_data for of_v1_2 """
    _ofctl = ofctl_v1_2
    _ofproto = ofproto_v1_2
    _parser = ofproto_v1_2_parser

    def __init__(self):
        super(test_data_v1_2, self).__init__()
        self.supported_action = {}
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
            {"type": "CLEAR_ACTIONS"},
            {"type": "WRITE_ACTIONS",
             "actions": [{"type": "OUTPUT", "port": 4}]},
            {'type': 'GOTO_TABLE', 'table_id': 8},
            {'type': 'WRITE_METADATA', 'metadata': 8,
             'metadata_mask': (1 << 64) - 1},
        ]
        self.attr_list = [
            {'in_port': 7},
            {'in_phy_port': 5, 'in_port': 3},
            {'metadata': 12345},
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
        self.supported_action.update(
            {
                'OUTPUT': self._parser.OFPActionOutput,
                'COPY_TTL_OUT': self._parser.OFPActionCopyTtlOut,
                'COPY_TTL_IN': self._parser.OFPActionCopyTtlIn,
                'SET_MPLS_TTL': self._parser.OFPActionSetMplsTtl,
                'DEC_MPLS_TTL': self._parser.OFPActionDecMplsTtl,
                'PUSH_VLAN': self._parser.OFPActionPushVlan,
                'POP_VLAN': self._parser.OFPActionPopVlan,
                'PUSH_MPLS': self._parser.OFPActionPushMpls,
                'POP_MPLS': self._parser.OFPActionPopMpls,
                'SET_QUEUE': self._parser.OFPActionSetQueue,
                'GROUP': self._parser.OFPActionGroup,
                'SET_NW_TTL': self._parser.OFPActionSetNwTtl,
                'DEC_NW_TTL': self._parser.OFPActionDecNwTtl,
                'SET_FIELD': self._parser.OFPActionSetField,
                'GOTO_TABLE': self._parser.OFPInstructionGotoTable,
                'WRITE_METADATA': self._parser.OFPInstructionWriteMetadata,
                'WRITE_ACTIONS': self._parser.OFPInstructionActions,
                'CLEAR_ACTIONS': self._parser.OFPInstructionActions,
            })
        self.set_expected_value()

    def set_expected_value(self):
        vid_present = self._ofproto.OFPVID_PRESENT
        self.expected_value = {
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


class test_data_v1_3(test_data_v1_2):
    """ Test_data for of_v1_3 """
    _ofctl = ofctl_v1_3
    _ofproto = ofproto_v1_3
    _parser = ofproto_v1_3_parser

    def __init__(self):
        super(test_data_v1_3, self).__init__()
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
                {'pbb_isid': "0x05", 'eth_type': 0x88E7},
                {'pbb_isid': "0x05/0xff", 'eth_type': 0x88E7},
                {'tunnel_id': 7},
                {'tunnel_id': "0x07"},
                {'tunnel_id': "0x07/0xff"},
                {'ipv6_exthdr': 3, 'eth_type': 0x86dd},
                {'ipv6_exthdr': "0x40", 'eth_type': 0x86dd},
                {'ipv6_exthdr': "0x40/0x1F0", 'eth_type': 0x86dd},
            ]
        )
        self.supported_action.update(
            {
                'PUSH_PBB': self._parser.OFPActionPushPbb,
                'POP_PBB': self._parser.OFPActionPopPbb,
                'METER': self._parser.OFPInstructionMeter,
            })
        self.set_expected_value()


def _add_tests_actions(cls):
    for act in cls.act_list:
        method_name = 'test_' + str(cls.ver) + '_' + act["type"] + '_action'

        def _run(self, name, act, cls):
            print('processing %s ...' % name)
            cls_ = Test_ofctl(name)
            cls_._test_actions(act, cls)
        print('adding %s ...' % method_name)
        func = functools.partial(_run, name=method_name, act=act, cls=cls)
        test_lib.add_method(Test_ofctl, method_name, func)


def _add_tests_match(cls):
    for attr in cls.attr_list:
        for key, value in attr.items():
            method_name = 'test_' + \
                str(cls.ver) + '_' + key + '_' + str(
                    value) + str(type(value)) + '_match'

            def _run(self, name, attr, cls):
                print('processing %s ...' % name)
                cls_ = Test_ofctl(name)
                cls_._test_match(attr, cls)
            print('adding %s ...' % method_name)
            func = functools.partial(
                _run, name=method_name, attr=attr, cls=cls)
            test_lib.add_method(Test_ofctl, method_name, func)


""" Test case """

# for of10
cls = test_data_v1_0()
_add_tests_actions(cls)
_add_tests_match(cls)

# for of12
cls = test_data_v1_2()
_add_tests_actions(cls)
_add_tests_match(cls)

# for of13
cls = test_data_v1_3()
_add_tests_actions(cls)
_add_tests_match(cls)
