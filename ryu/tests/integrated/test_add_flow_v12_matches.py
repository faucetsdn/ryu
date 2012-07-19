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

from ryu.controller import handler
from ryu.controller.handler import set_ev_cls
from ryu.tests.integrated import tester
from ryu.ofproto import nx_match

LOG = logging.getLogger(__name__)

_target = 'br-tester'

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_AH = 51
IPPROTO_ICMPV6 = 58
IPPROTO_NONE = 59
IPPROTO_DSTOPTS = 60
IPPROTO_SCTP = 132


class RunTest(tester.RunTestBase):
    """ Test case for add flows of Matches
    """

    def __init__(self):
        super(RunTest, self).__init__()

    def _set_val(self, type_, name, val):
        self.set_val('type', type_)
        self.set_val('name', name)
        self.set_val('val', val)

    def _get_val(self):
        type_ = self.get_val('type')
        name = self.get_val('name')
        val = self.get_val('val')
        return (type_, name, val)

    def _check_default(self):
        type_, name, val = self._get_val()

        ovs_flow = {}
        try:
            ovs_flow = self.get_ovs_flows(_target)[0][type_]
        except (KeyError, IndexError):
            pass

        ng = 0
        if val == None:
            if name in ovs_flow:
                ng = 1
        elif not name in ovs_flow or val != ovs_flow[name]:
            ng = 1

        if ng:
            err = ' send (%s:%s=%s)\n flow (%s:%s)' \
                   % (type_, name, val, type_, self.cnv_txt(ovs_flow))
            self.results(ret=False, msg=err)
        else:
            self.results()

    def test_rule_set_in_port(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        in_port = 42123
        self._set_val('rules',
                      'in_port',
                      str(in_port))

        match = ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_dst = 'e2:7a:09:79:0b:0f'
        self._set_val('rules',
                      'dl_dst',
                      dl_dst)
        dl_dst_bin = self.haddr_to_bin(dl_dst)

        match = ofproto_parser.OFPMatch()
        match.set_dl_dst(dl_dst_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_dst_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_dst = 'd0:98:79:b4:75:b5'
        self._set_val('rules',
                      'dl_dst',
                      dl_dst)
        dl_dst_bin = self.haddr_to_bin(dl_dst)

        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_dst_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_dst = 'a6:cf:40:9d:72:ec'
        mask = 'ff:ff:ff:ff:ff:00'
        self._set_val('rules',
                      'dl_dst',
                      dl_dst[:-2] + '00' + '/' + mask)

        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask_bin = self.haddr_to_bin(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_dst_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_dst = 'c6:12:6a:ae:da:0a'
        mask = '00:00:00:00:00:00'
        self._set_val('rules',
                      'dl_dst',
                      None)

        dl_dst_bin = self.haddr_to_bin(dl_dst)
        mask_bin = self.haddr_to_bin(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_dst_masked(dl_dst_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_src = 'e2:7a:09:79:0b:0f'
        self._set_val('rules',
                      'dl_src',
                      dl_src)
        dl_src_bin = self.haddr_to_bin(dl_src)

        match = ofproto_parser.OFPMatch()
        match.set_dl_src(dl_src_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_src_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_src = 'd0:98:79:b4:75:b5'
        self._set_val('rules',
                      'dl_src',
                      dl_src)
        dl_src_bin = self.haddr_to_bin(dl_src)

        mask = 'ff:ff:ff:ff:ff:ff'
        mask_bin = self.haddr_to_bin(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_src_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_src = 'a6:cf:40:9d:72:ec'
        mask = 'ff:ff:ff:ff:ff:00'
        self._set_val('rules',
                      'dl_src',
                      dl_src[:-2] + '00' + '/' + mask)

        dl_src_bin = self.haddr_to_bin(dl_src)
        mask_bin = self.haddr_to_bin(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_src_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_src = 'c6:12:6a:ae:da:0a'
        mask = '00:00:00:00:00:00'
        self._set_val('rules',
                      'dl_src',
                      None)

        dl_src_bin = self.haddr_to_bin(dl_src)
        mask_bin = self.haddr_to_bin(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_src_masked(dl_src_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_type_ip(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        self._set_val('rules',
                      'ip',
                      'ip')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_type_arp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        self._set_val('rules',
                      'arp',
                      'arp')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_type_vlan(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_VLAN
        self._set_val('rules',
                      'dl_type',
                      hex(dl_type))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_type_ipv6(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        self._set_val('rules',
                      'ipv6',
                      'ipv6')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_dl_type_lacp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_LACP
        self._set_val('rules',
                      'dl_type',
                      hex(dl_type))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_dscp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_dscp = 36
        self._set_val('rules',
                      'nw_tos',
                      str(ip_dscp))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_dscp(ip_dscp)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_vlan_vid(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        vlan_vid = 0b101010101010
        self._set_val('rules',
                      'dl_vlan',
                      str(vlan_vid))

        match = ofproto_parser.OFPMatch()
        match.set_vlan_vid(vlan_vid)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_vlan_vid_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        vlan_vid = 0x4ef
        mask = 0xfff
        self._set_val('rules',
                      'dl_vlan',
                      str(vlan_vid))

        match = ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_vlan_vid_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        vlan_vid = 0x7f
        mask = 0xff0
        # OVS set CFI filed is '1'
        self._set_val('rules',
                      'vlan_tci',
                      '0x1070/0x1ff0')

        match = ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_vlan_vid_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        vlan_vid = 0x4ef
        mask = 0x000
        self._set_val('rules',
                      'vlan_vid',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_vlan_vid_masked(vlan_vid, mask)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_vlan_pcp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        vlan_vid = 4023
        vlan_pcp = 5
        self._set_val('rules',
                      'dl_vlan_pcp',
                      str(vlan_pcp))

        match = ofproto_parser.OFPMatch()
        match.set_vlan_vid(vlan_vid)
        match.set_vlan_pcp(vlan_pcp)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_ecn(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_ecn = 3
        self._set_val('rules',
                      'nw_ecn',
                      str(ip_ecn))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_ecn(ip_ecn)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_icmp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_ICMP
        self._set_val('rules',
                      'icmp',
                      'icmp')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_tcp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_TCP
        self._set_val('rules',
                      'tcp',
                      'tcp')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_udp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_UDP
        self._set_val('rules',
                      'udp',
                      'udp')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_ipv6_route(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_ROUTING
        self._set_val('rules',
                      'nw_proto',
                      str(ip_proto))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_ipv6_frag(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_FRAGMENT
        self._set_val('rules',
                      'nw_proto',
                      str(ip_proto))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_ipv6_icmp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_ICMPV6
        self._set_val('rules',
                      'icmp6',
                      'icmp6')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_ipv6_none(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_NONE
        self._set_val('rules',
                      'nw_proto',
                      str(ip_proto))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ip_proto_ipv6_dstopts(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_DSTOPTS
        self._set_val('rules',
                      'nw_proto',
                      str(ip_proto))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        src = '192.168.196.250'
        src_int = self.ipv4_to_int(src)
        self._set_val('rules',
                      'nw_src',
                      src)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src(src_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_src_masked_32(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        src = '192.168.98.73'
        mask = '255.255.255.255'
        self._set_val('rules',
                      'nw_src',
                      src)

        src_int = self.ipv4_to_int(src)
        mask_int = self.ipv4_to_int(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src_masked(src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_src_masked_24(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        src = '192.168.188.254'
        mask = '255.255.255.0'
        self._set_val('rules',
                      'nw_src',
                      src[:-3] + '0/24')

        src_int = self.ipv4_to_int(src)
        mask_int = self.ipv4_to_int(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src_masked(src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_src_masked_0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        src = '192.168.188.254'
        mask = '0.0.0.0'
        self._set_val('rules',
                      'nw_src',
                      None)

        src_int = self.ipv4_to_int(src)
        mask_int = self.ipv4_to_int(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_src_masked(src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        dst = '192.168.54.155'
        self._set_val('rules',
                      'nw_dst',
                      dst)
        dst_int = self.ipv4_to_int(dst)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst(dst_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_dst_masked_32(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        dst = '192.168.54.155'
        mask = '255.255.255.255'
        self._set_val('rules',
                      'nw_dst',
                      dst)

        dst_int = self.ipv4_to_int(dst)
        mask_int = self.ipv4_to_int(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst_masked(dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_dst_masked_24(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        dst = '192.168.54.155'
        mask = '255.255.255.0'
        self._set_val('rules',
                      'nw_dst',
                      dst[:-3] + '0/24')

        dst_int = self.ipv4_to_int(dst)
        mask_int = self.ipv4_to_int(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst_masked(dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv4_dst_masked_0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        dst = '192.168.54.155'
        mask = '0.0.0.0'
        self._set_val('rules',
                      'nw_dst',
                      None)

        dst_int = self.ipv4_to_int(dst)
        mask_int = self.ipv4_to_int(mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv4_dst_masked(dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_tcp_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_TCP
        tp_src = 1103
        self._set_val('rules',
                      'tp_src',
                      str(tp_src))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_tcp_src(tp_src)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_tcp_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_TCP
        tp_dst = 236
        self._set_val('rules',
                      'tp_dst',
                      str(tp_dst))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_tcp_dst(tp_dst)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_udp_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_UDP
        tp_src = 56617
        self._set_val('rules',
                      'tp_src',
                      str(tp_src))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_udp_src(tp_src)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_udp_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_UDP
        tp_dst = 61278
        self._set_val('rules',
                      'tp_dst',
                      str(tp_dst))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_udp_dst(tp_dst)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_icmpv4_type(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_ICMP
        # type = 8: Echo Request
        icmp_type = 8
        self._set_val('rules',
                      'icmp_type',
                      str(icmp_type))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv4_type(icmp_type)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_icmpv4_code(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IP
        ip_proto = IPPROTO_ICMP
        # type = 9 : Router Advertisement
        # code = 16: Does not route common traffic
        icmp_type = 9
        icmp_code = 16
        self._set_val('rules',
                      'icmp_code',
                      str(icmp_code))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv4_type(icmp_type)
        match.set_icmpv4_code(icmp_code)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_opcode(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_op = 1
        self._set_val('rules',
                      'arp_op',
                      str(arp_op))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_opcode(arp_op)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_spa(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        nw_src_int = self.ipv4_to_int(nw_src)
        self._set_val('rules',
                      'nw_src',
                      nw_src)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa(nw_src_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_spa_masked_32(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        mask = '255.255.255.255'
        nw_src_int = self.ipv4_to_int(nw_src)
        mask_int = self.ipv4_to_int(mask)

        self._set_val('rules',
                      'nw_src',
                      nw_src)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa_masked(nw_src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_spa_masked_24(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        mask = '255.255.255.0'
        nw_src_int = self.ipv4_to_int(nw_src)
        mask_int = self.ipv4_to_int(mask)

        self._set_val('rules',
                      'nw_src',
                      nw_src[:-2] + '0/24')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa_masked(nw_src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_spa_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_src = '192.168.222.57'
        mask = '0.0.0.0'
        nw_src_int = self.ipv4_to_int(nw_src)
        mask_int = self.ipv4_to_int(mask)

        self._set_val('rules',
                      'nw_src',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_spa_masked(nw_src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tpa(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        nw_dst_int = self.ipv4_to_int(nw_dst)

        self._set_val('rules',
                      'nw_dst',
                      nw_dst)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa(nw_dst_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tpa_masked_32(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        mask = '255.255.255.255'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        mask_int = self.ipv4_to_int(mask)

        self._set_val('rules',
                      'nw_dst',
                      nw_dst)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa_masked(nw_dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tpa_masked_24(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        mask = '255.255.255.0'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        mask_int = self.ipv4_to_int(mask)

        self._set_val('rules',
                      'nw_dst',
                      nw_dst[:-3] + '0/24')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa_masked(nw_dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tpa_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        nw_dst = '192.168.198.233'
        mask = '0.0.0.0'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        mask_int = self.ipv4_to_int(mask)

        self._set_val('rules',
                      'nw_dst',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tpa_masked(nw_dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_sha(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        self._set_val('rules',
                      'arp_sha',
                      arp_sha)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha(arp_sha_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_sha_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        mask = 'ff:ff:ff:ff:ff:ff'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        mask_bin = self.haddr_to_bin(mask)

        self._set_val('rules',
                      'arp_sha',
                      arp_sha)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha_masked(arp_sha_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_sha_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        mask = 'ff:ff:ff:ff:ff:00'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        mask_bin = self.haddr_to_bin(mask)

        self._set_val('rules',
                      'arp_sha',
                      arp_sha[:-2] + '00/' + mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha_masked(arp_sha_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_sha_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_sha = '3e:ec:13:9b:f3:0b'
        mask = '00:00:00:00:00:00'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        mask_bin = self.haddr_to_bin(mask)

        self._set_val('rules',
                      'arp_sha',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_sha_masked(arp_sha_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tha(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_tha = '83:6c:21:52:49:68'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        self._set_val('rules',
                      'arp_tha',
                      arp_tha)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha(arp_tha_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tha_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_tha = '3e:ec:13:9b:f3:0b'
        mask = 'ff:ff:ff:ff:ff:ff'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        mask_bin = self.haddr_to_bin(mask)

        self._set_val('rules',
                      'arp_tha',
                      arp_tha)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha_masked(arp_tha_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tha_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_tha = '3e:ec:13:9b:f3:0b'
        mask = 'ff:ff:ff:ff:ff:00'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        mask_bin = self.haddr_to_bin(mask)

        self._set_val('rules',
                      'arp_tha',
                      arp_tha[:-2] + '00/' + mask)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha_masked(arp_tha_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_arp_tha_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_ARP
        arp_tha = '3e:ec:13:9b:f3:0b'
        mask = '00:00:00:00:00:00'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        mask_bin = self.haddr_to_bin(mask)

        self._set_val('rules',
                      'arp_tha',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_arp_tha_masked(arp_tha_bin, mask_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        self._set_val('rules',
                      'ipv6_src',
                      ipv6_src)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src(ipv6_src_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_src_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        mask_int = self.ipv6_to_int(mask)
        self._set_val('rules',
                      'ipv6_src',
                      ipv6_src)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src_masked(ipv6_src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_src_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:0'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        mask_int = self.ipv6_to_int(mask)
        self._set_val('rules',
                      'ipv6_src',
                      ipv6_src[:-4] + '0/112')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src_masked(ipv6_src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_src_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_src = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        mask = '0:0:0:0:0:0:0:0'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        mask_int = self.ipv6_to_int(mask)
        self._set_val('rules',
                      'ipv6_src',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_src_masked(ipv6_src_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        self._set_val('rules',
                      'ipv6_dst',
                      ipv6_dst)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst(ipv6_dst_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_dst_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        mask_int = self.ipv6_to_int(mask)
        self._set_val('rules',
                      'ipv6_dst',
                      ipv6_dst)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst_masked(ipv6_dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_dst_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:0'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        mask_int = self.ipv6_to_int(mask)
        self._set_val('rules',
                      'ipv6_dst',
                      ipv6_dst[:-4] + '0/112')

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst_masked(ipv6_dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_dst_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_dst = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        mask = '0:0:0:0:0:0:0:0'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        mask_int = self.ipv6_to_int(mask)
        self._set_val('rules',
                      'ipv6_dst',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_dst_masked(ipv6_dst_int, mask_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_flabel(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        self._set_val('rules',
                      'ipv6_label',
                      hex(ipv6_label))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel(ipv6_label)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_flabel_masked_ff(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0xfffff
        self._set_val('rules',
                      'ipv6_label',
                      hex(ipv6_label))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_flabel_masked_f0(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0xffff0
        self._set_val('rules',
                      'ipv6_label',
                      hex(ipv6_label)[:-1] + '0/' + hex(mask))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_flabel_masked_00(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ipv6_label = 0xc5384
        mask = 0x0
        self._set_val('rules',
                      'ipv6_label',
                      None)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ipv6_flabel_masked(ipv6_label, mask)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_icmpv6_type(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_ICMPV6
        icmp_type = 129
        self._set_val('rules',
                      'icmp_type',
                      str(icmp_type))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_icmpv6_code(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_ICMPV6
        icmp_type = 138
        icmp_code = 1
        self._set_val('rules',
                      'icmp_code',
                      str(icmp_code))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_icmpv6_code(icmp_code)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_nd_target(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_ICMPV6

        # type = 135 : Neighbor Solicitation
        icmp_type = 135
        target = "5420:db3f:921b:3e33:2791:98f:dd7f:2e19"
        target_int = self.ipv6_to_int(target)
        self._set_val('rules',
                      'nd_target',
                      target)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_ipv6_nd_target(target_int)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_nd_sll(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_ICMPV6

        # type = 135 : Neighbor Solicitation
        icmp_type = 135
        nd_sll = "93:6d:d0:d4:e8:36"
        nd_sll_bin = self.haddr_to_bin(nd_sll)
        self._set_val('rules',
                      'nd_sll',
                      nd_sll)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_ipv6_nd_sll(nd_sll_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_ipv6_nd_tll(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        ip_proto = IPPROTO_ICMPV6

        # type = 136 : Neighbor Advertisement
        icmp_type = 136
        nd_tll = "18:f6:66:b6:f1:b3"
        nd_tll_bin = self.haddr_to_bin(nd_tll)
        self._set_val('rules',
                      'nd_tll',
                      nd_tll)

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_ip_proto(ip_proto)
        match.set_icmpv6_type(icmp_type)
        match.set_ipv6_nd_tll(nd_tll_bin)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_mpls_label(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = 0x8847
        label = 2144
        self._set_val('rules',
                      'mpls_label',
                      str(label))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_mpls_label(label)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)

    def test_rule_set_mpls_tc(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = 0x8847
        tc = 3
        self._set_val('rules',
                      'mpls_tc',
                      str(tc))

        match = ofproto_parser.OFPMatch()
        match.set_dl_type(dl_type)
        match.set_mpls_tc(tc)
        inst = []

        m = ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                      ofproto.OFPFC_ADD,
                                      0, 0, 0, 0xffffffff,
                                      ofproto.OFPP_ANY, 0xffffffff,
                                      0, match, inst)
        datapath.send_msg(m)
