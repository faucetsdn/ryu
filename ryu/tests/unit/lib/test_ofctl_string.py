# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

from ryu.lib import ofctl_string
from ryu.ofproto import ofproto_parser
from ryu.ofproto.ofproto_protocol import ProtocolDesc
from ryu.ofproto import ofproto_v1_5


class Test_OfctlString(unittest.TestCase):
    """Test cases for ryu.ofproto.ofp_instruction_from_str.
    """

    def __init__(self, methodName):
        print('init %s' % methodName)
        self.fake_dp_of15 = ProtocolDesc(ofproto_v1_5.OFP_VERSION)
        self.maxDiff = None
        super(Test_OfctlString, self).__init__(methodName)

    def _test_str(self, dp, ofctl_str, *jsondict):
        json = ofctl_string.ofp_instruction_from_str(
            ofproto_v1_5, ofctl_str)
        inst = ofproto_parser.ofp_instruction_from_jsondict(dp, json)
        self.assertEqual(len(inst), len(jsondict))
        for i in range(len(inst)):
            self.assertEqual(jsondict[i], inst[i].to_jsondict())

    def test_drop(self):
        inst = ofctl_string.ofp_instruction_from_str(
            ofproto_v1_5, 'drop')
        self.assertEqual(inst, [])

    def test_conjunction(self):
        self._test_str(self.fake_dp_of15,
                       'conjunction(0x234, 1/3),conjunction(0xdea, 2/2)',
                       {'OFPInstructionActions': {
                           'actions': [
                               {'NXActionConjunction': {'clause': 0,
                                                        'experimenter': 8992,
                                                        'id': 0x234,
                                                        'len': None,
                                                        'n_clauses': 3,
                                                        'subtype': 34,
                                                        'type': 65535}},
                               {'NXActionConjunction': {'clause': 1,
                                                        'experimenter': 8992,
                                                        'id': 0xdea,
                                                        'len': None,
                                                        'n_clauses': 2,
                                                        'subtype': 34,
                                                        'type': 65535}}],
                           'type': 4}})

    def test_ct(self):
        self._test_str(self.fake_dp_of15,
                       'ct(commit)',
                       {'OFPInstructionActions': {
                           'actions': [{'NXActionCT': {'actions': [],
                                                       'alg': 0,
                                                       'experimenter': 8992,
                                                       'flags': 1,
                                                       'len': None,
                                                       'recirc_table': 255,
                                                       'subtype': 35,
                                                       'type': 65535,
                                                       'zone_ofs_nbits': 0,
                                                       'zone_src': u''}}],
                           'type': 4}})

    def test_ct_2(self):
        self._test_str(self.fake_dp_of15,
                       'ct(commit,zone=NXM_NX_REG8[0..15],'
                       'exec(set_field:1->ct_mark))',
                       {'OFPInstructionActions': {
                           'actions': [{'NXActionCT': {
                               'actions': [
                                   {'OFPActionSetField': {
                                       'field': {'OXMTlv': {'field': 'ct_mark',
                                                            'mask': None,
                                                            'value': 1}},
                                       'len': 8,
                                       'type': 25}}],
                               'alg': 0,
                               'experimenter': 8992,
                               'flags': 1,
                               'len': None,
                               'recirc_table': 255,
                               'subtype': 35,
                               'type': 65535,
                               'zone_ofs_nbits': 15,
                               'zone_src': u'reg8'}}],
                           'type': 4}})

    def test_resubmit(self):
        self._test_str(self.fake_dp_of15,
                       'resubmit(,10)',
                       {'OFPInstructionActions':
                        {'actions': [{'NXActionResubmitTable': {
                            'experimenter': 8992,
                            'in_port': 65528,
                            'len': None,
                            'subtype': 14,
                            'table_id': 10,
                            'type': 65535}}],
                         'type': 4}})

    def test_set_field(self):
        self._test_str(self.fake_dp_of15,
                       'set_field:10/0xff->tun_id',
                       {'OFPInstructionActions':
                        {'actions': [{'OFPActionSetField': {
                            'field': {'OXMTlv': {'field': 'tunnel_id',
                                                 'mask': 255,
                                                 'value': 10}},
                            'len': 8,
                            'type': 25}}],
                         'type': 4}})

    def test_pop_vlan(self):
        self._test_str(self.fake_dp_of15,
                       'pop_vlan',
                       {'OFPInstructionActions':
                        {'actions': [{'OFPActionPopVlan': {'len': 8,
                                                           'type': 18}}],
                         'type': 4}})

    def test_multi(self):
        self._test_str(self.fake_dp_of15,
                       'pop_vlan,goto_table:33',
                       {'OFPInstructionActions':
                        {'actions': [{'OFPActionPopVlan': {'len': 8,
                                                           'type': 18}}],
                         'type': 4}},
                       {'OFPInstructionGotoTable':
                        {'len': 8,
                         'table_id': 33,
                         'type': 1}})

    def test_multi_unordered(self):
        self._test_str(self.fake_dp_of15,
                       'pop_vlan,goto_table:33,output:1',
                       {'OFPInstructionActions':
                        {'actions': [{'OFPActionPopVlan': {'len': 8,
                                                           'type': 18}},
                                     {'OFPActionOutput': {'len': 16,
                                                          'max_len': 65509,
                                                          'port': 1,
                                                          'type': 0}}],
                         'type': 4}},
                       {'OFPInstructionGotoTable':
                        {'len': 8,
                         'table_id': 33,
                         'type': 1}})
