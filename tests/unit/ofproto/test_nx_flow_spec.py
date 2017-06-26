# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import ryu.ofproto.ofproto_v1_3_parser as ofpp


class Test_FlowSpec(unittest.TestCase):
    def test_flowspec_src_0_dst_0(self):
        user = ofpp.NXFlowSpecMatch(src=('in_port', 0),
                                    dst=('in_port', 0),
                                    n_bits=16)
        on_wire = (
            b'\x00\x10'
            b'\x80\x00\x00\x04\x00\x00'
            b'\x80\x00\x00\x04\x00\x00'
        )
        self.assertEqual(on_wire, user.serialize())
        (o, rest) = ofpp._NXFlowSpec.parse(on_wire)
        self.assertEqual(user.to_jsondict(), o.to_jsondict())
        self.assertEqual(str(user), str(o))
        self.assertEqual(b'', rest)

    def test_flowspec_src_1_dst_0(self):
        user = ofpp.NXFlowSpecMatch(src=99,
                                    dst=('in_port', 0),
                                    n_bits=16)
        on_wire = (
            b'\x20\x10'
            b'\x00\x63'
            b'\x80\x00\x00\x04\x00\x00'
        )
        self.assertEqual(on_wire, user.serialize())
        (o, rest) = ofpp._NXFlowSpec.parse(on_wire)
        self.assertEqual(user.to_jsondict(), o.to_jsondict())
        self.assertEqual(str(user), str(o))
        self.assertEqual(b'', rest)

    def test_flowspec_src_0_dst_1(self):
        user = ofpp.NXFlowSpecLoad(src=('in_port', 0),
                                   dst=('in_port', 0),
                                   n_bits=16)
        on_wire = (
            b'\x08\x10'
            b'\x80\x00\x00\x04\x00\x00'
            b'\x80\x00\x00\x04\x00\x00'
        )
        self.assertEqual(on_wire, user.serialize())
        (o, rest) = ofpp._NXFlowSpec.parse(on_wire)
        self.assertEqual(user.to_jsondict(), o.to_jsondict())
        self.assertEqual(str(user), str(o))
        self.assertEqual(b'', rest)

    def test_flowspec_src_1_dst_1(self):
        user = ofpp.NXFlowSpecLoad(src=99,
                                   dst=('in_port', 0),
                                   n_bits=16)
        on_wire = (
            b'\x28\x10'
            b'\x00\x63'
            b'\x80\x00\x00\x04\x00\x00'
        )
        self.assertEqual(on_wire, user.serialize())
        (o, rest) = ofpp._NXFlowSpec.parse(on_wire)
        self.assertEqual(user.to_jsondict(), o.to_jsondict())
        self.assertEqual(str(user), str(o))
        self.assertEqual(b'', rest)

    def test_flowspec_src_0_dst_2(self):
        user = ofpp.NXFlowSpecOutput(src=('in_port', 0),
                                     dst='',
                                     n_bits=16)
        on_wire = (
            b'\x10\x10'
            b'\x80\x00\x00\x04\x00\x00'
        )
        self.assertEqual(on_wire, user.serialize())
        (o, rest) = ofpp._NXFlowSpec.parse(on_wire)
        self.assertEqual(user.to_jsondict(), o.to_jsondict())
        self.assertEqual(str(user), str(o))
        self.assertEqual(b'', rest)
