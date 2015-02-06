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

import ryu.ofproto.ofproto_v1_3 as ofp


class Test_OXM(unittest.TestCase):
    def _test_encode(self, user, on_wire):
        (f, uv) = user
        (n, v, m) = ofp.oxm_from_user(f, uv)
        buf = bytearray()
        ofp.oxm_serialize(n, v, m, buf, 0)
        self.assertEqual(on_wire, buf)

    def _test_decode(self, user, on_wire):
        (n, v, m, l) = ofp.oxm_parse(on_wire, 0)
        self.assertEqual(len(on_wire), l)
        (f, uv) = ofp.oxm_to_user(n, v, m)
        self.assertEqual(user, (f, uv))

    def _test_encode_header(self, user, on_wire):
        f = user
        n = ofp.oxm_from_user_header(f)
        buf = bytearray()
        ofp.oxm_serialize_header(n, buf, 0)
        self.assertEqual(on_wire, buf)

    def _test_decode_header(self, user, on_wire):
        (n, l) = ofp.oxm_parse_header(on_wire, 0)
        self.assertEqual(len(on_wire), l)
        f = ofp.oxm_to_user_header(n)
        self.assertEqual(user, f)

    def _test(self, user, on_wire, header_bytes):
        self._test_encode(user, on_wire)
        self._test_decode(user, on_wire)
        if isinstance(user[1], tuple):  # has mask?
            return
        user_header = user[0]
        on_wire_header = on_wire[:header_bytes]
        self._test_decode_header(user_header, on_wire_header)
        if user_header.startswith('field_'):
            return  # not supported
        self._test_encode_header(user_header, on_wire_header)

    def test_basic_nomask(self):
        user = ('ipv4_src', '192.0.2.1')
        on_wire = (
            b'\x80\x00\x16\x04'
            b'\xc0\x00\x02\x01'
        )
        self._test(user, on_wire, 4)

    def test_basic_mask(self):
        user = ('ipv4_src', ('192.0.2.1', '255.255.0.0'))
        on_wire = (
            b'\x80\x00\x17\x08'
            b'\xc0\x00\x02\x01'
            b'\xff\xff\x00\x00'
        )
        self._test(user, on_wire, 4)

    def test_exp_nomask(self):
        user = ('_dp_hash', 0x12345678)
        on_wire = (
            b'\xff\xff\x00\x08'
            b'\x00\x00\x23\x20'  # Nicira
            b'\x12\x34\x56\x78'
        )
        self._test(user, on_wire, 8)

    def test_exp_mask(self):
        user = ('_dp_hash', (0x12345678, 0x7fffffff))
        on_wire = (
            b'\xff\xff\x01\x0c'
            b'\x00\x00\x23\x20'  # Nicira
            b'\x12\x34\x56\x78'
            b'\x7f\xff\xff\xff'
        )
        self._test(user, on_wire, 8)

    def test_exp_nomask_2(self):
        user = ('tcp_flags', 0x876)
        on_wire = (
            b'\xff\xff\x54\x06'
            b'\x4f\x4e\x46\x00'  # ONF
            b'\x08\x76'
        )
        self._test(user, on_wire, 8)

    def test_exp_mask_2(self):
        user = ('tcp_flags', (0x876, 0x7ff))
        on_wire = (
            b'\xff\xff\x55\x08'
            b'\x4f\x4e\x46\x00'  # ONF
            b'\x08\x76'
            b'\x07\xff'
        )
        self._test(user, on_wire, 8)

    def test_exp_nomask_3(self):
        user = ('actset_output', 0x98765432)
        on_wire = (
            b'\xff\xff\x56\x08'
            b'\x4f\x4e\x46\x00'  # ONF
            b'\x98\x76\x54\x32'
        )
        self._test(user, on_wire, 8)

    def test_exp_mask_3(self):
        user = ('actset_output', (0x98765432, 0xfffffffe))
        on_wire = (
            b'\xff\xff\x57\x0c'
            b'\x4f\x4e\x46\x00'  # ONF
            b'\x98\x76\x54\x32'
            b'\xff\xff\xff\xfe'
        )
        self._test(user, on_wire, 8)

    def test_nxm_1_nomask(self):
        user = ('tun_ipv4_src', '192.0.2.1')
        on_wire = (
            b'\x00\x01\x3e\x04'
            b'\xc0\x00\x02\x01'
        )
        self._test(user, on_wire, 4)

    def test_nxm_1_mask(self):
        user = ('tun_ipv4_src', ('192.0.2.1', '255.255.0.0'))
        on_wire = (
            b'\x00\x01\x3f\x08'
            b'\xc0\x00\x02\x01'
            b'\xff\xff\x00\x00'
        )
        self._test(user, on_wire, 4)

    def test_ext_256_nomask(self):
        user = ('pbb_uca', 50)
        on_wire = (
            b'\xff\xff\x00\x07'
            b'\x4f\x4e\x46\x00'  # ONF
            b'\x0a\x00'
            b'\x32'
        )
        self._test(user, on_wire, 10)

    def test_ext_256_mask(self):
        user = ('pbb_uca', (50, 51))
        on_wire = (
            b'\xff\xff\x01\x08'
            b'\x4f\x4e\x46\x00'  # ONF
            b'\x0a\x00'
            b'\x32'
            b'\x33'
        )
        self._test(user, on_wire, 10)

    def test_basic_unknown_nomask(self):
        user = ('field_100', 'aG9nZWhvZ2U=')
        on_wire = (
            b'\x00\x00\xc8\x08'
            b'hogehoge'
        )
        self._test(user, on_wire, 4)

    def test_basic_unknown_mask(self):
        user = ('field_100', ('aG9nZWhvZ2U=', 'ZnVnYWZ1Z2E='))
        on_wire = (
            b'\x00\x00\xc9\x10'
            b'hogehoge'
            b'fugafuga'
        )
        self._test(user, on_wire, 4)
