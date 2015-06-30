# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

import logging
import unittest

import ryu.ofproto.ofproto_v1_5 as ofp


LOG = logging.getLogger(__name__)


class Test_OXS(unittest.TestCase):
    def _test_encode(self, user, on_wire):
        """ test encording user value into on-wire bytes.

        n: name of OXS field
        uv: user vale
        t: oxs_type
        v: on-wire bytes value
        """
        (n, uv) = user
        (t, v, _) = ofp.oxs_from_user(n, uv)
        buf = bytearray()
        ofp.oxs_serialize(t, v, None, buf, 0)
        self.assertEqual(on_wire, buf)

    def _test_decode(self, user, on_wire):
        """ test decording user value from on-wire bytes.

        t: oxs_type
        v: on-wire bytes value
        l: length of field
        n: name of OXS field
        uv: user vale
        """
        (t, v, _, l) = ofp.oxs_parse(on_wire, 0)
        self.assertEqual(len(on_wire), l)
        (n, uv) = ofp.oxs_to_user(t, v, None)
        self.assertEqual(user, (n, uv))

    def _test_encode_header(self, user, on_wire):
        """ test encording header.

        t: oxs_type
        """
        t = ofp.oxs_from_user_header(user)
        buf = bytearray()
        ofp.oxs_serialize_header(t, buf, 0)
        self.assertEqual(on_wire, buf)

    def _test_decode_header(self, user, on_wire):
        """ test decording header.

        t: oxs_type
        l: length of header
        n: name of OXS field
        """
        (t, l) = ofp.oxs_parse_header(on_wire, 0)
        self.assertEqual(len(on_wire), l)
        n = ofp.oxs_to_user_header(t)
        self.assertEqual(user, n)

    def _test(self, user, on_wire, header_bytes):
        """ execute tests.

        user: user specified value.
              eg. user = ('duration', (100, 100))
        on_wire: on-wire bytes
        header_bytes: header length
        """
        self._test_encode(user, on_wire)
        self._test_decode(user, on_wire)
        user_header = user[0]
        on_wire_header = on_wire[:header_bytes]
        self._test_decode_header(user_header, on_wire_header)
        if user_header.startswith('field_'):
            return  # not supported
        self._test_encode_header(user_header, on_wire_header)

    def test_basic_single(self):
        user = ('flow_count', 100)
        on_wire = (
            b'\x80\x02\x06\x04'
            b'\x00\x00\x00\x64'
        )
        self._test(user, on_wire, 4)

    def test_basic_double(self):
        user = ('duration', (100, 200))
        on_wire = (
            b'\x80\x02\x00\x08'
            b'\x00\x00\x00\x64'
            b'\x00\x00\x00\xc8'
        )
        self._test(user, on_wire, 4)

    def test_basic_unknown(self):
        user = ('field_100', 'aG9nZWhvZ2U=')
        on_wire = (
            b'\x00\x00\xc8\x08'
            b'hogehoge'
        )
        self._test(user, on_wire, 4)
