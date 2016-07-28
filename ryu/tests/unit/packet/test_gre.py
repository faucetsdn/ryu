# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

import six
from nose.tools import eq_, raises

from ryu.lib.packet.gre import gre
from ryu.lib.packet.ether_types import ETH_TYPE_IP

LOG = logging.getLogger(__name__)


class Test_gre(unittest.TestCase):
    """ Test case for gre
    """

    protocol = ETH_TYPE_IP
    checksum = 0x440d
    key = 1000
    seq_number = 10

    buf = struct.pack("!BBHH2xII", 0xb0, 0, protocol, checksum, key, seq_number)
    gre = gre(protocol, checksum, key, seq_number)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.protocol, self.gre.protocol)
        eq_(self.checksum, self.gre.checksum)
        eq_(self.key, self.gre.key)
        eq_(self.seq_number, self.gre.seq_number)

    def test_parser(self):
        res, _, _ = self.gre.parser(self.buf)

        eq_(res.protocol, self.protocol)
        eq_(res.checksum, self.checksum)
        eq_(res.key, self.key)
        eq_(res.seq_number, self.seq_number)

    def test_serialize(self):
        buf = self.gre.serialize()
        res = struct.unpack_from("!BBHH2xII", six.binary_type(buf))

        eq_(res[0], 0xb0)
        eq_(res[1], 0)
        eq_(res[2], self.protocol)
        eq_(res[3], self.checksum)
        eq_(res[4], self.key)
        eq_(res[5], self.seq_number)

    @raises(Exception)
    def test_malformed_gre(self):
        m_short_buf = self.buf[1:gre._MIN_LEN]
        gre.parser(m_short_buf)

    def test_json(self):
        jsondict = self.gre.to_jsondict()
        g = gre.from_jsondict(jsondict['gre'])
        eq_(str(self.gre), str(g))
