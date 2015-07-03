# Copyright (C) 2014 Xinguard, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
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
import inspect
from nose.tools import ok_, eq_, nottest

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import bfd
from ryu.lib import addrconv

LOG = logging.getLogger(__name__)


class TestBFD(unittest.TestCase):
    def setUp(self):
        # BFD packet without authentication.
        self.data = b'\xb0\xa8\x6e\x18\xb8\x08\x64\x87' \
                    + b'\x88\xe9\xcb\xc8\x08\x00\x45\xc0' \
                    + b'\x00\x34\x68\x49\x00\x00\xff\x11' \
                    + b'\xf4\x73\xac\x1c\x03\x01\xac\x1c' \
                    + b'\x03\x02\xc0\x00\x0e\xc8\x00\x20' \
                    + b'\xd9\x02\x21\xc0\x03\x18\x00\x00' \
                    + b'\x00\x06\x00\x00\x00\x07\x00\x00' \
                    + b'\xea\x60\x00\x00\xea\x60\x00\x00' \
                    + b'\x00\x00'

        # BFD packet using simple password authentication.
        self.data_auth_simple = b'\x08\x00\x27\xd1\x95\x7c\x08\x00' \
                                + b'\x27\xed\x54\x41\x08\x00\x45\xc0' \
                                + b'\x00\x3d\x0c\x90\x00\x00\xff\x11' \
                                + b'\xbb\x0b\xc0\xa8\x39\x02\xc0\xa8' \
                                + b'\x39\x01\xc0\x00\x0e\xc8\x00\x29' \
                                + b'\x46\x35\x20\x44\x03\x21\x00\x00' \
                                + b'\x00\x01\x00\x00\x00\x00\x00\x0f' \
                                + b'\x42\x40\x00\x0f\x42\x40\x00\x00' \
                                + b'\x00\x00\x01\x09\x02\x73\x65\x63' \
                                + b'\x72\x65\x74'

        # BFD packet using md5 authentication.
        self.data_auth_md5 = b'\x08\x00\x27\xd1\x95\x7c\x08\x00' \
                             + b'\x27\xed\x54\x41\x08\x00\x45\xc0' \
                             + b'\x00\x4c\x0c\x44\x00\x00\xff\x11' \
                             + b'\xbb\x48\xc0\xa8\x39\x02\xc0\xa8' \
                             + b'\x39\x01\xc0\x00\x0e\xc8\x00\x38' \
                             + b'\x51\xbc\x20\x44\x03\x30\x00\x00' \
                             + b'\x00\x01\x00\x00\x00\x00\x00\x0f' \
                             + b'\x42\x40\x00\x0f\x42\x40\x00\x00' \
                             + b'\x00\x00\x02\x18\x02\x00\x00\x00' \
                             + b'\x41\xdb\x66\xa8\xf9\x25\x5a\x8b' \
                             + b'\xcb\x7e\x4b\xec\x25\xa6\x2c\x23' \
                             + b'\xda\x0f'

        # BFD packet using SHA1 authentication.
        self.data_auth_sha1 = b'\x08\x00\x27\xd1\x95\x7c\x08\x00' \
                              + b'\x27\xed\x54\x41\x08\x00\x45\xc0' \
                              + b'\x00\x50\x0b\x90\x00\x00\xff\x11' \
                              + b'\xbb\xf8\xc0\xa8\x39\x02\xc0\xa8' \
                              + b'\x39\x01\xc0\x00\x0e\xc8\x00\x3c' \
                              + b'\xb9\x92\x20\x44\x03\x34\x00\x00' \
                              + b'\x00\x01\x00\x00\x00\x00\x00\x0f' \
                              + b'\x42\x40\x00\x0f\x42\x40\x00\x00' \
                              + b'\x00\x00\x04\x1c\x02\x00\x00\x00' \
                              + b'\x41\xb1\x46\x20\x10\x81\x03\xd7' \
                              + b'\xf4\xde\x87\x61\x4c\x24\x61\x1f' \
                              + b'\x3c\xc1\x6a\x00\x69\x23'

        # BFD Key chain {auth_key_id: auth_key/password}
        self.auth_keys = {2: b"secret"}

    def tearDown(self):
        pass

    def test_parse(self):
        buf = self.data
        pkt = packet.Packet(buf)
        i = iter(pkt)

        eq_(type(next(i)), ethernet.ethernet)
        eq_(type(next(i)), ipv4.ipv4)
        eq_(type(next(i)), udp.udp)
        eq_(type(bfd.bfd.parser(next(i))[0]), bfd.bfd)

    def test_parse_with_auth_simple(self):
        buf = self.data_auth_simple
        pkt = packet.Packet(buf)
        i = iter(pkt)

        eq_(type(next(i)), ethernet.ethernet)
        eq_(type(next(i)), ipv4.ipv4)
        eq_(type(next(i)), udp.udp)

        bfd_obj = bfd.bfd.parser(next(i))[0]
        eq_(type(bfd_obj), bfd.bfd)
        eq_(type(bfd_obj.auth_cls), bfd.SimplePassword)
        ok_(bfd_obj.authenticate(self.auth_keys))

    def test_parse_with_auth_md5(self):
        buf = self.data_auth_md5
        pkt = packet.Packet(buf)
        i = iter(pkt)

        eq_(type(next(i)), ethernet.ethernet)
        eq_(type(next(i)), ipv4.ipv4)
        eq_(type(next(i)), udp.udp)

        bfd_obj = bfd.bfd.parser(next(i))[0]
        eq_(type(bfd_obj), bfd.bfd)
        eq_(type(bfd_obj.auth_cls), bfd.KeyedMD5)
        ok_(bfd_obj.authenticate(self.auth_keys))

    def test_parse_with_auth_sha1(self):
        buf = self.data_auth_sha1
        pkt = packet.Packet(buf)
        i = iter(pkt)

        eq_(type(next(i)), ethernet.ethernet)
        eq_(type(next(i)), ipv4.ipv4)
        eq_(type(next(i)), udp.udp)

        bfd_obj = bfd.bfd.parser(next(i))[0]
        eq_(type(bfd_obj), bfd.bfd)
        eq_(type(bfd_obj.auth_cls), bfd.KeyedSHA1)
        ok_(bfd_obj.authenticate(self.auth_keys))

    def test_serialize(self):
        pkt = packet.Packet()

        eth_pkt = ethernet.ethernet('b0:a8:6e:18:b8:08', '64:87:88:e9:cb:c8')
        pkt.add_protocol(eth_pkt)

        ip_pkt = ipv4.ipv4(src='172.28.3.1', dst='172.28.3.2', tos=192,
                           identification=26697, proto=inet.IPPROTO_UDP)
        pkt.add_protocol(ip_pkt)

        udp_pkt = udp.udp(49152, 3784)
        pkt.add_protocol(udp_pkt)

        bfd_pkt = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_CTRL_DETECT_TIME_EXPIRED,
                          state=bfd.BFD_STATE_UP, detect_mult=3, my_discr=6,
                          your_discr=7, desired_min_tx_interval=60000,
                          required_min_rx_interval=60000,
                          required_min_echo_rx_interval=0)
        pkt.add_protocol(bfd_pkt)

        eq_(len(pkt.protocols), 4)

        pkt.serialize()
        eq_(pkt.data, self.data)

    def test_serialize_with_auth_simple(self):
        pkt = packet.Packet()

        eth_pkt = ethernet.ethernet('08:00:27:d1:95:7c', '08:00:27:ed:54:41')
        pkt.add_protocol(eth_pkt)

        ip_pkt = ipv4.ipv4(src='192.168.57.2', dst='192.168.57.1', tos=192,
                           identification=3216, proto=inet.IPPROTO_UDP)
        pkt.add_protocol(ip_pkt)

        udp_pkt = udp.udp(49152, 3784)
        pkt.add_protocol(udp_pkt)

        auth_cls = bfd.SimplePassword(auth_key_id=2,
                                      password=self.auth_keys[2])

        bfd_pkt = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_NO_DIAG,
                          flags=bfd.BFD_FLAG_AUTH_PRESENT,
                          state=bfd.BFD_STATE_DOWN, detect_mult=3, my_discr=1,
                          your_discr=0, desired_min_tx_interval=1000000,
                          required_min_rx_interval=1000000,
                          required_min_echo_rx_interval=0,
                          auth_cls=auth_cls)

        pkt.add_protocol(bfd_pkt)

        eq_(len(pkt.protocols), 4)

        pkt.serialize()
        eq_(pkt.data, self.data_auth_simple)

    def test_serialize_with_auth_md5(self):
        pkt = packet.Packet()

        eth_pkt = ethernet.ethernet('08:00:27:d1:95:7c', '08:00:27:ed:54:41')
        pkt.add_protocol(eth_pkt)

        ip_pkt = ipv4.ipv4(src='192.168.57.2', dst='192.168.57.1', tos=192,
                           identification=3140, proto=inet.IPPROTO_UDP)
        pkt.add_protocol(ip_pkt)

        udp_pkt = udp.udp(49152, 3784)
        pkt.add_protocol(udp_pkt)

        auth_cls = bfd.KeyedMD5(auth_key_id=2, seq=16859,
                                auth_key=self.auth_keys[2])

        bfd_pkt = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_NO_DIAG,
                          flags=bfd.BFD_FLAG_AUTH_PRESENT,
                          state=bfd.BFD_STATE_DOWN, detect_mult=3, my_discr=1,
                          your_discr=0, desired_min_tx_interval=1000000,
                          required_min_rx_interval=1000000,
                          required_min_echo_rx_interval=0,
                          auth_cls=auth_cls)

        pkt.add_protocol(bfd_pkt)

        eq_(len(pkt.protocols), 4)

        pkt.serialize()
        eq_(pkt.data, self.data_auth_md5)

    def test_serialize_with_auth_sha1(self):
        pkt = packet.Packet()

        eth_pkt = ethernet.ethernet('08:00:27:d1:95:7c', '08:00:27:ed:54:41')
        pkt.add_protocol(eth_pkt)

        ip_pkt = ipv4.ipv4(src='192.168.57.2', dst='192.168.57.1', tos=192,
                           identification=2960, proto=inet.IPPROTO_UDP)
        pkt.add_protocol(ip_pkt)

        udp_pkt = udp.udp(49152, 3784)
        pkt.add_protocol(udp_pkt)

        auth_cls = bfd.KeyedSHA1(auth_key_id=2, seq=16817,
                                 auth_key=self.auth_keys[2])

        bfd_pkt = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_NO_DIAG,
                          flags=bfd.BFD_FLAG_AUTH_PRESENT,
                          state=bfd.BFD_STATE_DOWN, detect_mult=3, my_discr=1,
                          your_discr=0, desired_min_tx_interval=1000000,
                          required_min_rx_interval=1000000,
                          required_min_echo_rx_interval=0,
                          auth_cls=auth_cls)

        pkt.add_protocol(bfd_pkt)

        eq_(len(pkt.protocols), 4)

        pkt.serialize()
        eq_(pkt.data, self.data_auth_sha1)

    def test_json(self):
        bfd1 = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_CTRL_DETECT_TIME_EXPIRED,
                       state=bfd.BFD_STATE_UP, detect_mult=3, my_discr=6,
                       your_discr=7, desired_min_tx_interval=60000,
                       required_min_rx_interval=60000,
                       required_min_echo_rx_interval=0)

        jsondict = bfd1.to_jsondict()
        bfd2 = bfd.bfd.from_jsondict(jsondict['bfd'])
        eq_(str(bfd1), str(bfd2))

    def test_json_with_auth_simple(self):
        auth_cls = bfd.SimplePassword(auth_key_id=2,
                                      password=self.auth_keys[2])

        bfd1 = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_NO_DIAG,
                       flags=bfd.BFD_FLAG_AUTH_PRESENT,
                       state=bfd.BFD_STATE_DOWN, detect_mult=3, my_discr=1,
                       your_discr=0, desired_min_tx_interval=1000000,
                       required_min_rx_interval=1000000,
                       required_min_echo_rx_interval=0,
                       auth_cls=auth_cls)

        jsondict = bfd1.to_jsondict()
        bfd2 = bfd.bfd.from_jsondict(jsondict['bfd'])
        eq_(str(bfd1), str(bfd2))

    def test_json_with_auth_md5(self):
        auth_cls = bfd.KeyedMD5(auth_key_id=2, seq=16859,
                                auth_key=self.auth_keys[2])

        bfd1 = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_NO_DIAG,
                       flags=bfd.BFD_FLAG_AUTH_PRESENT,
                       state=bfd.BFD_STATE_DOWN, detect_mult=3, my_discr=1,
                       your_discr=0, desired_min_tx_interval=1000000,
                       required_min_rx_interval=1000000,
                       required_min_echo_rx_interval=0,
                       auth_cls=auth_cls)

        jsondict = bfd1.to_jsondict()
        bfd2 = bfd.bfd.from_jsondict(jsondict['bfd'])
        eq_(str(bfd1), str(bfd2))

    def test_json_with_auth_sha1(self):
        auth_cls = bfd.KeyedSHA1(auth_key_id=2, seq=16859,
                                 auth_key=self.auth_keys[2])

        bfd1 = bfd.bfd(ver=1, diag=bfd.BFD_DIAG_NO_DIAG,
                       flags=bfd.BFD_FLAG_AUTH_PRESENT,
                       state=bfd.BFD_STATE_DOWN, detect_mult=3, my_discr=1,
                       your_discr=0, desired_min_tx_interval=1000000,
                       required_min_rx_interval=1000000,
                       required_min_echo_rx_interval=0,
                       auth_cls=auth_cls)

        jsondict = bfd1.to_jsondict()
        bfd2 = bfd.bfd.from_jsondict(jsondict['bfd'])
        eq_(str(bfd1), str(bfd2))
