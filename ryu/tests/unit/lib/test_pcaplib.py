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

from __future__ import print_function

import logging
import os
import struct
import sys
import unittest

try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3

from nose.tools import eq_
from nose.tools import raises

from ryu.utils import binary_str
from ryu.lib import pcaplib

LOG = logging.getLogger(__name__)

PCAP_PACKET_DATA_DIR = os.path.join(
    os.path.dirname(sys.modules[__name__].__file__),
    '../../packet_data/pcap/')


class Test_PcapFileHdr(unittest.TestCase):
    """
    Test case for pcaplib.PcapFileHdr class
    """
    hdr = pcaplib.PcapFileHdr(
        magic=None,  # temporary default
        version_major=2,
        version_minor=4,
        thiszone=0x11223344,
        sigfigs=0x22334455,
        snaplen=0x33445566,
        network=0x44556677,
    )

    buf_big = (
        b'\xa1\xb2\xc3\xd4'  # magic (Big Endian)
        b'\x00\x02\x00\x04'  # version_major, version_minor
        b'\x11\x22\x33\x44'  # thiszone
        b'\x22\x33\x44\x55'  # sigfigs
        b'\x33\x44\x55\x66'  # snaplen
        b'\x44\x55\x66\x77'  # network
    )

    buf_little = (
        b'\xd4\xc3\xb2\xa1'  # magic (Little Endian)
        b'\x02\x00\x04\x00'  # version_major, version_minor
        b'\x44\x33\x22\x11'  # thiszone
        b'\x55\x44\x33\x22'  # sigfigs
        b'\x66\x55\x44\x33'  # snaplen
        b'\x77\x66\x55\x44'  # network
    )

    buf_invalid = (
        b'\xff\xff\xff\xff'  # magic (Invalid)
        b'\x02\x00\x04\x00'  # version_major, version_minor
        b'\x44\x33\x22\x11'  # thiszone
        b'\x55\x44\x33\x22'  # sigfigs
        b'\x66\x55\x44\x33'  # snaplen
        b'\x77\x66\x55\x44'  # network
    )

    def _assert(self, magic, ret):
        self.hdr.magic = magic
        eq_(self.hdr.__dict__, ret.__dict__)

    def test_parser_with_big_endian(self):
        ret, byteorder = pcaplib.PcapFileHdr.parser(self.buf_big)
        self._assert(pcaplib.PcapFileHdr.MAGIC_NUMBER_IDENTICAL, ret)
        eq_('big', byteorder)

    def test_parser_with_little_endian(self):
        ret, byteorder = pcaplib.PcapFileHdr.parser(self.buf_little)
        self._assert(pcaplib.PcapFileHdr.MAGIC_NUMBER_SWAPPED, ret)
        eq_('little', byteorder)

    @mock.patch('sys.byteorder', 'big')
    def test_serialize_with_big_endian(self):
        buf = self.hdr.serialize()
        eq_(binary_str(self.buf_big), binary_str(buf))

    @mock.patch('sys.byteorder', 'little')
    def test_serialize_with_little_endian(self):
        buf = self.hdr.serialize()
        eq_(binary_str(self.buf_little), binary_str(buf))

    @raises(struct.error)
    def test_parser_with_invalid_magic_number(self):
        pcaplib.PcapFileHdr.parser(self.buf_invalid)


class Test_PcapPktHdr(unittest.TestCase):
    """
    Test case for pcaplib.PcapPktHdr class
    """
    expected_buf = b'test_data'

    hdr = pcaplib.PcapPktHdr(
        ts_sec=0x11223344,
        ts_usec=0x22334455,
        incl_len=len(expected_buf),
        orig_len=0x44556677,
    )

    buf_big = (
        b'\x11\x22\x33\x44'  # ts_sec
        b'\x22\x33\x44\x55'  # ts_usec
        b'\x00\x00\x00\x09'  # incl_len = len(expected_buf)
        b'\x44\x55\x66\x77'  # orig_len
    )

    buf_little = (
        b'\x44\x33\x22\x11'  # ts_sec
        b'\x55\x44\x33\x22'  # ts_usec
        b'\x09\x00\x00\x00'  # incl_len = len(expected_buf)
        b'\x77\x66\x55\x44'  # orig_len
    )

    def test_parser_with_big_endian(self):
        ret, buf = pcaplib.PcapPktHdr.parser(
            self.buf_big + self.expected_buf, 'big')
        eq_(self.hdr.__dict__, ret.__dict__)
        eq_(self.expected_buf, buf)

    def test_parser_with_little_endian(self):
        ret, buf = pcaplib.PcapPktHdr.parser(
            self.buf_little + self.expected_buf, 'little')
        eq_(self.hdr.__dict__, ret.__dict__)
        eq_(self.expected_buf, buf)

    @mock.patch('sys.byteorder', 'big')
    def test_serialize_with_big_endian(self):
        buf = self.hdr.serialize()
        eq_(binary_str(self.buf_big), binary_str(buf))

    @mock.patch('sys.byteorder', 'little')
    def test_serialize_with_little_endian(self):
        buf = self.hdr.serialize()
        eq_(binary_str(self.buf_little), binary_str(buf))


class Test_pcaplib_Reader(unittest.TestCase):
    """
    Test case for pcaplib.Reader class
    """

    expected_outputs = [
        (0x1234 + (0x5678 / 1e6), b'test_data_1'),  # sec=0x1234, usec=0x5678
        (0x2345 + (0x6789 / 1e6), b'test_data_2'),  # sec=0x2345, usec=0x6789
    ]

    def _test(self, file_name):
        outputs = []
        for ts, buf in pcaplib.Reader(open(file_name, 'rb')):
            outputs.append((ts, buf))

        eq_(self.expected_outputs, outputs)

    def test_with_big_endian(self):
        self._test(os.path.join(PCAP_PACKET_DATA_DIR, 'big_endian.pcap'))

    def test_with_little_endian(self):
        self._test(os.path.join(PCAP_PACKET_DATA_DIR, 'little_endian.pcap'))


class DummyFile(object):

    def __init__(self):
        self.buf = b''

    def write(self, buf):
        self.buf += buf

    def close(self):
        pass


class Test_pcaplib_Writer(unittest.TestCase):
    """
    Test case for pcaplib.Writer class
    """

    @staticmethod
    def _test(file_name):
        expected_buf = open(file_name, 'rb').read()
        f = DummyFile()
        w = pcaplib.Writer(f)
        w.write_pkt(b'test_data_1', ts=(0x1234 + (0x5678 / 1e6)))
        w.write_pkt(b'test_data_2', ts=(0x2345 + (0x6789 / 1e6)))
        eq_(expected_buf, f.buf)

    @mock.patch('sys.byteorder', 'big')
    def test_with_big_endian(self):
        self._test(os.path.join(PCAP_PACKET_DATA_DIR, 'big_endian.pcap'))

    @mock.patch('sys.byteorder', 'little')
    def test_with_little_endian(self):
        self._test(os.path.join(PCAP_PACKET_DATA_DIR, 'little_endian.pcap'))

    @staticmethod
    @mock.patch.object(pcaplib.Writer, '_write_pcap_file_hdr', mock.MagicMock)
    @mock.patch.object(pcaplib.Writer, '_write_pkt_hdr', mock.MagicMock)
    def test_with_longer_buf():
        f = DummyFile()
        snaplen = 4
        w = pcaplib.Writer(f, snaplen=snaplen)
        w.write_pkt(b'hogehoge', ts=0)
        expected_buf = b'hoge'  # b'hogehoge'[:snaplen]
        eq_(expected_buf, f.buf)
        eq_(snaplen, len(f.buf))
