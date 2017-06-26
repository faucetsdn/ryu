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

import bz2
import io
import logging
import os
import sys
import unittest

try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3

from nose.tools import eq_
from nose.tools import ok_

from ryu.lib import addrconv
from ryu.lib import mrtlib
from ryu.lib.packet import bgp
from ryu.lib.packet import ospf
from ryu.utils import binary_str


LOG = logging.getLogger(__name__)

MRT_DATA_DIR = os.path.join(
    os.path.dirname(sys.modules[__name__].__file__), '../../packet_data/mrt/')


class TestMrtlib(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.
    """

    def test_reader(self):
        files = [
            'rib.20161101.0000_pick.bz2',
            'updates.20161101.0000.bz2',
        ]

        for f in files:
            # print('\n*** testing mrtlib.Reader with %s ...' % f)
            counter = 0
            input_file = os.path.join(MRT_DATA_DIR, f)
            for record in mrtlib.Reader(bz2.BZ2File(input_file, 'rb')):
                # print('* No.%d\n%s' % (counter, record))
                ok_(not isinstance(record, mrtlib.UnknownMrtRecord))
                counter += 1

    def test_writer(self):
        files = [
            'rib.20161101.0000_pick.bz2',
            'updates.20161101.0000.bz2',
        ]

        for f in files:
            # print('\n*** testing mrtlib.Writer with %s ...' % f)
            input_file = os.path.join(MRT_DATA_DIR, f)
            input_buf = bz2.BZ2File(input_file, 'rb').read()
            input_records = list(mrtlib.Reader(bz2.BZ2File(input_file, 'rb')))

            counter = 0
            f = io.BytesIO()
            mrt_writer = mrtlib.Writer(f)
            for record in input_records:
                # print('* No.%d\n%s' % (counter, record))
                mrt_writer.write(record)
                counter += 1

            output_buf = f.getvalue()

            eq_(binary_str(input_buf), binary_str(output_buf))

            mrt_writer.close()

            eq_(True, mrt_writer._f.closed)


class TestMrtlibMrtRecord(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.MrtRecord.
    """

    def test_init_without_type_subtype(self):
        type_ = mrtlib.MrtRecord.TYPE_TABLE_DUMP
        subtype = mrtlib.TableDumpMrtRecord.SUBTYPE_AFI_IPv4

        message = mrtlib.TableDumpAfiIPv4MrtMessage(
            view_num=1,
            seq_num=2,
            prefix='192.168.1.0',
            prefix_len=24,
            status=1,
            originated_time=0,
            peer_ip='10.0.0.1',
            peer_as=65000,
            bgp_attributes=[],
        )
        record = mrtlib.TableDumpMrtRecord(message)

        eq_(type_, record.type)
        eq_(subtype, record.subtype)

    def test_parse_pre_with_type_et(self):
        buf = (
            b'\x00\x00\x00\x00'  # timestamp
            b'\x00\x11\x00\x00'  # type=TYPE_BGP4MP_ET(17), subtype
            b'\x00\x00\x00\xaa'  # length
        )

        required_len = mrtlib.MrtRecord.parse_pre(buf)

        eq_(0xaa + mrtlib.ExtendedTimestampMrtRecord.HEADER_SIZE,
            required_len)


# Note: MrtCommonRecord is tested in TestMrtlibMrtRecord.
# class TestMrtlibMrtCommonRecord(unittest.TestCase):


class TestMrtlibExtendedTimestampMrtRecord(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.ExtendedTimestampMrtRecord.
    """

    def test_parse_extended_header(self):
        body = b'test'
        buf = (
            b'\x11\x11\x11\x11'  # ms_timestamp
            + body
        )

        (headers,
         rest) = mrtlib.ExtendedTimestampMrtRecord.parse_extended_header(buf)

        ok_(isinstance(headers, list))
        eq_(1, len(headers))
        eq_(0x11111111, headers[0])
        eq_(body, rest)

    def test_serialize(self):
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x22\x22\x33\x33'  # type, subtype
            b'\x00\x00\x00\x04'  # length=len(body)
            b'\x44\x44\x44\x44'  # ms_timestamp
            + body
        )

        message_mock = mock.MagicMock(spec=mrtlib.MrtMessage)
        message_mock.serialize.return_value = body

        record = mrtlib.ExtendedTimestampMrtRecord(
            message=message_mock,
            timestamp=0x11111111,
            type_=0x2222, subtype=0x3333,
            ms_timestamp=0x44444444,
            length=0x00000004,
        )

        output = record.serialize()

        eq_(buf, output)


class TestMrtlibUnknownMrtRecord(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.UnknownMrtRecord.
    """

    def test_parse(self):
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x22\x22\x33\x33'  # type, subtype
            b'\x00\x00\x00\x04'  # length=len(body)
            + body
        )

        (record, rest) = mrtlib.MrtRecord.parse(buf)

        eq_(0x11111111, record.timestamp)
        eq_(0x2222, record.type)
        eq_(0x3333, record.subtype)
        eq_(0x00000004, record.length)
        eq_(body, record.message.buf)
        eq_(b'', rest)

    def test_serialize(self):
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x22\x22\x33\x33'  # type, subtype
            b'\x00\x00\x00\x04'  # length=len(body)
            + body
        )

        message = mrtlib.UnknownMrtMessage(buf=body)
        record = mrtlib.UnknownMrtRecord(
            message=message,
            timestamp=0x11111111,
            type_=0x2222, subtype=0x3333,
            length=0x00000004,
        )

        output = record.serialize()

        eq_(buf, output)


class TestMrtlibOspf2MrtRecord(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.Ospf2MrtRecord.
    """

    @mock.patch('ryu.lib.packet.ospf.ospf.parser')
    def test_parse(self, mock_ospf_parser):
        remote_ip = '10.0.0.1'
        local_ip = '10.0.0.2'
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0b\x00\x00'  # type=TYPE_OSPFv2(11), subtype
            b'\x00\x00\x00\x0c'  # length=len(remote_ip + local_ip + body)
            + addrconv.ipv4.text_to_bin(remote_ip)  # remote_ip
            + addrconv.ipv4.text_to_bin(local_ip)   # local_ip
            + body               # ospf_message
        )

        mock_ospf_message = mock.MagicMock(spec=ospf.OSPFMessage)
        mock_ospf_parser.return_value = (mock_ospf_message, None, '')

        (record, rest) = mrtlib.MrtRecord.parse(buf)

        eq_(0x11111111, record.timestamp)
        eq_(mrtlib.MrtRecord.TYPE_OSPFv2, record.type)
        eq_(0x0000, record.subtype)
        eq_(0x0000000c, record.length)
        eq_(remote_ip, record.message.remote_ip)
        eq_(local_ip, record.message.local_ip)
        eq_(mock_ospf_message, record.message.ospf_message)
        eq_(b'', rest)

    def test_serialize(self):
        remote_ip = '10.0.0.1'
        local_ip = '10.0.0.2'
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0b\x00\x00'  # type=TYPE_OSPFv2(11), subtype
            b'\x00\x00\x00\x0c'  # length=len(remote_ip + local_ip + body)
            + addrconv.ipv4.text_to_bin(remote_ip)  # remote_ip
            + addrconv.ipv4.text_to_bin(local_ip)   # local_ip
            + body               # ospf_message
        )

        mock_ospf_message = mock.MagicMock(spec=ospf.OSPFMessage)
        mock_ospf_message.serialize.return_value = body

        message = mrtlib.Ospf2MrtMessage(
            remote_ip=remote_ip,
            local_ip=local_ip,
            ospf_message=mock_ospf_message,
        )
        record = mrtlib.Ospf2MrtRecord(
            message=message,
            timestamp=0x11111111,
            # type_=None,
            # subtype=None,
            # length=None,
        )

        output = record.serialize()

        eq_(buf, output)


class TestMrtlibTableDumpMrtRecord(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.TableDumpMrtRecord.
    """

    @mock.patch('ryu.lib.packet.bgp._PathAttribute.parser')
    def test_parse_afi_ipv4(self, mock_bgp_attr_parser):
        prefix = '10.0.0.0'
        peer_ip = '172.16.0.1'
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0c\x00\x01'  # type=TYPE_TABLE_DUMP(12),
                                 # subtype=SUBTYPE_AFI_IPv4(1)
            b'\x00\x00\x00\x1a'  # length=26
            b'\x22\x22\x33\x33'  # view_num, seq_num
            + addrconv.ipv4.text_to_bin(prefix) +  # prefix
            b'\x18\x01'          # prefix_len=24, status=1
            b'\x44\x44\x44\x44'  # originated_time
            + addrconv.ipv4.text_to_bin(peer_ip) +  # peer_ip
            b'\xfd\xe8\x00\x04'  # peer_as=65000, attr_len=len(body)
            + body               # bgp_attributes
        )

        mock_bgp_attr = mock.MagicMock(spec=bgp._PathAttribute)
        mock_bgp_attr_parser.return_value = (mock_bgp_attr, b'')

        (record, rest) = mrtlib.MrtRecord.parse(buf)

        eq_(0x11111111, record.timestamp)
        eq_(mrtlib.MrtRecord.TYPE_TABLE_DUMP, record.type)
        eq_(mrtlib.TableDumpMrtRecord.SUBTYPE_AFI_IPv4, record.subtype)
        eq_(0x0000001a, record.length)
        eq_(0x2222, record.message.view_num)
        eq_(0x3333, record.message.seq_num)
        eq_(prefix, record.message.prefix)
        eq_(24, record.message.prefix_len)
        eq_(1, record.message.status)
        eq_(0x44444444, record.message.originated_time)
        eq_(peer_ip, record.message.peer_ip)
        eq_(65000, record.message.peer_as)
        eq_(0x0004, record.message.attr_len)
        eq_([mock_bgp_attr], record.message.bgp_attributes)
        eq_(b'', rest)

    def test_serialize_afi_ipv4(self):
        prefix = '10.0.0.0'
        peer_ip = '172.16.0.1'
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0c\x00\x01'  # type=TYPE_TABLE_DUMP(12),
                                 # subtype=SUBTYPE_AFI_IPv4(1)
            b'\x00\x00\x00\x1a'  # length=26
            b'\x22\x22\x33\x33'  # view_num, seq_num
            + addrconv.ipv4.text_to_bin(prefix) +  # prefix
            b'\x18\x01'          # prefix_len=24, status=1
            b'\x44\x44\x44\x44'  # originated_time
            + addrconv.ipv4.text_to_bin(peer_ip) +  # peer_ip
            b'\xfd\xe8\x00\x04'  # peer_as=65000, attr_len=len(body)
            + body               # bgp_attributes
        )

        mock_bgp_attr = mock.MagicMock(spec=bgp._PathAttribute)
        mock_bgp_attr.serialize.return_value = body

        message = mrtlib.TableDumpAfiIPv4MrtMessage(
            view_num=0x2222,
            seq_num=0x3333,
            prefix=prefix,
            prefix_len=24,
            status=1,
            originated_time=0x44444444,
            peer_ip=peer_ip,
            peer_as=65000,
            bgp_attributes=[mock_bgp_attr],
            # attr_len=4
        )
        record = mrtlib.TableDumpMrtRecord(
            message=message,
            timestamp=0x11111111,
            # type_=None,
            # subtype=None,
            # length=None,
        )

        output = record.serialize()

        eq_(buf, output)

    @mock.patch('ryu.lib.packet.bgp._PathAttribute.parser')
    def test_parse_afi_ipv6(self, mock_bgp_attr_parser):
        prefix = '2001:db8::1'
        peer_ip = 'fe80::1'
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0c\x00\x02'  # type=TYPE_TABLE_DUMP(12),
                                 # subtype=SUBTYPE_AFI_IPv6(2)
            b'\x00\x00\x00\x32'  # length=50
            b'\x22\x22\x33\x33'  # view_num, seq_num
            + addrconv.ipv6.text_to_bin(prefix) +  # prefix
            b'\x40\x01'          # prefix_len=64, status=1
            b'\x44\x44\x44\x44'  # originated_time
            + addrconv.ipv6.text_to_bin(peer_ip) +  # peer_ip
            b'\xfd\xe8\x00\x04'  # peer_as=65000, attr_len=len(body)
            + body               # bgp_attributes
        )

        mock_bgp_attr = mock.MagicMock(spec=bgp._PathAttribute)
        mock_bgp_attr_parser.return_value = (mock_bgp_attr, b'')

        (record, rest) = mrtlib.MrtRecord.parse(buf)

        eq_(0x11111111, record.timestamp)
        eq_(mrtlib.MrtRecord.TYPE_TABLE_DUMP, record.type)
        eq_(mrtlib.TableDumpMrtRecord.SUBTYPE_AFI_IPv6, record.subtype)
        eq_(0x00000032, record.length)
        eq_(0x2222, record.message.view_num)
        eq_(0x3333, record.message.seq_num)
        eq_(prefix, record.message.prefix)
        eq_(64, record.message.prefix_len)
        eq_(1, record.message.status)
        eq_(0x44444444, record.message.originated_time)
        eq_(peer_ip, record.message.peer_ip)
        eq_(65000, record.message.peer_as)
        eq_(0x0004, record.message.attr_len)
        eq_([mock_bgp_attr], record.message.bgp_attributes)
        eq_(b'', rest)

    def test_serialize_afi_ipv6(self):
        prefix = '2001:db8::1'
        peer_ip = 'fe80::1'
        body = b'test'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0c\x00\x02'  # type=TYPE_TABLE_DUMP(12),
                                 # subtype=SUBTYPE_AFI_IPv6(2)
            b'\x00\x00\x00\x32'  # length=50
            b'\x22\x22\x33\x33'  # view_num, seq_num
            + addrconv.ipv6.text_to_bin(prefix) +  # prefix
            b'\x40\x01'          # prefix_len=64, status=1
            b'\x44\x44\x44\x44'  # originated_time
            + addrconv.ipv6.text_to_bin(peer_ip) +  # peer_ip
            b'\xfd\xe8\x00\x04'  # peer_as=65000, attr_len=len(body)
            + body               # bgp_attributes
        )

        mock_bgp_attr = mock.MagicMock(spec=bgp._PathAttribute)
        mock_bgp_attr.serialize.return_value = body

        message = mrtlib.TableDumpAfiIPv6MrtMessage(
            view_num=0x2222,
            seq_num=0x3333,
            prefix=prefix,
            prefix_len=64,
            status=1,
            originated_time=0x44444444,
            peer_ip=peer_ip,
            peer_as=65000,
            bgp_attributes=[mock_bgp_attr],
            # attr_len=4
        )
        record = mrtlib.TableDumpMrtRecord(
            message=message,
            timestamp=0x11111111,
            # type_=None,
            # subtype=None,
            # length=None,
        )

        output = record.serialize()

        eq_(buf, output)


class TestMrtlibTableDump2MrtRecord(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.TableDump2MrtRecord.
    """

    # Note: The classes corresponding to the following subtypes are
    # tested in TestMrtlibMrtRecord.
    # - SUBTYPE_PEER_INDEX_TABLE = 1
    # - SUBTYPE_RIB_IPV4_UNICAST = 2
    # - SUBTYPE_RIB_IPV4_MULTICAST = 3
    # - SUBTYPE_RIB_IPV6_UNICAST = 4
    # - SUBTYPE_RIB_IPV6_MULTICAST = 5

    @mock.patch('ryu.lib.mrtlib.MrtRibEntry.parse')
    @mock.patch('ryu.lib.packet.bgp.BGPNLRI.parser')
    def test_parse_rib_generic(self, mock_nlri_parser, mock_rib_entry_parser):
        nlri_bin = b'nlri'  # 4 bytes
        rib_entries_bin = b'ribs'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0d\x00\x06'  # type=TYPE_TABLE_DUMP_V2(13),
                                 # subtype=SUBTYPE_RIB_GENERIC(6)
            b'\x00\x00\x00\x11'  # length=17
            b'\x22\x22\x22\x22'  # seq_num
            b'\x33\x33\x44'      # afi, safi
            + nlri_bin +         # nlri
            b'\x00\x01'          # entry_count
            + rib_entries_bin    # rib_entries
        )
        buf_entries = (
            b'\x00\x01'          # entry_count
            + rib_entries_bin    # rib_entries
        )

        mock_bgp_nlri = mock.MagicMock(spec=bgp._AddrPrefix)
        mock_nlri_parser.return_value = (mock_bgp_nlri, buf_entries)

        mock_rib_entry = mock.MagicMock(spec=mrtlib.MrtRibEntry)
        mock_rib_entry_parser.return_value = (mock_rib_entry, b'')

        (record, rest) = mrtlib.MrtRecord.parse(buf)

        eq_(0x11111111, record.timestamp)
        eq_(mrtlib.MrtRecord.TYPE_TABLE_DUMP_V2, record.type)
        eq_(mrtlib.TableDump2MrtRecord.SUBTYPE_RIB_GENERIC, record.subtype)
        eq_(0x00000011, record.length)
        eq_(0x22222222, record.message.seq_num)
        eq_(0x3333, record.message.afi)
        eq_(0x44, record.message.safi)
        eq_(mock_bgp_nlri, record.message.nlri)
        eq_(0x0001, record.message.entry_count)
        eq_([mock_rib_entry], record.message.rib_entries)
        eq_(b'', rest)

    def test_serialize_rib_generic(self):
        nlri_bin = b'nlri'  # 4 bytes
        rib_entries_bin = b'ribs'  # 4 bytes
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x0d\x00\x06'  # type=TYPE_TABLE_DUMP_V2(13),
                                 # subtype=SUBTYPE_RIB_GENERIC(6)
            b'\x00\x00\x00\x11'  # length=17
            b'\x22\x22\x22\x22'  # seq_num
            b'\x33\x33\x44'      # afi, safi
            + nlri_bin +         # nlri
            b'\x00\x01'          # entry_count
            + rib_entries_bin    # rib_entries
        )

        mock_bgp_nlri = mock.MagicMock(spec=bgp._AddrPrefix)
        mock_bgp_nlri.serialize.return_value = nlri_bin

        mock_rib_entry = mock.MagicMock(spec=mrtlib.MrtRibEntry)
        mock_rib_entry.serialize.return_value = rib_entries_bin

        message = mrtlib.TableDump2RibGenericMrtMessage(
            seq_num=0x22222222,
            afi=0x3333,
            safi=0x44,
            nlri=mock_bgp_nlri,
            rib_entries=[mock_rib_entry],
            # entry_count=1,
        )
        record = mrtlib.TableDump2MrtRecord(
            message=message,
            timestamp=0x11111111,
            # type_=None,
            # subtype=None,
            # length=None,
        )

        output = record.serialize()

        eq_(buf, output)


class TestMrtlibMrtPeer(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.MrtPeer.
    """

    def test_parse_two_octet_as(self):
        bgp_id = '1.1.1.1'
        ip_addr = '10.0.0.1'
        buf = (
            b'\x00'      # type
            + addrconv.ipv4.text_to_bin(bgp_id)     # bgp_id
            + addrconv.ipv4.text_to_bin(ip_addr) +  # ip_addr
            b'\xfd\xe8'  # as_num
        )

        peer, rest = mrtlib.MrtPeer.parse(buf)

        eq_(0, peer.type)
        eq_(bgp_id, peer.bgp_id)
        eq_(ip_addr, peer.ip_addr)
        eq_(65000, peer.as_num)
        eq_(b'', rest)

    def test_serialize_two_octet_as(self):
        bgp_id = '1.1.1.1'
        ip_addr = '10.0.0.1'
        buf = (
            b'\x00'      # type
            + addrconv.ipv4.text_to_bin(bgp_id)     # bgp_id
            + addrconv.ipv4.text_to_bin(ip_addr) +  # ip_addr
            b'\xfd\xe8'  # as_num
        )

        peer = mrtlib.MrtPeer(
            bgp_id=bgp_id,
            ip_addr=ip_addr,
            as_num=65000,
            # type_=0,
        )

        output = peer.serialize()

        eq_(buf, output)


class TestMrtlibBgp4MpMrtRecord(unittest.TestCase):
    """
    Test case for ryu.lib.mrtlib.Bgp4MpMrtRecord.
    """

    # Note: The classes corresponding to the following subtypes are
    # tested in TestMrtlibMrtRecord.
    # - SUBTYPE_BGP4MP_MESSAGE = 1
    # - SUBTYPE_BGP4MP_MESSAGE_AS4 = 4
    # - SUBTYPE_BGP4MP_STATE_CHANGE_AS4 = 5
    # - SUBTYPE_BGP4MP_MESSAGE_LOCAL = 6
    # - SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL = 7

    def test_parse_state_change_afi_ipv4(self):
        peer_ip = '10.0.0.1'
        local_ip = '10.0.0.2'
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x10\x00\x00'  # type=TYPE_BGP4MP(16),
                                 # subtype=SUBTYPE_BGP4MP_STATE_CHANGE(0)
            b'\x00\x00\x00\x14'  # length=20
            b'\xfd\xe9\xfd\xea'  # peer_as=65001, local_as=65002
            b'\x22\x22\x00\x01'  # if_index, addr_family=AFI_IPv4(1)
            + addrconv.ipv4.text_to_bin(peer_ip)     # peer_ip
            + addrconv.ipv4.text_to_bin(local_ip) +  # local_ip
            b'\x00\x01\x00\x02'  # old_state=STATE_IDLE(1),
                                 # new_state=STATE_CONNECT(2)
        )

        (record, rest) = mrtlib.MrtRecord.parse(buf)

        eq_(0x11111111, record.timestamp)
        eq_(mrtlib.MrtRecord.TYPE_BGP4MP, record.type)
        eq_(mrtlib.Bgp4MpMrtRecord.SUBTYPE_BGP4MP_STATE_CHANGE, record.subtype)
        eq_(0x00000014, record.length)
        eq_(65001, record.message.peer_as)
        eq_(65002, record.message.local_as)
        eq_(0x2222, record.message.if_index)
        eq_(mrtlib.Bgp4MpStateChangeMrtMessage.AFI_IPv4,
            record.message.afi)
        eq_(mrtlib.Bgp4MpStateChangeMrtMessage.STATE_IDLE,
            record.message.old_state)
        eq_(mrtlib.Bgp4MpStateChangeMrtMessage.STATE_CONNECT,
            record.message.new_state)
        eq_(b'', rest)

    def test_serialize_state_change_afi_ipv4(self):
        peer_ip = '10.0.0.1'
        local_ip = '10.0.0.2'
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x10\x00\x00'  # type=TYPE_BGP4MP(16),
                                 # subtype=SUBTYPE_BGP4MP_STATE_CHANGE(0)
            b'\x00\x00\x00\x14'  # length=20
            b'\xfd\xe9\xfd\xea'  # peer_as=65001, local_as=65002
            b'\x22\x22\x00\x01'  # if_index, addr_family=AFI_IPv4(1)
            + addrconv.ipv4.text_to_bin(peer_ip)     # peer_ip
            + addrconv.ipv4.text_to_bin(local_ip) +  # local_ip
            b'\x00\x01\x00\x02'  # old_state=STATE_IDLE(1),
                                 # new_state=STATE_CONNECT(2)
        )

        message = mrtlib.Bgp4MpStateChangeMrtMessage(
            peer_as=65001,
            local_as=65002,
            if_index=0x2222,
            peer_ip=peer_ip,
            local_ip=local_ip,
            old_state=mrtlib.Bgp4MpStateChangeMrtMessage.STATE_IDLE,
            new_state=mrtlib.Bgp4MpStateChangeMrtMessage.STATE_CONNECT,
            # afi=mrtlib.Bgp4MpStateChangeMrtMessage.AFI_IPv4,
        )
        record = mrtlib.Bgp4MpMrtRecord(
            message=message,
            timestamp=0x11111111,
            # type_=None,
            # subtype=None,
            # length=None,
        )

        output = record.serialize()

        eq_(buf, output)

    def test_parse_state_change_afi_ipv6(self):
        peer_ip = 'fe80::1'
        local_ip = 'fe80::2'
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x10\x00\x00'  # type=TYPE_BGP4MP(16),
                                 # subtype=SUBTYPE_BGP4MP_STATE_CHANGE(0)
            b'\x00\x00\x00\x2c'  # length=44
            b'\xfd\xe9\xfd\xea'  # peer_as=65001, local_as=65002
            b'\x22\x22\x00\x02'  # if_index, addr_family=AFI_IPv6(2)
            + addrconv.ipv6.text_to_bin(peer_ip)     # peer_ip
            + addrconv.ipv6.text_to_bin(local_ip) +  # local_ip
            b'\x00\x01\x00\x02'  # old_state=STATE_IDLE(1),
                                 # new_state=STATE_CONNECT(2)
        )

        (record, rest) = mrtlib.MrtRecord.parse(buf)

        eq_(0x11111111, record.timestamp)
        eq_(mrtlib.MrtRecord.TYPE_BGP4MP, record.type)
        eq_(mrtlib.Bgp4MpMrtRecord.SUBTYPE_BGP4MP_STATE_CHANGE, record.subtype)
        eq_(0x0000002c, record.length)
        eq_(65001, record.message.peer_as)
        eq_(65002, record.message.local_as)
        eq_(0x2222, record.message.if_index)
        eq_(mrtlib.Bgp4MpStateChangeMrtMessage.AFI_IPv6,
            record.message.afi)
        eq_(mrtlib.Bgp4MpStateChangeMrtMessage.STATE_IDLE,
            record.message.old_state)
        eq_(mrtlib.Bgp4MpStateChangeMrtMessage.STATE_CONNECT,
            record.message.new_state)
        eq_(b'', rest)

    def test_serialize_state_change_afi_ipv6(self):
        peer_ip = 'fe80::1'
        local_ip = 'fe80::2'
        buf = (
            b'\x11\x11\x11\x11'  # timestamp
            b'\x00\x10\x00\x00'  # type=TYPE_BGP4MP(16),
                                 # subtype=SUBTYPE_BGP4MP_STATE_CHANGE(0)
            b'\x00\x00\x00\x2c'  # length=44
            b'\xfd\xe9\xfd\xea'  # peer_as=65001, local_as=65002
            b'\x22\x22\x00\x02'  # if_index, addr_family=AFI_IPv6(2)
            + addrconv.ipv6.text_to_bin(peer_ip)     # peer_ip
            + addrconv.ipv6.text_to_bin(local_ip) +  # local_ip
            b'\x00\x01\x00\x02'  # old_state=STATE_IDLE(1),
                                 # new_state=STATE_CONNECT(2)
        )

        message = mrtlib.Bgp4MpStateChangeMrtMessage(
            peer_as=65001,
            local_as=65002,
            if_index=0x2222,
            peer_ip=peer_ip,
            local_ip=local_ip,
            old_state=mrtlib.Bgp4MpStateChangeMrtMessage.STATE_IDLE,
            new_state=mrtlib.Bgp4MpStateChangeMrtMessage.STATE_CONNECT,
            # afi=mrtlib.Bgp4MpStateChangeMrtMessage.AFI_IPv4,
        )
        record = mrtlib.Bgp4MpMrtRecord(
            message=message,
            timestamp=0x11111111,
            # type_=None,
            # subtype=None,
            # length=None,
        )

        output = record.serialize()

        eq_(buf, output)
