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

"""
Library for reading/writing MRT (Multi-Threaded Routing Toolkit) Routing
Information Export Format [RFC6396].
"""

import abc
import logging
import struct
import time

import netaddr
import six

from ryu.lib import addrconv
from ryu.lib import ip
from ryu.lib import stringify
from ryu.lib import type_desc
from ryu.lib.packet import bgp
from ryu.lib.packet import ospf


LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class MrtRecord(stringify.StringifyMixin, type_desc.TypeDisp):
    """
    MRT record.
    """
    _HEADER_FMT = '!IHHI'  # the same as MRT Common Header
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    MESSAGE_CLS = None  # parser class for message field

    # MRT Types
    TYPE_OSPFv2 = 11
    TYPE_TABLE_DUMP = 12
    TYPE_TABLE_DUMP_V2 = 13
    TYPE_BGP4MP = 16
    TYPE_BGP4MP_ET = 17
    TYPE_ISIS = 32
    TYPE_ISIS_ET = 33
    TYPE_OSPFv3 = 48
    TYPE_OSPFv3_ET = 49

    # List of MRT type using Extended Timestamp MRT Header
    _EXT_TS_TYPES = [TYPE_BGP4MP_ET, TYPE_ISIS_ET, TYPE_OSPFv3_ET]

    def __init__(self, message, timestamp=None, type_=None, subtype=None,
                 length=None):
        assert issubclass(message.__class__, MrtMessage)
        self.message = message
        self.timestamp = timestamp
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.type = type_
        if subtype is None:
            subtype = self.MESSAGE_CLS._rev_lookup_type(message.__class__)
        self.subtype = subtype
        self.length = length

    @classmethod
    def parse_common_header(cls, buf):
        header_fields = struct.unpack_from(
            cls._HEADER_FMT, buf)

        return list(header_fields), buf[cls.HEADER_SIZE:]

    @classmethod
    def parse_extended_header(cls, buf):
        # If extended header field exist, override this in subclass.
        return [], buf

    @classmethod
    def parse_pre(cls, buf):
        buf = six.binary_type(buf)  # for convenience

        header_fields, _ = cls.parse_common_header(buf)
        # timestamp = header_fields[0]
        type_ = header_fields[1]
        # subtype = header_fields[2]
        length = header_fields[3]
        if type_ in cls._EXT_TS_TYPES:
            header_cls = ExtendedTimestampMrtRecord
        else:
            header_cls = MrtCommonRecord

        required_len = header_cls.HEADER_SIZE + length

        return required_len

    @classmethod
    def parse(cls, buf):
        buf = six.binary_type(buf)  # for convenience

        header_fields, rest = cls.parse_common_header(buf)
        # timestamp = header_fields[0]
        type_ = header_fields[1]
        subtype = header_fields[2]
        length = header_fields[3]

        sub_cls = MrtRecord._lookup_type(type_)
        extended_headers, rest = sub_cls.parse_extended_header(rest)
        header_fields.extend(extended_headers)

        msg_cls = sub_cls.MESSAGE_CLS._lookup_type(subtype)
        message_bin = rest[:length]
        message = msg_cls.parse(message_bin)

        return sub_cls(message, *header_fields), rest[length:]

    @abc.abstractmethod
    def serialize_header(self):
        pass

    def serialize(self):
        if self.timestamp is None:
            self.timestamp = int(time.time())

        buf = self.message.serialize()

        self.length = len(buf)  # fixup

        return self.serialize_header() + buf


class MrtCommonRecord(MrtRecord):
    """
    MRT record using MRT Common Header.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                           Timestamp                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |             Type              |            Subtype            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                             Length                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Message... (variable)                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IHHI'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def serialize_header(self):
        return struct.pack(self._HEADER_FMT,
                           self.timestamp,
                           self.type, self.subtype,
                           self.length)


class ExtendedTimestampMrtRecord(MrtRecord):
    """
    MRT record using Extended Timestamp MRT Header.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                           Timestamp                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |             Type              |            Subtype            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                             Length                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Microsecond Timestamp                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Message... (variable)                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IHHII'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _EXT_HEADER_FMT = '!I'
    EXT_HEADER_SIZE = struct.calcsize(_EXT_HEADER_FMT)

    def __init__(self, message, timestamp=None, type_=None, subtype=None,
                 ms_timestamp=None, length=None):
        super(ExtendedTimestampMrtRecord, self).__init__(
            message, timestamp, type_, subtype, length)
        self.ms_timestamp = ms_timestamp

    @classmethod
    def parse_extended_header(cls, buf):
        (ms_timestamp,) = struct.unpack_from(cls._EXT_HEADER_FMT, buf)

        return [ms_timestamp], buf[cls.EXT_HEADER_SIZE:]

    def serialize_header(self):
        return struct.pack(self._HEADER_FMT,
                           self.timestamp,
                           self.type, self.subtype,
                           self.length,
                           self.ms_timestamp)


@six.add_metaclass(abc.ABCMeta)
class MrtMessage(stringify.StringifyMixin, type_desc.TypeDisp):
    """
    MRT Message in record.
    """

    @classmethod
    @abc.abstractmethod
    def parse(cls, buf):
        pass

    @abc.abstractmethod
    def serialize(self):
        pass


class UnknownMrtMessage(MrtMessage):
    """
    MRT Message for the UNKNOWN Type.
    """

    def __init__(self, buf):
        self.buf = buf

    @classmethod
    def parse(cls, buf):
        return cls(buf)

    def serialize(self):
        return self.buf


# Registers self to unknown(default) type
UnknownMrtMessage._UNKNOWN_TYPE = UnknownMrtMessage


@MrtRecord.register_unknown_type()
class UnknownMrtRecord(MrtCommonRecord):
    """
    MRT record for the UNKNOWN Type.
    """
    MESSAGE_CLS = UnknownMrtMessage


class Ospf2MrtMessage(MrtMessage):
    """
    MRT Message for the OSPFv2 Type.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Remote IP Address                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Local IP Address                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                  OSPF Message Contents (variable)             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!4s4s'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _TYPE = {
        'ascii': [
            'remote_ip',
            'local_ip',
        ],
    }

    def __init__(self, remote_ip, local_ip, ospf_message):
        self.remote_ip = remote_ip
        self.local_ip = local_ip
        assert isinstance(ospf_message, ospf.OSPFMessage)
        self.ospf_message = ospf_message

    @classmethod
    def parse(cls, buf):
        (remote_ip, local_ip) = struct.unpack_from(cls._HEADER_FMT, buf)
        remote_ip = addrconv.ipv4.bin_to_text(remote_ip)
        local_ip = addrconv.ipv4.bin_to_text(local_ip)
        ospf_message, _, _ = ospf.OSPFMessage.parser(buf[cls.HEADER_SIZE:])

        return cls(remote_ip, local_ip, ospf_message)

    def serialize(self):
        return (addrconv.ipv4.text_to_bin(self.remote_ip)
                + addrconv.ipv4.text_to_bin(self.local_ip)
                + self.ospf_message.serialize())


@MrtRecord.register_type(MrtRecord.TYPE_OSPFv2)
class Ospf2MrtRecord(MrtCommonRecord):
    """
    MRT Record for the OSPFv2 Type.
    """
    MESSAGE_CLS = Ospf2MrtMessage

    def __init__(self, message, timestamp=None, type_=None, subtype=0,
                 length=None):
        super(Ospf2MrtRecord, self).__init__(
            message=message, timestamp=timestamp, type_=type_,
            subtype=subtype, length=length)


# Registers self to unknown(default) type
Ospf2MrtMessage._UNKNOWN_TYPE = Ospf2MrtMessage


@six.add_metaclass(abc.ABCMeta)
class TableDumpMrtMessage(MrtMessage):
    """
    MRT Message for the TABLE_DUMP Type.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         View Number           |       Sequence Number         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Prefix (variable)                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix Length |    Status     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Originated Time                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Peer IP Address (variable)                 |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Peer AS             |       Attribute Length        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                   BGP Attribute... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = ''  # should be defined in subclass
    HEADER_SIZE = 0
    _TYPE = {
        'ascii': [
            'prefix',
            'peer_ip',
        ],
    }

    def __init__(self, view_num, seq_num, prefix, prefix_len, status,
                 originated_time, peer_ip, peer_as, bgp_attributes,
                 attr_len=None):
        self.view_num = view_num
        self.seq_num = seq_num
        self.prefix = prefix
        self.prefix_len = prefix_len
        # Status in the TABLE_DUMP Type SHOULD be set to 1
        assert status == 1
        self.status = status
        self.originated_time = originated_time
        self.peer_ip = peer_ip
        self.peer_as = peer_as
        self.attr_len = attr_len
        assert isinstance(bgp_attributes, (list, tuple))
        for attr in bgp_attributes:
            assert isinstance(attr, bgp._PathAttribute)
        self.bgp_attributes = bgp_attributes

    @classmethod
    def parse(cls, buf):
        (view_num, seq_num, prefix, prefix_len, status, originated_time,
         peer_ip, peer_as, attr_len) = struct.unpack_from(cls._HEADER_FMT, buf)
        prefix = ip.bin_to_text(prefix)
        peer_ip = ip.bin_to_text(peer_ip)

        bgp_attr_bin = buf[cls.HEADER_SIZE:cls.HEADER_SIZE + attr_len]
        bgp_attributes = []
        while bgp_attr_bin:
            attr, bgp_attr_bin = bgp._PathAttribute.parser(bgp_attr_bin)
            bgp_attributes.append(attr)

        return cls(view_num, seq_num, prefix, prefix_len, status,
                   originated_time, peer_ip, peer_as, bgp_attributes,
                   attr_len)

    def serialize(self):
        bgp_attrs_bin = bytearray()
        for attr in self.bgp_attributes:
            bgp_attrs_bin += attr.serialize()
        self.attr_len = len(bgp_attrs_bin)  # fixup

        prefix = ip.text_to_bin(self.prefix)
        peer_ip = ip.text_to_bin(self.peer_ip)

        return struct.pack(self._HEADER_FMT,
                           self.view_num, self.seq_num,
                           prefix,
                           self.prefix_len, self.status,
                           self.originated_time,
                           peer_ip,
                           self.peer_as, self.attr_len) + bgp_attrs_bin


@MrtRecord.register_type(MrtRecord.TYPE_TABLE_DUMP)
class TableDumpMrtRecord(MrtCommonRecord):
    """
    MRT Record for the TABLE_DUMP Type.
    """
    MESSAGE_CLS = TableDumpMrtMessage

    # MRT Subtype
    SUBTYPE_AFI_IPv4 = 1
    SUBTYPE_AFI_IPv6 = 2


@TableDumpMrtMessage.register_type(TableDumpMrtRecord.SUBTYPE_AFI_IPv4)
class TableDumpAfiIPv4MrtMessage(TableDumpMrtMessage):
    """
    MRT Message for the TABLE_DUMP Type and the AFI_IPv4 subtype.
    """
    _HEADER_FMT = '!HH4sBBI4sHH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)


@TableDumpMrtMessage.register_type(TableDumpMrtRecord.SUBTYPE_AFI_IPv6)
class TableDumpAfiIPv6MrtMessage(TableDumpMrtMessage):
    """
    MRT Message for the TABLE_DUMP Type and the AFI_IPv6 subtype.
    """
    _HEADER_FMT = '!HH16sBBI16sHH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)


@six.add_metaclass(abc.ABCMeta)
class TableDump2MrtMessage(MrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type.
    """


@MrtRecord.register_type(MrtRecord.TYPE_TABLE_DUMP_V2)
class TableDump2MrtRecord(MrtCommonRecord):
    MESSAGE_CLS = TableDump2MrtMessage

    # MRT Subtype
    SUBTYPE_PEER_INDEX_TABLE = 1
    SUBTYPE_RIB_IPV4_UNICAST = 2
    SUBTYPE_RIB_IPV4_MULTICAST = 3
    SUBTYPE_RIB_IPV6_UNICAST = 4
    SUBTYPE_RIB_IPV6_MULTICAST = 5
    SUBTYPE_RIB_GENERIC = 6
    SUBTYPE_RIB_IPV4_UNICAST_ADDPATH = 8
    SUBTYPE_RIB_IPV4_MULTICAST_ADDPATH = 9
    SUBTYPE_RIB_IPV6_UNICAST_ADDPATH = 10
    SUBTYPE_RIB_IPV6_MULTICAST_ADDPATH = 11
    SUBTYPE_RIB_GENERIC_ADDPATH = 12


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_PEER_INDEX_TABLE)
class TableDump2PeerIndexTableMrtMessage(TableDump2MrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the PEER_INDEX_TABLE subtype.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Collector BGP ID                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |       View Name Length        |     View Name (variable)      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Peer Count           |    Peer Entries (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!4sH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _PEER_COUNT_FMT = '!H'
    PEER_COUNT_SIZE = struct.calcsize(_PEER_COUNT_FMT)
    _TYPE = {
        'ascii': [
            'bgp_id',
        ],
    }

    def __init__(self, bgp_id, peer_entries,
                 view_name='', view_name_len=None, peer_count=None):
        self.bgp_id = bgp_id
        assert isinstance(peer_entries, (list, tuple))
        for p in peer_entries:
            assert isinstance(p, MrtPeer)
        self.peer_entries = peer_entries
        assert isinstance(view_name, str)
        self.view_name = view_name
        self.view_name_len = view_name_len
        self.peer_count = peer_count

    @classmethod
    def parse(cls, buf):
        (bgp_id, view_name_len) = struct.unpack_from(cls._HEADER_FMT, buf)
        bgp_id = addrconv.ipv4.bin_to_text(bgp_id)
        offset = cls.HEADER_SIZE

        (view_name,) = struct.unpack_from('!%ds' % view_name_len, buf, offset)
        view_name = str(view_name.decode('utf-8'))
        offset += view_name_len

        (peer_count,) = struct.unpack_from(cls._PEER_COUNT_FMT, buf, offset)
        offset += cls.PEER_COUNT_SIZE

        rest = buf[offset:]
        peer_entries = []
        for i in range(peer_count):
            p, rest = MrtPeer.parse(rest)
            peer_entries.insert(i, p)

        return cls(bgp_id, peer_entries, view_name, view_name_len, peer_count)

    def serialize(self):
        view_name = self.view_name.encode('utf-8')
        self.view_name_len = len(view_name)  # fixup

        self.peer_count = len(self.peer_entries)  # fixup

        buf = struct.pack(self._HEADER_FMT,
                          addrconv.ipv4.text_to_bin(self.bgp_id),
                          self.view_name_len) + view_name

        buf += struct.pack(self._PEER_COUNT_FMT,
                           self.peer_count)

        for p in self.peer_entries:
            buf += p.serialize()

        return buf


class MrtPeer(stringify.StringifyMixin):
    """
    MRT Peer.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |   Peer Type   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Peer BGP ID                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                   Peer IP Address (variable)                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Peer AS (variable)                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!B4s'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    # Peer Type field:
    #
    #  0 1 2 3 4 5 6 7
    # +-+-+-+-+-+-+-+-+
    # | | | | | | |A|I|
    # +-+-+-+-+-+-+-+-+
    #
    #  Bit 6: Peer AS number size:  0 = 2 bytes, 1 = 4 bytes
    #  Bit 7: Peer IP Address family:  0 = IPv4(4 bytes),  1 = IPv6(16 bytes)
    IP_ADDR_FAMILY_BIT = 1 << 0
    AS_NUMBER_SIZE_BIT = 1 << 1

    _TYPE = {
        'ascii': [
            'bgp_id',
            'ip_addr',
        ],
    }

    def __init__(self, bgp_id, ip_addr, as_num, type_=0):
        self.type = type_
        self.bgp_id = bgp_id
        self.ip_addr = ip_addr
        self.as_num = as_num

    @classmethod
    def parse(cls, buf):
        (type_, bgp_id) = struct.unpack_from(cls._HEADER_FMT, buf)
        bgp_id = addrconv.ipv4.bin_to_text(bgp_id)
        offset = cls.HEADER_SIZE

        if type_ & cls.IP_ADDR_FAMILY_BIT:
            # IPv6 address family
            ip_addr_len = 16
        else:
            # IPv4 address family
            ip_addr_len = 4
        ip_addr = ip.bin_to_text(buf[offset:offset + ip_addr_len])
        offset += ip_addr_len

        if type_ & cls.AS_NUMBER_SIZE_BIT:
            # Four octet AS number
            (as_num,) = struct.unpack_from('!I', buf, offset)
            offset += 4
        else:
            # Two octet AS number
            (as_num,) = struct.unpack_from('!H', buf, offset)
            offset += 2

        return cls(bgp_id, ip_addr, as_num, type_), buf[offset:]

    def serialize(self):
        if ip.valid_ipv6(self.ip_addr):
            # Sets Peer IP Address family bit to IPv6
            self.type |= self.IP_ADDR_FAMILY_BIT
        ip_addr = ip.text_to_bin(self.ip_addr)

        if self.type & self.AS_NUMBER_SIZE_BIT or self.as_num > 0xffff:
            # Four octet AS number
            self.type |= self.AS_NUMBER_SIZE_BIT
            as_num = struct.pack('!I', self.as_num)
        else:
            # Two octet AS number
            as_num = struct.pack('!H', self.as_num)

        buf = struct.pack(self._HEADER_FMT,
                          self.type,
                          addrconv.ipv4.text_to_bin(self.bgp_id))

        return buf + ip_addr + as_num


@six.add_metaclass(abc.ABCMeta)
class TableDump2AfiSafiSpecificRibMrtMessage(TableDump2MrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the AFI/SAFI-specific
    RIB subtypes.

    The AFI/SAFI-specific RIB subtypes consist of the RIB_IPV4_UNICAST,
    RIB_IPV4_MULTICAST, RIB_IPV6_UNICAST, RIB_IPV6_MULTICAST and their
    additional-path version subtypes.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Sequence Number                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix Length |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Prefix (variable)                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Entry Count           |  RIB Entries (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!I'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    # Parser class to parse the Prefix field
    _PREFIX_CLS = None  # should be defined in subclass

    # Is additional-path version?
    _IS_ADDPATH = False

    def __init__(self, seq_num, prefix, rib_entries, entry_count=None):
        self.seq_num = seq_num
        assert isinstance(prefix, self._PREFIX_CLS)
        self.prefix = prefix
        self.entry_count = entry_count
        assert isinstance(rib_entries, (list, tuple))
        for rib_entry in rib_entries:
            assert isinstance(rib_entry, MrtRibEntry)
        self.rib_entries = rib_entries

    @classmethod
    def parse_rib_entries(cls, buf):
        (entry_count,) = struct.unpack_from('!H', buf)

        rest = buf[2:]
        rib_entries = []
        for i in range(entry_count):
            r, rest = MrtRibEntry.parse(rest, is_addpath=cls._IS_ADDPATH)
            rib_entries.insert(i, r)

        return entry_count, rib_entries, rest

    @classmethod
    def parse(cls, buf):
        (seq_num,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        prefix, rest = cls._PREFIX_CLS.parser(rest)

        entry_count, rib_entries, _ = cls.parse_rib_entries(rest)

        return cls(seq_num, prefix, rib_entries, entry_count)

    def serialize_rib_entries(self):
        self.entry_count = len(self.rib_entries)  # fixup

        rib_entries_bin = bytearray()
        for r in self.rib_entries:
            rib_entries_bin += r.serialize()

        return struct.pack('!H', self.entry_count) + rib_entries_bin

    def serialize(self):
        prefix_bin = self.prefix.serialize()

        rib_bin = self.serialize_rib_entries()  # entry_count + rib_entries

        return struct.pack(self._HEADER_FMT,
                           self.seq_num) + prefix_bin + rib_bin


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV4_UNICAST)
class TableDump2RibIPv4UnicastMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV4_UNICAST subtype.
    """
    _PREFIX_CLS = bgp.IPAddrPrefix


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV4_MULTICAST)
class TableDump2RibIPv4MulticastMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV4_MULTICAST subtype.
    """
    _PREFIX_CLS = bgp.IPAddrPrefix


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV6_UNICAST)
class TableDump2RibIPv6UnicastMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV6_MULTICAST subtype.
    """
    _PREFIX_CLS = bgp.IP6AddrPrefix


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV6_MULTICAST)
class TableDump2RibIPv6MulticastMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV6_MULTICAST subtype.
    """
    _PREFIX_CLS = bgp.IP6AddrPrefix


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV4_UNICAST_ADDPATH)
class TableDump2RibIPv4UnicastAddPathMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV4_UNICAST_ADDPATH subtype.
    """
    _PREFIX_CLS = bgp.IPAddrPrefix
    _IS_ADDPATH = True


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV4_MULTICAST_ADDPATH)
class TableDump2RibIPv4MulticastAddPathMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV4_MULTICAST_ADDPATH subtype.
    """
    _PREFIX_CLS = bgp.IPAddrPrefix
    _IS_ADDPATH = True


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV6_UNICAST_ADDPATH)
class TableDump2RibIPv6UnicastAddPathMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV6_UNICAST_ADDPATH subtype.
    """
    _PREFIX_CLS = bgp.IP6AddrPrefix
    _IS_ADDPATH = True


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_IPV6_MULTICAST_ADDPATH)
class TableDump2RibIPv6MulticastAddPathMrtMessage(
        TableDump2AfiSafiSpecificRibMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the
    SUBTYPE_RIB_IPV6_MULTICAST_ADDPATH subtype.
    """
    _PREFIX_CLS = bgp.IP6AddrPrefix
    _IS_ADDPATH = True


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_GENERIC)
class TableDump2RibGenericMrtMessage(TableDump2MrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the generic RIB subtypes.

    The generic RIB subtypes consist of the RIB_GENERIC and
    RIB_GENERIC_ADDPATH subtypes.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Sequence Number                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |    Address Family Identifier  |Subsequent AFI |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     Network Layer Reachability Information (variable)         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Entry Count           |  RIB Entries (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IHB'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    # Is additional-path version?
    _IS_ADDPATH = False

    def __init__(self, seq_num, afi, safi, nlri, rib_entries,
                 entry_count=None):
        self.seq_num = seq_num
        self.afi = afi
        self.safi = safi
        assert isinstance(nlri, bgp._AddrPrefix)
        self.nlri = nlri
        self.entry_count = entry_count
        assert isinstance(rib_entries, (list, tuple))
        for rib_entry in rib_entries:
            assert isinstance(rib_entry, MrtRibEntry)
        self.rib_entries = rib_entries

    @classmethod
    def parse_rib_entries(cls, buf):
        (entry_count,) = struct.unpack_from('!H', buf)

        rest = buf[2:]
        rib_entries = []
        for i in range(entry_count):
            r, rest = MrtRibEntry.parse(rest, is_addpath=cls._IS_ADDPATH)
            rib_entries.insert(i, r)

        return entry_count, rib_entries, rest

    @classmethod
    def parse(cls, buf):
        (seq_num, afi, safi) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        nlri, rest = bgp.BGPNLRI.parser(rest)

        entry_count, rib_entries, _ = cls.parse_rib_entries(rest)

        return cls(seq_num, afi, safi, nlri, rib_entries, entry_count)

    def serialize_rib_entries(self):
        self.entry_count = len(self.rib_entries)  # fixup

        rib_entries_bin = bytearray()
        for r in self.rib_entries:
            rib_entries_bin += r.serialize()

        return struct.pack('!H', self.entry_count) + rib_entries_bin

    def serialize(self):
        nlri_bin = self.nlri.serialize()

        rib_bin = self.serialize_rib_entries()  # entry_count + rib_entries

        return struct.pack(self._HEADER_FMT,
                           self.seq_num,
                           self.afi, self.safi) + nlri_bin + rib_bin


@TableDump2MrtMessage.register_type(
    TableDump2MrtRecord.SUBTYPE_RIB_GENERIC_ADDPATH)
class TableDump2RibGenericAddPathMrtMessage(TableDump2RibGenericMrtMessage):
    """
    MRT Message for the TABLE_DUMP_V2 Type and the RIB_GENERIC_ADDPATH
    subtype.
    """
    _IS_ADDPATH = True


class MrtRibEntry(stringify.StringifyMixin):
    """
    MRT RIB Entry.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer Index            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Originated Time                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        (Path Identifier)                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |      Attribute Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    BGP Attributes... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # peer_index, originated_time, attr_len
    _HEADER_FMT = '!HIH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    # peer_index, originated_time, path_id, attr_len
    _HEADER_FMT_ADDPATH = '!HIIH'
    HEADER_SIZE_ADDPATH = struct.calcsize(_HEADER_FMT_ADDPATH)

    def __init__(self, peer_index, originated_time, bgp_attributes,
                 attr_len=None, path_id=None):
        self.peer_index = peer_index
        self.originated_time = originated_time
        assert isinstance(bgp_attributes, (list, tuple))
        for attr in bgp_attributes:
            assert isinstance(attr, bgp._PathAttribute)
        self.bgp_attributes = bgp_attributes
        self.attr_len = attr_len
        self.path_id = path_id

    @classmethod
    def parse(cls, buf, is_addpath=False):
        path_id = None
        if not is_addpath:
            (peer_index, originated_time,
             attr_len) = struct.unpack_from(cls._HEADER_FMT, buf)
            _header_size = cls.HEADER_SIZE
        else:
            (peer_index, originated_time, path_id,
             attr_len) = struct.unpack_from(cls._HEADER_FMT_ADDPATH, buf)
            _header_size = cls.HEADER_SIZE_ADDPATH

        bgp_attr_bin = buf[_header_size:_header_size + attr_len]
        bgp_attributes = []
        while bgp_attr_bin:
            attr, bgp_attr_bin = bgp._PathAttribute.parser(bgp_attr_bin)
            bgp_attributes.append(attr)

        return cls(peer_index, originated_time, bgp_attributes,
                   attr_len, path_id), buf[_header_size + attr_len:]

    def serialize(self):
        bgp_attrs_bin = bytearray()
        for attr in self.bgp_attributes:
            bgp_attrs_bin += attr.serialize()
        self.attr_len = len(bgp_attrs_bin)  # fixup

        if self.path_id is None:
            return struct.pack(self._HEADER_FMT,
                               self.peer_index,
                               self.originated_time,
                               self.attr_len) + bgp_attrs_bin
        else:
            return struct.pack(self._HEADER_FMT_ADDPATH,
                               self.peer_index,
                               self.originated_time,
                               self.path_id,
                               self.attr_len) + bgp_attrs_bin


@six.add_metaclass(abc.ABCMeta)
class Bgp4MpMrtMessage(MrtMessage):
    """
    MRT Message for the BGP4MP Type.
    """
    _TYPE = {
        'ascii': [
            'peer_ip',
            'local_ip',
        ],
    }


@MrtRecord.register_type(MrtRecord.TYPE_BGP4MP)
class Bgp4MpMrtRecord(MrtCommonRecord):
    MESSAGE_CLS = Bgp4MpMrtMessage

    # MRT Subtype
    SUBTYPE_BGP4MP_STATE_CHANGE = 0
    SUBTYPE_BGP4MP_MESSAGE = 1
    SUBTYPE_BGP4MP_MESSAGE_AS4 = 4
    SUBTYPE_BGP4MP_STATE_CHANGE_AS4 = 5
    SUBTYPE_BGP4MP_MESSAGE_LOCAL = 6
    SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL = 7
    SUBTYPE_BGP4MP_MESSAGE_ADDPATH = 8
    SUBTYPE_BGP4MP_MESSAGE_AS4_ADDPATH = 9
    SUBTYPE_BGP4MP_MESSAGE_LOCAL_ADDPATH = 10
    SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH = 11


@MrtRecord.register_type(MrtRecord.TYPE_BGP4MP_ET)
class Bgp4MpEtMrtRecord(ExtendedTimestampMrtRecord):
    MESSAGE_CLS = Bgp4MpMrtMessage

    # MRT Subtype
    SUBTYPE_BGP4MP_STATE_CHANGE = 0
    SUBTYPE_BGP4MP_MESSAGE = 1
    SUBTYPE_BGP4MP_MESSAGE_AS4 = 4
    SUBTYPE_BGP4MP_STATE_CHANGE_AS4 = 5
    SUBTYPE_BGP4MP_MESSAGE_LOCAL = 6
    SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL = 7
    SUBTYPE_BGP4MP_MESSAGE_ADDPATH = 8
    SUBTYPE_BGP4MP_MESSAGE_AS4_ADDPATH = 9
    SUBTYPE_BGP4MP_MESSAGE_LOCAL_ADDPATH = 10
    SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH = 11


@Bgp4MpMrtMessage.register_type(
    Bgp4MpMrtRecord.SUBTYPE_BGP4MP_STATE_CHANGE)
class Bgp4MpStateChangeMrtMessage(Bgp4MpMrtMessage):
    """
    MRT Message for the BGP4MP Type and the BGP4MP_STATE_CHANGE subtype.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer AS Number        |        Local AS Number        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Interface Index        |        Address Family         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Peer IP Address (variable)               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Local IP Address (variable)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |            Old State          |          New State            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!HHHH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _ADDRS_FMT = '!%ds%ds'
    _STATES_FMT = '!HH'
    STATES_SIZE = struct.calcsize(_STATES_FMT)

    # FSM states
    STATE_IDLE = 1
    STATE_CONNECT = 2
    STATE_ACTIVE = 3
    STATE_OPEN_SENT = 4
    STATE_OPEN_CONFIRM = 5
    STATE_ESTABLISHED = 6

    # Address Family types
    AFI_IPv4 = 1
    AFI_IPv6 = 2

    def __init__(self, peer_as, local_as, if_index,
                 peer_ip, local_ip, old_state, new_state, afi=None):
        self.peer_as = peer_as
        self.local_as = local_as
        self.if_index = if_index
        self.afi = afi
        self.peer_ip = peer_ip
        self.local_ip = local_ip
        self.old_state = old_state
        self.new_state = new_state

    @classmethod
    def parse(cls, buf):
        (peer_as, local_as, if_index, afi) = struct.unpack_from(
            cls._HEADER_FMT, buf)
        offset = cls.HEADER_SIZE

        if afi == cls.AFI_IPv4:
            # IPv4 Address
            addrs_fmt = cls._ADDRS_FMT % (4, 4)
        elif afi == cls.AFI_IPv6:
            # IPv6 Address
            addrs_fmt = cls._ADDRS_FMT % (16, 16)
        else:
            raise struct.error('Unsupported address family: %d' % afi)

        (peer_ip, local_ip) = struct.unpack_from(addrs_fmt, buf, offset)
        peer_ip = ip.bin_to_text(peer_ip)
        local_ip = ip.bin_to_text(local_ip)
        offset += struct.calcsize(addrs_fmt)

        (old_state, new_state) = struct.unpack_from(
            cls._STATES_FMT, buf, offset)

        return cls(peer_as, local_as, if_index,
                   peer_ip, local_ip, old_state, new_state, afi)

    def serialize(self):
        # fixup
        if ip.valid_ipv4(self.peer_ip) and ip.valid_ipv4(self.local_ip):
            self.afi = self.AFI_IPv4
        elif ip.valid_ipv6(self.peer_ip) and ip.valid_ipv6(self.local_ip):
            self.afi = self.AFI_IPv6
        else:
            raise ValueError(
                'peer_ip and local_ip must be the same address family: '
                'peer_ip=%s, local_ip=%s' % (self.peer_ip, self.local_ip))

        buf = struct.pack(self._HEADER_FMT,
                          self.peer_as, self.local_as,
                          self.if_index, self.afi)

        buf += ip.text_to_bin(self.peer_ip)
        buf += ip.text_to_bin(self.local_ip)

        buf += struct.pack(self._STATES_FMT,
                           self.old_state, self.new_state)

        return buf


@Bgp4MpMrtMessage.register_type(
    Bgp4MpMrtRecord.SUBTYPE_BGP4MP_MESSAGE)
class Bgp4MpMessageMrtMessage(Bgp4MpMrtMessage):
    """
    MRT Message for the BGP4MP Type and the BGP4MP_MESSAGE subtype.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer AS Number        |        Local AS Number        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Interface Index        |        Address Family         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Peer IP Address (variable)               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Local IP Address (variable)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    BGP Message... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!HHHH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _ADDRS_FMT = '!%ds%ds'

    # Address Family types
    AFI_IPv4 = 1
    AFI_IPv6 = 2

    def __init__(self, peer_as, local_as, if_index,
                 peer_ip, local_ip, bgp_message, afi=None):
        self.peer_as = peer_as
        self.local_as = local_as
        self.if_index = if_index
        self.peer_ip = peer_ip
        self.local_ip = local_ip
        assert isinstance(bgp_message, bgp.BGPMessage)
        self.bgp_message = bgp_message
        self.afi = afi

    @classmethod
    def parse(cls, buf):
        (peer_as, local_as, if_index, afi) = struct.unpack_from(
            cls._HEADER_FMT, buf)
        offset = cls.HEADER_SIZE

        if afi == cls.AFI_IPv4:
            # IPv4 Address
            addrs_fmt = cls._ADDRS_FMT % (4, 4)
        elif afi == cls.AFI_IPv6:
            # IPv6 Address
            addrs_fmt = cls._ADDRS_FMT % (16, 16)
        else:
            raise struct.error('Unsupported address family: %d' % afi)

        (peer_ip, local_ip) = struct.unpack_from(addrs_fmt, buf, offset)
        peer_ip = ip.bin_to_text(peer_ip)
        local_ip = ip.bin_to_text(local_ip)
        offset += struct.calcsize(addrs_fmt)

        rest = buf[offset:]
        bgp_message, _, _ = bgp.BGPMessage.parser(rest)

        return cls(peer_as, local_as, if_index,
                   peer_ip, local_ip, bgp_message, afi)

    def serialize(self):
        # fixup
        if ip.valid_ipv4(self.peer_ip) and ip.valid_ipv4(self.local_ip):
            self.afi = self.AFI_IPv4
        elif ip.valid_ipv6(self.peer_ip) and ip.valid_ipv6(self.local_ip):
            self.afi = self.AFI_IPv6
        else:
            raise ValueError(
                'peer_ip and local_ip must be the same address family: '
                'peer_ip=%s, local_ip=%s' % (self.peer_ip, self.local_ip))

        buf = struct.pack(self._HEADER_FMT,
                          self.peer_as, self.local_as,
                          self.if_index, self.afi)

        buf += ip.text_to_bin(self.peer_ip)
        buf += ip.text_to_bin(self.local_ip)

        buf += self.bgp_message.serialize()

        return buf


@Bgp4MpMrtMessage.register_type(
    Bgp4MpMrtRecord.SUBTYPE_BGP4MP_MESSAGE_AS4)
class Bgp4MpMessageAs4MrtMessage(Bgp4MpMessageMrtMessage):
    """
    MRT Message for the BGP4MP Type and the BGP4MP_MESSAGE_AS4 subtype.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Peer AS Number                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Local AS Number                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Interface Index        |        Address Family         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Peer IP Address (variable)               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Local IP Address (variable)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    BGP Message... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IIHH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)


@Bgp4MpMrtMessage.register_type(
    Bgp4MpMrtRecord.SUBTYPE_BGP4MP_STATE_CHANGE_AS4)
class Bgp4MpStateChangeAs4MrtMessage(Bgp4MpStateChangeMrtMessage):
    """
    MRT Message for the BGP4MP Type and the BGP4MP_STATE_CHANGE_AS4 subtype.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Peer AS Number                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Local AS Number                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Interface Index        |        Address Family         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Peer IP Address (variable)               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Local IP Address (variable)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |            Old State          |          New State            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IIHH'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)


@Bgp4MpMrtMessage.register_type(
    Bgp4MpMrtRecord.SUBTYPE_BGP4MP_MESSAGE_LOCAL)
class Bgp4MpMessageLocalMrtMessage(Bgp4MpMessageMrtMessage):
    """
    MRT Message for the BGP4MP Type and the BGP4MP_MESSAGE_LOCAL subtype.
    """


@Bgp4MpMrtMessage.register_type(
    Bgp4MpMrtRecord.SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL)
class Bgp4MpMessageAs4LocalMrtMessage(Bgp4MpMessageAs4MrtMessage):
    """
    MRT Message for the BGP4MP Type and the BGP4MP_MESSAGE_AS4_LOCAL subtype.
    """


# TODO:
# Currently, Ryu does not provide the packet library for ISIS protocol.
# Implement parser for ISIS MRT message.
# class IsisMrtRecord(MrtCommonRecord):
# class IsisMrtMessage(MrtMessage):


# TODO:
# Currently, Ryu does not provide the packet library for OSPFv3 protocol.
# Implement the parser for OSPFv3 MRT message.
# class Ospf3MrtRecord(MrtCommonRecord):
# class Ospf3MrtMessage(MrtMessage):


class Reader(object):
    """
    MRT format file reader.

    ========= ================================================
    Argument  Description
    ========= ================================================
    f         File object which reading MRT format file
              in binary mode.
    ========= ================================================

    Example of Usage::

        import bz2
        from ryu.lib import mrtlib

        count = 0
        for record in mrtlib.Reader(
                bz2.BZ2File('rib.YYYYMMDD.hhmm.bz2', 'rb')):
            print("%d, %s" % (count, record))
            count += 1
    """

    def __init__(self, f):
        self._f = f

    def __iter__(self):
        return self

    def next(self):
        header_buf = self._f.read(MrtRecord.HEADER_SIZE)
        if len(header_buf) < MrtRecord.HEADER_SIZE:
            raise StopIteration()

        # Hack to avoid eating memory up
        self._f.seek(-MrtRecord.HEADER_SIZE, 1)
        required_len = MrtRecord.parse_pre(header_buf)
        buf = self._f.read(required_len)
        record, _ = MrtRecord.parse(buf)

        return record

    # for Python 3 compatible
    __next__ = next

    def close(self):
        self._f.close()

    def __del__(self):
        self.close()


class Writer(object):
    """
    MRT format file writer.

    ========= ================================================
    Argument  Description
    ========= ================================================
    f         File object which writing MRT format file
              in binary mode.
    ========= ================================================

    Example of usage::

        import bz2
        import time
        from ryu.lib import mrtlib
        from ryu.lib.packet import bgp

        mrt_writer = mrtlib.Writer(
            bz2.BZ2File('rib.YYYYMMDD.hhmm.bz2', 'wb'))

        prefix = bgp.IPAddrPrefix(24, '10.0.0.0')

        rib_entry = mrtlib.MrtRibEntry(
            peer_index=0,
            originated_time=int(time.time()),
            bgp_attributes=[bgp.BGPPathAttributeOrigin(0)])

        message = mrtlib.TableDump2RibIPv4UnicastMrtMessage(
            seq_num=0,
            prefix=prefix,
            rib_entries=[rib_entry])

        record = mrtlib.TableDump2MrtRecord(
            message=message)

        mrt_writer.write(record)
    """

    def __init__(self, f):
        self._f = f

    def write(self, record):
        if not isinstance(record, MrtRecord):
            raise ValueError(
                'record should be an instance of MrtRecord subclass')

        self._f.write(record.serialize())

    def close(self):
        self._f.close()

    def __del__(self):
        self.close()
