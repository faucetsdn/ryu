# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
Internet Group Management Protocol(IGMP) packet parser/serializer

[RFC 1112] IGMP v1 format::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Type  |    Unused     |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

[RFC 2236] IGMP v2 format::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Type     | Max Resp Time |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

[RFC 3376] IGMP v3 Membership Query format::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Type = 0x11  | Max Resp Code |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address [1]                      |
   +-                                                             -+
   |                       Source Address [2]                      |
   +-                              .                              -+
   .                               .                               .
   .                               .                               .
   +-                                                             -+
   |                       Source Address [N]                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IGMP v3 Membership Report format::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Type = 0x22  |    Reserved   |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Reserved            |  Number of Group Records (M)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   .                                                               .
   .                        Group Record [1]                       .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   .                                                               .
   .                        Group Record [2]                       .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               .                               |
   .                               .                               .
   |                               .                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   .                                                               .
   .                        Group Record [M]                       .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Where each Group Record has the following internal format::

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Multicast Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address [1]                      |
   +-                                                             -+
   |                       Source Address [2]                      |
   +-                                                             -+
   .                               .                               .
   .                               .                               .
   .                               .                               .
   +-                                                             -+
   |                       Source Address [N]                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   .                                                               .
   .                         Auxiliary Data                        .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import six
import struct
from math import trunc

from ryu.lib import addrconv
from ryu.lib import stringify
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet_utils


IGMP_TYPE_QUERY = 0x11
IGMP_TYPE_REPORT_V1 = 0x12
IGMP_TYPE_REPORT_V2 = 0x16
IGMP_TYPE_LEAVE = 0x17
IGMP_TYPE_REPORT_V3 = 0x22

QUERY_RESPONSE_INTERVAL = 10.0
LAST_MEMBER_QUERY_INTERVAL = 1.0

MULTICAST_IP_ALL_HOST = '224.0.0.1'
MULTICAST_MAC_ALL_HOST = '01:00:5e:00:00:01'

# for types of IGMPv3 Report Group Records
MODE_IS_INCLUDE = 1
MODE_IS_EXCLUDE = 2
CHANGE_TO_INCLUDE_MODE = 3
CHANGE_TO_EXCLUDE_MODE = 4
ALLOW_NEW_SOURCES = 5
BLOCK_OLD_SOURCES = 6


class igmp(packet_base.PacketBase):
    """
    Internet Group Management Protocol(IGMP, RFC 1112, RFC 2236)
    header encoder/decoder class.

    http://www.ietf.org/rfc/rfc1112.txt

    http://www.ietf.org/rfc/rfc2236.txt

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    =============== ====================================================
    Attribute       Description
    =============== ====================================================
    msgtype         a message type for v2, or a combination of
                    version and a message type for v1.
    maxresp         max response time in unit of 1/10 second. it is
                    meaningful only in Query Message.
    csum            a check sum value. 0 means automatically-calculate
                    when encoding.
    address         a group address value.
    =============== ====================================================
    """
    _PACK_STR = '!BBH4s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = {
        'ascii': [
            'address'
        ]
    }

    def __init__(self, msgtype=IGMP_TYPE_QUERY, maxresp=0, csum=0,
                 address='0.0.0.0'):
        super(igmp, self).__init__()
        self.msgtype = msgtype
        self.maxresp = maxresp
        self.csum = csum
        self.address = address

    @classmethod
    def parser(cls, buf):
        assert cls._MIN_LEN <= len(buf)
        (msgtype, ) = struct.unpack_from('!B', buf)
        if (IGMP_TYPE_QUERY == msgtype and
                igmpv3_query.MIN_LEN <= len(buf)):
            (instance, subclass, rest,) = igmpv3_query.parser(buf)
        elif IGMP_TYPE_REPORT_V3 == msgtype:
            (instance, subclass, rest,) = igmpv3_report.parser(buf)
        else:
            (msgtype, maxresp, csum, address
             ) = struct.unpack_from(cls._PACK_STR, buf)
            instance = cls(msgtype, maxresp, csum,
                           addrconv.ipv4.bin_to_text(address))
            subclass = None
            rest = buf[cls._MIN_LEN:]
        return instance, subclass, rest

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(self._PACK_STR, self.msgtype,
                                    trunc(self.maxresp), self.csum,
                                    addrconv.ipv4.text_to_bin(self.address)))

        if self.csum == 0:
            self.csum = packet_utils.checksum(hdr)
            struct.pack_into('!H', hdr, 2, self.csum)

        return hdr


class igmpv3_query(igmp):
    """
    Internet Group Management Protocol(IGMP, RFC 3376)
    Membership Query message encoder/decoder class.

    http://www.ietf.org/rfc/rfc3376.txt

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============== ====================================================
    Attribute       Description
    =============== ====================================================
    msgtype         a message type for v3.
    maxresp         max response time in unit of 1/10 second.
    csum            a check sum value. 0 means automatically-calculate
                    when encoding.
    address         a group address value.
    s_flg           when set to 1, routers suppress the timer process.
    qrv             robustness variable for a querier.
    qqic            an interval time for a querier in unit of seconds.
    num             a number of the multicast servers.
    srcs            a list of IPv4 addresses of the multicast servers.
    =============== ====================================================
    """

    _PACK_STR = '!BBH4sBBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    MIN_LEN = _MIN_LEN
    _TYPE = {
        'ascii': [
            'address'
        ],
        'asciilist': [
            'srcs'
        ]
    }

    def __init__(self, msgtype=IGMP_TYPE_QUERY, maxresp=100, csum=0,
                 address='0.0.0.0', s_flg=0, qrv=2, qqic=0, num=0,
                 srcs=None):
        super(igmpv3_query, self).__init__(
            msgtype, maxresp, csum, address)
        self.s_flg = s_flg
        self.qrv = qrv
        self.qqic = qqic
        self.num = num
        srcs = srcs or []
        assert isinstance(srcs, list)
        for src in srcs:
            assert isinstance(src, str)
        self.srcs = srcs

    @classmethod
    def parser(cls, buf):
        (msgtype, maxresp, csum, address, s_qrv, qqic, num
         ) = struct.unpack_from(cls._PACK_STR, buf)
        s_flg = (s_qrv >> 3) & 0b1
        qrv = s_qrv & 0b111
        offset = cls._MIN_LEN
        srcs = []
        while 0 < len(buf[offset:]) and num > len(srcs):
            assert 4 <= len(buf[offset:])
            (src, ) = struct.unpack_from('4s', buf, offset)
            srcs.append(addrconv.ipv4.bin_to_text(src))
            offset += 4
        assert num == len(srcs)
        return (cls(msgtype, maxresp, csum,
                    addrconv.ipv4.bin_to_text(address), s_flg, qrv,
                    qqic, num, srcs),
                None,
                buf[offset:])

    def serialize(self, payload, prev):
        s_qrv = self.s_flg << 3 | self.qrv
        buf = bytearray(struct.pack(self._PACK_STR, self.msgtype,
                                    trunc(self.maxresp), self.csum,
                                    addrconv.ipv4.text_to_bin(self.address),
                                    s_qrv, trunc(self.qqic), self.num))
        for src in self.srcs:
            buf.extend(struct.pack('4s', addrconv.ipv4.text_to_bin(src)))
        if 0 == self.num:
            self.num = len(self.srcs)
            struct.pack_into('!H', buf, 10, self.num)
        if 0 == self.csum:
            self.csum = packet_utils.checksum(buf)
            struct.pack_into('!H', buf, 2, self.csum)
        return six.binary_type(buf)

    def __len__(self):
        return self._MIN_LEN + len(self.srcs) * 4


class igmpv3_report(igmp):
    """
    Internet Group Management Protocol(IGMP, RFC 3376)
    Membership Report message encoder/decoder class.

    http://www.ietf.org/rfc/rfc3376.txt

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============== ====================================================
    Attribute       Description
    =============== ====================================================
    msgtype         a message type for v3.
    csum            a check sum value. 0 means automatically-calculate
                    when encoding.
    record_num      a number of the group records.
    records         a list of ryu.lib.packet.igmp.igmpv3_report_group.
                    None if no records.
    =============== ====================================================
    """

    _PACK_STR = '!BxH2xH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _class_prefixes = ['igmpv3_report_group']

    def __init__(self, msgtype=IGMP_TYPE_REPORT_V3, csum=0, record_num=0,
                 records=None):
        self.msgtype = msgtype
        self.csum = csum
        self.record_num = record_num
        records = records or []
        assert isinstance(records, list)
        for record in records:
            assert isinstance(record, igmpv3_report_group)
        self.records = records

    @classmethod
    def parser(cls, buf):
        (msgtype, csum, record_num
         ) = struct.unpack_from(cls._PACK_STR, buf)
        offset = cls._MIN_LEN
        records = []
        while 0 < len(buf[offset:]) and record_num > len(records):
            record = igmpv3_report_group.parser(buf[offset:])
            records.append(record)
            offset += len(record)
        assert record_num == len(records)
        return (cls(msgtype, csum, record_num, records),
                None,
                buf[offset:])

    def serialize(self, payload, prev):
        buf = bytearray(struct.pack(self._PACK_STR, self.msgtype,
                                    self.csum, self.record_num))
        for record in self.records:
            buf.extend(record.serialize())
        if 0 == self.record_num:
            self.record_num = len(self.records)
            struct.pack_into('!H', buf, 6, self.record_num)
        if 0 == self.csum:
            self.csum = packet_utils.checksum(buf)
            struct.pack_into('!H', buf, 2, self.csum)
        return six.binary_type(buf)

    def __len__(self):
        records_len = 0
        for record in self.records:
            records_len += len(record)
        return self._MIN_LEN + records_len


class igmpv3_report_group(stringify.StringifyMixin):
    r"""
    Internet Group Management Protocol(IGMP, RFC 3376)
    Membership Report Group Record message encoder/decoder class.

    http://www.ietf.org/rfc/rfc3376.txt

    This is used with ryu.lib.packet.igmp.igmpv3_report.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============== ====================================================
    Attribute       Description
    =============== ====================================================
    type\_          a group record type for v3.
    aux_len         the length of the auxiliary data.
    num             a number of the multicast servers.
    address         a group address value.
    srcs            a list of IPv4 addresses of the multicast servers.
    aux             the auxiliary data.
    =============== ====================================================
    """
    _PACK_STR = '!BBH4s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = {
        'ascii': [
            'address'
        ],
        'asciilist': [
            'srcs'
        ]
    }

    def __init__(self, type_=0, aux_len=0, num=0, address='0.0.0.0',
                 srcs=None, aux=None):
        self.type_ = type_
        self.aux_len = aux_len
        self.num = num
        self.address = address
        srcs = srcs or []
        assert isinstance(srcs, list)
        for src in srcs:
            assert isinstance(src, str)
        self.srcs = srcs
        self.aux = aux

    @classmethod
    def parser(cls, buf):
        (type_, aux_len, num, address
         ) = struct.unpack_from(cls._PACK_STR, buf)
        offset = cls._MIN_LEN
        srcs = []
        while 0 < len(buf[offset:]) and num > len(srcs):
            assert 4 <= len(buf[offset:])
            (src, ) = struct.unpack_from('4s', buf, offset)
            srcs.append(addrconv.ipv4.bin_to_text(src))
            offset += 4
        assert num == len(srcs)
        aux = None
        if aux_len:
            (aux, ) = struct.unpack_from('%ds' % (aux_len * 4), buf, offset)
        return cls(type_, aux_len, num,
                   addrconv.ipv4.bin_to_text(address), srcs, aux)

    def serialize(self):
        buf = bytearray(struct.pack(self._PACK_STR, self.type_,
                                    self.aux_len, self.num,
                                    addrconv.ipv4.text_to_bin(self.address)))
        for src in self.srcs:
            buf.extend(struct.pack('4s', addrconv.ipv4.text_to_bin(src)))
        if 0 == self.num:
            self.num = len(self.srcs)
            struct.pack_into('!H', buf, 2, self.num)
        if self.aux is not None:
            mod = len(self.aux) % 4
            if mod:
                self.aux += bytearray(4 - mod)
                self.aux = six.binary_type(self.aux)
            buf.extend(self.aux)
            if 0 == self.aux_len:
                self.aux_len = len(self.aux) // 4
                struct.pack_into('!B', buf, 1, self.aux_len)
        return six.binary_type(buf)

    def __len__(self):
        return self._MIN_LEN + len(self.srcs) * 4 + self.aux_len * 4
