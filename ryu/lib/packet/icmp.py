# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

import abc
import struct

import six

from . import packet_base
from . import packet_utils
from ryu.lib import stringify


ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_SRC_QUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

ICMP_ECHO_REPLY_CODE = 0
ICMP_HOST_UNREACH_CODE = 1
ICMP_PORT_UNREACH_CODE = 3
ICMP_TTL_EXPIRED_CODE = 0


class icmp(packet_base.PacketBase):
    """ICMP (RFC 792) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== ====================
    Attribute      Description
    ============== ====================
    type           Type
    code           Code
    csum           CheckSum \
                   (0 means automatically-calculate when encoding)
    data           Payload. \
                   Either a bytearray, or \
                   ryu.lib.packet.icmp.echo or \
                   ryu.lib.packet.icmp.dest_unreach or \
                   ryu.lib.packet.icmp.TimeExceeded object \
                   NOTE for icmp.echo: \
                   This includes "unused" 16 bits and the following \
                   "Internet Header + 64 bits of Original Data Datagram" of \
                   the ICMP header. \
                   NOTE for icmp.dest_unreach and icmp.TimeExceeded: \
                   This includes "unused" 8 or 24 bits and the following \
                   "Internet Header + leading octets of original datagram" \
                   of the original packet.
    ============== ====================
    """

    _PACK_STR = '!BBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _ICMP_TYPES = {}

    @staticmethod
    def register_icmp_type(*args):
        def _register_icmp_type(cls):
            for type_ in args:
                icmp._ICMP_TYPES[type_] = cls
            return cls
        return _register_icmp_type

    def __init__(self, type_=ICMP_ECHO_REQUEST, code=0, csum=0, data=b''):
        super(icmp, self).__init__()
        self.type = type_
        self.code = code
        self.csum = csum
        self.data = data

    @classmethod
    def parser(cls, buf):
        (type_, code, csum) = struct.unpack_from(cls._PACK_STR, buf)
        msg = cls(type_, code, csum)
        offset = cls._MIN_LEN

        if len(buf) > offset:
            cls_ = cls._ICMP_TYPES.get(type_, None)
            if cls_:
                msg.data = cls_.parser(buf, offset)
            else:
                msg.data = buf[offset:]

        return msg, None, None

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(icmp._PACK_STR, self.type,
                                    self.code, self.csum))

        if self.data:
            if self.type in icmp._ICMP_TYPES:
                assert isinstance(self.data, _ICMPv4Payload)
                hdr += self.data.serialize()
            else:
                hdr += self.data
        else:
            self.data = echo()
            hdr += self.data.serialize()

        if self.csum == 0:
            self.csum = packet_utils.checksum(hdr)
            struct.pack_into('!H', hdr, 2, self.csum)

        return hdr

    def __len__(self):
        return self._MIN_LEN + len(self.data)


@six.add_metaclass(abc.ABCMeta)
class _ICMPv4Payload(stringify.StringifyMixin):
    """
    Base class for the payload of ICMPv4 packet.
    """


@icmp.register_icmp_type(ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST)
class echo(_ICMPv4Payload):
    """ICMP sub encoder/decoder class for Echo and Echo Reply messages.

    This is used with ryu.lib.packet.icmp.icmp for
    ICMP Echo and Echo Reply messages.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== ====================
    Attribute      Description
    ============== ====================
    id             Identifier
    seq            Sequence Number
    data           Internet Header + 64 bits of Original Data Datagram
    ============== ====================
    """

    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, id_=0, seq=0, data=None):
        super(echo, self).__init__()
        self.id = id_
        self.seq = seq
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (id_, seq) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(id_, seq)
        offset += cls._MIN_LEN

        if len(buf) > offset:
            msg.data = buf[offset:]

        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(echo._PACK_STR, self.id,
                                    self.seq))

        if self.data is not None:
            hdr += self.data

        return hdr

    def __len__(self):
        length = self._MIN_LEN
        if self.data is not None:
            length += len(self.data)
        return length


@icmp.register_icmp_type(ICMP_DEST_UNREACH)
class dest_unreach(_ICMPv4Payload):
    """ICMP sub encoder/decoder class for Destination Unreachable Message.

    This is used with ryu.lib.packet.icmp.icmp for
    ICMP Destination Unreachable Message.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    [RFC1191] reserves bits for the "Next-Hop MTU" field.
    [RFC4884] introduced 8-bit data length attribute.

    .. tabularcolumns:: |l|p{35em}|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    data_len       data length
    mtu            Next-Hop MTU

                   NOTE: This field is required when icmp code is 4

                   code 4 = fragmentation needed and DF set
    data           Internet Header + leading octets of original datagram
    ============== =====================================================
    """

    _PACK_STR = '!xBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, data_len=0, mtu=0, data=None):
        super(dest_unreach, self).__init__()

        if ((data_len >= 0) and (data_len <= 255)):
            self.data_len = data_len
        else:
            raise ValueError('Specified data length (%d) is invalid.' % data_len)

        self.mtu = mtu
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (data_len, mtu) = struct.unpack_from(cls._PACK_STR,
                                             buf, offset)
        msg = cls(data_len, mtu)
        offset += cls._MIN_LEN

        if len(buf) > offset:
            msg.data = buf[offset:]

        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(dest_unreach._PACK_STR,
                                    self.data_len, self.mtu))

        if self.data is not None:
            hdr += self.data

        return hdr

    def __len__(self):
        length = self._MIN_LEN
        if self.data is not None:
            length += len(self.data)
        return length


@icmp.register_icmp_type(ICMP_TIME_EXCEEDED)
class TimeExceeded(_ICMPv4Payload):
    """ICMP sub encoder/decoder class for Time Exceeded Message.

    This is used with ryu.lib.packet.icmp.icmp for
    ICMP Time Exceeded Message.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    [RFC4884] introduced 8-bit data length attribute.

    .. tabularcolumns:: |l|L|

    ============== ====================
    Attribute      Description
    ============== ====================
    data_len       data length
    data           Internet Header + leading octets of original datagram
    ============== ====================
    """

    _PACK_STR = '!xBxx'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, data_len=0, data=None):
        if (data_len >= 0) and (data_len <= 255):
            self.data_len = data_len
        else:
            raise ValueError('Specified data length (%d) is invalid.' % data_len)

        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (data_len, ) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(data_len)
        offset += cls._MIN_LEN

        if len(buf) > offset:
            msg.data = buf[offset:]

        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(TimeExceeded._PACK_STR, self.data_len))

        if self.data is not None:
            hdr += self.data

        return hdr

    def __len__(self):
        length = self._MIN_LEN
        if self.data is not None:
            length += len(self.data)
        return length


icmp.set_classes(icmp._ICMP_TYPES)
