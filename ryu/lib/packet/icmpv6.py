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

import struct
import sys
import array
import binascii

from . import packet_base
from . import packet_utils
from ryu.lib.mac import haddr_to_bin, haddr_to_str

ICMPV6_DST_UNREACH = 1       # dest unreachable, codes:
ICMPV6_PACKET_TOO_BIG = 2       # packet too big
ICMPV6_TIME_EXCEEDED = 3       # time exceeded, code:
ICMPV6_PARAM_PROB = 4       # ip6 header bad

ICMPV6_ECHO_REQUEST = 128     # echo service
ICMPV6_ECHO_REPLY = 129     # echo reply
MLD_LISTENER_QUERY = 130     # multicast listener query
MLD_LISTENER_REPOR = 131     # multicast listener report
MLD_LISTENER_DONE = 132     # multicast listener done

# RFC2292 decls
ICMPV6_MEMBERSHIP_QUERY = 130     # group membership query
ICMPV6_MEMBERSHIP_REPORT = 131     # group membership report
ICMPV6_MEMBERSHIP_REDUCTION = 132     # group membership termination

ND_ROUTER_SOLICIT = 133     # router solicitation
ND_ROUTER_ADVERT = 134     # router advertisment
ND_NEIGHBOR_SOLICIT = 135     # neighbor solicitation
ND_NEIGHBOR_ADVERT = 136     # neighbor advertisment
ND_REDIREC = 137     # redirect

ICMPV6_ROUTER_RENUMBERING = 138     # router renumbering

ICMPV6_WRUREQUEST = 139     # who are you request
ICMPV6_WRUREPLY = 140     # who are you reply
ICMPV6_FQDN_QUERY = 139     # FQDN query
ICMPV6_FQDN_REPLY = 140     # FQDN reply
ICMPV6_NI_QUERY = 139     # node information request
ICMPV6_NI_REPLY = 140     # node information reply

ICMPV6_MAXTYPE = 201


class icmpv6(packet_base.PacketBase):
    """ICMPv6 (RFC 2463) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the correspondig args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    type\_         Type
    code           Code
    csum           CheckSum \
                   (0 means automatically-calculate when encoding)
    data           Payload. \
                   ryu.lib.packet.icmpv6.echo object, or \
                   ryu.lib.packet.icmpv6.nd_neighbor object, or a bytearray.
    ============== ====================
    """
    _PACK_STR = '!BBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _ICMPV6_TYPES = {}

    @staticmethod
    def register_icmpv6_type(*args):
        def _register_icmpv6_type(cls):
            for type_ in args:
                icmpv6._ICMPV6_TYPES[type_] = cls
            return cls
        return _register_icmpv6_type

    def __init__(self, type_, code, csum, data=None):
        super(icmpv6, self).__init__()
        self.type_ = type_
        self.code = code
        self.csum = csum
        self.data = data

    @classmethod
    def parser(cls, buf):
        (type_, code, csum) = struct.unpack_from(cls._PACK_STR, buf)
        msg = cls(type_, code, csum)
        offset = cls._MIN_LEN
        if len(buf) > offset:
            cls_ = cls._ICMPV6_TYPES.get(type_, None)
            if cls_:
                msg.data = cls_.parser(buf, offset)
            else:
                msg.data = buf[offset:]

        return msg, None

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(icmpv6._PACK_STR, self.type_,
                                    self.code, self.csum))

        if self.data is not None:
            if self.type_ in icmpv6._ICMPV6_TYPES:
                hdr += self.data.serialize()
            else:
                hdr += self.data
        if self.csum == 0:
            self.csum = packet_utils.checksum_ip(prev, len(hdr), hdr + payload)
            struct.pack_into('!H', hdr, 2, self.csum)

        return hdr


@icmpv6.register_icmpv6_type(ND_NEIGHBOR_SOLICIT, ND_NEIGHBOR_ADVERT)
class nd_neighbor(object):
    """ICMPv6 sub encoder/decoder class for Neighbor Solicitation and
    Neighbor Advertisement messages. (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.icmpv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the correspondig args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    res            R,S,O Flags for Neighbor Advertisement. \
                   The 3 MSBs of "Reserved" field for Neighbor Solicitation.
    dst            Target Address
    type\_         "Type" field of the first option.  None if no options. \
                   NOTE: This implementation doesn't support two or more \
                   options.
    length         "Length" field of the first option.  None if no options.
    data           An object to describe the first option. \
                   None if no options. \
                   Either ryu.lib.packet.icmpv6.nd_option_la object \
                   or a bytearray.
    ============== ====================
    """

    _PACK_STR = '!I16s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _ND_OPTION_TYPES = {}

    # ND option type
    ND_OPTION_SLA = 1  # Source Link-Layer Address
    ND_OPTION_TLA = 2  # Target Link-Layer Address
    ND_OPTION_PI = 3   # Prefix Information
    ND_OPTION_RH = 4   # Redirected Header
    ND_OPTION_MTU = 5  # MTU

    @staticmethod
    def register_nd_option_type(*args):
        def _register_nd_option_type(cls):
            for type_ in args:
                nd_neighbor._ND_OPTION_TYPES[type_] = cls
            return cls
        return _register_nd_option_type

    def __init__(self, res, dst, type_=None, length=None, data=None):
        self.res = res << 29
        self.dst = dst
        self.type_ = type_
        self.length = length
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (res, dst) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(res >> 29, dst)
        offset += cls._MIN_LEN
        if len(buf) > offset:
            (msg.type_, msg.length) = struct.unpack_from('!BB', buf, offset)
            cls_ = cls._ND_OPTION_TYPES.get(msg.type_, None)
            offset += 2
            if cls_:
                msg.data = cls_.parser(buf, offset)
            else:
                msg.data = buf[offset:]

        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(nd_neighbor._PACK_STR, self.res, self.dst))

        if self.type_ is not None:
            hdr += bytearray(struct.pack('!BB', self.type_, self.length))
            if self.type_ in nd_neighbor._ND_OPTION_TYPES:
                hdr += self.data.serialize()
            elif self.data is not None:
                hdr += bytearray(self.data)

        return hdr


@nd_neighbor.register_nd_option_type(nd_neighbor.ND_OPTION_SLA,
                                     nd_neighbor.ND_OPTION_TLA)
class nd_option_la(object):
    """ICMPv6 sub encoder/decoder class for Neighbor discovery
    Source/Target Link-Layer Address Option. (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.nd_neighbor.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the correspondig args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    hw_src         Link-Layer Address. \
                   NOTE: If the address is longer than 6 octets this contains \
                   the first 6 octets in the address. \
                   This implementation assumes the address has at least \
                   6 octets.
    data           A bytearray which contains the rest of Link-Layer Address \
                   and padding.  When encoding a packet, it's user's \
                   responsibility to provide necessary padding for 8-octets \
                   alignment required by the protocol.
    ============== ====================
    """

    _PACK_STR = '!6s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, hw_src, data=None):
        self.hw_src = hw_src
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (hw_src, ) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(hw_src)
        offset += cls._MIN_LEN
        if len(buf) > offset:
            msg.data = buf[offset:]

        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR, self.hw_src))

        if self.data is not None:
            hdr += bytearray(self.data)

        return hdr


@icmpv6.register_icmpv6_type(ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST)
class echo(object):
    """ICMPv6 sub encoder/decoder class for Echo Request and Echo Reply
    messages.

    This is used with ryu.lib.packet.icmpv6.icmpv6 for
    ICMPv6 Echo Request and Echo Reply messages.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the correspondig args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    id             Identifier
    seq            Sequence Number
    data           Data
    ============== ====================
    """

    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, id_, seq, data=None):
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
            hdr += bytearray(self.data)

        return hdr
