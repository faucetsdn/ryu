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
import sys
import array
import binascii

from . import packet_base
from . import packet_utils
from ryu.lib import addrconv
from ryu.lib import stringify

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

# ND_OPTIONS from RFC 4861
ND_OPTION_SLA = 1  # Source Link-Layer Address
ND_OPTION_TLA = 2  # Target Link-Layer Address
ND_OPTION_PI = 3   # Prefix Information
ND_OPTION_RH = 4   # Redirected Header
ND_OPTION_MTU = 5  # MTU


class icmpv6(packet_base.PacketBase):
    """ICMPv6 (RFC 2463) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{35em}|

    ============== ====================
    Attribute      Description
    ============== ====================
    type\_         Type
    code           Code
    csum           CheckSum
                   (0 means automatically-calculate when encoding)
    data           Payload.

                   ryu.lib.packet.icmpv6.echo object, \
                   ryu.lib.packet.icmpv6.nd_neighbor object, \
                   ryu.lib.packet.icmpv6.nd_router_solicit object, \
                   ryu.lib.packet.icmpv6.nd_router_advert object, \
                   or a bytearray.
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

    def __init__(self, type_=0, code=0, csum=0, data=None):
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

        return msg, None, None

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

    def __len__(self):
        length = self._MIN_LEN
        if self.data is not None:
            length += len(self.data)
        return length


@icmpv6.register_icmpv6_type(ND_NEIGHBOR_SOLICIT, ND_NEIGHBOR_ADVERT)
class nd_neighbor(stringify.StringifyMixin):
    """ICMPv6 sub encoder/decoder class for Neighbor Solicitation and
    Neighbor Advertisement messages. (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.icmpv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{35em}|

    ============== ====================
    Attribute      Description
    ============== ====================
    res            R,S,O Flags for Neighbor Advertisement. \
                   The 3 MSBs of "Reserved" field for Neighbor Solicitation.
    dst            Target Address
    option         a derived object of ryu.lib.packet.icmpv6.nd_option \
                   or a bytearray. None if no options.
    ============== ====================
    """

    _PACK_STR = '!I16s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _ND_OPTION_TYPES = {}

    @staticmethod
    def register_nd_option_type(*args):
        def _register_nd_option_type(cls):
            nd_neighbor._ND_OPTION_TYPES[cls.option_type()] = cls
            return cls
        return _register_nd_option_type(args[0])

    def __init__(self, res=0, dst='::', option=None):
        self.res = res
        self.dst = dst
        self.option = option

    @classmethod
    def parser(cls, buf, offset):
        (res, dst) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN
        option = None
        if len(buf) > offset:
            (type_, ) = struct.unpack_from('!B', buf, offset)
            cls_ = cls._ND_OPTION_TYPES.get(type_)
            if cls_ is not None:
                option = cls_.parser(buf, offset)
            else:
                option = buf[offset:]
        msg = cls(res >> 29, addrconv.ipv6.bin_to_text(dst), option)
        return msg

    def serialize(self):
        res = self.res << 29
        hdr = bytearray(struct.pack(
            nd_neighbor._PACK_STR, res,
            addrconv.ipv6.text_to_bin(self.dst)))
        if self.option is not None:
            if isinstance(self.option, nd_option):
                hdr.extend(self.option.serialize())
            else:
                hdr.extend(self.option)
        return str(hdr)

    def __len__(self):
        length = self._MIN_LEN
        if self.option is not None:
            length += len(self.option)
        return length


@icmpv6.register_icmpv6_type(ND_ROUTER_SOLICIT)
class nd_router_solicit(stringify.StringifyMixin):
    """ICMPv6 sub encoder/decoder class for Router Solicitation messages.
    (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.icmpv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{35em}|

    ============== ====================
    Attribute      Description
    ============== ====================
    res            This field is unused.  It MUST be initialized to zero.
    option         a derived object of ryu.lib.packet.icmpv6.nd_option \
                   or a bytearray. None if no options.
    ============== ====================
    """

    _PACK_STR = '!I'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _ND_OPTION_TYPES = {}

    @staticmethod
    def register_nd_option_type(*args):
        def _register_nd_option_type(cls):
            nd_router_solicit._ND_OPTION_TYPES[cls.option_type()] = cls
            return cls
        return _register_nd_option_type(args[0])

    def __init__(self, res=0, option=None):
        self.res = res
        self.option = option

    @classmethod
    def parser(cls, buf, offset):
        (res, ) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN
        option = None
        if len(buf) > offset:
            (type_, ) = struct.unpack_from('!B', buf, offset)
            cls_ = cls._ND_OPTION_TYPES.get(type_)
            if cls_ is not None:
                option = cls_.parser(buf, offset)
            else:
                option = buf[offset:]
        msg = cls(res, option)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(
            nd_router_solicit._PACK_STR, self.res))
        if self.option is not None:
            if isinstance(self.option, nd_option):
                hdr.extend(self.option.serialize())
            else:
                hdr.extend(self.option)
        return str(hdr)

    def __len__(self):
        length = self._MIN_LEN
        if self.option is not None:
            length += len(self.option)
        return length


@icmpv6.register_icmpv6_type(ND_ROUTER_ADVERT)
class nd_router_advert(stringify.StringifyMixin):
    """ICMPv6 sub encoder/decoder class for Router Advertisement messages.
    (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.icmpv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{35em}|

    ============== ====================
    Attribute      Description
    ============== ====================
    ch_l           Cur Hop Limit.
    res            M,O Flags for Router Advertisement.
    rou_l          Router Lifetime.
    rea_t          Reachable Time.
    ret_t          Retrans Timer.
    options        List of a derived object of \
                   ryu.lib.packet.icmpv6.nd_option or a bytearray. \
                   None if no options.
    ============== ====================
    """

    _PACK_STR = '!BBHII'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _ND_OPTION_TYPES = {}

    @staticmethod
    def register_nd_option_type(*args):
        def _register_nd_option_type(cls):
            nd_router_advert._ND_OPTION_TYPES[cls.option_type()] = cls
            return cls
        return _register_nd_option_type(args[0])

    def __init__(self, ch_l=0, res=0, rou_l=0, rea_t=0, ret_t=0, options=None):
        self.ch_l = ch_l
        self.res = res
        self.rou_l = rou_l
        self.rea_t = rea_t
        self.ret_t = ret_t
        options = options or []
        assert isinstance(options, list)
        self.options = options

    @classmethod
    def parser(cls, buf, offset):
        (ch_l, res, rou_l, rea_t, ret_t
         ) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN
        options = []
        while len(buf) > offset:
            (type_, length) = struct.unpack_from('!BB', buf, offset)
            cls_ = cls._ND_OPTION_TYPES.get(type_)
            if cls_ is not None:
                option = cls_.parser(buf, offset)
            else:
                option = buf[offset:offset + (length * 8 - 2)]
            options.append(option)
            offset += len(option)
        msg = cls(ch_l, res >> 6, rou_l, rea_t, ret_t, options)
        return msg

    def serialize(self):
        res = self.res << 6
        hdr = bytearray(struct.pack(
            nd_router_advert._PACK_STR, self.ch_l, res, self.rou_l,
            self.rea_t, self.ret_t))
        for option in self.options:
            if isinstance(option, nd_option):
                hdr.extend(option.serialize())
            else:
                hdr.extend(option)
        return str(hdr)

    def __len__(self):
        length = self._MIN_LEN
        for option in self.options:
            length += len(option)
        return length


class nd_option(stringify.StringifyMixin):

    __metaclass__ = abc.ABCMeta

    @classmethod
    @abc.abstractmethod
    def option_type(cls):
        pass

    @abc.abstractmethod
    def __init__(self, _type, length):
        self._type = _type
        self.length = length

    @classmethod
    @abc.abstractmethod
    def parser(cls, buf):
        pass

    @abc.abstractmethod
    def serialize(self):
        pass

    def __len__(self):
        return self._MIN_LEN


class nd_option_la(nd_option):

    _PACK_STR = '!BB6s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @abc.abstractmethod
    def __init__(self, length, hw_src, data):
        super(nd_option_la, self).__init__(self.option_type(), length)
        self.hw_src = hw_src
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (_, length, hw_src) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(length, addrconv.mac.bin_to_text(hw_src))
        offset += cls._MIN_LEN
        if len(buf) > offset:
            msg.data = buf[offset:]

        return msg

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.option_type(), self.length,
            addrconv.mac.text_to_bin(self.hw_src)))
        if self.data is not None:
            buf.extend(self.data)
        mod = len(buf) % 8
        if mod:
            buf.extend(bytearray(8 - mod))
        if 0 == self.length:
            self.length = len(buf) / 8
            struct.pack_into('!B', buf, 1, self.length)
        return str(buf)

    def __len__(self):
        length = self._MIN_LEN
        if self.data is not None:
            length += len(self.data)
        return length


@nd_neighbor.register_nd_option_type
@nd_router_solicit.register_nd_option_type
@nd_router_advert.register_nd_option_type
class nd_option_sla(nd_option_la):
    """ICMPv6 sub encoder/decoder class for Neighbor discovery
    Source Link-Layer Address Option. (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.nd_neighbor,
    ryu.lib.packet.icmpv6.nd_router_solicit or
    ryu.lib.packet.icmpv6.nd_router_advert.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{35em}|

    ============== ====================
    Attribute      Description
    ============== ====================
    length         length of the option. \
                   (0 means automatically-calculate when encoding)
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

    @classmethod
    def option_type(cls):
        return ND_OPTION_SLA

    def __init__(self, length=0, hw_src='00:00:00:00:00:00', data=None):
        super(nd_option_sla, self).__init__(length, hw_src, data)


@nd_neighbor.register_nd_option_type
class nd_option_tla(nd_option_la):
    """ICMPv6 sub encoder/decoder class for Neighbor discovery
    Target Link-Layer Address Option. (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.nd_neighbor.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{35em}|

    ============== ====================
    Attribute      Description
    ============== ====================
    length         length of the option. \
                   (0 means automatically-calculate when encoding)
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

    @classmethod
    def option_type(cls):
        return ND_OPTION_TLA

    def __init__(self, length=0, hw_src='00:00:00:00:00:00', data=None):
        super(nd_option_tla, self).__init__(length, hw_src, data)


@nd_router_advert.register_nd_option_type
class nd_option_pi(nd_option):
    """ICMPv6 sub encoder/decoder class for Neighbor discovery
    Prefix Information Option. (RFC 4861)

    This is used with ryu.lib.packet.icmpv6.nd_router_advert.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{35em}|

    ============== ====================
    Attribute      Description
    ============== ====================
    length         length of the option. \
                   (0 means automatically-calculate when encoding)
    pl             Prefix Length.
    res1           L,A,R\* Flags for Prefix Information.
    val_l          Valid Lifetime.
    pre_l          Preferred Lifetime.
    res2           This field is unused. It MUST be initialized to zero.
    prefix         An IP address or a prefix of an IP address.
    ============== ====================

    \*R flag is defined in (RFC 3775)
    """

    _PACK_STR = '!BBBBIII16s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def option_type(cls):
        return ND_OPTION_PI

    def __init__(self, length=0, pl=0, res1=0, val_l=0, pre_l=0, res2=0,
                 prefix='::'):
        super(nd_option_pi, self).__init__(self.option_type(), length)
        self.pl = pl
        self.res1 = res1
        self.val_l = val_l
        self.pre_l = pre_l
        self.res2 = res2
        self.prefix = prefix

    @classmethod
    def parser(cls, buf, offset):
        (_, length, pl, res1, val_l, pre_l, res2, prefix
         ) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(length, pl, res1 >> 5, val_l, pre_l, res2,
                  addrconv.ipv6.bin_to_text(prefix))

        return msg

    def serialize(self):
        res1 = self.res1 << 5
        hdr = bytearray(struct.pack(
            self._PACK_STR, self.option_type(), self.length, self.pl,
            res1, self.val_l, self.pre_l, self.res2,
            addrconv.ipv6.text_to_bin(self.prefix)))
        if 0 == self.length:
            self.length = len(hdr) / 8
            struct.pack_into('!B', hdr, 1, self.length)
        return str(hdr)


@icmpv6.register_icmpv6_type(ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST)
class echo(stringify.StringifyMixin):
    """ICMPv6 sub encoder/decoder class for Echo Request and Echo Reply
    messages.

    This is used with ryu.lib.packet.icmpv6.icmpv6 for
    ICMPv6 Echo Request and Echo Reply messages.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

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

    def __init__(self, id_=0, seq=0, data=None):
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

    def __len__(self):
        length = self._MIN_LEN
        if self.data is not None:
            length += len(self.data)
        return length
