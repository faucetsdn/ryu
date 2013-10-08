# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
RFC 4271 BGP-4
"""

# todo
# - notify data
# - notify subcode constants
# - RFC 1997 BGP Communities Attribute
# - RFC 2918 Route Refresh Capability for BGP-4
# - RFC 3107 Carrying Label Information in BGP-4
# - RFC 4360 BGP Extended Communities Attribute
# - RFC 4364 BGP/MPLS IP Virtual Private Networks (VPNs)
# - RFC 4486 Subcodes for BGP Cease Notification Message
# - RFC 4760 Multiprotocol Extensions for BGP-4

import struct

from ryu.ofproto.ofproto_parser import msg_pack_into
from ryu.lib.stringify import StringifyMixin
from ryu.lib.packet import packet_base
from ryu.lib.packet import stream_parser
from ryu.lib import addrconv


BGP_MSG_OPEN = 1
BGP_MSG_UPDATE = 2
BGP_MSG_NOTIFICATION = 3
BGP_MSG_KEEPALIVE = 4
BGP_MSG_ROUTE_REFRESH = 5  # RFC 2918

# RFC 4271 4.5.
BGP_ERROR_MESSAGE_HEADER_ERROR = 1
BGP_ERROR_OPEN_MESSAGE_ERROR = 2
BGP_ERROR_UPDATE_MESSAGE_ERROR = 3
BGP_ERROR_HOLD_TIMER_EXPIRED = 4
BGP_ERROR_FSM_ERROR = 5
BGP_ERROR_CEASE = 6

_VERSION = 4
_MARKER = 16 * '\xff'

BGP_OPT_CAPABILITY = 2  # RFC 5492

BGP_CAP_MULTI_PROTOCOL = 1  # RFC 4760
BGP_CAP_ROUTE_REFRESH = 2  # RFC 2918
BGP_CAP_FOUR_OCTET_AS_NUMBER = 65  # RFC 4893

BGP_ATTR_FLAG_OPTIONAL = 1 << 7
BGP_ATTR_FLAG_TRANSITIVE = 1 << 6
BGP_ATTR_FLAG_PARTIAL = 1 << 5
BGP_ATTR_FLAG_EXTENDED_LENGTH = 1 << 4

BGP_ATTR_TYPE_ORIGIN = 1  # 0,1,2 (1 byte)
BGP_ATTR_TYPE_AS_PATH = 2  # a list of AS_SET/AS_SEQUENCE  eg. {1 2 3} 4 5
BGP_ATTR_TYPE_NEXT_HOP = 3  # an IPv4 address
BGP_ATTR_TYPE_MULTI_EXIT_DISC = 4  # uint32 metric
BGP_ATTR_TYPE_LOCAL_PREF = 5  # uint32
BGP_ATTR_TYPE_ATOMIC_AGGREGATE = 6  # 0 bytes
BGP_ATTR_TYPE_AGGREGATOR = 7  # AS number and IPv4 address
BGP_ATTR_TYPE_MP_REACH_NLRI = 14  # RFC 4760
BGP_ATTR_TYPE_MP_UNREACH_NLRI = 15  # RFC 4760
BGP_ATTR_TYPE_AS4_PATH = 17  # RFC 4893
BGP_ATTR_TYPE_AS4_AGGREGATOR = 18  # RFC 4893

AS_TRANS = 23456  # RFC 4893


def pad(bin, len_):
    assert len(bin) <= len_
    return bin + (len_ - len(bin)) * '\0'


class _IPAddrPrefix(StringifyMixin):
    _PACK_STR = '!B'  # length

    def __init__(self, length, ip_addr):
        self.length = length
        self.ip_addr = ip_addr

    @classmethod
    def parser(cls, buf):
        (length, ) = struct.unpack_from(cls._PACK_STR, buffer(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        byte_length = (length + 7) / 8
        ip_addr = addrconv.ipv4.bin_to_text(pad(rest[:byte_length], 4))
        rest = rest[byte_length:]
        return cls(length=length, ip_addr=ip_addr), rest

    def serialize(self):
        # fixup
        byte_length = (self.length + 7) / 8
        bin_ip_addr = addrconv.ipv4.text_to_bin(self.ip_addr)
        if (self.length % 8) == 0:
            bin_ip_addr = bin_ip_addr[:byte_length]
        else:
            # clear trailing bits in the last octet.
            # rfc doesn't require this.
            mask = 0xff00 >> (self.length % 8)
            last_byte = chr(ord(bin_ip_addr[byte_length - 1]) & mask)
            bin_ip_addr = bin_ip_addr[:byte_length - 1] + last_byte
        self.ip_addr = addrconv.ipv4.bin_to_text(pad(bin_ip_addr, 4))

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.length)
        return buf + bytes(bin_ip_addr)


class _Value(object):
    _VALUE_PACK_STR = None

    @classmethod
    def parse_value(cls, buf):
        (value,) = struct.unpack_from(cls._VALUE_PACK_STR, buffer(buf))
        return {
            'value': value
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, self.value)
        return buf


class _TypeDisp(object):
    _TYPES = {}
    _REV_TYPES = None
    _UNKNOWN_TYPE = None

    @classmethod
    def register_unknown_type(cls):
        def _register_type(subcls):
            cls._UNKNOWN_TYPE = subcls
            return subcls
        return _register_type

    @classmethod
    def register_type(cls, type_):
        cls._TYPES = cls._TYPES.copy()

        def _register_type(subcls):
            cls._TYPES[type_] = subcls
            cls._REV_TYPES = None
            return subcls
        return _register_type

    @classmethod
    def _lookup_type(cls, type_):
        try:
            return cls._TYPES[type_]
        except KeyError:
            return cls._UNKNOWN_TYPE

    @classmethod
    def _rev_lookup_type(cls, targ_cls):
        if cls._REV_TYPES is None:
            rev = dict((v, k) for k, v in cls._TYPES.iteritems())
            cls._REV_TYPES = rev
        return cls._REV_TYPES[targ_cls]


class _OptParam(StringifyMixin, _TypeDisp, _Value):
    _PACK_STR = '!BB'  # type, length

    def __init__(self, type_, value=None, length=None):
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.type = type_
        self.length = length
        if not value is None:
            self.value = value

    @classmethod
    def parser(cls, buf):
        (type_, length) = struct.unpack_from(cls._PACK_STR, buffer(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        value = bytes(rest[:length])
        rest = rest[length:]
        subcls = cls._lookup_type(type_)
        kwargs = subcls.parse_value(value)
        return subcls(type_=type_, length=length, **kwargs), rest

    def serialize(self):
        # fixup
        value = self.serialize_value()
        self.length = len(value)

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type, self.length)
        return buf + value


@_OptParam.register_unknown_type()
class BGPOptParamUnknown(_OptParam):
    @classmethod
    def parse_value(cls, buf):
        return {
            'value': buf
        }

    def serialize_value(self):
        return self.value


@_OptParam.register_type(BGP_OPT_CAPABILITY)
class BGPOptParamCapability(_OptParam):
    _CAP_HDR_PACK_STR = '!BB'

    def __init__(self, cap_code, cap_value, cap_length=None,
                 type_=None, length=None):
        super(BGPOptParamCapability, self).__init__(type_=type_, length=length)
        self.cap_code = cap_code
        self.cap_length = cap_length
        self.cap_value = cap_value

    @classmethod
    def parse_value(cls, buf):
        (code, length) = struct.unpack_from(cls._CAP_HDR_PACK_STR, buffer(buf))
        value = buf[struct.calcsize(cls._CAP_HDR_PACK_STR):]
        assert len(value) == length
        kwargs = {
            'cap_code': code,
            'cap_length': length,
            'cap_value': value,
        }
        return kwargs

    def serialize_value(self):
        # fixup
        cap_value = self.cap_value
        self.cap_length = len(cap_value)

        buf = bytearray()
        msg_pack_into(self._CAP_HDR_PACK_STR, buf, 0, self.cap_code,
                      self.cap_length)
        return buf + cap_value


class BGPWithdrawnRoute(_IPAddrPrefix):
    pass


class _PathAttribute(StringifyMixin, _TypeDisp, _Value):
    _PACK_STR = '!BB'  # flags, type
    _PACK_STR_LEN = '!B'  # length
    _PACK_STR_EXT_LEN = '!H'  # length w/ BGP_ATTR_FLAG_EXTENDED_LENGTH
    _ATTR_FLAGS = None

    def __init__(self, value=None, flags=0, type_=None, length=None):
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.flags = flags
        self.type = type_
        self.length = length
        if not value is None:
            self.value = value

    @classmethod
    def parser(cls, buf):
        (flags, type_) = struct.unpack_from(cls._PACK_STR, buffer(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        if (flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) != 0:
            len_pack_str = cls._PACK_STR_EXT_LEN
        else:
            len_pack_str = cls._PACK_STR_LEN
        (length,) = struct.unpack_from(len_pack_str, buffer(rest))
        rest = rest[struct.calcsize(len_pack_str):]
        value = bytes(rest[:length])
        rest = rest[length:]
        subcls = cls._lookup_type(type_)
        return subcls(flags=flags, type_=type_, length=length,
                      **subcls.parse_value(value)), rest

    def serialize(self):
        # fixup
        if not self._ATTR_FLAGS is None:
            self.flags = self.flags \
                & ~(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE) \
                | self._ATTR_FLAGS
        value = self.serialize_value()
        self.length = len(value)
        if self.length > 255:
            self.flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH
            len_pack_str = self._PACK_STR_EXT_LEN
        else:
            self.flags &= ~BGP_ATTR_FLAG_EXTENDED_LENGTH
            len_pack_str = self._PACK_STR_LEN

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.flags, self.type)
        msg_pack_into(len_pack_str, buf, len(buf), self.length)
        return buf + value


@_PathAttribute.register_unknown_type()
class BGPPathAttributeUnknown(_PathAttribute):
    @classmethod
    def parse_value(cls, buf):
        return {
            'value': buf
        }

    def serialize_value(self):
        return self.value


class _PathAttributeUint32(_PathAttribute):
    _VALUE_PACK_STR = '!I'


@_PathAttribute.register_type(BGP_ATTR_TYPE_ORIGIN)
class BGPPathAttributeOrigin(_PathAttribute):
    _VALUE_PACK_STR = '!B'
    _ATTR_FLAGS = BGP_ATTR_FLAG_TRANSITIVE


class _BGPPathAttributeAsPathCommon(_PathAttribute):
    _AS_SET = 1
    _AS_SEQUENCE = 2
    _SEG_HDR_PACK_STR = '!BB'
    _AS_PACK_STR = None
    _ATTR_FLAGS = BGP_ATTR_FLAG_TRANSITIVE

    @classmethod
    def parse_value(cls, buf):
        result = []
        while buf:
            (type_, num_as) = struct.unpack_from(cls._SEG_HDR_PACK_STR,
                                                 buffer(buf))
            buf = buf[struct.calcsize(cls._SEG_HDR_PACK_STR):]
            l = []
            for i in xrange(0, num_as):
                (as_number,) = struct.unpack_from(cls._AS_PACK_STR,
                                                  buffer(buf))
                buf = buf[struct.calcsize(cls._AS_PACK_STR):]
                l.append(as_number)
            if type_ == cls._AS_SET:
                result.append(set(l))
            elif type_ == cls._AS_SEQUENCE:
                result.append(l)
            else:
                assert(0)  # protocol error
        return {
            'value': result
        }

    def serialize_value(self):
        buf = bytearray()
        offset = 0
        for e in self.value:
            if isinstance(e, set):
                type_ = self._AS_SET
            elif isinstance(e, list):
                type_ = self._AS_SEQUENCE
            l = list(e)
            num_as = len(l)
            msg_pack_into(self._SEG_HDR_PACK_STR, buf, offset, type_, num_as)
            offset += struct.calcsize(self._SEG_HDR_PACK_STR)
            for i in l:
                msg_pack_into(self._AS_PACK_STR, buf, offset, i)
                offset += struct.calcsize(self._AS_PACK_STR)
        return buf


@_PathAttribute.register_type(BGP_ATTR_TYPE_AS_PATH)
class BGPPathAttributeAsPath(_BGPPathAttributeAsPathCommon):
    # XXX currently this implementation assumes 16 bit AS numbers.
    # depends on negotiated capability, AS numbers can be 32 bit.
    # while wireshark seems to attempt auto-detect, it seems that
    # there's no way to detect it reliably.  for example, the
    # following byte sequence can be interpreted in two ways.
    #   01 02 99 88 77 66 02 01 55 44
    #   AS_SET num=2 9988 7766 AS_SEQUENCE num=1 5544
    #   AS_SET num=2 99887766 02015544
    _AS_PACK_STR = '!H'


@_PathAttribute.register_type(BGP_ATTR_TYPE_AS4_PATH)
class BGPPathAttributeAs4Path(_BGPPathAttributeAsPathCommon):
    _AS_PACK_STR = '!I'


@_PathAttribute.register_type(BGP_ATTR_TYPE_NEXT_HOP)
class BGPPathAttributeNextHop(_PathAttribute):
    _VALUE_PACK_STR = '!4s'
    _ATTR_FLAGS = BGP_ATTR_FLAG_TRANSITIVE

    @classmethod
    def parse_value(cls, buf):
        (ip_addr,) = struct.unpack_from(cls._VALUE_PACK_STR, buffer(buf))
        return {
            'value': addrconv.ipv4.bin_to_text(ip_addr),
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0,
                      addrconv.ipv4.text_to_bin(self.value))
        return buf


@_PathAttribute.register_type(BGP_ATTR_TYPE_MULTI_EXIT_DISC)
class BGPPathAttributeMultiExitDisc(_PathAttributeUint32):
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL


@_PathAttribute.register_type(BGP_ATTR_TYPE_LOCAL_PREF)
class BGPPathAttributeLocalPref(_PathAttributeUint32):
    _ATTR_FLAGS = BGP_ATTR_FLAG_TRANSITIVE


@_PathAttribute.register_type(BGP_ATTR_TYPE_ATOMIC_AGGREGATE)
class BGPPathAttributeAtomicAggregate(_PathAttribute):
    _ATTR_FLAGS = BGP_ATTR_FLAG_TRANSITIVE

    @classmethod
    def parse_value(cls, buf):
        return {}

    def serialize_value(self):
        return ''


class _BGPPathAttributeAggregatorCommon(_PathAttribute):
    _VALUE_PACK_STR = None
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE

    def __init__(self, as_number, ip_addr, flags=0, type_=None, length=None):
        super(_BGPPathAttributeAggregatorCommon, self).__init__(flags=flags,
                                                                type_=type_,
                                                                length=length)
        self.as_number = as_number
        self.ip_addr = ip_addr

    @classmethod
    def parse_value(cls, buf):
        (as_number, ip_addr) = struct.unpack_from(cls._VALUE_PACK_STR,
                                                  buffer(buf))
        return {
            'as_number': as_number,
            'ip_addr': addrconv.ipv4.bin_to_text(ip_addr),
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, self.as_number,
                      addrconv.ipv4.text_to_bin(self.ip_addr))
        return buf


@_PathAttribute.register_type(BGP_ATTR_TYPE_AGGREGATOR)
class BGPPathAttributeAggregator(_BGPPathAttributeAggregatorCommon):
    # XXX currently this implementation assumes 16 bit AS numbers.
    _VALUE_PACK_STR = '!H4s'


@_PathAttribute.register_type(BGP_ATTR_TYPE_AS4_AGGREGATOR)
class BGPPathAttributeAs4Aggregator(_BGPPathAttributeAggregatorCommon):
    _VALUE_PACK_STR = '!I4s'


class BGPNLRI(_IPAddrPrefix):
    pass


class BGPMessage(packet_base.PacketBase, _TypeDisp):
    """Base class for BGP-4 messages.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the correspondig args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    marker                     Marker field.  Ignored when encoding.
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BGP\_MSG\_ constants.
    ========================== ===============================================
    """

    _HDR_PACK_STR = '!16sHB'  # marker, len, type
    _HDR_LEN = struct.calcsize(_HDR_PACK_STR)

    def __init__(self, type_, len_=None, marker=None):
        if marker is None:
            self.marker = _MARKER
        else:
            self.marker = marker
        self.len = len_
        self.type = type_

    @classmethod
    def parser(cls, buf):
        if len(buf) < cls._HDR_LEN:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), cls._HDR_LEN))
        (marker, len_, type_) = struct.unpack_from(cls._HDR_PACK_STR,
                                                   buffer(buf))
        msglen = len_
        if len(buf) < msglen:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), msglen))
        binmsg = buf[cls._HDR_LEN:msglen]
        rest = buf[msglen:]
        subcls = cls._lookup_type(type_)
        kwargs = subcls.parser(binmsg)
        return subcls(marker=marker, len_=len_, type_=type_, **kwargs), rest

    def serialize(self):
        # fixup
        self.marker = _MARKER
        tail = self.serialize_tail()
        self.len = self._HDR_LEN + len(tail)

        hdr = bytearray(struct.pack(self._HDR_PACK_STR, self.marker,
                                    self.len, self.type))
        return hdr + tail

    def __len__(self):
        # XXX destructive
        buf = self.serialize()
        return len(buf)


@BGPMessage.register_type(BGP_MSG_OPEN)
class BGPOpen(BGPMessage):
    """BGP-4 OPEN Message encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the correspondig args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    marker                     Marker field.  Ignored when encoding.
    len                        Length field.  Ignored when encoding.
    type                       Type field.  The default is BGP_MSG_OPEN.
    version                    Version field.  The default is 4.
    my_as                      My Autonomous System field.  2 octet unsigned
                               integer.
    hold_time                  Hold Time field.  2 octet unsigned integer.
                               The default is 0.
    bgp_identifier             BGP Identifier field.  An IPv4 address.
                               For example, '192.0.2.1'
    opt_param_len              Optional Parameters Length field.
                               Ignored when encoding.
    opt_param                  Optional Parameters field.  A list of
                               BGPOptParam instances.  The default is [].
    ========================== ===============================================
    """

    _PACK_STR = '!BHH4sB'
    _MIN_LEN = BGPMessage._HDR_LEN + struct.calcsize(_PACK_STR)

    def __init__(self, my_as, bgp_identifier, type_=BGP_MSG_OPEN,
                 opt_param_len=0, opt_param=[],
                 version=_VERSION, hold_time=0, len_=None, marker=None):
        super(BGPOpen, self).__init__(marker=marker, len_=len_, type_=type_)
        self.version = version
        self.my_as = my_as
        self.bgp_identifier = bgp_identifier
        self.hold_time = hold_time
        self.opt_param_len = opt_param_len
        self.opt_param = opt_param

    @classmethod
    def parser(cls, buf):
        (version, my_as, hold_time,
         bgp_identifier, opt_param_len) = struct.unpack_from(cls._PACK_STR,
                                                             buffer(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        binopts = rest[:opt_param_len]
        opt_param = []
        while binopts:
            opt, binopts = _OptParam.parser(binopts)
            opt_param.append(opt)
        return {
            "version": version,
            "my_as": my_as,
            "hold_time": hold_time,
            "bgp_identifier": addrconv.ipv4.bin_to_text(bgp_identifier),
            "opt_param_len": opt_param_len,
            "opt_param": opt_param,
        }

    def serialize_tail(self):
        # fixup
        self.version = _VERSION
        binopts = bytearray()
        for opt in self.opt_param:
            binopts += opt.serialize()
        self.opt_param_len = len(binopts)

        msg = bytearray(struct.pack(self._PACK_STR,
                                    self.version,
                                    self.my_as,
                                    self.hold_time,
                                    addrconv.ipv4.text_to_bin(
                                        self.bgp_identifier),
                                    self.opt_param_len))
        msg += binopts
        return msg


@BGPMessage.register_type(BGP_MSG_UPDATE)
class BGPUpdate(BGPMessage):
    """BGP-4 UPDATE Message encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the correspondig args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    marker                     Marker field.  Ignored when encoding.
    len                        Length field.  Ignored when encoding.
    type                       Type field.  The default is BGP_MSG_UPDATE.
    withdrawn_routes_len       Withdrawn Routes Length field.
                               Ignored when encoding.
    withdrawn_routes           Withdrawn Routes field.  A list of
                               BGPWithdrawnRoute instances.
                               The default is [].
    total_path_attribute_len   Total Path Attribute Length field.
                               Ignored when encoding.
    path_attributes            Path Attributes field.  A list of
                               BGPPathAttribute instances.
                               The default is [].
    nlri                       Network Layer Reachability Information field.
                               A list of BGPNLRI instances.
                               The default is [].
    ========================== ===============================================
    """

    def __init__(self, type_=BGP_MSG_UPDATE,
                 withdrawn_routes_len=None,
                 withdrawn_routes=[],
                 total_path_attribute_len=None,
                 path_attributes=[],
                 nlri=[],
                 len_=None, marker=None):
        super(BGPUpdate, self).__init__(marker=marker, len_=len_, type_=type_)
        self.withdrawn_routes_len = withdrawn_routes_len
        self.withdrawn_routes = withdrawn_routes
        self.total_path_attribute_len = total_path_attribute_len
        self.path_attributes = path_attributes
        self.nlri = nlri

    @classmethod
    def parser(cls, buf):
        offset = 0
        (withdrawn_routes_len,) = struct.unpack_from('!H', buffer(buf), offset)
        binroutes = buffer(buf[offset + 2:
                               offset + 2 + withdrawn_routes_len])
        offset += 2 + withdrawn_routes_len
        (total_path_attribute_len,) = struct.unpack_from('!H', buffer(buf),
                                                         offset)
        binpathattrs = buffer(buf[offset + 2:
                                  offset + 2 + total_path_attribute_len])
        binnlri = buffer(buf[offset + 2 + total_path_attribute_len:])
        withdrawn_routes = []
        while binroutes:
            r, binroutes = BGPWithdrawnRoute.parser(binroutes)
            withdrawn_routes.append(r)
        path_attributes = []
        while binpathattrs:
            pa, binpathattrs = _PathAttribute.parser(binpathattrs)
            path_attributes.append(pa)
        offset += 2 + total_path_attribute_len
        nlri = []
        while binnlri:
            n, binnlri = BGPNLRI.parser(binnlri)
            nlri.append(n)
        return {
            "withdrawn_routes_len": withdrawn_routes_len,
            "withdrawn_routes": withdrawn_routes,
            "total_path_attribute_len": total_path_attribute_len,
            "path_attributes": path_attributes,
            "nlri": nlri,
        }

    def serialize_tail(self):
        # fixup
        binroutes = bytearray()
        for r in self.withdrawn_routes:
            binroutes += r.serialize()
        self.withdrawn_routes_len = len(binroutes)
        binpathattrs = bytearray()
        for pa in self.path_attributes:
            binpathattrs += pa.serialize()
        self.total_path_attribute_len = len(binpathattrs)
        binnlri = bytearray()
        for n in self.nlri:
            binnlri += n.serialize()

        msg = bytearray()
        offset = 0
        msg_pack_into('!H', msg, offset, self.withdrawn_routes_len)
        msg += binroutes
        offset += 2 + self.withdrawn_routes_len
        msg_pack_into('!H', msg, offset, self.total_path_attribute_len)
        msg += binpathattrs
        offset += 2 + self.total_path_attribute_len
        msg += binnlri
        return msg


@BGPMessage.register_type(BGP_MSG_KEEPALIVE)
class BGPKeepAlive(BGPMessage):
    """BGP-4 KEEPALIVE Message encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the correspondig args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    marker                     Marker field.  Ignored when encoding.
    len                        Length field.  Ignored when encoding.
    type                       Type field.  The default is BGP_MSG_KEEPALIVE.
    ========================== ===============================================
    """

    _MIN_LEN = BGPMessage._HDR_LEN

    def __init__(self, type_=BGP_MSG_KEEPALIVE, len_=None, marker=None):
        super(BGPKeepAlive, self).__init__(marker=marker, len_=len_,
                                           type_=type_)

    @classmethod
    def parser(cls, buf):
        return {}

    def serialize_tail(self):
        return bytearray()


@BGPMessage.register_type(BGP_MSG_NOTIFICATION)
class BGPNotification(BGPMessage):
    """BGP-4 NOTIFICATION Message encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the correspondig args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    marker                     Marker field.  Ignored when encoding.
    len                        Length field.  Ignored when encoding.
    type                       Type field.  The default is
                               BGP_MSG_NOTIFICATION.
    error_code                 Error code field.
    error_subcode              Error subcode field.
    data                       Data field.  The default is ''.
    ========================== ===============================================
    """

    _PACK_STR = '!BB'
    _MIN_LEN = BGPMessage._HDR_LEN + struct.calcsize(_PACK_STR)

    def __init__(self,
                 error_code,
                 error_subcode,
                 data='',
                 type_=BGP_MSG_NOTIFICATION, len_=None, marker=None):
        super(BGPNotification, self).__init__(marker=marker, len_=len_,
                                              type_=type_)
        self.error_code = error_code
        self.error_subcode = error_subcode
        self.data = data

    @classmethod
    def parser(cls, buf):
        (error_code, error_subcode,) = struct.unpack_from(cls._PACK_STR,
                                                          buffer(buf))
        data = bytes(buf[2:])
        return {
            "error_code": error_code,
            "error_subcode": error_subcode,
            "data": data,
        }

    def serialize_tail(self):
        msg = bytearray(struct.pack(self._PACK_STR, self.error_code,
                                    self.error_subcode))
        msg += self.data
        return msg


class StreamParser(stream_parser.StreamParser):
    """Streaming parser for BGP-4 messages.

    This is a subclass of ryu.lib.packet.stream_parser.StreamParser.
    Its parse method returns a list of BGPMessage subclass instances.
    """

    def try_parse(self, data):
        return BGPMessage.parser(data)
