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
# - streaming parser
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

BGP_OPT_CAPABILITY = 2  # RFC 3392

BGP_ATTR_FLAG_OPTIONAL = 1 << 7
BGP_ATTR_FLAG_TRANSITIVE = 1 << 6
BGP_ATTR_FLAG_PARTIAL = 1 << 5
BGP_ATTR_FLAG_EXTENDED_LENGTH = 1 << 4

BGP_ATTR_TYPE_ORIGIN = 1
BGP_ATTR_TYPE_AS_PATH = 2
BGP_ATTR_TYPE_NEXT_HOP = 3
BGP_ATTR_TYPE_MULTI_EXIT_DISC = 4
BGP_ATTR_TYPE_LOCAL_PREF = 5
BGP_ATTR_TYPE_ATOMIC_AGGREGATE = 6
BGP_ATTR_TYPE_AGGREGATOR = 7
BGP_ATTR_TYPE_MP_REACH_NLRI = 14  # RFC 4760
BGP_ATTR_TYPE_MP_UNREACH_NLRI = 15  # RFC 4760


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


class BGPOptParam(StringifyMixin):
    _PACK_STR = '!BB'  # type, length

    def __init__(self, type_, value, length=None):
        self.type = type_
        self.length = length
        self.value = value

    @classmethod
    def parser(cls, buf):
        (type_, length) = struct.unpack_from(cls._PACK_STR, buffer(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        value = bytes(rest[:length])
        rest = rest[length:]
        return cls(type_=type_, length=length, value=value), rest

    def serialize(self):
        # fixup
        self.length = len(self.value)

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type, self.length)
        return buf + bytes(self.value)


class BGPWithdrawnRoute(_IPAddrPrefix):
    pass


class BGPPathAttribute(StringifyMixin):
    _PACK_STR = '!BB'  # flags, type
    _PACK_STR_LEN = '!B'  # length
    _PACK_STR_EXT_LEN = '!H'  # length w/ BGP_ATTR_FLAG_EXTENDED_LENGTH

    def __init__(self, flags, type_, value, length=None):
        self.flags = flags
        self.type = type_
        self.length = length
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
        return cls(flags=flags, type_=type_, length=length, value=value), rest

    def serialize(self):
        # fixup
        self.length = len(self.value)
        if self.length > 255:
            self.flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH
            len_pack_str = self._PACK_STR_EXT_LEN
        else:
            self.flags &= ~BGP_ATTR_FLAG_EXTENDED_LENGTH
            len_pack_str = self._PACK_STR_LEN

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.flags, self.type)
        msg_pack_into(len_pack_str, buf, len(buf), self.length)
        return buf + bytes(self.value)


class BGPNLRI(_IPAddrPrefix):
    pass


class BGPMessage(packet_base.PacketBase):
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
    _TYPES = {}

    @classmethod
    def register_type(cls, type_):
        def _register_type(subcls):
            cls._TYPES[type_] = subcls
            return subcls
        return _register_type

    def __init__(self, type_, len_=None, marker=None):
        if marker is None:
            self.marker = _MARKER
        else:
            self.marker = marker
        self.len = len_
        self.type = type_

    @classmethod
    def parser(cls, buf):
        (marker, len_, type_) = struct.unpack_from(cls._HDR_PACK_STR,
                                                   buffer(buf))
        subcls = cls._TYPES[type_]
        kwargs = subcls.parser(buf[cls._HDR_LEN:])
        return subcls(marker=marker, len_=len_, type_=type_, **kwargs)

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
            opt, binopts = BGPOptParam.parser(binopts)
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
            pa, binpathattrs = BGPPathAttribute.parser(binpathattrs)
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
