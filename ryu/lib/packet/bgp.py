# Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
# - RFC 4364 BGP/MPLS IP Virtual Private Networks (VPNs)

import abc
import six
import struct
import copy
import netaddr
import numbers

try:
    # Python 3
    from functools import reduce
except ImportError:
    # Python 2
    pass

from ryu.lib.stringify import StringifyMixin
from ryu.lib.packet import afi as addr_family
from ryu.lib.packet import safi as subaddr_family
from ryu.lib.packet import packet_base
from ryu.lib.packet import stream_parser
from ryu.lib import addrconv
from ryu.lib.pack_utils import msg_pack_into

BGP_MSG_OPEN = 1
BGP_MSG_UPDATE = 2
BGP_MSG_NOTIFICATION = 3
BGP_MSG_KEEPALIVE = 4
BGP_MSG_ROUTE_REFRESH = 5  # RFC 2918

_VERSION = 4
_MARKER = 16 * b'\xff'

BGP_OPT_CAPABILITY = 2  # RFC 5492

BGP_CAP_MULTIPROTOCOL = 1  # RFC 4760
BGP_CAP_ROUTE_REFRESH = 2  # RFC 2918
BGP_CAP_CARRYING_LABEL_INFO = 4  # RFC 3107
BGP_CAP_GRACEFUL_RESTART = 64  # RFC 4724
BGP_CAP_FOUR_OCTET_AS_NUMBER = 65  # RFC 4893
BGP_CAP_ENHANCED_ROUTE_REFRESH = 70  # https://tools.ietf.org/html/\
# draft-ietf-idr-bgp-enhanced-route-refresh-05
BGP_CAP_ROUTE_REFRESH_CISCO = 128  # in cisco routers, there are two\
# route refresh code: one using the capability code of 128 (old),
# another using the capability code of 2 (new).

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
BGP_ATTR_TYPE_COMMUNITIES = 8  # RFC 1997
BGP_ATTR_TYPE_ORIGINATOR_ID = 9  # RFC 4456
BGP_ATTR_TYPE_CLUSTER_LIST = 10  # RFC 4456
BGP_ATTR_TYPE_MP_REACH_NLRI = 14  # RFC 4760
BGP_ATTR_TYPE_MP_UNREACH_NLRI = 15  # RFC 4760
BGP_ATTR_TYPE_EXTENDED_COMMUNITIES = 16  # RFC 4360
BGP_ATTR_TYPE_AS4_PATH = 17  # RFC 4893
BGP_ATTR_TYPE_AS4_AGGREGATOR = 18  # RFC 4893

BGP_ATTR_ORIGIN_IGP = 0x00
BGP_ATTR_ORIGIN_EGP = 0x01
BGP_ATTR_ORIGIN_INCOMPLETE = 0x02

AS_TRANS = 23456  # RFC 4893

# Well known commmunities  (RFC 1997)
BGP_COMMUNITY_NO_EXPORT = 0xffffff01
BGP_COMMUNITY_NO_ADVERTISE = 0xffffff02
BGP_COMMUNITY_NO_EXPORT_SUBCONFED = 0xffffff03

# RFC 4360
# The low-order octet of Type field (subtype)
BGP_EXTENDED_COMMUNITY_ROUTE_TARGET = 0x02
BGP_EXTENDED_COMMUNITY_ROUTE_ORIGIN = 0x03

# NOTIFICATION Error Code and SubCode
# Note: 0 is a valid SubCode.  (Unspecific)

# NOTIFICATION Error Code  RFC 4271 4.5.
BGP_ERROR_MESSAGE_HEADER_ERROR = 1
BGP_ERROR_OPEN_MESSAGE_ERROR = 2
BGP_ERROR_UPDATE_MESSAGE_ERROR = 3
BGP_ERROR_HOLD_TIMER_EXPIRED = 4
BGP_ERROR_FSM_ERROR = 5
BGP_ERROR_CEASE = 6

# NOTIFICATION Error Subcode for BGP_ERROR_MESSAGE_HEADER_ERROR
BGP_ERROR_SUB_CONNECTION_NOT_SYNCHRONIZED = 1
BGP_ERROR_SUB_BAD_MESSAGE_LENGTH = 2  # Data: the erroneous Length field
BGP_ERROR_SUB_BAD_MESSAGE_TYPE = 3  # Data: the erroneous Type field

# NOTIFICATION Error Subcode for BGP_ERROR_OPEN_MESSAGE_ERROR
BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER = 1  # Data: 2 octet version number
BGP_ERROR_SUB_BAD_PEER_AS = 2
BGP_ERROR_SUB_BAD_BGP_IDENTIFIER = 3
BGP_ERROR_SUB_UNSUPPORTED_OPTIONAL_PARAMETER = 4
BGP_ERROR_SUB_AUTHENTICATION_FAILURE = 5  # deprecated RFC 1771
BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME = 6

# NOTIFICATION Error Subcode for BGP_ERROR_UPDATE_MESSAGE_ERROR
BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST = 1
BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE = 2  # Data: type of the attr
BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE = 3  # Data: ditto
BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR = 4  # Data: the attr (type, len, value)
BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR = 5  # Data: ditto
BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE = 6  # Data: ditto
BGP_ERROR_SUB_ROUTING_LOOP = 7  # deprecated RFC 1771 AS Routing Loop
BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE = 8  # Data: ditto
BGP_ERROR_SUB_OPTIONAL_ATTRIBUTE_ERROR = 9  # Data: ditto
BGP_ERROR_SUB_INVALID_NETWORK_FIELD = 10
BGP_ERROR_SUB_MALFORMED_AS_PATH = 11

# NOTIFICATION Error Subcode for BGP_ERROR_HOLD_TIMER_EXPIRED
BGP_ERROR_SUB_HOLD_TIMER_EXPIRED = 1

# NOTIFICATION Error Subcode for BGP_ERROR_FSM_ERROR
BGP_ERROR_SUB_FSM_ERROR = 1

# NOTIFICATION Error Subcode for BGP_ERROR_CEASE  (RFC 4486)
BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED = 1  # Data: optional
BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN = 2
BGP_ERROR_SUB_PEER_DECONFIGURED = 3
BGP_ERROR_SUB_ADMINISTRATIVE_RESET = 4
BGP_ERROR_SUB_CONNECTION_RESET = 5
BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE = 6
BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION = 7
BGP_ERROR_SUB_OUT_OF_RESOURCES = 8


class _Value(object):
    _VALUE_PACK_STR = None
    _VALUE_FIELDS = ['value']

    @staticmethod
    def do_init(cls, self, kwargs, **extra_kwargs):
        ourfields = {}
        for f in cls._VALUE_FIELDS:
            v = kwargs[f]
            del kwargs[f]
            ourfields[f] = v
        kwargs.update(extra_kwargs)
        super(cls, self).__init__(**kwargs)
        self.__dict__.update(ourfields)

    @classmethod
    def parse_value(cls, buf):
        values = struct.unpack_from(cls._VALUE_PACK_STR, six.binary_type(buf))
        return dict(zip(cls._VALUE_FIELDS, values))

    def serialize_value(self):
        args = []
        for f in self._VALUE_FIELDS:
            args.append(getattr(self, f))
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, *args)
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
            rev = dict((v, k) for k, v in cls._TYPES.items())
            cls._REV_TYPES = rev
        return cls._REV_TYPES[targ_cls]


class BgpExc(Exception):
    """Base bgp exception."""

    CODE = 0
    """BGP error code."""

    SUB_CODE = 0
    """BGP error sub-code."""

    SEND_ERROR = True
    """Flag if set indicates Notification message should be sent to peer."""

    def __init__(self, data=''):
        self.data = data

    def __str__(self):
        return '<%s %r>' % (self.__class__.__name__, self.data)


class BadNotification(BgpExc):
    SEND_ERROR = False

# ============================================================================
# Message Header Errors
# ============================================================================


class NotSync(BgpExc):
    CODE = BGP_ERROR_MESSAGE_HEADER_ERROR
    SUB_CODE = BGP_ERROR_SUB_CONNECTION_NOT_SYNCHRONIZED


class BadLen(BgpExc):
    CODE = BGP_ERROR_MESSAGE_HEADER_ERROR
    SUB_CODE = BGP_ERROR_SUB_BAD_MESSAGE_LENGTH

    def __init__(self, msg_type_code, message_length):
        self.msg_type_code = msg_type_code
        self.length = message_length
        self.data = struct.pack('!H', self.length)

    def __str__(self):
        return '<BadLen %d msgtype=%d>' % (self.length, self.msg_type_code)


class BadMsg(BgpExc):
    """Error to indicate un-recognized message type.

    RFC says: If the Type field of the message header is not recognized, then
    the Error Subcode MUST be set to Bad Message Type.  The Data field MUST
    contain the erroneous Type field.
    """
    CODE = BGP_ERROR_MESSAGE_HEADER_ERROR
    SUB_CODE = BGP_ERROR_SUB_BAD_MESSAGE_TYPE

    def __init__(self, msg_type):
        self.msg_type = msg_type
        self.data = struct.pack('B', msg_type)

    def __str__(self):
        return '<BadMsg %d>' % (self.msg_type,)

# ============================================================================
# OPEN Message Errors
# ============================================================================


class MalformedOptionalParam(BgpExc):
    """If recognized optional parameters are malformed.

    RFC says: If one of the Optional Parameters in the OPEN message is
    recognized, but is malformed, then the Error Subcode MUST be set to 0
    (Unspecific).
    """
    CODE = BGP_ERROR_OPEN_MESSAGE_ERROR
    SUB_CODE = 0


class UnsupportedVersion(BgpExc):
    """Error to indicate unsupport bgp version number.

    RFC says: If the version number in the Version field of the received OPEN
    message is not supported, then the Error Subcode MUST be set to Unsupported
    Version Number.  The Data field is a 2-octet unsigned integer, which
    indicates the largest, locally-supported version number less than the
    version the remote BGP peer bid (as indicated in the received OPEN
    message), or if the smallest, locally-supported version number is greater
    than the version the remote BGP peer bid, then the smallest, locally-
    supported version number.
    """
    CODE = BGP_ERROR_OPEN_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER

    def __init__(self, locally_support_version):
        self.data = struct.pack('H', locally_support_version)


class BadPeerAs(BgpExc):
    """Error to indicate open message has incorrect AS number.

    RFC says: If the Autonomous System field of the OPEN message is
    unacceptable, then the Error Subcode MUST be set to Bad Peer AS.  The
    determination of acceptable Autonomous System numbers is configure peer AS.
    """
    CODE = BGP_ERROR_OPEN_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_BAD_PEER_AS


class BadBgpId(BgpExc):
    """Error to indicate incorrect BGP Identifier.

    RFC says: If the BGP Identifier field of the OPEN message is syntactically
    incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
    Syntactic correctness means that the BGP Identifier field represents a
    valid unicast IP host address.
    """
    CODE = BGP_ERROR_OPEN_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_BAD_BGP_IDENTIFIER


class UnsupportedOptParam(BgpExc):
    """Error to indicate unsupported optional parameters.

    RFC says: If one of the Optional Parameters in the OPEN message is not
    recognized, then the Error Subcode MUST be set to Unsupported Optional
    Parameters.
    """
    CODE = BGP_ERROR_OPEN_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_UNSUPPORTED_OPTIONAL_PARAMETER


class AuthFailure(BgpExc):
    CODE = BGP_ERROR_OPEN_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_AUTHENTICATION_FAILURE


class UnacceptableHoldTime(BgpExc):
    """Error to indicate Unacceptable Hold Time in open message.

    RFC says: If the Hold Time field of the OPEN message is unacceptable, then
    the Error Subcode MUST be set to Unacceptable Hold Time.
    """
    CODE = BGP_ERROR_OPEN_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME

# ============================================================================
# UPDATE message related errors
# ============================================================================


class MalformedAttrList(BgpExc):
    """Error to indicate UPDATE message is malformed.

    RFC says: Error checking of an UPDATE message begins by examining the path
    attributes.  If the Withdrawn Routes Length or Total Attribute Length is
    too large (i.e., if Withdrawn Routes Length + Total Attribute Length + 23
    exceeds the message Length), then the Error Subcode MUST be set to
    Malformed Attribute List.
    """
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST


class UnRegWellKnowAttr(BgpExc):
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE


class MissingWellKnown(BgpExc):
    """Error to indicate missing well-known attribute.

    RFC says: If any of the well-known mandatory attributes are not present,
    then the Error Subcode MUST be set to Missing Well-known Attribute.  The
    Data field MUST contain the Attribute Type Code of the missing, well-known
    attribute.
    """
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE

    def __init__(self, pattr_type_code):
        self.pattr_type_code = pattr_type_code
        self.data = struct.pack('B', pattr_type_code)


class AttrFlagError(BgpExc):
    """Error to indicate recognized path attributes have incorrect flags.

    RFC says: If any recognized attribute has Attribute Flags that conflict
    with the Attribute Type Code, then the Error Subcode MUST be set to
    Attribute Flags Error.  The Data field MUST contain the erroneous attribute
    (type, length, and value).
    """
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR


class AttrLenError(BgpExc):
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR


class InvalidOriginError(BgpExc):
    """Error indicates undefined Origin attribute value.

    RFC says: If the ORIGIN attribute has an undefined value, then the Error
    Sub- code MUST be set to Invalid Origin Attribute.  The Data field MUST
    contain the unrecognized attribute (type, length, and value).
    """
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE


class RoutingLoop(BgpExc):
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_ROUTING_LOOP


class InvalidNextHop(BgpExc):
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE


class OptAttrError(BgpExc):
    """Error indicates Optional Attribute is malformed.

    RFC says: If an optional attribute is recognized, then the value of this
    attribute MUST be checked.  If an error is detected, the attribute MUST be
    discarded, and the Error Subcode MUST be set to Optional Attribute Error.
    The Data field MUST contain the attribute (type, length, and value).
    """
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_OPTIONAL_ATTRIBUTE_ERROR


class InvalidNetworkField(BgpExc):
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_INVALID_NETWORK_FIELD


class MalformedAsPath(BgpExc):
    """Error to indicate if AP_PATH attribute is syntactically incorrect.

    RFC says: The AS_PATH attribute is checked for syntactic correctness.  If
    the path is syntactically incorrect, then the Error Subcode MUST be set to
    Malformed AS_PATH.
    """
    CODE = BGP_ERROR_UPDATE_MESSAGE_ERROR
    SUB_CODE = BGP_ERROR_SUB_MALFORMED_AS_PATH


# ============================================================================
# Hold Timer Expired
# ============================================================================


class HoldTimerExpired(BgpExc):
    """Error to indicate Hold Timer expired.

    RFC says: If a system does not receive successive KEEPALIVE, UPDATE, and/or
    NOTIFICATION messages within the period specified in the Hold Time field of
    the OPEN message, then the NOTIFICATION message with the Hold Timer Expired
    Error Code is sent and the BGP connection is closed.
    """
    CODE = BGP_ERROR_HOLD_TIMER_EXPIRED
    SUB_CODE = BGP_ERROR_SUB_HOLD_TIMER_EXPIRED

# ============================================================================
# Finite State Machine Error
# ============================================================================


class FiniteStateMachineError(BgpExc):
    """Error to indicate any Finite State Machine Error.

    RFC says: Any error detected by the BGP Finite State Machine (e.g., receipt
    of an unexpected event) is indicated by sending the NOTIFICATION message
    with the Error Code Finite State Machine Error.
    """
    CODE = BGP_ERROR_FSM_ERROR
    SUB_CODE = BGP_ERROR_SUB_FSM_ERROR


# ============================================================================
# Cease Errors
# ============================================================================

class MaxPrefixReached(BgpExc):
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED


class AdminShutdown(BgpExc):
    """Error to indicate Administrative shutdown.

    RFC says: If a BGP speaker decides to administratively shut down its
    peering with a neighbor, then the speaker SHOULD send a NOTIFICATION
    message  with the Error Code Cease and the Error Subcode 'Administrative
    Shutdown'.
    """
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN


class PeerDeConfig(BgpExc):
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_PEER_DECONFIGURED


class AdminReset(BgpExc):
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_ADMINISTRATIVE_RESET


class ConnRejected(BgpExc):
    """Error to indicate Connection Rejected.

    RFC says: If a BGP speaker decides to disallow a BGP connection (e.g., the
    peer is not configured locally) after the speaker accepts a transport
    protocol connection, then the BGP speaker SHOULD send a NOTIFICATION
    message with the Error Code Cease and the Error Subcode "Connection
    Rejected".
    """
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_CONNECTION_RESET


class OtherConfChange(BgpExc):
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE


class CollisionResolution(BgpExc):
    """Error to indicate Connection Collision Resolution.

    RFC says: If a BGP speaker decides to send a NOTIFICATION message with the
    Error Code Cease as a result of the collision resolution procedure (as
    described in [BGP-4]), then the subcode SHOULD be set to "Connection
    Collision Resolution".
    """
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION


class OutOfResource(BgpExc):
    CODE = BGP_ERROR_CEASE
    SUB_CODE = BGP_ERROR_SUB_OUT_OF_RESOURCES


class RouteFamily(StringifyMixin):
    def __init__(self, afi, safi):
        self.afi = afi
        self.safi = safi

    def __cmp__(self, other):
        return cmp((other.afi, other.safi), (self.afi, self.safi))

# Route Family Singleton
RF_IPv4_UC = RouteFamily(addr_family.IP, subaddr_family.UNICAST)
RF_IPv6_UC = RouteFamily(addr_family.IP6, subaddr_family.UNICAST)
RF_IPv4_VPN = RouteFamily(addr_family.IP, subaddr_family.MPLS_VPN)
RF_IPv6_VPN = RouteFamily(addr_family.IP6, subaddr_family.MPLS_VPN)
RF_IPv4_MPLS = RouteFamily(addr_family.IP, subaddr_family.MPLS_LABEL)
RF_IPv6_MPLS = RouteFamily(addr_family.IP6, subaddr_family.MPLS_LABEL)
RF_RTC_UC = RouteFamily(addr_family.IP,
                        subaddr_family.ROUTE_TARGET_CONSTRTAINS)

_rf_map = {
    (addr_family.IP, subaddr_family.UNICAST): RF_IPv4_UC,
    (addr_family.IP6, subaddr_family.UNICAST): RF_IPv6_UC,
    (addr_family.IP, subaddr_family.MPLS_VPN): RF_IPv4_VPN,
    (addr_family.IP6, subaddr_family.MPLS_VPN): RF_IPv6_VPN,
    (addr_family.IP, subaddr_family.MPLS_LABEL): RF_IPv4_MPLS,
    (addr_family.IP6, subaddr_family.MPLS_LABEL): RF_IPv6_MPLS,
    (addr_family.IP, subaddr_family.ROUTE_TARGET_CONSTRTAINS): RF_RTC_UC
}


def get_rf(afi, safi):
    return _rf_map[(afi, safi)]


def pad(bin, len_):
    assert len(bin) <= len_
    return bin + b'\0' * (len_ - len(bin))


class _RouteDistinguisher(StringifyMixin, _TypeDisp, _Value):
    _PACK_STR = '!H'
    TWO_OCTET_AS = 0
    IPV4_ADDRESS = 1
    FOUR_OCTET_AS = 2

    def __init__(self, type_, admin=0, assigned=0):
        self.type = type_
        self.admin = admin
        self.assigned = assigned

    @classmethod
    def parser(cls, buf):
        assert len(buf) == 8
        (type_,) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        subcls = cls._lookup_type(type_)
        return subcls(type_=type_, **subcls.parse_value(rest))

    @classmethod
    def from_str(cls, str_):
        assert isinstance(str_, str)

        first, second = str_.split(':')
        if '.' in first:
            type_ = cls.IPV4_ADDRESS
        elif int(first) > (1 << 16):
            type_ = cls.FOUR_OCTET_AS
            first = int(first)
        else:
            type_ = cls.TWO_OCTET_AS
            first = int(first)
        subcls = cls._lookup_type(type_)
        return subcls(type_=type_, admin=first, assigned=int(second))

    def serialize(self):
        value = self.serialize_value()
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type)
        return buf + value

    @property
    def formatted_str(self):
        return "%s:%s" % (str(self.admin), str(self.assigned))


@_RouteDistinguisher.register_type(_RouteDistinguisher.TWO_OCTET_AS)
class BGPTwoOctetAsRD(_RouteDistinguisher):
    _VALUE_PACK_STR = '!HI'
    _VALUE_FIELDS = ['admin', 'assigned']

    def __init__(self, type_=_RouteDistinguisher.TWO_OCTET_AS, **kwargs):
        self.do_init(BGPTwoOctetAsRD, self, kwargs, type_=type_)


@_RouteDistinguisher.register_type(_RouteDistinguisher.IPV4_ADDRESS)
class BGPIPv4AddressRD(_RouteDistinguisher):
    _VALUE_PACK_STR = '!4sH'
    _VALUE_FIELDS = ['admin', 'assigned']
    _TYPE = {
        'ascii': [
            'admin'
        ]
    }

    def __init__(self, type_=_RouteDistinguisher.IPV4_ADDRESS, **kwargs):
        self.do_init(BGPIPv4AddressRD, self, kwargs, type_=type_)

    @classmethod
    def parse_value(cls, buf):
        d_ = super(BGPIPv4AddressRD, cls).parse_value(buf)
        d_['admin'] = addrconv.ipv4.bin_to_text(d_['admin'])
        return d_

    def serialize_value(self):
        args = []
        for f in self._VALUE_FIELDS:
            v = getattr(self, f)
            if f == 'admin':
                v = bytes(addrconv.ipv4.text_to_bin(v))
            args.append(v)
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, *args)
        return buf


@_RouteDistinguisher.register_type(_RouteDistinguisher.FOUR_OCTET_AS)
class BGPFourOctetAsRD(_RouteDistinguisher):
    _VALUE_PACK_STR = '!IH'
    _VALUE_FIELDS = ['admin', 'assigned']

    def __init__(self, type_=_RouteDistinguisher.FOUR_OCTET_AS,
                 **kwargs):
        self.do_init(BGPFourOctetAsRD, self, kwargs, type_=type_)


@six.add_metaclass(abc.ABCMeta)
class _AddrPrefix(StringifyMixin):
    _PACK_STR = '!B'  # length

    def __init__(self, length, addr, prefixes=None):
        # length is on-wire bit length of prefixes+addr.
        assert prefixes != ()
        if isinstance(addr, tuple):
            # for _AddrPrefix.parser
            # also for _VPNAddrPrefix.__init__ etc
            (addr,) = addr
        self.length = length
        if prefixes:
            addr = prefixes + (addr,)
        self.addr = addr

    @staticmethod
    @abc.abstractmethod
    def _to_bin(addr):
        pass

    @staticmethod
    @abc.abstractmethod
    def _from_bin(addr):
        pass

    @classmethod
    def parser(cls, buf):
        (length, ) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        byte_length = (length + 7) // 8
        addr = cls._from_bin(rest[:byte_length])
        rest = rest[byte_length:]
        return cls(length=length, addr=addr), rest

    def serialize(self):
        # fixup
        byte_length = (self.length + 7) // 8
        bin_addr = self._to_bin(self.addr)
        if (self.length % 8) == 0:
            bin_addr = bin_addr[:byte_length]
        else:
            # clear trailing bits in the last octet.
            # rfc doesn't require this.
            mask = 0xff00 >> (self.length % 8)
            last_byte = six.int2byte(
                six.indexbytes(bin_addr, byte_length - 1) & mask)
            bin_addr = bin_addr[:byte_length - 1] + last_byte
        self.addr = self._from_bin(bin_addr)

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.length)
        return buf + bytes(bin_addr)


class _BinAddrPrefix(_AddrPrefix):
    @staticmethod
    def _to_bin(addr):
        return addr

    @staticmethod
    def _from_bin(addr):
        return addr


class _LabelledAddrPrefix(_AddrPrefix):
    _LABEL_PACK_STR = '!3B'
    # RFC3107
    # 3. Carrying Label Mapping Information
    # The label information carried (as part of NLRI) in the Withdrawn
    # Routes field should be set to 0x800000.  (Of course, terminating the
    # BGP session also withdraws all the previously advertised routes.)
    #
    _WITHDRAW_LABEL = 0x800000

    def __init__(self, length, addr, labels=[], **kwargs):
        assert isinstance(labels, list)
        is_tuple = isinstance(addr, tuple)
        if is_tuple:
            # for _AddrPrefix.parser
            assert not labels
            labels = addr[0]
            addr = addr[1:]
        else:
            length += struct.calcsize(self._LABEL_PACK_STR) * 8 * len(labels)
        assert length > struct.calcsize(self._LABEL_PACK_STR) * 8 * len(labels)
        prefixes = (labels,)
        super(_LabelledAddrPrefix, self).__init__(prefixes=prefixes,
                                                  length=length,
                                                  addr=addr,
                                                  **kwargs)

    @classmethod
    def _label_to_bin(cls, label):
        buf = bytearray()
        msg_pack_into(cls._LABEL_PACK_STR, buf, 0,
                      (label & 0xff0000) >> 16,
                      (label & 0x00ff00) >> 8,
                      (label & 0x0000ff) >> 0)
        return buf

    @classmethod
    def _label_from_bin(cls, bin):
        (b1, b2, b3) = struct.unpack_from(cls._LABEL_PACK_STR, six.binary_type(bin))
        rest = bin[struct.calcsize(cls._LABEL_PACK_STR):]
        return (b1 << 16) | (b2 << 8) | b3, rest

    @classmethod
    def _to_bin(cls, addr):
        labels = addr[0]
        rest = addr[1:]
        labels = [x << 4 for x in labels]
        if labels and labels[-1] != cls._WITHDRAW_LABEL:
            labels[-1] |= 1  # bottom of stack
        bin_labels = list(map(cls._label_to_bin, labels))
        return bytes(reduce(lambda x, y: x + y, bin_labels,
                            bytearray()) + cls._prefix_to_bin(rest))

    @classmethod
    def _has_no_label(cls, bin_):
        try:
            length = len(bin_)
            labels = []
            while True:
                (label, bin_) = cls._label_from_bin(bin_)
                labels.append(label)
                if label & 1 or label == cls._WITHDRAW_LABEL:
                    break
            assert length > struct.calcsize(cls._LABEL_PACK_STR) * len(labels)
        except struct.error:
            return True
        except AssertionError:
            return True
        return False

    @classmethod
    def _from_bin(cls, addr):
        rest = addr
        labels = []

        if cls._has_no_label(rest):
            return ([],) + cls._prefix_from_bin(rest)

        while True:
            (label, rest) = cls._label_from_bin(rest)
            labels.append(label >> 4)
            if label & 1 or label == cls._WITHDRAW_LABEL:
                break
        return (labels,) + cls._prefix_from_bin(rest)


class _UnlabelledAddrPrefix(_AddrPrefix):
    @classmethod
    def _to_bin(cls, addr):
        return cls._prefix_to_bin((addr,))

    @classmethod
    def _from_bin(cls, binaddr):
        (addr,) = cls._prefix_from_bin(binaddr)
        return addr


class _IPAddrPrefix(_AddrPrefix):
    @staticmethod
    def _prefix_to_bin(addr):
        (addr,) = addr
        return addrconv.ipv4.text_to_bin(addr)

    @staticmethod
    def _prefix_from_bin(addr):
        return (addrconv.ipv4.bin_to_text(pad(addr, 4)),)


class _IP6AddrPrefix(_AddrPrefix):
    @staticmethod
    def _prefix_to_bin(addr):
        (addr,) = addr
        return addrconv.ipv6.text_to_bin(addr)

    @staticmethod
    def _prefix_from_bin(addr):
        return (addrconv.ipv6.bin_to_text(pad(addr, 16)),)


class _VPNAddrPrefix(_AddrPrefix):
    _RD_PACK_STR = '!Q'

    def __init__(self, length, addr, prefixes=(), route_dist=0):
        if isinstance(addr, tuple):
            # for _AddrPrefix.parser
            assert not route_dist
            assert length > struct.calcsize(self._RD_PACK_STR) * 8
            route_dist = addr[0]
            addr = addr[1:]
        else:
            length += struct.calcsize(self._RD_PACK_STR) * 8

        if isinstance(route_dist, str):
            route_dist = _RouteDistinguisher.from_str(route_dist)

        prefixes = prefixes + (route_dist,)
        super(_VPNAddrPrefix, self).__init__(prefixes=prefixes,
                                             length=length,
                                             addr=addr)

    @classmethod
    def _prefix_to_bin(cls, addr):
        rd = addr[0]
        rest = addr[1:]
        binrd = rd.serialize()
        return binrd + super(_VPNAddrPrefix, cls)._prefix_to_bin(rest)

    @classmethod
    def _prefix_from_bin(cls, binaddr):
        binrd = binaddr[:8]
        binrest = binaddr[8:]
        rd = _RouteDistinguisher.parser(binrd)
        return (rd,) + super(_VPNAddrPrefix, cls)._prefix_from_bin(binrest)


class IPAddrPrefix(_UnlabelledAddrPrefix, _IPAddrPrefix):
    ROUTE_FAMILY = RF_IPv4_UC
    _TYPE = {
        'ascii': [
            'addr'
        ]
    }

    @property
    def prefix(self):
        return self.addr + '/{0}'.format(self.length)

    @property
    def formatted_nlri_str(self):
        return self.prefix


class IP6AddrPrefix(_UnlabelledAddrPrefix, _IP6AddrPrefix):
    ROUTE_FAMILY = RF_IPv6_UC
    _TYPE = {
        'ascii': [
            'addr'
        ]
    }

    @property
    def prefix(self):
        return self.addr + '/{0}'.format(self.length)

    @property
    def formatted_nlri_str(self):
        return self.prefix


class LabelledIPAddrPrefix(_LabelledAddrPrefix, _IPAddrPrefix):
    ROUTE_FAMILY = RF_IPv4_MPLS


class LabelledIP6AddrPrefix(_LabelledAddrPrefix, _IP6AddrPrefix):
    ROUTE_FAMILY = RF_IPv6_MPLS


class LabelledVPNIPAddrPrefix(_LabelledAddrPrefix, _VPNAddrPrefix,
                              _IPAddrPrefix):
    ROUTE_FAMILY = RF_IPv4_VPN

    @property
    def prefix(self):
        masklen = self.length - struct.calcsize(self._RD_PACK_STR) * 8 \
            - struct.calcsize(self._LABEL_PACK_STR) * 8 * len(self.addr[:-2])
        return self.addr[-1] + '/{0}'.format(masklen)

    @property
    def route_dist(self):
        return self.addr[-2].formatted_str

    @property
    def label_list(self):
        return self.addr[0]

    @property
    def formatted_nlri_str(self):
        return "%s:%s" % (self.route_dist, self.prefix)


class LabelledVPNIP6AddrPrefix(_LabelledAddrPrefix, _VPNAddrPrefix,
                               _IP6AddrPrefix):
    ROUTE_FAMILY = RF_IPv6_VPN

    @property
    def prefix(self):
        masklen = self.length - struct.calcsize(self._RD_PACK_STR) * 8 \
            - struct.calcsize(self._LABEL_PACK_STR) * 8 * len(self.addr[:-2])
        return self.addr[-1] + '/{0}'.format(masklen)

    @property
    def route_dist(self):
        return self.addr[-2].formatted_str

    @property
    def label_list(self):
        return self.addr[0]

    @property
    def formatted_nlri_str(self):
        return "%s:%s" % (self.route_dist, self.prefix)


class RouteTargetMembershipNLRI(StringifyMixin):
    """Route Target Membership NLRI.

    Route Target membership NLRI is advertised in BGP UPDATE messages using
    the MP_REACH_NLRI and MP_UNREACH_NLRI attributes.
    """

    ROUTE_FAMILY = RF_RTC_UC
    DEFAULT_AS = '0:0'
    DEFAULT_RT = '0:0'

    def __init__(self, origin_as, route_target):
        # If given is not default_as and default_rt
        if not (origin_as is self.DEFAULT_AS and
                route_target is self.DEFAULT_RT):
            # We validate them
            if (not self._is_valid_old_asn(origin_as) or
                    not self._is_valid_ext_comm_attr(route_target)):
                raise ValueError('Invalid params.')
        self.origin_as = origin_as
        self.route_target = route_target

    def _is_valid_old_asn(self, asn):
        """Returns true if given asn is a 16 bit number.

        Old AS numbers are 16 but unsigned number.
        """
        valid = True
        # AS number should be a 16 bit number
        if (not isinstance(asn, numbers.Integral) or (asn < 0) or
                (asn > ((2 ** 16) - 1))):
            valid = False

        return valid

    def _is_valid_ext_comm_attr(self, attr):
        """Validates *attr* as string representation of RT or SOO.

        Returns True if *attr* is as per our convention of RT or SOO, else
        False. Our convention is to represent RT/SOO is a string with format:
        *global_admin_part:local_admin_path*
        """
        is_valid = True

        if not isinstance(attr, str):
            is_valid = False
        else:
            first, second = attr.split(':')
            try:
                if '.' in first:
                    socket.inet_aton(first)
                else:
                    int(first)
                    int(second)
            except (ValueError, socket.error):
                is_valid = False

        return is_valid

    @property
    def formatted_nlri_str(self):
        return "%s:%s" % (self.origin_as, self.route_target)

    def is_default_rtnlri(self):
        if (self._origin_as is self.DEFAULT_AS and
                self._route_target is self.DEFAULT_RT):
            return True
        return False

    def __cmp__(self, other):
        return cmp(
            (self._origin_as, self._route_target),
            (other.origin_as, other.route_target),
        )

    @classmethod
    def parser(cls, buf):
        idx = 0

        # Extract origin AS.
        origin_as, = struct.unpack_from('!I', buf, idx)
        idx += 4

        # Extract route target.
        route_target = _ExtendedCommunity(buf[idx:])
        return cls(origin_as, route_target)

    def serialize(self):
        rt_nlri = ''
        if not self.is_default_rtnlri():
            rt_nlri += struct.pack('!I', self.origin_as)
            # Encode route target
            rt_nlri += self.route_target.serialize()

        # RT Nlri is 12 octets
        return struct.pack('B', (8 * 12)) + rt_nlri

_addr_class_key = lambda x: (x.afi, x.safi)

_ADDR_CLASSES = {
    _addr_class_key(RF_IPv4_UC): IPAddrPrefix,
    _addr_class_key(RF_IPv6_UC): IP6AddrPrefix,
    _addr_class_key(RF_IPv4_MPLS): LabelledIPAddrPrefix,
    _addr_class_key(RF_IPv6_MPLS): LabelledIP6AddrPrefix,
    _addr_class_key(RF_IPv4_VPN): LabelledVPNIPAddrPrefix,
    _addr_class_key(RF_IPv6_VPN): LabelledVPNIP6AddrPrefix,
    _addr_class_key(RF_RTC_UC): RouteTargetMembershipNLRI,
}


def _get_addr_class(afi, safi):
    try:
        return _ADDR_CLASSES[(afi, safi)]
    except KeyError:
        return _BinAddrPrefix


class _OptParam(StringifyMixin, _TypeDisp, _Value):
    _PACK_STR = '!BB'  # type, length

    def __init__(self, type_, value=None, length=None):
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.type = type_
        self.length = length
        if value is not None:
            self.value = value

    @classmethod
    def parser(cls, buf):
        (type_, length) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        value = bytes(rest[:length])
        rest = rest[length:]
        subcls = cls._lookup_type(type_)
        caps = subcls.parse_value(value)
        if type(caps) != list:
            caps = [subcls(type_=type_, length=length, **caps[0])]
        return caps, rest

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
        }, cls

    def serialize_value(self):
        return self.value


@_OptParam.register_type(BGP_OPT_CAPABILITY)
class _OptParamCapability(_OptParam, _TypeDisp):
    _CAP_HDR_PACK_STR = '!BB'

    def __init__(self, cap_code=None, cap_value=None, cap_length=None,
                 type_=None, length=None):
        super(_OptParamCapability, self).__init__(type_=BGP_OPT_CAPABILITY,
                                                  length=length)
        if cap_code is None:
            cap_code = self._rev_lookup_type(self.__class__)
        self.cap_code = cap_code
        if cap_value is not None:
            self.cap_value = cap_value
        if cap_length is not None:
            self.cap_length = cap_length

    @classmethod
    def parse_value(cls, buf):
        caps = []
        while len(buf) > 0:
            (code, length) = struct.unpack_from(cls._CAP_HDR_PACK_STR,
                                                six.binary_type(buf))
            value = buf[struct.calcsize(cls._CAP_HDR_PACK_STR):]
            buf = buf[length + 2:]
            kwargs = {
                'cap_code': code,
                'cap_length': length,
            }
            subcls = cls._lookup_type(code)
            kwargs.update(subcls.parse_cap_value(value))
            caps.append(subcls(type_=BGP_OPT_CAPABILITY, length=length + 2,
                               **kwargs))
        return caps

    def serialize_value(self):
        # fixup
        cap_value = self.serialize_cap_value()
        self.cap_length = len(cap_value)

        buf = bytearray()
        msg_pack_into(self._CAP_HDR_PACK_STR, buf, 0, self.cap_code,
                      self.cap_length)
        return buf + cap_value


class _OptParamEmptyCapability(_OptParamCapability):
    @classmethod
    def parse_cap_value(cls, buf):
        return {}

    def serialize_cap_value(self):
        return bytearray()


@_OptParamCapability.register_unknown_type()
class BGPOptParamCapabilityUnknown(_OptParamCapability):
    @classmethod
    def parse_cap_value(cls, buf):
        return {'cap_value': buf}

    def serialize_cap_value(self):
        return self.cap_value


@_OptParamCapability.register_type(BGP_CAP_ROUTE_REFRESH)
class BGPOptParamCapabilityRouteRefresh(_OptParamEmptyCapability):
    pass


@_OptParamCapability.register_type(BGP_CAP_ROUTE_REFRESH_CISCO)
class BGPOptParamCapabilityCiscoRouteRefresh(_OptParamEmptyCapability):
    pass


@_OptParamCapability.register_type(BGP_CAP_ENHANCED_ROUTE_REFRESH)
class BGPOptParamCapabilityEnhancedRouteRefresh(_OptParamEmptyCapability):
    pass


@_OptParamCapability.register_type(BGP_CAP_GRACEFUL_RESTART)
class BGPOptParamCapabilityGracefulRestart(_OptParamCapability):
    _CAP_PACK_STR = "!H"

    def __init__(self, flags, time, tuples, **kwargs):
        super(BGPOptParamCapabilityGracefulRestart, self).__init__(**kwargs)
        self.flags = flags
        self.time = time
        self.tuples = tuples

    @classmethod
    def parse_cap_value(cls, buf):
        (restart, ) = struct.unpack_from(cls._CAP_PACK_STR, six.binary_type(buf))
        buf = buf[2:]
        l = []
        while len(buf) > 0:
            l.append(struct.unpack_from("!HBB", buf))
            buf = buf[4:]
        return {'flags': restart >> 12, 'time': restart & 0xfff, 'tuples': l}

    def serialize_cap_value(self):
        buf = bytearray()
        msg_pack_into(self._CAP_PACK_STR, buf, 0, self.flags << 12 | self.time)
        tuples = self.tuples
        i = 0
        offset = 2
        for i in self.tuples:
            afi, safi, flags = i
            msg_pack_into("!HBB", buf, offset, afi, safi, flags)
            offset += 4
        return buf


@_OptParamCapability.register_type(BGP_CAP_FOUR_OCTET_AS_NUMBER)
class BGPOptParamCapabilityFourOctetAsNumber(_OptParamCapability):
    _CAP_PACK_STR = '!I'

    def __init__(self, as_number, **kwargs):
        super(BGPOptParamCapabilityFourOctetAsNumber, self).__init__(**kwargs)
        self.as_number = as_number

    @classmethod
    def parse_cap_value(cls, buf):
        (as_number, ) = struct.unpack_from(cls._CAP_PACK_STR, six.binary_type(buf))
        return {'as_number': as_number}

    def serialize_cap_value(self):
        buf = bytearray()
        msg_pack_into(self._CAP_PACK_STR, buf, 0, self.as_number)
        return buf


@_OptParamCapability.register_type(BGP_CAP_MULTIPROTOCOL)
class BGPOptParamCapabilityMultiprotocol(_OptParamCapability):
    _CAP_PACK_STR = '!HBB'  # afi, reserved, safi

    def __init__(self, afi, safi, reserved=0, **kwargs):
        super(BGPOptParamCapabilityMultiprotocol, self).__init__(**kwargs)
        self.afi = afi
        self.reserved = reserved
        self.safi = safi

    @classmethod
    def parse_cap_value(cls, buf):
        (afi, reserved, safi,) = struct.unpack_from(cls._CAP_PACK_STR,
                                                    six.binary_type(buf))
        return {
            'afi': afi,
            'reserved': reserved,
            'safi': safi,
        }

    def serialize_cap_value(self):
        # fixup
        self.reserved = 0

        buf = bytearray()
        msg_pack_into(self._CAP_PACK_STR, buf, 0,
                      self.afi, self.reserved, self.safi)
        return buf


@_OptParamCapability.register_type(BGP_CAP_CARRYING_LABEL_INFO)
class BGPOptParamCapabilityCarryingLabelInfo(_OptParamEmptyCapability):
    pass


class BGPWithdrawnRoute(IPAddrPrefix):
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
        if value is not None:
            self.value = value

    @classmethod
    def parser(cls, buf):
        (flags, type_) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        if (flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) != 0:
            len_pack_str = cls._PACK_STR_EXT_LEN
        else:
            len_pack_str = cls._PACK_STR_LEN
        (length,) = struct.unpack_from(len_pack_str, six.binary_type(rest))
        rest = rest[struct.calcsize(len_pack_str):]
        value = bytes(rest[:length])
        rest = rest[length:]
        subcls = cls._lookup_type(type_)
        return subcls(flags=flags, type_=type_, length=length,
                      **subcls.parse_value(value)), rest

    def serialize(self):
        # fixup
        if self._ATTR_FLAGS is not None:
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

    def __init__(self, value, as_pack_str=None, flags=0, type_=None,
                 length=None):
        super(_BGPPathAttributeAsPathCommon, self).__init__(value=value,
                                                            flags=flags,
                                                            type_=type_,
                                                            length=length)
        if as_pack_str:
            self._AS_PACK_STR = as_pack_str

    @property
    def path_seg_list(self):
        return copy.deepcopy(self.value)

    def get_as_path_len(self):
        count = 0
        for seg in self.value:
            if isinstance(seg, list):
                # Segment type 2 stored in list and all AS counted.
                count += len(seg)
            else:
                # Segment type 1 stored in set and count as one.
                count += 1

        return count

    def has_local_as(self, local_as):
        """Check if *local_as* is already present on path list."""
        for as_path_seg in self.value:
            for as_num in as_path_seg:
                if as_num == local_as:
                    return True
        return False

    def has_matching_leftmost(self, remote_as):
        """Check if leftmost AS matches *remote_as*."""
        if not self.value or not remote_as:
            return False

        leftmost_seg = self.path_seg_list[0]
        if leftmost_seg and leftmost_seg[0] == remote_as:
            return True

        return False

    @classmethod
    def _is_valid_16bit_as_path(cls, buf):

        two_byte_as_size = struct.calcsize('!H')

        while buf:
            (type_, num_as) = struct.unpack_from(cls._SEG_HDR_PACK_STR,
                                                 six.binary_type(buf))

            if type_ is not cls._AS_SET and type_ is not cls._AS_SEQUENCE:
                return False

            buf = buf[struct.calcsize(cls._SEG_HDR_PACK_STR):]

            if len(buf) < num_as * two_byte_as_size:
                return False

            buf = buf[num_as * two_byte_as_size:]

        return True

    @classmethod
    def parse_value(cls, buf):
        result = []

        if cls._is_valid_16bit_as_path(buf):
            as_pack_str = '!H'
        else:
            as_pack_str = '!I'

        while buf:
            (type_, num_as) = struct.unpack_from(cls._SEG_HDR_PACK_STR,
                                                 six.binary_type(buf))
            buf = buf[struct.calcsize(cls._SEG_HDR_PACK_STR):]
            l = []
            for i in range(0, num_as):
                (as_number,) = struct.unpack_from(as_pack_str,
                                                  six.binary_type(buf))
                buf = buf[struct.calcsize(as_pack_str):]
                l.append(as_number)
            if type_ == cls._AS_SET:
                result.append(set(l))
            elif type_ == cls._AS_SEQUENCE:
                result.append(l)
            else:
                assert(0)  # protocol error
        return {
            'value': result,
            'as_pack_str': as_pack_str,
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
            if num_as == 0:
                continue
            msg_pack_into(self._SEG_HDR_PACK_STR, buf, offset, type_, num_as)
            offset += struct.calcsize(self._SEG_HDR_PACK_STR)
            for i in l:
                msg_pack_into(self._AS_PACK_STR, buf, offset, i)
                offset += struct.calcsize(self._AS_PACK_STR)
        return buf


@_PathAttribute.register_type(BGP_ATTR_TYPE_AS_PATH)
class BGPPathAttributeAsPath(_BGPPathAttributeAsPathCommon):
    # XXX depends on negotiated capability, AS numbers can be 32 bit.
    # while wireshark seems to attempt auto-detect, it seems that
    # there's no way to detect it reliably.  for example, the
    # following byte sequence can be interpreted in two ways.
    #   01 02 99 88 77 66 02 01 55 44
    #   AS_SET num=2 9988 7766 AS_SEQUENCE num=1 5544
    #   AS_SET num=2 99887766 02015544
    # we first check whether AS path can be parsed in 16bit format and if
    # it fails, we try to parse as 32bit
    _AS_PACK_STR = '!H'


@_PathAttribute.register_type(BGP_ATTR_TYPE_AS4_PATH)
class BGPPathAttributeAs4Path(_BGPPathAttributeAsPathCommon):
    _AS_PACK_STR = '!I'

    @classmethod
    def _is_valid_16bit_as_path(cls, buf):
        return False


@_PathAttribute.register_type(BGP_ATTR_TYPE_NEXT_HOP)
class BGPPathAttributeNextHop(_PathAttribute):
    _VALUE_PACK_STR = '!4s'
    _ATTR_FLAGS = BGP_ATTR_FLAG_TRANSITIVE
    _TYPE = {
        'ascii': [
            'value'
        ]
    }

    @classmethod
    def parse_value(cls, buf):
        (ip_addr,) = struct.unpack_from(cls._VALUE_PACK_STR, six.binary_type(buf))
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
        return b''


class _BGPPathAttributeAggregatorCommon(_PathAttribute):
    _VALUE_PACK_STR = None
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE
    _TYPE = {
        'ascii': [
            'addr'
        ]
    }

    def __init__(self, as_number, addr, flags=0, type_=None, length=None):
        super(_BGPPathAttributeAggregatorCommon, self).__init__(flags=flags,
                                                                type_=type_,
                                                                length=length)
        self.as_number = as_number
        self.addr = addr

    @classmethod
    def parse_value(cls, buf):
        (as_number, addr) = struct.unpack_from(cls._VALUE_PACK_STR,
                                               six.binary_type(buf))
        return {
            'as_number': as_number,
            'addr': addrconv.ipv4.bin_to_text(addr),
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, self.as_number,
                      addrconv.ipv4.text_to_bin(self.addr))
        return buf


@_PathAttribute.register_type(BGP_ATTR_TYPE_AGGREGATOR)
class BGPPathAttributeAggregator(_BGPPathAttributeAggregatorCommon):
    # XXX currently this implementation assumes 16 bit AS numbers.
    _VALUE_PACK_STR = '!H4s'


@_PathAttribute.register_type(BGP_ATTR_TYPE_AS4_AGGREGATOR)
class BGPPathAttributeAs4Aggregator(_BGPPathAttributeAggregatorCommon):
    _VALUE_PACK_STR = '!I4s'


@_PathAttribute.register_type(BGP_ATTR_TYPE_COMMUNITIES)
class BGPPathAttributeCommunities(_PathAttribute):
    _VALUE_PACK_STR = '!I'
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE

    # String constants of well-known-communities
    NO_EXPORT = int('0xFFFFFF01', 16)
    NO_ADVERTISE = int('0xFFFFFF02', 16)
    NO_EXPORT_SUBCONFED = int('0xFFFFFF03', 16)
    WELL_KNOW_COMMUNITIES = (NO_EXPORT, NO_ADVERTISE, NO_EXPORT_SUBCONFED)

    def __init__(self, communities,
                 flags=0, type_=None, length=None):
        super(BGPPathAttributeCommunities, self).__init__(flags=flags,
                                                          type_=type_,
                                                          length=length)
        self.communities = communities

    @classmethod
    def parse_value(cls, buf):
        rest = buf
        communities = []
        elem_size = struct.calcsize(cls._VALUE_PACK_STR)
        while len(rest) >= elem_size:
            (comm, ) = struct.unpack_from(cls._VALUE_PACK_STR,
                                          six.binary_type(rest))
            communities.append(comm)
            rest = rest[elem_size:]
        return {
            'communities': communities,
        }

    def serialize_value(self):
        buf = bytearray()
        for comm in self.communities:
            bincomm = bytearray()
            msg_pack_into(self._VALUE_PACK_STR, bincomm, 0, comm)
            buf += bincomm
        return buf

    @staticmethod
    def is_no_export(comm_attr):
        """Returns True if given value matches well-known community NO_EXPORT
         attribute value.
         """
        return comm_attr == BGPPathAttributeCommunities.NO_EXPORT

    @staticmethod
    def is_no_advertise(comm_attr):
        """Returns True if given value matches well-known community
        NO_ADVERTISE attribute value.
        """
        return comm_attr == BGPPathAttributeCommunities.NO_ADVERTISE

    @staticmethod
    def is_no_export_subconfed(comm_attr):
        """Returns True if given value matches well-known community
         NO_EXPORT_SUBCONFED attribute value.
         """
        return comm_attr == BGPPathAttributeCommunities.NO_EXPORT_SUBCONFED

    def has_comm_attr(self, attr):
        """Returns True if given community attribute is present."""

        for comm_attr in self.communities:
            if comm_attr == attr:
                return True

        return False


@_PathAttribute.register_type(BGP_ATTR_TYPE_ORIGINATOR_ID)
class BGPPathAttributeOriginatorId(_PathAttribute):
    # ORIGINATOR_ID is a new optional, non-transitive BGP attribute of Type
    # code 9. This attribute is 4 bytes long and it will be created by an
    # RR in reflecting a route.
    _VALUE_PACK_STR = '!4s'
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL
    _TYPE = {
        'ascii': [
            'value'
        ]
    }

    @classmethod
    def parse_value(cls, buf):
        (originator_id,) = struct.unpack_from(cls._VALUE_PACK_STR,
                                              six.binary_type(buf))
        return {
            'value': addrconv.ipv4.bin_to_text(originator_id),
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0,
                      addrconv.ipv4.text_to_bin(self.value))
        return buf


@_PathAttribute.register_type(BGP_ATTR_TYPE_CLUSTER_LIST)
class BGPPathAttributeClusterList(_PathAttribute):
    # CLUSTER_LIST is a new, optional, non-transitive BGP attribute of Type
    # code 10. It is a sequence of CLUSTER_ID values representing the
    # reflection path that the route has passed.
    _VALUE_PACK_STR = '!4s'
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL
    _TYPE = {
        'ascii': [
            'value'
        ]
    }

    @classmethod
    def parse_value(cls, buf):
        rest = buf
        cluster_list = []
        elem_size = struct.calcsize(cls._VALUE_PACK_STR)
        while len(rest) >= elem_size:
            (cluster_id, ) = struct.unpack_from(
                cls._VALUE_PACK_STR, six.binary_type(rest))
            cluster_list.append(addrconv.ipv4.bin_to_text(cluster_id))
            rest = rest[elem_size:]
        return {
            'value': cluster_list,
        }

    def serialize_value(self):
        buf = bytearray()
        offset = 0
        for cluster_id in self.value:
            msg_pack_into(
                self._VALUE_PACK_STR,
                buf,
                offset,
                addrconv.ipv4.text_to_bin(cluster_id))
            offset += struct.calcsize(self._VALUE_PACK_STR)
        return buf


# Extended Communities
# RFC 4360
# RFC 5668
# IANA registry:
# https://www.iana.org/assignments/bgp-extended-communities/
# bgp-extended-communities.xml
#
# type
# high  low
# 00    sub-type    Two-Octet AS Specific Extended Community (transitive)
# 40    sub-type    Two-Octet AS Specific Extended Community
#                   payload:
#                     2 byte Global Administrator (AS number)
#                     4 byte Local Administrator (defined by sub-type)
# 01    sub-type    IPv4 Address Specific Extended Community (transitive)
# 41    sub-type    IPv4 Address Specific Extended Community
#                   payload:
#                     4 byte Global Administrator (IPv4 address)
#                     2 byte Local Administrator (defined by sub-type)
# 03    sub-type    Opaque Extended Community (transitive)
# 43    sub-type    Opaque Extended Community
#                   payload:
#                     6 byte opaque value (defined by sub-type)
#
# 00    02          Route Target Community (two-octet AS specific)
# 01    02          Route Target Community (IPv4 address specific)
# 02    02          Route Target Community (four-octet AS specific, RFC 5668)
# 00    03          Route Origin Community (two-octet AS specific)
# 01    03          Route Origin Community (IPv4 address specific)
# 02    03          Route Origin Community (four-octet AS specific, RFC 5668)

@_PathAttribute.register_type(BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
class BGPPathAttributeExtendedCommunities(_PathAttribute):
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE
    _class_prefixes = ['BGP']

    def __init__(self, communities,
                 flags=0, type_=None, length=None):
        super(BGPPathAttributeExtendedCommunities,
              self).__init__(flags=flags,
                             type_=type_,
                             length=length)
        self.communities = communities

    @classmethod
    def parse_value(cls, buf):
        rest = buf
        communities = []
        while rest:
            comm, rest = _ExtendedCommunity.parse(rest)
            communities.append(comm)
        return {
            'communities': communities,
        }

    def serialize_value(self):
        buf = bytearray()
        for comm in self.communities:
            buf += comm.serialize()
        return buf

    def _community_list(self, subtype):
        _list = []
        for comm in (c for c in self.communities
                     if hasattr(c, "subtype") and c.subtype == subtype):
            if comm.type == 0 or comm.type == 2:
                _list.append('%d:%d' % (comm.as_number,
                                        comm.local_administrator))
            elif comm.type == 1:
                _list.append('%s:%d' % (comm.ipv4_address,
                                        comm.local_administrator))
        return _list

    @property
    def rt_list(self):
        return self._community_list(2)

    @property
    def soo_list(self):
        return self._community_list(3)


class _ExtendedCommunity(StringifyMixin, _TypeDisp, _Value):
    _PACK_STR = '!B7s'  # type high (+ type low) + value
    IANA_AUTHORITY = 0x80
    TRANSITIVE = 0x40
    _TYPE_HIGH_MASK = ~TRANSITIVE

    TWO_OCTET_AS_SPECIFIC = 0x00
    IPV4_ADDRESS_SPECIFIC = 0x01
    FOUR_OCTET_AS_SPECIFIC = 0x02
    OPAQUE = 0x03

    def __init__(self, type_):
        self.type = type_

    @classmethod
    def parse(cls, buf):
        (type_high, payload) = struct.unpack_from(cls._PACK_STR,
                                                  six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        type_ = type_high & cls._TYPE_HIGH_MASK
        subcls = cls._lookup_type(type_)
        return subcls(type_=type_high,
                      **subcls.parse_value(payload)), rest

    def serialize(self):
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type,
                      bytes(self.serialize_value()))
        return buf


@_ExtendedCommunity.register_type(_ExtendedCommunity.TWO_OCTET_AS_SPECIFIC)
class BGPTwoOctetAsSpecificExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!BHI'  # sub type, as number, local adm
    _VALUE_FIELDS = ['subtype', 'as_number', 'local_administrator']

    def __init__(self, type_=_ExtendedCommunity.TWO_OCTET_AS_SPECIFIC,
                 **kwargs):
        self.do_init(BGPTwoOctetAsSpecificExtendedCommunity, self, kwargs,
                     type_=type_)


@_ExtendedCommunity.register_type(_ExtendedCommunity.IPV4_ADDRESS_SPECIFIC)
class BGPIPv4AddressSpecificExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!B4sH'  # sub type, IPv4 address, local adm
    _VALUE_FIELDS = ['subtype', 'ipv4_address', 'local_administrator']
    _TYPE = {
        'ascii': [
            'ipv4_address'
        ]
    }

    def __init__(self, type_=_ExtendedCommunity.IPV4_ADDRESS_SPECIFIC,
                 **kwargs):
        self.do_init(BGPIPv4AddressSpecificExtendedCommunity, self, kwargs,
                     type_=type_)

    @classmethod
    def parse_value(cls, buf):
        d_ = super(BGPIPv4AddressSpecificExtendedCommunity,
                   cls).parse_value(buf)
        d_['ipv4_address'] = addrconv.ipv4.bin_to_text(d_['ipv4_address'])
        return d_

    def serialize_value(self):
        args = []
        for f in self._VALUE_FIELDS:
            v = getattr(self, f)
            if f == 'ipv4_address':
                v = bytes(addrconv.ipv4.text_to_bin(v))
            args.append(v)
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, *args)
        return buf


@_ExtendedCommunity.register_type(_ExtendedCommunity.FOUR_OCTET_AS_SPECIFIC)
class BGPFourOctetAsSpecificExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!BIH'  # sub type, as number, local adm
    _VALUE_FIELDS = ['subtype', 'as_number', 'local_administrator']

    def __init__(self, type_=_ExtendedCommunity.FOUR_OCTET_AS_SPECIFIC,
                 **kwargs):
        self.do_init(BGPFourOctetAsSpecificExtendedCommunity, self, kwargs,
                     type_=type_)


@_ExtendedCommunity.register_type(_ExtendedCommunity.OPAQUE)
class BGPOpaqueExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!7s'  # opaque value
    _VALUE_FIELDS = ['opaque']

    def __init__(self, type_=_ExtendedCommunity.OPAQUE,
                 **kwargs):
        self.do_init(BGPOpaqueExtendedCommunity, self, kwargs,
                     type_=type_)


@_ExtendedCommunity.register_unknown_type()
class BGPUnknownExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!7s'  # opaque value

    def __init__(self, **kwargs):
        self.do_init(BGPUnknownExtendedCommunity, self, kwargs)


@_PathAttribute.register_type(BGP_ATTR_TYPE_MP_REACH_NLRI)
class BGPPathAttributeMpReachNLRI(_PathAttribute):
    _VALUE_PACK_STR = '!HBB'  # afi, safi, next hop len
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL
    _class_suffixes = ['AddrPrefix']
    _rd_length = 8
    _TYPE = {
        'ascii': [
            'next_hop'
        ]
    }

    def __init__(self, afi, safi, next_hop, nlri,
                 next_hop_len=0, reserved='\0',
                 flags=0, type_=None, length=None):
        super(BGPPathAttributeMpReachNLRI, self).__init__(flags=flags,
                                                          type_=type_,
                                                          length=length)
        self.afi = afi
        self.safi = safi
        self.next_hop_len = next_hop_len
        self.next_hop = next_hop
        if afi == addr_family.IP:
            self._next_hop_bin = addrconv.ipv4.text_to_bin(next_hop)
        elif afi == addr_family.IP6:
            self._next_hop_bin = addrconv.ipv6.text_to_bin(next_hop)
        else:
            raise ValueError('Invalid address familly(%d)' % afi)
        self._reserved = reserved
        self.nlri = nlri
        addr_cls = _get_addr_class(afi, safi)
        for i in nlri:
            assert isinstance(i, addr_cls)

    @classmethod
    def parse_value(cls, buf):
        (afi, safi, next_hop_len,) = struct.unpack_from(cls._VALUE_PACK_STR,
                                                        six.binary_type(buf))
        rest = buf[struct.calcsize(cls._VALUE_PACK_STR):]
        next_hop_bin = rest[:next_hop_len]
        rest = rest[next_hop_len:]
        reserved = rest[:1]
        assert reserved == b'\0'
        binnlri = rest[1:]
        addr_cls = _get_addr_class(afi, safi)
        nlri = []
        while binnlri:
            n, binnlri = addr_cls.parser(binnlri)
            nlri.append(n)

        rf = RouteFamily(afi, safi)
        if rf == RF_IPv6_VPN:
            next_hop = addrconv.ipv6.bin_to_text(next_hop_bin[cls._rd_length:])
            next_hop_len -= cls._rd_length
        elif rf == RF_IPv4_VPN:
            next_hop = addrconv.ipv4.bin_to_text(next_hop_bin[cls._rd_length:])
            next_hop_len -= cls._rd_length
        elif afi == addr_family.IP:
            next_hop = addrconv.ipv4.bin_to_text(next_hop_bin)
        elif afi == addr_family.IP6:
            # next_hop_bin can include global address and link-local address
            # according to RFC2545. Since a link-local address isn't needed in
            # Ryu BGPSpeaker, we ignore it if both addresses were sent.
            # The link-local address is supposed to follow after
            # a global address and next_hop_len will be 32 bytes,
            # so we use the first 16 bytes, which is a global address,
            # as a next_hop and change the next_hop_len to 16.
            if next_hop_len == 32:
                next_hop_bin = next_hop_bin[:16]
                next_hop_len = 16
            next_hop = addrconv.ipv6.bin_to_text(next_hop_bin)
        else:
            raise ValueError('Invalid address familly(%d)' % afi)

        return {
            'afi': afi,
            'safi': safi,
            'next_hop_len': next_hop_len,
            'next_hop': next_hop,
            'reserved': reserved,
            'nlri': nlri,
        }

    def serialize_value(self):
        # fixup
        self.next_hop_len = len(self._next_hop_bin)

        if RouteFamily(self.afi, self.safi) in (RF_IPv4_VPN, RF_IPv6_VPN):
            empty_label_stack = b'\x00' * self._rd_length
            next_hop_len = len(self._next_hop_bin) + len(empty_label_stack)
            next_hop_bin = empty_label_stack
            next_hop_bin += self._next_hop_bin
        else:
            next_hop_len = self.next_hop_len
            next_hop_bin = self._next_hop_bin

        self._reserved = b'\0'

        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, self.afi,
                      self.safi, next_hop_len)
        buf += next_hop_bin
        buf += self._reserved
        binnlri = bytearray()
        for n in self.nlri:
            binnlri += n.serialize()
        buf += binnlri
        return buf

    @property
    def route_family(self):
        return _rf_map[(self.afi, self.safi)]


@_PathAttribute.register_type(BGP_ATTR_TYPE_MP_UNREACH_NLRI)
class BGPPathAttributeMpUnreachNLRI(_PathAttribute):
    _VALUE_PACK_STR = '!HB'  # afi, safi
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL
    _class_suffixes = ['AddrPrefix']

    def __init__(self, afi, safi, withdrawn_routes,
                 flags=0, type_=None, length=None):
        super(BGPPathAttributeMpUnreachNLRI, self).__init__(flags=flags,
                                                            type_=type_,
                                                            length=length)
        self.afi = afi
        self.safi = safi
        self.withdrawn_routes = withdrawn_routes
        addr_cls = _get_addr_class(afi, safi)
        for i in withdrawn_routes:
            assert isinstance(i, addr_cls)

    @classmethod
    def parse_value(cls, buf):
        (afi, safi,) = struct.unpack_from(cls._VALUE_PACK_STR, six.binary_type(buf))
        binnlri = buf[struct.calcsize(cls._VALUE_PACK_STR):]
        addr_cls = _get_addr_class(afi, safi)
        nlri = []
        while binnlri:
            n, binnlri = addr_cls.parser(binnlri)
            nlri.append(n)
        return {
            'afi': afi,
            'safi': safi,
            'withdrawn_routes': nlri,
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, self.afi, self.safi)
        binnlri = bytearray()
        for n in self.withdrawn_routes:
            binnlri += n.serialize()
        buf += binnlri
        return buf

    @property
    def route_family(self):
        return _rf_map[(self.afi, self.safi)]


class BGPNLRI(IPAddrPrefix):
    pass


class BGPMessage(packet_base.PacketBase, _TypeDisp):
    """Base class for BGP-4 messages.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

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
    _class_prefixes = ['BGP']

    def __init__(self, type_, len_=None, marker=None):
        if marker is None:
            self._marker = _MARKER
        else:
            self._marker = marker
        self.len = len_
        self.type = type_

    @classmethod
    def parser(cls, buf):
        if len(buf) < cls._HDR_LEN:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), cls._HDR_LEN))
        (marker, len_, type_) = struct.unpack_from(cls._HDR_PACK_STR,
                                                   six.binary_type(buf))
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
        self._marker = _MARKER
        tail = self.serialize_tail()
        self.len = self._HDR_LEN + len(tail)

        hdr = bytearray(struct.pack(self._HDR_PACK_STR, self._marker,
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
    __init__ takes the corresponding args in this order.

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
    _TYPE = {
        'ascii': [
            'bgp_identifier'
        ]
    }

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
                                                             six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        binopts = rest[:opt_param_len]
        opt_param = []
        while binopts:
            opt, binopts = _OptParam.parser(binopts)
            opt_param.extend(opt)
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
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

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

    _MIN_LEN = BGPMessage._HDR_LEN

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
        self._pathattr_map = {}
        for attr in path_attributes:
            self._pathattr_map[attr.type] = attr
        self.nlri = nlri

    @property
    def pathattr_map(self):
        return self._pathattr_map

    def get_path_attr(self, attr_name):
        return self._pathattr_map.get(attr_name)

    @classmethod
    def parser(cls, buf):
        offset = 0
        buf = six.binary_type(buf)
        (withdrawn_routes_len,) = struct.unpack_from('!H', buf, offset)
        binroutes = buf[offset + 2:
                        offset + 2 + withdrawn_routes_len]
        offset += 2 + withdrawn_routes_len
        (total_path_attribute_len,) = struct.unpack_from('!H', buf, offset)
        binpathattrs = buf[offset + 2:
                           offset + 2 + total_path_attribute_len]
        binnlri = buf[offset + 2 + total_path_attribute_len:]
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
    __init__ takes the corresponding args in this order.

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
    __init__ takes the corresponding args in this order.

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

    _REASONS = {
        (1, 1): 'Message Header Error: not synchronised',
        (1, 2): 'Message Header Error: bad message len',
        (1, 3): 'Message Header Error: bad message type',
        (2, 1): 'Open Message Error: unsupported version',
        (2, 2): 'Open Message Error: bad peer AS',
        (2, 3): 'Open Message Error: bad BGP identifier',
        (2, 4): 'Open Message Error: unsupported optional param',
        (2, 5): 'Open Message Error: authentication failure',
        (2, 6): 'Open Message Error: unacceptable hold time',
        (2, 7): 'Open Message Error: Unsupported Capability',
        (2, 8): 'Open Message Error: Unassigned',
        (3, 1): 'Update Message Error: malformed attribute list',
        (3, 2): 'Update Message Error: unrecognized well-known attr',
        (3, 3): 'Update Message Error: missing well-known attr',
        (3, 4): 'Update Message Error: attribute flags error',
        (3, 5): 'Update Message Error: attribute length error',
        (3, 6): 'Update Message Error: invalid origin attr',
        (3, 7): 'Update Message Error: as routing loop',
        (3, 8): 'Update Message Error: invalid next hop attr',
        (3, 9): 'Update Message Error: optional attribute error',
        (3, 10): 'Update Message Error: invalid network field',
        (3, 11): 'Update Message Error: malformed AS_PATH',
        (4, 1): 'Hold Timer Expired',
        (5, 1): 'Finite State Machine Error',
        (6, 1): 'Cease: Maximum Number of Prefixes Reached',
        (6, 2): 'Cease: Administrative Shutdown',
        (6, 3): 'Cease: Peer De-configured',
        (6, 4): 'Cease: Administrative Reset',
        (6, 5): 'Cease: Connection Rejected',
        (6, 6): 'Cease: Other Configuration Change',
        (6, 7): 'Cease: Connection Collision Resolution',
        (6, 8): 'Cease: Out of Resources',
    }

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
                                                          six.binary_type(buf))
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

    @property
    def reason(self):
        return self._REASONS.get((self.error_code, self.error_subcode))


@BGPMessage.register_type(BGP_MSG_ROUTE_REFRESH)
class BGPRouteRefresh(BGPMessage):
    """BGP-4 ROUTE REFRESH Message (RFC 2918) encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    marker                     Marker field.  Ignored when encoding.
    len                        Length field.  Ignored when encoding.
    type                       Type field.  The default is
                               BGP_MSG_ROUTE_REFRESH.
    afi                        Address Family Identifier
    safi                       Subsequent Address Family Identifier
    ========================== ===============================================
    """

    _PACK_STR = '!HBB'
    _MIN_LEN = BGPMessage._HDR_LEN + struct.calcsize(_PACK_STR)

    def __init__(self,
                 afi, safi, demarcation=0,
                 type_=BGP_MSG_ROUTE_REFRESH, len_=None, marker=None):
        super(BGPRouteRefresh, self).__init__(marker=marker, len_=len_,
                                              type_=type_)
        self.afi = afi
        self.safi = safi
        self.demarcation = demarcation

    @classmethod
    def parser(cls, buf):
        (afi, demarcation, safi,) = struct.unpack_from(cls._PACK_STR,
                                                       six.binary_type(buf))
        return {
            "afi": afi,
            "safi": safi,
            "demarcation": demarcation,
        }

    def serialize_tail(self):
        return bytearray(struct.pack(self._PACK_STR, self.afi,
                                     self.demarcation, self.safi))


class StreamParser(stream_parser.StreamParser):
    """Streaming parser for BGP-4 messages.

    This is a subclass of ryu.lib.packet.stream_parser.StreamParser.
    Its parse method returns a list of BGPMessage subclass instances.
    """

    def try_parse(self, data):
        return BGPMessage.parser(data)
