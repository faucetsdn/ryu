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
import base64
import collections
import copy
import functools
import io
import itertools
import math
import re
import socket
import struct

import netaddr
import six

from ryu.lib.stringify import StringifyMixin
from ryu.lib.packet import afi as addr_family
from ryu.lib.packet import safi as subaddr_family
from ryu.lib.packet import packet_base
from ryu.lib.packet import stream_parser
from ryu.lib.packet import vxlan
from ryu.lib.packet import mpls
from ryu.lib import addrconv
from ryu.lib import type_desc
from ryu.lib.type_desc import TypeDisp
from ryu.lib import ip
from ryu.lib.pack_utils import msg_pack_into
from ryu.utils import binary_str
from ryu.utils import import_module

reduce = six.moves.reduce

TCP_SERVER_PORT = 179

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
BGP_ATTR_TYEP_PMSI_TUNNEL_ATTRIBUTE = 22  # RFC 6514

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
    def do_init(cls_type, self, kwargs, **extra_kwargs):
        ourfields = {}
        for f in cls_type._VALUE_FIELDS:
            v = kwargs[f]
            del kwargs[f]
            ourfields[f] = v
        kwargs.update(extra_kwargs)
        super(cls_type, self).__init__(**kwargs)
        self.__dict__.update(ourfields)

    @classmethod
    def parse_value(cls, buf):
        values = struct.unpack_from(cls._VALUE_PACK_STR, six.binary_type(buf))
        return dict(zip(cls._VALUE_FIELDS, values))

    def serialize_value(self):
        args = []
        for f in self._VALUE_FIELDS:
            args.append(getattr(self, f))
        return struct.pack(self._VALUE_PACK_STR, *args)


class BgpExc(Exception):
    """Base bgp exception."""

    CODE = 0
    """BGP error code."""

    SUB_CODE = 0
    """BGP error sub-code."""

    SEND_ERROR = True
    """Flag if set indicates Notification message should be sent to peer."""

    def __init__(self, data=''):
        super(BgpExc, self).__init__()
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
        super(BadLen, self).__init__()
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
        super(BadMsg, self).__init__()
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
        super(UnsupportedVersion, self).__init__()
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
        super(MissingWellKnown, self).__init__()
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


@functools.total_ordering
class RouteFamily(StringifyMixin):
    def __init__(self, afi, safi):
        self.afi = afi
        self.safi = safi

    def __lt__(self, other):
        return (self.afi, self.safi) < (other.afi, other.safi)

    def __eq__(self, other):
        return (self.afi, self.safi) == (other.afi, other.safi)

    def __hash__(self):
        return hash((self.afi, self.safi))


# Route Family Singleton
RF_IPv4_UC = RouteFamily(addr_family.IP, subaddr_family.UNICAST)
RF_IPv6_UC = RouteFamily(addr_family.IP6, subaddr_family.UNICAST)
RF_IPv4_VPN = RouteFamily(addr_family.IP, subaddr_family.MPLS_VPN)
RF_IPv6_VPN = RouteFamily(addr_family.IP6, subaddr_family.MPLS_VPN)
RF_IPv4_MPLS = RouteFamily(addr_family.IP, subaddr_family.MPLS_LABEL)
RF_IPv6_MPLS = RouteFamily(addr_family.IP6, subaddr_family.MPLS_LABEL)
RF_L2_EVPN = RouteFamily(addr_family.L2VPN, subaddr_family.EVPN)
RF_IPv4_FLOWSPEC = RouteFamily(addr_family.IP, subaddr_family.IP_FLOWSPEC)
RF_IPv6_FLOWSPEC = RouteFamily(addr_family.IP6, subaddr_family.IP_FLOWSPEC)
RF_VPNv4_FLOWSPEC = RouteFamily(addr_family.IP, subaddr_family.VPN_FLOWSPEC)
RF_VPNv6_FLOWSPEC = RouteFamily(addr_family.IP6, subaddr_family.VPN_FLOWSPEC)
RF_L2VPN_FLOWSPEC = RouteFamily(
    addr_family.L2VPN, subaddr_family.VPN_FLOWSPEC)
RF_RTC_UC = RouteFamily(addr_family.IP,
                        subaddr_family.ROUTE_TARGET_CONSTRAINTS)

_rf_map = {
    (addr_family.IP, subaddr_family.UNICAST): RF_IPv4_UC,
    (addr_family.IP6, subaddr_family.UNICAST): RF_IPv6_UC,
    (addr_family.IP, subaddr_family.MPLS_VPN): RF_IPv4_VPN,
    (addr_family.IP6, subaddr_family.MPLS_VPN): RF_IPv6_VPN,
    (addr_family.IP, subaddr_family.MPLS_LABEL): RF_IPv4_MPLS,
    (addr_family.IP6, subaddr_family.MPLS_LABEL): RF_IPv6_MPLS,
    (addr_family.L2VPN, subaddr_family.EVPN): RF_L2_EVPN,
    (addr_family.IP, subaddr_family.IP_FLOWSPEC): RF_IPv4_FLOWSPEC,
    (addr_family.IP6, subaddr_family.IP_FLOWSPEC): RF_IPv6_FLOWSPEC,
    (addr_family.IP, subaddr_family.VPN_FLOWSPEC): RF_VPNv4_FLOWSPEC,
    (addr_family.IP6, subaddr_family.VPN_FLOWSPEC): RF_VPNv6_FLOWSPEC,
    (addr_family.L2VPN, subaddr_family.VPN_FLOWSPEC): RF_L2VPN_FLOWSPEC,
    (addr_family.IP, subaddr_family.ROUTE_TARGET_CONSTRAINTS): RF_RTC_UC
}


def get_rf(afi, safi):
    return _rf_map[(afi, safi)]


def pad(binary, len_):
    assert len(binary) <= len_
    return binary + b'\0' * (len_ - len(binary))


class _RouteDistinguisher(StringifyMixin, TypeDisp, _Value):
    _PACK_STR = '!H'
    TWO_OCTET_AS = 0
    IPV4_ADDRESS = 1
    FOUR_OCTET_AS = 2

    def __init__(self, admin=0, assigned=0, type_=None):
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.type = type_
        self.admin = admin
        self.assigned = assigned

    @classmethod
    def parser(cls, buf):
        assert len(buf) == 8
        (type_,) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        subcls = cls._lookup_type(type_)
        return subcls(**subcls.parse_value(rest))

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
        return subcls(admin=first, assigned=int(second))

    def serialize(self):
        value = self.serialize_value()
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type)
        return six.binary_type(buf + value)

    @property
    def formatted_str(self):
        return "%s:%s" % (self.admin, self.assigned)


@_RouteDistinguisher.register_type(_RouteDistinguisher.TWO_OCTET_AS)
class BGPTwoOctetAsRD(_RouteDistinguisher):
    _VALUE_PACK_STR = '!HI'
    _VALUE_FIELDS = ['admin', 'assigned']

    def __init__(self, **kwargs):
        super(BGPTwoOctetAsRD, self).__init__()
        self.do_init(BGPTwoOctetAsRD, self, kwargs)


@_RouteDistinguisher.register_type(_RouteDistinguisher.IPV4_ADDRESS)
class BGPIPv4AddressRD(_RouteDistinguisher):
    _VALUE_PACK_STR = '!4sH'
    _VALUE_FIELDS = ['admin', 'assigned']
    _TYPE = {
        'ascii': [
            'admin'
        ]
    }

    def __init__(self, **kwargs):
        super(BGPIPv4AddressRD, self).__init__()
        self.do_init(BGPIPv4AddressRD, self, kwargs)

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

    def __init__(self, **kwargs):
        super(BGPFourOctetAsRD, self).__init__()
        self.do_init(BGPFourOctetAsRD, self, kwargs)


@six.add_metaclass(abc.ABCMeta)
class _AddrPrefix(StringifyMixin):
    _PACK_STR = '!B'  # length

    def __init__(self, length, addr, prefixes=None, **kwargs):
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

    @classmethod
    @abc.abstractmethod
    def _to_bin(cls, addr):
        pass

    @classmethod
    @abc.abstractmethod
    def _from_bin(cls, addr):
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
    @classmethod
    def _to_bin(cls, addr):
        return addr

    @classmethod
    def _from_bin(cls, addr):
        return addr


class _LabelledAddrPrefix(_AddrPrefix):
    _LABEL_PACK_STR = '!3B'
    # RFC3107
    # 3. Carrying Label Mapping Information
    # The label information carried (as part of NLRI) in the Withdrawn
    # Routes field should be set to 0x800000.  (Of course, terminating the
    # BGP session also withdraws all the previously advertised routes.)
    #
    # RFC8227
    # 2.4 How to Explicitly Withdraw the Binding of a Label to a Prefix
    # [RFC3107] also made it possible to withdraw a binding without specifying
    # the label explicitly, by setting the Compatibility field to 0x800000.
    # However, some implementations set it to 0x000000. In order to ensure
    # backwards compatibility, it is RECOMMENDED by this document that the
    # Compatibility field be set to 0x800000, but it is REQUIRED that it be
    # ignored upon reception.
    #
    _WITHDRAW_LABELS = [0x800000, 0x000000]

    def __init__(self, length, addr, labels=None, **kwargs):
        labels = labels if labels else []
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
        return six.binary_type(buf)

    @classmethod
    def _label_from_bin(cls, label):
        (b1, b2, b3) = struct.unpack_from(cls._LABEL_PACK_STR,
                                          six.binary_type(label))
        rest = label[struct.calcsize(cls._LABEL_PACK_STR):]
        return (b1 << 16) | (b2 << 8) | b3, rest

    @classmethod
    def _to_bin(cls, addr):
        labels = addr[0]
        rest = addr[1:]
        labels = [x << 4 for x in labels]
        if labels and labels[-1] not in cls._WITHDRAW_LABELS:
            labels[-1] |= 1  # bottom of stack
        bin_labels = list(cls._label_to_bin(l) for l in labels)
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
                if label & 1 or label in cls._WITHDRAW_LABELS:
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
            if label & 1 or label in cls._WITHDRAW_LABELS:
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
        return addrconv.ipv4.bin_to_text(pad(addr, 4)),


class _IP6AddrPrefix(_AddrPrefix):
    @staticmethod
    def _prefix_to_bin(addr):
        (addr,) = addr
        return addrconv.ipv6.text_to_bin(addr)

    @staticmethod
    def _prefix_from_bin(addr):
        return addrconv.ipv6.bin_to_text(pad(addr, 16)),


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


class EvpnEsi(StringifyMixin, TypeDisp, _Value):
    """
    Ethernet Segment Identifier

    The supported ESI Types:

     - ``EvpnEsi.ARBITRARY`` indicates EvpnArbitraryEsi.

     - ``EvpnEsi.LACP`` indicates EvpnLACPEsi.

     - ``EvpnEsi.L2_BRIDGE`` indicates EvpnL2BridgeEsi.

     - ``EvpnEsi.MAC_BASED`` indicates EvpnMacBasedEsi.

     - ``EvpnEsi.ROUTER_ID`` indicates EvpnRouterIDEsi.

     - ``EvpnEsi.AS_BASED`` indicates EvpnASBasedEsi.
    """
    _PACK_STR = "!B"  # ESI Type
    _ESI_LEN = 10

    ARBITRARY = 0x00
    LACP = 0x01
    L2_BRIDGE = 0x02
    MAC_BASED = 0x03
    ROUTER_ID = 0x04
    AS_BASED = 0x05
    MAX = 0xff  # Reserved

    _TYPE_NAME = None  # must be defined in subclass

    def __init__(self, type_=None):
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.type = type_

    @classmethod
    def parser(cls, buf):
        (esi_type,) = struct.unpack_from(
            cls._PACK_STR, six.binary_type(buf))
        subcls = cls._lookup_type(esi_type)
        return subcls(**subcls.parse_value(buf[1:cls._ESI_LEN]))

    def serialize(self):
        buf = bytearray()
        msg_pack_into(EvpnEsi._PACK_STR, buf, 0, self.type)
        return six.binary_type(buf + self.serialize_value())

    @property
    def formatted_str(self):
        return '%s(%s)' % (
            self._TYPE_NAME,
            ','.join(str(getattr(self, v)) for v in self._VALUE_FIELDS))


@EvpnEsi.register_unknown_type()
class EvpnUnknownEsi(EvpnEsi):
    """
    ESI value for unknown type
    """
    _TYPE_NAME = 'unknown'
    _VALUE_PACK_STR = '!9s'
    _VALUE_FIELDS = ['value']

    def __init__(self, value, type_=None):
        super(EvpnUnknownEsi, self).__init__(type_)
        self.value = value

    @property
    def formatted_str(self):
        return '%s(%s)' % (self._TYPE_NAME, binary_str(self.value))


@EvpnEsi.register_type(EvpnEsi.ARBITRARY)
class EvpnArbitraryEsi(EvpnEsi):
    """
    Arbitrary 9-octet ESI value

    This type indicates an arbitrary 9-octet ESI value,
    which is managed and configured by the operator.
    """
    _TYPE_NAME = 'arbitrary'
    _VALUE_PACK_STR = '!9s'
    _VALUE_FIELDS = ['value']

    def __init__(self, value, type_=None):
        super(EvpnArbitraryEsi, self).__init__(type_)
        self.value = value

    @property
    def formatted_str(self):
        return '%s(%s)' % (self._TYPE_NAME, binary_str(self.value))


@EvpnEsi.register_type(EvpnEsi.LACP)
class EvpnLACPEsi(EvpnEsi):
    """
    ESI value for LACP

    When IEEE 802.1AX LACP is used between the PEs and CEs,
    this ESI type indicates an auto-generated ESI value
    determined from LACP.
    """
    _TYPE_NAME = 'lacp'
    _VALUE_PACK_STR = '!6sHx'
    _VALUE_FIELDS = ['mac_addr', 'port_key']
    _TYPE = {
        'ascii': [
            'mac_addr'
        ]
    }

    def __init__(self, mac_addr, port_key, type_=None):
        super(EvpnLACPEsi, self).__init__(type_)
        self.mac_addr = mac_addr
        self.port_key = port_key

    @classmethod
    def parse_value(cls, buf):
        (mac_addr, port_key) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'mac_addr': addrconv.mac.bin_to_text(mac_addr),
            'port_key': port_key,
        }

    def serialize_value(self):
        return struct.pack(
            self._VALUE_PACK_STR,
            addrconv.mac.text_to_bin(self.mac_addr), self.port_key)


@EvpnEsi.register_type(EvpnEsi.L2_BRIDGE)
class EvpnL2BridgeEsi(EvpnEsi):
    """
    ESI value for Layer 2 Bridge

    This type is used in the case of indirectly connected hosts
    via a bridged LAN between the CEs and the PEs.
    The ESI Value is auto-generated and determined based
    on the Layer 2 bridge protocol.
    """
    _TYPE_NAME = 'l2_bridge'
    _VALUE_PACK_STR = '!6sHx'
    _VALUE_FIELDS = ['mac_addr', 'priority']
    _TYPE = {
        'ascii': [
            'mac_addr'
        ]
    }

    def __init__(self, mac_addr, priority, type_=None):
        super(EvpnL2BridgeEsi, self).__init__(type_)
        self.mac_addr = mac_addr
        self.priority = priority

    @classmethod
    def parse_value(cls, buf):
        (mac_addr, priority) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'mac_addr': addrconv.mac.bin_to_text(mac_addr),
            'priority': priority,
        }

    def serialize_value(self):
        return struct.pack(
            self._VALUE_PACK_STR,
            addrconv.mac.text_to_bin(self.mac_addr), self.priority)


@EvpnEsi.register_type(EvpnEsi.MAC_BASED)
class EvpnMacBasedEsi(EvpnEsi):
    """
    MAC-based ESI Value

    This type indicates a MAC-based ESI Value that
    can be auto-generated or configured by the operator.
    """
    _TYPE_NAME = 'mac_based'
    _VALUE_PACK_STR = '!6s3s'
    _VALUE_FIELDS = ['mac_addr', 'local_disc']
    _TYPE = {
        'ascii': [
            'mac_addr'
        ]
    }

    def __init__(self, mac_addr, local_disc, type_=None):
        super(EvpnMacBasedEsi, self).__init__(type_)
        self.mac_addr = mac_addr
        self.local_disc = local_disc

    @classmethod
    def parse_value(cls, buf):
        (mac_addr, local_disc) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'mac_addr': addrconv.mac.bin_to_text(mac_addr),
            'local_disc': type_desc.Int3.to_user(local_disc),
        }

    def serialize_value(self):
        return struct.pack(
            self._VALUE_PACK_STR,
            addrconv.mac.text_to_bin(self.mac_addr),
            type_desc.Int3.from_user(self.local_disc))


@EvpnEsi.register_type(EvpnEsi.ROUTER_ID)
class EvpnRouterIDEsi(EvpnEsi):
    """
    Router-ID ESI Value

    This type indicates a router-ID ESI Value that
    can be auto-generated or configured by the operator.
    """
    _TYPE_NAME = 'router_id'
    _VALUE_PACK_STR = '!4sIx'
    _VALUE_FIELDS = ['router_id', 'local_disc']
    _TYPE = {
        'ascii': [
            'router_id'
        ]
    }

    def __init__(self, router_id, local_disc, type_=None):
        super(EvpnRouterIDEsi, self).__init__(type_)
        self.router_id = router_id
        self.local_disc = local_disc

    @classmethod
    def parse_value(cls, buf):
        (router_id, local_disc) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'router_id': addrconv.ipv4.bin_to_text(router_id),
            'local_disc': local_disc,
        }

    def serialize_value(self):
        return struct.pack(
            self._VALUE_PACK_STR,
            addrconv.ipv4.text_to_bin(self.router_id), self.local_disc)


@EvpnEsi.register_type(EvpnEsi.AS_BASED)
class EvpnASBasedEsi(EvpnEsi):
    """
    AS based ESI value

    This type indicates an Autonomous System(AS)-based
    ESI Value that can be auto-generated or configured by
    the operator.
    """
    _TYPE_NAME = 'as_based'
    _VALUE_PACK_STR = '!IIx'
    _VALUE_FIELDS = ['as_number', 'local_disc']

    def __init__(self, as_number, local_disc, type_=None):
        super(EvpnASBasedEsi, self).__init__(type_)
        self.as_number = as_number
        self.local_disc = local_disc


class EvpnNLRI(StringifyMixin, TypeDisp):
    """
    BGP Network Layer Reachability Information (NLRI) for EVPN
    """
    ROUTE_FAMILY = RF_L2_EVPN

    # EVPN NLRI:
    # +-----------------------------------+
    # |    Route Type (1 octet)           |
    # +-----------------------------------+
    # |     Length (1 octet)              |
    # +-----------------------------------+
    # | Route Type specific (variable)    |
    # +-----------------------------------+
    _PACK_STR = "!BB"
    _PACK_STR_SIZE = struct.calcsize(_PACK_STR)

    ETHERNET_AUTO_DISCOVERY = 0x01
    MAC_IP_ADVERTISEMENT = 0x02
    INCLUSIVE_MULTICAST_ETHERNET_TAG = 0x03
    ETHERNET_SEGMENT = 0x04
    IP_PREFIX_ROUTE = 0x05

    ROUTE_TYPE_NAME = None  # must be defined in subclass

    # Reserved value for Ethernet Tag ID.
    MAX_ET = 0xFFFFFFFF

    # Dictionary of ROUTE_TYPE_NAME to subclass.
    # e.g.)
    #   _NAMES = {'eth_ad': EvpnEthernetAutoDiscoveryNLRI, ...}
    _NAMES = {}

    # List of the fields considered to be part of the prefix in the NLRI.
    # This list should be defined in subclasses to format NLRI string
    # representation.
    NLRI_PREFIX_FIELDS = []

    def __init__(self, type_=None, length=None):
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.type = type_
        self.length = length
        self.route_dist = None  # should be initialized in subclass

    @classmethod
    def register_type(cls, type_):
        cls._TYPES = cls._TYPES.copy()
        cls._NAMES = cls._NAMES.copy()

        def _register_type(subcls):
            cls._TYPES[type_] = subcls
            cls._NAMES[subcls.ROUTE_TYPE_NAME] = subcls
            cls._REV_TYPES = None
            return subcls

        return _register_type

    @classmethod
    def _lookup_type_name(cls, type_name):
        try:
            return cls._NAMES[type_name]
        except KeyError:
            return EvpnUnknownNLRI

    @classmethod
    def parser(cls, buf):
        (route_type, length) = struct.unpack_from(
            cls._PACK_STR, six.binary_type(buf))
        offset = cls._PACK_STR_SIZE + length
        subcls = cls._lookup_type(route_type)
        values = subcls.parse_value(buf[cls._PACK_STR_SIZE:offset])
        return subcls(type_=route_type, length=length,
                      **values), buf[offset:]

    def serialize_value(self):
        # Overrided in subclass
        return b''

    def serialize(self):
        value_bin = self.serialize_value()
        # fixup
        self.length = len(value_bin)
        return struct.pack(EvpnNLRI._PACK_STR,
                           self.type, self.length) + value_bin

    @staticmethod
    def _rd_from_bin(buf):
        return _RouteDistinguisher.parser(buf[:8]), buf[8:]

    @staticmethod
    def _rd_to_bin(rd):
        return six.binary_type(rd.serialize())

    @staticmethod
    def _esi_from_bin(buf):
        return EvpnEsi.parser(buf[:10]), buf[10:]

    @staticmethod
    def _esi_to_bin(esi):
        return esi.serialize()

    @staticmethod
    def _ethernet_tag_id_from_bin(buf):
        return type_desc.Int4.to_user(six.binary_type(buf[:4])), buf[4:]

    @staticmethod
    def _ethernet_tag_id_to_bin(tag_id):
        return type_desc.Int4.from_user(tag_id)

    @staticmethod
    def _mac_addr_len_from_bin(buf):
        return type_desc.Int1.to_user(six.binary_type(buf[:1])), buf[1:]

    @staticmethod
    def _mac_addr_len_to_bin(mac_len):
        return type_desc.Int1.from_user(mac_len)

    @staticmethod
    def _mac_addr_from_bin(buf, mac_len):
        mac_len //= 8
        return addrconv.mac.bin_to_text(buf[:mac_len]), buf[mac_len:]

    @staticmethod
    def _mac_addr_to_bin(mac_addr):
        return addrconv.mac.text_to_bin(mac_addr)

    @staticmethod
    def _ip_addr_len_from_bin(buf):
        return type_desc.Int1.to_user(six.binary_type(buf[:1])), buf[1:]

    @staticmethod
    def _ip_addr_len_to_bin(ip_len):
        return type_desc.Int1.from_user(ip_len)

    @staticmethod
    def _ip_addr_from_bin(buf, ip_len):
        return ip.bin_to_text(buf[:ip_len]), buf[ip_len:]

    @staticmethod
    def _ip_addr_to_bin(ip_addr):
        return ip.text_to_bin(ip_addr)

    @staticmethod
    def _mpls_label_from_bin(buf):
        mpls_label, is_bos = mpls.label_from_bin(buf)
        rest = buf[3:]
        return mpls_label, rest, is_bos

    @staticmethod
    def _mpls_label_to_bin(label, is_bos=True):
        return mpls.label_to_bin(label, is_bos=is_bos)

    @staticmethod
    def _vni_from_bin(buf):
        return vxlan.vni_from_bin(six.binary_type(buf[:3])), buf[3:]

    @staticmethod
    def _vni_to_bin(vni):
        return vxlan.vni_to_bin(vni)

    @property
    def prefix(self):
        def _format(i):
            pairs = []
            for k in i.NLRI_PREFIX_FIELDS:
                v = getattr(i, k)
                if k == 'esi':
                    pairs.append('%s:%s' % (k, v.formatted_str))
                else:
                    pairs.append('%s:%s' % (k, v))
            return ','.join(pairs)

        return '%s(%s)' % (self.ROUTE_TYPE_NAME, _format(self))

    @property
    def formatted_nlri_str(self):
        return '%s:%s' % (self.route_dist, self.prefix)


@EvpnNLRI.register_unknown_type()
class EvpnUnknownNLRI(EvpnNLRI):
    """
    Unknown route type specific EVPN NLRI
    """
    ROUTE_TYPE_NAME = 'unknown'
    NLRI_PREFIX_FIELDS = ['value']

    def __init__(self, value, type_, length=None):
        super(EvpnUnknownNLRI, self).__init__(type_, length)
        self.value = value

    @classmethod
    def parse_value(cls, buf):
        return {
            'value': buf
        }

    def serialize_value(self):
        return self.value

    @property
    def formatted_nlri_str(self):
        return '%s(%s)' % (self.ROUTE_TYPE_NAME, binary_str(self.value))


@EvpnNLRI.register_type(EvpnNLRI.ETHERNET_AUTO_DISCOVERY)
class EvpnEthernetAutoDiscoveryNLRI(EvpnNLRI):
    """
    Ethernet A-D route type specific EVPN NLRI
    """
    ROUTE_TYPE_NAME = 'eth_ad'

    # +---------------------------------------+
    # |  Route Distinguisher (RD) (8 octets)  |
    # +---------------------------------------+
    # |Ethernet Segment Identifier (10 octets)|
    # +---------------------------------------+
    # |  Ethernet Tag ID (4 octets)           |
    # +---------------------------------------+
    # |  MPLS Label (3 octets)                |
    # +---------------------------------------+
    _PACK_STR = "!8s10sI3s"
    NLRI_PREFIX_FIELDS = ['esi', 'ethernet_tag_id']
    _TYPE = {
        'ascii': [
            'route_dist',
        ]
    }

    def __init__(self, route_dist, esi, ethernet_tag_id,
                 mpls_label=None, vni=None, label=None,
                 type_=None, length=None):
        super(EvpnEthernetAutoDiscoveryNLRI, self).__init__(type_, length)
        self.route_dist = route_dist
        self.esi = esi
        self.ethernet_tag_id = ethernet_tag_id
        if label:
            # If binary type label field value is specified, stores it
            # and decodes as MPLS label and VNI.
            self._label = label
            self._mpls_label, _, _ = self._mpls_label_from_bin(label)
            self._vni, _ = self._vni_from_bin(label)
        else:
            # If either MPLS label or VNI is specified, stores it
            # and encodes into binary type label field value.
            self._label = self._serialize_label(mpls_label, vni)
            self._mpls_label = mpls_label
            self._vni = vni

    def _serialize_label(self, mpls_label, vni):
        if mpls_label:
            return self._mpls_label_to_bin(mpls_label, is_bos=True)
        elif vni:
            return self._vni_to_bin(vni)
        else:
            return b'\x00' * 3

    @classmethod
    def parse_value(cls, buf):
        route_dist, rest = cls._rd_from_bin(buf)
        esi, rest = cls._esi_from_bin(rest)
        ethernet_tag_id, rest = cls._ethernet_tag_id_from_bin(rest)

        return {
            'route_dist': route_dist.formatted_str,
            'esi': esi,
            'ethernet_tag_id': ethernet_tag_id,
            'label': rest,
        }

    def serialize_value(self):
        route_dist = _RouteDistinguisher.from_str(self.route_dist)
        return struct.pack(
            self._PACK_STR, route_dist.serialize(), self.esi.serialize(),
            self.ethernet_tag_id, self._label)

    @property
    def mpls_label(self):
        return self._mpls_label

    @mpls_label.setter
    def mpls_label(self, mpls_label):
        self._label = self._mpls_label_to_bin(mpls_label, is_bos=True)
        self._mpls_label = mpls_label
        self._vni = None  # disables VNI

    @property
    def vni(self):
        return self._vni

    @vni.setter
    def vni(self, vni):
        self._label = self._vni_to_bin(vni)
        self._mpls_label = None  # disables MPLS label
        self._vni = vni

    @property
    def label_list(self):
        return [self.mpls_label]


@EvpnNLRI.register_type(EvpnNLRI.MAC_IP_ADVERTISEMENT)
class EvpnMacIPAdvertisementNLRI(EvpnNLRI):
    """
    MAC/IP Advertisement route type specific EVPN NLRI
    """
    ROUTE_TYPE_NAME = 'mac_ip_adv'

    # +---------------------------------------+
    # |  RD (8 octets)                        |
    # +---------------------------------------+
    # |Ethernet Segment Identifier (10 octets)|
    # +---------------------------------------+
    # |  Ethernet Tag ID (4 octets)           |
    # +---------------------------------------+
    # |  MAC Address Length (1 octet)         |
    # +---------------------------------------+
    # |  MAC Address (6 octets)               |
    # +---------------------------------------+
    # |  IP Address Length (1 octet)          |
    # +---------------------------------------+
    # |  IP Address (0, 4, or 16 octets)      |
    # +---------------------------------------+
    # |  MPLS Label1 (3 octets)               |
    # +---------------------------------------+
    # |  MPLS Label2 (0 or 3 octets)          |
    # +---------------------------------------+
    _PACK_STR = "!8s10sIB6sB%ds%ds"
    # Note: mac_addr_len and ip_addr_len are omitted for readability.
    NLRI_PREFIX_FIELDS = ['ethernet_tag_id', 'mac_addr', 'ip_addr']
    _TYPE = {
        'ascii': [
            'route_dist',
            'mac_addr',
            'ip_addr',
        ]
    }

    def __init__(self, route_dist, ethernet_tag_id, mac_addr, ip_addr,
                 esi=None, mpls_labels=None, vni=None, labels=None,
                 mac_addr_len=None, ip_addr_len=None,
                 type_=None, length=None):
        super(EvpnMacIPAdvertisementNLRI, self).__init__(type_, length)
        self.route_dist = route_dist
        self.esi = esi
        self.ethernet_tag_id = ethernet_tag_id
        self.mac_addr_len = mac_addr_len
        self.mac_addr = mac_addr
        self.ip_addr_len = ip_addr_len
        self.ip_addr = ip_addr
        if labels:
            # If binary type labels field value is specified, stores it
            # and decodes as MPLS labels and VNI.
            self._mpls_labels, self._vni = self._parse_labels(labels)
            self._labels = labels
        else:
            # If either MPLS labels or VNI is specified, stores it
            # and encodes into binary type labels field value.
            self._labels = self._serialize_labels(mpls_labels, vni)
            self._mpls_labels = mpls_labels
            self._vni = vni

    def _parse_labels(self, labels):
        mpls_label1, rest, is_bos = self._mpls_label_from_bin(labels)
        mpls_labels = [mpls_label1]
        if rest and not is_bos:
            mpls_label2, rest, _ = self._mpls_label_from_bin(rest)
            mpls_labels.append(mpls_label2)
        vni, _ = self._vni_from_bin(labels)
        return mpls_labels, vni

    def _serialize_labels(self, mpls_labels, vni):
        if mpls_labels:
            return self._serialize_mpls_labels(mpls_labels)
        elif vni:
            return self._vni_to_bin(vni)
        else:
            return b'\x00' * 3

    def _serialize_mpls_labels(self, mpls_labels):
        if len(mpls_labels) == 1:
            return self._mpls_label_to_bin(mpls_labels[0], is_bos=True)
        elif len(mpls_labels) == 2:
            return (self._mpls_label_to_bin(mpls_labels[0], is_bos=False) +
                    self._mpls_label_to_bin(mpls_labels[1], is_bos=True))
        else:
            return b'\x00' * 3

    @classmethod
    def parse_value(cls, buf):
        route_dist, rest = cls._rd_from_bin(buf)
        esi, rest = cls._esi_from_bin(rest)
        ethernet_tag_id, rest = cls._ethernet_tag_id_from_bin(rest)
        mac_addr_len, rest = cls._mac_addr_len_from_bin(rest)
        mac_addr, rest = cls._mac_addr_from_bin(rest, mac_addr_len)
        ip_addr_len, rest = cls._ip_addr_len_from_bin(rest)
        if ip_addr_len != 0:
            ip_addr, rest = cls._ip_addr_from_bin(rest, ip_addr_len // 8)
        else:
            ip_addr = None

        return {
            'route_dist': route_dist.formatted_str,
            'esi': esi,
            'ethernet_tag_id': ethernet_tag_id,
            'mac_addr_len': mac_addr_len,
            'mac_addr': mac_addr,
            'ip_addr_len': ip_addr_len,
            'ip_addr': ip_addr,
            'labels': rest,
        }

    def serialize_value(self):
        route_dist = _RouteDistinguisher.from_str(self.route_dist)
        mac_addr = self._mac_addr_to_bin(self.mac_addr)
        self.mac_addr_len = len(mac_addr) * 8  # fixup
        if self.ip_addr:
            ip_addr = self._ip_addr_to_bin(self.ip_addr)
        else:
            ip_addr = b''
        ip_addr_len = len(ip_addr)
        self.ip_addr_len = ip_addr_len * 8  # fixup

        return struct.pack(
            self._PACK_STR % (ip_addr_len, len(self._labels)),
            route_dist.serialize(), self.esi.serialize(),
            self.ethernet_tag_id,
            self.mac_addr_len, mac_addr,
            self.ip_addr_len, ip_addr,
            self._labels)

    @property
    def mpls_labels(self):
        return self._mpls_labels

    @mpls_labels.setter
    def mpls_labels(self, mpls_labels):
        self._labels = self._serialize_mpls_labels(mpls_labels)
        self._mpls_labels = mpls_labels
        self._vni = None  # disables VNI

    @property
    def vni(self):
        return self._vni

    @vni.setter
    def vni(self, vni):
        self._labels = self._vni_to_bin(vni)
        self._mpls_labels = None  # disables MPLS labels
        self._vni = vni

    @property
    def label_list(self):
        return self.mpls_labels


@EvpnNLRI.register_type(EvpnNLRI.INCLUSIVE_MULTICAST_ETHERNET_TAG)
class EvpnInclusiveMulticastEthernetTagNLRI(EvpnNLRI):
    """
    Inclusive Multicast Ethernet Tag route type specific EVPN NLRI
    """
    ROUTE_TYPE_NAME = 'multicast_etag'

    # +---------------------------------------+
    # |  RD (8 octets)                        |
    # +---------------------------------------+
    # |  Ethernet Tag ID (4 octets)           |
    # +---------------------------------------+
    # |  IP Address Length (1 octet)          |
    # +---------------------------------------+
    # |  Originating Router's IP Address      |
    # |          (4 or 16 octets)             |
    # +---------------------------------------+
    _PACK_STR = '!8sIB%ds'
    NLRI_PREFIX_FIELDS = ['ethernet_tag_id', 'ip_addr']
    _TYPE = {
        'ascii': [
            'route_dist',
            'ip_addr',
        ]
    }

    def __init__(self, route_dist, ethernet_tag_id, ip_addr,
                 ip_addr_len=None, type_=None, length=None):
        super(EvpnInclusiveMulticastEthernetTagNLRI,
              self).__init__(type_, length)
        self.route_dist = route_dist
        self.ethernet_tag_id = ethernet_tag_id
        self.ip_addr_len = ip_addr_len
        self.ip_addr = ip_addr

    @classmethod
    def parse_value(cls, buf):
        route_dist, rest = cls._rd_from_bin(buf)
        ethernet_tag_id, rest = cls._ethernet_tag_id_from_bin(rest)
        ip_addr_len, rest = cls._ip_addr_len_from_bin(rest)
        ip_addr, rest = cls._ip_addr_from_bin(rest, ip_addr_len // 8)

        return {
            'route_dist': route_dist.formatted_str,
            'ethernet_tag_id': ethernet_tag_id,
            'ip_addr_len': ip_addr_len,
            'ip_addr': ip_addr,
        }

    def serialize_value(self):
        route_dist = _RouteDistinguisher.from_str(self.route_dist)
        ip_addr = self._ip_addr_to_bin(self.ip_addr)
        self.ip_addr_len = len(ip_addr) * 8  # fixup

        return struct.pack(
            self._PACK_STR % len(ip_addr),
            route_dist.serialize(), self.ethernet_tag_id,
            self.ip_addr_len, ip_addr)


@EvpnNLRI.register_type(EvpnNLRI.ETHERNET_SEGMENT)
class EvpnEthernetSegmentNLRI(EvpnNLRI):
    """
    Ethernet Segment route type specific EVPN NLRI
    """
    ROUTE_TYPE_NAME = 'eth_seg'

    # +---------------------------------------+
    # |  RD (8 octets)                        |
    # +---------------------------------------+
    # |Ethernet Segment Identifier (10 octets)|
    # +---------------------------------------+
    # |  IP Address Length (1 octet)          |
    # +---------------------------------------+
    # |  Originating Router's IP Address      |
    # |          (4 or 16 octets)             |
    # +---------------------------------------+
    _PACK_STR = '!8s10sB%ds'
    NLRI_PREFIX_FIELDS = ['esi', 'ip_addr']
    _TYPE = {
        'ascii': [
            'route_dist',
            'ip_addr',
        ]
    }

    def __init__(self, route_dist, esi, ip_addr, ip_addr_len=None,
                 type_=None, length=None):
        super(EvpnEthernetSegmentNLRI, self).__init__(type_, length)
        self.route_dist = route_dist
        self.esi = esi
        self.ip_addr_len = ip_addr_len
        self.ip_addr = ip_addr

    @classmethod
    def parse_value(cls, buf):
        route_dist, rest = cls._rd_from_bin(buf)
        esi, rest = cls._esi_from_bin(rest)
        ip_addr_len, rest = cls._ip_addr_len_from_bin(rest)
        ip_addr, rest = cls._ip_addr_from_bin(rest, ip_addr_len // 8)

        return {
            'route_dist': route_dist.formatted_str,
            'esi': esi,
            'ip_addr_len': ip_addr_len,
            'ip_addr': ip_addr,
        }

    def serialize_value(self):
        route_dist = _RouteDistinguisher.from_str(self.route_dist)
        ip_addr = self._ip_addr_to_bin(self.ip_addr)
        # fixup
        self.ip_addr_len = len(ip_addr) * 8

        return struct.pack(
            self._PACK_STR % len(ip_addr),
            route_dist.serialize(), self.esi.serialize(),
            self.ip_addr_len, ip_addr)


@EvpnNLRI.register_type(EvpnNLRI.IP_PREFIX_ROUTE)
class EvpnIpPrefixNLRI(EvpnNLRI):
    """
    IP Prefix advertisement route NLRI
    """
    ROUTE_TYPE_NAME = 'ip_prefix'

    # +---------------------------------------+
    # |      RD   (8 octets)                  |
    # +---------------------------------------+
    # |Ethernet Segment Identifier (10 octets)|
    # +---------------------------------------+
    # |  Ethernet Tag ID (4 octets)           |
    # +---------------------------------------+
    # |  IP Prefix Length (1 octet)           |
    # +---------------------------------------+
    # |  IP Prefix (4 or 16 octets)           |
    # +---------------------------------------+
    # |  GW IP Address (4 or 16 octets)       |
    # +---------------------------------------+
    # |  MPLS Label (3 octets)                |
    # +---------------------------------------+
    _PACK_STR = '!8s10sIB%ds%ds3s'
    NLRI_PREFIX_FIELDS = ['ethernet_tag_id', 'ip_prefix']
    _TYPE = {
        'ascii': [
            'route_dist',
            'ip_prefix',
            'gw_ip_addr'
        ]
    }
    _LABEL_LEN = 3

    def __init__(self, route_dist, ethernet_tag_id, ip_prefix,
                 esi=None, gw_ip_addr=None,
                 mpls_label=None, vni=None, label=None,
                 type_=None, length=None):
        super(EvpnIpPrefixNLRI, self).__init__(type_, length)
        self.route_dist = route_dist
        self.esi = esi
        self.ethernet_tag_id = ethernet_tag_id
        self._ip_prefix = None
        self._ip_prefix_len = None
        self.ip_prefix = ip_prefix

        if gw_ip_addr is None:
            if ':' not in self._ip_prefix:
                self.gw_ip_addr = '0.0.0.0'
            else:
                self.gw_ip_addr = '::'
        else:
            self.gw_ip_addr = gw_ip_addr

        if label:
            # If binary type label field value is specified, stores it
            # and decodes as MPLS label and VNI.
            self._label = label
            self._mpls_label, _, _ = self._mpls_label_from_bin(label)
            self._vni, _ = self._vni_from_bin(label)
        else:
            # If either MPLS label or VNI is specified, stores it
            # and encodes into binary type label field value.
            self._label = self._serialize_label(mpls_label, vni)
            self._mpls_label = mpls_label
            self._vni = vni

    def _serialize_label(self, mpls_label, vni):
        if mpls_label:
            return self._mpls_label_to_bin(mpls_label, is_bos=True)
        elif vni:
            return vxlan.vni_to_bin(vni)
        else:
            return b'\x00' * 3

    @classmethod
    def parse_value(cls, buf):
        route_dist, rest = cls._rd_from_bin(buf)
        esi, rest = cls._esi_from_bin(rest)
        ethernet_tag_id, rest = cls._ethernet_tag_id_from_bin(rest)
        ip_prefix_len, rest = cls._ip_addr_len_from_bin(rest)
        _len = (len(rest) - cls._LABEL_LEN) // 2
        ip_prefix, rest = cls._ip_addr_from_bin(rest, _len)
        gw_ip_addr, rest = cls._ip_addr_from_bin(rest, _len)

        return {
            'route_dist': route_dist.formatted_str,
            'esi': esi,
            'ethernet_tag_id': ethernet_tag_id,
            'ip_prefix': '%s/%s' % (ip_prefix, ip_prefix_len),
            'gw_ip_addr': gw_ip_addr,
            'label': rest,
        }

    def serialize_value(self):
        route_dist = _RouteDistinguisher.from_str(self.route_dist)
        ip_prefix = self._ip_addr_to_bin(self._ip_prefix)
        gw_ip_addr = self._ip_addr_to_bin(self.gw_ip_addr)

        return struct.pack(
            self._PACK_STR % (len(ip_prefix), len(gw_ip_addr)),
            route_dist.serialize(), self.esi.serialize(),
            self.ethernet_tag_id, self._ip_prefix_len, ip_prefix,
            gw_ip_addr, self._label)

    @property
    def ip_prefix(self):
        return '%s/%s' % (self._ip_prefix, self._ip_prefix_len)

    @ip_prefix.setter
    def ip_prefix(self, ip_prefix):
        self._ip_prefix, ip_prefix_len = ip_prefix.split('/')
        self._ip_prefix_len = int(ip_prefix_len)

    @property
    def mpls_label(self):
        return self._mpls_label

    @mpls_label.setter
    def mpls_label(self, mpls_label):
        self._label = self._mpls_label_to_bin(mpls_label, is_bos=True)
        self._mpls_label = mpls_label
        self._vni = None  # disables VNI

    @property
    def vni(self):
        return self._vni

    @vni.setter
    def vni(self, vni):
        self._label = self._vni_to_bin(vni)
        self._mpls_label = None  # disables MPLS label
        self._vni = vni

    @property
    def label_list(self):
        return [self.mpls_label]


class _FlowSpecNLRIBase(StringifyMixin, TypeDisp):
    """
    Base class for Flow Specification NLRI
    """

    # flow-spec NLRI:
    # +-----------------------------------+
    # |    length (0xnn or 0xfn nn)       |
    # +-----------------------------------+
    # |     NLRI value  (variable)        |
    # +-----------------------------------+
    ROUTE_FAMILY = None
    _LENGTH_SHORT_FMT = '!B'
    LENGTH_SHORT_SIZE = struct.calcsize(_LENGTH_SHORT_FMT)
    _LENGTH_LONG_FMT = '!H'
    LENGTH_LONG_SIZE = struct.calcsize(_LENGTH_LONG_FMT)
    _LENGTH_THRESHOLD = 0xf000
    FLOWSPEC_FAMILY = ''

    def __init__(self, length=0, rules=None):
        self.length = length
        rules = rules or []
        for r in rules:
            assert isinstance(r, _FlowSpecComponentBase)
        self.rules = rules

    @classmethod
    def parser(cls, buf):
        (length,) = struct.unpack_from(
            cls._LENGTH_LONG_FMT, six.binary_type(buf))

        if length < cls._LENGTH_THRESHOLD:
            length >>= 8
            offset = cls.LENGTH_SHORT_SIZE
        else:
            offset = cls.LENGTH_LONG_SIZE

        kwargs = {'length': length}
        rest = buf[offset:offset + length]

        if cls.ROUTE_FAMILY.safi == subaddr_family.VPN_FLOWSPEC:
            route_dist = _RouteDistinguisher.parser(rest[:8])
            kwargs['route_dist'] = route_dist.formatted_str
            rest = rest[8:]

        rules = []

        while rest:
            subcls, rest = _FlowSpecComponentBase.parse_header(
                rest, cls.ROUTE_FAMILY.afi)

            while rest:
                rule, rest = subcls.parse_body(rest)
                rules.append(rule)

                if (not isinstance(rule, _FlowSpecOperatorBase) or
                        rule.operator & rule.END_OF_LIST):
                    break

        kwargs['rules'] = rules

        return cls(**kwargs), rest

    def serialize(self):
        rules_bin = b''

        if self.ROUTE_FAMILY.safi == subaddr_family.VPN_FLOWSPEC:
            route_dist = _RouteDistinguisher.from_str(self.route_dist)
            rules_bin += route_dist.serialize()

        self.rules.sort(key=lambda x: x.type)
        for _, rules in itertools.groupby(self.rules, key=lambda x: x.type):
            rules = list(rules)
            rules_bin += rules[0].serialize_header()

            if isinstance(rules[-1], _FlowSpecOperatorBase):
                rules[-1].operator |= rules[-1].END_OF_LIST

            for r in rules:
                rules_bin += r.serialize_body()

        self.length = len(rules_bin)

        if self.length < self._LENGTH_THRESHOLD:
            buf = struct.pack(self._LENGTH_SHORT_FMT, self.length)
        else:
            buf = struct.pack(self._LENGTH_LONG_FMT, self.length)

        return buf + rules_bin

    @classmethod
    def _from_user(cls, **kwargs):
        rules = []
        for k, v in kwargs.items():
            subcls = _FlowSpecComponentBase.lookup_type_name(
                k, cls.ROUTE_FAMILY.afi)
            rule = subcls.from_str(str(v))
            rules.extend(rule)
        rules.sort(key=lambda x: x.type)
        return cls(rules=rules)

    @property
    def prefix(self):
        def _format(i):
            pairs = []
            i.rules.sort(key=lambda x: x.type)
            previous_type = None
            for r in i.rules:
                if r.type == previous_type:
                    if r.to_str()[0] != '&':
                        pairs[-1] += '|'
                    pairs[-1] += r.to_str()
                else:
                    pairs.append('%s:%s' % (r.COMPONENT_NAME, r.to_str()))
                previous_type = r.type

            return ','.join(pairs)

        return '%s(%s)' % (self.FLOWSPEC_FAMILY, _format(self))

    @property
    def formatted_nlri_str(self):
        return self.prefix


class FlowSpecIPv4NLRI(_FlowSpecNLRIBase):
    """
    Flow Specification NLRI class for IPv4 [RFC 5575]
    """
    ROUTE_FAMILY = RF_IPv4_FLOWSPEC
    FLOWSPEC_FAMILY = 'ipv4fs'

    @classmethod
    def from_user(cls, **kwargs):
        """
        Utility method for creating a NLRI instance.

        This function returns a NLRI instance from human readable format value.

        :param kwargs: The following arguments are available.

        =========== ============= ========= ==============================
        Argument    Value         Operator  Description
        =========== ============= ========= ==============================
        dst_prefix  IPv4 Prefix   Nothing   Destination Prefix.
        src_prefix  IPv4 Prefix   Nothing   Source Prefix.
        ip_proto    Integer       Numeric   IP Protocol.
        port        Integer       Numeric   Port number.
        dst_port    Integer       Numeric   Destination port number.
        src_port    Integer       Numeric   Source port number.
        icmp_type   Integer       Numeric   ICMP type.
        icmp_code   Integer       Numeric   ICMP code.
        tcp_flags   Fixed string  Bitmask   TCP flags.
                                            Supported values are
                                            ``CWR``, ``ECN``, ``URGENT``,
                                            ``ACK``, ``PUSH``, ``RST``,
                                            ``SYN`` and ``FIN``.
        packet_len  Integer       Numeric   Packet length.
        dscp        Integer       Numeric   Differentiated Services
                                            Code Point.
        fragment    Fixed string  Bitmask   Fragment.
                                            Supported values are
                                            ``DF`` (Don't fragment),
                                            ``ISF`` (Is a fragment),
                                            ``FF`` (First fragment) and
                                            ``LF`` (Last fragment)
        =========== ============= ========= ==============================

        Example::

            >>> msg = bgp.FlowSpecIPv4NLRI.from_user(
            ...     dst_prefix='10.0.0.0/24',
            ...     src_prefix='20.0.0.1/24',
            ...     ip_proto=6,
            ...     port='80 | 8000',
            ...     dst_port='>9000 & <9050',
            ...     src_port='>=8500 & <=9000',
            ...     icmp_type=0,
            ...     icmp_code=6,
            ...     tcp_flags='SYN+ACK & !=URGENT',
            ...     packet_len=1000,
            ...     dscp='22 | 24',
            ...     fragment='LF | ==FF')
            >>>

        You can specify conditions with the following keywords.

        The following keywords can be used when the operator type is Numeric.

        ========== ============================================================
        Keyword    Description
        ========== ============================================================
        <          Less than comparison between data and value.
        <=         Less than or equal to comparison between data and value.
        >          Greater than comparison between data and value.
        >=         Greater than or equal to comparison between data and value.
        ==         Equality between data and value.
                   This operator can be omitted.
        ========== ============================================================

        The following keywords can be used when the operator type is Bitmask.

        ========== ================================================
        Keyword    Description
        ========== ================================================
        !=         Not equal operation.
        ==         Exact match operation if specified.
                   Otherwise partial match operation.
        `+`        Used for the summation of bitmask values.
                   (e.g., SYN+ACK)
        ========== ================================================

        You can combine the multiple conditions with the following operators.

        ========== =======================================
        Keyword    Description
        ========== =======================================
        `|`        Logical OR operation
        &          Logical AND operation
        ========== =======================================

        :return: A instance of FlowSpecVPNv4NLRI.
        """
        return cls._from_user(**kwargs)


class FlowSpecVPNv4NLRI(_FlowSpecNLRIBase):
    """
    Flow Specification NLRI class for VPNv4 [RFC 5575]
    """

    # flow-spec NLRI:
    # +-----------------------------------+
    # |    length (0xnn or 0xfn nn)       |
    # +-----------------------------------+
    # |     RD   (8 octets)               |
    # +-----------------------------------+
    # |     NLRI value  (variable)        |
    # +-----------------------------------+
    ROUTE_FAMILY = RF_VPNv4_FLOWSPEC
    FLOWSPEC_FAMILY = 'vpnv4fs'

    def __init__(self, length=0, route_dist=None, rules=None):
        super(FlowSpecVPNv4NLRI, self).__init__(length, rules)
        assert route_dist is not None
        self.route_dist = route_dist

    @classmethod
    def _from_user(cls, route_dist, **kwargs):
        rules = []
        for k, v in kwargs.items():
            subcls = _FlowSpecComponentBase.lookup_type_name(
                k, cls.ROUTE_FAMILY.afi)
            rule = subcls.from_str(str(v))
            rules.extend(rule)
        rules.sort(key=lambda x: x.type)
        return cls(route_dist=route_dist, rules=rules)

    @classmethod
    def from_user(cls, route_dist, **kwargs):
        """
        Utility method for creating a NLRI instance.

        This function returns a NLRI instance from human readable format value.

        :param route_dist: Route Distinguisher.
        :param kwargs: See :py:mod:`ryu.lib.packet.bgp.FlowSpecIPv4NLRI`

        Example::

            >>> msg = bgp.FlowSpecIPv4NLRI.from_user(
            ...     route_dist='65000:1000',
            ...     dst_prefix='10.0.0.0/24',
            ...     src_prefix='20.0.0.1/24',
            ...     ip_proto=6,
            ...     port='80 | 8000',
            ...     dst_port='>9000 & <9050',
            ...     src_port='>=8500 & <=9000',
            ...     icmp_type=0,
            ...     icmp_code=6,
            ...     tcp_flags='SYN+ACK & !=URGENT',
            ...     packet_len=1000,
            ...     dscp='22 | 24',
            ...     fragment='LF | ==FF')
            >>>
        """
        return cls._from_user(route_dist, **kwargs)

    @property
    def formatted_nlri_str(self):
        return '%s:%s' % (self.route_dist, self.prefix)


class FlowSpecIPv6NLRI(_FlowSpecNLRIBase):
    """
    Flow Specification NLRI class for IPv6 [RFC draft-ietf-idr-flow-spec-v6-08]
    """
    ROUTE_FAMILY = RF_IPv6_FLOWSPEC
    FLOWSPEC_FAMILY = 'ipv6fs'

    @classmethod
    def from_user(cls, **kwargs):
        """
        Utility method for creating a NLRI instance.

        This function returns a NLRI instance from human readable format value.

        :param kwargs: The following arguments are available.

        =========== ============= ========= ==============================
        Argument    Value         Operator  Description
        =========== ============= ========= ==============================
        dst_prefix  IPv6 Prefix   Nothing   Destination Prefix.
        src_prefix  IPv6 Prefix   Nothing   Source Prefix.
        next_header Integer       Numeric   Next Header.
        port        Integer       Numeric   Port number.
        dst_port    Integer       Numeric   Destination port number.
        src_port    Integer       Numeric   Source port number.
        icmp_type   Integer       Numeric   ICMP type.
        icmp_code   Integer       Numeric   ICMP code.
        tcp_flags   Fixed string  Bitmask   TCP flags.
                                            Supported values are
                                            ``CWR``, ``ECN``, ``URGENT``,
                                            ``ACK``, ``PUSH``, ``RST``,
                                            ``SYN`` and ``FIN``.
        packet_len  Integer       Numeric   Packet length.
        dscp        Integer       Numeric   Differentiated Services
                                            Code Point.
        fragment    Fixed string  Bitmask   Fragment.
                                            Supported values are
                                            ``ISF`` (Is a fragment),
                                            ``FF`` (First fragment) and
                                            ``LF`` (Last fragment)
        flow_label   Intefer      Numeric   Flow Label.
        =========== ============= ========= ==============================

        .. Note::

            For ``dst_prefix`` and ``src_prefix``, you can give "offset" value
            like this: ``2001::2/128/32``. At this case, ``offset`` is 32.
            ``offset`` can be omitted, then ``offset`` is treated as 0.
        """
        return cls._from_user(**kwargs)


class FlowSpecVPNv6NLRI(_FlowSpecNLRIBase):
    """
    Flow Specification NLRI class for VPNv6 [draft-ietf-idr-flow-spec-v6-08]
    """

    # flow-spec NLRI:
    # +-----------------------------------+
    # |    length (0xnn or 0xfn nn)       |
    # +-----------------------------------+
    # |     RD   (8 octets)               |
    # +-----------------------------------+
    # |     NLRI value  (variable)        |
    # +-----------------------------------+
    ROUTE_FAMILY = RF_VPNv6_FLOWSPEC
    FLOWSPEC_FAMILY = 'vpnv6fs'

    def __init__(self, length=0, route_dist=None, rules=None):
        super(FlowSpecVPNv6NLRI, self).__init__(length, rules)
        assert route_dist is not None
        self.route_dist = route_dist

    @classmethod
    def _from_user(cls, route_dist, **kwargs):
        rules = []
        for k, v in kwargs.items():
            subcls = _FlowSpecComponentBase.lookup_type_name(
                k, cls.ROUTE_FAMILY.afi)
            rule = subcls.from_str(str(v))
            rules.extend(rule)
        rules.sort(key=lambda x: x.type)
        return cls(route_dist=route_dist, rules=rules)

    @classmethod
    def from_user(cls, route_dist, **kwargs):
        """
        Utility method for creating a NLRI instance.

        This function returns a NLRI instance from human readable format value.

        :param route_dist: Route Distinguisher.
        :param kwargs: See :py:mod:`ryu.lib.packet.bgp.FlowSpecIPv6NLRI`
        """
        return cls._from_user(route_dist, **kwargs)

    @property
    def formatted_nlri_str(self):
        return '%s:%s' % (self.route_dist, self.prefix)


class FlowSpecL2VPNNLRI(_FlowSpecNLRIBase):
    """
    Flow Specification NLRI class for L2VPN [draft-ietf-idr-flowspec-l2vpn-05]
    """

    # flow-spec NLRI:
    # +-----------------------------------+
    # |    length (0xnn or 0xfn nn)       |
    # +-----------------------------------+
    # |     RD   (8 octets)               |
    # +-----------------------------------+
    # |     NLRI value  (variable)        |
    # +-----------------------------------+
    ROUTE_FAMILY = RF_L2VPN_FLOWSPEC
    FLOWSPEC_FAMILY = 'l2vpnfs'

    def __init__(self, length=0, route_dist=None, rules=None):
        super(FlowSpecL2VPNNLRI, self).__init__(length, rules)
        assert route_dist is not None
        self.route_dist = route_dist

    @classmethod
    def _from_user(cls, route_dist, **kwargs):
        rules = []
        for k, v in kwargs.items():
            subcls = _FlowSpecComponentBase.lookup_type_name(
                k, cls.ROUTE_FAMILY.afi)
            rule = subcls.from_str(str(v))
            rules.extend(rule)
        rules.sort(key=lambda x: x.type)
        return cls(route_dist=route_dist, rules=rules)

    @classmethod
    def from_user(cls, route_dist, **kwargs):
        """
        Utility method for creating a L2VPN NLRI instance.

        This function returns a L2VPN NLRI instance
        from human readable format value.

        :param kwargs: The following arguments are available.

        ============== ============= ========= ==============================
        Argument       Value         Operator  Description
        ============== ============= ========= ==============================
        ether_type     Integer       Numeric   Ethernet Type.
        src_mac        Mac Address   Nothing   Source Mac address.
        dst_mac        Mac Address   Nothing   Destination Mac address.
        llc_ssap       Integer       Numeric   Source Service Access Point
                                               in LLC.
        llc_dsap       Integer       Numeric   Destination Service Access
                                               Point in LLC.
        llc_control    Integer       Numeric   Control field in LLC.
        snap           Integer       Numeric   Sub-Network Access Protocol
                                               field.
        vlan_id        Integer       Numeric   VLAN ID.
        vlan_cos       Integer       Numeric   VLAN COS field.
        inner_vlan_id  Integer       Numeric   Inner VLAN ID.
        inner_vlan_cos Integer       Numeric   Inner VLAN COS field.
        ============== ============= ========= ==============================
        """
        return cls._from_user(route_dist, **kwargs)

    @property
    def formatted_nlri_str(self):
        return '%s:%s' % (self.route_dist, self.prefix)


class _FlowSpecComponentBase(StringifyMixin, TypeDisp):
    """
    Base class for Flow Specification NLRI component
    """
    COMPONENT_NAME = None

    _BASE_STR = '!B'
    _BASE_STR_SIZE = struct.calcsize(_BASE_STR)

    # Dictionary of COMPONENT_NAME to subclass.
    # e.g.)
    #   _NAMES = {'dst_prefix': FlowSpecDestPrefix, ...}
    _NAMES = {}

    def __init__(self, type_=None):
        if type_ is None:
            type_, _ = self._rev_lookup_type(self.__class__)
        self.type = type_

    @classmethod
    def register_type(cls, type_, afi):
        cls._TYPES = cls._TYPES.copy()
        cls._NAMES = cls._NAMES.copy()

        def _register_type(subcls):
            cls._TYPES[(type_, afi)] = subcls
            cls._NAMES[(subcls.COMPONENT_NAME, afi)] = subcls
            cls._REV_TYPES = None
            return subcls

        return _register_type

    @classmethod
    def lookup_type_name(cls, type_name, afi):
        return cls._NAMES[(type_name, afi)]

    @classmethod
    def _lookup_type(cls, type_, afi):
        try:
            return cls._TYPES[(type_, afi)]
        except KeyError:
            return cls._UNKNOWN_TYPE

    @classmethod
    def parse_header(cls, rest, afi):
        (type_,) = struct.unpack_from(
            cls._BASE_STR, six.binary_type(rest))
        rest = rest[cls._BASE_STR_SIZE:]
        return cls._lookup_type(type_, afi), rest

    def serialize_header(self):
        return struct.pack(self._BASE_STR, self.type)


class _FlowSpecIPv4Component(_FlowSpecComponentBase):
    """
    Base class for Flow Specification for IPv4 NLRI component
    """
    TYPE_DESTINATION_PREFIX = 0x01
    TYPE_SOURCE_PREFIX = 0x02
    TYPE_PROTOCOL = 0x03
    TYPE_PORT = 0x04
    TYPE_DESTINATION_PORT = 0x05
    TYPE_SOURCE_PORT = 0x06
    TYPE_ICMP = 0x07
    TYPE_ICMP_CODE = 0x08
    TYPE_TCP_FLAGS = 0x09
    TYPE_PACKET_LENGTH = 0x0a
    TYPE_DIFFSERV_CODE_POINT = 0x0b
    TYPE_FRAGMENT = 0x0c


class _FlowSpecIPv6Component(_FlowSpecComponentBase):
    """
    Base class for Flow Specification for IPv6 NLRI component
    """
    TYPE_DESTINATION_PREFIX = 0x01
    TYPE_SOURCE_PREFIX = 0x02
    TYPE_NEXT_HEADER = 0x03
    TYPE_PORT = 0x04
    TYPE_DESTINATION_PORT = 0x05
    TYPE_SOURCE_PORT = 0x06
    TYPE_ICMP = 0x07
    TYPE_ICMP_CODE = 0x08
    TYPE_TCP_FLAGS = 0x09
    TYPE_PACKET_LENGTH = 0x0a
    TYPE_DIFFSERV_CODE_POINT = 0x0b
    TYPE_FRAGMENT = 0x0c
    TYPE_FLOW_LABEL = 0x0d


class _FlowSpecL2VPNComponent(_FlowSpecComponentBase):
    """
    Base class for Flow Specification for L2VPN NLRI component
    """
    TYPE_ETHER_TYPE = 0x0e
    TYPE_SOURCE_MAC = 0x0f
    TYPE_DESTINATION_MAC = 0x10
    TYPE_LLC_DSAP = 0x11
    TYPE_LLC_SSAP = 0x12
    TYPE_LLC_CONTROL = 0x13
    TYPE_SNAP = 0x14
    TYPE_VLAN_ID = 0x15
    TYPE_VLAN_COS = 0x16
    TYPE_INNER_VLAN_ID = 0x17
    TYPE_INNER_VLAN_COS = 0x18


@_FlowSpecComponentBase.register_unknown_type()
class FlowSpecComponentUnknown(_FlowSpecComponentBase):
    """
    Unknown component type for Flow Specification NLRI component
    """

    def __init__(self, buf, type_=None):
        super(FlowSpecComponentUnknown, self).__init__(type_)
        self.buf = buf

    @classmethod
    def parse_body(cls, buf):
        return cls(buf), None

    def serialize_body(self):
        return self.buf


class _FlowSpecPrefixBase(_FlowSpecIPv4Component, IPAddrPrefix):
    """
    Prefix base class for Flow Specification NLRI component
    """

    def __init__(self, length, addr, type_=None):
        super(_FlowSpecPrefixBase, self).__init__(type_)
        self.length = length
        prefix = "%s/%s" % (addr, length)
        self.addr = str(netaddr.ip.IPNetwork(prefix).network)

    @classmethod
    def parse_body(cls, buf):
        return cls.parser(buf)

    def serialize_body(self):
        return self.serialize()

    @classmethod
    def from_str(cls, value):
        rule = []
        addr, length = value.split('/')
        rule.append(cls(int(length), addr))
        return rule

    @property
    def value(self):
        return "%s/%s" % (self.addr, self.length)

    def to_str(self):
        return self.value


class _FlowSpecIPv6PrefixBase(_FlowSpecIPv6Component, IP6AddrPrefix):
    """
    Prefix base class for Flow Specification NLRI component
    """
    _PACK_STR = '!BB'  # length, offset

    def __init__(self, length, addr, offset=0, type_=None):
        super(_FlowSpecIPv6PrefixBase, self).__init__(type_)
        self.length = length
        self.offset = offset
        prefix = "%s/%s" % (addr, length)
        self.addr = str(netaddr.ip.IPNetwork(prefix).network)

    @classmethod
    def parser(cls, buf):
        (length, offset) = struct.unpack_from(
            cls._PACK_STR, six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        byte_length = (length + 7) // 8
        addr = cls._from_bin(rest[:byte_length])
        rest = rest[byte_length:]
        return cls(length=length, offset=offset, addr=addr), rest

    @classmethod
    def parse_body(cls, buf):
        return cls.parser(buf)

    def serialize(self):
        byte_length = (self.length + 7) // 8
        bin_addr = self._to_bin(self.addr)[:byte_length]
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.length, self.offset)
        return buf + bin_addr

    def serialize_body(self):
        return self.serialize()

    @classmethod
    def from_str(cls, value):
        rule = []
        values = value.split('/')
        if len(values) == 3:
            rule.append(cls(int(values[1]), values[0], offset=int(values[2])))
        else:
            rule.append(cls(int(values[1]), values[0]))
        return rule

    @property
    def value(self):
        return "%s/%s/%s" % (self.addr, self.length, self.offset)

    def to_str(self):
        return self.value


class _FlowSpecL2VPNPrefixBase(_FlowSpecL2VPNComponent):
    """
    Prefix base class for Flow Specification NLRI component
    """
    _PACK_STR = "!B6s"

    def __init__(self, length, addr, type_=None):
        super(_FlowSpecL2VPNPrefixBase, self).__init__(type_)
        self.length = length
        self.addr = addr.lower()

    @classmethod
    def parse_body(cls, buf):
        (length, addr) = struct.unpack_from(
            cls._PACK_STR, six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        addr = addrconv.mac.bin_to_text(addr)
        return cls(length=length, addr=addr), rest

    def serialize(self):
        addr = addrconv.mac.text_to_bin(self.addr)
        return struct.pack(self._PACK_STR, self.length, addr)

    def serialize_body(self):
        return self.serialize()

    @classmethod
    def from_str(cls, value):
        return [cls(len(value.split(':')), value)]

    @property
    def value(self):
        return self.addr

    def to_str(self):
        return self.value


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_DESTINATION_PREFIX, addr_family.IP)
class FlowSpecDestPrefix(_FlowSpecPrefixBase):
    """
    Destination Prefix for Flow Specification NLRI component
    """
    COMPONENT_NAME = 'dst_prefix'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_SOURCE_PREFIX, addr_family.IP)
class FlowSpecSrcPrefix(_FlowSpecPrefixBase):
    """
    Source Prefix for Flow Specification NLRI component
    """
    COMPONENT_NAME = 'src_prefix'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_DESTINATION_PREFIX, addr_family.IP6)
class FlowSpecIPv6DestPrefix(_FlowSpecIPv6PrefixBase):
    """
    IPv6 destination Prefix for Flow Specification NLRI component
    """
    COMPONENT_NAME = 'dst_prefix'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_SOURCE_PREFIX, addr_family.IP6)
class FlowSpecIPv6SrcPrefix(_FlowSpecIPv6PrefixBase):
    """
    IPv6 source Prefix for Flow Specification NLRI component
    """
    COMPONENT_NAME = 'src_prefix'


class _FlowSpecOperatorBase(_FlowSpecComponentBase):
    """Operator base class for Flow Specification NLRI component

    ===================== ===============================================
    Attribute             Description
    ===================== ===============================================
    operator              Match conditions.
    value                 Value of component.
    ===================== ===============================================
    """
    _OPE_PACK_STR = '!B'
    _OPE_PACK_STR_SIZE = struct.calcsize(_OPE_PACK_STR)
    _VAL_PACK_STR = '!%ds'

    END_OF_LIST = 1 << 7     # END OF LIST bit
    AND = 1 << 6             # AND bit
    OR = 0                   # OR
    _LENGTH_BIT_MASK = 0x30  # The mask for length of the value

    _logical_conditions = {
        "|": OR,
        "&": AND,
    }
    _comparison_conditions = {}

    def __init__(self, operator, value, type_=None):
        super(_FlowSpecOperatorBase, self).__init__(type_)
        self.operator = operator
        self.value = value

    @classmethod
    def parse_body(cls, rest):
        (operator,) = struct.unpack_from(cls._OPE_PACK_STR,
                                         six.binary_type(rest))
        rest = rest[cls._OPE_PACK_STR_SIZE:]
        length = 1 << ((operator & cls._LENGTH_BIT_MASK) >> 4)
        value_type = type_desc.IntDescr(length)
        value = value_type.to_user(rest)
        rest = rest[length:]

        return cls(operator, value), rest

    def serialize_body(self):
        byte_length = (self.value.bit_length() + 7) // 8 or 1
        length = int(math.ceil(math.log(byte_length, 2)))
        self.operator |= length << 4
        buf = struct.pack(self._OPE_PACK_STR, self.operator)
        value_type = type_desc.IntDescr(1 << length)
        buf += struct.pack(self._VAL_PACK_STR % (1 << length),
                           value_type.from_user(self.value))

        return buf

    @classmethod
    def from_str(cls, val):
        operator = 0
        rules = []

        # e.g.)
        # value = '80 | ==90|>=8000&<=9000 | <100 & >110'
        # elements = ['80', '|', '==', '90', '|', '>=', '8000', '&',
        #             '<=', '9000', '|', '<', '100', '&', '>', '110']
        elements = [v.strip() for v in re.split(
            r'([0-9]+)|([A-Z]+)|(\|&\+)|([!=<>]+)', val) if v and v.strip()]

        elms_iter = iter(elements)

        for elm in elms_iter:
            if elm in cls._logical_conditions:
                # ['&', '|']
                operator |= cls._logical_conditions[elm]
                continue
            elif elm in cls._comparison_conditions:
                # ['=', '<', '>', '<=', '>=' ] or ['=', '!=']
                operator |= cls._comparison_conditions[elm]
                continue
            elif elm == '+':
                # If keyword "+" is used, add the value to the previous rule.
                #  e.g.) 'SYN+ACK' or '!=SYN+ACK'
                rules[-1].value |= cls._to_value(next(elms_iter))
                continue

            value = cls._to_value(elm)

            operator = cls.normalize_operator(operator)

            rules.append(cls(operator, value))
            operator = 0

        return rules

    @classmethod
    def _to_value(cls, value):
        return value

    @classmethod
    def normalize_operator(cls, operator):
        return operator


class _FlowSpecNumeric(_FlowSpecOperatorBase):
    """
    Numeric operator class for Flow Specification NLRI component
    """
    # Numeric operator format
    #  0   1   2   3   4   5   6   7
    # +---+---+---+---+---+---+---+---+
    # | e | a |  len  | 0 |lt |gt |eq |
    # +---+---+---+---+---+---+---+---+

    LT = 1 << 2  # Less than comparison bit
    GT = 1 << 1  # Greater than comparison bit
    EQ = 1 << 0  # Equality bit

    _comparison_conditions = {
        '==': EQ,
        '<': LT,
        '>': GT,
        '<=': LT | EQ,
        '>=': GT | EQ
    }

    @classmethod
    def _to_value(cls, value):
        try:
            return int(str(value), 0)
        except ValueError:
            raise ValueError('Invalid params: %s="%s"' % (
                cls.COMPONENT_NAME, value))

    def to_str(self):
        string = ""
        if self.operator & self.AND:
            string += "&"

        operator = self.operator & (self.LT | self.GT | self.EQ)
        for k, v in self._comparison_conditions.items():
            if operator == v:
                string += k

        string += str(self.value)

        return string

    @classmethod
    def normalize_operator(cls, operator):
        if operator & (cls.LT | cls.GT | cls.EQ):
            return operator
        else:
            return operator | cls.EQ


class _FlowSpecBitmask(_FlowSpecOperatorBase):
    """
    Bitmask operator class for Flow Specification NLRI component
    """
    # Bitmask operator format
    #  0   1   2   3   4   5   6   7
    # +---+---+---+---+---+---+---+---+
    # | e | a |  len  | 0 | 0 |not| m |
    # +---+---+---+---+---+---+---+---+

    NOT = 1 << 1    # NOT bit
    MATCH = 1 << 0  # MATCH bit

    _comparison_conditions = {
        '!=': NOT,
        '==': MATCH,
    }

    _bitmask_flags = {}

    @classmethod
    def _to_value(cls, value):
        try:
            return cls.__dict__[value]
        except KeyError:
            raise ValueError('Invalid params: %s="%s"' % (
                cls.COMPONENT_NAME, value))

    def to_str(self):
        string = ""
        if self.operator & self.AND:
            string += "&"

        operator = self.operator & (self.NOT | self.MATCH)
        for k, v in self._comparison_conditions.items():
            if operator == v:
                string += k

        plus = ""
        for k, v in self._bitmask_flags.items():
            if self.value & k:
                string += plus + v
                plus = "+"

        return string


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_PROTOCOL, addr_family.IP)
class FlowSpecIPProtocol(_FlowSpecNumeric):
    """IP Protocol for Flow Specification NLRI component

    Set the IP protocol number at value.
    """
    COMPONENT_NAME = 'ip_proto'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_NEXT_HEADER, addr_family.IP6)
class FlowSpecNextHeader(_FlowSpecNumeric):
    """Next Header value in IPv6 packets

    Set the IP protocol number at value
    """
    COMPONENT_NAME = 'next_header'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_PORT, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_PORT, addr_family.IP6)
class FlowSpecPort(_FlowSpecNumeric):
    """Port number for Flow Specification NLRI component

    Set the source or destination TCP/UDP ports at value.
    """
    COMPONENT_NAME = 'port'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_DESTINATION_PORT, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_DESTINATION_PORT, addr_family.IP6)
class FlowSpecDestPort(_FlowSpecNumeric):
    """Destination port number for Flow Specification NLRI component

    Set the destination port of a TCP or UDP packet at value.
    """
    COMPONENT_NAME = 'dst_port'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_SOURCE_PORT, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_SOURCE_PORT, addr_family.IP6)
class FlowSpecSrcPort(_FlowSpecNumeric):
    """Source port number for Flow Specification NLRI component

    Set the source port of a TCP or UDP packet at value.
    """
    COMPONENT_NAME = 'src_port'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_ICMP, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_ICMP, addr_family.IP6)
class FlowSpecIcmpType(_FlowSpecNumeric):
    """ICMP type for Flow Specification NLRI component

    Set the type field of an ICMP packet at value.
    """
    COMPONENT_NAME = 'icmp_type'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_ICMP_CODE, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_ICMP_CODE, addr_family.IP6)
class FlowSpecIcmpCode(_FlowSpecNumeric):
    """ICMP code Flow Specification NLRI component

    Set the code field of an ICMP packet at value.
    """
    COMPONENT_NAME = 'icmp_code'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_TCP_FLAGS, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_TCP_FLAGS, addr_family.IP6)
class FlowSpecTCPFlags(_FlowSpecBitmask):
    """TCP flags for Flow Specification NLRI component

    Supported TCP flags are CWR, ECN, URGENT, ACK, PUSH, RST, SYN and FIN.
    """
    COMPONENT_NAME = 'tcp_flags'

    # bitmask format
    #  0    1    2    3    4    5    6    7
    # +----+----+----+----+----+----+----+----+
    # |CWR |ECN |URG |ACK |PSH |RST |SYN |FIN |
    # +----+----+----+----+----+----+----+----+

    CWR = 1 << 7
    ECN = 1 << 6
    URGENT = 1 << 5
    ACK = 1 << 4
    PUSH = 1 << 3
    RST = 1 << 2
    SYN = 1 << 1
    FIN = 1 << 0

    _bitmask_flags = collections.OrderedDict()
    _bitmask_flags[SYN] = 'SYN'
    _bitmask_flags[ACK] = 'ACK'
    _bitmask_flags[FIN] = 'FIN'
    _bitmask_flags[RST] = 'RST'
    _bitmask_flags[PUSH] = 'PUSH'
    _bitmask_flags[URGENT] = 'URGENT'
    _bitmask_flags[ECN] = 'ECN'
    _bitmask_flags[CWR] = 'CWR'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_PACKET_LENGTH, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_PACKET_LENGTH, addr_family.IP6)
class FlowSpecPacketLen(_FlowSpecNumeric):
    """Packet length for Flow Specification NLRI component

    Set the total IP packet length at value.
    """
    COMPONENT_NAME = 'packet_len'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_DIFFSERV_CODE_POINT, addr_family.IP)
@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_DIFFSERV_CODE_POINT, addr_family.IP6)
class FlowSpecDSCP(_FlowSpecNumeric):
    """Diffserv Code Point for Flow Specification NLRI component

    Set the 6-bit DSCP field at value. [RFC2474]
    """
    COMPONENT_NAME = 'dscp'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv4Component.TYPE_FRAGMENT, addr_family.IP)
class FlowSpecFragment(_FlowSpecBitmask):
    """Fragment for Flow Specification NLRI component

    Set the bitmask for operand format at value.
    The following values are supported.

    ========== ===============================================
    Attribute  Description
    ========== ===============================================
    LF         Last fragment
    FF         First fragment
    ISF        Is a fragment
    DF         Don't fragment
    ========== ===============================================
    """
    COMPONENT_NAME = 'fragment'

    # bitmask format
    #  0   1   2   3   4   5   6   7
    # +---+---+---+---+---+---+---+---+
    # |   Reserved    |LF |FF |IsF|DF |
    # +---+---+---+---+---+---+---+---+

    LF = 1 << 3
    FF = 1 << 2
    ISF = 1 << 1
    DF = 1 << 0

    _bitmask_flags = collections.OrderedDict()
    _bitmask_flags[LF] = 'LF'
    _bitmask_flags[FF] = 'FF'
    _bitmask_flags[ISF] = 'ISF'
    _bitmask_flags[DF] = 'DF'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_FRAGMENT, addr_family.IP6)
class FlowSpecIPv6Fragment(_FlowSpecBitmask):
    """Fragment for Flow Specification for IPv6 NLRI component

    ========== ===============================================
    Attribute  Description
    ========== ===============================================
    LF         Last fragment
    FF         First fragment
    ISF        Is a fragment
    ========== ===============================================
    """
    COMPONENT_NAME = 'fragment'

    # bitmask format
    #  0   1   2   3   4   5   6   7
    # +---+---+---+---+---+---+---+---+
    # |   Reserved    |LF |FF |IsF| 0 |
    # +---+---+---+---+---+---+---+---+

    LF = 1 << 3
    FF = 1 << 2
    ISF = 1 << 1

    _bitmask_flags = collections.OrderedDict()
    _bitmask_flags[LF] = 'LF'
    _bitmask_flags[FF] = 'FF'
    _bitmask_flags[ISF] = 'ISF'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_ETHER_TYPE, addr_family.L2VPN)
class FlowSpecEtherType(_FlowSpecNumeric):
    """Ethernet Type field in an Ethernet frame.

    Set the 2 byte value of an Ethernet Type field at value.
    """
    COMPONENT_NAME = 'ether_type'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_SOURCE_MAC, addr_family.L2VPN)
class FlowSpecSourceMac(_FlowSpecL2VPNPrefixBase):
    """Source Mac Address.

    Set the Mac Address at value.
    """
    COMPONENT_NAME = 'src_mac'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_DESTINATION_MAC, addr_family.L2VPN)
class FlowSpecDestinationMac(_FlowSpecL2VPNPrefixBase):
    """Destination Mac Address.

    Set the Mac Address at value.
    """
    COMPONENT_NAME = 'dst_mac'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_LLC_DSAP, addr_family.L2VPN)
class FlowSpecLLCDSAP(_FlowSpecNumeric):
    """Destination SAP field in LLC header in an Ethernet frame.

    Set the 2 byte value of an Destination SAP at value.
    """
    COMPONENT_NAME = 'llc_dsap'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_LLC_SSAP, addr_family.L2VPN)
class FlowSpecLLCSSAP(_FlowSpecNumeric):
    """Source SAP field in LLC header in an Ethernet frame.

    Set the 2 byte value of an Source SAP at value.
    """
    COMPONENT_NAME = 'llc_ssap'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_LLC_CONTROL, addr_family.L2VPN)
class FlowSpecLLCControl(_FlowSpecNumeric):
    """Control field in LLC header in an Ethernet frame.

    Set the Contorol field at value.
    """
    COMPONENT_NAME = 'llc_control'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_SNAP, addr_family.L2VPN)
class FlowSpecSNAP(_FlowSpecNumeric):
    """Sub-Network Access Protocol field in an Ethernet frame.

    Set the 5 byte SNAP field at value.
    """
    COMPONENT_NAME = 'snap'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_VLAN_ID, addr_family.L2VPN)
class FlowSpecVLANID(_FlowSpecNumeric):
    """VLAN ID.

    Set VLAN ID at value.
    """
    COMPONENT_NAME = 'vlan_id'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_VLAN_COS, addr_family.L2VPN)
class FlowSpecVLANCoS(_FlowSpecNumeric):
    """VLAN CoS Fields in an Ethernet frame.

    Set the 3 bit CoS field at value.
    """
    COMPONENT_NAME = 'vlan_cos'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_INNER_VLAN_ID, addr_family.L2VPN)
class FlowSpecInnerVLANID(_FlowSpecNumeric):
    """Inner VLAN ID.

    Set VLAN ID at value.
    """
    COMPONENT_NAME = 'inner_vlan_id'


@_FlowSpecComponentBase.register_type(
    _FlowSpecL2VPNComponent.TYPE_INNER_VLAN_COS, addr_family.L2VPN)
class FlowSpecInnerVLANCoS(_FlowSpecNumeric):
    """VLAN CoS Fields in an Inner Ethernet frame.

    Set the 3 bit CoS field at value..
    """
    COMPONENT_NAME = 'inner_vlan_cos'


@_FlowSpecComponentBase.register_type(
    _FlowSpecIPv6Component.TYPE_FLOW_LABEL, addr_family.IP6)
class FlowSpecIPv6FlowLabel(_FlowSpecNumeric):
    COMPONENT_NAME = 'flow_label'


@functools.total_ordering
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
            if (not self._is_valid_asn(origin_as) or
                    not self._is_valid_ext_comm_attr(route_target)):
                raise ValueError('Invalid params.')
        self.origin_as = origin_as
        self.route_target = route_target

    def _is_valid_asn(self, asn):
        """Returns True if the given AS number is Two or Four Octet."""
        if isinstance(asn, six.integer_types) and 0 <= asn <= 0xffffffff:
            return True
        else:
            return False

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

    def __lt__(self, other):
        return ((self.origin_as, self.route_target) <
                (other.origin_as, other.route_target))

    def __eq__(self, other):
        return ((self.origin_as, self.route_target) ==
                (other.origin_as, other.route_target))

    def __hash__(self):
        return hash((self.origin_as, self.route_target))

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
        rt_nlri = b''
        if not self.is_default_rtnlri():
            rt_nlri += struct.pack('!I', self.origin_as)
            # Encode route target
            rt_nlri += self.route_target.serialize()

        # RT Nlri is 12 octets
        return struct.pack('B', (8 * 12)) + rt_nlri


def _addr_class_key(route_family):
    return route_family.afi, route_family.safi


_ADDR_CLASSES = {
    _addr_class_key(RF_IPv4_UC): IPAddrPrefix,
    _addr_class_key(RF_IPv6_UC): IP6AddrPrefix,
    _addr_class_key(RF_IPv4_MPLS): LabelledIPAddrPrefix,
    _addr_class_key(RF_IPv6_MPLS): LabelledIP6AddrPrefix,
    _addr_class_key(RF_IPv4_VPN): LabelledVPNIPAddrPrefix,
    _addr_class_key(RF_IPv6_VPN): LabelledVPNIP6AddrPrefix,
    _addr_class_key(RF_L2_EVPN): EvpnNLRI,
    _addr_class_key(RF_IPv4_FLOWSPEC): FlowSpecIPv4NLRI,
    _addr_class_key(RF_IPv6_FLOWSPEC): FlowSpecIPv6NLRI,
    _addr_class_key(RF_VPNv4_FLOWSPEC): FlowSpecVPNv4NLRI,
    _addr_class_key(RF_VPNv6_FLOWSPEC): FlowSpecVPNv6NLRI,
    _addr_class_key(RF_L2VPN_FLOWSPEC): FlowSpecL2VPNNLRI,
    _addr_class_key(RF_RTC_UC): RouteTargetMembershipNLRI,
}


def _get_addr_class(afi, safi):
    try:
        return _ADDR_CLASSES[(afi, safi)]
    except KeyError:
        return _BinAddrPrefix


class _OptParam(StringifyMixin, TypeDisp, _Value):
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
        (type_, length) = struct.unpack_from(cls._PACK_STR,
                                             six.binary_type(buf))
        rest = buf[struct.calcsize(cls._PACK_STR):]
        value = bytes(rest[:length])
        rest = rest[length:]
        subcls = cls._lookup_type(type_)
        caps = subcls.parse_value(value)
        if not isinstance(caps, list):
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
class _OptParamCapability(_OptParam, TypeDisp):
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
        (restart, ) = struct.unpack_from(cls._CAP_PACK_STR,
                                         six.binary_type(buf))
        buf = buf[2:]
        l = []
        while len(buf) >= 4:
            l.append(struct.unpack_from("!HBB", buf))
            buf = buf[4:]
        return {'flags': restart >> 12, 'time': restart & 0xfff, 'tuples': l}

    def serialize_cap_value(self):
        buf = bytearray()
        msg_pack_into(self._CAP_PACK_STR, buf, 0, self.flags << 12 | self.time)
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
        (as_number, ) = struct.unpack_from(cls._CAP_PACK_STR,
                                           six.binary_type(buf))
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


class _PathAttribute(StringifyMixin, TypeDisp, _Value):
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
        (flags, type_) = struct.unpack_from(cls._PACK_STR,
                                            six.binary_type(buf))
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
            self.flags = (
                self.flags
                & ~(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)
                | self._ATTR_FLAGS)
        value = self.serialize_value()
        self.length = len(value)
        if self.flags & BGP_ATTR_FLAG_EXTENDED_LENGTH:
            len_pack_str = self._PACK_STR_EXT_LEN
        elif self.length > 255:
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

    def has_local_as(self, local_as, max_count=0):
        """Check if *local_as* is already present on path list."""
        _count = 0
        for as_path_seg in self.value:
            _count += list(as_path_seg).count(local_as)
        return _count > max_count

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
            for _ in range(0, num_as):
                (as_number,) = struct.unpack_from(as_pack_str,
                                                  six.binary_type(buf))
                buf = buf[struct.calcsize(as_pack_str):]
                l.append(as_number)
            if type_ == cls._AS_SET:
                result.append(set(l))
            elif type_ == cls._AS_SEQUENCE:
                result.append(l)
            else:
                # protocol error
                raise struct.error('Unsupported segment type: %s' % type_)
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
            else:
                raise struct.error(
                    'Element of %s.value must be of type set or list' %
                    self.__class__.__name__)
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
    _ATTR_FLAGS = BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL

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
        (ip_addr,) = struct.unpack_from(cls._VALUE_PACK_STR,
                                        six.binary_type(buf))
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
    # Note: AS numbers can be Two-Octet or Four-Octet.
    # This class would detect it by the value length field.
    # For example,
    # - if the value field length is 6 (='!H4s'), AS number should
    #   be Two-Octet.
    # - else if the length is 8 (='!I4s'), AS number should be Four-Octet.
    _TWO_OCTET_VALUE_PACK_STR = '!H4s'
    _FOUR_OCTET_VALUE_PACK_STR = '!I4s'
    _VALUE_PACK_STR = _TWO_OCTET_VALUE_PACK_STR  # Two-Octet by default
    _FOUR_OCTET_VALUE_SIZE = struct.calcsize(_FOUR_OCTET_VALUE_PACK_STR)

    @classmethod
    def parse_value(cls, buf):
        if len(buf) == cls._FOUR_OCTET_VALUE_SIZE:
            cls._VALUE_PACK_STR = cls._FOUR_OCTET_VALUE_PACK_STR
        return super(BGPPathAttributeAggregator, cls).parse_value(buf)

    def serialize_value(self):
        if self.as_number > 0xffff:
            self._VALUE_PACK_STR = self._FOUR_OCTET_VALUE_PACK_STR
        return super(BGPPathAttributeAggregator, self).serialize_value()


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
        'asciilist': [
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
# 06    sub-type    Ethernet VPN Extended Community (RFC 7432)
# 80    sub-type    Flow Specification Extended Community (RFC 5575)

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


class _ExtendedCommunity(StringifyMixin, TypeDisp, _Value):
    _PACK_STR = '!B7s'  # type high (+ type low), value
    _PACK_STR_SIZE = struct.calcsize(_PACK_STR)
    _SUBTYPE_PACK_STR = '!B'  # subtype
    IANA_AUTHORITY = 0x80
    TRANSITIVE = 0x40
    _TYPE_HIGH_MASK = ~TRANSITIVE

    TWO_OCTET_AS_SPECIFIC = 0x00
    IPV4_ADDRESS_SPECIFIC = 0x01
    FOUR_OCTET_AS_SPECIFIC = 0x02
    OPAQUE = 0x03
    SUBTYPE_ENCAPSULATION = 0x0c
    ENCAPSULATION = (OPAQUE, SUBTYPE_ENCAPSULATION)
    EVPN = 0x06
    SUBTYPE_EVPN_MAC_MOBILITY = 0x00
    SUBTYPE_EVPN_ESI_LABEL = 0x01
    SUBTYPE_EVPN_ES_IMPORT_RT = 0x02
    EVPN_MAC_MOBILITY = (EVPN, SUBTYPE_EVPN_MAC_MOBILITY)
    EVPN_ESI_LABEL = (EVPN, SUBTYPE_EVPN_ESI_LABEL)
    EVPN_ES_IMPORT_RT = (EVPN, SUBTYPE_EVPN_ES_IMPORT_RT)
    FLOWSPEC = 0x80
    FLOWSPEC_L2VPN = 0x08
    SUBTYPE_FLOWSPEC_TRAFFIC_RATE = 0x06
    SUBTYPE_FLOWSPEC_TRAFFIC_ACTION = 0x07
    SUBTYPE_FLOWSPEC_REDIRECT = 0x08
    SUBTYPE_FLOWSPEC_TRAFFIC_REMARKING = 0x09
    SUBTYPE_FLOWSPEC_VLAN_ACTION = 0x0a
    SUBTYPE_FLOWSPEC_TPID_ACTION = 0x0b
    FLOWSPEC_TRAFFIC_RATE = (FLOWSPEC, SUBTYPE_FLOWSPEC_TRAFFIC_RATE)
    FLOWSPEC_TRAFFIC_ACTION = (FLOWSPEC, SUBTYPE_FLOWSPEC_TRAFFIC_ACTION)
    FLOWSPEC_REDIRECT = (FLOWSPEC, SUBTYPE_FLOWSPEC_REDIRECT)
    FLOWSPEC_TRAFFIC_REMARKING = (FLOWSPEC, SUBTYPE_FLOWSPEC_TRAFFIC_REMARKING)
    FLOWSPEC_VLAN_ACTION = (FLOWSPEC_L2VPN, SUBTYPE_FLOWSPEC_VLAN_ACTION)
    FLOWSPEC_TPID_ACTION = (FLOWSPEC_L2VPN, SUBTYPE_FLOWSPEC_TPID_ACTION)

    def __init__(self, type_=None):
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
            if isinstance(type_, (tuple, list)):
                type_ = type_[0]
        self.type = type_

    @classmethod
    def parse_subtype(cls, buf):
        (subtype,) = struct.unpack_from(cls._SUBTYPE_PACK_STR, buf)
        return subtype

    @classmethod
    def parse(cls, buf):
        (type_, value) = struct.unpack_from(cls._PACK_STR, buf)
        rest = buf[cls._PACK_STR_SIZE:]
        type_low = type_ & cls._TYPE_HIGH_MASK
        subtype = cls.parse_subtype(value)
        subcls = cls._lookup_type((type_low, subtype))
        if subcls == cls._UNKNOWN_TYPE:
            subcls = cls._lookup_type(type_low)
        return subcls(type_=type_, **subcls.parse_value(value)), rest

    def serialize(self):
        return struct.pack(self._PACK_STR, self.type,
                           self.serialize_value())


@_ExtendedCommunity.register_type(_ExtendedCommunity.TWO_OCTET_AS_SPECIFIC)
class BGPTwoOctetAsSpecificExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!BHI'  # sub type, as number, local adm
    _VALUE_FIELDS = ['subtype', 'as_number', 'local_administrator']

    def __init__(self, **kwargs):
        super(BGPTwoOctetAsSpecificExtendedCommunity, self).__init__()
        self.do_init(BGPTwoOctetAsSpecificExtendedCommunity, self, kwargs)


@_ExtendedCommunity.register_type(_ExtendedCommunity.IPV4_ADDRESS_SPECIFIC)
class BGPIPv4AddressSpecificExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!B4sH'  # sub type, IPv4 address, local adm
    _VALUE_FIELDS = ['subtype', 'ipv4_address', 'local_administrator']
    _TYPE = {
        'ascii': [
            'ipv4_address'
        ]
    }

    def __init__(self, **kwargs):
        super(BGPIPv4AddressSpecificExtendedCommunity, self).__init__()
        self.do_init(BGPIPv4AddressSpecificExtendedCommunity, self, kwargs)

    @classmethod
    def parse_value(cls, buf):
        d_ = super(BGPIPv4AddressSpecificExtendedCommunity,
                   cls).parse_value(buf)
        d_['ipv4_address'] = addrconv.ipv4.bin_to_text(d_['ipv4_address'])
        return d_

    def serialize_value(self):
        return struct.pack(self._VALUE_PACK_STR, self.subtype,
                           addrconv.ipv4.text_to_bin(self.ipv4_address),
                           self.local_administrator)


@_ExtendedCommunity.register_type(_ExtendedCommunity.FOUR_OCTET_AS_SPECIFIC)
class BGPFourOctetAsSpecificExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!BIH'  # sub type, as number, local adm
    _VALUE_FIELDS = ['subtype', 'as_number', 'local_administrator']

    def __init__(self, **kwargs):
        super(BGPFourOctetAsSpecificExtendedCommunity, self).__init__()
        self.do_init(BGPFourOctetAsSpecificExtendedCommunity, self, kwargs)


@_ExtendedCommunity.register_type(_ExtendedCommunity.OPAQUE)
class BGPOpaqueExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!B6s'
    _VALUE_FIELDS = ['subtype', 'opaque']

    def __init__(self, **kwargs):
        super(BGPOpaqueExtendedCommunity, self).__init__()
        self.do_init(BGPOpaqueExtendedCommunity, self, kwargs)


@_ExtendedCommunity.register_type(_ExtendedCommunity.ENCAPSULATION)
class BGPEncapsulationExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!B4xH'
    _VALUE_FIELDS = ['subtype', 'tunnel_type']

    # BGP Tunnel Encapsulation Attribute Tunnel Types
    # http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#tunnel-types
    TUNNEL_TYPE_L2TPV3 = 1
    TUNNEL_TYPE_GRE = 2
    TUNNEL_TYPE_IP_IN_IP = 7
    TUNNEL_TYPE_VXLAN = 8
    TUNNEL_TYPE_NVGRE = 9
    TUNNEL_TYPE_MPLS = 10
    TUNNEL_TYPE_MPLS_IN_GRE = 11
    TUNNEL_TYPE_VXLAN_GRE = 12
    TUNNEL_TYPE_MPLS_IN_UDP = 13

    def __init__(self, **kwargs):
        super(BGPEncapsulationExtendedCommunity, self).__init__()
        self.do_init(BGPEncapsulationExtendedCommunity, self, kwargs)

    @classmethod
    def from_str(cls, tunnel_type):
        """
        Returns an instance identified with the given `tunnel_type`.

        `tunnel_type` should be a str type value and corresponding to
        BGP Tunnel Encapsulation Attribute Tunnel Type constants name
        omitting `TUNNEL_TYPE_` prefix.

        Example:
            - `gre` means TUNNEL_TYPE_GRE
            - `vxlan` means TUNNEL_TYPE_VXLAN

        And raises AttributeError when the corresponding Tunnel Type
        is not found to the given `tunnel_type`.
        """
        return cls(subtype=_ExtendedCommunity.SUBTYPE_ENCAPSULATION,
                   tunnel_type=getattr(cls,
                                       'TUNNEL_TYPE_' + tunnel_type.upper()))


@_ExtendedCommunity.register_type(_ExtendedCommunity.EVPN_MAC_MOBILITY)
class BGPEvpnMacMobilityExtendedCommunity(_ExtendedCommunity):
    """
    MAC Mobility Extended Community
    """
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x06     | Sub-Type=0x00 |Flags(1 octet)|  Reserved=0    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                       Sequence Number                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _VALUE_PACK_STR = '!BBxI'
    _VALUE_FIELDS = ['subtype', 'flags', 'sequence_number']

    def __init__(self, **kwargs):
        super(BGPEvpnMacMobilityExtendedCommunity, self).__init__()
        self.do_init(BGPEvpnMacMobilityExtendedCommunity, self, kwargs)


@_ExtendedCommunity.register_type(_ExtendedCommunity.EVPN_ESI_LABEL)
class BGPEvpnEsiLabelExtendedCommunity(_ExtendedCommunity):
    """
    ESI Label Extended Community
    """
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x06     | Sub-Type=0x01 | Flags(1 octet)|  Reserved=0   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Reserved=0   |          ESI Label                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _VALUE_PACK_STR = '!BB2x3s'
    _VALUE_FIELDS = ['subtype', 'flags']

    # Classification for Flags.
    SINGLE_ACTIVE_BIT = 1 << 0

    def __init__(self, label=None, mpls_label=None, vni=None, **kwargs):
        super(BGPEvpnEsiLabelExtendedCommunity, self).__init__()
        self.do_init(BGPEvpnEsiLabelExtendedCommunity, self, kwargs)

        if label:
            # If binary type label field value is specified, stores it
            # and decodes as MPLS label and VNI.
            self._label = label
            self._mpls_label, _ = mpls.label_from_bin(label)
            self._vni = vxlan.vni_from_bin(label)
        else:
            # If either MPLS label or VNI is specified, stores it
            # and encodes into binary type label field value.
            self._label = self._serialize_label(mpls_label, vni)
            self._mpls_label = mpls_label
            self._vni = vni

    def _serialize_label(self, mpls_label, vni):
        if mpls_label:
            return mpls.label_to_bin(mpls_label, is_bos=True)
        elif vni:
            return vxlan.vni_to_bin(vni)
        else:
            return b'\x00' * 3

    @classmethod
    def parse_value(cls, buf):
        (subtype, flags,
         label) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'subtype': subtype,
            'flags': flags,
            'label': label,
        }

    def serialize_value(self):
        return struct.pack(self._VALUE_PACK_STR, self.subtype, self.flags,
                           self._label)

    @property
    def mpls_label(self):
        return self._mpls_label

    @mpls_label.setter
    def mpls_label(self, mpls_label):
        self._label = mpls.label_to_bin(mpls_label, is_bos=True)
        self._mpls_label = mpls_label
        self._vni = None  # disables VNI

    @property
    def vni(self):
        return self._vni

    @vni.setter
    def vni(self, vni):
        self._label = vxlan.vni_to_bin(vni)
        self._mpls_label = None  # disables ESI label
        self._vni = vni


@_ExtendedCommunity.register_type(_ExtendedCommunity.EVPN_ES_IMPORT_RT)
class BGPEvpnEsImportRTExtendedCommunity(_ExtendedCommunity):
    """
    ES-Import Route Target Extended Community
    """
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x06     | Sub-Type=0x02 |          ES-Import            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                     ES-Import Cont'd                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _VALUE_PACK_STR = '!B6s'
    _VALUE_FIELDS = ['subtype', 'es_import']
    _TYPE = {
        'ascii': [
            'es_import'
        ]
    }

    def __init__(self, **kwargs):
        super(BGPEvpnEsImportRTExtendedCommunity, self).__init__()
        self.do_init(BGPEvpnEsImportRTExtendedCommunity, self, kwargs)

    @classmethod
    def parse_value(cls, buf):
        (subtype, es_import) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'subtype': subtype,
            'es_import': addrconv.mac.bin_to_text(es_import),
        }

    def serialize_value(self):
        return struct.pack(self._VALUE_PACK_STR, self.subtype,
                           addrconv.mac.text_to_bin(self.es_import))


@_ExtendedCommunity.register_type(_ExtendedCommunity.FLOWSPEC_TRAFFIC_RATE)
class BGPFlowSpecTrafficRateCommunity(_ExtendedCommunity):
    """
    Flow Specification Traffic Filtering Actions for Traffic Rate.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    as_number                  Autonomous System number.
    rate_info                  rate information.
    ========================== ===============================================
    """
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x80     | Sub-Type=0x06 |           AS number           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Rate information                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _VALUE_PACK_STR = '!BHf'
    _VALUE_FIELDS = ['subtype', 'as_number', 'rate_info']
    ACTION_NAME = 'traffic_rate'

    def __init__(self, **kwargs):
        super(BGPFlowSpecTrafficRateCommunity, self).__init__()
        kwargs['subtype'] = self.SUBTYPE_FLOWSPEC_TRAFFIC_RATE
        self.do_init(BGPFlowSpecTrafficRateCommunity, self, kwargs)

    @classmethod
    def parse_value(cls, buf):
        (subtype, as_number,
         rate_info) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'subtype': subtype,
            'as_number': as_number,
            'rate_info': rate_info,
        }

    def serialize_value(self):
        return struct.pack(self._VALUE_PACK_STR, self.subtype,
                           self.as_number, self.rate_info)


@_ExtendedCommunity.register_type(_ExtendedCommunity.FLOWSPEC_TRAFFIC_ACTION)
class BGPFlowSpecTrafficActionCommunity(_ExtendedCommunity):
    """
    Flow Specification Traffic Filtering Actions for Traffic Action.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    action                     Apply action.
                               The supported action are
                               ``SAMPLE`` and ``TERMINAL``.
    ========================== ===============================================
    """
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x80     | Sub-Type=0x07 |          Traffic-action       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                     Traffic-action Cont'd                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Traffic-action format
    #  40  41  42  43  44  45  46  47
    # +---+---+---+---+---+---+---+---+
    # |        reserved       | S | T |
    # +---+---+---+---+---+---+---+---+

    _VALUE_PACK_STR = '!B5xB'
    _VALUE_FIELDS = ['subtype', 'action']
    ACTION_NAME = 'traffic_action'
    SAMPLE = 1 << 1
    TERMINAL = 1 << 0

    def __init__(self, **kwargs):
        super(BGPFlowSpecTrafficActionCommunity, self).__init__()
        kwargs['subtype'] = self.SUBTYPE_FLOWSPEC_TRAFFIC_ACTION
        self.do_init(BGPFlowSpecTrafficActionCommunity, self, kwargs)


@_ExtendedCommunity.register_type(_ExtendedCommunity.FLOWSPEC_REDIRECT)
class BGPFlowSpecRedirectCommunity(BGPTwoOctetAsSpecificExtendedCommunity):
    """
    Flow Specification Traffic Filtering Actions for Redirect.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    as_number                  Autonomous System number.
    local_administrator        Local Administrator.
    ========================== ===============================================
    """
    ACTION_NAME = 'redirect'

    def __init__(self, **kwargs):
        super(BGPTwoOctetAsSpecificExtendedCommunity, self).__init__()
        kwargs['subtype'] = self.SUBTYPE_FLOWSPEC_REDIRECT
        self.do_init(BGPTwoOctetAsSpecificExtendedCommunity, self, kwargs)


@_ExtendedCommunity.register_type(
    _ExtendedCommunity.FLOWSPEC_TRAFFIC_REMARKING)
class BGPFlowSpecTrafficMarkingCommunity(_ExtendedCommunity):
    """
    Flow Specification Traffic Filtering Actions for Traffic Marking.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    dscp                       Differentiated Services Code Point.
    ========================== ===============================================
    """
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x80     | Sub-Type=0x09 |           Reserved=0          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Reserved=0                 |      Dscp     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _VALUE_PACK_STR = '!B5xB'
    _VALUE_FIELDS = ['subtype', 'dscp']
    ACTION_NAME = 'traffic_marking'

    def __init__(self, **kwargs):
        super(BGPFlowSpecTrafficMarkingCommunity, self).__init__()
        kwargs['subtype'] = self.SUBTYPE_FLOWSPEC_TRAFFIC_REMARKING
        self.do_init(BGPFlowSpecTrafficMarkingCommunity, self, kwargs)

    @classmethod
    def parse_value(cls, buf):
        (subtype, dscp) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        return {
            'subtype': subtype,
            'dscp': dscp,
        }

    def serialize_value(self):
        return struct.pack(self._VALUE_PACK_STR, self.subtype, self.dscp)


# TODO
# Implement "Redirect-IPv6" [draft-ietf-idr-flow-spec-v6-08]


@_ExtendedCommunity.register_type(
    _ExtendedCommunity.FLOWSPEC_VLAN_ACTION)
class BGPFlowSpecVlanActionCommunity(_ExtendedCommunity):
    """
    Flow Specification Vlan Actions.

    ========= ===============================================
    Attribute Description
    ========= ===============================================
    actions_1 Bit representation of actions.
              Supported actions are
              ``POP``, ``PUSH``, ``SWAP``, ``REWRITE_INNER``, ``REWRITE_OUTER``.
    actions_2 Same as ``actions_1``.
    vlan_1    VLAN ID used by ``actions_1``.
    cos_1     Class of Service used by ``actions_1``.
    vlan_2    VLAN ID used by ``actions_2``.
    cos_2     Class of Service used by ``actions_2``.
    ========= ===============================================
    """
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x08     | Sub-Type=0x0a |PO1|PU1|SW1|RT1|RO1|...|PO2|...|
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |       VLAN ID1      |  COS1 |0|       VLAN ID2      |  COS2 |0|
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _VALUE_PACK_STR = '!BBBHH'
    _VALUE_FIELDS = [
        'subtype',
        'actions_1',
        'actions_2',
        'vlan_1',
        'vlan_2',
        'cos_1',
        'cos_2']
    ACTION_NAME = 'vlan_action'
    _COS_MASK = 0x07

    POP = 1 << 7
    PUSH = 1 << 6
    SWAP = 1 << 5
    REWRITE_INNER = 1 << 4
    REWRITE_OUTER = 1 << 3

    def __init__(self, **kwargs):
        super(BGPFlowSpecVlanActionCommunity, self).__init__()
        kwargs['subtype'] = self.SUBTYPE_FLOWSPEC_VLAN_ACTION
        self.do_init(BGPFlowSpecVlanActionCommunity, self, kwargs)

    @classmethod
    def parse_value(cls, buf):
        (subtype, actions_1, actions_2,
         vlan_cos_1, vlan_cos_2) = struct.unpack_from(cls._VALUE_PACK_STR, buf)

        return {
            'subtype': subtype,
            'actions_1': actions_1,
            'vlan_1': int(vlan_cos_1 >> 4),
            'cos_1': int((vlan_cos_1 >> 1) & cls._COS_MASK),
            'actions_2': actions_2,
            'vlan_2': int(vlan_cos_2 >> 4),
            'cos_2': int((vlan_cos_2 >> 1) & cls._COS_MASK)
        }

    def serialize_value(self):
        return struct.pack(
            self._VALUE_PACK_STR,
            self.subtype,
            self.actions_1,
            self.actions_2,
            (self.vlan_1 << 4) + (self.cos_1 << 1),
            (self.vlan_2 << 4) + (self.cos_2 << 1),
        )


@_ExtendedCommunity.register_type(
    _ExtendedCommunity.FLOWSPEC_TPID_ACTION)
class BGPFlowSpecTPIDActionCommunity(_ExtendedCommunity):
    """
    Flow Specification TPID Actions.

    ========= =========================================================
    Attribute Description
    ========= =========================================================
    actions   Bit representation of actions.
              Supported actions are
              ``TI(inner TPID action)`` and ``TO(outer TPID action)``.
    tpid_1    TPID used by ``TI``.
    tpid_2    TPID used by ``TO``.
    ========= =========================================================
    """
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Type=0x08     | Sub-Type=0x0b   |TI|TO|      Reserved=0       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |             TPID1               |             TPID2           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _VALUE_PACK_STR = '!BHHH'
    _VALUE_FIELDS = ['subtype', 'actions', 'tpid_1', 'tpid_2']
    ACTION_NAME = 'tpid_action'

    TI = 1 << 15
    TO = 1 << 14

    def __init__(self, **kwargs):
        super(BGPFlowSpecTPIDActionCommunity, self).__init__()
        kwargs['subtype'] = self.SUBTYPE_FLOWSPEC_TPID_ACTION
        self.do_init(BGPFlowSpecTPIDActionCommunity, self, kwargs)

    @classmethod
    def parse_value(cls, buf):
        (subtype, actions, tpid_1, tpid_2) = struct.unpack_from(
            cls._VALUE_PACK_STR, buf)

        return {
            'subtype': subtype,
            'actions': actions,
            'tpid_1': tpid_1,
            'tpid_2': tpid_2,
        }

    def serialize_value(self):
        return struct.pack(
            self._VALUE_PACK_STR,
            self.subtype,
            self.actions,
            self.tpid_1,
            self.tpid_2,
        )


@_ExtendedCommunity.register_unknown_type()
class BGPUnknownExtendedCommunity(_ExtendedCommunity):
    _VALUE_PACK_STR = '!7s'  # opaque value

    def __init__(self, type_, **kwargs):
        super(BGPUnknownExtendedCommunity, self).__init__(type_=type_)
        self.do_init(BGPUnknownExtendedCommunity, self, kwargs, type_=type_)


@_PathAttribute.register_type(BGP_ATTR_TYPE_MP_REACH_NLRI)
class BGPPathAttributeMpReachNLRI(_PathAttribute):
    _VALUE_PACK_STR = '!HBB'  # afi, safi, next_hop_len
    _VALUE_PACK_SIZE = struct.calcsize(_VALUE_PACK_STR)
    _RD_LENGTH = 8
    _RESERVED_LENGTH = 1
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL
    _class_suffixes = ['AddrPrefix']
    _opt_attributes = ['next_hop']
    _TYPE = {
        'ascii': [
            'next_hop'
        ]
    }

    def __init__(self, afi, safi, next_hop, nlri,
                 flags=0, type_=None, length=None):
        super(BGPPathAttributeMpReachNLRI, self).__init__(
            flags=flags, type_=type_, length=length)
        self.afi = afi
        self.safi = safi
        if not isinstance(next_hop, (list, tuple)):
            next_hop = [next_hop]
        for n in next_hop:
            if not ip.valid_ipv4(n) and not ip.valid_ipv6(n):
                raise ValueError('Invalid address for next_hop: %s' % n)
        # Note: For the backward compatibility, stores the first next_hop
        # address and all next_hop addresses separately.
        if next_hop:
            self._next_hop = next_hop[0]
        else:
            self._next_hop = None
        self._next_hop_list = next_hop
        self.nlri = nlri
        addr_cls = _get_addr_class(afi, safi)
        for i in nlri:
            if not isinstance(i, addr_cls):
                raise ValueError('Invalid NRLI class for afi=%d and safi=%d'
                                 % (self.afi, self.safi))

    @staticmethod
    def split_bin_with_len(buf, unit_len):
        f = io.BytesIO(buf)
        return [f.read(unit_len) for _ in range(0, len(buf), unit_len)]

    @classmethod
    def parse_next_hop_ipv4(cls, buf, unit_len):
        next_hop = []
        for next_hop_bin in cls.split_bin_with_len(buf, unit_len):
            next_hop.append(addrconv.ipv4.bin_to_text(next_hop_bin[-4:]))
        return next_hop

    @classmethod
    def parse_next_hop_ipv6(cls, buf, unit_len):
        next_hop = []
        for next_hop_bin in cls.split_bin_with_len(buf, unit_len):
            next_hop.append(addrconv.ipv6.bin_to_text(next_hop_bin[-16:]))
        return next_hop

    @classmethod
    def parse_value(cls, buf):
        (afi, safi, next_hop_len,) = struct.unpack_from(
            cls._VALUE_PACK_STR, six.binary_type(buf))
        rest = buf[cls._VALUE_PACK_SIZE:]

        next_hop_bin = rest[:next_hop_len]
        rest = rest[next_hop_len:]
        reserved = rest[:cls._RESERVED_LENGTH]
        assert reserved == b'\0'

        nlri_bin = rest[cls._RESERVED_LENGTH:]
        addr_cls = _get_addr_class(afi, safi)
        nlri = []
        while nlri_bin:
            n, nlri_bin = addr_cls.parser(nlri_bin)
            nlri.append(n)

        rf = RouteFamily(afi, safi)
        if rf == RF_IPv4_VPN:
            next_hop = cls.parse_next_hop_ipv4(next_hop_bin,
                                               cls._RD_LENGTH + 4)
            next_hop_len -= cls._RD_LENGTH * len(next_hop)
        elif rf == RF_IPv6_VPN:
            next_hop = cls.parse_next_hop_ipv6(next_hop_bin,
                                               cls._RD_LENGTH + 16)
            next_hop_len -= cls._RD_LENGTH * len(next_hop)
        elif (afi == addr_family.IP
              or (rf == RF_L2_EVPN and next_hop_len < 16)):
            next_hop = cls.parse_next_hop_ipv4(next_hop_bin, 4)
        elif (afi == addr_family.IP6
              or (rf == RF_L2_EVPN and next_hop_len >= 16)):
            next_hop = cls.parse_next_hop_ipv6(next_hop_bin, 16)
        elif rf == RF_L2VPN_FLOWSPEC:
            next_hop = []
        else:
            raise ValueError('Invalid address family: afi=%d, safi=%d'
                             % (afi, safi))

        return {
            'afi': afi,
            'safi': safi,
            'next_hop': next_hop,
            'nlri': nlri,
        }

    def serialize_next_hop(self):
        buf = bytearray()
        for next_hop in self.next_hop_list:
            if self.afi == addr_family.IP6:
                next_hop = str(netaddr.IPAddress(next_hop).ipv6())
            next_hop_bin = ip.text_to_bin(next_hop)
            if RouteFamily(self.afi, self.safi) in (RF_IPv4_VPN, RF_IPv6_VPN):
                # Empty label stack(RD=0:0) + IP address
                next_hop_bin = b'\x00' * self._RD_LENGTH + next_hop_bin
            buf += next_hop_bin

        return buf

    def serialize_value(self):
        next_hop_bin = self.serialize_next_hop()

        # fixup
        next_hop_len = len(next_hop_bin)

        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0,
                      self.afi, self.safi, next_hop_len)
        buf += next_hop_bin
        buf += b'\0'  # reserved

        nlri_bin = bytearray()
        for n in self.nlri:
            nlri_bin += n.serialize()
        buf += nlri_bin

        return buf

    @property
    def next_hop(self):
        return self._next_hop

    @next_hop.setter
    def next_hop(self, addr):
        if not ip.valid_ipv4(addr) and not ip.valid_ipv6(addr):
            raise ValueError('Invalid address for next_hop: %s' % addr)
        self._next_hop = addr
        self.next_hop_list[0] = addr

    @property
    def next_hop_list(self):
        return self._next_hop_list

    @next_hop_list.setter
    def next_hop_list(self, addr_list):
        if not isinstance(addr_list, (list, tuple)):
            addr_list = [addr_list]
        for addr in addr_list:
            if not ip.valid_ipv4(addr) and not ip.valid_ipv6(addr):
                raise ValueError('Invalid address for next_hop: %s' % addr)
        self._next_hop = addr_list[0]
        self._next_hop_list = addr_list

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
        super(BGPPathAttributeMpUnreachNLRI, self).__init__(
            flags=flags, type_=type_, length=length)
        self.afi = afi
        self.safi = safi
        self.withdrawn_routes = withdrawn_routes
        addr_cls = _get_addr_class(afi, safi)
        for i in withdrawn_routes:
            if not isinstance(i, addr_cls):
                raise ValueError('Invalid NRLI class for afi=%d and safi=%d'
                                 % (self.afi, self.safi))

    @classmethod
    def parse_value(cls, buf):
        (afi, safi,) = struct.unpack_from(
            cls._VALUE_PACK_STR, six.binary_type(buf))

        nlri_bin = buf[struct.calcsize(cls._VALUE_PACK_STR):]
        addr_cls = _get_addr_class(afi, safi)
        nlri = []
        while nlri_bin:
            n, nlri_bin = addr_cls.parser(nlri_bin)
            nlri.append(n)

        return {
            'afi': afi,
            'safi': safi,
            'withdrawn_routes': nlri,
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0, self.afi, self.safi)

        nlri_bin = bytearray()
        for n in self.withdrawn_routes:
            nlri_bin += n.serialize()
        buf += nlri_bin

        return buf

    @property
    def route_family(self):
        return _rf_map[(self.afi, self.safi)]


@_PathAttribute.register_type(BGP_ATTR_TYEP_PMSI_TUNNEL_ATTRIBUTE)
class BGPPathAttributePmsiTunnel(_PathAttribute):
    """
    P-Multicast Service Interface Tunnel (PMSI Tunnel) attribute
    """

    # pmsi_flags, tunnel_type, mpls_label
    _VALUE_PACK_STR = '!BB3s'
    _PACK_STR_SIZE = struct.calcsize(_VALUE_PACK_STR)
    _ATTR_FLAGS = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE

    # RFC 6514
    # +--------------------------------+
    # |  Flags (1 octet)               |
    # +--------------------------------+
    # |  Tunnel Type (1 octets)        |
    # +--------------------------------+
    # |  MPLS Label (3 octets)         |
    # +--------------------------------+
    # |  Tunnel Identifier (variable)  |
    # +--------------------------------+

    # The Flags field has the following format:
    #  0 1 2 3 4 5 6 7
    # +-+-+-+-+-+-+-+-+
    # |  reserved   |L|
    # +-+-+-+-+-+-+-+-+
    # `L` refers to the Leaf Information Required.

    # Current, Tunnel Type supports following.
    # + 0 - No tunnel information present
    # + 6 - Ingress Replication
    TYPE_NO_TUNNEL_INFORMATION_PRESENT = 0
    TYPE_INGRESS_REPLICATION = 6

    # TODO:
    # The following Tunnel Type are not supported.
    # Therefore, we will need to support in the future.
    # + 1 - RSVP-TE P2MP LSP
    # + 2 - mLDP P2MP LSP
    # + 3 - PIM-SSM Tree
    # + 4 - PIM-SM Tree
    # + 5 - BIDIR-PIM Tree
    # + 7 - mLDP MP2MP LSP

    def __init__(self, pmsi_flags, tunnel_type,
                 mpls_label=None, label=None, vni=None, tunnel_id=None,
                 flags=0, type_=None, length=None):
        super(BGPPathAttributePmsiTunnel, self).__init__(flags=flags,
                                                         type_=type_,
                                                         length=length)
        self.pmsi_flags = pmsi_flags
        self.tunnel_type = tunnel_type
        self.tunnel_id = tunnel_id

        if label:
            # If binary type label field value is specified, stores it
            # and decodes as MPLS label and VNI.
            self._label = label
            self._mpls_label, _ = mpls.label_from_bin(label)
            self._vni = vxlan.vni_from_bin(label)
        else:
            # If either MPLS label or VNI is specified, stores it
            # and encodes into binary type label field value.
            self._label = self._serialize_label(mpls_label, vni)
            self._mpls_label = mpls_label
            self._vni = vni

    @classmethod
    def parse_value(cls, buf):
        (pmsi_flags,
         tunnel_type,
         label) = struct.unpack_from(cls._VALUE_PACK_STR, buf)
        value = buf[cls._PACK_STR_SIZE:]

        return {
            'pmsi_flags': pmsi_flags,
            'tunnel_type': tunnel_type,
            'label': label,
            'tunnel_id': _PmsiTunnelId.parse(tunnel_type, value)
        }

    def serialize_value(self):
        buf = bytearray()
        msg_pack_into(self._VALUE_PACK_STR, buf, 0,
                      self.pmsi_flags, self.tunnel_type, self._label)

        if self.tunnel_id is not None:
            buf += self.tunnel_id.serialize()

        return buf

    def _serialize_label(self, mpls_label, vni):
        if mpls_label:
            return mpls.label_to_bin(mpls_label, is_bos=True)
        elif vni:
            return vxlan.vni_to_bin(vni)
        else:
            return b'\x00' * 3

    @property
    def mpls_label(self):
        return self._mpls_label

    @mpls_label.setter
    def mpls_label(self, mpls_label):
        self._label = mpls.label_to_bin(mpls_label, is_bos=True)
        self._mpls_label = mpls_label
        self._vni = None  # disables VNI

    @property
    def vni(self):
        return self._vni

    @vni.setter
    def vni(self, vni):
        self._label = vxlan.vni_to_bin(vni)
        self._mpls_label = None  # disables MPLS label
        self._vni = vni

    @classmethod
    def from_jsondict(cls, dict_, decode_string=base64.b64decode,
                      **additional_args):
        if isinstance(dict_['tunnel_id'], dict):
            tunnel_id = dict_.pop('tunnel_id')
            ins = super(BGPPathAttributePmsiTunnel,
                        cls).from_jsondict(dict_,
                                           decode_string,
                                           **additional_args)

            mod = import_module(cls.__module__)

            for key, value in tunnel_id.items():
                tunnel_id_cls = getattr(mod, key)
                ins.tunnel_id = tunnel_id_cls.from_jsondict(value,
                                                            decode_string,
                                                            **additional_args)
        else:
            ins = super(BGPPathAttributePmsiTunnel,
                        cls).from_jsondict(dict_,
                                           decode_string,
                                           **additional_args)

        return ins


class _PmsiTunnelId(StringifyMixin, TypeDisp):

    @classmethod
    def parse(cls, tunnel_type, buf):
        subcls = cls._lookup_type(tunnel_type)
        return subcls.parser(buf)


@_PmsiTunnelId.register_unknown_type()
class PmsiTunnelIdUnknown(_PmsiTunnelId):
    """
    Unknown route type specific _PmsiTunnelId
    """

    def __init__(self, value):
        super(PmsiTunnelIdUnknown, self).__init__()
        self.value = value

    @classmethod
    def parser(cls, buf):
        return cls(value=buf)

    def serialize(self):
        return self.value


@_PmsiTunnelId.register_type(
    BGPPathAttributePmsiTunnel.TYPE_NO_TUNNEL_INFORMATION_PRESENT)
class _PmsiTunnelIdNoInformationPresent(_PmsiTunnelId):

    @classmethod
    def parser(cls, buf):
        return None


@_PmsiTunnelId.register_type(
    BGPPathAttributePmsiTunnel.TYPE_INGRESS_REPLICATION)
class PmsiTunnelIdIngressReplication(_PmsiTunnelId):
    # tunnel_endpoint_ip
    _VALUE_PACK_STR = '!%ds'
    _TYPE = {
        'ascii': [
            'tunnel_endpoint_ip'
        ]
    }

    def __init__(self, tunnel_endpoint_ip):
        super(PmsiTunnelIdIngressReplication, self).__init__()
        self.tunnel_endpoint_ip = tunnel_endpoint_ip

    @classmethod
    def parser(cls, buf):
        (tunnel_endpoint_ip, ) = struct.unpack_from(
            cls._VALUE_PACK_STR % len(buf),
            six.binary_type(buf))
        return cls(tunnel_endpoint_ip=ip.bin_to_text(tunnel_endpoint_ip))

    def serialize(self):
        ip_bin = ip.text_to_bin(self.tunnel_endpoint_ip)
        return struct.pack(self._VALUE_PACK_STR % len(ip_bin),
                           ip.text_to_bin(self.tunnel_endpoint_ip))


class BGPNLRI(IPAddrPrefix):
    pass


class BGPMessage(packet_base.PacketBase, TypeDisp):
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
    type                       Type field.  one of ``BGP_MSG_*`` constants.
    ========================== ===============================================
    """

    _HDR_PACK_STR = '!16sHB'  # marker, len, type
    _HDR_LEN = struct.calcsize(_HDR_PACK_STR)
    _class_prefixes = ['BGP']

    def __init__(self, marker=None, len_=None, type_=None):
        super(BGPMessage, self).__init__()
        if marker is None:
            self._marker = _MARKER
        else:
            self._marker = marker
        self.len = len_
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
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
        return subcls(marker=marker, len_=len_, type_=type_,
                      **kwargs), cls, rest

    def serialize(self, payload=None, prev=None):
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
    type                       Type field.
    version                    Version field.
    my_as                      My Autonomous System field.
                               2 octet unsigned integer.
    hold_time                  Hold Time field.
                               2 octet unsigned integer.
    bgp_identifier             BGP Identifier field.
                               An IPv4 address.
                               For example, '192.0.2.1'
    opt_param_len              Optional Parameters Length field.
                               Ignored when encoding.
    opt_param                  Optional Parameters field.
                               A list of BGPOptParam instances.
                               The default is [].
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
                 opt_param_len=0, opt_param=None,
                 version=_VERSION, hold_time=0, len_=None, marker=None):
        opt_param = opt_param if opt_param else []
        super(BGPOpen, self).__init__(marker=marker, len_=len_, type_=type_)
        self.version = version
        self.my_as = my_as
        self.bgp_identifier = bgp_identifier
        self.hold_time = hold_time
        self.opt_param_len = opt_param_len
        self.opt_param = opt_param

    @property
    def opt_param_cap_map(self):
        cap_map = {}
        for param in self.opt_param:
            if param.type == BGP_OPT_CAPABILITY:
                cap_map[param.cap_code] = param
        return cap_map

    def get_opt_param_cap(self, cap_code):
        return self.opt_param_cap_map.get(cap_code)

    @classmethod
    def parser(cls, buf):
        (version,
         my_as,
         hold_time,
         bgp_identifier,
         opt_param_len) = struct.unpack_from(cls._PACK_STR,
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
    type                       Type field.
    withdrawn_routes_len       Withdrawn Routes Length field.
                               Ignored when encoding.
    withdrawn_routes           Withdrawn Routes field.
                               A list of BGPWithdrawnRoute instances.
                               The default is [].
    total_path_attribute_len   Total Path Attribute Length field.
                               Ignored when encoding.
    path_attributes            Path Attributes field.
                               A list of BGPPathAttribute instances.
                               The default is [].
    nlri                       Network Layer Reachability Information field.
                               A list of BGPNLRI instances.
                               The default is [].
    ========================== ===============================================
    """

    _MIN_LEN = BGPMessage._HDR_LEN

    def __init__(self, type_=BGP_MSG_UPDATE,
                 withdrawn_routes_len=None,
                 withdrawn_routes=None,
                 total_path_attribute_len=None,
                 path_attributes=None,
                 nlri=None,
                 len_=None, marker=None):
        withdrawn_routes = withdrawn_routes if withdrawn_routes else []
        path_attributes = path_attributes if path_attributes else []
        nlri = nlri if nlri else []
        super(BGPUpdate, self).__init__(marker=marker, len_=len_, type_=type_)
        self.withdrawn_routes_len = withdrawn_routes_len
        self.withdrawn_routes = withdrawn_routes
        self.total_path_attribute_len = total_path_attribute_len
        self.path_attributes = path_attributes
        self.nlri = nlri

    @property
    def pathattr_map(self):
        passattr_map = {}
        for attr in self.path_attributes:
            passattr_map[attr.type] = attr
        return passattr_map

    def get_path_attr(self, attr_name):
        return self.pathattr_map.get(attr_name)

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
    type                       Type field.
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
    type                       Type field.
    error_code                 Error code field.
    error_subcode              Error subcode field.
    data                       Data field.
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
                 data=b'',
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
    type                       Type field.
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
        self.eor_sent = False

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
        msg, _, rest = BGPMessage.parser(data)
        return msg, rest
