# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
Zebra protocol parser/serializer

Zebra Protocol is used to communicate with the zebra daemon.
"""

import abc
import socket
import struct
import logging

import netaddr
import six

from ryu.lib import addrconv
from ryu.lib import ip
from ryu.lib import stringify
from ryu.lib import type_desc
from . import packet_base
from . import bgp


LOG = logging.getLogger(__name__)


# Constants in quagga/lib/zebra.h

# Default Zebra TCP port
ZEBRA_PORT = 2600

# Zebra message types
ZEBRA_INTERFACE_ADD = 1
ZEBRA_INTERFACE_DELETE = 2
ZEBRA_INTERFACE_ADDRESS_ADD = 3
ZEBRA_INTERFACE_ADDRESS_DELETE = 4
ZEBRA_INTERFACE_UP = 5
ZEBRA_INTERFACE_DOWN = 6
ZEBRA_IPV4_ROUTE_ADD = 7
ZEBRA_IPV4_ROUTE_DELETE = 8
ZEBRA_IPV6_ROUTE_ADD = 9
ZEBRA_IPV6_ROUTE_DELETE = 10
ZEBRA_REDISTRIBUTE_ADD = 11
ZEBRA_REDISTRIBUTE_DELETE = 12
ZEBRA_REDISTRIBUTE_DEFAULT_ADD = 13
ZEBRA_REDISTRIBUTE_DEFAULT_DELETE = 14
ZEBRA_IPV4_NEXTHOP_LOOKUP = 15
ZEBRA_IPV6_NEXTHOP_LOOKUP = 16
ZEBRA_IPV4_IMPORT_LOOKUP = 17
ZEBRA_IPV6_IMPORT_LOOKUP = 18
ZEBRA_INTERFACE_RENAME = 19
ZEBRA_ROUTER_ID_ADD = 20
ZEBRA_ROUTER_ID_DELETE = 21
ZEBRA_ROUTER_ID_UPDATE = 22
ZEBRA_HELLO = 23
ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB = 24
ZEBRA_VRF_UNREGISTER = 25
ZEBRA_INTERFACE_LINK_PARAMS = 26
ZEBRA_NEXTHOP_REGISTER = 27
ZEBRA_NEXTHOP_UNREGISTER = 28
ZEBRA_NEXTHOP_UPDATE = 29
ZEBRA_MESSAGE_MAX = 30

# Zebra route types
ZEBRA_ROUTE_SYSTEM = 0
ZEBRA_ROUTE_KERNEL = 1
ZEBRA_ROUTE_CONNECT = 2
ZEBRA_ROUTE_STATIC = 3
ZEBRA_ROUTE_RIP = 4
ZEBRA_ROUTE_RIPNG = 5
ZEBRA_ROUTE_OSPF = 6
ZEBRA_ROUTE_OSPF6 = 7
ZEBRA_ROUTE_ISIS = 8
ZEBRA_ROUTE_BGP = 9
ZEBRA_ROUTE_PIM = 10
ZEBRA_ROUTE_HSLS = 11
ZEBRA_ROUTE_OLSR = 12
ZEBRA_ROUTE_BABEL = 13
ZEBRA_ROUTE_MAX = 14

# Zebra message flags
ZEBRA_FLAG_INTERNAL = 0x01
ZEBRA_FLAG_SELFROUTE = 0x02
ZEBRA_FLAG_BLACKHOLE = 0x04
ZEBRA_FLAG_IBGP = 0x08
ZEBRA_FLAG_SELECTED = 0x10
ZEBRA_FLAG_FIB_OVERRIDE = 0x20
ZEBRA_FLAG_STATIC = 0x40
ZEBRA_FLAG_REJECT = 0x80

# Zebra nexthop flags
ZEBRA_NEXTHOP_IFINDEX = 1
ZEBRA_NEXTHOP_IFNAME = 2
ZEBRA_NEXTHOP_IPV4 = 3
ZEBRA_NEXTHOP_IPV4_IFINDEX = 4
ZEBRA_NEXTHOP_IPV4_IFNAME = 5
ZEBRA_NEXTHOP_IPV6 = 6
ZEBRA_NEXTHOP_IPV6_IFINDEX = 7
ZEBRA_NEXTHOP_IPV6_IFNAME = 8
ZEBRA_NEXTHOP_BLACKHOLE = 9


# Constants in quagga/lib/zclient.h

# Zebra API message flags
ZAPI_MESSAGE_NEXTHOP = 0x01
ZAPI_MESSAGE_IFINDEX = 0x02
ZAPI_MESSAGE_DISTANCE = 0x04
ZAPI_MESSAGE_METRIC = 0x08
ZAPI_MESSAGE_MTU = 0x10
ZAPI_MESSAGE_TAG = 0x20


# Constants in quagga/lib/if.h

# Interface name length
#   Linux define value in /usr/include/linux/if.h.
#   #define IFNAMSIZ        16
#   FreeBSD define value in /usr/include/net/if.h.
#   #define IFNAMSIZ        16
INTERFACE_NAMSIZE = 20
INTERFACE_HWADDR_MAX = 20

# Zebra internal interface status
ZEBRA_INTERFACE_ACTIVE = 1 << 0
ZEBRA_INTERFACE_SUB = 1 << 1
ZEBRA_INTERFACE_LINKDETECTION = 1 << 2

# Zebra link layer types
ZEBRA_LLT_UNKNOWN = 0
ZEBRA_LLT_ETHER = 1
ZEBRA_LLT_EETHER = 2
ZEBRA_LLT_AX25 = 3
ZEBRA_LLT_PRONET = 4
ZEBRA_LLT_IEEE802 = 5
ZEBRA_LLT_ARCNET = 6
ZEBRA_LLT_APPLETLK = 7
ZEBRA_LLT_DLCI = 8
ZEBRA_LLT_ATM = 9
ZEBRA_LLT_METRICOM = 10
ZEBRA_LLT_IEEE1394 = 11
ZEBRA_LLT_EUI64 = 12
ZEBRA_LLT_INFINIBAND = 13
ZEBRA_LLT_SLIP = 14
ZEBRA_LLT_CSLIP = 15
ZEBRA_LLT_SLIP6 = 16
ZEBRA_LLT_CSLIP6 = 17
ZEBRA_LLT_RSRVD = 18
ZEBRA_LLT_ADAPT = 19
ZEBRA_LLT_ROSE = 20
ZEBRA_LLT_X25 = 21
ZEBRA_LLT_PPP = 22
ZEBRA_LLT_CHDLC = 23
ZEBRA_LLT_LAPB = 24
ZEBRA_LLT_RAWHDLC = 25
ZEBRA_LLT_IPIP = 26
ZEBRA_LLT_IPIP6 = 27
ZEBRA_LLT_FRAD = 28
ZEBRA_LLT_SKIP = 29
ZEBRA_LLT_LOOPBACK = 30
ZEBRA_LLT_LOCALTLK = 31
ZEBRA_LLT_FDDI = 32
ZEBRA_LLT_SIT = 33
ZEBRA_LLT_IPDDP = 34
ZEBRA_LLT_IPGRE = 35
ZEBRA_LLT_IP6GRE = 36
ZEBRA_LLT_PIMREG = 37
ZEBRA_LLT_HIPPI = 38
ZEBRA_LLT_ECONET = 39
ZEBRA_LLT_IRDA = 40
ZEBRA_LLT_FCPP = 41
ZEBRA_LLT_FCAL = 42
ZEBRA_LLT_FCPL = 43
ZEBRA_LLT_FCFABRIC = 44
ZEBRA_LLT_IEEE802_TR = 45
ZEBRA_LLT_IEEE80211 = 46
ZEBRA_LLT_IEEE80211_RADIOTAP = 47
ZEBRA_LLT_IEEE802154 = 48
ZEBRA_LLT_IEEE802154_PHY = 49

# "non-official" architectural constants
MAX_CLASS_TYPE = 8


# Utility functions/classes

IPv4Prefix = bgp.IPAddrPrefix
IPv6Prefix = bgp.IP6AddrPrefix


def _parse_ip_prefix(family, buf):
    if family == socket.AF_INET:
        prefix, rest = bgp.IPAddrPrefix.parser(buf)
    elif family == socket.AF_INET6:
        prefix, rest = IPv6Prefix.parser(buf)
    else:
        raise struct.error('Unsupported family: %d' % family)

    return prefix.prefix, rest


def _serialize_ip_prefix(prefix):
    if ip.valid_ipv4(prefix):
        prefix_addr, prefix_num = prefix.split('/')
        return bgp.IPAddrPrefix(int(prefix_num), prefix_addr).serialize()
    elif ip.valid_ipv6(prefix):
        prefix_addr, prefix_num = prefix.split('/')
        return IPv6Prefix(int(prefix_num), prefix_addr).serialize()
    else:
        raise ValueError('Invalid prefix: %s' % prefix)


class InterfaceLinkParams(stringify.StringifyMixin):
    """
    Interface Link Parameters class for if_link_params structure.
    """
    # Interface Link Parameters structure:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Status of Link Parameters                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Traffic Engineering metric                                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Maximum Bandwidth                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Maximum Reservable Bandwidth                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Unreserved Bandwidth per Class Type * MAX_CLASS_TYPE  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Administrative group                                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Remote AS number                                              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Remote IP address                                             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Link Average Delay                                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Link Min Delay                                                |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Link Max Delay                                                |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Link Delay Variation                                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Link Packet Loss                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Residual Bandwidth                                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Available Bandwidth                                   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Utilized Bandwidth                                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IIff'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _REPEATED_FMT = '!f'
    REPEATED_SIZE = struct.calcsize(_REPEATED_FMT)
    _FOOTER_FMT = '!II4sIIIIffff'
    FOOTER_SIZE = struct.calcsize(_FOOTER_FMT)

    def __init__(self, lp_status, te_metric, max_bw, max_reserved_bw,
                 unreserved_bw, admin_group, remote_as, remote_ip,
                 average_delay, min_delay, max_delay, delay_var, pkt_loss,
                 residual_bw, average_bw, utilized_bw):
        super(InterfaceLinkParams, self).__init__()
        self.lp_status = lp_status
        self.te_metric = te_metric
        self.max_bw = max_bw
        self.max_reserved_bw = max_reserved_bw
        assert isinstance(unreserved_bw, (list, tuple))
        assert len(unreserved_bw) == MAX_CLASS_TYPE
        self.unreserved_bw = unreserved_bw
        self.admin_group = admin_group
        self.remote_as = remote_as
        assert netaddr.valid_ipv4(remote_ip)
        self.remote_ip = remote_ip
        self.average_delay = average_delay
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.delay_var = delay_var
        self.pkt_loss = pkt_loss
        self.residual_bw = residual_bw
        self.average_bw = average_bw
        self.utilized_bw = utilized_bw

    @classmethod
    def parse(cls, buf):
        (lp_status, te_metric, max_bw,
         max_reserved_bw) = struct.unpack_from(cls._HEADER_FMT, buf)
        offset = cls.HEADER_SIZE

        unreserved_bw = []
        for _ in range(MAX_CLASS_TYPE):
            (u_bw,) = struct.unpack_from(cls._REPEATED_FMT, buf, offset)
            unreserved_bw.append(u_bw)
            offset += cls.REPEATED_SIZE

        (admin_group, remote_as, remote_ip, average_delay, min_delay,
         max_delay, delay_var, pkt_loss, residual_bw, average_bw,
         utilized_bw) = struct.unpack_from(
             cls._FOOTER_FMT, buf, offset)
        offset += cls.FOOTER_SIZE

        remote_ip = addrconv.ipv4.bin_to_text(remote_ip)

        return cls(lp_status, te_metric, max_bw, max_reserved_bw,
                   unreserved_bw, admin_group, remote_as, remote_ip,
                   average_delay, min_delay, max_delay, delay_var, pkt_loss,
                   residual_bw, average_bw, utilized_bw), buf[offset:]

    def serialize(self):
        buf = struct.pack(
            self._HEADER_FMT, self.lp_status, self.te_metric, self.max_bw,
            self.max_reserved_bw)

        for u_bw in self.unreserved_bw:
            buf += struct.pack(self._REPEATED_FMT, u_bw)

        remote_ip = addrconv.ipv4.text_to_bin(self.remote_ip)

        buf += struct.pack(
            self._FOOTER_FMT, self.admin_group, self.remote_as, remote_ip,
            self.average_delay, self.min_delay, self.max_delay,
            self.delay_var, self.pkt_loss, self.residual_bw, self.average_bw,
            self.utilized_bw)

        return buf


@six.add_metaclass(abc.ABCMeta)
class _NextHop(type_desc.TypeDisp, stringify.StringifyMixin):
    """
    Base class for Zebra Nexthop structure.
    """
    # Zebra Nexthop structure:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Type  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 address or Interface Index number (Variable)          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!B'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, ifindex=None, ifname=None, addr=None, type_=None):
        super(_NextHop, self).__init__()
        self.ifindex = ifindex
        self.ifname = ifname
        self.addr = addr
        if type_ is None:
            type_ = self._rev_lookup_type(self.__class__)
        self.type = type_

    @classmethod
    @abc.abstractmethod
    def parse(cls, buf):
        (type_,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        subcls = cls._lookup_type(type_)
        if subcls is None:
            raise struct.error('unsupported Nexthop type: %d' % type_)

        return subcls.parse(rest)

    @abc.abstractmethod
    def _serialize(self):
        return b''

    def serialize(self):
        return struct.pack(self._HEADER_FMT, self.type) + self._serialize()


_NEXTHOP_COUNT_FMT = '!B'  # nexthop_count
_NEXTHOP_COUNT_SIZE = struct.calcsize(_NEXTHOP_COUNT_FMT)


def _parse_nexthops(buf):
    (nexthop_count,) = struct.unpack_from(_NEXTHOP_COUNT_FMT, buf)
    rest = buf[_NEXTHOP_COUNT_SIZE:]

    nexthops = []
    for _ in range(nexthop_count):
        nexthop, rest = _NextHop.parse(rest)
        nexthops.append(nexthop)

    return nexthops, rest


def _serialize_nexthops(nexthops):
    nexthop_count = len(nexthops)
    buf = struct.pack(_NEXTHOP_COUNT_FMT, nexthop_count)

    if nexthop_count == 0:
        return buf

    for nexthop in nexthops:
        buf += nexthop.serialize()

    return buf


@_NextHop.register_type(ZEBRA_NEXTHOP_IFINDEX)
class NextHopIFIndex(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IFINDEX type.
    """
    _BODY_FMT = '!I'  # ifindex
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        (ifindex,) = struct.unpack_from(cls._BODY_FMT, buf)
        rest = buf[cls.BODY_SIZE:]

        return cls(ifindex=ifindex), rest

    def _serialize(self):
        return struct.pack(self._BODY_FMT, self.ifindex)


@_NextHop.register_type(ZEBRA_NEXTHOP_IFNAME)
class NextHopIFName(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IFNAME type.
    """
    _BODY_FMT = '!I'  # ifindex
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        (ifindex,) = struct.unpack_from(cls._BODY_FMT, buf)
        rest = buf[cls.BODY_SIZE:]

        return cls(ifindex=ifindex), rest

    def _serialize(self):
        return struct.pack(self._BODY_FMT, self.ifindex)


@_NextHop.register_type(ZEBRA_NEXTHOP_IPV4)
class NextHopIPv4(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV4 type.
    """
    _BODY_FMT = '!4s'  # addr(IPv4)
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        addr = addrconv.ipv4.bin_to_text(buf[:cls.BODY_SIZE])
        rest = buf[cls.BODY_SIZE:]

        return cls(addr=addr), rest

    def _serialize(self):
        return addrconv.ipv4.text_to_bin(self.addr)


@_NextHop.register_type(ZEBRA_NEXTHOP_IPV4_IFINDEX)
class NextHopIPv4IFIndex(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV4_IFINDEX type.
    """
    _BODY_FMT = '!4sI'  # addr(IPv4), ifindex
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        (addr, ifindex) = struct.unpack_from(cls._BODY_FMT, buf)
        addr = addrconv.ipv4.bin_to_text(addr)
        rest = buf[cls.BODY_SIZE:]

        return cls(ifindex=ifindex, addr=addr), rest

    def _serialize(self):
        addr = addrconv.ipv4.text_to_bin(self.addr)

        return struct.pack(self._BODY_FMT, addr, self.ifindex)


@_NextHop.register_type(ZEBRA_NEXTHOP_IPV4_IFNAME)
class NextHopIPv4IFName(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV4_IFNAME type.
    """
    _BODY_FMT = '!4sI'  # addr(IPv4), ifindex
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        (addr, ifindex) = struct.unpack_from(cls._BODY_FMT, buf)
        addr = addrconv.ipv4.bin_to_text(addr)
        rest = buf[cls.BODY_SIZE:]

        return cls(ifindex=ifindex, addr=addr), rest

    def _serialize(self):
        addr = addrconv.ipv4.text_to_bin(self.addr)

        return struct.pack(self._BODY_FMT, addr, self.ifindex)


@_NextHop.register_type(ZEBRA_NEXTHOP_IPV6)
class NextHopIPv6(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV6 type.
    """
    _BODY_FMT = '!16s'  # addr(IPv6)
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        addr = addrconv.ipv6.bin_to_text(buf[:cls.BODY_SIZE])
        rest = buf[cls.BODY_SIZE:]

        return cls(addr=addr), rest

    def _serialize(self):
        return addrconv.ipv6.text_to_bin(self.addr)


@_NextHop.register_type(ZEBRA_NEXTHOP_IPV6_IFINDEX)
class NextHopIPv6IFIndex(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV6_IFINDEX type.
    """
    _BODY_FMT = '!16sI'  # addr(IPv6), ifindex
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        (addr, ifindex) = struct.unpack_from(cls._BODY_FMT, buf)
        addr = addrconv.ipv6.bin_to_text(addr)
        rest = buf[cls.BODY_SIZE:]

        return cls(ifindex=ifindex, addr=addr), rest

    def _serialize(self):
        addr = addrconv.ipv6.text_to_bin(self.addr)

        return struct.pack(self._BODY_FMT, addr, self.ifindex)


@_NextHop.register_type(ZEBRA_NEXTHOP_IPV6_IFNAME)
class NextHopIPv6IFName(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV6_IFNAME type.
    """
    _BODY_FMT = '!16sI'  # addr(IPv6), ifindex
    BODY_SIZE = struct.calcsize(_BODY_FMT)

    @classmethod
    def parse(cls, buf):
        (addr, ifindex) = struct.unpack_from(cls._BODY_FMT, buf)
        addr = addrconv.ipv6.bin_to_text(addr)
        rest = buf[cls.BODY_SIZE:]

        return cls(ifindex=ifindex, addr=addr), rest

    def _serialize(self):
        addr = addrconv.ipv6.text_to_bin(self.addr)

        return struct.pack(self._BODY_FMT, addr, self.ifindex)


@_NextHop.register_type(ZEBRA_NEXTHOP_BLACKHOLE)
class NextHopBlackhole(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_BLACKHOLE type.
    """

    @classmethod
    def parse(cls, buf):
        return cls(), buf

    def _serialize(self):
        return b''


class RegisteredNexthop(stringify.StringifyMixin):
    """
    Unit of ZEBRA_NEXTHOP_REGISTER message body.
    """
    # Unit of Zebra Nexthop Register message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Connected     | Family                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (Variable)                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!?H'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, connected, family, prefix):
        super(RegisteredNexthop, self).__init__()
        self.connected = connected
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix

    @classmethod
    def parse(cls, buf):
        (connected, family) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        prefix, rest = _parse_ip_prefix(family, rest)

        return cls(connected, family, prefix), rest

    def serialize(self):
        buf = struct.pack(self._HEADER_FMT, self.connected, self.family)

        return buf + _serialize_ip_prefix(self.prefix)


# Zebra message class

class ZebraMessage(packet_base.PacketBase):
    """
    Zebra protocol parser/serializer class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ==========================================================
    Attribute      Description
    ============== ==========================================================
    length         Total packet length including this header.
                   The minimum length is 3 bytes for version 0 messages,
                   6 bytes for version 1/2 messages and 8 bytes for version
                   3 messages.
    version        Version number of the Zebra protocol message.
                   To instantiate messages with other than the default
                   version, ``version`` must be specified.
    vrf_id         VRF ID for the route contained in message.
                   Not present in version 0/1/2 messages in the on-wire
                   structure, and always 0 for theses version.
    command        Zebra Protocol command, which denotes message type.
    body           Messages body.
                   An instance of subclass of ``_ZebraMessageBody`` named
                   like "Zebra + <message name>" (e.g., ``ZebraHello``).
                   Or ``None`` if message does not contain any body.
    ============== ==========================================================

    .. Note::

        To instantiate Zebra messages, ``command`` can be omitted when the
        valid ``body`` is specified.

        ::

            >>> from ryu.lib.packet import zebra
            >>> zebra.ZebraMessage(body=zebra.ZebraHello())
            ZebraMessage(body=ZebraHello(route_type=14),command=23,
            length=None,version=3,vrf_id=0)

        On the other hand, if ``body`` is omitted, ``command`` must be
        specified.

        ::

            >>> zebra.ZebraMessage(command=zebra.ZEBRA_INTERFACE_ADD)
            ZebraMessage(body=None,command=1,length=None,version=3,vrf_id=0)
    """

    # Zebra Protocol Common Header (version 0):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Length                        | Command       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _V0_HEADER_FMT = '!HB'
    V0_HEADER_SIZE = struct.calcsize(_V0_HEADER_FMT)
    _MIN_LEN = V0_HEADER_SIZE

    # Zebra Protocol Common Header (version 1):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Length                        | Marker        | Version       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Command                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _V1_HEADER_FMT = '!HBBH'
    V1_HEADER_SIZE = struct.calcsize(_V1_HEADER_FMT)

    # Zebra Protocol Common Header (version 3):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Length                        | Marker        | Version       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | VRF ID                        | Command                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _V3_HEADER_FMT = '!HBBHH'
    V3_HEADER_SIZE = struct.calcsize(_V3_HEADER_FMT)

    # Default Zebra protocol version
    _DEFAULT_VERSION = 3

    # Note: Marker should be 0xff(=255) in the version>=1 header.
    _MARKER = 0xff

    def __init__(self, length=None, version=_DEFAULT_VERSION,
                 vrf_id=0, command=None, body=None):
        super(ZebraMessage, self).__init__()
        self.length = length
        self.version = version
        self.vrf_id = vrf_id
        if body is None:
            assert command is not None
        else:
            assert isinstance(body, _ZebraMessageBody)
            if command is None:
                command = _ZebraMessageBody.rev_lookup_command(body.__class__)
        self.command = command
        self.body = body

    @classmethod
    def get_header_size(cls, version):
        if version == 0:
            return cls.V0_HEADER_SIZE
        elif version in [1, 2]:
            return cls.V1_HEADER_SIZE
        elif version == 3:
            return cls.V3_HEADER_SIZE
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % version)

    @classmethod
    def parse_header(cls, buf):
        (length, marker) = struct.unpack_from(cls._V0_HEADER_FMT, buf)
        if marker != cls._MARKER:
            command = marker
            body_buf = buf[cls.V0_HEADER_SIZE:length]
            # version=0, vrf_id=0
            return length, 0, 0, command, body_buf

        (length, marker, version, command) = struct.unpack_from(
            cls._V1_HEADER_FMT, buf)
        if version in [1, 2]:
            body_buf = buf[cls.V1_HEADER_SIZE:length]
            # vrf_id=0
            return length, version, 0, command, body_buf

        (length, marker, version, vrf_id, command) = struct.unpack_from(
            cls._V3_HEADER_FMT, buf)
        if version == 3:
            body_buf = buf[cls.V3_HEADER_SIZE:length]
            return length, version, vrf_id, command, body_buf

        raise struct.error(
            'Failed to parse Zebra protocol header: '
            'marker=%d, version=%d' % (marker, version))

    @classmethod
    def parser(cls, buf):
        buf = six.binary_type(buf)
        (length, version, vrf_id, command,
         body_buf) = cls.parse_header(buf)

        if body_buf:
            body_cls = _ZebraMessageBody.lookup_command(command)
            body = body_cls.parse(body_buf)
        else:
            body = None

        rest = buf[length:]

        return cls(length, version, vrf_id, command, body), cls, rest

    def serialize_header(self, body_len):
        if self.version == 0:
            self.length = self.V0_HEADER_SIZE + body_len  # fixup
            return struct.pack(
                self._V0_HEADER_FMT,
                self.length, self.command)
        elif self.version in [1, 2]:
            self.length = self.V1_HEADER_SIZE + body_len  # fixup
            return struct.pack(
                self._V1_HEADER_FMT,
                self.length, self._MARKER, self.version,
                self.command)
        elif self.version == 3:
            self.length = self.V3_HEADER_SIZE + body_len  # fixup
            return struct.pack(
                self._V3_HEADER_FMT,
                self.length, self._MARKER, self.version,
                self.vrf_id, self.command)
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % self.version)

    def serialize(self, _payload=None, _prev=None):
        if isinstance(self.body, _ZebraMessageBody):
            body = self.body.serialize()
        else:
            body = b''

        return self.serialize_header(len(body)) + body


# Alias
zebra = ZebraMessage


# Zebra message body classes

class _ZebraMessageBody(type_desc.TypeDisp, stringify.StringifyMixin):
    """
    Base class for Zebra message body.
    """

    @classmethod
    def lookup_command(cls, command):
        return cls._lookup_type(command)

    @classmethod
    def rev_lookup_command(cls, body_cls):
        return cls._rev_lookup_type(body_cls)

    @classmethod
    def parse(cls, buf):
        return cls()

    def serialize(self):
        return b''


@_ZebraMessageBody.register_unknown_type()
class ZebraUnknownMessage(_ZebraMessageBody):
    """
    Message body class for Unknown command.
    """

    def __init__(self, buf):
        super(ZebraUnknownMessage, self).__init__()
        self.buf = buf

    @classmethod
    def parse(cls, buf):
        return cls(buf)

    def serialize(self):
        return self.buf


@six.add_metaclass(abc.ABCMeta)
class _ZebraInterface(_ZebraMessageBody):
    """
    Base class for ZEBRA_INTERFACE_ADD, ZEBRA_INTERFACE_DELETE,
    ZEBRA_INTERFACE_UP and ZEBRA_INTERFACE_DOWN message body.
    """
    # Zebra Interface Add/Delete message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface Name (INTERFACE_NAMSIZE bytes length)               |
    # |                                                               |
    # |                                                               |
    # |                                                               |
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface index                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | status        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface flags                                               |
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface's MTU for IPv4                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface's MTU for IPv6                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Bandwidth                                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Link Layer Type)                                             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Hardware Address Length                                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Hardware Address    if HW length different from 0             |
    # |  ...                max is INTERFACE_HWADDR_MAX               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | link_params?  |  Whether a link-params follows: 1 or 0.
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Link params    0 or 1 INTERFACE_LINK_PARAMS_SIZE sized        |
    # |  ....          (struct if_link_params).                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!%dsIBQIIIIII' % INTERFACE_NAMSIZE
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _HEADER_SHORT_FMT = '!%dsIBQIIIII' % INTERFACE_NAMSIZE
    HEADER_SHORT_SIZE = struct.calcsize(_HEADER_SHORT_FMT)

    # link_params_state (whether a link-params follows)
    _LP_STATE_FMT = '!?'
    LP_STATE_SIZE = struct.calcsize(_LP_STATE_FMT)
    # See InterfaceLinkParams class for Link params structure

    def __init__(self, ifname, ifindex, status, if_flags,
                 metric, ifmtu, ifmtu6, bandwidth,
                 ll_type=None, hw_addr_len=0, hw_addr=None,
                 link_params=None):
        super(_ZebraInterface, self).__init__()
        self.ifname = ifname
        self.ifindex = ifindex
        self.status = status
        self.if_flags = if_flags
        self.metric = metric
        self.ifmtu = ifmtu
        self.ifmtu6 = ifmtu6
        self.bandwidth = bandwidth
        self.ll_type = ll_type
        self.hw_addr_lenght = hw_addr_len
        hw_addr = hw_addr or b''
        self.hw_addr = hw_addr
        assert (isinstance(link_params, InterfaceLinkParams)
                or link_params is None)
        self.link_params = link_params

    @classmethod
    def parse(cls, buf):
        ll_type = None
        if (len(buf) == cls.HEADER_SHORT_SIZE + 6  # with MAC addr
                or len(buf) == cls.HEADER_SHORT_SIZE):  # without MAC addr
            # Assumption: Case for version<=2
            (ifname, ifindex, status, if_flags, metric,
             ifmtu, ifmtu6, bandwidth,
             hw_addr_len) = struct.unpack_from(cls._HEADER_SHORT_FMT, buf)
            rest = buf[cls.HEADER_SHORT_SIZE:]
        else:
            (ifname, ifindex, status, if_flags, metric,
             ifmtu, ifmtu6, bandwidth, ll_type,
             hw_addr_len) = struct.unpack_from(cls._HEADER_FMT, buf)
            rest = buf[cls.HEADER_SIZE:]
        ifname = str(six.text_type(ifname.strip(b'\x00'), 'ascii'))

        hw_addr_len = min(hw_addr_len, INTERFACE_HWADDR_MAX)
        hw_addr_bin = rest[:hw_addr_len]
        rest = rest[hw_addr_len:]
        if 0 < hw_addr_len < 7:
            # Assuming MAC address
            hw_addr = addrconv.mac.bin_to_text(
                hw_addr_bin + b'\x00' * (6 - hw_addr_len))
        else:
            # Unknown hardware address
            hw_addr = hw_addr_bin

        if not rest:
            return cls(ifname, ifindex, status, if_flags, metric,
                       ifmtu, ifmtu6, bandwidth, ll_type,
                       hw_addr_len, hw_addr)

        (link_param_state,) = struct.unpack_from(cls._LP_STATE_FMT, rest)
        rest = rest[cls.LP_STATE_SIZE:]

        if link_param_state:
            link_params, rest = InterfaceLinkParams.parse(rest)
        else:
            link_params = None

        return cls(ifname, ifindex, status, if_flags, metric, ifmtu, ifmtu6,
                   bandwidth, ll_type, hw_addr_len, hw_addr, link_params)

    def serialize(self):
        # fixup
        if netaddr.valid_mac(self.hw_addr):
            # MAC address
            hw_addr_len = 6
            hw_addr = addrconv.mac.text_to_bin(self.hw_addr)
        else:
            # Unknown hardware address
            hw_addr_len = len(self.hw_addr)
            hw_addr = self.hw_addr

        if self.ll_type:
            # Assumption: version<=2
            buf = struct.pack(
                self._HEADER_FMT,
                self.ifname.encode('ascii'), self.ifindex, self.status,
                self.if_flags, self.metric, self.ifmtu, self.ifmtu6,
                self.bandwidth, self.ll_type, hw_addr_len) + hw_addr
        else:
            buf = struct.pack(
                self._HEADER_SHORT_FMT,
                self.ifname.encode('ascii'), self.ifindex, self.status,
                self.if_flags, self.metric, self.ifmtu, self.ifmtu6,
                self.bandwidth, hw_addr_len) + hw_addr

        if isinstance(self.link_params, InterfaceLinkParams):
            buf += struct.pack(self._LP_STATE_FMT, True)
            buf += self.link_params.serialize()
        elif self.ll_type is None:
            # Assumption: version<=2
            pass
        else:
            buf += struct.pack(self._LP_STATE_FMT, False)

        return buf


@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_ADD)
class ZebraInterfaceAdd(_ZebraInterface):
    """
    Message body class for ZEBRA_INTERFACE_ADD.
    """


@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_DELETE)
class ZebraInterfaceDelete(_ZebraInterface):
    """
    Message body class for ZEBRA_INTERFACE_DELETE.
    """


@six.add_metaclass(abc.ABCMeta)
class _ZebraInterfaceAddress(_ZebraMessageBody):
    """
    Base class for ZEBRA_INTERFACE_ADDRESS_ADD and
    ZEBRA_INTERFACE_ADDRESS_DELETE message body.
    """
    # Zebra Interface Address Add/Delete message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface index                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IFC Flags     |  flags for connected address
    # +-+-+-+-+-+-+-+-+
    # | Family        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (Variable)                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix len    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Destination Address (Variable)                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IBB'  # ifindex, ifc_flags, family
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _IPV4_BODY_FMT = '!4sB4s'  # prefix, prefix_len, dest
    _IPV6_BODY_FMT = '!16sB16s'

    def __init__(self, ifindex, ifc_flags, family, prefix, dest):
        super(_ZebraInterfaceAddress, self).__init__()
        self.ifindex = ifindex
        self.ifc_flags = ifc_flags
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix
        assert netaddr.valid_ipv4(dest) or netaddr.valid_ipv6(dest)
        self.dest = dest

    @classmethod
    def parse(cls, buf):
        (ifindex, ifc_flags,
         family) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        if socket.AF_INET == family:
            (prefix, p_len,
             dest) = struct.unpack_from(cls._IPV4_BODY_FMT, rest)
            prefix = '%s/%d' % (addrconv.ipv4.bin_to_text(prefix), p_len)
            dest = addrconv.ipv4.bin_to_text(dest)
        elif socket.AF_INET6 == family:
            (prefix, p_len,
             dest) = struct.unpack_from(cls._IPV6_BODY_FMT, rest)
            prefix = '%s/%d' % (addrconv.ipv6.bin_to_text(prefix), p_len)
            dest = addrconv.ipv6.bin_to_text(dest)
        else:
            raise struct.error('Unsupported family: %d' % family)

        return cls(ifindex, ifc_flags, family, prefix, dest)

    def serialize(self):
        if ip.valid_ipv4(self.prefix):
            self.family = socket.AF_INET  # fixup
            prefix_addr, prefix_num = self.prefix.split('/')
            body_bin = struct.pack(
                self._IPV4_BODY_FMT,
                addrconv.ipv4.text_to_bin(prefix_addr),
                int(prefix_num),
                addrconv.ipv4.text_to_bin(self.dest))
        elif ip.valid_ipv6(self.prefix):
            self.family = socket.AF_INET6  # fixup
            prefix_addr, prefix_num = self.prefix.split('/')
            body_bin = struct.pack(
                self._IPV6_BODY_FMT,
                addrconv.ipv6.text_to_bin(prefix_addr),
                int(prefix_num),
                addrconv.ipv6.text_to_bin(self.dest))
        else:
            raise ValueError(
                'Invalid address family for prefix=%s and dest=%s'
                % (self.prefix, self.dest))

        buf = struct.pack(self._HEADER_FMT,
                          self.ifindex, self.ifc_flags, self.family)

        return buf + body_bin


@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_ADDRESS_ADD)
class ZebraInterfaceAddressAdd(_ZebraInterfaceAddress):
    """
    Message body class for ZEBRA_INTERFACE_ADDRESS_ADD.
    """


@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_ADDRESS_DELETE)
class ZebraInterfaceAddressDelete(_ZebraInterfaceAddress):
    """
    Message body class for ZEBRA_INTERFACE_ADDRESS_DELETE.
    """


@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_UP)
class ZebraInterfaceUp(_ZebraInterface):
    """
    Message body class for ZEBRA_INTERFACE_UP.
    """


@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_DOWN)
class ZebraInterfaceDown(_ZebraInterface):
    """
    Message body class for ZEBRA_INTERFACE_DOWN.
    """


@six.add_metaclass(abc.ABCMeta)
class _ZebraIPRoute(_ZebraMessageBody):
    """
    Base class for ZEBRA_IPV4_ROUTE_* and ZEBRA_IPV6_ROUTE_*
    message body.
    """
    # Zebra IPv4/IPv6 Route message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    | Flags         | Message       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | SAFI                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (Variable)                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Distance)    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Metric)                                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (MTU)                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (TAG)                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!BBBH'  # type, flags, message, safi
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    # API type specific constants
    _FAMILY = None  # either socket.AF_INET or socket.AF_INET6

    def __init__(self, route_type, flags, message, safi, prefix,
                 nexthops=None,
                 distance=None, metric=None, mtu=None, tag=None,
                 _tail=None):
        super(_ZebraIPRoute, self).__init__()
        self.route_type = route_type
        self.flags = flags
        self.message = message
        self.safi = safi
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops
        self.distance = distance
        self.metric = metric
        self.mtu = mtu
        self.tag = tag
        self._tail = _tail or b''

    @classmethod
    def _parse_message_option(cls, message, flag, fmt, buf):
        if message & flag:
            (option,) = struct.unpack_from(fmt, buf)
            return option, buf[struct.calcsize(fmt):]
        else:
            return None, buf

    @classmethod
    def parse(cls, buf):
        (route_type, flags, message, safi) = struct.unpack_from(
            cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        prefix, rest = _parse_ip_prefix(cls._FAMILY, rest)

        nexthops, rest = _parse_nexthops(rest)

        distance, rest = cls._parse_message_option(
            message, ZAPI_MESSAGE_DISTANCE, '!B', rest)
        metric, rest = cls._parse_message_option(
            message, ZAPI_MESSAGE_METRIC, '!I', rest)
        mtu, rest = cls._parse_message_option(
            message, ZAPI_MESSAGE_MTU, '!I', rest)
        tag, rest = cls._parse_message_option(
            message, ZAPI_MESSAGE_TAG, '!I', rest)

        return cls(route_type, flags, message, safi,
                   prefix, nexthops,
                   distance, metric, mtu, tag, _tail=rest)

    def _serialize_message_option(self, option, flag, fmt):
        if option is None:
            return b''

        # fixup
        self.message |= flag

        return struct.pack(fmt, option)

    def serialize(self):
        prefix = _serialize_ip_prefix(self.prefix)

        nexthops = _serialize_nexthops(self.nexthops)
        if self.nexthops:
            self.message |= ZAPI_MESSAGE_NEXTHOP  # fixup

        options = self._serialize_message_option(
            self.distance, ZAPI_MESSAGE_DISTANCE, '!B')
        options += self._serialize_message_option(
            self.metric, ZAPI_MESSAGE_METRIC, '!I')
        options += self._serialize_message_option(
            self.mtu, ZAPI_MESSAGE_MTU, '!I')
        options += self._serialize_message_option(
            self.tag, ZAPI_MESSAGE_TAG, '!I')

        header = struct.pack(
            self._HEADER_FMT,
            self.route_type, self.flags, self.message, self.safi)

        return header + prefix + nexthops + options + self._tail


class _ZebraIPv4Route(_ZebraIPRoute):
    """
    Base class for ZEBRA_IPV4_ROUTE_* message body.
    """
    _FAMILY = socket.AF_INET


@_ZebraMessageBody.register_type(ZEBRA_IPV4_ROUTE_ADD)
class ZebraIPv4RouteAdd(_ZebraIPv4Route):
    """
    Message body class for ZEBRA_IPV4_ROUTE_ADD.
    """


@_ZebraMessageBody.register_type(ZEBRA_IPV4_ROUTE_DELETE)
class ZebraIPv4RouteDelete(_ZebraIPv4Route):
    """
    Message body class for ZEBRA_IPV4_ROUTE_DELETE.
    """


class _ZebraIPv6Route(_ZebraIPRoute):
    """
    Base class for ZEBRA_IPV6_ROUTE_* message body.
    """
    _FAMILY = socket.AF_INET6


@_ZebraMessageBody.register_type(ZEBRA_IPV6_ROUTE_ADD)
class ZebraIPv6RouteAdd(_ZebraIPv6Route):
    """
    Message body class for ZEBRA_IPV6_ROUTE_ADD.
    """


@_ZebraMessageBody.register_type(ZEBRA_IPV6_ROUTE_DELETE)
class ZebraIPv6RouteDelete(_ZebraIPv6Route):
    """
    Message body class for ZEBRA_IPV6_ROUTE_DELETE.
    """


@six.add_metaclass(abc.ABCMeta)
class _ZebraRedistribute(_ZebraMessageBody):
    """
    Base class for ZEBRA_REDISTRIBUTE_ADD and ZEBRA_REDISTRIBUTE_DELETE
    message body.
    """
    # Zebra Redistribute message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    |
    # +-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!B'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, route_type):
        super(_ZebraRedistribute, self).__init__()
        self.route_type = route_type

    @classmethod
    def parse(cls, buf):
        (route_type,) = struct.unpack_from(cls._HEADER_FMT, buf)

        return cls(route_type)

    def serialize(self):
        return struct.pack(self._HEADER_FMT, self.route_type)


@_ZebraMessageBody.register_type(ZEBRA_REDISTRIBUTE_ADD)
class ZebraRedistributeAdd(_ZebraRedistribute):
    """
    Message body class for ZEBRA_REDISTRIBUTE_ADD.
    """


@_ZebraMessageBody.register_type(ZEBRA_REDISTRIBUTE_DELETE)
class ZebraRedistributeDelete(_ZebraRedistribute):
    """
    Message body class for ZEBRA_REDISTRIBUTE_DELETE.
    """


@six.add_metaclass(abc.ABCMeta)
class _ZebraRedistributeDefault(_ZebraMessageBody):
    """
    Base class for ZEBRA_REDISTRIBUTE_DEFAULT_ADD and
    ZEBRA_REDISTRIBUTE_DEFAULT_DELETE message body.
    """


@_ZebraMessageBody.register_type(ZEBRA_REDISTRIBUTE_DEFAULT_ADD)
class ZebraRedistributeDefaultAdd(_ZebraRedistribute):
    """
    Message body class for ZEBRA_REDISTRIBUTE_DEFAULT_ADD.
    """


@_ZebraMessageBody.register_type(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE)
class ZebraRedistributeDefaultDelete(_ZebraRedistribute):
    """
    Message body class for ZEBRA_REDISTRIBUTE_DEFAULT_DELETE.
    """


@six.add_metaclass(abc.ABCMeta)
class _ZebraIPNexthopLookup(_ZebraMessageBody):
    """
    Base class for ZEBRA_IPV4_NEXTHOP_LOOKUP and
    ZEBRA_IPV6_NEXTHOP_LOOKUP message body.
    """
    # Zebra IPv4/v6 Nexthop Lookup message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 address                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _METRIC_FMT = '!I'  # metric
    METRIC_SIZE = struct.calcsize(_METRIC_FMT)

    # Message type specific constants
    ADDR_CLS = None  # either addrconv.ipv4 or addrconv.ipv6
    ADDR_LEN = None  # IP address length in bytes

    def __init__(self, addr, metric=None, nexthops=None):
        super(_ZebraIPNexthopLookup, self).__init__()
        assert netaddr.valid_ipv4(addr) or netaddr.valid_ipv6(addr)
        self.addr = addr
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf):
        addr = cls.ADDR_CLS.bin_to_text(buf[:cls.ADDR_LEN])
        rest = buf[cls.ADDR_LEN:]

        metric = None
        if rest:
            # Note: Case for ZEBRA_IPV4_NEXTHOP_LOOKUP request
            (metric,) = struct.unpack_from(cls._METRIC_FMT, rest)
            rest = rest[cls.METRIC_SIZE:]

        nexthops = None
        if rest:
            nexthops, rest = _parse_nexthops(rest)

        return cls(addr, metric, nexthops)

    def serialize(self):
        buf = self.ADDR_CLS.text_to_bin(self.addr)

        if self.metric is None:
            return buf

        buf += struct.pack(self._METRIC_FMT, self.metric)

        return buf + _serialize_nexthops(self.nexthops)


@_ZebraMessageBody.register_type(ZEBRA_IPV4_NEXTHOP_LOOKUP)
class ZebraIPv4NexthopLookup(_ZebraIPNexthopLookup):
    """
    Message body class for ZEBRA_IPV4_NEXTHOP_LOOKUP.
    """
    ADDR_CLS = addrconv.ipv4
    ADDR_LEN = 4


@_ZebraMessageBody.register_type(ZEBRA_IPV6_NEXTHOP_LOOKUP)
class ZebraIPv6NexthopLookup(_ZebraIPNexthopLookup):
    """
    Message body class for ZEBRA_IPV6_NEXTHOP_LOOKUP.
    """
    ADDR_CLS = addrconv.ipv6
    ADDR_LEN = 16


@six.add_metaclass(abc.ABCMeta)
class _ZebraIPImportLookup(_ZebraMessageBody):
    """
    Base class for ZEBRA_IPV4_IMPORT_LOOKUP and
    ZEBRA_IPV6_IMPORT_LOOKUP message body.
    """
    # Zebra IPv4/v6 Import Lookup message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 prefix                                                |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _METRIC_FMT = '!I'  # metric
    METRIC_SIZE = struct.calcsize(_METRIC_FMT)

    # Message type specific constants
    PREFIX_CLS = None  # either addrconv.ipv4 or addrconv.ipv6
    PREFIX_LEN = None  # IP prefix length in bytes

    def __init__(self, prefix, metric=None, nexthops=None):
        super(_ZebraIPImportLookup, self).__init__()
        assert netaddr.valid_ipv4(prefix) or netaddr.valid_ipv6(prefix)
        self.prefix = prefix
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf):
        prefix = cls.PREFIX_CLS.bin_to_text(buf[:cls.PREFIX_LEN])
        rest = buf[cls.PREFIX_LEN:]

        metric = None
        if rest:
            (metric,) = struct.unpack_from(cls._METRIC_FMT, rest)
            rest = rest[cls.METRIC_SIZE:]

        nexthops = None
        if rest:
            nexthops, rest = _parse_nexthops(rest)

        return cls(prefix, metric, nexthops)

    def serialize(self):
        buf = self.PREFIX_CLS.text_to_bin(self.prefix)

        if self.metric is None:
            return buf

        buf += struct.pack(self._METRIC_FMT, self.metric)

        return buf + _serialize_nexthops(self.nexthops)


@_ZebraMessageBody.register_type(ZEBRA_IPV4_IMPORT_LOOKUP)
class ZebraIPv4ImportLookup(_ZebraIPImportLookup):
    """
    Message body class for ZEBRA_IPV4_IMPORT_LOOKUP.
    """
    PREFIX_CLS = addrconv.ipv4
    PREFIX_LEN = 4


@_ZebraMessageBody.register_type(ZEBRA_IPV6_IMPORT_LOOKUP)
class ZebraIPv6ImportLookup(_ZebraIPImportLookup):
    """
    Message body class for ZEBRA_IPV6_IMPORT_LOOKUP.
    """
    PREFIX_CLS = addrconv.ipv6
    PREFIX_LEN = 16


# Note: Not implemented in quagga/zebra/zserv.c
# @_ZebraMessageBody.register_type(ZEBRA_INTERFACE_RENAME)
# class ZebraInterfaceRename(_ZebraMessageBody):


@_ZebraMessageBody.register_type(ZEBRA_ROUTER_ID_ADD)
class ZebraRouterIDAdd(_ZebraMessageBody):
    """
    Message body class for ZEBRA_ROUTER_ID_ADD.
    """


@_ZebraMessageBody.register_type(ZEBRA_ROUTER_ID_DELETE)
class ZebraRouterIDDelete(_ZebraMessageBody):
    """
    Message body class for ZEBRA_ROUTER_ID_DELETE.
    """


@_ZebraMessageBody.register_type(ZEBRA_ROUTER_ID_UPDATE)
class ZebraRouterIDUpdate(_ZebraMessageBody):
    """
    Message body class for ZEBRA_ROUTER_ID_UPDATE.
    """
    # Zebra Router ID Update message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Family        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 prefix                                                |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix len    |
    # +-+-+-+-+-+-+-+-+
    _FAMILY_FMT = '!B'
    FAMILY_SIZE = struct.calcsize(_FAMILY_FMT)
    _IPV4_BODY_FMT = '!4sB'  # prefix, prefix_len
    _IPV6_BODY_FMT = '!16sB'

    def __init__(self, family, prefix):
        super(ZebraRouterIDUpdate, self).__init__()
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix

    @classmethod
    def parse(cls, buf):
        (family,) = struct.unpack_from(cls._FAMILY_FMT, buf)
        rest = buf[cls.FAMILY_SIZE:]

        if socket.AF_INET == family:
            (prefix, p_len) = struct.unpack_from(cls._IPV4_BODY_FMT, rest)
            prefix = '%s/%d' % (addrconv.ipv4.bin_to_text(prefix), p_len)
        elif socket.AF_INET6 == family:
            (prefix, p_len) = struct.unpack_from(cls._IPV6_BODY_FMT, rest)
            prefix = '%s/%d' % (addrconv.ipv6.bin_to_text(prefix), p_len)
        else:
            raise struct.error('Unsupported family: %d' % family)

        return cls(family, prefix)

    def serialize(self):
        if ip.valid_ipv4(self.prefix):
            self.family = socket.AF_INET  # fixup
            prefix_addr, prefix_num = self.prefix.split('/')
            body_bin = struct.pack(
                self._IPV4_BODY_FMT,
                addrconv.ipv4.text_to_bin(prefix_addr),
                int(prefix_num))
        elif ip.valid_ipv6(self.prefix):
            self.family = socket.AF_INET6  # fixup
            prefix_addr, prefix_num = self.prefix.split('/')
            body_bin = struct.pack(
                self._IPV6_BODY_FMT,
                addrconv.ipv6.text_to_bin(prefix_addr),
                int(prefix_num))
        else:
            raise ValueError('Invalid prefix: %s' % self.prefix)

        return struct.pack(self._FAMILY_FMT, self.family) + body_bin


@_ZebraMessageBody.register_type(ZEBRA_HELLO)
class ZebraHello(_ZebraMessageBody):
    """
    Message body class for ZEBRA_HELLO.
    """
    # Zebra Hello message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    |
    # +-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!B'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, route_type=ZEBRA_ROUTE_MAX):
        super(ZebraHello, self).__init__()
        self.route_type = route_type

    @classmethod
    def parse(cls, buf):
        route_type = None
        if buf:
            (route_type,) = struct.unpack_from(cls._HEADER_FMT, buf)

        return cls(route_type)

    def serialize(self):
        return struct.pack(self._HEADER_FMT, self.route_type)


@six.add_metaclass(abc.ABCMeta)
class _ZebraIPNexthopLookupMRib(_ZebraMessageBody):
    """
    Base class for ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB (and
    ZEBRA_IPV6_NEXTHOP_LOOKUP_MRIB) message body.
    """
    # Zebra IPv4/v6 Nexthop Lookup MRIB message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 address                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Distance      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _DISTANCE_METRIC_FMT = '!I'  # metric
    DISTANCE_METRIC_SIZE = struct.calcsize(_DISTANCE_METRIC_FMT)

    # Message type specific constants
    ADDR_CLS = None  # either addrconv.ipv4 or addrconv.ipv6
    ADDR_LEN = None  # IP address length in bytes

    def __init__(self, addr, distance, metric, nexthops=None):
        super(_ZebraIPNexthopLookupMRib, self).__init__()
        assert netaddr.valid_ipv4(addr) or netaddr.valid_ipv6(addr)
        self.addr = addr
        self.distance = distance
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf):
        addr = cls.ADDR_CLS.bin_to_text(buf[:cls.ADDR_LEN])
        rest = buf[cls.ADDR_LEN:]

        (metric,) = struct.unpack_from(cls._DISTANCE_METRIC_FMT, rest)
        rest = rest[cls.DISTANCE_METRIC_SIZE:]

        nexthops, rest = _parse_nexthops(rest)

        return cls(addr, metric, nexthops)

    def serialize(self):
        buf = self.ADDR_CLS.text_to_bin(self.addr)

        buf += struct.pack(
            self._DISTANCE_METRIC_FMT, self.distance, self.metric)

        return buf + self._serialize_nexthops(self.nexthops)


@_ZebraMessageBody.register_type(ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB)
class ZebraIPv4NexthopLookupMRib(_ZebraIPNexthopLookupMRib):
    """
    Message body class for ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB.
    """
    ADDR_CLS = addrconv.ipv4
    ADDR_LEN = 4


@_ZebraMessageBody.register_type(ZEBRA_VRF_UNREGISTER)
class ZebraVrfUnregister(_ZebraMessageBody):
    """
    Message body class for ZEBRA_VRF_UNREGISTER.
    """


@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_LINK_PARAMS)
class ZebraInterfaceLinkParams(_ZebraMessageBody):
    """
    Message body class for ZEBRA_INTERFACE_LINK_PARAMS.
    """
    # Zebra Interface Link Parameters message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface Index                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface Link Parameters                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!I'  # ifindex
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    # See InterfaceLinkParams class for Interface Link Parameters structure

    def __init__(self, ifindex, link_params):
        super(ZebraInterfaceLinkParams, self).__init__()
        self.ifindex = ifindex
        assert isinstance(link_params, InterfaceLinkParams)
        self.link_params = link_params

    @classmethod
    def parse(cls, buf):
        (ifindex,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        link_params, rest = InterfaceLinkParams.parse(rest)

        return cls(ifindex, link_params)

    def serialize(self):
        buf = struct.pack(self._HEADER_FMT, self.ifindex)

        return buf + self.link_params.serialize()


class _ZebraNexthopRegister(_ZebraMessageBody):
    """
    Base class for ZEBRA_NEXTHOP_REGISTER and ZEBRA_NEXTHOP_UNREGISTER
    message body.
    """
    # Zebra Nexthop Register message body:
    # (Repeat of RegisteredNexthop class)

    def __init__(self, nexthops):
        super(_ZebraNexthopRegister, self).__init__()
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, RegisteredNexthop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf):
        nexthops = []
        while buf:
            nexthop, buf = RegisteredNexthop.parse(buf)
            nexthops.append(nexthop)

        return cls(nexthops)

    def serialize(self):
        buf = b''
        for nexthop in self.nexthops:
            buf += nexthop.serialize()

        return buf


@_ZebraMessageBody.register_type(ZEBRA_NEXTHOP_REGISTER)
class ZebraNexthopRegister(_ZebraNexthopRegister):
    """
    Message body class for ZEBRA_NEXTHOP_REGISTER.
    """


@_ZebraMessageBody.register_type(ZEBRA_NEXTHOP_UNREGISTER)
class ZebraNexthopUnregister(_ZebraNexthopRegister):
    """
    Message body class for ZEBRA_NEXTHOP_UNREGISTER.
    """


@_ZebraMessageBody.register_type(ZEBRA_NEXTHOP_UPDATE)
class ZebraNexthopUpdate(_ZebraMessageBody):
    """
    Message body class for ZEBRA_NEXTHOP_UPDATE.
    """
    # Zebra IPv4/v6 Nexthop Update message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Family                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 prefix                                                |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _FAMILY_FMT = '!H'  # family
    FAMILY_SIZE = struct.calcsize(_FAMILY_FMT)
    _METRIC_FMT = '!I'  # metric
    METRIC_SIZE = struct.calcsize(_METRIC_FMT)

    def __init__(self, family, prefix, metric, nexthops=None):
        super(ZebraNexthopUpdate, self).__init__()
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf):
        (family,) = struct.unpack_from(cls._FAMILY_FMT, buf)
        rest = buf[cls.FAMILY_SIZE:]

        prefix, rest = _parse_ip_prefix(family, rest)

        (metric,) = struct.unpack_from(cls._METRIC_FMT, rest)
        rest = rest[cls.METRIC_SIZE:]

        nexthops, rest = _parse_nexthops(rest)

        return cls(family, prefix, metric, nexthops)

    def serialize(self):
        # fixup
        if ip.valid_ipv4(self.prefix):
            self.family = socket.AF_INET
        elif ip.valid_ipv6(self.prefix):
            self.family = socket.AF_INET6
        else:
            raise ValueError('Invalid prefix: %s' % self.prefix)

        buf = struct.pack(self._FAMILY_FMT, self.family)

        buf += _serialize_ip_prefix(self.prefix)

        buf += struct.pack(self._METRIC_FMT, self.metric)

        return buf + _serialize_nexthops(self.nexthops)
