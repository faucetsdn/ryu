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
from distutils.version import LooseVersion

import netaddr
import six

from ryu import flags as cfg_flags  # For loading 'zapi' option definition
from ryu.cfg import CONF
from ryu.lib import addrconv
from ryu.lib import ip
from ryu.lib import stringify
from ryu.lib import type_desc
from . import packet_base
from . import bgp
from . import safi as packet_safi


LOG = logging.getLogger(__name__)

# Default Zebra protocol version
_DEFAULT_VERSION = 3
_DEFAULT_FRR_VERSION = 4

_FRR_VERSION_2_0 = LooseVersion('2.0')
_FRR_VERSION_3_0 = LooseVersion('3.0')

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

# Zebra message types on FRRouting
FRR_ZEBRA_INTERFACE_ADD = 0
FRR_ZEBRA_INTERFACE_DELETE = 1
FRR_ZEBRA_INTERFACE_ADDRESS_ADD = 2
FRR_ZEBRA_INTERFACE_ADDRESS_DELETE = 3
FRR_ZEBRA_INTERFACE_UP = 4
FRR_ZEBRA_INTERFACE_DOWN = 5
FRR_ZEBRA_IPV4_ROUTE_ADD = 6
FRR_ZEBRA_IPV4_ROUTE_DELETE = 7
FRR_ZEBRA_IPV6_ROUTE_ADD = 8
FRR_ZEBRA_IPV6_ROUTE_DELETE = 9
FRR_ZEBRA_REDISTRIBUTE_ADD = 10
FRR_ZEBRA_REDISTRIBUTE_DELETE = 11
FRR_ZEBRA_REDISTRIBUTE_DEFAULT_ADD = 12
FRR_ZEBRA_REDISTRIBUTE_DEFAULT_DELETE = 13
FRR_ZEBRA_ROUTER_ID_ADD = 14
FRR_ZEBRA_ROUTER_ID_DELETE = 15
FRR_ZEBRA_ROUTER_ID_UPDATE = 16
FRR_ZEBRA_HELLO = 17
FRR_ZEBRA_NEXTHOP_REGISTER = 18
FRR_ZEBRA_NEXTHOP_UNREGISTER = 19
FRR_ZEBRA_NEXTHOP_UPDATE = 20
FRR_ZEBRA_INTERFACE_NBR_ADDRESS_ADD = 21
FRR_ZEBRA_INTERFACE_NBR_ADDRESS_DELETE = 22
FRR_ZEBRA_INTERFACE_BFD_DEST_UPDATE = 23
FRR_ZEBRA_IMPORT_ROUTE_REGISTER = 24
FRR_ZEBRA_IMPORT_ROUTE_UNREGISTER = 25
FRR_ZEBRA_IMPORT_CHECK_UPDATE = 26
FRR_ZEBRA_IPV4_ROUTE_IPV6_NEXTHOP_ADD = 27
FRR_ZEBRA_BFD_DEST_REGISTER = 28
FRR_ZEBRA_BFD_DEST_DEREGISTER = 29
FRR_ZEBRA_BFD_DEST_UPDATE = 30
FRR_ZEBRA_BFD_DEST_REPLAY = 31
FRR_ZEBRA_REDISTRIBUTE_IPV4_ADD = 32
FRR_ZEBRA_REDISTRIBUTE_IPV4_DEL = 33
FRR_ZEBRA_REDISTRIBUTE_IPV6_ADD = 34
FRR_ZEBRA_REDISTRIBUTE_IPV6_DEL = 35
FRR_ZEBRA_VRF_UNREGISTER = 36
FRR_ZEBRA_VRF_ADD = 37
FRR_ZEBRA_VRF_DELETE = 38
FRR_ZEBRA_INTERFACE_VRF_UPDATE = 39
FRR_ZEBRA_BFD_CLIENT_REGISTER = 40
FRR_ZEBRA_INTERFACE_ENABLE_RADV = 41
FRR_ZEBRA_INTERFACE_DISABLE_RADV = 42
FRR_ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB = 43
FRR_ZEBRA_INTERFACE_LINK_PARAMS = 44
FRR_ZEBRA_MPLS_LABELS_ADD = 45
FRR_ZEBRA_MPLS_LABELS_DELETE = 46
FRR_ZEBRA_IPV4_NEXTHOP_ADD = 47
FRR_ZEBRA_IPV4_NEXTHOP_DELETE = 48
FRR_ZEBRA_IPV6_NEXTHOP_ADD = 49
FRR_ZEBRA_IPV6_NEXTHOP_DELETE = 50

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

# Zebra route types on FRRouting
FRR_ZEBRA_ROUTE_SYSTEM = 0
FRR_ZEBRA_ROUTE_KERNEL = 1
FRR_ZEBRA_ROUTE_CONNECT = 2
FRR_ZEBRA_ROUTE_STATIC = 3
FRR_ZEBRA_ROUTE_RIP = 4
FRR_ZEBRA_ROUTE_RIPNG = 5
FRR_ZEBRA_ROUTE_OSPF = 6
FRR_ZEBRA_ROUTE_OSPF6 = 7
FRR_ZEBRA_ROUTE_ISIS = 8
FRR_ZEBRA_ROUTE_BGP = 9
FRR_ZEBRA_ROUTE_PIM = 10
FRR_ZEBRA_ROUTE_HSLS = 11
FRR_ZEBRA_ROUTE_OLSR = 12
FRR_ZEBRA_ROUTE_TABLE = 13
FRR_ZEBRA_ROUTE_LDP = 14
FRR_ZEBRA_ROUTE_VNC = 15
FRR_ZEBRA_ROUTE_VNC_DIRECT = 16
FRR_ZEBRA_ROUTE_VNC_DIRECT_RH = 17
FRR_ZEBRA_ROUTE_BGP_DIRECT = 18
FRR_ZEBRA_ROUTE_BGP_DIRECT_EXT = 19
FRR_ZEBRA_ROUTE_ALL = 20
FRR_ZEBRA_ROUTE_MAX = 21

# Zebra message flags
ZEBRA_FLAG_INTERNAL = 0x01
ZEBRA_FLAG_SELFROUTE = 0x02
ZEBRA_FLAG_BLACKHOLE = 0x04
ZEBRA_FLAG_IBGP = 0x08
ZEBRA_FLAG_SELECTED = 0x10
ZEBRA_FLAG_FIB_OVERRIDE = 0x20
ZEBRA_FLAG_STATIC = 0x40
ZEBRA_FLAG_REJECT = 0x80

# Zebra message flags on FRRouting
FRR_ZEBRA_FLAG_INTERNAL = 0x01
FRR_ZEBRA_FLAG_SELFROUTE = 0x02
FRR_ZEBRA_FLAG_BLACKHOLE = 0x04
FRR_ZEBRA_FLAG_IBGP = 0x08
FRR_ZEBRA_FLAG_SELECTED = 0x10
FRR_ZEBRA_FLAG_STATIC = 0x40
FRR_ZEBRA_FLAG_REJECT = 0x80
FRR_ZEBRA_FLAG_SCOPE_LINK = 0x100
FRR_ZEBRA_FLAG_FIB_OVERRIDE = 0x200

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

# Zebra nexthop flags on FRRouting
FRR_ZEBRA_NEXTHOP_IFINDEX = 1
FRR_ZEBRA_NEXTHOP_IPV4 = 2
FRR_ZEBRA_NEXTHOP_IPV4_IFINDEX = 3
FRR_ZEBRA_NEXTHOP_IPV6 = 4
FRR_ZEBRA_NEXTHOP_IPV6_IFINDEX = 5
FRR_ZEBRA_NEXTHOP_BLACKHOLE = 6

# Constants in quagga/lib/zclient.h

# Zebra API message flags
ZAPI_MESSAGE_NEXTHOP = 0x01
ZAPI_MESSAGE_IFINDEX = 0x02
ZAPI_MESSAGE_DISTANCE = 0x04
ZAPI_MESSAGE_METRIC = 0x08
ZAPI_MESSAGE_MTU = 0x10
ZAPI_MESSAGE_TAG = 0x20

# Zebra API message flags on FRRouting.
# Note: Constants for TAG/MTU is inverted from Quagga version.
FRR_ZAPI_MESSAGE_NEXTHOP = 0x01
FRR_ZAPI_MESSAGE_IFINDEX = 0x02
FRR_ZAPI_MESSAGE_DISTANCE = 0x04
FRR_ZAPI_MESSAGE_METRIC = 0x08
FRR_ZAPI_MESSAGE_TAG = 0x10
FRR_ZAPI_MESSAGE_MTU = 0x20
FRR_ZAPI_MESSAGE_SRCPFX = 0x40
FRR_ZAPI_MESSAGE_LABEL = 0x80

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
# Followings are extended on FRRouting
ZEBRA_INTERFACE_VRF_LOOPBACK = 1 << 3

# Zebra interface connected address flags
ZEBRA_IFA_SECONDARY = 1 << 0
ZEBRA_IFA_PEER = 1 << 1
ZEBRA_IFA_UNNUMBERED = 1 << 2

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

# Link Parameters Status
LP_UNSET = 0x0000
LP_TE = 0x0001
LP_MAX_BW = 0x0002
LP_MAX_RSV_BW = 0x0004
LP_UNRSV_BW = 0x0008
LP_ADM_GRP = 0x0010
LP_RMT_AS = 0x0020
LP_DELAY = 0x0040
LP_MM_DELAY = 0x0080
LP_DELAY_VAR = 0x0100
LP_PKT_LOSS = 0x0200
LP_RES_BW = 0x0400
LP_AVA_BW = 0x0800
LP_USE_BW = 0x1000
LP_TE_METRIC = 0x2000

# "non-official" architectural constants
MAX_CLASS_TYPE = 8

# Constants in frr/zebra/zebra_ptm.h

# Interface PTM Enable configuration
ZEBRA_IF_PTM_ENABLE_OFF = 0
ZEBRA_IF_PTM_ENABLE_ON = 1
ZEBRA_IF_PTM_ENABLE_UNSPEC = 2

# PTM status
ZEBRA_PTM_STATUS_DOWN = 0
ZEBRA_PTM_STATUS_UP = 1
ZEBRA_PTM_STATUS_UNKNOWN = 2

# Constants in frr/lib/bfd.h

# BFD status
BFD_STATUS_UNKNOWN = 1 << 0
BFD_STATUS_DOWN = 1 << 1
BFD_STATUS_UP = 1 << 2

# Constants in frr/lib/vrf.h

# VRF name length
VRF_NAMSIZ = 36

# Constants in frr/lib/mpls.h

# Reserved MPLS label values
MPLS_V4_EXP_NULL_LABEL = 0
MPLS_RA_LABEL = 1
MPLS_V6_EXP_NULL_LABEL = 2
MPLS_IMP_NULL_LABEL = 3
MPLS_ENTROPY_LABEL_INDICATOR = 7
MPLS_GAL_LABEL = 13
MPLS_OAM_ALERT_LABEL = 14
MPLS_EXTENSION_LABEL = 15
MPLS_MIN_RESERVED_LABEL = 0
MPLS_MAX_RESERVED_LABEL = 15
MPLS_MIN_UNRESERVED_LABEL = 16
MPLS_MAX_UNRESERVED_LABEL = 1048575


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


# Family and Zebra Prefix format:
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Family        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | IPv4/v6 prefix (4 bytes or 16 bytes)                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Prefix len    |
# +-+-+-+-+-+-+-+-+
_ZEBRA_FAMILY_FMT = '!B'  # family
_ZEBRA_FAMILY_SIZE = struct.calcsize(_ZEBRA_FAMILY_FMT)
_ZEBRA_IPV4_PREFIX_FMT = '!4sB'  # prefix, prefix_len
_ZEBRA_IPV6_PREFIX_FMT = '!16sB'
_ZEBRA_IPV4_PREFIX_SIZE = struct.calcsize(_ZEBRA_IPV4_PREFIX_FMT)
_ZEBRA_IPV6_PREFIX_SIZE = struct.calcsize(_ZEBRA_IPV6_PREFIX_FMT)
_ZEBRA_FAMILY_IPV4_PREFIX_FMT = '!B4sB'  # family, prefix, prefix_len
_ZEBRA_FAMILY_IPV6_PREFIX_FMT = '!B16sB'  # family, prefix, prefix_len


def _parse_zebra_family_prefix(buf):
    """
    Parses family and prefix in Zebra format.
    """
    (family,) = struct.unpack_from(_ZEBRA_FAMILY_FMT, buf)
    rest = buf[_ZEBRA_FAMILY_SIZE:]

    if socket.AF_INET == family:
        (prefix, p_len) = struct.unpack_from(_ZEBRA_IPV4_PREFIX_FMT, rest)
        prefix = '%s/%d' % (addrconv.ipv4.bin_to_text(prefix), p_len)
        rest = rest[_ZEBRA_IPV4_PREFIX_SIZE:]
    elif socket.AF_INET6 == family:
        (prefix, p_len) = struct.unpack_from(_ZEBRA_IPV6_PREFIX_FMT, rest)
        prefix = '%s/%d' % (addrconv.ipv6.bin_to_text(prefix), p_len)
        rest = rest[_ZEBRA_IPV6_PREFIX_SIZE:]
    else:
        raise struct.error('Unsupported family: %d' % family)

    return family, prefix, rest


def _serialize_zebra_family_prefix(prefix):
    """
    Serializes family and prefix in Zebra format.
    """
    if ip.valid_ipv4(prefix):
        family = socket.AF_INET  # fixup
        prefix_addr, prefix_num = prefix.split('/')
        return family, struct.pack(
            _ZEBRA_FAMILY_IPV4_PREFIX_FMT,
            family,
            addrconv.ipv4.text_to_bin(prefix_addr),
            int(prefix_num))
    elif ip.valid_ipv6(prefix):
        family = socket.AF_INET6  # fixup
        prefix_addr, prefix_num = prefix.split('/')
        return family, struct.pack(
            _ZEBRA_FAMILY_IPV6_PREFIX_FMT,
            family,
            addrconv.ipv6.text_to_bin(prefix_addr),
            int(prefix_num))

    raise ValueError('Invalid prefix: %s' % prefix)


def _is_frr_version_ge(compared_version):
    return CONF['zapi'].frr_version >= compared_version


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
    # | Number of Unreserved Bandwidth Classes (max is MAX_CLASS_TYPE)|
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (float) Unreserved Bandwidth per Class Type                   |
    # |  ...  repeats Number of Unreserved Bandwidth Classes times    |
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
    # lp_status, te_metric, max_bw, max_reserved_bw, bw_cls_num
    _HEADER_FMT = '!IIffI'
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _REPEATED_FMT = '!f'
    REPEATED_SIZE = struct.calcsize(_REPEATED_FMT)
    # admin_group, remote_as, remote_ip,
    # average_delay, min_delay, max_delay, delay_var,
    #  pkt_loss, residual_bw, average_bw, utilized_bw
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
        assert ip.valid_ipv4(remote_ip)
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
        (lp_status, te_metric, max_bw, max_reserved_bw,
         bw_cls_num) = struct.unpack_from(cls._HEADER_FMT, buf)
        if MAX_CLASS_TYPE < bw_cls_num:
            bw_cls_num = MAX_CLASS_TYPE
        offset = cls.HEADER_SIZE

        unreserved_bw = []
        for _ in range(bw_cls_num):
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
            self.max_reserved_bw, len(self.unreserved_bw))

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
        self.type = type_

    @classmethod
    @abc.abstractmethod
    def parse(cls, buf):
        (type_,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        subcls = cls._lookup_type(type_)
        if subcls is None:
            raise struct.error('unsupported Nexthop type: %d' % type_)

        nexthop, rest = subcls.parse(rest)
        nexthop.type = type_
        return nexthop, rest

    @abc.abstractmethod
    def _serialize(self):
        return b''

    def serialize(self, version=_DEFAULT_VERSION):
        if self.type is None:
            if version <= 3:
                nh_cls = _NextHop
            elif version == 4:
                nh_cls = _FrrNextHop
            else:
                raise ValueError(
                    'Unsupported Zebra protocol version: %d' % version)
            self.type = nh_cls._rev_lookup_type(self.__class__)
        return struct.pack(self._HEADER_FMT, self.type) + self._serialize()


@six.add_metaclass(abc.ABCMeta)
class _FrrNextHop(_NextHop):
    """
    Base class for Zebra Nexthop structure for translating nexthop types
    on FRRouting.
    """


_NEXTHOP_COUNT_FMT = '!B'  # nexthop_count
_NEXTHOP_COUNT_SIZE = struct.calcsize(_NEXTHOP_COUNT_FMT)


def _parse_nexthops(buf, version=_DEFAULT_VERSION):
    (nexthop_count,) = struct.unpack_from(_NEXTHOP_COUNT_FMT, buf)
    rest = buf[_NEXTHOP_COUNT_SIZE:]

    if version <= 3:
        nh_cls = _NextHop
    elif version == 4:
        nh_cls = _FrrNextHop
    else:
        raise struct.error(
            'Unsupported Zebra protocol version: %d' % version)

    nexthops = []
    for _ in range(nexthop_count):
        nexthop, rest = nh_cls.parse(rest)
        nexthops.append(nexthop)

    return nexthops, rest


def _serialize_nexthops(nexthops, version=_DEFAULT_VERSION):
    nexthop_count = len(nexthops)
    buf = struct.pack(_NEXTHOP_COUNT_FMT, nexthop_count)

    if nexthop_count == 0:
        return buf

    for nexthop in nexthops:
        buf += nexthop.serialize(version=version)

    return buf


@_FrrNextHop.register_type(FRR_ZEBRA_NEXTHOP_IFINDEX)
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


@_FrrNextHop.register_type(FRR_ZEBRA_NEXTHOP_IPV4)
@_NextHop.register_type(ZEBRA_NEXTHOP_IPV4)
class NextHopIPv4(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV4 type.
    """
    _BODY_FMT = '!4s'  # addr(IPv4)
    BODY_SIZE = struct.calcsize(_BODY_FMT)
    _BODY_FMT_FRR_V3 = '!4sI'  # addr(IPv4), ifindex
    BODY_SIZE_FRR_V3 = struct.calcsize(_BODY_FMT_FRR_V3)

    @classmethod
    def parse(cls, buf):
        if _is_frr_version_ge(_FRR_VERSION_3_0):
            (addr, ifindex) = struct.unpack_from(cls._BODY_FMT_FRR_V3, buf)
            addr = addrconv.ipv4.bin_to_text(addr)
            rest = buf[cls.BODY_SIZE_FRR_V3:]
            return cls(ifindex=ifindex, addr=addr), rest

        addr = addrconv.ipv4.bin_to_text(buf[:cls.BODY_SIZE])
        rest = buf[cls.BODY_SIZE:]

        return cls(addr=addr), rest

    def _serialize(self):
        if _is_frr_version_ge(_FRR_VERSION_3_0) and self.ifindex:
            addr = addrconv.ipv4.text_to_bin(self.addr)
            return struct.pack(self._BODY_FMT_FRR_V3, addr, self.ifindex)

        return addrconv.ipv4.text_to_bin(self.addr)


@_FrrNextHop.register_type(FRR_ZEBRA_NEXTHOP_IPV4_IFINDEX)
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


@_FrrNextHop.register_type(FRR_ZEBRA_NEXTHOP_IPV6)
@_NextHop.register_type(ZEBRA_NEXTHOP_IPV6)
class NextHopIPv6(_NextHop):
    """
    Nexthop class for ZEBRA_NEXTHOP_IPV6 type.
    """
    _BODY_FMT = '!16s'  # addr(IPv6)
    BODY_SIZE = struct.calcsize(_BODY_FMT)
    _BODY_FMT_FRR_V3 = '!16sI'  # addr(IPv6), ifindex
    BODY_SIZE_FRR_V3 = struct.calcsize(_BODY_FMT_FRR_V3)

    @classmethod
    def parse(cls, buf):
        if _is_frr_version_ge(_FRR_VERSION_3_0):
            (addr, ifindex) = struct.unpack_from(cls._BODY_FMT_FRR_V3, buf)
            addr = addrconv.ipv4.bin_to_text(addr)
            rest = buf[cls.BODY_SIZE_FRR_V3:]
            return cls(ifindex=ifindex, addr=addr), rest

        addr = addrconv.ipv6.bin_to_text(buf[:cls.BODY_SIZE])
        rest = buf[cls.BODY_SIZE:]

        return cls(addr=addr), rest

    def _serialize(self):
        if _is_frr_version_ge(_FRR_VERSION_3_0) and self.ifindex:
            addr = addrconv.ipv4.text_to_bin(self.addr)
            return struct.pack(self._BODY_FMT_FRR_V3, addr, self.ifindex)

        return addrconv.ipv6.text_to_bin(self.addr)


@_FrrNextHop.register_type(FRR_ZEBRA_NEXTHOP_IPV6_IFINDEX)
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


@_FrrNextHop.register_type(FRR_ZEBRA_NEXTHOP_BLACKHOLE)
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
    # Note: connected is renamed to flags on FRRouting.

    def __init__(self, connected, family, prefix):
        super(RegisteredNexthop, self).__init__()
        self.connected = connected
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix

    @property
    def flags(self):
        return self.connected

    @flags.setter
    def flags(self, v):
        self.connected = v

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

    # Note: Marker should be 0xff(=255) in the version>=1 header.
    # Also, FRRouting uses the different marker value.
    _MARKER = 0xff
    _LT_MARKER = 0xfe

    def __init__(self, length=None, version=_DEFAULT_VERSION,
                 vrf_id=0, command=None, body=None):
        super(ZebraMessage, self).__init__()
        self.length = length
        self.version = version
        self.vrf_id = vrf_id
        self.command = command
        self.body = body

    def _fill_command(self):
        assert isinstance(self.body, _ZebraMessageBody)
        body_base_cls = _ZebraMessageBody
        if self.version == 4:
            body_base_cls = _FrrZebraMessageBody
        self.command = body_base_cls.rev_lookup_command(self.body.__class__)

    @classmethod
    def get_header_size(cls, version):
        if version == 0:
            return cls.V0_HEADER_SIZE
        elif version in [1, 2]:
            return cls.V1_HEADER_SIZE
        elif version in [3, 4]:
            return cls.V3_HEADER_SIZE
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % version)

    @classmethod
    def parse_header(cls, buf):
        (length, marker) = struct.unpack_from(cls._V0_HEADER_FMT, buf)
        if marker not in [cls._MARKER, cls._LT_MARKER]:
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
        if version == 3 or (version == 4 and marker == cls._LT_MARKER):
            body_buf = buf[cls.V3_HEADER_SIZE:length]
            return length, version, vrf_id, command, body_buf

        raise struct.error(
            'Failed to parse Zebra protocol header: '
            'marker=%d, version=%d' % (marker, version))

    @classmethod
    def get_body_class(cls, version, command):
        if version == 4:
            return _FrrZebraMessageBody.lookup_command(command)
        else:
            return _ZebraMessageBody.lookup_command(command)

    @classmethod
    def _parser_impl(cls, buf, from_zebra=False):
        buf = six.binary_type(buf)
        (length, version, vrf_id, command,
         body_buf) = cls.parse_header(buf)

        if body_buf:
            body_cls = cls.get_body_class(version, command)
            if from_zebra:
                body = body_cls.parse_from_zebra(body_buf, version=version)
            else:
                body = body_cls.parse(body_buf, version=version)
        else:
            body = None

        rest = buf[length:]

        if from_zebra:
            return (cls(length, version, vrf_id, command, body),
                    _ZebraMessageFromZebra, rest)

        return cls(length, version, vrf_id, command, body), cls, rest

    @classmethod
    def parser(cls, buf):
        return cls._parser_impl(buf)

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
        elif self.version in [3, 4]:
            if self.version == 3:
                _marker = self._MARKER
            else:  # self.version == 4
                _marker = self._LT_MARKER
            self.length = self.V3_HEADER_SIZE + body_len  # fixup
            return struct.pack(
                self._V3_HEADER_FMT,
                self.length, _marker, self.version,
                self.vrf_id, self.command)
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % self.version)

    def serialize(self, _payload=None, _prev=None):
        if self.body is None:
            assert self.command is not None
            body = b''
        else:
            assert isinstance(self.body, _ZebraMessageBody)
            self._fill_command()  # fixup
            body = self.body.serialize(version=self.version)

        return self.serialize_header(len(body)) + body


class _ZebraMessageFromZebra(ZebraMessage):
    """
    This class is corresponding to the message sent from Zebra daemon.
    """

    @classmethod
    def parser(cls, buf):
        return ZebraMessage._parser_impl(buf, from_zebra=True)


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
    def parse(cls, buf, version=_DEFAULT_VERSION):
        return cls()

    @classmethod
    def parse_from_zebra(cls, buf, version=_DEFAULT_VERSION):
        return cls.parse(buf, version=version)

    def serialize(self, version=_DEFAULT_VERSION):
        return b''


class _FrrZebraMessageBody(_ZebraMessageBody):
    """
    Pseudo message body class for translating message types on FRRouting.
    """


@_FrrZebraMessageBody.register_unknown_type()
@_ZebraMessageBody.register_unknown_type()
class ZebraUnknownMessage(_ZebraMessageBody):
    """
    Message body class for Unknown command.
    """

    def __init__(self, buf):
        super(ZebraUnknownMessage, self).__init__()
        self.buf = buf

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        return cls(buf)

    def serialize(self, version=_DEFAULT_VERSION):
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
    # | Status        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface flags                                               |
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (PTM Enable)  | (PTM Status)  | v4(FRRouting)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Speed): v4(FRRouting v3.0 or later)                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface's MTU for IPv4                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface's MTU for IPv6                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Bandwidth                                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Link Layer Type): v3 or later                                |
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
    # ifname, ifindex, status, if_flags, metric, ifmtu, ifmtu6, bandwidth,
    # hw_addr_len
    _HEADER_FMT = '!%dsIBQIIIII' % INTERFACE_NAMSIZE
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    # ifname, ifindex, status, if_flags, metric, ifmtu, ifmtu6, bandwidth,
    # ll_type, hw_addr_len
    _V3_HEADER_FMT = '!%dsIBQIIIIII' % INTERFACE_NAMSIZE
    V3_HEADER_SIZE = struct.calcsize(_V3_HEADER_FMT)
    # ifname, ifindex, status, if_flags, ptm_enable, ptm_status, metric,
    # ifmtu, ifmtu6, bandwidth, ll_type, hw_addr_len
    _V4_HEADER_FMT_2_0 = '!%dsIBQBBIIIIII' % INTERFACE_NAMSIZE
    V4_HEADER_SIZE_2_0 = struct.calcsize(_V4_HEADER_FMT_2_0)
    # ifname, ifindex, status, if_flags, ptm_enable, ptm_status, metric,
    # speed, ifmtu, ifmtu6, bandwidth, ll_type, hw_addr_len
    _V4_HEADER_FMT_3_0 = '!%dsIBQBBIIIIIII' % INTERFACE_NAMSIZE
    V4_HEADER_SIZE_3_0 = struct.calcsize(_V4_HEADER_FMT_3_0)

    # link_params_state (whether a link-params follows)
    _LP_STATE_FMT = '!?'
    LP_STATE_SIZE = struct.calcsize(_LP_STATE_FMT)
    # See InterfaceLinkParams class for Link params structure

    def __init__(self, ifname=None, ifindex=None, status=None, if_flags=None,
                 ptm_enable=None, ptm_status=None,
                 metric=None, speed=None, ifmtu=None, ifmtu6=None,
                 bandwidth=None, ll_type=None, hw_addr_len=0, hw_addr=None,
                 link_params=None):
        super(_ZebraInterface, self).__init__()
        self.ifname = ifname
        self.ifindex = ifindex
        self.status = status
        self.if_flags = if_flags
        self.ptm_enable = ptm_enable
        self.ptm_status = ptm_status
        self.metric = metric
        self.speed = speed
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
    def parse(cls, buf, version=_DEFAULT_VERSION):
        ptm_enable = None
        ptm_status = None
        speed = None
        ll_type = None
        if version <= 2:
            (ifname, ifindex, status, if_flags, metric,
             ifmtu, ifmtu6, bandwidth,
             hw_addr_len) = struct.unpack_from(cls._HEADER_FMT, buf)
            rest = buf[cls.HEADER_SIZE:]
        elif version == 3:
            (ifname, ifindex, status, if_flags, metric,
             ifmtu, ifmtu6, bandwidth, ll_type,
             hw_addr_len) = struct.unpack_from(cls._V3_HEADER_FMT, buf)
            rest = buf[cls.V3_HEADER_SIZE:]
        elif version == 4:
            if _is_frr_version_ge(_FRR_VERSION_3_0):
                (ifname, ifindex, status, if_flags, ptm_enable, ptm_status,
                 metric, speed, ifmtu, ifmtu6, bandwidth, ll_type,
                 hw_addr_len) = struct.unpack_from(cls._V4_HEADER_FMT_3_0, buf)
                rest = buf[cls.V4_HEADER_SIZE_3_0:]
            elif _is_frr_version_ge(_FRR_VERSION_2_0):
                (ifname, ifindex, status, if_flags, ptm_enable, ptm_status,
                 metric, ifmtu, ifmtu6, bandwidth, ll_type,
                 hw_addr_len) = struct.unpack_from(cls._V4_HEADER_FMT_2_0, buf)
                rest = buf[cls.V4_HEADER_SIZE_2_0:]
            else:
                raise struct.error(
                    'Unsupported FRRouting version: %s'
                    % CONF['zapi'].frr_version)
        else:
            raise struct.error(
                'Unsupported Zebra protocol version: %d'
                % version)
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
            return cls(ifname, ifindex, status, if_flags,
                       ptm_enable, ptm_status, metric, speed, ifmtu, ifmtu6,
                       bandwidth, ll_type, hw_addr_len, hw_addr)

        (link_param_state,) = struct.unpack_from(cls._LP_STATE_FMT, rest)
        rest = rest[cls.LP_STATE_SIZE:]

        if link_param_state:
            link_params, rest = InterfaceLinkParams.parse(rest)
        else:
            link_params = None

        return cls(ifname, ifindex, status, if_flags,
                   ptm_enable, ptm_status, metric, speed, ifmtu, ifmtu6,
                   bandwidth, ll_type, hw_addr_len, hw_addr,
                   link_params)

    def serialize(self, version=_DEFAULT_VERSION):
        if self.ifname is None:
            # Case for sending message to Zebra
            return b''
        # fixup
        if netaddr.valid_mac(self.hw_addr):
            # MAC address
            hw_addr_len = 6
            hw_addr = addrconv.mac.text_to_bin(self.hw_addr)
        else:
            # Unknown hardware address
            hw_addr_len = len(self.hw_addr)
            hw_addr = self.hw_addr

        if version <= 2:
            return struct.pack(
                self._HEADER_FMT,
                self.ifname.encode('ascii'), self.ifindex, self.status,
                self.if_flags, self.metric, self.ifmtu, self.ifmtu6,
                self.bandwidth, hw_addr_len) + hw_addr
        elif version == 3:
            buf = struct.pack(
                self._V3_HEADER_FMT,
                self.ifname.encode('ascii'), self.ifindex, self.status,
                self.if_flags, self.metric, self.ifmtu, self.ifmtu6,
                self.bandwidth, self.ll_type, hw_addr_len) + hw_addr
        elif version == 4:
            if _is_frr_version_ge(_FRR_VERSION_3_0):
                buf = struct.pack(
                    self._V4_HEADER_FMT_3_0,
                    self.ifname.encode('ascii'), self.ifindex, self.status,
                    self.if_flags, self.ptm_enable, self.ptm_status,
                    self.metric, self.speed, self.ifmtu, self.ifmtu6,
                    self.bandwidth, self.ll_type, hw_addr_len) + hw_addr
            elif _is_frr_version_ge(_FRR_VERSION_2_0):
                buf = struct.pack(
                    self._V4_HEADER_FMT_2_0,
                    self.ifname.encode('ascii'), self.ifindex, self.status,
                    self.if_flags, self.ptm_enable, self.ptm_status,
                    self.metric, self.ifmtu, self.ifmtu6,
                    self.bandwidth, self.ll_type, hw_addr_len) + hw_addr
            else:
                raise ValueError(
                    'Unsupported FRRouting version: %s'
                    % CONF['zapi'].frr_version)
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % version)

        if isinstance(self.link_params, InterfaceLinkParams):
            buf += struct.pack(self._LP_STATE_FMT, True)
            buf += self.link_params.serialize()
        else:
            buf += struct.pack(self._LP_STATE_FMT, False)

        return buf


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_ADD)
@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_ADD)
class ZebraInterfaceAdd(_ZebraInterface):
    """
    Message body class for ZEBRA_INTERFACE_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_DELETE)
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
    _HEADER_FMT = '!IB'  # ifindex, ifc_flags
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, ifindex, ifc_flags, family, prefix, dest):
        super(_ZebraInterfaceAddress, self).__init__()
        self.ifindex = ifindex
        self.ifc_flags = ifc_flags
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix
        assert ip.valid_ipv4(dest) or ip.valid_ipv6(dest)
        self.dest = dest

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (ifindex, ifc_flags) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        (family, prefix, rest) = _parse_zebra_family_prefix(rest)

        if socket.AF_INET == family:
            dest = addrconv.ipv4.bin_to_text(rest)
        elif socket.AF_INET6 == family:
            dest = addrconv.ipv6.bin_to_text(rest)
        else:
            raise struct.error('Unsupported family: %d' % family)

        return cls(ifindex, ifc_flags, family, prefix, dest)

    def serialize(self, version=_DEFAULT_VERSION):
        (self.family,  # fixup
         body_bin) = _serialize_zebra_family_prefix(self.prefix)

        if ip.valid_ipv4(self.dest):
            body_bin += addrconv.ipv4.text_to_bin(self.dest)
        elif ip.valid_ipv6(self.prefix):
            body_bin += addrconv.ipv6.text_to_bin(self.dest)
        else:
            raise ValueError(
                'Invalid destination address: %s' % self.dest)

        return struct.pack(self._HEADER_FMT,
                           self.ifindex, self.ifc_flags) + body_bin


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_ADDRESS_ADD)
@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_ADDRESS_ADD)
class ZebraInterfaceAddressAdd(_ZebraInterfaceAddress):
    """
    Message body class for ZEBRA_INTERFACE_ADDRESS_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_ADDRESS_DELETE)
@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_ADDRESS_DELETE)
class ZebraInterfaceAddressDelete(_ZebraInterfaceAddress):
    """
    Message body class for ZEBRA_INTERFACE_ADDRESS_DELETE.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_UP)
@_ZebraMessageBody.register_type(ZEBRA_INTERFACE_UP)
class ZebraInterfaceUp(_ZebraInterface):
    """
    Message body class for ZEBRA_INTERFACE_UP.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_DOWN)
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

    .. Note::

        Zebra IPv4/IPv6 Route message have asymmetric structure.
        If the message sent from Zebra Daemon, set 'from_zebra=True' to
        create an instance of this class.
    """
    # Zebra IPv4/IPv6 Route message body (Protocol Daemons -> Zebra Daemon):
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
    #
    # Zebra IPv4/IPv6 Route message body on FRRouting
    # (Protocol Daemons -> Zebra Daemon):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    | Instance                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Flags                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Message       | SAFI                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (Variable)                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (IPv4/v6 Source Prefix): v4(FRRouting v3.0 or later)          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Distance)    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Metric)                                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (TAG)                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (MTU)                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Zebra IPv4/IPv6 Route message body (Zebra Daemon -> Protocol Daemons):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    | Flags         | Message       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (Variable)                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Nexthop Num) |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Nexthops (Variable))                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (IFIndex Num) |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Interface indexes)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Distance)    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Metric)                                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (MTU)                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (TAG)                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Zebra IPv4/IPv6 Route message body on FRRouting
    # (Zebra Daemon -> Protocol Daemons):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    | Instance                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Flags                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Message       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (Variable)                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (IPv4/v6 Source Prefix): v4(FRRouting v3.0 or later)          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Nexthop Num) |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Nexthops (Variable))                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (IFIndex Num) |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Interface indexes)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Distance)    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Metric)                                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (TAG)                                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!BBB'  # type, flags, message
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _V4_HEADER_FMT = '!BHIB'  # type, instance, flags, message
    V4_HEADER_SIZE = struct.calcsize(_V4_HEADER_FMT)
    _SAFI_FMT = '!H'  # safi
    SAFI_SIZE = struct.calcsize(_SAFI_FMT)
    _NUM_FMT = '!B'  # nexthop_num or ifindex_num
    NUM_SIZE = struct.calcsize(_NUM_FMT)
    _IFINDEX_FMT = '!I'  # ifindex
    IFINDEX_SIZE = struct.calcsize(_IFINDEX_FMT)

    # API type specific constants
    _FAMILY = None  # either socket.AF_INET or socket.AF_INET6

    def __init__(self, route_type, flags, message, safi=None,
                 prefix=None, src_prefix=None,
                 nexthops=None, ifindexes=None,
                 distance=None, metric=None, mtu=None, tag=None,
                 instance=None, from_zebra=False):
        super(_ZebraIPRoute, self).__init__()
        self.route_type = route_type
        self.instance = instance
        self.flags = flags
        self.message = message

        # SAFI should be included if this message sent to Zebra.
        if from_zebra:
            self.safi = None
        else:
            self.safi = safi or packet_safi.UNICAST

        assert prefix is not None
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix

        if isinstance(src_prefix, (IPv4Prefix, IPv6Prefix)):
            src_prefix = src_prefix.prefix
        self.src_prefix = src_prefix

        # Nexthops should be a list of str representations of IP address
        # if this message sent from Zebra, otherwise a list of _Nexthop
        # subclasses.
        nexthops = nexthops or []
        if from_zebra:
            for nexthop in nexthops:
                assert ip.valid_ipv4(nexthop) or ip.valid_ipv6(nexthop)
        else:
            for nexthop in nexthops:
                assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

        # Interface indexes should be included if this message sent from
        # Zebra.
        if from_zebra:
            ifindexes = ifindexes or []
            for ifindex in ifindexes:
                assert isinstance(ifindex, six.integer_types)
            self.ifindexes = ifindexes
        else:
            self.ifindexes = None

        self.distance = distance
        self.metric = metric
        self.mtu = mtu
        self.tag = tag

        # is this message sent from Zebra message or not.
        self.from_zebra = from_zebra

    @classmethod
    def _parse_message_option(cls, message, flag, fmt, buf):
        if message & flag:
            (option,) = struct.unpack_from(fmt, buf)
            return option, buf[struct.calcsize(fmt):]

        return None, buf

    @classmethod
    def _parse_impl(cls, buf, version=_DEFAULT_VERSION, from_zebra=False):
        instance = None
        if version <= 3:
            (route_type, flags, message,) = struct.unpack_from(
                cls._HEADER_FMT, buf)
            rest = buf[cls.HEADER_SIZE:]
        elif version == 4:
            (route_type, instance, flags, message,) = struct.unpack_from(
                cls._V4_HEADER_FMT, buf)
            rest = buf[cls.V4_HEADER_SIZE:]
        else:
            raise struct.error(
                'Unsupported Zebra protocol version: %d'
                % version)

        if from_zebra:
            safi = None
        else:
            (safi,) = struct.unpack_from(cls._SAFI_FMT, rest)
            rest = rest[cls.SAFI_SIZE:]

        prefix, rest = _parse_ip_prefix(cls._FAMILY, rest)

        src_prefix = None
        if version == 4 and message & FRR_ZAPI_MESSAGE_SRCPFX:
            src_prefix, rest = _parse_ip_prefix(cls._FAMILY, rest)

        if from_zebra and message & ZAPI_MESSAGE_NEXTHOP:
            nexthops = []
            (nexthop_num,) = struct.unpack_from(cls._NUM_FMT, rest)
            rest = rest[cls.NUM_SIZE:]
            if cls._FAMILY == socket.AF_INET:
                for _ in range(nexthop_num):
                    nexthop = addrconv.ipv4.bin_to_text(rest[:4])
                    nexthops.append(nexthop)
                    rest = rest[4:]
            else:  # cls._FAMILY == socket.AF_INET6:
                for _ in range(nexthop_num):
                    nexthop = addrconv.ipv6.bin_to_text(rest[:16])
                    nexthops.append(nexthop)
                    rest = rest[16:]
        else:
            nexthops, rest = _parse_nexthops(rest, version)

        ifindexes = []
        if from_zebra and message & ZAPI_MESSAGE_IFINDEX:
            (ifindex_num,) = struct.unpack_from(cls._NUM_FMT, rest)
            rest = rest[cls.NUM_SIZE:]
            for _ in range(ifindex_num):
                (ifindex,) = struct.unpack_from(cls._IFINDEX_FMT, rest)
                ifindexes.append(ifindex)
                rest = rest[cls.IFINDEX_SIZE:]

        if version <= 3:
            distance, rest = cls._parse_message_option(
                message, ZAPI_MESSAGE_DISTANCE, '!B', rest)
            metric, rest = cls._parse_message_option(
                message, ZAPI_MESSAGE_METRIC, '!I', rest)
            mtu, rest = cls._parse_message_option(
                message, ZAPI_MESSAGE_MTU, '!I', rest)
            tag, rest = cls._parse_message_option(
                message, ZAPI_MESSAGE_TAG, '!I', rest)
        elif version == 4:
            distance, rest = cls._parse_message_option(
                message, FRR_ZAPI_MESSAGE_DISTANCE, '!B', rest)
            metric, rest = cls._parse_message_option(
                message, FRR_ZAPI_MESSAGE_METRIC, '!I', rest)
            tag, rest = cls._parse_message_option(
                message, FRR_ZAPI_MESSAGE_TAG, '!I', rest)
            mtu, rest = cls._parse_message_option(
                message, FRR_ZAPI_MESSAGE_MTU, '!I', rest)
        else:
            raise struct.error(
                'Unsupported Zebra protocol version: %d'
                % version)

        return cls(route_type, flags, message, safi, prefix, src_prefix,
                   nexthops, ifindexes,
                   distance, metric, mtu, tag,
                   instance, from_zebra=from_zebra)

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        return cls._parse_impl(buf, version=version)

    @classmethod
    def parse_from_zebra(cls, buf, version=_DEFAULT_VERSION):
        return cls._parse_impl(buf, version=version, from_zebra=True)

    def _serialize_message_option(self, option, flag, fmt):
        if option is None:
            return b''

        # fixup
        self.message |= flag

        return struct.pack(fmt, option)

    def serialize(self, version=_DEFAULT_VERSION):
        prefix = _serialize_ip_prefix(self.prefix)
        if version == 4 and self.src_prefix:
            self.message |= FRR_ZAPI_MESSAGE_SRCPFX  # fixup
            prefix += _serialize_ip_prefix(self.src_prefix)

        nexthops = b''
        if self.from_zebra and self.nexthops:
            self.message |= ZAPI_MESSAGE_NEXTHOP  # fixup
            nexthops += struct.pack(self._NUM_FMT, len(self.nexthops))
            for nexthop in self.nexthops:
                nexthops += ip.text_to_bin(nexthop)
        else:
            self.message |= ZAPI_MESSAGE_NEXTHOP  # fixup
            nexthops = _serialize_nexthops(self.nexthops, version=version)

        ifindexes = b''
        if self.ifindexes and self.from_zebra:
            self.message |= ZAPI_MESSAGE_IFINDEX  # fixup
            ifindexes += struct.pack(self._NUM_FMT, len(self.ifindexes))
            for ifindex in self.ifindexes:
                ifindexes += struct.pack(self._IFINDEX_FMT, ifindex)

        if version <= 3:
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
                self.route_type, self.flags, self.message)
        elif version == 4:
            options = self._serialize_message_option(
                self.distance, FRR_ZAPI_MESSAGE_DISTANCE, '!B')
            options += self._serialize_message_option(
                self.metric, FRR_ZAPI_MESSAGE_METRIC, '!I')
            options += self._serialize_message_option(
                self.tag, FRR_ZAPI_MESSAGE_TAG, '!I')
            options += self._serialize_message_option(
                self.mtu, FRR_ZAPI_MESSAGE_MTU, '!I')
            header = struct.pack(
                self._V4_HEADER_FMT,
                self.route_type, self.instance, self.flags, self.message)
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % version)

        if not self.from_zebra:
            header += struct.pack(self._SAFI_FMT, self.safi)

        return header + prefix + nexthops + ifindexes + options


class _ZebraIPv4Route(_ZebraIPRoute):
    """
    Base class for ZEBRA_IPV4_ROUTE_* message body.
    """
    _FAMILY = socket.AF_INET


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV4_ROUTE_ADD)
@_ZebraMessageBody.register_type(ZEBRA_IPV4_ROUTE_ADD)
class ZebraIPv4RouteAdd(_ZebraIPv4Route):
    """
    Message body class for ZEBRA_IPV4_ROUTE_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV4_ROUTE_DELETE)
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


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV6_ROUTE_ADD)
@_ZebraMessageBody.register_type(ZEBRA_IPV6_ROUTE_ADD)
class ZebraIPv6RouteAdd(_ZebraIPv6Route):
    """
    Message body class for ZEBRA_IPV6_ROUTE_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV6_ROUTE_DELETE)
@_ZebraMessageBody.register_type(ZEBRA_IPV6_ROUTE_DELETE)
class ZebraIPv6RouteDelete(_ZebraIPv6Route):
    """
    Message body class for ZEBRA_IPV6_ROUTE_DELETE.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV4_ROUTE_IPV6_NEXTHOP_ADD)
class ZebraIPv4RouteIPv6NexthopAdd(_ZebraIPv4Route):
    """
    Message body class for FRR_ZEBRA_IPV4_ROUTE_IPV6_NEXTHOP_ADD.
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
    #
    # Zebra Redistribute message body on FRRouting:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | AFI           | Route Type    | Instance                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+-+-+-+
    _HEADER_FMT = '!B'  # route_type
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _V4_HEADER_FMT = '!BBH'  # afi, route_type, instance
    V4_HEADER_SIZE = struct.calcsize(_V4_HEADER_FMT)

    def __init__(self, route_type, afi=None, instance=None):
        super(_ZebraRedistribute, self).__init__()
        self.afi = afi
        self.route_type = route_type
        self.instance = instance

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        afi = None
        instance = None
        if version <= 3:
            (route_type,) = struct.unpack_from(cls._HEADER_FMT, buf)
        elif version == 4:
            (afi, route_type,
             instance) = struct.unpack_from(cls._V4_HEADER_FMT, buf)
        else:
            raise struct.error(
                'Unsupported Zebra protocol version: %d'
                % version)

        return cls(route_type, afi, instance)

    def serialize(self, version=_DEFAULT_VERSION):
        if version <= 3:
            return struct.pack(self._HEADER_FMT, self.route_type)
        elif version == 4:
            return struct.pack(self._V4_HEADER_FMT,
                               self.afi, self.route_type, self.instance)
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % version)


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_ADD)
@_ZebraMessageBody.register_type(ZEBRA_REDISTRIBUTE_ADD)
class ZebraRedistributeAdd(_ZebraRedistribute):
    """
    Message body class for ZEBRA_REDISTRIBUTE_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_DELETE)
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


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_DEFAULT_ADD)
@_ZebraMessageBody.register_type(ZEBRA_REDISTRIBUTE_DEFAULT_ADD)
class ZebraRedistributeDefaultAdd(_ZebraRedistribute):
    """
    Message body class for ZEBRA_REDISTRIBUTE_DEFAULT_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_DEFAULT_DELETE)
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
        assert ip.valid_ipv4(addr) or ip.valid_ipv6(addr)
        self.addr = addr
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        addr = cls.ADDR_CLS.bin_to_text(buf[:cls.ADDR_LEN])
        rest = buf[cls.ADDR_LEN:]

        metric = None
        if rest:
            # Note: Case for ZEBRA_IPV4_NEXTHOP_LOOKUP request
            (metric,) = struct.unpack_from(cls._METRIC_FMT, rest)
            rest = rest[cls.METRIC_SIZE:]

        nexthops = None
        if rest:
            nexthops, rest = _parse_nexthops(rest, version)

        return cls(addr, metric, nexthops)

    def serialize(self, version=_DEFAULT_VERSION):
        buf = self.ADDR_CLS.text_to_bin(self.addr)

        if self.metric is None:
            return buf

        buf += struct.pack(self._METRIC_FMT, self.metric)

        return buf + _serialize_nexthops(self.nexthops, version=version)


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

    .. Note::

        Zebra IPv4/v6 Import Lookup message have asymmetric structure.
        If the message sent from Zebra Daemon, set 'from_zebra=True' to
        create an instance of this class.
    """
    # Zebra IPv4/v6 Import Lookup message body
    # (Protocol Daemons -> Zebra Daemon):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix Len    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (4 bytes or 16 bytes)                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Zebra IPv4/v6 Import Lookup message body
    # (Zebra Daemons -> Protocol Daemon):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (4 bytes or 16 bytes)                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _PREFIX_LEN_FMT = '!B'  # prefix_len
    PREFIX_LEN_SIZE = struct.calcsize(_PREFIX_LEN_FMT)
    _METRIC_FMT = '!I'  # metric
    METRIC_SIZE = struct.calcsize(_METRIC_FMT)

    # Message type specific constants
    PREFIX_CLS = None  # either addrconv.ipv4 or addrconv.ipv6
    PREFIX_LEN = None  # IP prefix length in bytes

    def __init__(self, prefix, metric=None, nexthops=None,
                 from_zebra=False):
        super(_ZebraIPImportLookup, self).__init__()
        if not from_zebra:
            assert ip.valid_ipv4(prefix) or ip.valid_ipv6(prefix)
        else:
            if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
                prefix = prefix.prefix
            else:
                assert ip.valid_ipv4(prefix) or ip.valid_ipv6(prefix)
        self.prefix = prefix
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops
        self.from_zebra = from_zebra

    @classmethod
    def parse_impl(cls, buf, version=_DEFAULT_VERSION, from_zebra=False):
        if not from_zebra:
            (prefix_len,) = struct.unpack_from(cls._PREFIX_LEN_FMT, buf)
            rest = buf[cls.PREFIX_LEN_SIZE:]
            prefix = cls.PREFIX_CLS.bin_to_text(rest[:cls.PREFIX_LEN])
            return cls('%s/%d' % (prefix, prefix_len), from_zebra=False)

        prefix = cls.PREFIX_CLS.bin_to_text(buf[:cls.PREFIX_LEN])
        rest = buf[4:]

        (metric,) = struct.unpack_from(cls._METRIC_FMT, rest)
        rest = rest[cls.METRIC_SIZE:]

        nexthops, rest = _parse_nexthops(rest, version)

        return cls(prefix, metric, nexthops, from_zebra=True)

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        return cls.parse_impl(buf, version=version, from_zebra=False)

    @classmethod
    def parse_from_zebra(cls, buf, version=_DEFAULT_VERSION):
        return cls.parse_impl(buf, version=version, from_zebra=True)

    def serialize(self, version=_DEFAULT_VERSION):
        if not self.from_zebra:
            if ip.valid_ipv4(self.prefix) or ip.valid_ipv6(self.prefix):
                prefix, prefix_len = self.prefix.split('/')
                return struct.pack(
                    self._PREFIX_LEN_FMT,
                    int(prefix_len)) + self.PREFIX_CLS.text_to_bin(prefix)
            else:
                raise ValueError('Invalid prefix: %s' % self.prefix)

        if ip.valid_ipv4(self.prefix) or ip.valid_ipv6(self.prefix):
            buf = self.PREFIX_CLS.text_to_bin(self.prefix)
        else:
            raise ValueError('Invalid prefix: %s' % self.prefix)

        buf += struct.pack(self._METRIC_FMT, self.metric)

        return buf + _serialize_nexthops(self.nexthops, version=version)


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


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_ROUTER_ID_ADD)
@_ZebraMessageBody.register_type(ZEBRA_ROUTER_ID_ADD)
class ZebraRouterIDAdd(_ZebraMessageBody):
    """
    Message body class for ZEBRA_ROUTER_ID_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_ROUTER_ID_DELETE)
@_ZebraMessageBody.register_type(ZEBRA_ROUTER_ID_DELETE)
class ZebraRouterIDDelete(_ZebraMessageBody):
    """
    Message body class for ZEBRA_ROUTER_ID_DELETE.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_ROUTER_ID_UPDATE)
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

    def __init__(self, family, prefix):
        super(ZebraRouterIDUpdate, self).__init__()
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (family, prefix, _) = _parse_zebra_family_prefix(buf)

        return cls(family, prefix)

    def serialize(self, version=_DEFAULT_VERSION):
        (self.family,  # fixup
         buf) = _serialize_zebra_family_prefix(self.prefix)

        return buf


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_HELLO)
@_ZebraMessageBody.register_type(ZEBRA_HELLO)
class ZebraHello(_ZebraMessageBody):
    """
    Message body class for ZEBRA_HELLO.
    """
    # Zebra Hello message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    | (Instance): v4(FRRouting)     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!B'  # route_type
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _V4_HEADER_FMT = '!BH'  # route_type, instance
    V4_HEADER_SIZE = struct.calcsize(_V4_HEADER_FMT)

    def __init__(self, route_type, instance=None):
        super(ZebraHello, self).__init__()
        self.route_type = route_type
        self.instance = instance

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        instance = None
        if version <= 3:
            (route_type,) = struct.unpack_from(cls._HEADER_FMT, buf)
        elif version == 4:
            (route_type,
             instance) = struct.unpack_from(cls._V4_HEADER_FMT, buf)
        else:
            raise struct.error(
                'Unsupported Zebra protocol version: %d'
                % version)

        return cls(route_type, instance)

    def serialize(self, version=_DEFAULT_VERSION):
        if version <= 3:
            return struct.pack(self._HEADER_FMT, self.route_type)
        elif version == 4:
            return struct.pack(self._V4_HEADER_FMT,
                               self.route_type, self.instance)
        else:
            raise ValueError(
                'Unsupported Zebra protocol version: %d'
                % version)


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
    _DISTANCE_METRIC_FMT = '!BI'  # distance, metric
    DISTANCE_METRIC_SIZE = struct.calcsize(_DISTANCE_METRIC_FMT)

    # Message type specific constants
    ADDR_CLS = None  # either addrconv.ipv4 or addrconv.ipv6
    ADDR_LEN = None  # IP address length in bytes

    def __init__(self, addr, distance=None, metric=None, nexthops=None):
        super(_ZebraIPNexthopLookupMRib, self).__init__()
        assert ip.valid_ipv4(addr) or ip.valid_ipv6(addr)
        self.addr = addr
        self.distance = distance
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        addr = cls.ADDR_CLS.bin_to_text(buf[:cls.ADDR_LEN])
        rest = buf[cls.ADDR_LEN:]

        if not rest:
            return cls(addr)

        (distance,
         metric) = struct.unpack_from(cls._DISTANCE_METRIC_FMT, rest)
        rest = rest[cls.DISTANCE_METRIC_SIZE:]

        nexthops, rest = _parse_nexthops(rest, version)

        return cls(addr, distance, metric, nexthops)

    def serialize(self, version=_DEFAULT_VERSION):
        buf = self.ADDR_CLS.text_to_bin(self.addr)

        if self.distance is None or self.metric is None:
            return buf

        buf += struct.pack(
            self._DISTANCE_METRIC_FMT, self.distance, self.metric)

        return buf + _serialize_nexthops(self.nexthops, version=version)


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB)
@_ZebraMessageBody.register_type(ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB)
class ZebraIPv4NexthopLookupMRib(_ZebraIPNexthopLookupMRib):
    """
    Message body class for ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB.
    """
    ADDR_CLS = addrconv.ipv4
    ADDR_LEN = 4


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_VRF_UNREGISTER)
@_ZebraMessageBody.register_type(ZEBRA_VRF_UNREGISTER)
class ZebraVrfUnregister(_ZebraMessageBody):
    """
    Message body class for ZEBRA_VRF_UNREGISTER.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_LINK_PARAMS)
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
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (ifindex,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        link_params, rest = InterfaceLinkParams.parse(rest)

        return cls(ifindex, link_params)

    def serialize(self, version=_DEFAULT_VERSION):
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
    def parse(cls, buf, version=_DEFAULT_VERSION):
        nexthops = []
        while buf:
            nexthop, buf = RegisteredNexthop.parse(buf)
            nexthops.append(nexthop)

        return cls(nexthops)

    def serialize(self, version=_DEFAULT_VERSION):
        buf = b''
        for nexthop in self.nexthops:
            buf += nexthop.serialize()

        return buf


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_NEXTHOP_REGISTER)
@_ZebraMessageBody.register_type(ZEBRA_NEXTHOP_REGISTER)
class ZebraNexthopRegister(_ZebraNexthopRegister):
    """
    Message body class for ZEBRA_NEXTHOP_REGISTER.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_NEXTHOP_UNREGISTER)
@_ZebraMessageBody.register_type(ZEBRA_NEXTHOP_UNREGISTER)
class ZebraNexthopUnregister(_ZebraNexthopRegister):
    """
    Message body class for ZEBRA_NEXTHOP_UNREGISTER.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_NEXTHOP_UPDATE)
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
    # | (Distance)    | v4(FRRouting v3.0 or later)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Metric                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthop Num   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Nexthops (Variable)                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _FAMILY_FMT = '!H'  # family
    FAMILY_SIZE = struct.calcsize(_FAMILY_FMT)
    _DISTANCE_FMT = '!B'  # metric
    DISTANCE_SIZE = struct.calcsize(_DISTANCE_FMT)
    _METRIC_FMT = '!I'  # metric
    METRIC_SIZE = struct.calcsize(_METRIC_FMT)

    def __init__(self, family, prefix, distance=None, metric=None,
                 nexthops=None):
        super(ZebraNexthopUpdate, self).__init__()
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix
        if _is_frr_version_ge(_FRR_VERSION_3_0):
            assert distance is not None
        self.distance = distance
        assert metric is not None
        self.metric = metric
        nexthops = nexthops or []
        for nexthop in nexthops:
            assert isinstance(nexthop, _NextHop)
        self.nexthops = nexthops

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (family,) = struct.unpack_from(cls._FAMILY_FMT, buf)
        rest = buf[cls.FAMILY_SIZE:]

        prefix, rest = _parse_ip_prefix(family, rest)

        distance = None
        if _is_frr_version_ge(_FRR_VERSION_3_0):
            (distance,) = struct.unpack_from(cls._DISTANCE_FMT, rest)
            rest = rest[cls.DISTANCE_SIZE:]

        (metric,) = struct.unpack_from(cls._METRIC_FMT, rest)
        rest = rest[cls.METRIC_SIZE:]

        nexthops, rest = _parse_nexthops(rest, version)

        return cls(family, prefix, distance, metric, nexthops)

    def serialize(self, version=_DEFAULT_VERSION):
        # fixup
        if ip.valid_ipv4(self.prefix):
            self.family = socket.AF_INET
        elif ip.valid_ipv6(self.prefix):
            self.family = socket.AF_INET6
        else:
            raise ValueError('Invalid prefix: %s' % self.prefix)

        buf = struct.pack(self._FAMILY_FMT, self.family)

        buf += _serialize_ip_prefix(self.prefix)

        if _is_frr_version_ge(_FRR_VERSION_3_0):
            buf += struct.pack(self._DISTANCE_FMT, self.distance)

        buf += struct.pack(self._METRIC_FMT, self.metric)

        return buf + _serialize_nexthops(self.nexthops, version=version)


class _ZebraInterfaceNbrAddress(_ZebraMessageBody):
    """
    Base class for FRR_ZEBRA_INTERFACE_NBR_ADDRESS_* message body.
    """
    # Zebra Interface Neighbor Address message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface index                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Family        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 prefix                                                |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix len    |
    # +-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!I'  # ifindex
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, ifindex, family, prefix):
        super(_ZebraInterfaceNbrAddress, self).__init__()
        self.ifindex = ifindex
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (ifindex,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        (family, prefix, _) = _parse_zebra_family_prefix(rest)

        return cls(ifindex, family, prefix)

    def serialize(self, version=_DEFAULT_VERSION):
        (self.family,  # fixup
         body_bin) = _serialize_zebra_family_prefix(self.prefix)

        return struct.pack(self._HEADER_FMT, self.ifindex) + body_bin


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_NBR_ADDRESS_ADD)
class ZebraInterfaceNbrAddressAdd(_ZebraInterfaceNbrAddress):
    """
    Message body class for FRR_ZEBRA_INTERFACE_NBR_ADDRESS_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_NBR_ADDRESS_DELETE)
class ZebraInterfaceNbrAddressDelete(_ZebraInterfaceNbrAddress):
    """
    Message body class for FRR_ZEBRA_INTERFACE_NBR_ADDRESS_DELETE.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_BFD_DEST_UPDATE)
class ZebraInterfaceBfdDestinationUpdate(_ZebraMessageBody):
    """
    Message body class for FRR_ZEBRA_INTERFACE_BFD_DEST_UPDATE.
    """
    # Zebra Interface BFD Destination Update message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface index                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Dst Family    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Dst IPv4/v6 prefix                                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Dst Plen      |
    # +-+-+-+-+-+-+-+-+
    # | Status        |
    # +-+-+-+-+-+-+-+-+
    # | Src Family    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Source IPv4/v6 prefix                                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Src Plen      |
    # +-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!I'  # ifindex
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _STATUS_FMT = '!B'  # status
    STATUS_SIZE = struct.calcsize(_STATUS_FMT)

    def __init__(self, ifindex, dst_family, dst_prefix, status,
                 src_family, src_prefix):
        super(ZebraInterfaceBfdDestinationUpdate, self).__init__()
        self.ifindex = ifindex
        self.dst_family = dst_family
        if isinstance(dst_prefix, (IPv4Prefix, IPv6Prefix)):
            dst_prefix = dst_prefix.prefix
        self.dst_prefix = dst_prefix
        self.status = status
        self.src_family = src_family
        if isinstance(src_prefix, (IPv4Prefix, IPv6Prefix)):
            src_prefix = src_prefix.prefix
        self.src_prefix = src_prefix

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (ifindex,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        (dst_family, dst_prefix,
         rest) = _parse_zebra_family_prefix(rest)

        (status,) = struct.unpack_from(cls._STATUS_FMT, rest)
        rest = rest[cls.STATUS_SIZE:]

        (src_family, src_prefix,
         _) = _parse_zebra_family_prefix(rest)

        return cls(ifindex, dst_family, dst_prefix, status,
                   src_family, src_prefix)

    def serialize(self, version=_DEFAULT_VERSION):
        (self.dst_family,  # fixup
         dst_bin) = _serialize_zebra_family_prefix(self.dst_prefix)

        status_bin = struct.pack(
            self._STATUS_FMT, self.status)

        (self.src_family,  # fixup
         src_bin) = _serialize_zebra_family_prefix(self.src_prefix)

        return struct.pack(
            self._HEADER_FMT,
            self.ifindex) + dst_bin + status_bin + src_bin


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IMPORT_ROUTE_REGISTER)
class ZebraImportRouteRegister(_ZebraNexthopRegister):
    """
    Message body class for FRR_ZEBRA_IMPORT_ROUTE_REGISTER.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IMPORT_ROUTE_UNREGISTER)
class ZebraImportRouteUnregister(_ZebraNexthopRegister):
    """
    Message body class for FRR_ZEBRA_IMPORT_ROUTE_UNREGISTER.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IMPORT_CHECK_UPDATE)
class ZebraImportCheckUpdate(ZebraNexthopUpdate):
    """
    Message body class for FRR_ZEBRA_IMPORT_CHECK_UPDATE.
    """


class _ZebraBfdDestination(_ZebraMessageBody):
    """
    Base class for FRR_ZEBRA_BFD_DEST_REGISTER and
    FRR_ZEBRA_BFD_DEST_UPDATE message body.
    """
    # Zebra BFD Destination message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | PID                                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Destination Family            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Destination IPv4/v6 prefix (4 bytes or 16 bytes)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Min RX Timer                                                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Min TX Timer                                                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Detect Mult   |
    # +-+-+-+-+-+-+-+-+
    # | Multi Hop     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Source Family                 |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Source IPv4/v6 prefix  (4 bytes or 16 bytes)                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (MultiHopCnt) | if Multi Hop enabled
    # +-+-+-+-+-+-+-+-+
    # | (IFName Len)  | if Multi Hop disabled
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (Interface Name (Variable)) if Multi Hop disabled             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!I'  # pid
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _FAMILY_FMT = '!H'
    FAMILY_SIZE = struct.calcsize(_FAMILY_FMT)
    _BODY_FMT = '!IIBB'  # min_rx_timer, min_tx_timer, detect_mult, multi_hop
    BODY_SIZE = struct.calcsize(_BODY_FMT)
    _FOOTER_FMT = '!B'  # multi_hop_count or ifname_len
    FOOTER_SIZE = struct.calcsize(_FOOTER_FMT)

    def __init__(self, pid, dst_family, dst_prefix,
                 min_rx_timer, min_tx_timer, detect_mult,
                 multi_hop, src_family, src_prefix,
                 multi_hop_count=None, ifname=None):
        super(_ZebraBfdDestination, self).__init__()
        self.pid = pid
        self.dst_family = dst_family
        assert ip.valid_ipv4(dst_prefix) or ip.valid_ipv6(dst_prefix)
        self.dst_prefix = dst_prefix
        self.min_rx_timer = min_rx_timer
        self.min_tx_timer = min_tx_timer
        self.detect_mult = detect_mult
        self.multi_hop = multi_hop
        self.src_family = src_family
        assert ip.valid_ipv4(src_prefix) or ip.valid_ipv6(src_prefix)
        self.src_prefix = src_prefix
        self.multi_hop_count = multi_hop_count
        self.ifname = ifname

    @classmethod
    def _parse_family_prefix(cls, buf):
        (family,) = struct.unpack_from(cls._FAMILY_FMT, buf)
        rest = buf[cls.FAMILY_SIZE:]

        if socket.AF_INET == family:
            return family, addrconv.ipv4.bin_to_text(rest[:4]), rest[4:]
        elif socket.AF_INET6 == family:
            return family, addrconv.ipv6.bin_to_text(rest[:16]), rest[16:]

        raise struct.error('Unsupported family: %d' % family)

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (pid,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        (dst_family, dst_prefix,
         rest) = cls._parse_family_prefix(rest)

        (min_rx_timer, min_tx_timer, detect_mult,
         multi_hop) = struct.unpack_from(cls._BODY_FMT, rest)
        rest = rest[cls.BODY_SIZE:]

        (src_family, src_prefix,
         rest) = cls._parse_family_prefix(rest)

        multi_hop_count = None
        ifname = None
        if multi_hop:
            (multi_hop_count,) = struct.unpack_from(cls._FOOTER_FMT, rest)
        else:
            (ifname_len,) = struct.unpack_from(cls._FOOTER_FMT, rest)
            ifname_bin = rest[cls.FOOTER_SIZE:cls.FOOTER_SIZE + ifname_len]
            ifname = str(six.text_type(ifname_bin.strip(b'\x00'), 'ascii'))

        return cls(pid, dst_family, dst_prefix,
                   min_rx_timer, min_tx_timer, detect_mult,
                   multi_hop, src_family, src_prefix,
                   multi_hop_count, ifname)

    def _serialize_family_prefix(self, prefix):
        if ip.valid_ipv4(prefix):
            family = socket.AF_INET
            return (family,
                    struct.pack(self._FAMILY_FMT, family)
                    + addrconv.ipv4.text_to_bin(prefix))
        elif ip.valid_ipv6(prefix):
            family = socket.AF_INET6
            return (family,
                    struct.pack(self._FAMILY_FMT, family)
                    + addrconv.ipv6.text_to_bin(prefix))

        raise ValueError('Invalid prefix: %s' % prefix)

    def serialize(self, version=_DEFAULT_VERSION):
        (self.dst_family,  # fixup
         dst_bin) = self._serialize_family_prefix(self.dst_prefix)

        body_bin = struct.pack(
            self._BODY_FMT,
            self.min_rx_timer, self.min_tx_timer, self.detect_mult,
            self.multi_hop)

        (self.src_family,  # fixup
         src_bin) = self._serialize_family_prefix(self.src_prefix)

        if self.multi_hop:
            footer_bin = struct.pack(
                self._FOOTER_FMT, self.multi_hop_count)
        else:
            ifname_bin = self.ifname.encode('ascii')
            footer_bin = struct.pack(
                self._FOOTER_FMT, len(ifname_bin)) + ifname_bin

        return struct.pack(
            self._HEADER_FMT,
            self.pid) + dst_bin + body_bin + src_bin + footer_bin


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_BFD_DEST_REGISTER)
class ZebraBfdDestinationRegister(_ZebraBfdDestination):
    """
    Message body class for FRR_ZEBRA_BFD_DEST_REGISTER.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_BFD_DEST_DEREGISTER)
class ZebraBfdDestinationDeregister(_ZebraMessageBody):
    """
    Message body class for FRR_ZEBRA_BFD_DEST_DEREGISTER.
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | PID                                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Family                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Destination IPv4/v6 prefix (4 bytes or 16 bytes)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Multi Hop     |
    # +-+-+-+-+-+-+-+-+
    # | Family        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Source IPv4/v6 prefix  (4 bytes or 16 bytes)                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (MultiHopCnt) | if Multi Hop enabled
    # +-+-+-+-+-+-+-+-+
    # | (IF Name Len) | if Multi Hop disabled
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | (IF Name (Variable)) if Multi Hop disabled                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!I'  # pid
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _FAMILY_FMT = '!H'
    FAMILY_SIZE = struct.calcsize(_FAMILY_FMT)
    _BODY_FMT = '!B'  # multi_hop
    BODY_SIZE = struct.calcsize(_BODY_FMT)
    _FOOTER_FMT = '!B'  # multi_hop_count or ifname_len
    FOOTER_SIZE = struct.calcsize(_FOOTER_FMT)

    def __init__(self, pid, dst_family, dst_prefix,
                 multi_hop, src_family, src_prefix,
                 multi_hop_count=None, ifname=None):
        super(ZebraBfdDestinationDeregister, self).__init__()
        self.pid = pid
        self.dst_family = dst_family
        assert ip.valid_ipv4(dst_prefix) or ip.valid_ipv6(dst_prefix)
        self.dst_prefix = dst_prefix
        self.multi_hop = multi_hop
        self.src_family = src_family
        assert ip.valid_ipv4(src_prefix) or ip.valid_ipv6(src_prefix)
        self.src_prefix = src_prefix
        self.multi_hop_count = multi_hop_count
        self.ifname = ifname

    @classmethod
    def _parse_family_prefix(cls, buf):
        (family,) = struct.unpack_from(cls._FAMILY_FMT, buf)
        rest = buf[cls.FAMILY_SIZE:]

        if socket.AF_INET == family:
            return family, addrconv.ipv4.bin_to_text(rest[:4]), rest[4:]
        elif socket.AF_INET6 == family:
            return family, addrconv.ipv6.bin_to_text(rest[:16]), rest[16:]

        raise struct.error('Unsupported family: %d' % family)

    @classmethod
    def parse(cls, buf, version=_DEFAULT_VERSION):
        (pid,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        (dst_family, dst_prefix,
         rest) = cls._parse_family_prefix(rest)

        (multi_hop,) = struct.unpack_from(cls._BODY_FMT, rest)
        rest = rest[cls.BODY_SIZE:]

        (src_family, src_prefix,
         rest) = cls._parse_family_prefix(rest)

        multi_hop_count = None
        ifname = None
        if multi_hop:
            (multi_hop_count,) = struct.unpack_from(cls._FOOTER_FMT, rest)
        else:
            (ifname_len,) = struct.unpack_from(cls._FOOTER_FMT, rest)
            ifname_bin = rest[cls.FOOTER_SIZE:cls.FOOTER_SIZE + ifname_len]
            ifname = str(six.text_type(ifname_bin.strip(b'\x00'), 'ascii'))

        return cls(pid, dst_family, dst_prefix,
                   multi_hop, src_family, src_prefix,
                   multi_hop_count, ifname)

    def _serialize_family_prefix(self, prefix):
        if ip.valid_ipv4(prefix):
            family = socket.AF_INET
            return (family,
                    struct.pack(self._FAMILY_FMT, family)
                    + addrconv.ipv4.text_to_bin(prefix))
        elif ip.valid_ipv6(prefix):
            family = socket.AF_INET6
            return (family,
                    struct.pack(self._FAMILY_FMT, family)
                    + addrconv.ipv6.text_to_bin(prefix))

        raise ValueError('Invalid prefix: %s' % prefix)

    def serialize(self, version=_DEFAULT_VERSION):
        (self.dst_family,  # fixup
         dst_bin) = self._serialize_family_prefix(self.dst_prefix)

        body_bin = struct.pack(self._BODY_FMT, self.multi_hop)

        (self.src_family,  # fixup
         src_bin) = self._serialize_family_prefix(self.src_prefix)

        if self.multi_hop:
            footer_bin = struct.pack(
                self._FOOTER_FMT, self.multi_hop_count)
        else:
            ifname_bin = self.ifname.encode('ascii')
            footer_bin = struct.pack(
                self._FOOTER_FMT, len(ifname_bin)) + ifname_bin

        return struct.pack(
            self._HEADER_FMT,
            self.pid) + dst_bin + body_bin + src_bin + footer_bin


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_BFD_DEST_UPDATE)
class ZebraBfdDestinationUpdate(_ZebraBfdDestination):
    """
    Message body class for FRR_ZEBRA_BFD_DEST_UPDATE.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_BFD_DEST_REPLAY)
class ZebraBfdDestinationReply(_ZebraMessageBody):
    """
    Message body class for FRR_ZEBRA_BFD_DEST_REPLAY.
    """


class _ZebraRedistributeIPv4(_ZebraIPRoute):
    """
    Base class for FRR_ZEBRA_REDISTRIBUTE_IPV4_* message body.
    """
    _FAMILY = socket.AF_INET


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_IPV4_ADD)
class ZebraRedistributeIPv4Add(_ZebraRedistributeIPv4):
    """
    Message body class for FRR_ZEBRA_IPV4_ROUTE_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_IPV4_DEL)
class ZebraRedistributeIPv4Delete(_ZebraRedistributeIPv4):
    """
    Message body class for FRR_ZEBRA_IPV4_ROUTE_DELETE.
    """


class _ZebraRedistributeIPv6(_ZebraIPRoute):
    """
    Base class for FRR_ZEBRA_REDISTRIBUTE_IPV6_* message body.
    """
    _FAMILY = socket.AF_INET6


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_IPV6_ADD)
class ZebraRedistributeIPv6Add(_ZebraRedistributeIPv6):
    """
    Message body class for FRR_ZEBRA_REDISTRIBUTE_IPV6_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_REDISTRIBUTE_IPV6_DEL)
class ZebraRedistributeIPv6Delete(_ZebraRedistributeIPv6):
    """
    Message body class for FRR_ZEBRA_REDISTRIBUTE_IPV6_DEL.
    """


class _ZebraVrf(_ZebraMessageBody):
    """
    Base class for FRR_ZEBRA_VRF_ADD and FRR_ZEBRA_VRF_DELETE message body.
    """
    # Zebra VRF Add/Delete message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | VRF Name (VRF_NAMSIZ bytes length)                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!%ds' % VRF_NAMSIZ

    def __init__(self, vrf_name):
        super(_ZebraVrf, self).__init__()
        self.vrf_name = vrf_name

    @classmethod
    def parse(cls, buf, version=_DEFAULT_FRR_VERSION):
        vrf_name_bin = buf[:VRF_NAMSIZ]
        vrf_name = str(six.text_type(vrf_name_bin.strip(b'\x00'), 'ascii'))

        return cls(vrf_name)

    def serialize(self, version=_DEFAULT_FRR_VERSION):
        return struct.pack(self._HEADER_FMT, self.vrf_name.encode('ascii'))


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_VRF_ADD)
class ZebraVrfAdd(_ZebraVrf):
    """
    Message body class for FRR_ZEBRA_VRF_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_VRF_DELETE)
class ZebraVrfDelete(_ZebraVrf):
    """
    Message body class for FRR_ZEBRA_VRF_DELETE.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_VRF_UPDATE)
class ZebraInterfaceVrfUpdate(_ZebraMessageBody):
    """
    Message body class for FRR_ZEBRA_INTERFACE_VRF_UPDATE.
    """
    # Zebra Interface VRF Update message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface Index                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | VRF ID                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!IH'  # ifindex, vrf_id

    def __init__(self, ifindex, vrf_id):
        super(ZebraInterfaceVrfUpdate, self).__init__()
        self.ifindex = ifindex
        self.vrf_id = vrf_id

    @classmethod
    def parse(cls, buf, version=_DEFAULT_FRR_VERSION):
        (ifindex, vrf_id) = struct.unpack_from(cls._HEADER_FMT, buf)

        return cls(ifindex, vrf_id)

    def serialize(self, version=_DEFAULT_FRR_VERSION):
        return struct.pack(self._HEADER_FMT, self.ifindex, self.vrf_id)


class _ZebraBfdClient(_ZebraMessageBody):
    """
    Base class for FRR_ZEBRA_BFD_CLIENT_*.
    """
    # Zebra BFD Client message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | PID                                                           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!I'  # pid
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, pid):
        super(_ZebraBfdClient, self).__init__()
        self.pid = pid

    @classmethod
    def parse(cls, buf, version=_DEFAULT_FRR_VERSION):
        (pid,) = struct.unpack_from(cls._HEADER_FMT, buf)

        return cls(pid)

    def serialize(self, version=_DEFAULT_FRR_VERSION):
        return struct.pack(self._HEADER_FMT, self.pid)


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_BFD_CLIENT_REGISTER)
class ZebraBfdClientRegister(_ZebraBfdClient):
    """
    Message body class for FRR_ZEBRA_BFD_CLIENT_REGISTER.
    """


class _ZebraInterfaceRadv(_ZebraMessageBody):
    """
    Base class for FRR_ZEBRA_INTERFACE_*_RADV message body.
    """
    # Zebra interface Router Advertisement message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface Index                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | RA Interval                                                   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!II'  # ifindex, interval
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)

    def __init__(self, ifindex, interval):
        super(_ZebraInterfaceRadv, self).__init__()
        self.ifindex = ifindex
        self.interval = interval

    @classmethod
    def parse(cls, buf, version=_DEFAULT_FRR_VERSION):
        (ifindex, interval,) = struct.unpack_from(cls._HEADER_FMT, buf)

        return cls(ifindex, interval)

    def serialize(self, version=_DEFAULT_FRR_VERSION):
        return struct.pack(self._HEADER_FMT, self.ifindex, self.interval)


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_ENABLE_RADV)
class ZebraInterfaceEnableRadv(_ZebraInterfaceRadv):
    """
    Message body class for FRR_ZEBRA_INTERFACE_ENABLE_RADV.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_INTERFACE_DISABLE_RADV)
class ZebraInterfaceDisableRadv(_ZebraInterfaceRadv):
    """
    Message body class for FRR_ZEBRA_INTERFACE_DISABLE_RADV.
    """


class _ZebraMplsLabels(_ZebraMessageBody):
    """
    Base class for ZEBRA_MPLS_LABELS_* message body.
    """
    # Zebra MPLS Labels message body:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Route Type    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Family                                                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | IPv4/v6 Prefix (4 bytes/16 bytes)                             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix Len    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Gate IPv4/v6 Address (4 bytes/16 bytes)                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Interface Index: v4(FRRouting v3.0 or later)                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Distance      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | In Label                                                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Out Label                                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    _HEADER_FMT = '!B'  # route_type
    HEADER_SIZE = struct.calcsize(_HEADER_FMT)
    _FAMILY_FMT = '!I'
    FAMILY_SIZE = struct.calcsize(_FAMILY_FMT)
    _IPV4_PREFIX_FMT = '!4sB'  # prefix, prefix_len
    _IPV6_PREFIX_FMT = '!16sB'
    IPV4_PREFIX_SIZE = struct.calcsize(_IPV4_PREFIX_FMT)
    IPV6_PREFIX_SIZE = struct.calcsize(_IPV6_PREFIX_FMT)
    _FAMILY_IPV4_PREFIX_FMT = '!I4sB'
    _FAMILY_IPV6_PREFIX_FMT = '!I16sB'
    _IFINDEX_FMT = '!I'
    IFINDEX_SIZE = struct.calcsize(_IFINDEX_FMT)
    _BODY_FMT = '!BII'  # distance, in_label, out_label

    def __init__(self, route_type, family, prefix, gate_addr, ifindex=None,
                 distance=None, in_label=None, out_label=None):
        super(_ZebraMplsLabels, self).__init__()
        self.route_type = route_type
        self.family = family
        if isinstance(prefix, (IPv4Prefix, IPv6Prefix)):
            prefix = prefix.prefix
        self.prefix = prefix
        assert ip.valid_ipv4(gate_addr) or ip.valid_ipv6(gate_addr)
        self.gate_addr = gate_addr
        if _is_frr_version_ge(_FRR_VERSION_3_0):
            assert ifindex is not None
        self.ifindex = ifindex
        assert distance is not None
        self.distance = distance
        assert in_label is not None
        self.in_label = in_label
        assert out_label is not None
        self.out_label = out_label

    @classmethod
    def _parse_family_prefix(cls, buf):
        (family,) = struct.unpack_from(cls._FAMILY_FMT, buf)
        rest = buf[cls.FAMILY_SIZE:]

        if socket.AF_INET == family:
            (prefix, p_len) = struct.unpack_from(cls._IPV4_PREFIX_FMT, rest)
            prefix = '%s/%d' % (addrconv.ipv4.bin_to_text(prefix), p_len)
            rest = rest[cls.IPV4_PREFIX_SIZE:]
        elif socket.AF_INET6 == family:
            (prefix, p_len) = struct.unpack_from(cls._IPV6_PREFIX_FMT, rest)
            prefix = '%s/%d' % (addrconv.ipv6.bin_to_text(prefix), p_len)
            rest = rest[cls.IPV6_PREFIX_SIZE:]
        else:
            raise struct.error('Unsupported family: %d' % family)

        return family, prefix, rest

    @classmethod
    def parse(cls, buf, version=_DEFAULT_FRR_VERSION):
        (route_type,) = struct.unpack_from(cls._HEADER_FMT, buf)
        rest = buf[cls.HEADER_SIZE:]

        (family, prefix, rest) = cls._parse_family_prefix(rest)

        if family == socket.AF_INET:
            gate_addr = addrconv.ipv4.bin_to_text(rest[:4])
            rest = rest[4:]
        elif family == socket.AF_INET6:
            gate_addr = addrconv.ipv6.bin_to_text(rest[:16])
            rest = rest[16:]
        else:
            raise struct.error('Unsupported family: %d' % family)

        ifindex = None
        if _is_frr_version_ge(_FRR_VERSION_3_0):
            (ifindex,) = struct.unpack_from(cls._IFINDEX_FMT, rest)
            rest = rest[cls.IFINDEX_SIZE:]

        (distance, in_label,
         out_label) = struct.unpack_from(cls._BODY_FMT, rest)

        return cls(route_type, family, prefix, gate_addr, ifindex,
                   distance, in_label, out_label)

    def _serialize_family_prefix(self, prefix):
        if ip.valid_ipv4(prefix):
            family = socket.AF_INET  # fixup
            prefix_addr, prefix_num = prefix.split('/')
            return family, struct.pack(
                self._FAMILY_IPV4_PREFIX_FMT,
                family,
                addrconv.ipv4.text_to_bin(prefix_addr),
                int(prefix_num))
        elif ip.valid_ipv6(prefix):
            family = socket.AF_INET6  # fixup
            prefix_addr, prefix_num = prefix.split('/')
            return family, struct.pack(
                self._FAMILY_IPV6_PREFIX_FMT,
                family,
                addrconv.ipv6.text_to_bin(prefix_addr),
                int(prefix_num))

        raise ValueError('Invalid prefix: %s' % prefix)

    def serialize(self, version=_DEFAULT_FRR_VERSION):
        (self.family,  # fixup
         prefix_bin) = self._serialize_family_prefix(self.prefix)

        if self.family == socket.AF_INET:
            gate_addr_bin = addrconv.ipv4.text_to_bin(self.gate_addr)
        elif self.family == socket.AF_INET6:
            gate_addr_bin = addrconv.ipv6.text_to_bin(self.gate_addr)
        else:
            raise ValueError('Unsupported family: %d' % self.family)

        body_bin = b''
        if _is_frr_version_ge(_FRR_VERSION_3_0):
            body_bin = struct.pack(self._IFINDEX_FMT, self.ifindex)

        body_bin += struct.pack(
            self._BODY_FMT, self.distance, self.in_label, self.out_label)

        return struct.pack(
            self._HEADER_FMT,
            self.route_type) + prefix_bin + gate_addr_bin + body_bin


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_MPLS_LABELS_ADD)
class ZebraMplsLabelsAdd(_ZebraMplsLabels):
    """
    Message body class for FRR_ZEBRA_MPLS_LABELS_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_MPLS_LABELS_DELETE)
class ZebraMplsLabelsDelete(_ZebraMplsLabels):
    """
    Message body class for FRR_ZEBRA_MPLS_LABELS_DELETE.
    """


class _ZebraIPv4Nexthop(_ZebraIPRoute):
    """
    Base class for FRR_ZEBRA_IPV4_NEXTHOP_* message body.
    """
    _FAMILY = socket.AF_INET


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV4_NEXTHOP_ADD)
class ZebraIPv4NexthopAdd(_ZebraIPv4Nexthop):
    """
    Message body class for FRR_ZEBRA_IPV4_NEXTHOP_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV4_NEXTHOP_DELETE)
class ZebraIPv4NexthopDelete(_ZebraIPv4Nexthop):
    """
    Message body class for FRR_ZEBRA_IPV4_NEXTHOP_DELETE.
    """


class _ZebraIPv6Nexthop(_ZebraIPRoute):
    """
    Base class for FRR_ZEBRA_IPV6_NEXTHOP_* message body.
    """
    _FAMILY = socket.AF_INET6


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV6_NEXTHOP_ADD)
class ZebraIPv6NexthopAdd(_ZebraIPv6Nexthop):
    """
    Message body class for FRR_ZEBRA_IPV6_NEXTHOP_ADD.
    """


@_FrrZebraMessageBody.register_type(FRR_ZEBRA_IPV6_NEXTHOP_DELETE)
class ZebraIPv6NexthopDelete(_ZebraIPv6Nexthop):
    """
    Message body class for FRR_ZEBRA_IPV6_NEXTHOP_DELETE.
    """
