# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

# Nicira extensions
# Many of these definitions are common among OpenFlow versions.

import sys
from struct import calcsize
from ryu.lib import type_desc
from ryu.ofproto.ofproto_common import OFP_HEADER_SIZE
from ryu.ofproto import oxm_fields

# Action subtypes
NXAST_RESUBMIT = 1
NXAST_SET_TUNNEL = 2
NXAST_DROP_SPOOFED_ARP__OBSOLETE = 3
NXAST_SET_QUEUE = 4
NXAST_POP_QUEUE = 5
NXAST_REG_MOVE = 6
NXAST_REG_LOAD = 7
NXAST_NOTE = 8
NXAST_SET_TUNNEL64 = 9
NXAST_MULTIPATH = 10
NXAST_AUTOPATH = 11
NXAST_BUNDLE = 12
NXAST_BUNDLE_LOAD = 13
NXAST_RESUBMIT_TABLE = 14
NXAST_OUTPUT_REG = 15
NXAST_LEARN = 16
NXAST_EXIT = 17
NXAST_DEC_TTL = 18
NXAST_FIN_TIMEOUT = 19
NXAST_CONTROLLER = 20
NXAST_CONJUNCTION = 34
NXAST_CT = 35
NXAST_NAT = 36

NX_ACTION_RESUBMIT_PACK_STR = '!HHIHHB3x'
NX_ACTION_RESUBMIT_SIZE = 16
assert calcsize(NX_ACTION_RESUBMIT_PACK_STR) == NX_ACTION_RESUBMIT_SIZE

NX_ACTION_SET_TUNNEL_PACK_STR = '!HHIH2xI'
NX_ACTION_SET_TUNNEL_SIZE = 16
assert calcsize(NX_ACTION_SET_TUNNEL_PACK_STR) == NX_ACTION_SET_TUNNEL_SIZE

NX_ACTION_SET_QUEUE_PACK_STR = '!HHIH2xI'
NX_ACTION_SET_QUEUE_SIZE = 16
assert calcsize(NX_ACTION_SET_QUEUE_PACK_STR) == NX_ACTION_SET_QUEUE_SIZE

NX_ACTION_POP_QUEUE_PACK_STR = '!HHIH6x'
NX_ACTION_POP_QUEUE_SIZE = 16
assert calcsize(NX_ACTION_POP_QUEUE_PACK_STR) == NX_ACTION_POP_QUEUE_SIZE

NX_ACTION_REG_MOVE_PACK_STR = '!HHIHHHHII'
NX_ACTION_REG_MOVE_SIZE = 24
assert calcsize(NX_ACTION_REG_MOVE_PACK_STR) == NX_ACTION_REG_MOVE_SIZE

NX_ACTION_REG_LOAD_PACK_STR = '!HHIHHIQ'
NX_ACTION_REG_LOAD_SIZE = 24
assert calcsize(NX_ACTION_REG_LOAD_PACK_STR) == NX_ACTION_REG_LOAD_SIZE

NX_ACTION_SET_TUNNEL64_PACK_STR = '!HHIH6xQ'
NX_ACTION_SET_TUNNEL64_SIZE = 24
assert calcsize(NX_ACTION_SET_TUNNEL64_PACK_STR) == NX_ACTION_SET_TUNNEL64_SIZE

NX_ACTION_MULTIPATH_PACK_STR = '!HHIHHH2xHHI2xHI'
NX_ACTION_MULTIPATH_SIZE = 32
assert calcsize(NX_ACTION_MULTIPATH_PACK_STR) == NX_ACTION_MULTIPATH_SIZE

NX_ACTION_NOTE_PACK_STR = '!HHIH6B'
NX_ACTION_NOTE_SIZE = 16
assert calcsize(NX_ACTION_NOTE_PACK_STR) == NX_ACTION_NOTE_SIZE

NX_ACTION_BUNDLE_PACK_STR = '!HHIHHHHIHHI4x'
NX_ACTION_BUNDLE_SIZE = 32
NX_ACTION_BUNDLE_0_SIZE = 24
assert calcsize(NX_ACTION_BUNDLE_PACK_STR) == NX_ACTION_BUNDLE_SIZE

NX_ACTION_AUTOPATH_PACK_STR = '!HHIHHII4x'
NX_ACTION_AUTOPATH_SIZE = 24
assert calcsize(NX_ACTION_AUTOPATH_PACK_STR) == NX_ACTION_AUTOPATH_SIZE

NX_ACTION_OUTPUT_REG_PACK_STR = '!HHIHHIH6x'
NX_ACTION_OUTPUT_REG_SIZE = 24
assert calcsize(NX_ACTION_OUTPUT_REG_PACK_STR) == NX_ACTION_OUTPUT_REG_SIZE

NX_ACTION_LEARN_PACK_STR = '!HHIHHHHQHBxHH'
NX_ACTION_LEARN_SIZE = 32
assert calcsize(NX_ACTION_LEARN_PACK_STR) == NX_ACTION_LEARN_SIZE

NX_ACTION_CONTROLLER_PACK_STR = '!HHIHHHBB'
NX_ACTION_CONTROLLER_SIZE = 16
assert calcsize(NX_ACTION_CONTROLLER_PACK_STR) == NX_ACTION_CONTROLLER_SIZE

NX_ACTION_FIN_TIMEOUT_PACK_STR = '!HHIHHH2x'
NX_ACTION_FIN_TIMEOUT_SIZE = 16
assert calcsize(NX_ACTION_FIN_TIMEOUT_PACK_STR) == NX_ACTION_FIN_TIMEOUT_SIZE

NX_ACTION_HEADER_PACK_STR = '!HHIH6x'
NX_ACTION_HEADER_SIZE = 16
NX_ACTION_HEADER_0_SIZE = 2
assert calcsize(NX_ACTION_HEADER_PACK_STR) == NX_ACTION_HEADER_SIZE

# Messages
NXT_ROLE_REQUEST = 10
NXT_ROLE_REPLY = 11
NXT_SET_FLOW_FORMAT = 12
NXT_FLOW_MOD = 13
NXT_FLOW_REMOVED = 14
NXT_FLOW_MOD_TABLE_ID = 15
NXT_SET_PACKET_IN_FORMAT = 16
NXT_PACKET_IN = 17
NXT_FLOW_AGE = 18
NXT_SET_ASYNC_CONFIG = 19
NXT_SET_CONTROLLER_ID = 20

# enum nx_role
NX_ROLE_OTHER = 0
NX_ROLE_MASTER = 1
NX_ROLE_SLAVE = 2

# enum nx_flow_format
NXFF_OPENFLOW10 = 0
NXFF_NXM = 2

# enum nx_packet_in_format
NXPIF_OPENFLOW10 = 0
NXPIF_NXM = 1

# enum nx_stats_types
NXST_FLOW = 0
NXST_AGGREGATE = 1
NXST_FLOW_MONITOR = 2

NICIRA_HEADER_PACK_STR = '!II'
NICIRA_HEADER_SIZE = 16
assert (calcsize(NICIRA_HEADER_PACK_STR) +
        OFP_HEADER_SIZE == NICIRA_HEADER_SIZE)

NX_ROLE_PACK_STR = '!I'
NX_ROLE_SIZE = 20
assert (calcsize(NX_ROLE_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_ROLE_SIZE)

NX_FLOW_MOD_PACK_STR = '!Q4HI3H6x'
NX_FLOW_MOD_SIZE = 48
assert (calcsize(NX_FLOW_MOD_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_FLOW_MOD_SIZE)

NX_SET_FLOW_FORMAT_PACK_STR = '!I'
NX_SET_FLOW_FORMAT_SIZE = 20
assert (calcsize(NX_SET_FLOW_FORMAT_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_SET_FLOW_FORMAT_SIZE)

NX_FLOW_REMOVED_PACK_STR = '!QHBxIIHHQQ'
NX_FLOW_REMOVED_SIZE = 56
assert (calcsize(NX_FLOW_REMOVED_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_FLOW_REMOVED_SIZE)

NX_FLOW_MOD_TABLE_ID_PACK_STR = '!B7x'
NX_FLOW_MOD_TABLE_ID_SIZE = 24
assert (calcsize(NX_FLOW_MOD_TABLE_ID_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_FLOW_MOD_TABLE_ID_SIZE)

NX_SET_PACKET_IN_FORMAT_PACK_STR = '!I'
NX_SET_PACKET_IN_FORMAT_SIZE = 20
assert (calcsize(NX_SET_PACKET_IN_FORMAT_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_SET_PACKET_IN_FORMAT_SIZE)

NX_PACKET_IN_PACK_STR = '!IHBBQH6x'
NX_PACKET_IN_SIZE = 40
assert (calcsize(NX_PACKET_IN_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_PACKET_IN_SIZE)

NX_ASYNC_CONFIG_PACK_STR = '!IIIIII'
NX_ASYNC_CONFIG_SIZE = 40
assert (calcsize(NX_ASYNC_CONFIG_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_ASYNC_CONFIG_SIZE)

NX_CONTROLLER_ID_PACK_STR = '!6xH'
NX_CONTROLLER_ID_SIZE = 24
assert (calcsize(NX_CONTROLLER_ID_PACK_STR) +
        NICIRA_HEADER_SIZE == NX_CONTROLLER_ID_SIZE)

NX_STATS_MSG_PACK_STR = '!I4x'
NX_STATS_MSG0_SIZE = 8
assert calcsize(NX_STATS_MSG_PACK_STR) == NX_STATS_MSG0_SIZE
NX_STATS_MSG_SIZE = 24
_OFP_VENDOR_STATS_MSG_SIZE = 16
assert (calcsize(NX_STATS_MSG_PACK_STR) + _OFP_VENDOR_STATS_MSG_SIZE ==
        NX_STATS_MSG_SIZE)

NX_FLOW_STATS_REQUEST_PACK_STR = '!2HB3x'
NX_FLOW_STATS_REQUEST_SIZE = 8
assert (calcsize(NX_FLOW_STATS_REQUEST_PACK_STR) ==
        NX_FLOW_STATS_REQUEST_SIZE)

NX_FLOW_STATS_PACK_STR = '!HBxIIHHHHHHQQQ'
NX_FLOW_STATS_SIZE = 48
assert calcsize(NX_FLOW_STATS_PACK_STR) == NX_FLOW_STATS_SIZE

NX_AGGREGATE_STATS_REQUEST_PACK_STR = '!2HB3x'
NX_AGGREGATE_STATS_REQUEST_SIZE = 8
assert (calcsize(NX_AGGREGATE_STATS_REQUEST_PACK_STR) ==
        NX_AGGREGATE_STATS_REQUEST_SIZE)

NX_AGGREGATE_STATS_REPLY_PACK_STR = '!QQI4x'
NX_AGGREGATE_STATS_REPLY_SIZE = 24
assert (calcsize(NX_AGGREGATE_STATS_REPLY_PACK_STR) ==
        NX_AGGREGATE_STATS_REPLY_SIZE)

# enum nx_hash_fields
NX_HASH_FIELDS_ETH_SRC = 0
NX_HASH_FIELDS_SYMMETRIC_L4 = 1

# enum nx_mp_algorithm
NX_MP_ALG_MODULO_N = 0
NX_MP_ALG_HASH_THRESHOLD = 1
NX_MP_ALG_HRW = 2
NX_MP_ALG_ITER_HASH = 3

# enum nx_bd_algorithm
NX_BD_ALG_ACTIVE_BACKUP = 0
NX_BD_ALG_HRW = 1

# nx_learn constants
NX_LEARN_N_BITS_MASK = 0x3ff
NX_LEARN_SRC_FIELD = 0 << 13  # Copy from field.
NX_LEARN_SRC_IMMEDIATE = 1 << 13  # Copy from immediate value.
NX_LEARN_SRC_MASK = 1 << 13
NX_LEARN_DST_MATCH = 0 << 11  # Add match criterion.
NX_LEARN_DST_LOAD = 1 << 11  # Add NXAST_REG_LOAD action
NX_LEARN_DST_OUTPUT = 2 << 11  # Add OFPAT_OUTPUT action.
NX_LEARN_DST_RESERVED = 3 << 11  # Not yet defined.
NX_LEARN_DST_MASK = 3 << 11

# nx_nat constants
NX_NAT_RANGE_IPV4_MIN = 1 << 0
NX_NAT_RANGE_IPV4_MAX = 1 << 1
NX_NAT_RANGE_IPV6_MIN = 1 << 2
NX_NAT_RANGE_IPV6_MAX = 1 << 3
NX_NAT_RANGE_PROTO_MIN = 1 << 4
NX_NAT_RANGE_PROTO_MAX = 1 << 5


def nxm_header__(vendor, field, hasmask, length):
    return (vendor << 16) | (field << 9) | (hasmask << 8) | length


def nxm_header(vendor, field, length):
    return nxm_header__(vendor, field, 0, length)


def nxm_header_w(vendor, field, length):
    return nxm_header__(vendor, field, 1, (length) * 2)


NXM_OF_IN_PORT = nxm_header(0x0000, 0, 2)

NXM_OF_ETH_DST = nxm_header(0x0000, 1, 6)
NXM_OF_ETH_DST_W = nxm_header_w(0x0000, 1, 6)
NXM_OF_ETH_SRC = nxm_header(0x0000, 2, 6)
NXM_OF_ETH_SRC_W = nxm_header_w(0x0000, 2, 6)
NXM_OF_ETH_TYPE = nxm_header(0x0000, 3, 2)

NXM_OF_VLAN_TCI = nxm_header(0x0000, 4, 2)
NXM_OF_VLAN_TCI_W = nxm_header_w(0x0000, 4, 2)

NXM_OF_IP_TOS = nxm_header(0x0000, 5, 1)

NXM_OF_IP_PROTO = nxm_header(0x0000, 6, 1)

NXM_OF_IP_SRC = nxm_header(0x0000, 7, 4)
NXM_OF_IP_SRC_W = nxm_header_w(0x0000, 7, 4)
NXM_OF_IP_DST = nxm_header(0x0000, 8, 4)
NXM_OF_IP_DST_W = nxm_header_w(0x0000, 8, 4)

NXM_OF_TCP_SRC = nxm_header(0x0000, 9, 2)
NXM_OF_TCP_SRC_W = nxm_header_w(0x0000, 9, 2)
NXM_OF_TCP_DST = nxm_header(0x0000, 10, 2)
NXM_OF_TCP_DST_W = nxm_header_w(0x0000, 10, 2)

NXM_OF_UDP_SRC = nxm_header(0x0000, 11, 2)
NXM_OF_UDP_SRC_W = nxm_header_w(0x0000, 11, 2)
NXM_OF_UDP_DST = nxm_header(0x0000, 12, 2)
NXM_OF_UDP_DST_W = nxm_header_w(0x0000, 12, 2)

NXM_OF_ICMP_TYPE = nxm_header(0x0000, 13, 1)
NXM_OF_ICMP_CODE = nxm_header(0x0000, 14, 1)

NXM_OF_ARP_OP = nxm_header(0x0000, 15, 2)

NXM_OF_ARP_SPA = nxm_header(0x0000, 16, 4)
NXM_OF_ARP_SPA_W = nxm_header_w(0x0000, 16, 4)
NXM_OF_ARP_TPA = nxm_header(0x0000, 17, 4)
NXM_OF_ARP_TPA_W = nxm_header_w(0x0000, 17, 4)

NXM_NX_TUN_ID = nxm_header(0x0001, 16, 8)
NXM_NX_TUN_ID_W = nxm_header_w(0x0001, 16, 8)
NXM_NX_TUN_IPV4_SRC = nxm_header(0x0001, 31, 4)
NXM_NX_TUN_IPV4_SRC_W = nxm_header_w(0x0001, 31, 4)
NXM_NX_TUN_IPV4_DST = nxm_header(0x0001, 32, 4)
NXM_NX_TUN_IPV4_DST_W = nxm_header_w(0x0001, 32, 4)

NXM_NX_ARP_SHA = nxm_header(0x0001, 17, 6)
NXM_NX_ARP_THA = nxm_header(0x0001, 18, 6)

NXM_NX_IPV6_SRC = nxm_header(0x0001, 19, 16)
NXM_NX_IPV6_SRC_W = nxm_header_w(0x0001, 19, 16)
NXM_NX_IPV6_DST = nxm_header(0x0001, 20, 16)
NXM_NX_IPV6_DST_W = nxm_header_w(0x0001, 20, 16)

NXM_NX_ICMPV6_TYPE = nxm_header(0x0001, 21, 1)
NXM_NX_ICMPV6_CODE = nxm_header(0x0001, 22, 1)

NXM_NX_ND_TARGET = nxm_header(0x0001, 23, 16)
NXM_NX_ND_TARGET_W = nxm_header_w(0x0001, 23, 16)

NXM_NX_ND_SLL = nxm_header(0x0001, 24, 6)

NXM_NX_ND_TLL = nxm_header(0x0001, 25, 6)

NXM_NX_IP_FRAG = nxm_header(0x0001, 26, 1)
NXM_NX_IP_FRAG_W = nxm_header_w(0x0001, 26, 1)

NXM_NX_IPV6_LABEL = nxm_header(0x0001, 27, 4)

NXM_NX_IP_ECN = nxm_header(0x0001, 28, 1)

NXM_NX_IP_TTL = nxm_header(0x0001, 29, 1)

NXM_NX_PKT_MARK = nxm_header(0x0001, 33, 4)
NXM_NX_PKT_MARK_W = nxm_header_w(0x0001, 33, 4)

NXM_NX_TCP_FLAGS = nxm_header(0x0001, 34, 2)
NXM_NX_TCP_FLAGS_W = nxm_header_w(0x0001, 34, 2)


def nxm_nx_reg(idx):
    return nxm_header(0x0001, idx, 4)


def nxm_nx_reg_w(idx):
    return nxm_header_w(0x0001, idx, 4)

NXM_HEADER_PACK_STRING = '!I'

#
# The followings are implementations for OpenFlow 1.2+
#

sys.modules[__name__].__doc__ = """
The API of this class is the same as ``OFPMatch``.

You can define the flow match by the keyword arguments.
The following arguments are available.

================ =============== ==============================================
Argument         Value           Description
================ =============== ==============================================
eth_dst_nxm      MAC address     Ethernet destination address.
eth_src_nxm      MAC address     Ethernet source address.
eth_type_nxm     Integer 16bit   Ethernet type.  Needed to support Nicira
                                 extensions that require the eth_type to
                                 be set. (i.e. tcp_flags_nxm)
ip_proto_nxm     Integer 8bit    IP protocol. Needed to support Nicira
                                 extensions that require the ip_proto to
                                 be set. (i.e. tcp_flags_nxm)
tunnel_id_nxm    Integer 64bit   Tunnel identifier.
tun_ipv4_src     IPv4 address    Tunnel IPv4 source address.
tun_ipv4_dst     IPv4 address    Tunnel IPv4 destination address.
pkt_mark         Integer 32bit   Packet metadata mark.
tcp_flags_nxm    Integer 16bit   TCP Flags.  Requires setting fields:
                                 eth_type_nxm = [0x0800 (IP)|0x86dd (IPv6)] and
                                 ip_proto_nxm = 6 (TCP)
conj_id          Integer 32bit   Conjunction ID used only with
                                 the conjunction action
ct_state         Integer 32bit   Conntrack state.
ct_zone          Integer 16bit   Conntrack zone.
ct_mark          Integer 32bit   Conntrack mark.
ct_label         Integer 128bit  Conntrack label.
tun_ipv6_src     IPv6 address    Tunnel IPv6 source address.
tun_ipv6_dst     IPv6 address    Tunnel IPv6 destination address.
_dp_hash         Integer 32bit   Flow hash computed in Datapath.
reg<idx>         Integer 32bit   Packet register.
                                 <idx> is register number 0-7.
================ =============== ==============================================

.. Note::

    Setting the TCP flags via the nicira extensions.
    This is required when using OVS version < 2.4.
    When using the nxm fields, you need to use any nxm prereq
    fields as well or you will receive a OFPBMC_BAD_PREREQ error

    Example::

        # WILL NOT work
        flag = tcp.TCP_ACK
        match = parser.OFPMatch(
            tcp_flags_nxm=(flag, flag),
            ip_proto=inet.IPPROTO_TCP,
            eth_type=eth_type)

        # Works
        flag = tcp.TCP_ACK
        match = parser.OFPMatch(
            tcp_flags_nxm=(flag, flag),
            ip_proto_nxm=inet.IPPROTO_TCP,
            eth_type_nxm=eth_type)
"""

oxm_types = [
    oxm_fields.NiciraExtended0('eth_dst_nxm', 1, type_desc.MacAddr),
    oxm_fields.NiciraExtended0('eth_src_nxm', 2, type_desc.MacAddr),
    oxm_fields.NiciraExtended0('eth_type_nxm', 3, type_desc.Int2),
    oxm_fields.NiciraExtended0('ip_proto_nxm', 6, type_desc.Int1),
    oxm_fields.NiciraExtended1('tunnel_id_nxm', 16, type_desc.Int8),
    oxm_fields.NiciraExtended1('tun_ipv4_src', 31, type_desc.IPv4Addr),
    oxm_fields.NiciraExtended1('tun_ipv4_dst', 32, type_desc.IPv4Addr),
    oxm_fields.NiciraExtended1('pkt_mark', 33, type_desc.Int4),
    oxm_fields.NiciraExtended1('tcp_flags_nxm', 34, type_desc.Int2),
    oxm_fields.NiciraExtended1('conj_id', 37, type_desc.Int4),
    oxm_fields.NiciraExtended1('ct_state', 105, type_desc.Int4),
    oxm_fields.NiciraExtended1('ct_zone', 106, type_desc.Int2),
    oxm_fields.NiciraExtended1('ct_mark', 107, type_desc.Int4),
    oxm_fields.NiciraExtended1('ct_label', 108, type_desc.Int16),
    oxm_fields.NiciraExtended1('tun_ipv6_src', 109, type_desc.IPv6Addr),
    oxm_fields.NiciraExtended1('tun_ipv6_dst', 110, type_desc.IPv6Addr),

    # The following definition is merely for testing 64-bit experimenter OXMs.
    # Following Open vSwitch, we use dp_hash for this purpose.
    # Prefix the name with '_' to indicate this is not intended to be used
    # in wild.
    oxm_fields.NiciraExperimenter('_dp_hash', 0, type_desc.Int4),

    # Support for matching/setting NX registers 0-7
    oxm_fields.NiciraExtended1('reg0', 0, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg1', 1, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg2', 2, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg3', 3, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg4', 4, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg5', 5, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg6', 6, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg7', 7, type_desc.Int4),
]
