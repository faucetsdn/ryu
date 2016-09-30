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
NXAST_DEC_TTL_CNT_IDS = 21
NXAST_PUSH_MPLS = 23
NXAST_POP_MPLS = 24
NXAST_SET_MPLS_TTL = 25
NXAST_DEC_MPLS_TTL = 26
NXAST_STACK_PUSH = 27
NXAST_STACK_POP = 28
NXAST_SAMPLE = 29
NXAST_SET_MPLS_LABEL = 30
NXAST_SET_MPLS_TC = 31
NXAST_OUTPUT_REG2 = 32
NXAST_REG_LOAD2 = 33
NXAST_CONJUNCTION = 34
NXAST_CT = 35
NXAST_NAT = 36
NXAST_CONTROLLER2 = 37
NXAST_SAMPLE2 = 38
NXAST_OUTPUT_TRUNC = 39

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

# enum nx_action_controller2_prop_type
NXAC2PT_MAX_LEN = 0
NXAC2PT_CONTROLLER_ID = 1
NXAC2PT_REASON = 2
NXAC2PT_USERDATA = 3
NXAC2PT_PAUSE = 4

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


def ofs_nbits(start, end):
    """
    The utility method for ofs_nbits

    This method is used in the class to set the ofs_nbits.

    This method converts start/end bits into ofs_nbits required to
    specify the bit range of OXM/NXM fields.

    ofs_nbits can be calculated as following::

      ofs_nbits = (start << 6) + (end - start)

    The parameter start/end  means the OXM/NXM field of ovs-ofctl command.

    ..
      field[start..end]
    ..

    +------------------------------------------+
    | *field*\ **[**\ *start*\..\ *end*\ **]** |
    +------------------------------------------+

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    start            Start bit for OXM/NXM field
    end              End bit for OXM/NXM field
    ================ ======================================================
    """
    return (start << 6) + (end - start)


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
in_port_nxm      Integer 16bit   OpenFlow port number.
eth_dst_nxm      MAC address     Ethernet destination address.
eth_src_nxm      MAC address     Ethernet source address.
eth_type_nxm     Integer 16bit   Ethernet type.  Needed to support Nicira
                                 extensions that require the eth_type to
                                 be set. (i.e. tcp_flags_nxm)
vlan_tci         Integer 16bit   VLAN TCI. Basically same as vlan_vid plus
                                 vlan_pcp.
nw_tos           Integer 8bit    IP ToS or IPv6 traffic class field dscp.
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
ip_proto_nxm     Integer 8bit    IP protocol. Needed to support Nicira
                                 extensions that require the ip_proto to
                                 be set. (i.e. tcp_flags_nxm)
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
ipv4_src_nxm     IPv4 address    IPv4 source address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0800 (IPv4)
ipv4_dst_nxm     IPv4 address    IPv4 destination address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0800 (IPv4)
tcp_src_nxm      Integer 16bit   TCP source port.
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
                                 and ip_proto_nxm = 6 (TCP)
tcp_dst_nxm      Integer 16bit   TCP destination port.
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
                                 and ip_proto_nxm = 6 (TCP)
udp_src_nxm      Integer 16bit   UDP source port.
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
                                 and ip_proto_nxm = 17 (UDP)
udp_dst_nxm      Integer 16bit   UDP destination port.
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
                                 and ip_proto_nxm = 17 (UDP)
icmpv4_type_nxm  Integer 8bit    Type  matches  the ICMP type and code matches
                                 the ICMP code.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0800 (IPv4) and
                                 ip_proto_nxm = 1 (ICMP)
icmpv4_code_nxm  Integer 8bit    Type  matches  the ICMP type and code matches
                                 the ICMP code.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0800 (IPv4) and
                                 ip_proto_nxm = 1 (ICMP)
arp_op_nxm       Integer 16bit   Only ARP opcodes between 1 and 255 should be
                                 specified for matching.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0806 (ARP)
arp_spa_nxm      IPv4 address    An address may be specified as an IP address
                                 or host name.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0806 (ARP)
arp_tpa_nxm      IPv4 address    An address may be specified as an IP address
                                 or host name.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0806 (ARP)
tunnel_id_nxm    Integer 64bit   Tunnel identifier.
arp_sha_nxm      MAC address     An address is specified as 6 pairs of
                                 hexadecimal digits delimited by colons.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0806 (ARP)
arp_tha_nxm      MAC address     An address is specified as 6 pairs of
                                 hexadecimal digits delimited by colons.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0806 (ARP)
ipv6_src_nxm     IPv6 address    IPv6 source address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6)
ipv6_dst_nxm     IPv6 address    IPv6 destination address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6)
icmpv6_type_nxm  Integer 8bit    Type  matches the ICMP type and code matches
                                 the ICMP code.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6) and
                                 ip_proto_nxm = 58 (ICMP for IPv6)
icmpv6_code_nxm  Integer 8bit    Type  matches the ICMP type and code matches
                                 the ICMP code.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6) and
                                 ip_proto_nxm = 58 (ICMP for IPv6)
nd_target        IPv6 address    The target address ipv6.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6) and
                                 ip_proto_nxm = 58 (ICMP for IPv6)
nd_sll           MAC address     The source link-layer address option.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6) and
                                 ip_proto_nxm = 58 (ICMP for IPv6) and
                                 icmpv6_type_nxm = 135 (Neighbor solicitation)
nd_tll           MAC address     The target link-layer address option.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6) and
                                 ip_proto_nxm = 58 (ICMP for IPv6) and
                                 icmpv6_type_nxm = 136 (Neighbor advertisement)
ip_frag          Integer 8bit    frag_type specifies what kind of IP fragments
                                 or non-fragments to match.
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
ipv6_label       Integer 32bit   Matches IPv6 flow label.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6)
ip_ecn_nxm       Integer 8bit    Matches ecn bits in IP ToS or IPv6 traffic
                                 class fields.
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
nw_ttl           Integer 8bit    IP TTL or IPv6 hop limit value ttl.
                                 Requires setting fields:
                                 eth_type_nxm = [0x0800 (IPv4)|0x86dd (IPv6)]
mpls_ttl         Integer 8bit    The TTL of the outer MPLS label stack entry
                                 of a packet.
                                 Requires setting fields:
                                 eth_type_nxm = 0x8847 (MPLS Unicast)
tun_ipv4_src     IPv4 address    Tunnel IPv4 source address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0800 (IPv4)
tun_ipv4_dst     IPv4 address    Tunnel IPv4 destination address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x0800 (IPv4)
pkt_mark         Integer 32bit   Packet metadata mark.
tcp_flags_nxm    Integer 16bit   TCP Flags.  Requires setting fields:
                                 eth_type_nxm = [0x0800 (IP)|0x86dd (IPv6)] and
                                 ip_proto_nxm = 6 (TCP)
conj_id          Integer 32bit   Conjunction ID used only with
                                 the conjunction action
tun_gbp_id       Integer 16bit   The group policy identifier in the
                                 VXLAN header.
tun_gbp_flags    Integer 8bit    The group policy flags in the
                                 VXLAN header.
tun_flags        Integer 16bit   Flags indicating various aspects of
                                 the tunnel encapsulation.
ct_state         Integer 32bit   Conntrack state.
ct_zone          Integer 16bit   Conntrack zone.
ct_mark          Integer 32bit   Conntrack mark.
ct_label         Integer 128bit  Conntrack label.
tun_ipv6_src     IPv6 address    Tunnel IPv6 source address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6)
tun_ipv6_dst     IPv6 address    Tunnel IPv6 destination address.
                                 Requires setting fields:
                                 eth_type_nxm = 0x86dd (IPv6)
_recirc_id       Integer 32bit   ID for recirculation.
_dp_hash         Integer 32bit   Flow hash computed in Datapath.
reg<idx>         Integer 32bit   Packet register.
                                 <idx> is register number 0-15.
xxreg<idx>       Integer 128bit  Packet extended-extended register.
                                 <idx> is register number 0-3.
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
    # OFPXMC_NXM_0
    oxm_fields.NiciraExtended0('in_port_nxm', 0, type_desc.Int2),
    oxm_fields.NiciraExtended0('eth_dst_nxm', 1, type_desc.MacAddr),
    oxm_fields.NiciraExtended0('eth_src_nxm', 2, type_desc.MacAddr),
    oxm_fields.NiciraExtended0('eth_type_nxm', 3, type_desc.Int2),
    oxm_fields.NiciraExtended0('vlan_tci', 4, type_desc.Int2),
    oxm_fields.NiciraExtended0('nw_tos', 5, type_desc.Int1),
    oxm_fields.NiciraExtended0('ip_proto_nxm', 6, type_desc.Int1),
    oxm_fields.NiciraExtended0('ipv4_src_nxm', 7, type_desc.IPv4Addr),
    oxm_fields.NiciraExtended0('ipv4_dst_nxm', 8, type_desc.IPv4Addr),
    oxm_fields.NiciraExtended0('tcp_src_nxm', 9, type_desc.Int2),
    oxm_fields.NiciraExtended0('tcp_dst_nxm', 10, type_desc.Int2),
    oxm_fields.NiciraExtended0('udp_src_nxm', 11, type_desc.Int2),
    oxm_fields.NiciraExtended0('udp_dst_nxm', 12, type_desc.Int2),
    oxm_fields.NiciraExtended0('icmpv4_type_nxm', 13, type_desc.Int1),
    oxm_fields.NiciraExtended0('icmpv4_code_nxm', 14, type_desc.Int1),
    oxm_fields.NiciraExtended0('arp_op_nxm', 15, type_desc.Int2),
    oxm_fields.NiciraExtended0('arp_spa_nxm', 16, type_desc.IPv4Addr),
    oxm_fields.NiciraExtended0('arp_tpa_nxm', 17, type_desc.IPv4Addr),

    # OFPXMC_NXM_1
    oxm_fields.NiciraExtended1('tunnel_id_nxm', 16, type_desc.Int8),
    oxm_fields.NiciraExtended1('arp_sha_nxm', 17, type_desc.MacAddr),
    oxm_fields.NiciraExtended1('arp_tha_nxm', 18, type_desc.MacAddr),
    oxm_fields.NiciraExtended1('ipv6_src_nxm', 19, type_desc.IPv6Addr),
    oxm_fields.NiciraExtended1('ipv6_dst_nxm', 20, type_desc.IPv6Addr),
    oxm_fields.NiciraExtended1('icmpv6_type_nxm', 21, type_desc.Int1),
    oxm_fields.NiciraExtended1('icmpv6_code_nxm', 22, type_desc.Int1),
    oxm_fields.NiciraExtended1('nd_target', 23, type_desc.IPv6Addr),
    oxm_fields.NiciraExtended1('nd_sll', 24, type_desc.MacAddr),
    oxm_fields.NiciraExtended1('nd_tll', 25, type_desc.MacAddr),
    oxm_fields.NiciraExtended1('ip_frag', 26, type_desc.Int1),
    oxm_fields.NiciraExtended1('ipv6_label', 27, type_desc.Int4),
    oxm_fields.NiciraExtended1('ip_ecn_nxm', 28, type_desc.Int1),
    oxm_fields.NiciraExtended1('nw_ttl', 29, type_desc.Int1),
    oxm_fields.NiciraExtended1('mpls_ttl', 30, type_desc.Int1),
    oxm_fields.NiciraExtended1('tun_ipv4_src', 31, type_desc.IPv4Addr),
    oxm_fields.NiciraExtended1('tun_ipv4_dst', 32, type_desc.IPv4Addr),
    oxm_fields.NiciraExtended1('pkt_mark', 33, type_desc.Int4),
    oxm_fields.NiciraExtended1('tcp_flags_nxm', 34, type_desc.Int2),
    oxm_fields.NiciraExtended1('conj_id', 37, type_desc.Int4),
    oxm_fields.NiciraExtended1('tun_gbp_id', 38, type_desc.Int2),
    oxm_fields.NiciraExtended1('tun_gbp_flags', 39, type_desc.Int1),
    oxm_fields.NiciraExtended1('tun_flags', 104, type_desc.Int2),
    oxm_fields.NiciraExtended1('ct_state', 105, type_desc.Int4),
    oxm_fields.NiciraExtended1('ct_zone', 106, type_desc.Int2),
    oxm_fields.NiciraExtended1('ct_mark', 107, type_desc.Int4),
    oxm_fields.NiciraExtended1('ct_label', 108, type_desc.Int16),
    oxm_fields.NiciraExtended1('tun_ipv6_src', 109, type_desc.IPv6Addr),
    oxm_fields.NiciraExtended1('tun_ipv6_dst', 110, type_desc.IPv6Addr),

    # Prefix the name with '_' to indicate this is not intended to be used
    # in wild.
    # Because the following definitions are supposed to be internal use only
    # in OVS.
    oxm_fields.NiciraExtended1('_recirc_id', 36, type_desc.Int4),

    # The following definition is merely for testing 64-bit experimenter OXMs.
    # Following Open vSwitch, we use dp_hash for this purpose.
    # Prefix the name with '_' to indicate this is not intended to be used
    # in wild.
    oxm_fields.NiciraExperimenter('_dp_hash', 0, type_desc.Int4),

    # Support for matching/setting NX registers 0-15
    oxm_fields.NiciraExtended1('reg0', 0, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg1', 1, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg2', 2, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg3', 3, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg4', 4, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg5', 5, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg6', 6, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg7', 7, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg8', 8, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg9', 9, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg10', 10, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg11', 11, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg12', 12, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg13', 13, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg14', 14, type_desc.Int4),
    oxm_fields.NiciraExtended1('reg15', 15, type_desc.Int4),

    # Support for matching/setting NX extended-extended registers 0-3
    oxm_fields.NiciraExtended1('xxreg0', 111, type_desc.Int16),
    oxm_fields.NiciraExtended1('xxreg1', 112, type_desc.Int16),
    oxm_fields.NiciraExtended1('xxreg2', 113, type_desc.Int16),
    oxm_fields.NiciraExtended1('xxreg3', 114, type_desc.Int16),

]
