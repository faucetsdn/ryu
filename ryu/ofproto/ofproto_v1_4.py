# Copyright (C) 2012,2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>
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
OpenFlow 1.4 definitions.
"""

from ryu.lib import type_desc
from ryu.ofproto import nicira_ext
from ryu.ofproto import ofproto_utils
from ryu.ofproto import oxm_fields

from struct import calcsize


# enum ofp_port_no
# Port numbering. Ports are numbered starting from 1.
OFPP_MAX = 0xffffff00           # Maximum number of physical and logical
                                # switch ports.
OFPP_IN_PORT = 0xfffffff8       # Send the packet out the input port.  This
                                # reserved port must be explicitly used in
                                # order to send back out of the input port.
OFPP_TABLE = 0xfffffff9         # Submit the packet to the first flow table
                                # NB: This destination port can only be used
                                # in packet-out messages.
OFPP_NORMAL = 0xfffffffa        # Process with normal L2/L3 switching.
OFPP_FLOOD = 0xfffffffb         # All physical ports in VLAN, except input
                                # port and those blocked or link down.
OFPP_ALL = 0xfffffffc           # All physical ports except input port.
OFPP_CONTROLLER = 0xfffffffd    # Send to controller.
OFPP_LOCAL = 0xfffffffe         # Local openflow "port".
OFPP_ANY = 0xffffffff           # Wildcard port used only for flow mod
                                # (delete) and flow stats requests. Selects
                                # all flows regardless of output port
                                # (including flows with no output port).


# enum ofp_type
# Immutable messages.
OFPT_HELLO = 0                  # Symmetric message
OFPT_ERROR = 1                  # Symmetric message
OFPT_ECHO_REQUEST = 2           # Symmetric message
OFPT_ECHO_REPLY = 3             # Symmetric message
OFPT_EXPERIMENTER = 4           # Symmetric message
# Switch configuration messages.
OFPT_FEATURES_REQUEST = 5       # Controller/switch message
OFPT_FEATURES_REPLY = 6         # Controller/switch message
OFPT_GET_CONFIG_REQUEST = 7     # Controller/switch message
OFPT_GET_CONFIG_REPLY = 8       # Controller/switch message
OFPT_SET_CONFIG = 9             # Controller/switch message
# Asynchronous messages.
OFPT_PACKET_IN = 10             # Async message
OFPT_FLOW_REMOVED = 11          # Async message
OFPT_PORT_STATUS = 12           # Async message
# Controller command messages.
OFPT_PACKET_OUT = 13            # Controller/switch message
OFPT_FLOW_MOD = 14              # Controller/switch message
OFPT_GROUP_MOD = 15             # Controller/switch message
OFPT_PORT_MOD = 16              # Controller/switch message
OFPT_TABLE_MOD = 17             # Controller/switch message
# Multipart messages.
OFPT_MULTIPART_REQUEST = 18     # Controller/switch message
OFPT_MULTIPART_REPLY = 19       # Controller/switch message
# Barrier messages.
OFPT_BARRIER_REQUEST = 20       # Controller/switch message
OFPT_BARRIER_REPLY = 21         # Controller/switch message
# Controller role change request messages.
OFPT_ROLE_REQUEST = 24          # Controller/switch message
OFPT_ROLE_REPLY = 25            # Controller/switch message
# Asynchronous message configuration.
OFPT_GET_ASYNC_REQUEST = 26     # Controller/switch message
OFPT_GET_ASYNC_REPLY = 27       # Controller/switch message
OFPT_SET_ASYNC = 28             # Controller/switch message
# Meters and rate limiters configuration messages.
OFPT_METER_MOD = 29             # Controller/switch message
# Controller role change event messages.
OFPT_ROLE_STATUS = 30           # Async message
# Asynchronous messages.
OFPT_TABLE_STATUS = 31          # Async message
# Request forwarding by the switch.
OFPT_REQUESTFORWARD = 32        # Async message
# Bundle operations (multiple messages as a single operation).
OFPT_BUNDLE_CONTROL = 33
OFPT_BUNDLE_ADD_MESSAGE = 34


_OFP_HEADER_PACK_STR = 'BBHI'
OFP_HEADER_PACK_STR = '!' + _OFP_HEADER_PACK_STR
OFP_HEADER_SIZE = 8


# struct ofp_hello
OFP_HELLO_HEADER_SIZE = 8

# struct ofp_hello_elem_header
OFP_HELLO_ELEM_HEADER_PACK_STR = '!HH'
OFP_HELLO_ELEM_HEADER_SIZE = 4
assert (calcsize(OFP_HELLO_ELEM_HEADER_PACK_STR) == OFP_HELLO_ELEM_HEADER_SIZE)

# enum ofp_hello_elem_type
OFPHET_VERSIONBITMAP = 1

# struct ofp_hello_elem_versionbitmap
OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_PACK_STR = '!HH'
OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_SIZE = 4
assert (calcsize(OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_PACK_STR) ==
        OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_SIZE)


OFP_DEFAULT_MISS_SEND_LEN = 128

# enum ofp_config_flags
# Handling of IP fragments.
OFPC_FRAG_NORMAL = 0        # No special handling for fragments.
OFPC_FRAG_DROP = 1 << 0     # Drop fragments.
OFPC_FRAG_REASM = 1 << 1    # Reassemble (only if OFPC_IP_REASM set).
OFPC_FRAG_MASK = 3

# struct ofp_switch_config
OFP_SWITCH_CONFIG_PACK_STR = '!HH'
OFP_SWITCH_CONFIG_SIZE = 12
assert (calcsize(OFP_SWITCH_CONFIG_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_SWITCH_CONFIG_SIZE)


# enum ofp_table
OFPTT_MAX = 0xfe    # Last usable table number.
OFPTT_ALL = 0xff    # Wildcard table used for table config, flow stats
                    # and flow deletes.


# enum ofp_table_config
OFPTC_DEPRECATED_MASK = 3       # Deprecated bits
OFPTC_EVICTION = 1 << 2         # Authorise table to evict flows.
OFPTC_VACANCY_EVENTS = 1 << 3   # Enable vacancy events.

# enum ofp_table_mod_prop_type
OFPTMPT_EVICTION = 0x2          # Eviction property.
OFPTMPT_VACANCY = 0x3           # Vacancy property.
OFPTMPT_EXPERIMENTER = 0xFFFF   # Experimenter property.

# enum ofp_table_mod_prop_eviction_flag
OFPTMPEF_OTHER = 1 << 0         # Using other factors.
OFPTMPEF_IMPORTANCE = 1 << 1    # Using flow entry importance.
OFPTMPEF_LIFETIME = 1 << 2      # Using flow entry lifetime.

# struct ofp_table_mod_prop_eviction
OFP_TABLE_MOD_PROP_EVICTION_PACK_STR = '!HHI'
OFP_TABLE_MOD_PROP_EVICTION_SIZE = 8
assert(calcsize(OFP_TABLE_MOD_PROP_EVICTION_PACK_STR) ==
       OFP_TABLE_MOD_PROP_EVICTION_SIZE)

# struct ofp_table_mod_prop_vacancy
OFP_TABLE_MOD_PROP_VACANCY_PACK_STR = '!HHBBBx'
OFP_TABLE_MOD_PROP_VACANCY_SIZE = 8
assert(calcsize(OFP_TABLE_MOD_PROP_VACANCY_PACK_STR) ==
       OFP_TABLE_MOD_PROP_VACANCY_SIZE)

# struct ofp_table_mod_prop_experimenter
OFP_TABLE_MOD_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_TABLE_MOD_PROP_EXPERIMENTER_SIZE = 12
assert(calcsize(OFP_TABLE_MOD_PROP_EXPERIMENTER_PACK_STR) ==
       OFP_TABLE_MOD_PROP_EXPERIMENTER_SIZE)

# struct ofp_table_mod
OFP_TABLE_MOD_PACK_STR = '!B3xI'
OFP_TABLE_MOD_SIZE = 16
assert (calcsize(OFP_TABLE_MOD_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_TABLE_MOD_SIZE)

# enum ofp_capabilities
OFPC_FLOW_STATS = 1 << 0    # Flow statistics.
OFPC_TABLE_STATS = 1 << 1   # Table statistics.
OFPC_PORT_STATS = 1 << 2    # Port statistics.
OFPC_GROUP_STATS = 1 << 3   # Group statistics.
OFPC_IP_REASM = 1 << 5      # Can reassemble IP fragments.
OFPC_QUEUE_STATS = 1 << 6   # Queue statistics.
OFPC_PORT_BLOCKED = 1 << 8  # Switch will block looping ports.

# enum ofp_port_config
OFPPC_PORT_DOWN = 1 << 0        # Port is administratively down.
OFPPC_NO_RECV = 1 << 2          # Drop all packets recieved by port.
OFPPC_NO_FWD = 1 << 5           # Drop packets forwarded to port.
OFPPC_NO_PACKET_IN = 1 << 6     # Do not send packet-in msgs for port.

# enum ofp_port_state
OFPPS_LINK_DOWN = 1 << 0    # No physical link present.
OFPPS_BLOCKED = 1 << 1      # Port is blocked
OFPPS_LIVE = 1 << 2         # Live for Fast Failover Group.

# enum ofp_port_features
OFPPF_10MB_HD = 1 << 0      # 10 Mb half-duplex rate support.
OFPPF_10MB_FD = 1 << 1      # 10 Mb full-duplex rate support.
OFPPF_100MB_HD = 1 << 2     # 100 Mb half-duplex rate support.
OFPPF_100MB_FD = 1 << 3     # 100 Mb full-duplex rate support.
OFPPF_1GB_HD = 1 << 4       # 1 Gb half-duplex rate support.
OFPPF_1GB_FD = 1 << 5       # 1 Gb full-duplex rate support.
OFPPF_10GB_FD = 1 << 6      # 10 Gb full-duplex rate support.
OFPPF_40GB_FD = 1 << 7      # 40 Gb full-duplex rate support.
OFPPF_100GB_FD = 1 << 8     # 100 Gb full-duplex rate support.
OFPPF_1TB_FD = 1 << 9       # 1 Tb full-duplex rate support.
OFPPF_OTHER = 1 << 10       # Other rate, not in the list.
OFPPF_COPPER = 1 << 11      # Copper medium.
OFPPF_FIBER = 1 << 12       # Fiber medium.
OFPPF_AUTONEG = 1 << 13     # Auto-negotiation.
OFPPF_PAUSE = 1 << 14       # Pause.
OFPPF_PAUSE_ASYM = 1 << 15  # Asymmetric pause.

# enum ofp_port_desc_prop_type
OFPPDPT_ETHERNET = 0            # Ethernet property.
OFPPDPT_OPTICAL = 1             # Optical property.
OFPPDPT_EXPERIMENTER = 0xFFFF   # Experimenter property.

# struct ofp_port_desc_prop_ethernet
OFP_PORT_DESC_PROP_ETHERNET_PACK_STR = '!HH4xIIIIII'
OFP_PORT_DESC_PROP_ETHERNET_SIZE = 32
assert (calcsize(OFP_PORT_DESC_PROP_ETHERNET_PACK_STR) ==
        OFP_PORT_DESC_PROP_ETHERNET_SIZE)

# enum ofp_optical_port_features
OFPOPF_RX_TUNE = 1 << 0     # Receiver is tunable
OFPOPF_TX_TUNE = 1 << 1     # Transmit is tunable
OFPOPF_TX_PWR = 1 << 2      # Power is configurable
OFPOPF_USE_FREQ = 1 << 3    # Use Frequency, not wavelength

# struct ofp_port_desc_prop_optical
OFP_PORT_DESC_PROP_OPTICAL_PACK_STR = '!HH4xIIIIIIIHH'
OFP_PORT_DESC_PROP_OPTICAL_SIZE = 40
assert (calcsize(OFP_PORT_DESC_PROP_OPTICAL_PACK_STR) ==
        OFP_PORT_DESC_PROP_OPTICAL_SIZE)

# struct ofp_port_desc_prop_experimenter
OFP_PORT_DESC_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_PORT_DESC_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_PORT_DESC_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_PORT_DESC_PROP_EXPERIMENTER_SIZE)

# struct ofp_port
OFP_MAX_PORT_NAME_LEN = 16
OFP_ETH_ALEN = 6
OFP_ETH_ALEN_STR = str(OFP_ETH_ALEN)
_OFP_PORT_PACK_STR = 'IH2x' + OFP_ETH_ALEN_STR + 's' + '2x' + \
    str(OFP_MAX_PORT_NAME_LEN) + 's' + 'II'
OFP_PORT_PACK_STR = '!' + _OFP_PORT_PACK_STR
OFP_PORT_SIZE = 40
assert (calcsize(OFP_PORT_PACK_STR) == OFP_PORT_SIZE)

# struct ofp_switch_features
OFP_SWITCH_FEATURES_PACK_STR = '!QIBB2xII'
OFP_SWITCH_FEATURES_SIZE = 32
assert (calcsize(OFP_SWITCH_FEATURES_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_SWITCH_FEATURES_SIZE)

# enum ofp_port_reason
OFPPR_ADD = 0       # The port was added.
OFPPR_DELETE = 1    # The port was removed.
OFPPR_MODIFY = 2    # Some attribute of the port has changed.

# struct ofp_port_status
OFP_PORT_STATUS_PACK_STR = '!B7x' + _OFP_PORT_PACK_STR
OFP_PORT_STATUS_SIZE = 56
assert (calcsize(OFP_PORT_STATUS_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PORT_STATUS_SIZE)

# enum ofp_port_mod_prop_type
OFPPMPT_ETHERNET = 0            # Ethernet property.
OFPPMPT_OPTICAL = 1             # Optical property.
OFPPMPT_EXPERIMENTER = 0xFFFF   # Experimenter property.

# struct ofp_port_mod_prop_ethernet
OFP_PORT_MOD_PROP_ETHERNET_PACK_STR = '!HHI'
OFP_PORT_MOD_PROP_ETHERNET_SIZE = 8
assert (calcsize(OFP_PORT_MOD_PROP_ETHERNET_PACK_STR) ==
        OFP_PORT_MOD_PROP_ETHERNET_SIZE)

# struct ofp_port_mod_prop_optical
OFP_PORT_MOD_PROP_OPTICAL_PACK_STR = '!HHIIIII'
OFP_PORT_MOD_PROP_OPTICAL_SIZE = 24
assert (calcsize(OFP_PORT_MOD_PROP_OPTICAL_PACK_STR) ==
        OFP_PORT_MOD_PROP_OPTICAL_SIZE)

# struct ofp_port_mod_prop_experimenter
OFP_PORT_MOD_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_PORT_MOD_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_PORT_MOD_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_PORT_MOD_PROP_EXPERIMENTER_SIZE)

# struct ofp_port_mod
OFP_PORT_MOD_PACK_STR = '!I4x' + OFP_ETH_ALEN_STR + 's2xII'
OFP_PORT_MOD_SIZE = 32
assert (calcsize(OFP_PORT_MOD_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PORT_MOD_SIZE)


# enum ofp_match_type
OFPMT_STANDARD = 0  # Deprecated
OFPMT_OXM = 1       # OpenFlow Extensible Match

# struct ofp_match
_OFP_MATCH_PACK_STR = 'HH4x'
OFP_MATCH_PACK_STR = '!' + _OFP_MATCH_PACK_STR
OFP_MATCH_SIZE = 8
assert calcsize(OFP_MATCH_PACK_STR) == OFP_MATCH_SIZE

# enum ofp_oxm_class
OFPXMC_NXM_0 = 0x0000           # Backward compatibility with NXM
OFPXMC_NXM_1 = 0x0001           # Backward compatibility with NXM
OFPXMC_OPENFLOW_BASIC = 0x8000  # Basic class for OpenFlow
OFPXMC_EXPERIMENTER = 0xFFFF    # Experimenter class

# enum ofp_vlan_id
OFPVID_PRESENT = 0x1000     # bit that indicate that a VLAN id is set.
OFPVID_NONE = 0X0000        # No VLAN id was set.


def _oxm_tlv_header(class_, field, hasmask, length):
    return (class_ << 16) | (field << 9) | (hasmask << 8) | length


def oxm_tlv_header(field, length):
    return _oxm_tlv_header(OFPXMC_OPENFLOW_BASIC, field, 0, length)


def oxm_tlv_header_w(field, length):
    return _oxm_tlv_header(OFPXMC_OPENFLOW_BASIC, field, 1, length * 2)


def oxm_tlv_header_extract_hasmask(header):
    return (header >> 8) & 1


def oxm_tlv_header_extract_length(header):
    if oxm_tlv_header_extract_hasmask(header):
        length = (header & 0xff) // 2
    else:
        length = header & 0xff
    return length

oxm_types = [
    oxm_fields.OpenFlowBasic('in_port', 0, type_desc.Int4),
    oxm_fields.OpenFlowBasic('in_phy_port', 1, type_desc.Int4),
    oxm_fields.OpenFlowBasic('metadata', 2, type_desc.Int8),
    oxm_fields.OpenFlowBasic('eth_dst', 3, type_desc.MacAddr),
    oxm_fields.OpenFlowBasic('eth_src', 4, type_desc.MacAddr),
    oxm_fields.OpenFlowBasic('eth_type', 5, type_desc.Int2),
    oxm_fields.OpenFlowBasic('vlan_vid', 6, type_desc.Int2),
    oxm_fields.OpenFlowBasic('vlan_pcp', 7, type_desc.Int1),
    oxm_fields.OpenFlowBasic('ip_dscp', 8, type_desc.Int1),
    oxm_fields.OpenFlowBasic('ip_ecn', 9, type_desc.Int1),
    oxm_fields.OpenFlowBasic('ip_proto', 10, type_desc.Int1),
    oxm_fields.OpenFlowBasic('ipv4_src', 11, type_desc.IPv4Addr),
    oxm_fields.OpenFlowBasic('ipv4_dst', 12, type_desc.IPv4Addr),
    oxm_fields.OpenFlowBasic('tcp_src', 13, type_desc.Int2),
    oxm_fields.OpenFlowBasic('tcp_dst', 14, type_desc.Int2),
    oxm_fields.OpenFlowBasic('udp_src', 15, type_desc.Int2),
    oxm_fields.OpenFlowBasic('udp_dst', 16, type_desc.Int2),
    oxm_fields.OpenFlowBasic('sctp_src', 17, type_desc.Int2),
    oxm_fields.OpenFlowBasic('sctp_dst', 18, type_desc.Int2),
    oxm_fields.OpenFlowBasic('icmpv4_type', 19, type_desc.Int1),
    oxm_fields.OpenFlowBasic('icmpv4_code', 20, type_desc.Int1),
    oxm_fields.OpenFlowBasic('arp_op', 21, type_desc.Int2),
    oxm_fields.OpenFlowBasic('arp_spa', 22, type_desc.IPv4Addr),
    oxm_fields.OpenFlowBasic('arp_tpa', 23, type_desc.IPv4Addr),
    oxm_fields.OpenFlowBasic('arp_sha', 24, type_desc.MacAddr),
    oxm_fields.OpenFlowBasic('arp_tha', 25, type_desc.MacAddr),
    oxm_fields.OpenFlowBasic('ipv6_src', 26, type_desc.IPv6Addr),
    oxm_fields.OpenFlowBasic('ipv6_dst', 27, type_desc.IPv6Addr),
    oxm_fields.OpenFlowBasic('ipv6_flabel', 28, type_desc.Int4),
    oxm_fields.OpenFlowBasic('icmpv6_type', 29, type_desc.Int1),
    oxm_fields.OpenFlowBasic('icmpv6_code', 30, type_desc.Int1),
    oxm_fields.OpenFlowBasic('ipv6_nd_target', 31, type_desc.IPv6Addr),
    oxm_fields.OpenFlowBasic('ipv6_nd_sll', 32, type_desc.MacAddr),
    oxm_fields.OpenFlowBasic('ipv6_nd_tll', 33, type_desc.MacAddr),
    oxm_fields.OpenFlowBasic('mpls_label', 34, type_desc.Int4),
    oxm_fields.OpenFlowBasic('mpls_tc', 35, type_desc.Int1),
    oxm_fields.OpenFlowBasic('mpls_bos', 36, type_desc.Int1),
    oxm_fields.OpenFlowBasic('pbb_isid', 37, type_desc.Int3),
    oxm_fields.OpenFlowBasic('tunnel_id', 38, type_desc.Int8),
    oxm_fields.OpenFlowBasic('ipv6_exthdr', 39, type_desc.Int2),
    oxm_fields.OpenFlowBasic('pbb_uca', 41, type_desc.Int1),
    # EXT-109 TCP flags match field Extension
    oxm_fields.ONFExperimenter('tcp_flags', 42, type_desc.Int2),
    # EXT-233 Output match Extension
    # NOTE(yamamoto): The spec says uint64_t but I assume it's an error.
    oxm_fields.ONFExperimenter('actset_output', 43, type_desc.Int4),
] + nicira_ext.oxm_types

oxm_fields.generate(__name__)


# enum ofp_action_type
OFPAT_OUTPUT = 0            # Output to switch port.
OFPAT_COPY_TTL_OUT = 11     # Copy TTL "outwards" -- from
                            # next-to-outermost to outermost
OFPAT_COPY_TTL_IN = 12      # Copy TTL "inwards" -- from outermost to
                            # next-to-outermost
OFPAT_SET_MPLS_TTL = 15     # MPLS TTL.
OFPAT_DEC_MPLS_TTL = 16     # Decrement MPLS TTL
OFPAT_PUSH_VLAN = 17        # Push a new VLAN tag
OFPAT_POP_VLAN = 18         # Pop the outer VLAN tag
OFPAT_PUSH_MPLS = 19        # Push a new MPLS tag
OFPAT_POP_MPLS = 20         # Pop the outer MPLS tag
OFPAT_SET_QUEUE = 21        # Set queue id when outputting to a port
OFPAT_GROUP = 22            # Apply group
OFPAT_SET_NW_TTL = 23       # IP TTL.
OFPAT_DEC_NW_TTL = 24       # Decrement IP TTL.
OFPAT_SET_FIELD = 25        # Set a header field using OXM TLV format.
OFPAT_PUSH_PBB = 26         # Push a new PBB service tag (I-TAG)
OFPAT_POP_PBB = 27          # Pop the outer PBB service tag (I-TAG)
OFPAT_EXPERIMENTER = 0xffff


# struct ofp_action_header
OFP_ACTION_HEADER_PACK_STR = '!HH4x'
OFP_ACTION_HEADER_SIZE = 8
assert calcsize(OFP_ACTION_HEADER_PACK_STR) == OFP_ACTION_HEADER_SIZE

# enum ofp_controller_max_len
OFPCML_MAX = 0xffe5         # maximum max_len value which can be used to
                            # request a specific byte length.
OFPCML_NO_BUFFER = 0xffff   # indicates that no buffering should be
                            # applied and the whole packet is to be
                            # sent to the controller.

# struct ofp_action_output
OFP_ACTION_OUTPUT_PACK_STR = '!HHIH6x'
OFP_ACTION_OUTPUT_SIZE = 16
assert calcsize(OFP_ACTION_OUTPUT_PACK_STR) == OFP_ACTION_OUTPUT_SIZE

# struct ofp_action_generic
OFP_ACTION_GENERIC_PACK_STR = '!HH4x'
OFP_ACTION_GENERIC_SIZE = 8
assert (calcsize(OFP_ACTION_GENERIC_PACK_STR) == OFP_ACTION_GENERIC_SIZE)

# struct ofp_action_mpls_ttl
OFP_ACTION_MPLS_TTL_PACK_STR = '!HHB3x'
OFP_ACTION_MPLS_TTL_SIZE = 8
assert calcsize(OFP_ACTION_MPLS_TTL_PACK_STR) == OFP_ACTION_MPLS_TTL_SIZE

# struct ofp_action_push
OFP_ACTION_PUSH_PACK_STR = '!HHH2x'
OFP_ACTION_PUSH_SIZE = 8
assert calcsize(OFP_ACTION_PUSH_PACK_STR) == OFP_ACTION_PUSH_SIZE

# struct ofp_action_pop_mpls
OFP_ACTION_POP_MPLS_PACK_STR = '!HHH2x'
OFP_ACTION_POP_MPLS_SIZE = 8
assert calcsize(OFP_ACTION_POP_MPLS_PACK_STR) == OFP_ACTION_POP_MPLS_SIZE

# struct ofp_action_set_queue
OFP_ACTION_SET_QUEUE_PACK_STR = '!HHI'
OFP_ACTION_SET_QUEUE_SIZE = 8
assert calcsize(OFP_ACTION_SET_QUEUE_PACK_STR) == OFP_ACTION_SET_QUEUE_SIZE

# struct ofp_action_group
OFP_ACTION_GROUP_PACK_STR = '!HHI'
OFP_ACTION_GROUP_SIZE = 8
assert calcsize(OFP_ACTION_GROUP_PACK_STR) == OFP_ACTION_GROUP_SIZE

# struct ofp_action_nw_ttl
OFP_ACTION_NW_TTL_PACK_STR = '!HHB3x'
OFP_ACTION_NW_TTL_SIZE = 8
assert calcsize(OFP_ACTION_NW_TTL_PACK_STR) == OFP_ACTION_NW_TTL_SIZE

# struct ofp_action_set_field
OFP_ACTION_SET_FIELD_PACK_STR = '!HH4x'
OFP_ACTION_SET_FIELD_SIZE = 8
assert calcsize(OFP_ACTION_SET_FIELD_PACK_STR) == OFP_ACTION_SET_FIELD_SIZE

# struct ofp_action_experimenter_header
OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR = '!HHI'
OFP_ACTION_EXPERIMENTER_HEADER_SIZE = 8
assert (calcsize(OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR) ==
        OFP_ACTION_EXPERIMENTER_HEADER_SIZE)

# enum ofp_instruction_type
OFPIT_GOTO_TABLE = 1            # Setup the next table in the lookup pipeline.
OFPIT_WRITE_METADATA = 2        # Setup the metadata field for use later in
                                # pipeline.
OFPIT_WRITE_ACTIONS = 3         # Write the action(s) onto the datapath
                                # action set
OFPIT_APPLY_ACTIONS = 4         # Applies the action(s) immediately
OFPIT_CLEAR_ACTIONS = 5         # Clears all actions from the datapath action
                                # set
OFPIT_METER = 6                 # Apply meter (rate limiter)
OFPIT_EXPERIMENTER = 0xFFFF     # Experimenter instruction

# struct ofp_instruction_goto_table
OFP_INSTRUCTION_GOTO_TABLE_PACK_STR = '!HHB3x'
OFP_INSTRUCTION_GOTO_TABLE_SIZE = 8
assert (calcsize(OFP_INSTRUCTION_GOTO_TABLE_PACK_STR) ==
        OFP_INSTRUCTION_GOTO_TABLE_SIZE)

# struct ofp_instruction_write_metadata
OFP_INSTRUCTION_WRITE_METADATA_PACK_STR = '!HH4xQQ'
OFP_INSTRUCTION_WRITE_METADATA_SIZE = 24
assert (calcsize(OFP_INSTRUCTION_WRITE_METADATA_PACK_STR) ==
        OFP_INSTRUCTION_WRITE_METADATA_SIZE)

# struct ofp_instruction_actions
OFP_INSTRUCTION_ACTIONS_PACK_STR = '!HH4x'
OFP_INSTRUCTION_ACTIONS_SIZE = 8
assert (calcsize(OFP_INSTRUCTION_ACTIONS_PACK_STR) ==
        OFP_INSTRUCTION_ACTIONS_SIZE)

# struct ofp_instruction_meter
OFP_INSTRUCTION_METER_PACK_STR = '!HHI'
OFP_INSTRUCTION_METER_SIZE = 8
assert calcsize(OFP_INSTRUCTION_METER_PACK_STR) == OFP_INSTRUCTION_METER_SIZE

# struct ofp_instruction_experimenter_header
OFP_INSTRUCTION_EXPERIMENTER_HEADER_PACK_STR = '!HHI'
OFP_INSTRUCTION_EXPERIMENTER_HEADER_SIZE = 8
assert (calcsize(OFP_INSTRUCTION_EXPERIMENTER_HEADER_PACK_STR) ==
        OFP_INSTRUCTION_EXPERIMENTER_HEADER_SIZE)

# enum ofp_flow_mod_command
OFPFC_ADD = 0               # New flow.
OFPFC_MODIFY = 1            # Modify all matching flows.
OFPFC_MODIFY_STRICT = 2     # Modify entry strictly matching wildcards
OFPFC_DELETE = 3            # Delete all matching flows.
OFPFC_DELETE_STRICT = 4     # Strictly match wildcards and priority.

# Value used in "idle_timeout" and "hard_timeout" to indicate that the
# entry is permanent. */
OFP_FLOW_PERMANENT = 0

# By default, choose a priority in the middle.
OFP_DEFAULT_PRIORITY = 0x8000

# enum ofp_flow_mod_flags
OFPFF_SEND_FLOW_REM = 1 << 0    # Send flow removed message when flow
                                # expires or is deleted.
OFPFF_CHECK_OVERLAP = 1 << 1    # Check for overlapping entries first.
OFPFF_RESET_COUNTS = 1 << 2     # Reset flow packet and byte counts.
OFPFF_NO_PKT_COUNTS = 1 << 3    # Don't keep track of packet count.
OFPFF_NO_BYT_COUNTS = 1 << 4    # Don't keep track of byte count.

# struct ofp_flow_mod
_OFP_FLOW_MOD_PACK_STR0 = 'QQBBHHHIIIHH'
OFP_FLOW_MOD_PACK_STR = '!' + _OFP_FLOW_MOD_PACK_STR0 + _OFP_MATCH_PACK_STR
OFP_FLOW_MOD_PACK_STR0 = '!' + _OFP_FLOW_MOD_PACK_STR0
OFP_FLOW_MOD_SIZE = 56
assert (calcsize(OFP_FLOW_MOD_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_FLOW_MOD_SIZE)

# enum ofp_group
OFPG_MAX = 0xffffff00   # Last usable group number.
OFPG_ALL = 0xfffffffc   # Represents all groups for group delete commands.
OFPG_ANY = 0xffffffff   # Wildcard group used only for flow stats requests.
                        # Selects all flows regardless of group
                        # (including flows with no group).

# enum ofp_group_mod_command
OFPGC_ADD = 0       # New group.
OFPGC_MODIFY = 1    # Modify all matching groups.
OFPGC_DELETE = 2    # Delete all matching groups.

# struct ofp_bucket
OFP_BUCKET_PACK_STR = '!HHII4x'
OFP_BUCKET_SIZE = 16
assert calcsize(OFP_BUCKET_PACK_STR) == OFP_BUCKET_SIZE

# struct ofp_group_mod
OFP_GROUP_MOD_PACK_STR = '!HBxI'
OFP_GROUP_MOD_SIZE = 16
assert (calcsize(OFP_GROUP_MOD_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_GROUP_MOD_SIZE)

# enum ofp_group_type
OFPGT_ALL = 0       # All (multicast/broadcast) group.
OFPGT_SELECT = 1    # Select group.
OFPGT_INDIRECT = 2  # Indirect group.
OFPGT_FF = 3        # Fast failover group.


OFP_NO_BUFFER = 0xffffffff  # Special buffer-id to indicate 'no buffer'

# struct ofp_packet_out
OFP_PACKET_OUT_PACK_STR = '!IIH6x'
OFP_PACKET_OUT_SIZE = 24
assert (calcsize(OFP_PACKET_OUT_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PACKET_OUT_SIZE)

# enum ofp_packet_in_reason
OFPR_TABLE_MISS = 0     # No matching flow (table-miss flow entry).
OFPR_APPLY_ACTION = 1   # Output to controller in apply-actions.
OFPR_INVALID_TTL = 2    # Packet has invalid TTL.
OFPR_ACTION_SET = 3     # Output to controller in action set.
OFPR_GROUP = 4          # Output to controller in group bucket.
OFPR_PACKET_OUT = 5     # Output to controller in packet-out.

# struct ofp_packet_in
OFP_PACKET_IN_PACK_STR = '!IHBBQ'
OFP_PACKET_IN_SIZE = 32
assert (calcsize(OFP_PACKET_IN_PACK_STR) + OFP_MATCH_SIZE + OFP_HEADER_SIZE ==
        OFP_PACKET_IN_SIZE)

# enum ofp_flow_removed_reason
OFPRR_IDLE_TIMEOUT = 0  # Flow idle time exceeded idle_timeout.
OFPRR_HARD_TIMEOUT = 1  # Time exceeded hard_timeout.
OFPRR_DELETE = 2        # Evicted by a DELETE flow mod.
OFPRR_GROUP_DELETE = 3  # Group was removed.
OFPRR_METER_DELETE = 4  # Meter was removed.
OFPRR_EVICTION = 5      # Switch eviction to free resources.

# struct ofp_port_status
OFP_PORT_STATUS_PACK_STR = '!B7x' + _OFP_PORT_PACK_STR
OFP_PORT_STATUS_DESC_OFFSET = OFP_HEADER_SIZE + 8
OFP_PORT_STATUS_SIZE = 56
assert (calcsize(OFP_PORT_STATUS_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PORT_STATUS_SIZE)

# struct ofp_flow_removed
_OFP_FLOW_REMOVED_PACK_STR0 = 'QHBBIIHHQQ'
OFP_FLOW_REMOVED_PACK_STR = '!' + _OFP_FLOW_REMOVED_PACK_STR0 + \
                            _OFP_MATCH_PACK_STR
OFP_FLOW_REMOVED_PACK_STR0 = '!' + _OFP_FLOW_REMOVED_PACK_STR0
OFP_FLOW_REMOVED_SIZE = 56
assert (calcsize(OFP_FLOW_REMOVED_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_FLOW_REMOVED_SIZE)

# enum ofp_meter
OFPM_MAX = 0xffff0000
OFPM_SLOWPATH = 0xfffffffd      # Meter for slow datapath, if any.
OFPM_CONTROLLER = 0xfffffffe    # Meter for controller connection.
OFPM_ALL = 0xffffffff           # Represents all meters for stat requests
                                # commands.

# enum ofp_meter_band_type
OFPMBT_DROP = 1                 # Drop packet.
OFPMBT_DSCP_REMARK = 2          # Remark DSCP in the IP header.
OFPMBT_EXPERIMENTER = 0xFFFF    # Experimenter meter band.

# struct ofp_meter_band_drop
OFP_METER_BAND_DROP_PACK_STR = '!HHII4x'
OFP_METER_BAND_DROP_SIZE = 16
assert (calcsize(OFP_METER_BAND_DROP_PACK_STR) ==
        OFP_METER_BAND_DROP_SIZE)

# struct ofp_meter_band_dscp_remark
OFP_METER_BAND_DSCP_REMARK_PACK_STR = '!HHIIB3x'
OFP_METER_BAND_DSCP_REMARK_SIZE = 16
assert (calcsize(OFP_METER_BAND_DSCP_REMARK_PACK_STR) ==
        OFP_METER_BAND_DSCP_REMARK_SIZE)

# struct ofp_meter_band_experimenter
OFP_METER_BAND_EXPERIMENTER_PACK_STR = '!HHIII'
OFP_METER_BAND_EXPERIMENTER_SIZE = 16
assert (calcsize(OFP_METER_BAND_EXPERIMENTER_PACK_STR) ==
        OFP_METER_BAND_EXPERIMENTER_SIZE)

# enum ofp_meter_mod_command
OFPMC_ADD = 0       # New meter.
OFPMC_MODIFY = 1    # Modify specified meter.
OFPMC_DELETE = 2    # Delete specified meter.

# enum ofp_meter_flags
OFPMF_KBPS = 1 << 0     # Rate value in kb/s (kilo-bit per second).
OFPMF_PKTPS = 1 << 1    # Rate value in packet/sec.
OFPMF_BURST = 1 << 2    # Do burst size.
OFPMF_STATS = 1 << 3    # Collect statistics.

# struct ofp_meter_band_header
OFP_METER_BAND_HEADER_PACK_STR = '!HHII'
OFP_METER_BAND_HEADER_SIZE = 12
assert (calcsize(OFP_METER_BAND_HEADER_PACK_STR) ==
        OFP_METER_BAND_HEADER_SIZE)

# struct ofp_meter_mod
OFP_METER_MOD_PACK_STR = '!HHI'
OFP_METER_MOD_SIZE = 16
assert (calcsize(OFP_METER_MOD_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_METER_MOD_SIZE)


# enum ofp_error_type
OFPET_HELLO_FAILED = 0              # Hello protocol failed.
OFPET_BAD_REQUEST = 1               # Request was not understood.
OFPET_BAD_ACTION = 2                # Error in action description.
OFPET_BAD_INSTRUCTION = 3           # Error in instruction list.
OFPET_BAD_MATCH = 4                 # Error in match.
OFPET_FLOW_MOD_FAILED = 5           # Problem modifying flow entry.
OFPET_GROUP_MOD_FAILED = 6          # Problem modifying group entry.
OFPET_PORT_MOD_FAILED = 7           # OFPT_PORT_MOD failed.
OFPET_TABLE_MOD_FAILED = 8          # Table mod request failed.
OFPET_QUEUE_OP_FAILED = 9           # Queue operation failed.
OFPET_SWITCH_CONFIG_FAILED = 10     # Switch config request failed.
OFPET_ROLE_REQUEST_FAILED = 11      # Controller Role request failed.
OFPET_METER_MOD_FAILED = 12         # Error in meter.
OFPET_TABLE_FEATURES_FAILED = 13    # Setting table features failed.
OFPET_BAD_PROPERTY = 14             # Some property is invalid.
OFPET_ASYNC_CONFIG_FAILED = 15      # Asynchronous config request failed.
OFPET_FLOW_MONITOR_FAILED = 16      # Setting flow monitor failed.
OFPET_BUNDLE_FAILED = 17            # Bundle operation failed.
OFPET_EXPERIMENTER = 0xffff         # Experimenter error messages.

# enum ofp_hello_failed_code
OFPHFC_INCOMPATIBLE = 0     # No compatible version.
OFPHFC_EPERM = 1            # Permissions error.

# enum ofp_bad_request_code
OFPBRC_BAD_VERSION = 0                  # ofp_header.version not supported.
OFPBRC_BAD_TYPE = 1                     # ofp_header.type not supported.
OFPBRC_BAD_MULTIPART = 2                # ofp_multipart_request.type not
                                        # supported.
OFPBRC_BAD_EXPERIMENTER = 3             # Experimenter id not supported
                                        # (in ofp_experimenter_header
                                        # or ofp_multipart_request or
                                        # ofp_multipart_reply).
OFPBRC_BAD_EXP_TYPE = 4                 # Experimenter type not supported.
OFPBRC_EPERM = 5                        # Permissions error.
OFPBRC_BAD_LEN = 6                      # Wrong request length for type.
OFPBRC_BUFFER_EMPTY = 7                 # Specified buffer has already been
                                        # used.
OFPBRC_BUFFER_UNKNOWN = 8               # Specified buffer does not exist.
OFPBRC_BAD_TABLE_ID = 9                 # Specified table-id invalid or does
                                        # not exist.
OFPBRC_IS_SLAVE = 10                    # Denied because controller is slave.
OFPBRC_BAD_PORT = 11                    # Invalid port.
OFPBRC_BAD_PACKET = 12                  # Invalid packet in packet-out
OFPBRC_MULTIPART_BUFFER_OVERFLOW = 13   # ofp_multipart_request
                                        # overflowed the assigned buffer.
OFPBRC_MULTIPART_REQUEST_TIMEOUT = 14   # Timeout during multipart request.
OFPBRC_MULTIPART_REPLY_TIMEOUT = 15     # Timeout during multipart reply.


# enum ofp_bad_action_code
OFPBAC_BAD_TYPE = 0             # Unknown action type.
OFPBAC_BAD_LEN = 1              # Length problem in actions.
OFPBAC_BAD_EXPERIMENTER = 2     # Unknown experimenter id specified.
OFPBAC_BAD_EXP_TYPE = 3         # Unknown action type for experimenter id.
OFPBAC_BAD_OUT_PORT = 4         # Problem validating output action.
OFPBAC_BAD_ARGUMENT = 5         # Bad action argument.
OFPBAC_EPERM = 6                # Permissions error.
OFPBAC_TOO_MANY = 7             # Can't handle this many actions.
OFPBAC_BAD_QUEUE = 8            # Problem validating output queue.
OFPBAC_BAD_OUT_GROUP = 9        # Invalid group id in forward action.
OFPBAC_MATCH_INCONSISTENT = 10  # Action can't apply for this match,
                                # or Set-Field missing prerequisite.
OFPBAC_UNSUPPORTED_ORDER = 11   # Action order is unsupported for
                                # the action list in an Apply-Actions
                                # instruction
OFPBAC_BAD_TAG = 12             # Actions uses an unsupported tag/encap.
OFPBAC_BAD_SET_TYPE = 13        # Unsupported type in SET_FIELD action.
OFPBAC_BAD_SET_LEN = 14         # Length problem in SET_FIELD action.
OFPBAC_BAD_SET_ARGUMENT = 15    # Bad arguement in SET_FIELD action.

# enum ofp_bad_instruction_code
OFPBIC_UNKNOWN_INST = 0         # Unknown instruction.
OFPBIC_UNSUP_INST = 1           # Switch or table does not support
                                # the instruction.
OFPBIC_BAD_TABLE_ID = 2         # Invalid Table-Id specified
OFPBIC_UNSUP_METADATA = 3       # Metadata value unsupported by datapath.
OFPBIC_UNSUP_METADATA_MASK = 4  # Metadata mask value unsupported by
                                # datapath.
OFPBIC_BAD_EXPERIMENTER = 5     # Unknown experimenter id specified.
OFPBIC_BAD_EXP_TYPE = 6         # Unknown instruction for experimenter id.
OFPBIC_BAD_LEN = 7              # Length problem in instrucitons.
OFPBIC_EPERM = 8                # Permissions error.
OFPBIC_DUP_INST = 9             # Duplicate instruction.

# enum ofp_bad_match_code
OFPBMC_BAD_TYPE = 0             # Unsupported match type apecified by
                                # the match.
OFPBMC_BAD_LEN = 1              # Length problem in math.
OFPBMC_BAD_TAG = 2              # Match uses an unsupported tag/encap.
OFPBMC_BAD_DL_ADDR_MASK = 3     # Unsupported datalink addr mask -
                                # switch does not support arbitrary
                                # datalink address mask.
OFPBMC_BAD_NW_ADDR_MASK = 4     # Unsupported network addr mask -
                                # switch does not support arbitrary
                                # network addres mask.
OFPBMC_BAD_WILDCARDS = 5        # Unsupported combination of fields
                                # masked or omitted in the match.
OFPBMC_BAD_FIELD = 6            # Unsupported field type in the match.
OFPBMC_BAD_VALUE = 7            # Unsupported value in a match field.
OFPBMC_BAD_MASK = 8             # Unsupported mask specified in the
                                # match.
OFPBMC_BAD_PREREQ = 9           # A prerequisite was not met.
OFPBMC_DUP_FIELD = 10           # A field type was duplicated.
OFPBMC_EPERM = 11               # Permissions error.

# enum ofp_flow_mod_failed_code
OFPFMFC_UNKNOWN = 0         # Unspecified error.
OFPFMFC_TABLE_FULL = 1      # Flow not added because table was full.
OFPFMFC_BAD_TABLE_ID = 2    # Table does not exist
OFPFMFC_OVERLAP = 3         # Attempted to add overlapping flow with
                            # CHECK_OVERLAP flag set.
OFPFMFC_EPERM = 4           # Permissions error.
OFPFMFC_BAD_TIMEOUT = 5     # Flow not added because of unsupported
                            # idle/hard timeout.
OFPFMFC_BAD_COMMAND = 6     # Unsupported or unknown command.
OFPFMFC_BAD_FLAGS = 7       # Unsupported or unknown flags.
OFPFMFC_CANT_SYNC = 8       # Problem in table synchronisation.
OFPFMFC_BAD_PRIORITY = 9    # Unsupported priority value.

# enum ofp_group_mod_failed_code
OFPGMFC_GROUP_EXISTS = 0            # Group not added because a group ADD
                                    # attempted to replace an already-present
                                    # group.
OFPGMFC_INVALID_GROUP = 1           # Group not added because Group specified
                                    # is invalid.
OFPGMFC_WEIGHT_UNSUPPORTED = 2      # Switch does not support unequal load
                                    # sharing with select groups.
OFPGMFC_OUT_OF_GROUPS = 3           # The group table is full.
OFPGMFC_OUT_OF_BUCKETS = 4          # The maximum number of action buckets
                                    # for a group has been exceeded.
OFPGMFC_CHAINING_UNSUPPORTED = 5    # Switch does not support groups that
                                    # forward to groups.
OFPGMFC_WATCH_UNSUPPORTED = 6       # This group cannot watch the
                                    # watch_port or watch_group specified.
OFPGMFC_LOOP = 7                    # Group entry would cause a loop.
OFPGMFC_UNKNOWN_GROUP = 8           # Group not modified because a group MODIFY
                                    # attempted to modify a non-existent group.
OFPGMFC_CHAINED_GROUP = 9           # Group not deleted because another group
                                    # is forwarding to it.
OFPGMFC_BAD_TYPE = 10               # Unsupported or unknown group type.
OFPGMFC_BAD_COMMAND = 11            # Unsupported or unknown command.
OFPGMFC_BAD_BUCKET = 12             # Error in bucket.
OFPGMFC_BAD_WATCH = 13              # Error in watch port/group.
OFPGMFC_EPERM = 14                  # Permissions error.

# enum ofp_port_mod_failed_code
OFPPMFC_BAD_PORT = 0        # Specified port does not exist.
OFPPMFC_BAD_HW_ADDR = 1     # Specified hardware address does not match
                            # the port number.
OFPPMFC_BAD_CONFIG = 2      # Specified config is invalid.
OFPPMFC_BAD_ADVERTISE = 3   # Specified advertise is invalid.
OFPPMFC_EPERM = 4           # Permissions error.

# enum ofp_table_mod_failed_code
OFPTMFC_BAD_TABLE = 0       # Specified table does not exist.
OFPTMFC_BAD_CONFIG = 1      # Specified config is invalid.
OFPTMFC_EPERM = 2           # Permissions error

# enum ofp_queue_op_failed_code
OFPQOFC_BAD_PORT = 0        # Invalid port (or port does not exist).
OFPQOFC_BAD_QUEUE = 1       # Queue does not exist.
OFPQOFC_EPERM = 2           # Permissions error.

# enum ofp_switch_config_failed_code
OFPSCFC_BAD_FLAGS = 0       # Specified flags is invalid.
OFPSCFC_BAD_LEN = 1         # Specified len is invalid.
OFPSCFC_EPERM = 2           # Permissions error.

# enum ofp_role_request_failed_code
OFPRRFC_STALE = 0           # Stale Message: old generation_id.
OFPRRFC_UNSUP = 1           # Controller role change unsupported.
OFPRRFC_BAD_ROLE = 2        # Invalid role.

# enum ofp_meter_mod_failed_code
OFPMMFC_UNKNOWN = 0         # Unspecified error.
OFPMMFC_METER_EXISTS = 1    # Meter not added because a Meter ADD
                            # attempted to replace an existing Meter.
OFPMMFC_INVALID_METER = 2   # Meter not added because Meter specified
                            # is invalid.
OFPMMFC_UNKNOWN_METER = 3   # Meter not modified because a Meter MODIFY
                            # attempted to modify a non-existent Meter.
OFPMMFC_BAD_COMMAND = 4     # Unsupported or unknown command.
OFPMMFC_BAD_FLAGS = 5       # Flag configuration unsupported.
OFPMMFC_BAD_RATE = 6        # Rate unsupported.
OFPMMFC_BAD_BURST = 7       # Burst size unsupported.
OFPMMFC_BAD_BAND = 8        # Band unsupported.
OFPMMFC_BAD_BAND_VALUE = 9  # Band value unsupported.
OFPMMFC_OUT_OF_METERS = 10  # No more meters availabile.
OFPMMFC_OUT_OF_BANDS = 11   # The maximum number of properties for a
                            # meter has been exceeded.

# enum ofp_table_features_failed_code
OFPTFFC_BAD_TABLE = 0       # Specified table does not exist.
OFPTFFC_BAD_METADATA = 1    # Invalid metadata mask.
OFPTFFC_EPERM = 5           # Permissions error.

# enum ofp_bad_property_code
OFPBPC_BAD_TYPE = 0             # Unknown property type.
OFPBPC_BAD_LEN = 1              # Length problem in property.
OFPBPC_BAD_VALUE = 2            # Unsupported property value.
OFPBPC_TOO_MANY = 3             # Can't handle this many properties.
OFPBPC_DUP_TYPE = 4             # A property type was duplicated.
OFPBPC_BAD_EXPERIMENTER = 5     # Unknown experimenter id specified.
OFPBPC_BAD_EXP_TYPE = 6         # Unknown exp_type for experimenter id.
OFPBPC_BAD_EXP_VALUE = 7        # Unknown value for experimenter id.
OFPBPC_EPERM = 8                # Permissions error.

# enum ofp_async_config_failed_code
OFPACFC_INVALID = 0         # One mask is invalid.
OFPACFC_UNSUPPORTED = 1     # Requested configuration not supported.
OFPACFC_EPERM = 2           # Permissions error.

# enum ofp_flow_monitor_failed_code
OFPMOFC_UNKNOWN = 0             # Unspecified error.
OFPMOFC_MONITOR_EXISTS = 1      # Monitor not added because a Monitor ADD
                                # attempted to replace an existing
                                # Monitor.
OFPMOFC_INVALID_MONITOR = 2     # Monitor not added because Monitor
                                # specified is invalid.
OFPMOFC_UNKNOWN_MONITOR = 3     # Monitor not modified because a Monitor
                                # MODIFY attempted to modify a non-existent
                                #  Monitor.
OFPMOFC_BAD_COMMAND = 4         # Unsupported or unknown command.
OFPMOFC_BAD_FLAGS = 5           # Flag configuration unsupported.
OFPMOFC_BAD_TABLE_ID = 6        # Specified table does not exist.
OFPMOFC_BAD_OUT = 7             # Error in output port/group.

# enum ofp_bundle_failed_code
OFPBFC_UNKNOWN = 0              # Unspecified error.
OFPBFC_EPERM = 1                # Permissions error.
OFPBFC_BAD_ID = 2               # Bundle ID doesn't exist.
OFPBFC_BUNDLE_EXIST = 3         # Bundle ID already exist.
OFPBFC_BUNDLE_CLOSED = 4        # Bundle ID is closed.
OFPBFC_OUT_OF_BUNDLES = 5       # Too many bundles IDs.
OFPBFC_BAD_TYPE = 6             # Unsupported or unknown message control type.
OFPBFC_BAD_FLAGS = 7            # Unsupported, unknown, or inconsistent flags.
OFPBFC_MSG_BAD_LEN = 8          # Length problem in included message.
OFPBFC_MSG_BAD_XID = 9          # Inconsistent or duplicate XID.
OFPBFC_MSG_UNSUP = 10           # Unsupported message in this bundle.
OFPBFC_MSG_CONFLICT = 11        # Unsupported message combination in this
                                # bundle.
OFPBFC_MSG_TOO_MANY = 12        # Can't handle this many messages in bundle.
OFPBFC_MSG_FAILED = 13          # One message in bundle failed.
OFPBFC_TIMEOUT = 14             # Bundle is taking too long.
OFPBFC_BUNDLE_IN_PROGRESS = 15  # Bundle is locking the resource.

# struct ofp_error_msg
OFP_ERROR_MSG_PACK_STR = '!HH'
OFP_ERROR_MSG_SIZE = 12
assert (calcsize(OFP_ERROR_MSG_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_ERROR_MSG_SIZE)

# struct ofp_error_experimenter_msg
OFP_ERROR_EXPERIMENTER_MSG_PACK_STR = '!HHI'
OFP_ERROR_EXPERIMENTER_MSG_SIZE = 16
assert (calcsize(OFP_ERROR_EXPERIMENTER_MSG_PACK_STR) +
        OFP_HEADER_SIZE) == OFP_ERROR_EXPERIMENTER_MSG_SIZE

# struct ofp_experimenter_header
OFP_EXPERIMENTER_HEADER_PACK_STR = '!II'
OFP_EXPERIMENTER_HEADER_SIZE = 16
assert (calcsize(OFP_EXPERIMENTER_HEADER_PACK_STR) + OFP_HEADER_SIZE
        == OFP_EXPERIMENTER_HEADER_SIZE)

# enum ofp_multipart_type
OFPMP_DESC = 0
OFPMP_FLOW = 1
OFPMP_AGGREGATE = 2
OFPMP_TABLE = 3
OFPMP_PORT_STATS = 4
OFPMP_QUEUE_STATS = 5
OFPMP_GROUP = 6
OFPMP_GROUP_DESC = 7
OFPMP_GROUP_FEATURES = 8
OFPMP_METER = 9
OFPMP_METER_CONFIG = 10
OFPMP_METER_FEATURES = 11
OFPMP_TABLE_FEATURES = 12
OFPMP_PORT_DESC = 13
OFPMP_TABLE_DESC = 14
OFPMP_QUEUE_DESC = 15
OFPMP_FLOW_MONITOR = 16
OFPMP_EXPERIMENTER = 0xffff

# struct ofp_multipart_request
OFP_MULTIPART_REQUEST_PACK_STR = '!HH4x'
OFP_MULTIPART_REQUEST_SIZE = 16
assert (calcsize(OFP_MULTIPART_REQUEST_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_MULTIPART_REQUEST_SIZE)

# enum ofp_multipart_reply_flags
OFPMPF_REPLY_MORE = 1 << 0  # More requests to follow.

# struct ofp_multipart_reply
OFP_MULTIPART_REPLY_PACK_STR = '!HH4x'
OFP_MULTIPART_REPLY_SIZE = 16
assert (calcsize(OFP_MULTIPART_REPLY_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_MULTIPART_REPLY_SIZE)

DESC_STR_LEN = 256
DESC_STR_LEN_STR = str(DESC_STR_LEN)
SERIAL_NUM_LEN = 32
SERIAL_NUM_LEN_STR = str(SERIAL_NUM_LEN)
OFP_DESC_PACK_STR = '!' + \
                    DESC_STR_LEN_STR + 's' + \
                    DESC_STR_LEN_STR + 's' + \
                    DESC_STR_LEN_STR + 's' + \
                    SERIAL_NUM_LEN_STR + 's' + \
                    DESC_STR_LEN_STR + 's'
OFP_DESC_SIZE = 1056
assert calcsize(OFP_DESC_PACK_STR) == OFP_DESC_SIZE

# struct ofp_flow_stats_request
_OFP_FLOW_STATS_REQUEST_0_PACK_STR = 'B3xII4xQQ'
OFP_FLOW_STATS_REQUEST_0_PACK_STR = '!' + _OFP_FLOW_STATS_REQUEST_0_PACK_STR
OFP_FLOW_STATS_REQUEST_0_SIZE = 32
assert (calcsize(OFP_FLOW_STATS_REQUEST_0_PACK_STR) ==
        OFP_FLOW_STATS_REQUEST_0_SIZE)
OFP_FLOW_STATS_REQUEST_PACK_STR = (OFP_FLOW_STATS_REQUEST_0_PACK_STR +
                                   _OFP_MATCH_PACK_STR)
OFP_FLOW_STATS_REQUEST_SIZE = 40
assert (calcsize(OFP_FLOW_STATS_REQUEST_PACK_STR) ==
        OFP_FLOW_STATS_REQUEST_SIZE)

# struct ofp_flow_stats
_OFP_FLOW_STATS_0_PACK_STR = 'HBxIIHHHHH2xQQQ'
OFP_FLOW_STATS_0_PACK_STR = '!' + _OFP_FLOW_STATS_0_PACK_STR
OFP_FLOW_STATS_0_SIZE = 48
assert calcsize(OFP_FLOW_STATS_0_PACK_STR) == OFP_FLOW_STATS_0_SIZE
OFP_FLOW_STATS_PACK_STR = (OFP_FLOW_STATS_0_PACK_STR +
                           _OFP_MATCH_PACK_STR)
OFP_FLOW_STATS_SIZE = 56
assert calcsize(OFP_FLOW_STATS_PACK_STR) == OFP_FLOW_STATS_SIZE

# struct ofp_aggregate_stats_request
OFP_AGGREGATE_STATS_REQUEST_PACK_STR = '!B3xII4xQQ' + _OFP_MATCH_PACK_STR
OFP_AGGREGATE_STATS_REQUEST_SIZE = 40
assert (calcsize(OFP_AGGREGATE_STATS_REQUEST_PACK_STR) ==
        OFP_AGGREGATE_STATS_REQUEST_SIZE)

# struct ofp_aggregate_stats_reply
OFP_AGGREGATE_STATS_REPLY_PACK_STR = '!QQI4x'
OFP_AGGREGATE_STATS_REPLY_SIZE = 24
assert (calcsize(OFP_AGGREGATE_STATS_REPLY_PACK_STR) ==
        OFP_AGGREGATE_STATS_REPLY_SIZE)


# enum ofp_table_feature_prop_type
OFPTFPT_INSTRUCTIONS = 0
OFPTFPT_INSTRUCTIONS_MISS = 1
OFPTFPT_NEXT_TABLES = 2
OFPTFPT_NEXT_TABLES_MISS = 3
OFPTFPT_WRITE_ACTIONS = 4
OFPTFPT_WRITE_ACTIONS_MISS = 5
OFPTFPT_APPLY_ACTIONS = 6
OFPTFPT_APPLY_ACTIONS_MISS = 7
OFPTFPT_MATCH = 8
OFPTFPT_WILDCARDS = 10
OFPTFPT_WRITE_SETFIELD = 12
OFPTFPT_WRITE_SETFIELD_MISS = 13
OFPTFPT_APPLY_SETFIELD = 14
OFPTFPT_APPLY_SETFIELD_MISS = 15
OFPTFPT_TABLE_SYNC_FROM = 16
OFPTFPT_EXPERIMENTER = 0xFFFE
OFPTFPT_EXPERIMENTER_MISS = 0xFFFF

# struct ofp_instruction_id
OFP_INSTRUCTION_ID_PACK_STR = '!HH'
OFP_INSTRUCTION_ID_SIZE = 4
assert calcsize(OFP_INSTRUCTION_ID_PACK_STR) == OFP_INSTRUCTION_ID_SIZE

# struct ofp_table_feature_prop_instructions
OFP_TABLE_FEATURE_PROP_INSTRUCTIONS_PACK_STR = '!HH'
OFP_TABLE_FEATURE_PROP_INSTRUCTIONS_SIZE = 4
assert (calcsize(OFP_TABLE_FEATURE_PROP_INSTRUCTIONS_PACK_STR) ==
        OFP_TABLE_FEATURE_PROP_INSTRUCTIONS_SIZE)

# struct ofp_table_feature_prop_actions
OFP_TABLE_FEATURE_PROP_ACTIONS_PACK_STR = '!HH'
OFP_TABLE_FEATURE_PROP_ACTIONS_SIZE = 4
assert (calcsize(OFP_TABLE_FEATURE_PROP_ACTIONS_PACK_STR) ==
        OFP_TABLE_FEATURE_PROP_ACTIONS_SIZE)

# struct ofp_table_feature_prop_oxm
OFP_TABLE_FEATURE_PROP_OXM_PACK_STR = '!HH'
OFP_TABLE_FEATURE_PROP_OXM_SIZE = 4
assert (calcsize(OFP_TABLE_FEATURE_PROP_OXM_PACK_STR) ==
        OFP_TABLE_FEATURE_PROP_OXM_SIZE)

# struct ofp_table_feature_prop_experimenter
OFP_TABLE_FEATURE_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_TABLE_FEATURE_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_TABLE_FEATURE_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_TABLE_FEATURE_PROP_EXPERIMENTER_SIZE)


# struct ofp_table_features
OFP_MAX_TABLE_NAME_LEN = 32
OFP_MAX_TABLE_NAME_LEN_STR = str(OFP_MAX_TABLE_NAME_LEN)
OFP_TABLE_FEATURES_PACK_STR = '!HB5x' + OFP_MAX_TABLE_NAME_LEN_STR + \
                              's' + 'QQII'
OFP_TABLE_FEATURES_SIZE = 64
assert (calcsize(OFP_TABLE_FEATURES_PACK_STR) ==
        OFP_TABLE_FEATURES_SIZE)

# struct ofp_table_stats
OFP_TABLE_STATS_PACK_STR = '!B3xIQQ'
OFP_TABLE_STATS_SIZE = 24
assert calcsize(OFP_TABLE_STATS_PACK_STR) == OFP_TABLE_STATS_SIZE

# struct ofp_table_desc
_OFP_TABLE_DESC_PACK_STR = 'HBxI'
OFP_TABLE_DESC_PACK_STR = '!' + _OFP_TABLE_DESC_PACK_STR
OFP_TABLE_DESC_SIZE = 8
assert calcsize(OFP_TABLE_DESC_PACK_STR) == OFP_TABLE_DESC_SIZE

# struct ofp_port_stats_request
OFP_PORT_STATS_REQUEST_PACK_STR = '!I4x'
OFP_PORT_STATS_REQUEST_SIZE = 8
assert (calcsize(OFP_PORT_STATS_REQUEST_PACK_STR) ==
        OFP_PORT_STATS_REQUEST_SIZE)

# enum ofp_port_stats_prop_type
OFPPSPT_ETHERNET = 0            # Ethernet property.
OFPPSPT_OPTICAL = 1             # Optical property.
OFPPSPT_EXPERIMENTER = 0xFFFF   # Experimenter property.

# struct ofp_port_stats_prop_ethernet
OFP_PORT_STATS_PROP_ETHERNET_PACK_STR = '!HH4xQQQQ'
OFP_PORT_STATS_PROP_ETHERNET_SIZE = 40
assert (calcsize(OFP_PORT_STATS_PROP_ETHERNET_PACK_STR) ==
        OFP_PORT_STATS_PROP_ETHERNET_SIZE)

# struct ofp_port_stats_prop_optical
OFP_PORT_STATS_PROP_OPTICAL_PACK_STR = '!HH4xIIIIIIIHHHH'
OFP_PORT_STATS_PROP_OPTICAL_SIZE = 44
assert (calcsize(OFP_PORT_STATS_PROP_OPTICAL_PACK_STR) ==
        OFP_PORT_STATS_PROP_OPTICAL_SIZE)

# enum ofp_port_stats_optical_flags
OFPOSF_RX_TUNE = 1 << 0     # Receiver tune info valid
OFPOSF_TX_TUNE = 1 << 1     # Transmit tune info valid
OFPOSF_TX_PWR = 1 << 2      # TX Power is valid
OFPOSF_RX_PWR = 1 << 4      # RX power is valid
OFPOSF_TX_BIAS = 1 << 5     # Transmit bias is valid
OFPOSF_TX_TEMP = 1 << 6     # TX Temp is valid

# struct ofp_port_stats_prop_experimenter
OFP_PORT_STATS_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_PORT_STATS_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_PORT_STATS_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_PORT_STATS_PROP_EXPERIMENTER_SIZE)

# struct ofp_port_stats
OFP_PORT_STATS_PACK_STR = '!H2xIIIQQQQQQQQ'
OFP_PORT_STATS_SIZE = 80
assert calcsize(OFP_PORT_STATS_PACK_STR) == OFP_PORT_STATS_SIZE

# struct ofp_group_stats_request
OFP_GROUP_STATS_REQUEST_PACK_STR = '!I4x'
OFP_GROUP_STATS_REQUEST_SIZE = 8
assert (calcsize(OFP_GROUP_STATS_REQUEST_PACK_STR) ==
        OFP_GROUP_STATS_REQUEST_SIZE)

# struct ofp_bucket_counter
OFP_BUCKET_COUNTER_PACK_STR = '!QQ'
OFP_BUCKET_COUNTER_SIZE = 16
assert calcsize(OFP_BUCKET_COUNTER_PACK_STR) == OFP_BUCKET_COUNTER_SIZE

# struct ofp_group_stats
OFP_GROUP_STATS_PACK_STR = '!H2xII4xQQII'
OFP_GROUP_STATS_SIZE = 40
assert calcsize(OFP_GROUP_STATS_PACK_STR) == OFP_GROUP_STATS_SIZE

# struct ofp_group_desc
OFP_GROUP_DESC_PACK_STR = '!HBxI'
OFP_GROUP_DESC_SIZE = 8
assert calcsize(OFP_GROUP_DESC_PACK_STR) == OFP_GROUP_DESC_SIZE

# struct ofp_group_desc_stats
# Backward compatibility with 1.3.1 - avoid breaking the API.
OFP_GROUP_DESC_STATS_PACK_STR = OFP_GROUP_DESC_PACK_STR
OFP_GROUP_DESC_STATS_SIZE = OFP_GROUP_DESC_SIZE
assert calcsize(OFP_GROUP_DESC_STATS_PACK_STR) == OFP_GROUP_DESC_STATS_SIZE

# enum ofp_group_capabilities
OFPGFC_SELECT_WEIGHT = 1 << 0       # Support weight for select groups.
OFPGFC_SELECT_LIVENESS = 1 << 1     # Support liveness for select groups.
OFPGFC_CHAINING = 1 << 2            # Support chaining groups.
OFPGFC_CHAINING_CHECKS = 1 << 3     # Check chaining for loops and delete

# struct ofp_group_features
OFP_GROUP_FEATURES_PACK_STR = '!II4I4I'
OFP_GROUP_FEATURES_SIZE = 40
assert calcsize(OFP_GROUP_FEATURES_PACK_STR) == OFP_GROUP_FEATURES_SIZE

# struct ofp_meter_multipart_request
OFP_METER_MULTIPART_REQUEST_PACK_STR = '!I4x'
OFP_METER_MULTIPART_REQUEST_SIZE = 8
assert (calcsize(OFP_METER_MULTIPART_REQUEST_PACK_STR) ==
        OFP_METER_MULTIPART_REQUEST_SIZE)

# struct ofp_meter_stats
OFP_METER_STATS_PACK_STR = '!IH6xIQQII'
OFP_METER_STATS_SIZE = 40
assert calcsize(OFP_METER_STATS_PACK_STR) == OFP_METER_STATS_SIZE

# struct ofp_meter_band_stats
OFP_METER_BAND_STATS_PACK_STR = '!QQ'
OFP_METER_BAND_STATS_SIZE = 16
assert (calcsize(OFP_METER_BAND_STATS_PACK_STR) ==
        OFP_METER_BAND_STATS_SIZE)

# struct ofp_meter_config
OFP_METER_CONFIG_PACK_STR = '!HHI'
OFP_METER_CONFIG_SIZE = 8
assert calcsize(OFP_METER_CONFIG_PACK_STR) == OFP_METER_CONFIG_SIZE

# struct ofp_meter_features
OFP_METER_FEATURES_PACK_STR = '!IIIBB2x'
OFP_METER_FEATURES_SIZE = 16
assert (calcsize(OFP_METER_FEATURES_PACK_STR) ==
        OFP_METER_FEATURES_SIZE)

# All ones is used to indicate all queues in a port (for stats retrieval).
OFPQ_ALL = 0xffffffff

# Min rate > 1000 means not configured.
OFPQ_MIN_RATE_UNCFG = 0xffff

# Max rate > 1000 means not configured.
OFPQ_MAX_RATE_UNCFG = 0xffff

# enum ofp_queue_desc_prop_type
OFPQDPT_MIN_RATE = 1            # Minimum datarate guaranteed.
OFPQDPT_MAX_RATE = 2            # Maximum datarate.
OFPQDPT_EXPERIMENTER = 0xffff   # Experimenter defined property.

# struct ofp_queue_desc_prop_min_rate
OFP_QUEUE_DESC_PROP_MIN_RATE_PACK_STR = '!HHH2x'
OFP_QUEUE_DESC_PROP_MIN_RATE_SIZE = 8
assert (calcsize(OFP_QUEUE_DESC_PROP_MIN_RATE_PACK_STR) ==
        OFP_QUEUE_DESC_PROP_MIN_RATE_SIZE)

# ofp_queue_desc_prop_max_rate
OFP_QUEUE_DESC_PROP_MAX_RATE_PACK_STR = '!HHH2x'
OFP_QUEUE_DESC_PROP_MAX_RATE_SIZE = 8
assert (calcsize(OFP_QUEUE_DESC_PROP_MAX_RATE_PACK_STR) ==
        OFP_QUEUE_DESC_PROP_MAX_RATE_SIZE)

# struct ofp_queue_desc_prop_experimenter
OFP_QUEUE_DESC_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_QUEUE_DESC_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_QUEUE_DESC_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_QUEUE_DESC_PROP_EXPERIMENTER_SIZE)

# struct ofp_queue_desc_request
OFP_QUEUE_DESC_REQUEST_PACK_STR = '!II'
OFP_QUEUE_DESC_REQUEST_SIZE = 8
assert (calcsize(OFP_QUEUE_DESC_REQUEST_PACK_STR) ==
        OFP_QUEUE_DESC_REQUEST_SIZE)

# struct ofp_queue_desc
OFP_QUEUE_DESC_PACK_STR = '!IIH6x'
OFP_QUEUE_DESC_SIZE = 16
assert calcsize(OFP_QUEUE_DESC_PACK_STR) == OFP_QUEUE_DESC_SIZE

# struct ofp_queue_stats_request
OFP_QUEUE_STATS_REQUEST_PACK_STR = '!II'
OFP_QUEUE_STATS_REQUEST_SIZE = 8
assert (calcsize(OFP_QUEUE_STATS_REQUEST_PACK_STR) ==
        OFP_QUEUE_STATS_REQUEST_SIZE)

# enum ofp_queue_stats_prop_type
OFPQSPT_EXPERIMENTER = 0xffff   # Experimenter defined property.

# struct ofp_queue_stats_prop_experimenter
OFP_QUEUE_STATS_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_QUEUE_STATS_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_QUEUE_STATS_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_QUEUE_STATS_PROP_EXPERIMENTER_SIZE)

# struct ofp_queue_stats
OFP_QUEUE_STATS_PACK_STR = '!H6xIIQQQII'
OFP_QUEUE_STATS_SIZE = 48
assert calcsize(OFP_QUEUE_STATS_PACK_STR) == OFP_QUEUE_STATS_SIZE

# struct ofp_flow_monitor_request
_OFP_FLOW_MONITOR_REQUEST_0_PACK_STR = 'IIIHBB'
OFP_FLOW_MONITOR_REQUEST_0_PACK_STR = ('!' +
                                       _OFP_FLOW_MONITOR_REQUEST_0_PACK_STR)
OFP_FLOW_MONITOR_REQUEST_0_SIZE = 16
OFP_FLOW_MONITOR_REQUEST_PACK_STR = (OFP_FLOW_MONITOR_REQUEST_0_PACK_STR +
                                     _OFP_MATCH_PACK_STR)
OFP_FLOW_MONITOR_REQUEST_SIZE = 24
assert (calcsize(OFP_FLOW_MONITOR_REQUEST_PACK_STR) ==
        OFP_FLOW_MONITOR_REQUEST_SIZE)

# enum ofp_flow_monitor_command
OFPFMC_ADD = 0      # New flow monitor.
OFPFMC_MODIFY = 1   # Modify existing flow monitor.
OFPFMC_DELETE = 2   # Delete/cancel existing flow monitor.

# enum ofp_flow_monitor_flags
# When to send updates.
OFPFMF_INITIAL = 1 << 0         # Initially matching flows.
OFPFMF_ADD = 1 << 1             # New matching flows as they are added.
OFPFMF_REMOVED = 1 << 2         # Old matching flows as they are removed.
OFPFMF_MODIFY = 1 << 3          # Matching flows as they are changed.
# What to include in updates.
OFPFMF_INSTRUCTIONS = 1 << 4    # If set, instructions are included.
OFPFMF_NO_ABBREV = 1 << 5       # If set, include own changes in full.
OFPFMF_ONLY_OWN = 1 << 6        # If set, don't include other controllers.

# struct ofp_flow_update_header
OFP_FLOW_UPDATE_HEADER_PACK_STR = '!HH'
OFP_FLOW_UPDATE_HEADER_SIZE = 4
assert (calcsize(OFP_FLOW_UPDATE_HEADER_PACK_STR) ==
        OFP_FLOW_UPDATE_HEADER_SIZE)

# enum ofp_flow_update_event
# struct ofp_flow_update_full.
OFPFME_INITIAL = 0      # Flow present when flow monitor created.
OFPFME_ADDED = 1        # Flow was added.
OFPFME_REMOVED = 2      # Flow was removed.
OFPFME_MODIFIED = 3     # Flow instructions were changed.
# struct ofp_flow_update_abbrev.
OFPFME_ABBREV = 4       # Abbreviated reply.
# struct ofp_flow_update_header.
OFPFME_PAUSED = 5       # Monitoring paused (out of buffer space).
OFPFME_RESUMED = 6      # Monitoring resumed.

# struct ofp_flow_update_full
_OFP_FLOW_UPDATE_FULL_0_PACK_STR = 'HHBBHHH4xQ'
OFP_FLOW_UPDATE_FULL_0_PACK_STR = '!' + _OFP_FLOW_UPDATE_FULL_0_PACK_STR
OFP_FLOW_UPDATE_FULL_0_SIZE = 24
OFP_FLOW_UPDATE_FULL_PACK_STR = (OFP_FLOW_UPDATE_FULL_0_PACK_STR +
                                 _OFP_MATCH_PACK_STR)
OFP_FLOW_UPDATE_FULL_SIZE = 32
assert (calcsize(OFP_FLOW_UPDATE_FULL_PACK_STR) ==
        OFP_FLOW_UPDATE_FULL_SIZE)

# struct ofp_flow_update_abbrev
OFP_FLOW_UPDATE_ABBREV_PACK_STR = '!HHI'
OFP_FLOW_UPDATE_ABBREV_SIZE = 8
assert (calcsize(OFP_FLOW_UPDATE_ABBREV_PACK_STR) ==
        OFP_FLOW_UPDATE_ABBREV_SIZE)

# struct ofp_flow_update_paused
OFP_FLOW_UPDATE_PAUSED_PACK_STR = '!HH4x'
OFP_FLOW_UPDATE_PAUSED_SIZE = 8
assert (calcsize(OFP_FLOW_UPDATE_PAUSED_PACK_STR) ==
        OFP_FLOW_UPDATE_PAUSED_SIZE)

# struct ofp_experimenter_multipart_header
OFP_EXPERIMENTER_MULTIPART_HEADER_PACK_STR = '!II'
OFP_EXPERIMENTER_MULTIPART_HEADER_SIZE = 8
assert (calcsize(OFP_EXPERIMENTER_MULTIPART_HEADER_PACK_STR) ==
        OFP_EXPERIMENTER_MULTIPART_HEADER_SIZE)

# struct ofp_experimenter_structure
OFP_EXPERIMENTER_STRUCTURE_PACK_STR = '!II'
OFP_EXPERIMENTER_STRUCTURE_SIZE = 8
assert (calcsize(OFP_EXPERIMENTER_STRUCTURE_PACK_STR) ==
        OFP_EXPERIMENTER_STRUCTURE_SIZE)

# struct ofp_error_experimenter_msg
OFP_ERROR_EXPERIMENTER_MSG_PACK_STR = '!HHI'
OFP_ERROR_EXPERIMENTER_MSG_SIZE = 16
assert (calcsize(OFP_ERROR_EXPERIMENTER_MSG_PACK_STR) +
        OFP_HEADER_SIZE) == OFP_ERROR_EXPERIMENTER_MSG_SIZE

# enum ofp_controller_role
OFPCR_ROLE_NOCHANGE = 0     # Don't change current role.
OFPCR_ROLE_EQUAL = 1        # Default role, full access.
OFPCR_ROLE_MASTER = 2       # Full access, at most one master.
OFPCR_ROLE_SLAVE = 3        # Read-only access.

# struct ofp_role_request
OFP_ROLE_REQUEST_PACK_STR = '!I4xQ'
OFP_ROLE_REQUEST_SIZE = 24
assert (calcsize(OFP_ROLE_REQUEST_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_ROLE_REQUEST_SIZE)

# enum ofp_role_prop_type
OFPRPT_EXPERIMENTER = 0xFFFF    # Experimenter property.

# struct ofp_role_prop_experimenter
OFP_ROLE_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_ROLE_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_ROLE_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_ROLE_PROP_EXPERIMENTER_SIZE)

# enum ofp_controller_role_reason
OFPCRR_MASTER_REQUEST = 0   # Another controller asked to be master.
OFPCRR_CONFIG = 1           # Configuration changed on the switch.
OFPCRR_EXPERIMENTER = 2     # Experimenter data changed.

# struct ofp_role_status
OFP_ROLE_STATUS_PACK_STR = '!IB3xQ'
OFP_ROLE_STATUS_SIZE = 24
assert (calcsize(OFP_ROLE_STATUS_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_ROLE_STATUS_SIZE)

# enum ofp_async_config_prop_type
OFPACPT_PACKET_IN_SLAVE = 0             # Packet-in mask for slave.
OFPACPT_PACKET_IN_MASTER = 1            # Packet-in mask for master.
OFPACPT_PORT_STATUS_SLAVE = 2           # Port-status mask for slave.
OFPACPT_PORT_STATUS_MASTER = 3          # Port-status mask for master.
OFPACPT_FLOW_REMOVED_SLAVE = 4          # Flow removed mask for slave.
OFPACPT_FLOW_REMOVED_MASTER = 5         # Flow removed mask for master.
OFPACPT_ROLE_STATUS_SLAVE = 6           # Role status mask for slave.
OFPACPT_ROLE_STATUS_MASTER = 7          # Role status mask for master.
OFPACPT_TABLE_STATUS_SLAVE = 8          # Table status mask for slave.
OFPACPT_TABLE_STATUS_MASTER = 9         # Table status mask for master.
OFPACPT_REQUESTFORWARD_SLAVE = 10       # RequestForward mask for slave.
OFPACPT_REQUESTFORWARD_MASTER = 11      # RequestForward mask for master.
OFPTFPT_EXPERIMENTER_SLAVE = 0xFFFE     # Experimenter for slave (depracated).
OFPTFPT_EXPERIMENTER_MASTER = 0xFFFF    # Experimenter for master (depracated).
                                        # New or updated Ryu applications shall use
                                        # OFPACPT_EXPERIMENTER_SLAVE and OFPACPT_EXPERIMENTER_MASTER.
                                        # The variable name is a typo of in specifications before v1.5.0.
OFPACPT_EXPERIMENTER_SLAVE = 0xFFFE     # Experimenter for slave.
OFPACPT_EXPERIMENTER_MASTER = 0xFFFF    # Experimenter for master.
                                        # Backporting from ofproto_v1_5 for consistency with
                                        # later OF specs.

# struct ofp_async_config_prop_reasons
OFP_ASYNC_CONFIG_PROP_REASONS_PACK_STR = '!HHI'
OFP_ASYNC_CONFIG_PROP_REASONS_SIZE = 8
assert (calcsize(OFP_ASYNC_CONFIG_PROP_REASONS_PACK_STR) ==
        OFP_ASYNC_CONFIG_PROP_REASONS_SIZE)

# struct ofp_async_config_prop_experimenter
OFP_ASYNC_CONFIG_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_ASYNC_CONFIG_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_ASYNC_CONFIG_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_ASYNC_CONFIG_PROP_EXPERIMENTER_SIZE)

# enum ofp_table_reason
OFPTR_VACANCY_DOWN = 3  # Vacancy down threshold event.
OFPTR_VACANCY_UP = 4    # Vacancy up threshold event.

# struct ofp_table_status
_OFP_TABLE_STATUS_0_PACK_STR = 'B7x'
OFP_TABLE_STATUS_0_PACK_STR = '!' + _OFP_TABLE_STATUS_0_PACK_STR
OFP_TABLE_STATUS_0_SIZE = 16
OFP_TABLE_STATUS_PACK_STR = (OFP_TABLE_STATUS_0_PACK_STR +
                             _OFP_TABLE_DESC_PACK_STR)
OFP_TABLE_STATUS_SIZE = 24
assert (calcsize(OFP_TABLE_STATUS_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_TABLE_STATUS_SIZE)

# enum ofp_requestforward_reason
OFPRFR_GROUP_MOD = 0    # Forward group mod requests.
OFPRFR_METER_MOD = 1    # Forward meter mod requests.

# enum ofp_bundle_prop_type
OFPBPT_EXPERIMENTER = 0xFFFF    # Experimenter property.

# struct ofp_bundle_prop_experimenter
OFP_BUNDLE_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_BUNDLE_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_BUNDLE_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_BUNDLE_PROP_EXPERIMENTER_SIZE)

# enum ofp_bundle_ctrl_type
OFPBCT_OPEN_REQUEST = 0
OFPBCT_OPEN_REPLY = 1
OFPBCT_CLOSE_REQUEST = 2
OFPBCT_CLOSE_REPLY = 3
OFPBCT_COMMIT_REQUEST = 4
OFPBCT_COMMIT_REPLY = 5
OFPBCT_DISCARD_REQUEST = 6
OFPBCT_DISCARD_REPLY = 7

# enum ofp_bundle_flags
OFPBF_ATOMIC = 1 << 0   # Execute atomically.
OFPBF_ORDERED = 1 << 1  # Execute in specified order.

# struct ofp_bundle_ctrl_msg
OFP_BUNDLE_CTRL_MSG_PACK_STR = '!IHH'
OFP_BUNDLE_CTRL_MSG_SIZE = 16
assert (calcsize(OFP_BUNDLE_CTRL_MSG_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_BUNDLE_CTRL_MSG_SIZE)

# struct ofp_bundle_add_msg
_OFP_BUNDLE_ADD_MSG_0_PACK_STR = 'I2xH'
OFP_BUNDLE_ADD_MSG_0_PACK_STR = '!' + _OFP_BUNDLE_ADD_MSG_0_PACK_STR
OFP_BUNDLE_ADD_MSG_PACK_STR = (OFP_BUNDLE_ADD_MSG_0_PACK_STR +
                               _OFP_HEADER_PACK_STR)
OFP_BUNDLE_ADD_MSG_SIZE = 24
assert (calcsize(OFP_BUNDLE_ADD_MSG_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_BUNDLE_ADD_MSG_SIZE)

# Note: struct ofp_prop_experimenter is specific to this implementation.
# It does not have a corresponding structure in the specification.
# This structure defines common structure for ofp_*_prop_experimenter.
# struct ofp_prop_experimenter
OFP_PROP_EXPERIMENTER_PACK_STR = '!HHII'
OFP_PROP_EXPERIMENTER_SIZE = 12
assert (calcsize(OFP_PROP_EXPERIMENTER_PACK_STR) ==
        OFP_PROP_EXPERIMENTER_SIZE)

# generate utility methods
ofproto_utils.generate(__name__)

# define constants
OFP_VERSION = 0x05
OFP_TCP_PORT = 6653
OFP_SSL_PORT = 6653
MAX_XID = 0xffffffff
