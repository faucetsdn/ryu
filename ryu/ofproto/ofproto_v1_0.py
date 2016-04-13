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

"""
OpenFlow 1.0 definitions.
"""

from struct import calcsize

from ryu.ofproto import ofproto_utils


MAX_XID = 0xffffffff

# define constants
OFP_VERSION = 0x01
OFP_MAX_TABLE_NAME_LEN = 32
OFP_MAX_TABLE_NAME_LEN_STR = str(OFP_MAX_TABLE_NAME_LEN)
OFP_MAX_PORT_NAME_LEN = 16
OFP_TCP_PORT = 6633
OFP_SSL_PORT = 6633
OFP_ETH_ALEN = 6
OFP_ETH_ALEN_STR = str(OFP_ETH_ALEN)

OFP_NO_BUFFER = 0xffffffff

# enum ofp_port
OFPP_MAX = 0xff00
OFPP_IN_PORT = 0xfff8   # Send the packet out the input port. This
                        # virtual port must be explicitly used
                        # in order to send back out of the input
                        # port.
OFPP_TABLE = 0xfff9     # Perform actions in flow table.
                        # NB: This can only be the destination
                        # port for packet-out messages.
OFPP_NORMAL = 0xfffa    # Process with normal L2/L3 switching.
OFPP_FLOOD = 0xfffb     # All physical ports except input port and
                        # those disabled by STP.
OFPP_ALL = 0xfffc       # All physical ports except input port.
OFPP_CONTROLLER = 0xfffd        # Send to controller.
OFPP_LOCAL = 0xfffe     # Local openflow "port".
OFPP_NONE = 0xffff      # Not associated with a physical port.

# enum ofp_type
OFPT_HELLO = 0  # Symmetric message
OFPT_ERROR = 1  # Symmetric message
OFPT_ECHO_REQUEST = 2   # Symmetric message
OFPT_ECHO_REPLY = 3     # Symmetric message
OFPT_VENDOR = 4         # Symmetric message
OFPT_FEATURES_REQUEST = 5       # Controller/switch message
OFPT_FEATURES_REPLY = 6         # Controller/switch message
OFPT_GET_CONFIG_REQUEST = 7     # Controller/switch message
OFPT_GET_CONFIG_REPLY = 8       # Controller/switch message
OFPT_SET_CONFIG = 9      # Controller/switch message
OFPT_PACKET_IN = 10      # Async message
OFPT_FLOW_REMOVED = 11   # Async message
OFPT_PORT_STATUS = 12    # Async message
OFPT_PACKET_OUT = 13     # Controller/switch message
OFPT_FLOW_MOD = 14       # Controller/switch message
OFPT_PORT_MOD = 15       # Controller/switch message
OFPT_STATS_REQUEST = 16  # Controller/switch message
OFPT_STATS_REPLY = 17    # Controller/switch message
OFPT_BARRIER_REQUEST = 18       # Controller/switch message
OFPT_BARRIER_REPLY = 19  # Controller/switch message
OFPT_QUEUE_GET_CONFIG_REQUEST = 20      # Controller/switch message
OFPT_QUEUE_GET_CONFIG_REPLY = 21        # Controller/switch message

OFP_HEADER_PACK_STR = '!BBHI'
OFP_HEADER_SIZE = 8
OFP_MSG_SIZE_MAX = 65535
assert calcsize(OFP_HEADER_PACK_STR) == OFP_HEADER_SIZE

# define constants
OFP_DEFAULT_MISS_SEND_LEN = 128

# enum ofp_config_flags
OFPC_FRAG_NORMAL = 0    # No special handling for fragments.
OFPC_FRAG_DROP = 1      # Drop fragments.
OFPC_FRAG_REASM = 2     # Reassemble (only if OFPC_IP_REASM set).
OFPC_FRAG_NX_MATCH = 3  # Make first fragments available for matching.
OFPC_FRAG_MASK = 3

OFP_SWITCH_CONFIG_PACK_STR = '!HH'
OFP_SWITCH_CONFIG_SIZE = 12
assert (calcsize(OFP_SWITCH_CONFIG_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_SWITCH_CONFIG_SIZE)

# enum ofp_capabilities
OFPC_FLOW_STATS = 1 << 0        # Flow statistics.
OFPC_TABLE_STATS = 1 << 1       # Table statistics.
OFPC_PORT_STATS = 1 << 2        # Port statistics.
OFPC_STP = 1 << 3               # 802.1d spanning tree.
OFPC_RESERVED = 1 << 4          # Reserved, must not be set.
OFPC_IP_REASM = 1 << 5          # Can reassemble IP fragments.
OFPC_QUEUE_STATS = 1 << 6       # Queue statistics.
OFPC_ARP_MATCH_IP = 1 << 7      # Match IP addresses in ARP pkts.

# enum ofp_port_config
OFPPC_PORT_DOWN = 1 << 0        # Port is administratively down.
OFPPC_NO_STP = 1 << 1           # Disable 802.1D spanning tree on port.
OFPPC_NO_RECV = 1 << 2          # Drop all packets except 802.1D
                                # spanning tree packets
OFPPC_NO_RECV_STP = 1 << 3      # Drop received 802.1D STP packets.
OFPPC_NO_FLOOD = 1 << 4         # Do not include this port when flooding.
OFPPC_NO_FWD = 1 << 5           # Drop packets forwarded to port.
OFPPC_NO_PACKET_IN = 1 << 6     # Do not send packet-in msgs for port.

# enum ofp_port_state
OFPPS_LINK_DOWN = 1 << 0        # No physical link present.
OFPPS_STP_LISTEN = 0 << 8       # Not learning or relaying frames.
OFPPS_STP_LEARN = 1 << 8        # Learning but not relaying frames.
OFPPS_STP_FORWARD = 2 << 8      # Learning and relaying frames.
OFPPS_STP_BLOCK = 3 << 8        # Not part of spanning tree.
OFPPS_STP_MASK = 3 << 8         # Bit mask for OFPPS_STP_* values.

# enum ofp_port_features
OFPPF_10MB_HD = 1 << 0          # 10 Mb half-duplex rate support.
OFPPF_10MB_FD = 1 << 1          # 10 Mb full-duplex rate support.
OFPPF_100MB_HD = 1 << 2         # 100 Mb half-duplex rate support.
OFPPF_100MB_FD = 1 << 3         # 100 Mb full-duplex rate support.
OFPPF_1GB_HD = 1 << 4           # 1 Gb half-duplex rate support.
OFPPF_1GB_FD = 1 << 5           # 1 Gb full-duplex rate support.
OFPPF_10GB_FD = 1 << 6          # 10 Gb full-duplex rate support.
OFPPF_COPPER = 1 << 7           # Copper medium.
OFPPF_FIBER = 1 << 8            # Fiber medium.
OFPPF_AUTONEG = 1 << 9          # Auto-negotiation.
OFPPF_PAUSE = 1 << 10           # Pause.
OFPPF_PAUSE_ASYM = 1 << 11      # Asymmetric pause.

_OFP_PHY_PORT_PACK_STR = 'H' + OFP_ETH_ALEN_STR + 's' + \
                         str(OFP_MAX_PORT_NAME_LEN) + 'sIIIIII'
OFP_PHY_PORT_PACK_STR = '!' + _OFP_PHY_PORT_PACK_STR
OFP_PHY_PORT_SIZE = 48
assert calcsize(OFP_PHY_PORT_PACK_STR) == OFP_PHY_PORT_SIZE

OFP_SWITCH_FEATURES_PACK_STR = '!QIB3xII'
OFP_SWITCH_FEATURES_SIZE = 32
assert (calcsize(OFP_SWITCH_FEATURES_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_SWITCH_FEATURES_SIZE)

# enum ofp_port_reason
OFPPR_ADD = 0           # The port was added.
OFPPR_DELETE = 1        # The port was removed.
OFPPR_MODIFY = 2        # Some attribute of the port has changed.

OFP_PORT_STATUS_PACK_STR = '!B7x' + _OFP_PHY_PORT_PACK_STR
OFP_PORT_STATUS_DESC_OFFSET = OFP_HEADER_SIZE + 8
OFP_PORT_STATUS_SIZE = 64
assert (calcsize(OFP_PORT_STATUS_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PORT_STATUS_SIZE)

OFP_PORT_MOD_PACK_STR = '!H' + OFP_ETH_ALEN_STR + 'sIII4x'
OFP_PORT_MOD_SIZE = 32
assert calcsize(OFP_PORT_MOD_PACK_STR) + OFP_HEADER_SIZE == OFP_PORT_MOD_SIZE

# enum ofp_packet_in_reason
OFPR_NO_MATCH = 0       # No matching flow.
OFPR_ACTION = 1         # Action explicitly output to controller.

# OF1.0 spec says OFP_ASSERT(sizeof(struct ofp_packet_in) == 20).
# It's quite bogus as it assumes a specific class of C implementations.
# (well, if it was C.  it's unclear from the spec itself.)
# We just use the real size of the structure as this is not C.  This
# agrees with on-wire messages OpenFlow Reference Release and Open vSwitch
# produce.
OFP_PACKET_IN_PACK_STR = '!IHHBx'
OFP_PACKET_IN_SIZE = 18
assert calcsize(OFP_PACKET_IN_PACK_STR) + OFP_HEADER_SIZE == OFP_PACKET_IN_SIZE

# enum ofp_action_type
OFPAT_OUTPUT = 0        # Output to switch port.
OFPAT_SET_VLAN_VID = 1  # Set the 802.1q VLAN id.
OFPAT_SET_VLAN_PCP = 2  # Set the 802.1q priority.
OFPAT_STRIP_VLAN = 3    # Strip the 802.1q header.
OFPAT_SET_DL_SRC = 4    # Ethernet source address.
OFPAT_SET_DL_DST = 5    # Ethernet destination address.
OFPAT_SET_NW_SRC = 6    # IP source address.
OFPAT_SET_NW_DST = 7    # IP destination address.
OFPAT_SET_NW_TOS = 8    # IP ToS (DSCP field, 6 bits).
OFPAT_SET_TP_SRC = 9    # TCP/UDP source port.
OFPAT_SET_TP_DST = 10   # TCP/UDP destination port.
OFPAT_ENQUEUE = 11      # Output to queue.
OFPAT_VENDOR = 0xffff

OFP_ACTION_OUTPUT_PACK_STR = '!HHHH'
OFP_ACTION_OUTPUT_SIZE = 8
assert calcsize(OFP_ACTION_OUTPUT_PACK_STR) == OFP_ACTION_OUTPUT_SIZE

OFP_ACTION_VLAN_VID_PACK_STR = '!HHH2x'
OFP_ACTION_VLAN_VID_SIZE = 8
assert calcsize(OFP_ACTION_VLAN_VID_PACK_STR) == OFP_ACTION_VLAN_VID_SIZE

OFP_ACTION_VLAN_PCP_PACK_STR = '!HHB3x'
OFP_ACTION_VLAN_PCP_SIZE = 8
assert calcsize(OFP_ACTION_VLAN_PCP_PACK_STR) == OFP_ACTION_VLAN_PCP_SIZE

OFP_ACTION_DL_ADDR_PACK_STR = '!HH' + OFP_ETH_ALEN_STR + 's6x'
OFP_ACTION_DL_ADDR_SIZE = 16
assert calcsize(OFP_ACTION_DL_ADDR_PACK_STR) == OFP_ACTION_DL_ADDR_SIZE

OFP_ACTION_NW_ADDR_PACK_STR = '!HHI'
OFP_ACTION_NW_ADDR_SIZE = 8
assert calcsize(OFP_ACTION_NW_ADDR_PACK_STR) == OFP_ACTION_NW_ADDR_SIZE

OFP_ACTION_NW_TOS_PACK_STR = '!HHB3x'
OFP_ACTION_NW_TOS_SIZE = 8
assert calcsize(OFP_ACTION_NW_TOS_PACK_STR) == OFP_ACTION_NW_TOS_SIZE

OFP_ACTION_TP_PORT_PACK_STR = '!HHH2x'
OFP_ACTION_TP_PORT_SIZE = 8
assert calcsize(OFP_ACTION_TP_PORT_PACK_STR) == OFP_ACTION_TP_PORT_SIZE

OFP_ACTION_VENDOR_HEADER_PACK_STR = '!HHI'
OFP_ACTION_VENDOR_HEADER_SIZE = 8
assert (calcsize(OFP_ACTION_VENDOR_HEADER_PACK_STR) ==
        OFP_ACTION_VENDOR_HEADER_SIZE)

OFP_ACTION_HEADER_PACK_STR = '!HH4x'
OFP_ACTION_HEADER_SIZE = 8
assert calcsize(OFP_ACTION_HEADER_PACK_STR) == OFP_ACTION_HEADER_SIZE

OFP_ACTION_ENQUEUE_PACK_STR = '!HHH6xI'
OFP_ACTION_ENQUEUE_SIZE = 16
assert calcsize(OFP_ACTION_ENQUEUE_PACK_STR) == OFP_ACTION_ENQUEUE_SIZE

OFP_ACTION_PACK_STR = '!H'
# because of union ofp_action
# OFP_ACTION_SIZE = 8
# assert calcsize(OFP_ACTION_PACK_STR) == OFP_ACTION_SIZE

OFP_PACKET_OUT_PACK_STR = '!IHH'
OFP_PACKET_OUT_SIZE = 16
assert (calcsize(OFP_PACKET_OUT_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PACKET_OUT_SIZE)

# enum ofp_flow_mod_command
OFPFC_ADD = 0               # New flow.
OFPFC_MODIFY = 1            # Modify all matching flows.
OFPFC_MODIFY_STRICT = 2     # Modify entry strictly matching wildcards
OFPFC_DELETE = 3            # Delete all matching flows.
OFPFC_DELETE_STRICT = 4     # Strictly match wildcards and priority.

# enum ofp_flow_wildcards
OFPFW_IN_PORT = 1 << 0      # Switch input port.
OFPFW_DL_VLAN = 1 << 1      # VLAN vid.
OFPFW_DL_SRC = 1 << 2       # Ethernet source address.
OFPFW_DL_DST = 1 << 3       # Ethernet destination address.
OFPFW_DL_TYPE = 1 << 4      # Ethernet frame type.
OFPFW_NW_PROTO = 1 << 5     # IP protocol.
OFPFW_TP_SRC = 1 << 6       # TCP/UDP source port.
OFPFW_TP_DST = 1 << 7       # TCP/UDP destination port.
OFPFW_NW_SRC_SHIFT = 8
OFPFW_NW_SRC_BITS = 6
OFPFW_NW_SRC_MASK = ((1 << OFPFW_NW_SRC_BITS) - 1) << OFPFW_NW_SRC_SHIFT
OFPFW_NW_SRC = OFPFW_NW_SRC_MASK  # IP source address (not in OF Spec).
OFPFW_NW_SRC_ALL = 32 << OFPFW_NW_SRC_SHIFT
OFPFW_NW_DST_SHIFT = 14
OFPFW_NW_DST_BITS = 6
OFPFW_NW_DST_MASK = ((1 << OFPFW_NW_DST_BITS) - 1) << OFPFW_NW_DST_SHIFT
OFPFW_NW_DST = OFPFW_NW_DST_MASK  # IP destination address (not in OF Spec).
OFPFW_NW_DST_ALL = 32 << OFPFW_NW_DST_SHIFT
OFPFW_DL_VLAN_PCP = 1 << 20     # VLAN priority.
OFPFW_NW_TOS = 1 << 21  # IP ToS (DSCP field, 6 bits).
OFPFW_ALL = ((1 << 22) - 1)

# define constants
OFPFW_ICMP_TYPE = OFPFW_TP_SRC
OFPFW_ICMP_CODE = OFPFW_TP_DST
OFP_DL_TYPE_ETH2_CUTOFF = 0x0600
OFP_DL_TYPE_NOT_ETH_TYPE = 0x05ff
OFP_VLAN_NONE = 0xffff

_OFP_MATCH_PACK_STR = 'IH' + OFP_ETH_ALEN_STR + 's' + OFP_ETH_ALEN_STR + \
                      'sHBxHBB2xIIHH'
OFP_MATCH_PACK_STR = '!' + _OFP_MATCH_PACK_STR
OFP_MATCH_SIZE = 40
assert calcsize(OFP_MATCH_PACK_STR) == OFP_MATCH_SIZE

OFP_FLOW_PERMANENT = 0
OFP_DEFAULT_PRIORITY = 0x8000

# enum ofp_flow_mod_flags
OFPFF_SEND_FLOW_REM = 1 << 0    # Send flow removed message when flow
                                # expires or is deleted.
OFPFF_CHECK_OVERLAP = 1 << 1    # Check for overlapping entries first.
OFPFF_EMERG = 1 << 2            # Ramark this is for emergency.

_OFP_FLOW_MOD_PACK_STR0 = 'QHHHHIHH'
OFP_FLOW_MOD_PACK_STR = '!' + _OFP_MATCH_PACK_STR + _OFP_FLOW_MOD_PACK_STR0
OFP_FLOW_MOD_PACK_STR0 = '!' + _OFP_FLOW_MOD_PACK_STR0
OFP_FLOW_MOD_SIZE = 72
assert calcsize(OFP_FLOW_MOD_PACK_STR) + OFP_HEADER_SIZE == OFP_FLOW_MOD_SIZE

# enum ofp_flow_removed_reason
OFPRR_IDLE_TIMEOUT = 0  # Flow idle time exceeded idle_timeout.
OFPRR_HARD_TIMEOUT = 1  # Time exceeded hard_timeout.
OFPRR_DELETE = 2        # Evicted by a DELETE flow mod.

_OFP_FLOW_REMOVED_PACK_STR0 = 'QHBxIIH2xQQ'
OFP_FLOW_REMOVED_PACK_STR = '!' + _OFP_MATCH_PACK_STR + \
                            _OFP_FLOW_REMOVED_PACK_STR0
OFP_FLOW_REMOVED_PACK_STR0 = '!' + _OFP_FLOW_REMOVED_PACK_STR0
OFP_FLOW_REMOVED_SIZE = 88
assert (calcsize(OFP_FLOW_REMOVED_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_FLOW_REMOVED_SIZE)


# enum ofp_error_type
OFPET_HELLO_FAILED = 0  # Hello protocol failed.
OFPET_BAD_REQUEST = 1   # Request was not understood.
OFPET_BAD_ACTION = 2    # Error in action description.
OFPET_FLOW_MOD_FAILED = 3       # Problem modifying flow entry.
OFPET_PORT_MOD_FAILED = 4       # OFPT_PORT_MOD failed.
OFPET_QUEUE_OP_FAILED = 5       # Queue operation failed.

# enum ofp_hello_failed_code
OFPHFC_INCOMPATIBLE = 0  # No compatible version.
OFPHFC_EPERM = 1         # Permissions error.

# enum ofp_bad_request_code
OFPBRC_BAD_VERSION = 0          # ofp_header.version not supported.
OFPBRC_BAD_TYPE = 1             # ofp_header.type not supported.
OFPBRC_BAD_STAT = 2             # ofp_stats_msg.type not supported.
OFPBRC_BAD_VENDOR = 3           # Vendor not supported (in ofp_vendor_header
                                # or ofp_stats_msg).
OFPBRC_BAD_SUBTYPE = 4          # Vendor subtype not supported.
OFPBRC_EPERM = 5                # Permissions error.
OFPBRC_BAD_LEN = 6              # Wrong request length for type.
OFPBRC_BUFFER_EMPTY = 7         # Specified buffer has already been used.
OFPBRC_BUFFER_UNKNOWN = 8       # Specified buffer does not exist.

# enum ofp_bad_action_code
OFPBAC_BAD_TYPE = 0         # Unknown action type.
OFPBAC_BAD_LEN = 1          # Length problem in actions.
OFPBAC_BAD_VENDOR = 2       # Unknown vendor id specified.
OFPBAC_BAD_VENDOR_TYPE = 3  # Unknown action type for vendor id.
OFPBAC_BAD_OUT_PORT = 4     # Problem validating output action.
OFPBAC_BAD_ARGUMENT = 5     # Bad action argument.
OFPBAC_EPERM = 6            # Permissions error.
OFPBAC_TOO_MANY = 7         # Can't handle this many actions.
OFPBAC_BAD_QUEUE = 8        # Problem validating output queue.

# enum ofp_flow_mod_failed_code
OFPFMFC_ALL_TABLES_FULL = 0     # Flow not added because of full tables.
OFPFMFC_OVERLAP = 1             # Attempted to add overlapping flow with
                                # CHECK_OVERLAP flags set.
OFPFMFC_EPERM = 2               # Permissions error.
OFPFMFC_BAD_EMERG_TIMEOUT = 3   # Flow not added because of non-zero idle/hard
                                # timeout.
OFPFMFC_BAD_COMMAND = 4         # Unknown command.
OFPFMFC_UNSUPPORTED = 5         # Unsupported action list - cannot process in
                                # the order specified.

# enum ofp_port_mod_failed_code
OFPPMFC_BAD_PORT = 0        # Specified port does not exist.
OFPPMFC_BAD_HW_ADDR = 1     # Specified hardware address is wrong.

# enum ofp_queue_op_failed_code
OFPQOFC_BAD_PORT = 0    # Invalid port (or port does not exist).
OFPQOFC_BAD_QUEUE = 1   # Queue does not exist.
OFPQOFC_EPERM = 2       # Permissions error.

OFP_ERROR_MSG_PACK_STR = '!HH'
OFP_ERROR_MSG_SIZE = 12
assert calcsize(OFP_ERROR_MSG_PACK_STR) + OFP_HEADER_SIZE == OFP_ERROR_MSG_SIZE

# enum ofp_stats_types
OFPST_DESC = 0
OFPST_FLOW = 1
OFPST_AGGREGATE = 2
OFPST_TABLE = 3
OFPST_PORT = 4
OFPST_QUEUE = 5
OFPST_VENDOR = 0xffff

_OFP_STATS_MSG_PACK_STR = 'HH'
OFP_STATS_MSG_PACK_STR = '!' + _OFP_STATS_MSG_PACK_STR
OFP_STATS_MSG_SIZE = 12
assert calcsize(OFP_STATS_MSG_PACK_STR) + OFP_HEADER_SIZE == OFP_STATS_MSG_SIZE

# enum ofp_stats_reply_flags
OFPSF_REPLY_MORE = 1 << 0       # More replies to follow.

# define constants
DESC_STR_LEN = 256
DESC_STR_LEN_STR = str(DESC_STR_LEN)
SERIAL_NUM_LEN = 32
SERIAL_NUM_LEN_STR = str(SERIAL_NUM_LEN)

OFP_DESC_STATS_PACK_STR = '!' + \
                          DESC_STR_LEN_STR + 's' + \
                          DESC_STR_LEN_STR + 's' + \
                          DESC_STR_LEN_STR + 's' + \
                          SERIAL_NUM_LEN_STR + 's' + \
                          DESC_STR_LEN_STR + 's'
OFP_DESC_STATS_SIZE = 1068
assert (calcsize(OFP_DESC_STATS_PACK_STR) + OFP_STATS_MSG_SIZE ==
        OFP_DESC_STATS_SIZE)

_OFP_FLOW_STATS_REQUEST_ID_PORT_STR = 'BxH'
OFP_FLOW_STATS_REQUEST_ID_PORT_STR = '!' + _OFP_FLOW_STATS_REQUEST_ID_PORT_STR
OFP_FLOW_STATS_REQUEST_PACK_STR = '!' + _OFP_MATCH_PACK_STR + \
                                  _OFP_FLOW_STATS_REQUEST_ID_PORT_STR
OFP_FLOW_STATS_REQUEST_SIZE = 56
assert (calcsize(OFP_FLOW_STATS_REQUEST_PACK_STR) + OFP_STATS_MSG_SIZE ==
        OFP_FLOW_STATS_REQUEST_SIZE)

_OFP_FLOW_STATS_0_PACK_STR = 'HBx'
OFP_FLOW_STATS_0_PACK_STR = '!' + _OFP_FLOW_STATS_0_PACK_STR
OFP_FLOW_STATS_0_SIZE = 4
assert calcsize(OFP_FLOW_STATS_0_PACK_STR) == OFP_FLOW_STATS_0_SIZE
_OFP_FLOW_STATS_1_PACK_STR = 'IIHHH6xQQQ'
OFP_FLOW_STATS_1_PACK_STR = '!' + _OFP_FLOW_STATS_1_PACK_STR
OFP_FLOW_STATS_1_SIZE = 44
assert calcsize(OFP_FLOW_STATS_1_PACK_STR) == OFP_FLOW_STATS_1_SIZE
OFP_FLOW_STATS_PACK_STR = '!' + _OFP_FLOW_STATS_0_PACK_STR +\
                          _OFP_MATCH_PACK_STR + _OFP_FLOW_STATS_1_PACK_STR
OFP_FLOW_STATS_SIZE = 88
assert calcsize(OFP_FLOW_STATS_PACK_STR) == OFP_FLOW_STATS_SIZE

OFP_AGGREGATE_STATS_REPLY_PACK_STR = '!QQI4x'
OFP_AGGREGATE_STATS_REPLY_SIZE = 36
assert (calcsize(OFP_AGGREGATE_STATS_REPLY_PACK_STR) +
        OFP_STATS_MSG_SIZE == OFP_AGGREGATE_STATS_REPLY_SIZE)

OFP_TABLE_STATS_PACK_STR = '!B3x' + OFP_MAX_TABLE_NAME_LEN_STR + 'sIIIQQ'
OFP_TABLE_STATS_SIZE = 64
assert calcsize(OFP_TABLE_STATS_PACK_STR) == OFP_TABLE_STATS_SIZE

OFP_PORT_STATS_REQUEST_PACK_STR = '!H6x'
OFP_PORT_STATS_REQUEST_SIZE = 20
assert (calcsize(OFP_PORT_STATS_REQUEST_PACK_STR) + OFP_STATS_MSG_SIZE ==
        OFP_PORT_STATS_REQUEST_SIZE)

OFP_PORT_STATS_PACK_STR = '!H6xQQQQQQQQQQQQ'
OFP_PORT_STATS_SIZE = 104
assert calcsize(OFP_PORT_STATS_PACK_STR) == OFP_PORT_STATS_SIZE

OFPQ_ALL = 0xffffffff

OFP_QUEUE_STATS_REQUEST_PACK_STR = '!HxxI'
OFP_QUEUE_STATS_REQUEST_SIZE = 8
assert (calcsize(OFP_QUEUE_STATS_REQUEST_PACK_STR) ==
        OFP_QUEUE_STATS_REQUEST_SIZE)

OFP_QUEUE_STATS_PACK_STR = '!H2xIQQQ'
OFP_QUEUE_STATS_SIZE = 32
assert calcsize(OFP_QUEUE_STATS_PACK_STR) == OFP_QUEUE_STATS_SIZE

OFP_VENDOR_STATS_MSG_PACK_STR = '!I'
OFP_VENDOR_STATS_MSG_SIZE = 16
assert (calcsize(OFP_VENDOR_STATS_MSG_PACK_STR) + OFP_STATS_MSG_SIZE ==
        OFP_VENDOR_STATS_MSG_SIZE)

OFP_VENDOR_HEADER_PACK_STR = '!I'
OFP_VENDOR_HEADER_SIZE = 12
assert (calcsize(OFP_VENDOR_HEADER_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_VENDOR_HEADER_SIZE)

OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR = '!H2x'
OFP_QUEUE_GET_CONFIG_REQUEST_SIZE = 12
assert (calcsize(OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_QUEUE_GET_CONFIG_REQUEST_SIZE)

OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR = '!H6x'
OFP_QUEUE_GET_CONFIG_REPLY_SIZE = 16
assert (calcsize(OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_QUEUE_GET_CONFIG_REPLY_SIZE)

OFP_PACKET_QUEUE_PQCK_STR = '!IH2x'
OFP_PACKET_QUEUE_SIZE = 8
assert calcsize(OFP_PACKET_QUEUE_PQCK_STR) == OFP_PACKET_QUEUE_SIZE

OFPQT_NONE = 0
OFPQT_MIN_RATE = 1

OFP_QUEUE_PROP_HEADER_PACK_STR = '!HH4x'
OFP_QUEUE_PROP_HEADER_SIZE = 8
assert calcsize(OFP_QUEUE_PROP_HEADER_PACK_STR) == OFP_QUEUE_PROP_HEADER_SIZE

OFP_QUEUE_PROP_MIN_RATE_PACK_STR = '!H6x'
OFP_QUEUE_PROP_MIN_RATE_SIZE = 16
assert (calcsize(OFP_QUEUE_PROP_MIN_RATE_PACK_STR) +
        OFP_QUEUE_PROP_HEADER_SIZE == OFP_QUEUE_PROP_MIN_RATE_SIZE)

# generate utility methods
ofproto_utils.generate(__name__)


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

from ryu.ofproto.nicira_ext import *  # For API compat
