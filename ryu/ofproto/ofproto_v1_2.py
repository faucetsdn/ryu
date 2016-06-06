# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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
OpenFlow 1.2 definitions.
"""

from ryu.lib import type_desc
from ryu.ofproto import nicira_ext
from ryu.ofproto import ofproto_utils
from ryu.ofproto import oxm_fields

from struct import calcsize

# struct ofp_header
OFP_HEADER_PACK_STR = '!BBHI'
OFP_HEADER_SIZE = 8
assert calcsize(OFP_HEADER_PACK_STR) == OFP_HEADER_SIZE

# enum ofp_type
OFPT_HELLO = 0    # Symmetric message
OFPT_ERROR = 1    # Symmetric message
OFPT_ECHO_REQUEST = 2    # Symmetric message
OFPT_ECHO_REPLY = 3    # Symmetric message
OFPT_EXPERIMENTER = 4    # Symmetric message
# Immutable message
OFPT_FEATURES_REQUEST = 5    # Controller/switch message
OFPT_FEATURES_REPLY = 6    # Controller/switch message
OFPT_GET_CONFIG_REQUEST = 7    # Controller/switch message
OFPT_GET_CONFIG_REPLY = 8    # Controller/switch message
OFPT_SET_CONFIG = 9    # Controller/switch message

OFPT_PACKET_IN = 10    # Async message
OFPT_FLOW_REMOVED = 11    # Async message
OFPT_PORT_STATUS = 12    # Async message

OFPT_PACKET_OUT = 13    # Controller/switch message
OFPT_FLOW_MOD = 14    # Controller/switch message
OFPT_GROUP_MOD = 15    # Controller/switch message
OFPT_PORT_MOD = 16    # Controller/switch message
OFPT_TABLE_MOD = 17    # Controller/switch message

OFPT_STATS_REQUEST = 18    # Controller/switch message
OFPT_STATS_REPLY = 19    # Controller/switch message

OFPT_BARRIER_REQUEST = 20    # Controller/switch message
OFPT_BARRIER_REPLY = 21    # Controller/switch message

OFPT_QUEUE_GET_CONFIG_REQUEST = 22    # Controller/switch message
OFPT_QUEUE_GET_CONFIG_REPLY = 23    # Controller/switch message

OFPT_ROLE_REQUEST = 24    # Controller/switch message
OFPT_ROLE_REPLY = 25    # Controller/switch message

# struct ofp_port
OFP_MAX_PORT_NAME_LEN = 16
OFP_ETH_ALEN = 6
OFP_ETH_ALEN_STR = str(OFP_ETH_ALEN)
_OFP_PORT_PACK_STR = 'I4x' + OFP_ETH_ALEN_STR + 's' + '2x' + \
                     str(OFP_MAX_PORT_NAME_LEN) + 's' + 'IIIIIIII'
OFP_PORT_PACK_STR = '!' + _OFP_PORT_PACK_STR
OFP_PORT_SIZE = 64
assert calcsize(OFP_PORT_PACK_STR) == OFP_PORT_SIZE

# enum ofp_port_config
OFPPC_PORT_DOWN = 1 << 0    # Port is administratively down.
OFPPC_NO_RECV = 1 << 2        # Drop all packets recieved by port.
OFPPC_NO_FWD = 1 << 5        # Drop packets forwarded to port.
OFPPC_NO_PACKET_IN = 1 << 6    # Do not send packet-in msgs for port.

# enum ofp_port_state
OFPPS_LINK_DOWN = 1 << 0    # No physical link present.
OFPPS_BLOCKED = 1 << 1        # Port is blocked.
OFPPS_LIVE = 1 << 2        # Live for Fast Failover Group.

# enum ofp_port_no
OFPP_MAX = 0xffffff00
OFPP_IN_PORT = 0xfffffff8       # Send the packet out the input port. This
                                # virtual port must be explicitly used
                                # in order to send back out of the input
                                # port.
OFPP_TABLE = 0xfffffff9         # Perform actions in flow table.
                                # NB: This can only be the destination
                                # port for packet-out messages.
OFPP_NORMAL = 0xfffffffa        # Process with normal L2/L3 switching.
OFPP_FLOOD = 0xfffffffb         # All physical ports except input port and
                                # those disabled by STP.
OFPP_ALL = 0xfffffffc           # All physical ports except input port.
OFPP_CONTROLLER = 0xfffffffd    # Send to controller.
OFPP_LOCAL = 0xfffffffe         # Local openflow "port".
OFPP_ANY = 0xffffffff 	        # Not associated with a physical port.

# All ones is used to indicate all queues in a port (for stats retrieval).
OFPQ_ALL = 0xffffffff

# enum ofp_port_features
OFPPF_10MB_HD = 1 << 0    # 10 Mb half-duplex rate support.
OFPPF_10MB_FD = 1 << 1    # 10 Mb full-duplex rate support.
OFPPF_100MB_HD = 1 << 2    # 100 Mb half-duplex rate support.
OFPPF_100MB_FD = 1 << 3    # 100 Mb full-duplex rate support.
OFPPF_1GB_HD = 1 << 4    # 1 Gb half-duplex rate support.
OFPPF_1GB_FD = 1 << 5    # 1 Gb full-duplex rate support.
OFPPF_10GB_FD = 1 << 6    # 10 Gb full-duplex rate support.
OFPPF_40GB_FD = 1 << 7    # 40 Gb full-duplex rate support.
OFPPF_100GB_FD = 1 << 8    # 100 Gb full-duplex rate support.
OFPPF_1TB_FD = 1 << 9    # 1 Tb full-duplex rate support.
OFPPF_OTHER = 1 << 10    # Other rate, not in the list.
OFPPF_COPPER = 1 << 11    # Copper medium.
OFPPF_FIBER = 1 << 12    # Fiber medium.
OFPPF_AUTONEG = 1 << 13    # Auto-negotiation.
OFPPF_PAUSE = 1 << 14    # Pause.
OFPPF_PAUSE_ASYM = 1 << 15    # Asymmetric pause.

# struct ofp_packet_queue
OFP_PACKET_QUEUE_PACK_STR = '!IIH6x'
OFP_PACKET_QUEUE_SIZE = 16
assert calcsize(OFP_PACKET_QUEUE_PACK_STR) == OFP_PACKET_QUEUE_SIZE

# enum ofp_queue_properties
OFPQT_MIN_RATE = 1        # Minimum datarate guaranteed.
OFPQT_MAX_RATE = 2        # Maximum datarate.
OFPQT_EXPERIMENTER = 0xffff     # Experimenter defined property.

# struct ofp_queue_prop_header
OFP_QUEUE_PROP_HEADER_PACK_STR = '!HH4x'
OFP_QUEUE_PROP_HEADER_SIZE = 8
assert calcsize(OFP_QUEUE_PROP_HEADER_PACK_STR) == OFP_QUEUE_PROP_HEADER_SIZE

# struct ofp_queue_prop_min_rate
OFP_QUEUE_PROP_MIN_RATE_PACK_STR = '!H6x'
OFP_QUEUE_PROP_MIN_RATE_SIZE = 16
assert (calcsize(OFP_QUEUE_PROP_MIN_RATE_PACK_STR) +
        OFP_QUEUE_PROP_HEADER_SIZE) == OFP_QUEUE_PROP_MIN_RATE_SIZE

# struct ofp_queue_prop_max_rate
OFP_QUEUE_PROP_MAX_RATE_PACK_STR = '!H6x'
OFP_QUEUE_PROP_MAX_RATE_SIZE = 16
assert (calcsize(OFP_QUEUE_PROP_MAX_RATE_PACK_STR) +
        OFP_QUEUE_PROP_HEADER_SIZE) == OFP_QUEUE_PROP_MAX_RATE_SIZE

# struct ofp_queue_prop_experimenter
OFP_QUEUE_PROP_EXPERIMENTER_PACK_STR = '!I4x'
OFP_QUEUE_PROP_EXPERIMENTER_SIZE = 16
assert (calcsize(OFP_QUEUE_PROP_EXPERIMENTER_PACK_STR) +
        OFP_QUEUE_PROP_HEADER_SIZE) == OFP_QUEUE_PROP_EXPERIMENTER_SIZE

# struct ofp_match
_OFP_MATCH_PACK_STR = 'HHBBBB'
OFP_MATCH_PACK_STR = '!' + _OFP_MATCH_PACK_STR
OFP_MATCH_SIZE = 8
assert calcsize(OFP_MATCH_PACK_STR) == OFP_MATCH_SIZE

# enum ofp_match_type
OFPMT_STANDARD = 0  # Deprecated
OFPMT_OXM = 1       # OpenFlow Extensible Match

# enum ofp_oxm_class
OFPXMC_NXM_0 = 0x0000           # Backward compatibility with NXM
OFPXMC_NXM_1 = 0x0001           # Backward compatibility with NXM
OFPXMC_OPENFLOW_BASIC = 0x8000  # Basic class for OpenFlow
OFPXMC_EXPERIMENTER = 0xFFFF    # Experimenter class

# enum ofp_vlan_id
OFPVID_PRESENT = 0x1000     # bit that indicate that a VLAN id is set.
OFPVID_NONE = 0x0000        # No VLAN id was set.

# struct ofp_oxm_experimenter_header
OFP_OXM_EXPERIMENTER_HEADER_PACK_STR = '!II'
OFP_OXM_EXPERIMENTER_HEADER_SIZE = 8
assert (calcsize(OFP_OXM_EXPERIMENTER_HEADER_PACK_STR) ==
        OFP_OXM_EXPERIMENTER_HEADER_SIZE)

# enum ofp_instruction_type
OFPIT_GOTO_TABLE = 1            # Setup the next table in the lookup pipeline.
OFPIT_WRITE_METADATA = 2        # Setup the metadata field for use later in
                                # pipeline.
OFPIT_WRITE_ACTIONS = 3         # Write the action(s) onto the datapath
                                # action set
OFPIT_APPLY_ACTIONS = 4         # Applies the action(s) immediately
OFPIT_CLEAR_ACTIONS = 5         # Clears all actions from the datapath action
                                # set
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

# struct ofp_instaruction_actions
OFP_INSTRUCTION_ACTIONS_PACK_STR = '!HH4x'
OFP_INSTRUCTION_ACTIONS_SIZE = 8
assert (calcsize(OFP_INSTRUCTION_ACTIONS_PACK_STR) ==
        OFP_INSTRUCTION_ACTIONS_SIZE)

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
OFPAT_EXPERIMENTER = 0xffff

# struct ofp_action_header
OFP_ACTION_HEADER_PACK_STR = '!HH4x'
OFP_ACTION_HEADER_SIZE = 8
assert calcsize(OFP_ACTION_HEADER_PACK_STR) == OFP_ACTION_HEADER_SIZE

# struct ofp_action_output
OFP_ACTION_OUTPUT_PACK_STR = '!HHIH6x'
OFP_ACTION_OUTPUT_SIZE = 16
assert calcsize(OFP_ACTION_OUTPUT_PACK_STR) == OFP_ACTION_OUTPUT_SIZE

# enum ofp_controller_max_len
OFPCML_MAX = 0xffe5         # maximum max_len value which can be used to
                            # request a specific byte length.
OFPCML_NO_BUFFER = 0xffff   # indicates that no buffering should be
                            # applied and the whole packet is to be
                            # sent to the controller.

# struct ofp_action_group
OFP_ACTION_GROUP_PACK_STR = '!HHI'
OFP_ACTION_GROUP_SIZE = 8
assert calcsize(OFP_ACTION_GROUP_PACK_STR) == OFP_ACTION_GROUP_SIZE

# struct ofp_action_set_queue
OFP_ACTION_SET_QUEUE_PACK_STR = '!HHI'
OFP_ACTION_SET_QUEUE_SIZE = 8
assert calcsize(OFP_ACTION_SET_QUEUE_PACK_STR) == OFP_ACTION_SET_QUEUE_SIZE

# struct ofp_aciton_mpls_ttl
OFP_ACTION_MPLS_TTL_PACK_STR = '!HHB3x'
OFP_ACTION_MPLS_TTL_SIZE = 8
assert calcsize(OFP_ACTION_MPLS_TTL_PACK_STR) == OFP_ACTION_MPLS_TTL_SIZE

# struct ofp_action_nw_ttl
OFP_ACTION_NW_TTL_PACK_STR = '!HHB3x'
OFP_ACTION_NW_TTL_SIZE = 8
assert calcsize(OFP_ACTION_NW_TTL_PACK_STR) == OFP_ACTION_NW_TTL_SIZE

# struct ofp_action_push
OFP_ACTION_PUSH_PACK_STR = '!HHH2x'
OFP_ACTION_PUSH_SIZE = 8
assert calcsize(OFP_ACTION_PUSH_PACK_STR) == OFP_ACTION_PUSH_SIZE

# struct ofp_action_pop_mpls
OFP_ACTION_POP_MPLS_PACK_STR = '!HHH2x'
OFP_ACTION_POP_MPLS_SIZE = 8
assert calcsize(OFP_ACTION_POP_MPLS_PACK_STR) == OFP_ACTION_POP_MPLS_SIZE

# struct ofp_action_set_field
OFP_ACTION_SET_FIELD_PACK_STR = '!HH4B'
OFP_ACTION_SET_FIELD_SIZE = 8
assert calcsize(OFP_ACTION_SET_FIELD_PACK_STR) == OFP_ACTION_SET_FIELD_SIZE

# struct ofp_action_experimenter_header
OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR = '!HHI'
OFP_ACTION_EXPERIMENTER_HEADER_SIZE = 8
assert (calcsize(OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR) ==
        OFP_ACTION_EXPERIMENTER_HEADER_SIZE)

# struct ofp_switch_feature
OFP_SWITCH_FEATURES_PACK_STR = '!QIB3xII'
OFP_SWITCH_FEATURES_SIZE = 32
assert (calcsize(OFP_SWITCH_FEATURES_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_SWITCH_FEATURES_SIZE)

# enum ofp_capabilities
OFPC_FLOW_STATS = 1 << 0    # Flow statistics.
OFPC_TABLE_STATS = 1 << 1   # Table statistics.
OFPC_PORT_STATS = 1 << 2    # Port statistics.
OFPC_GROUP_STATS = 1 << 3   # Group statistics.
OFPC_IP_REASM = 1 << 5      # Can reassemble IP fragments.
OFPC_QUEUE_STATS = 1 << 6   # Queue statistics.
OFPC_PORT_BLOCKED = 1 << 8  # Switch will block looping ports.

# struct ofp_switch_config
OFP_SWITCH_CONFIG_PACK_STR = '!HH'
OFP_SWITCH_CONFIG_SIZE = 12
assert (calcsize(OFP_SWITCH_CONFIG_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_SWITCH_CONFIG_SIZE)

# enum ofp_config_flags
OFPC_FRAG_NORMAL = 0    # No special handling for fragments.
OFPC_FRAG_DROP = 1      # Drop fragments.
OFPC_FRAG_REASM = 2     # Reassemble (only if OFPC_IP_REASM set).
OFPC_FRAG_MASK = 3
OFPC_INVALID_TTL_TO_CONTROLLER = 1 << 2     # Send packets with invalid
                                            # TTL to the controller.

# enum ofp_table
OFPTT_MAX = 0xfe
OFPTT_ALL = 0xff

# struct ofp_table_mod
OFP_TABLE_MOD_PACK_STR = '!B3xI'
OFP_TABLE_MOD_SIZE = 16
assert (calcsize(OFP_TABLE_MOD_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_TABLE_MOD_SIZE)

# enum ofp_table_config
OFPTC_TABLE_MISS_CONTROLLER = 0
OFPTC_TABLE_MISS_CONTINUE = 1 << 0
OFPTC_TABLE_MISS_DROP = 1 << 1
OFPTC_TABLE_MISS_MASK = 3

# struct ofp_flow_mod
_OFP_FLOW_MOD_PACK_STR0 = 'QQBBHHHIIIH2x'
OFP_FLOW_MOD_PACK_STR = '!' + _OFP_FLOW_MOD_PACK_STR0 + _OFP_MATCH_PACK_STR
OFP_FLOW_MOD_PACK_STR0 = '!' + _OFP_FLOW_MOD_PACK_STR0
OFP_FLOW_MOD_SIZE = 56
assert (calcsize(OFP_FLOW_MOD_PACK_STR) + OFP_HEADER_SIZE == OFP_FLOW_MOD_SIZE)

# enum ofp_flow_mod_command
OFPFC_ADD = 0               # New flow.
OFPFC_MODIFY = 1            # Modify all matching flows.
OFPFC_MODIFY_STRICT = 2     # Modify entry strictly matching wildcards
OFPFC_DELETE = 3            # Delete all matching flows.
OFPFC_DELETE_STRICT = 4     # Strictly match wildcards and priority.

# enum ofp_flow_mod_flags
OFPFF_SEND_FLOW_REM = 1 << 0    # Send flow removed message when flow
                                # expires or is deleted.
OFPFF_CHECK_OVERLAP = 1 << 1    # Check for overlapping entries first.
OFPFF_RESET_COUNTS = 1 << 2     # Reset flow packet and byte counts.

# struct ofp_group_mod
OFP_GROUP_MOD_PACK_STR = '!HBxI'
OFP_GROUP_MOD_SIZE = 16
assert (calcsize(OFP_GROUP_MOD_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_GROUP_MOD_SIZE)

# enum ofp_group
OFPG_MAX = 0xffffff00
OFPG_ALL = 0xfffffffc
OFPG_ANY = 0xffffffff

# enum ofp_group_mod_command
OFPGC_ADD = 0       # New group.
OFPGC_MODIFY = 1    # Modify all matching groups.
OFPGC_DELETE = 2    # Deletes all matching groups.

# enum ofp_group_type
OFPGT_ALL = 0       # All (multicast/broadcast) group.
OFPGT_SELECT = 1    # Select group.
OFPGT_INDIRECT = 2  # Indirect group.
OFPGT_FF = 3        # Fast failover group.

# struct ofp_bucket
OFP_BUCKET_PACK_STR = '!HHII4x'
OFP_BUCKET_SIZE = 16
assert calcsize(OFP_BUCKET_PACK_STR) == OFP_BUCKET_SIZE

# struct ofp_port_mod
OFP_PORT_MOD_PACK_STR = '!I4x' + OFP_ETH_ALEN_STR + 's' + '2xIII4x'
OFP_PORT_MOD_SIZE = 40
assert calcsize(OFP_PORT_MOD_PACK_STR) + OFP_HEADER_SIZE == OFP_PORT_MOD_SIZE

# sturct ofp_stats_request
OFP_STATS_REQUEST_PACK_STR = '!HH4x'
OFP_STATS_REQUEST_SIZE = 16
assert (calcsize(OFP_STATS_REQUEST_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_STATS_REQUEST_SIZE)

# enum ofp_stats_reply_flags
OFPSF_REPLY_MORE = 1 << 0       # More replies to follow.

# struct ofp_stats_reply
OFP_STATS_REPLY_PACK_STR = '!HH4x'
OFP_STATS_REPLY_SIZE = 16
assert (calcsize(OFP_STATS_REPLY_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_STATS_REPLY_SIZE)

# enum ofp_stats_types
OFPST_DESC = 0
OFPST_FLOW = 1
OFPST_AGGREGATE = 2
OFPST_TABLE = 3
OFPST_PORT = 4
OFPST_QUEUE = 5
OFPST_GROUP = 6
OFPST_GROUP_DESC = 7
OFPST_GROUP_FEATURES = 8
OFPST_EXPERIMENTER = 0xffff

# struct ofp_desc_stats
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
OFP_DESC_STATS_SIZE = 1056
assert calcsize(OFP_DESC_STATS_PACK_STR) == OFP_DESC_STATS_SIZE

# struct ofp_flow_stats_request
OFP_FLOW_STATS_REQUEST_PACK_STR = '!B3xII4xQQ'
OFP_FLOW_STATS_REQUEST_SIZE = 40
assert (calcsize(OFP_FLOW_STATS_REQUEST_PACK_STR) + OFP_MATCH_SIZE ==
        OFP_FLOW_STATS_REQUEST_SIZE)

# struct ofp_flow_stats
OFP_FLOW_STATS_PACK_STR = '!HBxIIHHH6xQQQ'
OFP_FLOW_STATS_SIZE = 56
assert (calcsize(OFP_FLOW_STATS_PACK_STR) + OFP_MATCH_SIZE ==
        OFP_FLOW_STATS_SIZE)

# struct ofp_aggregate_stats_request
OFP_AGGREGATE_STATS_REQUEST_PACK_STR = '!B3xII4xQQ'
OFP_AGGREGATE_STATS_REQUEST_SIZE = 40
assert (calcsize(OFP_AGGREGATE_STATS_REQUEST_PACK_STR) + OFP_MATCH_SIZE ==
        OFP_AGGREGATE_STATS_REQUEST_SIZE)

# struct ofp_aggregate_stats_reply
OFP_AGGREGATE_STATS_REPLY_PACK_STR = '!QQI4x'
OFP_AGGREGATE_STATS_REPLY_SIZE = 24
assert (calcsize(OFP_AGGREGATE_STATS_REPLY_PACK_STR) ==
        OFP_AGGREGATE_STATS_REPLY_SIZE)

# sturct ofp_table_stats
OFP_TABLE_STATS_SIZE = 128
OFP_MAX_TABLE_NAME_LEN = 32
OFP_MAX_TABLE_NAME_LEN_STR = str(OFP_MAX_TABLE_NAME_LEN)
OFP_TABLE_STATS_PACK_STR = '!B7x' + OFP_MAX_TABLE_NAME_LEN_STR + \
                           'sQQIIQQQQIIIIQQ'
assert calcsize(OFP_TABLE_STATS_PACK_STR) == OFP_TABLE_STATS_SIZE

# struct ofp_port_stats_request
OFP_PORT_STATS_REQUEST_PACK_STR = '!I4x'
OFP_PORT_STATS_REQUEST_SIZE = 8
assert calcsize(OFP_PORT_STATS_REQUEST_PACK_STR) == OFP_PORT_STATS_REQUEST_SIZE

# struct ofp_port_stats
OFP_PORT_STATS_PACK_STR = '!I4xQQQQQQQQQQQQ'
OFP_PORT_STATS_SIZE = 104
assert calcsize(OFP_PORT_STATS_PACK_STR) == OFP_PORT_STATS_SIZE

# struct ofp_queue_stats_request
OFP_QUEUE_STATS_REQUEST_PACK_STR = '!II'
OFP_QUEUE_STATS_REQUEST_SIZE = 8
assert (calcsize(OFP_QUEUE_STATS_REQUEST_PACK_STR) ==
        OFP_QUEUE_STATS_REQUEST_SIZE)

# struct ofp_queue_stats
OFP_QUEUE_STATS_PACK_STR = '!IIQQQ'
OFP_QUEUE_STATS_SIZE = 32
assert calcsize(OFP_QUEUE_STATS_PACK_STR) == OFP_QUEUE_STATS_SIZE

# struct ofp_group_stats_request
OFP_GROUP_STATS_REQUEST_PACK_STR = '!I4x'
OFP_GROUP_STATS_REQUEST_SIZE = 8
assert (calcsize(OFP_GROUP_STATS_REQUEST_PACK_STR) ==
        OFP_GROUP_STATS_REQUEST_SIZE)

# struct ofp_group_stats
OFP_GROUP_STATS_PACK_STR = '!H2xII4xQQ'
OFP_GROUP_STATS_SIZE = 32
assert calcsize(OFP_GROUP_STATS_PACK_STR) == OFP_GROUP_STATS_SIZE

# struct ofp_bucket_counter
OFP_BUCKET_COUNTER_PACK_STR = '!QQ'
OFP_BUCKET_COUNTER_SIZE = 16
assert calcsize(OFP_BUCKET_COUNTER_PACK_STR) == OFP_BUCKET_COUNTER_SIZE

# struct ofp_group_desc_stats
OFP_GROUP_DESC_STATS_PACK_STR = '!HBxI'
OFP_GROUP_DESC_STATS_SIZE = 8
assert calcsize(OFP_GROUP_DESC_STATS_PACK_STR) == OFP_GROUP_DESC_STATS_SIZE

# struct ofp_group_features_stats
OFP_GROUP_FEATURES_STATS_PACK_STR = '!II4I4I'
OFP_GROUP_FEATURES_STATS_SIZE = 40
assert (calcsize(OFP_GROUP_FEATURES_STATS_PACK_STR) ==
        OFP_GROUP_FEATURES_STATS_SIZE)

# enmu ofp_group_capabilities
OFPGFC_SELECT_WEIGHT = 1 << 0       # Support weight for select groups.
OFPGFC_SELECT_LIVENESS = 1 << 1     # Support liveness for select groups.
OFPGFC_CHAINING = 1 << 2            # Support chaining groups.
OFPGFC_CHAINING_CHECKS = 1 << 3     # Check chaining for loops and delete

# struct ofp_experimenter_stats_header
OFP_EXPERIMENTER_STATS_HEADER_PACK_STR = '!II'
OFP_EXPERIMENTER_STATS_HEADER_SIZE = 8
assert (calcsize(OFP_EXPERIMENTER_STATS_HEADER_PACK_STR) ==
        OFP_EXPERIMENTER_STATS_HEADER_SIZE)

# struct opf_queue_get_config_request
OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR = '!I4x'
OFP_QUEUE_GET_CONFIG_REQUEST_SIZE = 16
assert (calcsize(OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_QUEUE_GET_CONFIG_REQUEST_SIZE)

# struct ofp_queue_get_config_reply
OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR = '!I4x'
OFP_QUEUE_GET_CONFIG_REPLY_SIZE = 16
assert (calcsize(OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_QUEUE_GET_CONFIG_REPLY_SIZE)

# struct ofp_packet_out
OFP_PACKET_OUT_PACK_STR = '!IIH6x'
OFP_PACKET_OUT_SIZE = 24
assert (calcsize(OFP_PACKET_OUT_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PACKET_OUT_SIZE)

# struct ofp_role_request
OFP_ROLE_REQUEST_PACK_STR = '!I4xQ'
OFP_ROLE_REQUEST_SIZE = 24
assert (calcsize(OFP_ROLE_REQUEST_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_ROLE_REQUEST_SIZE)

# enum ofp_controller_role
OFPCR_ROLE_NOCHANGE = 0     # Don't change current role.
OFPCR_ROLE_EQUAL = 1        # Default role, full access.
OFPCR_ROLE_MASTER = 2       # Full access, at most one master.
OFPCR_ROLE_SLAVE = 3        # Read-only access.

# struct ofp_packet_in
OFP_PACKET_IN_PACK_STR = '!IHBB'
OFP_PACKET_IN_SIZE = 24
assert (calcsize(OFP_PACKET_IN_PACK_STR) + OFP_MATCH_SIZE + OFP_HEADER_SIZE ==
        OFP_PACKET_IN_SIZE)

# enum ofp_packet_in_reason
OFPR_NO_MATCH = 0       # No matching flow.
OFPR_ACTION = 1         # Action explicitly output to controller.
OFPR_INVALID_TTL = 2    # Packet has invalid TTL.

# struct ofp_flow_removed
_OFP_FLOW_REMOVED_PACK_STR0 = 'QHBBIIHHQQ'
OFP_FLOW_REMOVED_PACK_STR = '!' + _OFP_FLOW_REMOVED_PACK_STR0 + \
                            _OFP_MATCH_PACK_STR
OFP_FLOW_REMOVED_PACK_STR0 = '!' + _OFP_FLOW_REMOVED_PACK_STR0
OFP_FLOW_REMOVED_SIZE = 56
assert (calcsize(OFP_FLOW_REMOVED_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_FLOW_REMOVED_SIZE)

# enum ofp_flow_removed_reason
OFPRR_IDLE_TIMEOUT = 0      # Flow idle time exceeded idle_timeout.
OFPRR_HARD_TIMEOUT = 1      # Time exceeded hard_timeout.
OFPRR_DELETE = 2            # Evicted by a DELETE flow mod.
OFPRR_GROUP_DELETE = 3      # Group was removed.

# struct ofp_port_status
OFP_PORT_STATUS_PACK_STR = '!B7x' + _OFP_PORT_PACK_STR
OFP_PORT_STATUS_DESC_OFFSET = OFP_HEADER_SIZE + 8
OFP_PORT_STATUS_SIZE = 80
assert (calcsize(OFP_PORT_STATUS_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_PORT_STATUS_SIZE)

# enum ofp_port_reason
OFPPR_ADD = 0       # The port was added.
OFPPR_DELETE = 1    # The port was removed.
OFPPR_MODIFY = 2    # Some attribute of the port has changed.

# struct ofp_error_msg
OFP_ERROR_MSG_PACK_STR = '!HH'
OFP_ERROR_MSG_SIZE = 12
assert calcsize(OFP_ERROR_MSG_PACK_STR) + OFP_HEADER_SIZE == OFP_ERROR_MSG_SIZE

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
OFPET_EXPERIMENTER = 0xffff         # Experimenter error messages.

# enum ofp_hello_failed_code
OFPHFC_INCOMPATIBLE = 0     # No compatible version.
OFPHFC_EPERM = 1            # Permissions error.

# enum ofp_bad_request_code
OFPBRC_BAD_VERSION = 0          # ofp_header.version not supported.
OFPBRC_BAD_TYPE = 1             # ofp_header.type not supported.
OFPBRC_BAD_STAT = 2             # ofp_stats_msg.type not supported.
OFPBRC_BAD_EXPERIMENTER = 3     # Experimenter id not supported
                                # (in ofp_experimenter_header
                                # or ofp_stats_request or ofp_stats_reply).
OFPBRC_BAD_EXP_TYPE = 4         # Experimenter type not supported.
OFPBRC_EPERM = 5                # Permissions error.
OFPBRC_BAD_LEN = 6              # Wrong request length for type.
OFPBRC_BUFFER_EMPTY = 7         # Specified buffer has already been used.
OFPBRC_BUFFER_UNKNOWN = 8       # Specified buffer does not exist.
OFPBRC_BAD_TABLE_ID = 9         # Specified table-id invalid or does not exist.
OFPBRC_IS_SLAVE = 10            # Denied because controller is slave.
OFPBRC_BAD_PORT = 11            # Invalid port.
OFPBRC_BAD_PACKET = 12          # Invalid packet in packet-out

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
OFPFMFC_UNKNOWN = 0             # Unspecified error.
OFPFMFC_TABLE_FULL = 1          # Flow not added because table was full.
OFPFMFC_BAD_TABLE_ID = 2        # Table does not exist
OFPFMFC_OVERLAP = 3             # Attempted to add overlapping flow
                                # with CHECK_OVERLAP flag set.
OFPFMFC_EPERM = 4               # Permissions error.
OFPFMFC_BAD_TIMEOUT = 5         # Flow not added because of
                                # unsupported idle/hard timeout.
OFPFMFC_BAD_COMMAND = 6         # Unsupported or unknown command.
OFPFMFC_BAD_FLAGS = 7           # Unsupported or unknown flags.

# enum ofp_group_mod_failed_code
OFPGMFC_GROUP_EXISTS = 0
OFPGMFC_INVALID_GROUP = 1
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
OFPGMFC_UNKNOWN_GROUP = 8           # Group not modified because a group
                                    # MODIFY attempted to modify a
                                    # non-existent group.
OFPGMFC_CHAINED_GROUP = 9           # Group not deleted because another
                                    # group is forwarding to it.
OFPGMFC_BAD_TYPE = 10               # Unsupported or unknown group type.
OFPGMFC_BAD_COMMAND = 11            # Unsupported or unknown command.
OFPGMFC_BAD_BUCKET = 12             # Error in bucket.
OFPGMFC_BAD_WATCH = 13              # Error in watch port/group.
OFPGMFC_EPERM = 14                  # Permissions error.

# enum ofp_port_mod_failed_code
OFPPMFC_BAD_PORT = 0        # Specified port does not exist.
OFPPMFC_BAD_HW_ADDR = 1     # Specified hardware address does not
                            # match the port number.
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
OFPQCFC_EPERM = 2           # Permissions error (depracated).
                            # New or updated Ryu applications shall use
                            # OFPSCFC_EPERM. The variable name is a typo of
                            # in specifications before v1.3.1 (EXT-208).
OFPSCFC_EPERM = 2           # Permissions error.
                            # Ported back to ofproto_v1_2 for consistency with
                            # later OF specs (EXT-208).

# enum ofp_role_request_failed_code
OFPRRFC_STALE = 0           # Stale Message: old generation_id.
OFPRRFC_UNSUP = 1           # Controller role change unsupported.
OFPRRFC_BAD_ROLE = 2        # Invalid role.

# struct ofp_error_experimenter_msg
OFP_ERROR_EXPERIMENTER_MSG_PACK_STR = '!HHI'
OFP_ERROR_EXPERIMENTER_MSG_SIZE = 16
assert (calcsize(OFP_ERROR_EXPERIMENTER_MSG_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_ERROR_EXPERIMENTER_MSG_SIZE)

# struct ofp_experimenter_header
OFP_EXPERIMENTER_HEADER_PACK_STR = '!II'
OFP_EXPERIMENTER_HEADER_SIZE = 16
assert (calcsize(OFP_EXPERIMENTER_HEADER_PACK_STR) + OFP_HEADER_SIZE ==
        OFP_EXPERIMENTER_HEADER_SIZE)


# OXM


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
    # EXT-256 Old version of ONF Extension
    oxm_fields.OldONFExperimenter('pbb_uca', 2560, type_desc.Int1),
    # EXT-109 TCP flags match field Extension
    oxm_fields.ONFExperimenter('tcp_flags', 42, type_desc.Int2),
    # EXT-233 Output match Extension
    # NOTE(yamamoto): The spec says uint64_t but I assume it's an error.
    oxm_fields.ONFExperimenter('actset_output', 43, type_desc.Int4),
] + nicira_ext.oxm_types

oxm_fields.generate(__name__)

# generate utility methods
ofproto_utils.generate(__name__)

# define constants
OFP_VERSION = 0x03
OFP_TCP_PORT = 6633

MAX_XID = 0xffffffff

OFP_NO_BUFFER = 0xffffffff
