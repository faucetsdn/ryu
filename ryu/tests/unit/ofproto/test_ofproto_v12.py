# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
from nose.tools import eq_
from ryu.ofproto.ofproto_v1_2 import *


LOG = logging.getLogger('test_ofproto_v12')


class TestOfprot12(unittest.TestCase):
    """ Test case for ofproto_v1_2
    """

    def test_struct_ofp_header(self):
        eq_(OFP_HEADER_PACK_STR, '!BBHI')
        eq_(OFP_HEADER_SIZE, 8)

    def test_enum_ofp_type(self):
        eq_(OFPT_HELLO, 0)
        eq_(OFPT_ERROR, 1)
        eq_(OFPT_ECHO_REQUEST, 2)
        eq_(OFPT_ECHO_REPLY, 3)
        eq_(OFPT_EXPERIMENTER, 4)
        eq_(OFPT_FEATURES_REQUEST, 5)
        eq_(OFPT_FEATURES_REPLY, 6)
        eq_(OFPT_GET_CONFIG_REQUEST, 7)
        eq_(OFPT_GET_CONFIG_REPLY, 8)
        eq_(OFPT_SET_CONFIG, 9)
        eq_(OFPT_PACKET_IN, 10)
        eq_(OFPT_FLOW_REMOVED, 11)
        eq_(OFPT_PORT_STATUS, 12)
        eq_(OFPT_PACKET_OUT, 13)
        eq_(OFPT_FLOW_MOD, 14)
        eq_(OFPT_GROUP_MOD, 15)
        eq_(OFPT_PORT_MOD, 16)
        eq_(OFPT_TABLE_MOD, 17)
        eq_(OFPT_STATS_REQUEST, 18)
        eq_(OFPT_STATS_REPLY, 19)
        eq_(OFPT_BARRIER_REQUEST, 20)
        eq_(OFPT_BARRIER_REPLY, 21)
        eq_(OFPT_QUEUE_GET_CONFIG_REQUEST, 22)
        eq_(OFPT_QUEUE_GET_CONFIG_REPLY, 23)
        eq_(OFPT_ROLE_REQUEST, 24)
        eq_(OFPT_ROLE_REPLY, 25)

    def test_struct_ofp_port(self):
        eq_(OFP_PORT_PACK_STR, '!I4x6s2x16sIIIIIIII')
        eq_(OFP_PORT_SIZE, 64)

    def test_enum_ofp_port_config(self):
        eq_(OFPPC_PORT_DOWN, 1 << 0)
        eq_(OFPPC_NO_RECV, 1 << 2)
        eq_(OFPPC_NO_FWD, 1 << 5)
        eq_(OFPPC_NO_PACKET_IN, 1 << 6)

    def test_enum_ofp_port_state(self):
        eq_(OFPPS_LINK_DOWN, 1 << 0)
        eq_(OFPPS_BLOCKED, 1 << 1)
        eq_(OFPPS_LIVE, 1 << 2)

    def test_enum_ofp_port_no(self):
        eq_(OFPP_MAX, 0xffffff00)
        eq_(OFPP_IN_PORT, 0xfffffff8)
        eq_(OFPP_TABLE, 0xfffffff9)
        eq_(OFPP_NORMAL, 0xfffffffa)
        eq_(OFPP_FLOOD, 0xfffffffb)
        eq_(OFPP_ALL, 0xfffffffc)
        eq_(OFPP_CONTROLLER, 0xfffffffd)
        eq_(OFPP_LOCAL, 0xfffffffe)
        eq_(OFPP_ANY, 0xffffffff)
        eq_(OFPQ_ALL, 0xffffffff)

    def test_enum_ofp_port_features(self):
        eq_(OFPPF_10MB_HD, 1 << 0)
        eq_(OFPPF_10MB_FD, 1 << 1)
        eq_(OFPPF_100MB_HD, 1 << 2)
        eq_(OFPPF_100MB_FD, 1 << 3)
        eq_(OFPPF_1GB_HD, 1 << 4)
        eq_(OFPPF_1GB_FD, 1 << 5)
        eq_(OFPPF_10GB_FD, 1 << 6)
        eq_(OFPPF_40GB_FD, 1 << 7)
        eq_(OFPPF_100GB_FD, 1 << 8)
        eq_(OFPPF_1TB_FD, 1 << 9)
        eq_(OFPPF_OTHER, 1 << 10)
        eq_(OFPPF_COPPER, 1 << 11)
        eq_(OFPPF_FIBER, 1 << 12)
        eq_(OFPPF_AUTONEG, 1 << 13)
        eq_(OFPPF_PAUSE, 1 << 14)
        eq_(OFPPF_PAUSE_ASYM, 1 << 15)

    def test_struct_ofp_packet_queue(self):
        eq_(OFP_PACKET_QUEUE_PACK_STR, '!IIH6x')
        eq_(OFP_PACKET_QUEUE_SIZE, 16)

    def test_enum_ofp_queue_properties(self):
        eq_(OFPQT_MIN_RATE, 1)
        eq_(OFPQT_MAX_RATE, 2)
        eq_(OFPQT_EXPERIMENTER, 0xffff)

    def test_struct_ofp_queue_prop_header(self):
        eq_(OFP_QUEUE_PROP_HEADER_PACK_STR, '!HH4x')
        eq_(OFP_QUEUE_PROP_HEADER_SIZE, 8)

    def test_struct_ofp_queue_prop_min_rate(self):
        eq_(OFP_QUEUE_PROP_MIN_RATE_PACK_STR, '!H6x')
        eq_(OFP_QUEUE_PROP_MIN_RATE_SIZE, 16)

    def test_struct_ofp_queue_prop_max_rate(self):
        eq_(OFP_QUEUE_PROP_MAX_RATE_PACK_STR, '!H6x')
        eq_(OFP_QUEUE_PROP_MAX_RATE_SIZE, 16)

    def test_struct_ofp_queue_prop_experimenter(self):
        eq_(OFP_QUEUE_PROP_EXPERIMENTER_PACK_STR, '!I4x')
        eq_(OFP_QUEUE_PROP_EXPERIMENTER_SIZE, 16)

    def test_struct_ofp_match(self):
        eq_(OFP_MATCH_PACK_STR, '!HHBBBB')
        eq_(OFP_MATCH_SIZE, 8)

    def test_enum_ofp_match_type(self):
        eq_(OFPMT_STANDARD, 0)
        eq_(OFPMT_OXM, 1)

    def test_enum_ofp_oxm_class(self):
        eq_(OFPXMC_NXM_0, 0x0000)
        eq_(OFPXMC_NXM_1, 0x0001)
        eq_(OFPXMC_OPENFLOW_BASIC, 0x8000)
        eq_(OFPXMC_EXPERIMENTER, 0xFFFF)

    def test_enmu_oxm_ofb_match_fields(self):
        eq_(OFPXMT_OFB_IN_PORT, 0)
        eq_(OFPXMT_OFB_IN_PHY_PORT, 1)
        eq_(OFPXMT_OFB_METADATA, 2)
        eq_(OFPXMT_OFB_ETH_DST, 3)
        eq_(OFPXMT_OFB_ETH_SRC, 4)
        eq_(OFPXMT_OFB_ETH_TYPE, 5)
        eq_(OFPXMT_OFB_VLAN_VID, 6)
        eq_(OFPXMT_OFB_VLAN_PCP, 7)
        eq_(OFPXMT_OFB_IP_DSCP, 8)
        eq_(OFPXMT_OFB_IP_ECN, 9)
        eq_(OFPXMT_OFB_IP_PROTO, 10)
        eq_(OFPXMT_OFB_IPV4_SRC, 11)
        eq_(OFPXMT_OFB_IPV4_DST, 12)
        eq_(OFPXMT_OFB_TCP_SRC, 13)
        eq_(OFPXMT_OFB_TCP_DST, 14)
        eq_(OFPXMT_OFB_UDP_SRC, 15)
        eq_(OFPXMT_OFB_UDP_DST, 16)
        eq_(OFPXMT_OFB_SCTP_SRC, 17)
        eq_(OFPXMT_OFB_SCTP_DST, 18)
        eq_(OFPXMT_OFB_ICMPV4_TYPE, 19)
        eq_(OFPXMT_OFB_ICMPV4_CODE, 20)
        eq_(OFPXMT_OFB_ARP_OP, 21)
        eq_(OFPXMT_OFB_ARP_SPA, 22)
        eq_(OFPXMT_OFB_ARP_TPA, 23)
        eq_(OFPXMT_OFB_ARP_SHA, 24)
        eq_(OFPXMT_OFB_ARP_THA, 25)
        eq_(OFPXMT_OFB_IPV6_SRC, 26)
        eq_(OFPXMT_OFB_IPV6_DST, 27)
        eq_(OFPXMT_OFB_IPV6_FLABEL, 28)
        eq_(OFPXMT_OFB_ICMPV6_TYPE, 29)
        eq_(OFPXMT_OFB_ICMPV6_CODE, 30)
        eq_(OFPXMT_OFB_IPV6_ND_TARGET, 31)
        eq_(OFPXMT_OFB_IPV6_ND_SLL, 32)
        eq_(OFPXMT_OFB_IPV6_ND_TLL, 33)
        eq_(OFPXMT_OFB_MPLS_LABEL, 34)
        eq_(OFPXMT_OFB_MPLS_TC, 35)

    def test_enum_ofp_vlan_id(self):
        eq_(OFPVID_PRESENT, 0x1000)
        eq_(OFPVID_NONE, 0x0000)

    def test_struct_ofp_oxm_experimenter_header(self):
        eq_(OFP_OXM_EXPERIMENTER_HEADER_PACK_STR, '!II')
        eq_(OFP_OXM_EXPERIMENTER_HEADER_SIZE, 8)

    def test_enum_ofp_instruction_type(self):
        eq_(OFPIT_GOTO_TABLE, 1)
        eq_(OFPIT_WRITE_METADATA, 2)
        eq_(OFPIT_WRITE_ACTIONS, 3)
        eq_(OFPIT_APPLY_ACTIONS, 4)
        eq_(OFPIT_CLEAR_ACTIONS, 5)
        eq_(OFPIT_EXPERIMENTER, 0xFFFF)

    def test_struct_ofp_instruction_goto_table(self):
        eq_(OFP_INSTRUCTION_GOTO_TABLE_PACK_STR, '!HHB3x')
        eq_(OFP_INSTRUCTION_GOTO_TABLE_SIZE, 8)

    def test_struct_ofp_instruction_write_metadata(self):
        eq_(OFP_INSTRUCTION_WRITE_METADATA_PACK_STR, '!HH4xQQ')
        eq_(OFP_INSTRUCTION_WRITE_METADATA_SIZE, 24)

    def test_struct_ofp_instaruction_actions(self):
        eq_(OFP_INSTRUCTION_ACTIONS_PACK_STR, '!HH4x')
        eq_(OFP_INSTRUCTION_ACTIONS_SIZE, 8)

    def test_enum_ofp_action_type(self):
        eq_(OFPAT_OUTPUT, 0)
        eq_(OFPAT_COPY_TTL_OUT, 11)
        eq_(OFPAT_COPY_TTL_IN, 12)
        eq_(OFPAT_SET_MPLS_TTL, 15)
        eq_(OFPAT_DEC_MPLS_TTL, 16)
        eq_(OFPAT_PUSH_VLAN, 17)
        eq_(OFPAT_POP_VLAN, 18)
        eq_(OFPAT_PUSH_MPLS, 19)
        eq_(OFPAT_POP_MPLS, 20)
        eq_(OFPAT_SET_QUEUE, 21)
        eq_(OFPAT_GROUP, 22)
        eq_(OFPAT_SET_NW_TTL, 23)
        eq_(OFPAT_DEC_NW_TTL, 24)
        eq_(OFPAT_SET_FIELD, 25)
        eq_(OFPAT_EXPERIMENTER, 0xffff)

    def test_struct_ofp_action_header(self):
        eq_(OFP_ACTION_HEADER_PACK_STR, '!HH4x')
        eq_(OFP_ACTION_HEADER_SIZE, 8)

    def test_struct_ofp_action_output(self):
        eq_(OFP_ACTION_OUTPUT_PACK_STR, '!HHIH6x')
        eq_(OFP_ACTION_OUTPUT_SIZE, 16)

    def test_enum_ofp_controller_max_len(self):
        eq_(OFPCML_MAX, 0xffe5)
        eq_(OFPCML_NO_BUFFER, 0xffff)

    def test_struct_ofp_action_group(self):
        eq_(OFP_ACTION_GROUP_PACK_STR, '!HHI')
        eq_(OFP_ACTION_GROUP_SIZE, 8)

    def test_struct_ofp_action_set_queue(self):
        eq_(OFP_ACTION_SET_QUEUE_PACK_STR, '!HHI')
        eq_(OFP_ACTION_SET_QUEUE_SIZE, 8)

    def test_struct_ofp_aciton_mpls_ttl(self):
        eq_(OFP_ACTION_MPLS_TTL_PACK_STR, '!HHB3x')
        eq_(OFP_ACTION_MPLS_TTL_SIZE, 8)

    def test_struct_ofp_action_nw_ttl(self):
        eq_(OFP_ACTION_NW_TTL_PACK_STR, '!HHB3x')
        eq_(OFP_ACTION_NW_TTL_SIZE, 8)

    def test_struct_ofp_action_push(self):
        eq_(OFP_ACTION_PUSH_PACK_STR, '!HHH2x')
        eq_(OFP_ACTION_PUSH_SIZE, 8)

    def test_struct_ofp_action_pop_mpls(self):
        eq_(OFP_ACTION_POP_MPLS_PACK_STR, '!HHH2x')
        eq_(OFP_ACTION_POP_MPLS_SIZE, 8)

    def test_struct_ofp_action_set_field(self):
        eq_(OFP_ACTION_SET_FIELD_PACK_STR, '!HH4B')
        eq_(OFP_ACTION_SET_FIELD_SIZE, 8)

    def test_struct_ofp_action_experimenter_header(self):
        eq_(OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR, '!HHI')
        eq_(OFP_ACTION_EXPERIMENTER_HEADER_SIZE, 8)

    def test_struct_ofp_switch_feature(self):
        eq_(OFP_SWITCH_FEATURES_PACK_STR, '!QIB3xII')
        eq_(OFP_SWITCH_FEATURES_SIZE, 32)

    def test_enum_ofp_capabilities(self):
        eq_(OFPC_FLOW_STATS, 1 << 0)
        eq_(OFPC_TABLE_STATS, 1 << 1)
        eq_(OFPC_PORT_STATS, 1 << 2)
        eq_(OFPC_GROUP_STATS, 1 << 3)
        eq_(OFPC_IP_REASM, 1 << 5)
        eq_(OFPC_QUEUE_STATS, 1 << 6)
        eq_(OFPC_PORT_BLOCKED, 1 << 8)

    def test_struct_ofp_switch_config(self):
        eq_(OFP_SWITCH_CONFIG_PACK_STR, '!HH')
        eq_(OFP_SWITCH_CONFIG_SIZE, 12)

    def test_enum_ofp_config_flags(self):
        eq_(OFPC_FRAG_NORMAL, 0)
        eq_(OFPC_FRAG_DROP, 1 << 0)
        eq_(OFPC_FRAG_REASM, 1 << 1)
        eq_(OFPC_FRAG_MASK, 3)
        eq_(OFPC_INVALID_TTL_TO_CONTROLLER, 1 << 2)

    def test_enum_ofp_table(self):
        eq_(OFPTT_MAX, 0xfe)
        eq_(OFPTT_ALL, 0xff)

    def test_struct_ofp_table_mod(self):
        eq_(OFP_TABLE_MOD_PACK_STR, '!B3xI')
        eq_(OFP_TABLE_MOD_SIZE, 16)

    def test_enum_ofp_table_config(self):
        eq_(OFPTC_TABLE_MISS_CONTROLLER, 0)
        eq_(OFPTC_TABLE_MISS_CONTINUE, 1 << 0)
        eq_(OFPTC_TABLE_MISS_DROP, 1 << 1)
        eq_(OFPTC_TABLE_MISS_MASK, 3)

    def test_struct_ofp_flow_mod(self):
        eq_(OFP_FLOW_MOD_PACK_STR, '!QQBBHHHIIIH2xHHBBBB')
        eq_(OFP_FLOW_MOD_SIZE, 56)

    def test_enum_ofp_flow_mod_command(self):
        eq_(OFPFC_ADD, 0)
        eq_(OFPFC_MODIFY, 1)
        eq_(OFPFC_MODIFY_STRICT, 2)
        eq_(OFPFC_DELETE, 3)
        eq_(OFPFC_DELETE_STRICT, 4)

    def test_enum_ofp_flow_mod_flags(self):
        eq_(OFPFF_SEND_FLOW_REM, 1 << 0)
        eq_(OFPFF_CHECK_OVERLAP, 1 << 1)
        eq_(OFPFF_RESET_COUNTS, 1 << 2)

    def test_struct_ofp_group_mod(self):
        eq_(OFP_GROUP_MOD_PACK_STR, '!HBxI')
        eq_(OFP_GROUP_MOD_SIZE, 16)

    # same to OFPP_*
    def test_enum_ofp_group(self):
        eq_(OFPG_MAX, 0xffffff00)
        eq_(OFPG_ALL, 0xfffffffc)
        eq_(OFPG_ANY, 0xffffffff)

    def test_enum_ofp_group_mod_command(self):
        eq_(OFPGC_ADD, 0)
        eq_(OFPGC_MODIFY, 1)
        eq_(OFPGC_DELETE, 2)

    def test_enum_ofp_group_type(self):
        eq_(OFPGT_ALL, 0)
        eq_(OFPGT_SELECT, 1)
        eq_(OFPGT_INDIRECT, 2)
        eq_(OFPGT_FF, 3)

    def test_struct_ofp_bucket(self):
        eq_(OFP_BUCKET_PACK_STR, '!HHII4x')
        eq_(OFP_BUCKET_SIZE, 16)

    def test_struct_ofp_port_mod(self):
        eq_(OFP_PORT_MOD_PACK_STR, '!I4x6s2xIII4x')
        eq_(OFP_PORT_MOD_SIZE, 40)

    def test_sturct_ofp_stats_request(self):
        eq_(OFP_STATS_REQUEST_PACK_STR, '!HH4x')
        eq_(OFP_STATS_REQUEST_SIZE, 16)

    # OFPSF_REQ_* flags (none yet defined).
    # The only value defined for flags in a reply is whether more
    # replies will follow this one - this has the value 0x0001.
    def test_enum_ofp_stats_reply_flags(self):
        eq_(OFPSF_REPLY_MORE, 0x0001)

    def test_struct_ofp_stats_reply(self):
        eq_(OFP_STATS_REPLY_PACK_STR, '!HH4x')
        eq_(OFP_STATS_REPLY_SIZE, 16)

    def test_enum_ofp_stats_types(self):
        eq_(OFPST_DESC, 0)
        eq_(OFPST_FLOW, 1)
        eq_(OFPST_AGGREGATE, 2)
        eq_(OFPST_TABLE, 3)
        eq_(OFPST_PORT, 4)
        eq_(OFPST_QUEUE, 5)
        eq_(OFPST_GROUP, 6)
        eq_(OFPST_GROUP_DESC, 7)
        eq_(OFPST_GROUP_FEATURES, 8)
        eq_(OFPST_EXPERIMENTER, 0xffff)

    def test_struct_ofp_desc_stats(self):
        eq_(OFP_DESC_STATS_PACK_STR, '!256s256s256s32s256s')
        eq_(OFP_DESC_STATS_SIZE, 1056)

    def test_struct_ofp_flow_stats_request(self):
        eq_(OFP_FLOW_STATS_REQUEST_PACK_STR, '!B3xII4xQQ')
        eq_(OFP_FLOW_STATS_REQUEST_SIZE, 40)

    def test_struct_ofp_flow_stats(self):
        eq_(OFP_FLOW_STATS_PACK_STR, '!HBxIIHHH6xQQQ')
        eq_(OFP_FLOW_STATS_SIZE, 56)

    def test_struct_ofp_aggregate_stats_request(self):
        eq_(OFP_AGGREGATE_STATS_REQUEST_PACK_STR, '!B3xII4xQQ')
        eq_(OFP_AGGREGATE_STATS_REQUEST_SIZE, 40)

    def test_struct_ofp_aggregate_stats_reply(self):
        eq_(OFP_AGGREGATE_STATS_REPLY_PACK_STR, '!QQI4x')
        eq_(OFP_AGGREGATE_STATS_REPLY_SIZE, 24)

    def test_sturct_ofp_table_stats(self):
        eq_(OFP_TABLE_STATS_PACK_STR, '!B7x32sQQIIQQQQIIIIQQ')
        eq_(OFP_TABLE_STATS_SIZE, 128)

    def test_struct_ofp_port_stats_request(self):
        eq_(OFP_PORT_STATS_REQUEST_PACK_STR, '!I4x')
        eq_(OFP_PORT_STATS_REQUEST_SIZE, 8)

    def test_struct_ofp_port_stats(self):
        eq_(OFP_PORT_STATS_PACK_STR, '!I4xQQQQQQQQQQQQ')
        eq_(OFP_PORT_STATS_SIZE, 104)

    def test_struct_ofp_queue_stats_request(self):
        eq_(OFP_QUEUE_STATS_REQUEST_PACK_STR, '!II')
        eq_(OFP_QUEUE_STATS_REQUEST_SIZE, 8)

    def test_struct_ofp_queue_stats(self):
        eq_(OFP_QUEUE_STATS_PACK_STR, '!IIQQQ')
        eq_(OFP_QUEUE_STATS_SIZE, 32)

    def test_struct_ofp_group_stats_request(self):
        eq_(OFP_GROUP_STATS_REQUEST_PACK_STR, '!I4x')
        eq_(OFP_GROUP_STATS_REQUEST_SIZE, 8)

    def test_struct_ofp_group_stats(self):
        eq_(OFP_GROUP_STATS_PACK_STR, '!H2xII4xQQ')
        eq_(OFP_GROUP_STATS_SIZE, 32)

    def test_struct_ofp_bucket_counter(self):
        eq_(OFP_BUCKET_COUNTER_PACK_STR, '!QQ')
        eq_(OFP_BUCKET_COUNTER_SIZE, 16)

    def test_struct_ofp_group_desc_stats(self):
        eq_(OFP_GROUP_DESC_STATS_PACK_STR, '!HBxI')
        eq_(OFP_GROUP_DESC_STATS_SIZE, 8)

    def test_struct_ofp_group_features_stats(self):
        eq_(OFP_GROUP_FEATURES_STATS_PACK_STR, '!II4I4I')
        eq_(OFP_GROUP_FEATURES_STATS_SIZE, 40)

    def test_enmu_ofp_group_capabilities(self):
        eq_(OFPGFC_SELECT_WEIGHT, 1 << 0)
        eq_(OFPGFC_SELECT_LIVENESS, 1 << 1)
        eq_(OFPGFC_CHAINING, 1 << 2)
        eq_(OFPGFC_CHAINING_CHECKS, 1 << 3)

    def test_struct_ofp_experimenter_stats_header(self):
        eq_(OFP_EXPERIMENTER_STATS_HEADER_PACK_STR, '!II')
        eq_(OFP_EXPERIMENTER_STATS_HEADER_SIZE, 8)

    def test_struct_opf_queue_get_config_request(self):
        eq_(OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR, '!I4x')
        eq_(OFP_QUEUE_GET_CONFIG_REQUEST_SIZE, 16)

    def test_struct_ofp_queue_get_config_reply(self):
        eq_(OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR, '!I4x')
        eq_(OFP_QUEUE_GET_CONFIG_REPLY_SIZE, 16)

    def test_struct_ofp_packet_out(self):
        eq_(OFP_PACKET_OUT_PACK_STR, '!IIH6x')
        eq_(OFP_PACKET_OUT_SIZE, 24)

    def test_struct_ofp_role_request(self):
        eq_(OFP_ROLE_REQUEST_PACK_STR, '!I4xQ')
        eq_(OFP_ROLE_REQUEST_SIZE, 24)

    def test_enum_ofp_controller_role(self):
        eq_(OFPCR_ROLE_NOCHANGE, 0)
        eq_(OFPCR_ROLE_EQUAL, 1)
        eq_(OFPCR_ROLE_MASTER, 2)
        eq_(OFPCR_ROLE_SLAVE, 3)

    def test_struct_ofp_packet_in(self):
        eq_(OFP_PACKET_IN_PACK_STR, '!IHBB')
        eq_(OFP_PACKET_IN_SIZE, 24)

    def test_enum_ofp_packet_in_reason(self):
        eq_(OFPR_NO_MATCH, 0)
        eq_(OFPR_ACTION, 1)
        eq_(OFPR_INVALID_TTL, 2)

    def test_struct_ofp_flow_removed(self):
        eq_(OFP_FLOW_REMOVED_PACK_STR, '!QHBBIIHHQQHHBBBB')
        eq_(OFP_FLOW_REMOVED_PACK_STR0, '!QHBBIIHHQQ')
        eq_(OFP_FLOW_REMOVED_SIZE, 56)

    def test_enum_ofp_flow_removed_reason(self):
        eq_(OFPRR_IDLE_TIMEOUT, 0)
        eq_(OFPRR_HARD_TIMEOUT, 1)
        eq_(OFPRR_DELETE, 2)
        eq_(OFPRR_GROUP_DELETE, 3)

    def test_struct_ofp_port_status(self):
        eq_(OFP_PORT_STATUS_PACK_STR, '!B7xI4x6s2x16sIIIIIIII')
        eq_(OFP_PORT_STATUS_DESC_OFFSET, 16)
        eq_(OFP_PORT_STATUS_SIZE, 80)

    def test_enum_ofp_port_reason(self):
        eq_(OFPPR_ADD, 0)
        eq_(OFPPR_DELETE, 1)
        eq_(OFPPR_MODIFY, 2)

    def test_struct_ofp_error_msg(self):
        eq_(OFP_ERROR_MSG_PACK_STR, '!HH')
        eq_(OFP_ERROR_MSG_SIZE, 12)

    def test_enum_ofp_error_type(self):
        eq_(OFPET_HELLO_FAILED, 0)
        eq_(OFPET_BAD_REQUEST, 1)
        eq_(OFPET_BAD_ACTION, 2)
        eq_(OFPET_BAD_INSTRUCTION, 3)
        eq_(OFPET_BAD_MATCH, 4)
        eq_(OFPET_FLOW_MOD_FAILED, 5)
        eq_(OFPET_GROUP_MOD_FAILED, 6)
        eq_(OFPET_PORT_MOD_FAILED, 7)
        eq_(OFPET_TABLE_MOD_FAILED, 8)
        eq_(OFPET_QUEUE_OP_FAILED, 9)
        eq_(OFPET_SWITCH_CONFIG_FAILED, 10)
        eq_(OFPET_ROLE_REQUEST_FAILED, 11)
        eq_(OFPET_EXPERIMENTER, 0xffff)

    def test_enum_ofp_hello_failed_code(self):
        eq_(OFPHFC_INCOMPATIBLE, 0)
        eq_(OFPHFC_EPERM, 1)

    def test_enum_ofp_bad_request_code(self):
        eq_(OFPBRC_BAD_VERSION, 0)
        eq_(OFPBRC_BAD_TYPE, 1)
        eq_(OFPBRC_BAD_STAT, 2)
        eq_(OFPBRC_BAD_EXPERIMENTER, 3)
        eq_(OFPBRC_BAD_EXP_TYPE, 4)
        eq_(OFPBRC_EPERM, 5)
        eq_(OFPBRC_BAD_LEN, 6)
        eq_(OFPBRC_BUFFER_EMPTY, 7)
        eq_(OFPBRC_BUFFER_UNKNOWN, 8)
        eq_(OFPBRC_BAD_TABLE_ID, 9)
        eq_(OFPBRC_IS_SLAVE, 10)
        eq_(OFPBRC_BAD_PORT, 11)
        eq_(OFPBRC_BAD_PACKET, 12)

    def test_enum_ofp_bad_action_code(self):
        eq_(OFPBAC_BAD_TYPE, 0)
        eq_(OFPBAC_BAD_LEN, 1)
        eq_(OFPBAC_BAD_EXPERIMENTER, 2)
        eq_(OFPBAC_BAD_EXP_TYPE, 3)
        eq_(OFPBAC_BAD_OUT_PORT, 4)
        eq_(OFPBAC_BAD_ARGUMENT, 5)
        eq_(OFPBAC_EPERM, 6)
        eq_(OFPBAC_TOO_MANY, 7)
        eq_(OFPBAC_BAD_QUEUE, 8)
        eq_(OFPBAC_BAD_OUT_GROUP, 9)
        eq_(OFPBAC_MATCH_INCONSISTENT, 10)
        eq_(OFPBAC_UNSUPPORTED_ORDER, 11)
        eq_(OFPBAC_BAD_TAG, 12)
        eq_(OFPBAC_BAD_SET_TYPE, 13)
        eq_(OFPBAC_BAD_SET_LEN, 14)
        eq_(OFPBAC_BAD_SET_ARGUMENT, 15)

    def test_enum_ofp_bad_instruction_code(self):
        eq_(OFPBIC_UNKNOWN_INST, 0)
        eq_(OFPBIC_UNSUP_INST, 1)
        eq_(OFPBIC_BAD_TABLE_ID, 2)
        eq_(OFPBIC_UNSUP_METADATA, 3)
        eq_(OFPBIC_UNSUP_METADATA_MASK, 4)
        eq_(OFPBIC_BAD_EXPERIMENTER, 5)
        eq_(OFPBIC_BAD_EXP_TYPE, 6)
        eq_(OFPBIC_BAD_LEN, 7)
        eq_(OFPBIC_EPERM, 8)

    def test_enum_ofp_bad_match_code(self):
        eq_(OFPBMC_BAD_TYPE, 0)
        eq_(OFPBMC_BAD_LEN, 1)
        eq_(OFPBMC_BAD_TAG, 2)
        eq_(OFPBMC_BAD_DL_ADDR_MASK, 3)
        eq_(OFPBMC_BAD_NW_ADDR_MASK, 4)
        eq_(OFPBMC_BAD_WILDCARDS, 5)
        eq_(OFPBMC_BAD_FIELD, 6)
        eq_(OFPBMC_BAD_VALUE, 7)
        eq_(OFPBMC_BAD_MASK, 8)
        eq_(OFPBMC_BAD_PREREQ, 9)
        eq_(OFPBMC_DUP_FIELD, 10)
        eq_(OFPBMC_EPERM, 11)

    def test_enum_ofp_flow_mod_failed_code(self):
        eq_(OFPFMFC_UNKNOWN, 0)
        eq_(OFPFMFC_TABLE_FULL, 1)
        eq_(OFPFMFC_BAD_TABLE_ID, 2)
        eq_(OFPFMFC_OVERLAP, 3)
        eq_(OFPFMFC_EPERM, 4)
        eq_(OFPFMFC_BAD_TIMEOUT, 5)
        eq_(OFPFMFC_BAD_COMMAND, 6)
        eq_(OFPFMFC_BAD_FLAGS, 7)

    def test_enum_ofp_group_mod_failed_code(self):
        eq_(OFPGMFC_GROUP_EXISTS, 0)
        eq_(OFPGMFC_INVALID_GROUP, 1)
        eq_(OFPGMFC_WEIGHT_UNSUPPORTED, 2)
        eq_(OFPGMFC_OUT_OF_GROUPS, 3)
        eq_(OFPGMFC_OUT_OF_BUCKETS, 4)
        eq_(OFPGMFC_CHAINING_UNSUPPORTED, 5)
        eq_(OFPGMFC_WATCH_UNSUPPORTED, 6)
        eq_(OFPGMFC_LOOP, 7)
        eq_(OFPGMFC_UNKNOWN_GROUP, 8)
        eq_(OFPGMFC_CHAINED_GROUP, 9)
        eq_(OFPGMFC_BAD_TYPE, 10)
        eq_(OFPGMFC_BAD_COMMAND, 11)
        eq_(OFPGMFC_BAD_BUCKET, 12)
        eq_(OFPGMFC_BAD_WATCH, 13)
        eq_(OFPGMFC_EPERM, 14)

    def test_enum_ofp_port_mod_failed_code(self):
        eq_(OFPPMFC_BAD_PORT, 0)
        eq_(OFPPMFC_BAD_HW_ADDR, 1)
        eq_(OFPPMFC_BAD_CONFIG, 2)
        eq_(OFPPMFC_BAD_ADVERTISE, 3)
        eq_(OFPPMFC_EPERM, 4)

    def test_enum_ofp_table_mod_failed_code(self):
        eq_(OFPTMFC_BAD_TABLE, 0)
        eq_(OFPTMFC_BAD_CONFIG, 1)
        eq_(OFPTMFC_EPERM, 2)

    def test_enum_ofp_queue_op_failed_code(self):
        eq_(OFPQOFC_BAD_PORT, 0)
        eq_(OFPQOFC_BAD_QUEUE, 1)
        eq_(OFPQOFC_EPERM, 2)

    def test_enum_ofp_switch_config_failed_code(self):
        eq_(OFPSCFC_BAD_FLAGS, 0)
        eq_(OFPSCFC_BAD_LEN, 1)
        eq_(OFPSCFC_EPERM, 2)

    def test_enum_ofp_role_request_failed_code(self):
        eq_(OFPRRFC_STALE, 0)
        eq_(OFPRRFC_UNSUP, 1)
        eq_(OFPRRFC_BAD_ROLE, 2)

    def test_struct_ofp_error_experimenter_msg(self):
        eq_(OFP_ERROR_EXPERIMENTER_MSG_PACK_STR, '!HHI')
        eq_(OFP_ERROR_EXPERIMENTER_MSG_SIZE, 16)

    def test_struct_ofp_experimenter_header(self):
        eq_(OFP_EXPERIMENTER_HEADER_PACK_STR, '!II')
        eq_(OFP_EXPERIMENTER_HEADER_SIZE, 16)

    # OXM is interpreted as a 32-bit word in network byte order.
    # - oxm_class   17-bit to 32-bit (OFPXMC_*).
    # - oxm_field   10-bit to 16-bit (OFPXMT_OFB_*).
    # - oxm_hasmask  9-bit           (Set if OXM include a bitmask).
    # - oxm_length   1-bit to 8-bit  (Lenght of OXM payload).
    def _test_OXM(self, value, class_, field, hasmask, length):
        virfy = (class_ << 16) | (field << 9) | (hasmask << 8) | length
        eq_(value >> 32, 0)
        eq_(value, virfy)

    def _test_OXM_basic(self, value, field, hasmask, length):
        self._test_OXM(value, OFPXMC_OPENFLOW_BASIC, field, hasmask, length)

    def test_OXM_basic(self):
        self._test_OXM_basic(OXM_OF_IN_PORT, OFPXMT_OFB_IN_PORT, 0, 4)
        self._test_OXM_basic(OXM_OF_IN_PHY_PORT, OFPXMT_OFB_IN_PHY_PORT, 0, 4)
        self._test_OXM_basic(OXM_OF_METADATA, OFPXMT_OFB_METADATA, 0, 8)
        self._test_OXM_basic(OXM_OF_METADATA_W, OFPXMT_OFB_METADATA, 1, 16)
        self._test_OXM_basic(OXM_OF_ETH_DST, OFPXMT_OFB_ETH_DST, 0, 6)
        self._test_OXM_basic(OXM_OF_ETH_DST_W, OFPXMT_OFB_ETH_DST, 1, 12)
        self._test_OXM_basic(OXM_OF_ETH_SRC, OFPXMT_OFB_ETH_SRC, 0, 6)
        self._test_OXM_basic(OXM_OF_ETH_SRC_W, OFPXMT_OFB_ETH_SRC, 1, 12)
        self._test_OXM_basic(OXM_OF_ETH_TYPE, OFPXMT_OFB_ETH_TYPE, 0, 2)
        self._test_OXM_basic(OXM_OF_VLAN_VID, OFPXMT_OFB_VLAN_VID, 0, 2)
        self._test_OXM_basic(OXM_OF_VLAN_VID_W, OFPXMT_OFB_VLAN_VID, 1, 4)
        self._test_OXM_basic(OXM_OF_VLAN_PCP, OFPXMT_OFB_VLAN_PCP, 0, 1)
        self._test_OXM_basic(OXM_OF_IP_DSCP, OFPXMT_OFB_IP_DSCP, 0, 1)
        self._test_OXM_basic(OXM_OF_IP_ECN, OFPXMT_OFB_IP_ECN, 0, 1)
        self._test_OXM_basic(OXM_OF_IP_PROTO, OFPXMT_OFB_IP_PROTO, 0, 1)
        self._test_OXM_basic(OXM_OF_IPV4_SRC, OFPXMT_OFB_IPV4_SRC, 0, 4)
        self._test_OXM_basic(OXM_OF_IPV4_SRC_W, OFPXMT_OFB_IPV4_SRC, 1, 8)
        self._test_OXM_basic(OXM_OF_IPV4_DST, OFPXMT_OFB_IPV4_DST, 0, 4)
        self._test_OXM_basic(OXM_OF_IPV4_DST_W, OFPXMT_OFB_IPV4_DST, 1, 8)
        self._test_OXM_basic(OXM_OF_TCP_SRC, OFPXMT_OFB_TCP_SRC, 0, 2)
        self._test_OXM_basic(OXM_OF_TCP_DST, OFPXMT_OFB_TCP_DST, 0, 2)
        self._test_OXM_basic(OXM_OF_UDP_SRC, OFPXMT_OFB_UDP_SRC, 0, 2)
        self._test_OXM_basic(OXM_OF_UDP_DST, OFPXMT_OFB_UDP_DST, 0, 2)
        self._test_OXM_basic(OXM_OF_SCTP_SRC, OFPXMT_OFB_SCTP_SRC, 0, 2)
        self._test_OXM_basic(OXM_OF_SCTP_DST, OFPXMT_OFB_SCTP_DST, 0, 2)
        self._test_OXM_basic(OXM_OF_ICMPV4_TYPE, OFPXMT_OFB_ICMPV4_TYPE, 0, 1)
        self._test_OXM_basic(OXM_OF_ICMPV4_CODE, OFPXMT_OFB_ICMPV4_CODE, 0, 1)
        self._test_OXM_basic(OXM_OF_ARP_OP, OFPXMT_OFB_ARP_OP, 0, 2)
        self._test_OXM_basic(OXM_OF_ARP_SPA, OFPXMT_OFB_ARP_SPA, 0, 4)
        self._test_OXM_basic(OXM_OF_ARP_SPA_W, OFPXMT_OFB_ARP_SPA, 1, 8)
        self._test_OXM_basic(OXM_OF_ARP_TPA, OFPXMT_OFB_ARP_TPA, 0, 4)
        self._test_OXM_basic(OXM_OF_ARP_TPA_W, OFPXMT_OFB_ARP_TPA, 1, 8)
        self._test_OXM_basic(OXM_OF_ARP_SHA, OFPXMT_OFB_ARP_SHA, 0, 6)
        self._test_OXM_basic(OXM_OF_ARP_SHA_W, OFPXMT_OFB_ARP_SHA, 1, 12)
        self._test_OXM_basic(OXM_OF_ARP_THA, OFPXMT_OFB_ARP_THA, 0, 6)
        self._test_OXM_basic(OXM_OF_ARP_THA_W, OFPXMT_OFB_ARP_THA, 1, 12)
        self._test_OXM_basic(OXM_OF_IPV6_SRC, OFPXMT_OFB_IPV6_SRC, 0, 16)
        self._test_OXM_basic(OXM_OF_IPV6_SRC_W, OFPXMT_OFB_IPV6_SRC, 1, 32)
        self._test_OXM_basic(OXM_OF_IPV6_DST, OFPXMT_OFB_IPV6_DST, 0, 16)
        self._test_OXM_basic(OXM_OF_IPV6_DST_W, OFPXMT_OFB_IPV6_DST, 1, 32)
        self._test_OXM_basic(OXM_OF_IPV6_FLABEL, OFPXMT_OFB_IPV6_FLABEL, 0, 4)
        self._test_OXM_basic(OXM_OF_IPV6_FLABEL_W,
                             OFPXMT_OFB_IPV6_FLABEL, 1, 8)
        self._test_OXM_basic(OXM_OF_ICMPV6_TYPE, OFPXMT_OFB_ICMPV6_TYPE, 0, 1)
        self._test_OXM_basic(OXM_OF_ICMPV6_CODE, OFPXMT_OFB_ICMPV6_CODE, 0, 1)
        self._test_OXM_basic(OXM_OF_IPV6_ND_TARGET,
                             OFPXMT_OFB_IPV6_ND_TARGET, 0, 16)
        self._test_OXM_basic(OXM_OF_IPV6_ND_SLL, OFPXMT_OFB_IPV6_ND_SLL, 0, 6)
        self._test_OXM_basic(OXM_OF_IPV6_ND_TLL, OFPXMT_OFB_IPV6_ND_TLL, 0, 6)
        self._test_OXM_basic(OXM_OF_MPLS_LABEL, OFPXMT_OFB_MPLS_LABEL, 0, 4)
        self._test_OXM_basic(OXM_OF_MPLS_TC, OFPXMT_OFB_MPLS_TC, 0, 1)

    def test_define_constants(self):
        eq_(OFP_VERSION, 0x03)
        eq_(OFP_TCP_PORT, 6633)
        eq_(MAX_XID, 0xffffffff)
