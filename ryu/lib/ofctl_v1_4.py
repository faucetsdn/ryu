# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_4_parser
from ryu.lib import ofctl_utils

LOG = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 1.0

UTIL = ofctl_utils.OFCtlUtil(ofproto_v1_4)


def to_action(dp, dic):
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    action_type = dic.get('type')
    return ofctl_utils.to_action(dic, ofp, parser, action_type, UTIL)


def _get_actions(dp, dics):
    actions = []
    for d in dics:
        action = to_action(dp, d)
        if action is not None:
            actions.append(action)
        else:
            LOG.error('Unknown action type: %s', d)
    return actions


def to_instructions(dp, insts):
    instructions = []
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    for i in insts:
        inst_type = i.get('type')
        if inst_type in ['APPLY_ACTIONS', 'WRITE_ACTIONS']:
            dics = i.get('actions', [])
            actions = _get_actions(dp, dics)
            if actions:
                if inst_type == 'APPLY_ACTIONS':
                    instructions.append(
                        parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions))
                else:
                    instructions.append(
                        parser.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS,
                                                     actions))
        elif inst_type == 'CLEAR_ACTIONS':
            instructions.append(
                parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, []))
        elif inst_type == 'GOTO_TABLE':
            table_id = int(i.get('table_id'))
            instructions.append(parser.OFPInstructionGotoTable(table_id))
        elif inst_type == 'WRITE_METADATA':
            metadata = ofctl_utils.str_to_int(i.get('metadata'))
            metadata_mask = (ofctl_utils.str_to_int(i['metadata_mask'])
                             if 'metadata_mask' in i
                             else parser.UINT64_MAX)
            instructions.append(
                parser.OFPInstructionWriteMetadata(
                    metadata, metadata_mask))
        elif inst_type == 'METER':
            meter_id = int(i.get('meter_id'))
            instructions.append(parser.OFPInstructionMeter(meter_id))
        else:
            LOG.error('Unknown instruction type: %s', inst_type)

    return instructions


def action_to_str(act):
    s = act.to_jsondict()[act.__class__.__name__]
    t = UTIL.ofp_action_type_to_user(s['type'])
    s['type'] = t if t != s['type'] else 'UNKNOWN'

    if 'field' in s:
        field = s.pop('field')
        s['field'] = field['OXMTlv']['field']
        s['mask'] = field['OXMTlv']['mask']
        s['value'] = field['OXMTlv']['value']

    return s


def instructions_to_str(instructions):

    s = []

    for i in instructions:
        v = i.to_jsondict()[i.__class__.__name__]
        t = UTIL.ofp_instruction_type_to_user(v['type'])
        inst_type = t if t != v['type'] else 'UNKNOWN'
        # apply/write/clear-action instruction
        if isinstance(i, ofproto_v1_4_parser.OFPInstructionActions):
            acts = []
            for a in i.actions:
                acts.append(action_to_str(a))
            v['type'] = inst_type
            v['actions'] = acts
            s.append(v)
        # others
        else:
            v['type'] = inst_type
            s.append(v)

    return s


def to_match(dp, attrs):
    convert = {'in_port': UTIL.ofp_port_from_user,
               'in_phy_port': int,
               'metadata': ofctl_utils.to_match_masked_int,
               'eth_dst': ofctl_utils.to_match_eth,
               'eth_src': ofctl_utils.to_match_eth,
               'eth_type': int,
               'vlan_vid': to_match_vid,
               'vlan_pcp': int,
               'ip_dscp': int,
               'ip_ecn': int,
               'ip_proto': int,
               'ipv4_src': ofctl_utils.to_match_ip,
               'ipv4_dst': ofctl_utils.to_match_ip,
               'tcp_src': int,
               'tcp_dst': int,
               'udp_src': int,
               'udp_dst': int,
               'sctp_src': int,
               'sctp_dst': int,
               'icmpv4_type': int,
               'icmpv4_code': int,
               'arp_op': int,
               'arp_spa': ofctl_utils.to_match_ip,
               'arp_tpa': ofctl_utils.to_match_ip,
               'arp_sha': ofctl_utils.to_match_eth,
               'arp_tha': ofctl_utils.to_match_eth,
               'ipv6_src': ofctl_utils.to_match_ip,
               'ipv6_dst': ofctl_utils.to_match_ip,
               'ipv6_flabel': int,
               'icmpv6_type': int,
               'icmpv6_code': int,
               'ipv6_nd_target': ofctl_utils.to_match_ip,
               'ipv6_nd_sll': ofctl_utils.to_match_eth,
               'ipv6_nd_tll': ofctl_utils.to_match_eth,
               'mpls_label': int,
               'mpls_tc': int,
               'mpls_bos': int,
               'pbb_isid': ofctl_utils.to_match_masked_int,
               'tunnel_id': ofctl_utils.to_match_masked_int,
               'ipv6_exthdr': ofctl_utils.to_match_masked_int,
               'pbb_uca': int,
               }

    keys = {'dl_dst': 'eth_dst',
            'dl_src': 'eth_src',
            'dl_type': 'eth_type',
            'dl_vlan': 'vlan_vid',
            'nw_src': 'ipv4_src',
            'nw_dst': 'ipv4_dst',
            'nw_proto': 'ip_proto'}

    if attrs.get('eth_type') == ether.ETH_TYPE_ARP:
        if 'ipv4_src' in attrs and 'arp_spa' not in attrs:
            attrs['arp_spa'] = attrs['ipv4_src']
            del attrs['ipv4_src']
        if 'ipv4_dst' in attrs and 'arp_tpa' not in attrs:
            attrs['arp_tpa'] = attrs['ipv4_dst']
            del attrs['ipv4_dst']

    kwargs = {}
    for key, value in attrs.items():
        if key in keys:
            # For old field name
            key = keys[key]
        if key in convert:
            value = convert[key](value)
            kwargs[key] = value
        else:
            LOG.error('Unknown match field: %s', key)

    return dp.ofproto_parser.OFPMatch(**kwargs)


def to_match_vid(value):
    return ofctl_utils.to_match_vid(value, ofproto_v1_4.OFPVID_PRESENT)


def match_to_str(ofmatch):
    match = {}

    ofmatch = ofmatch.to_jsondict()['OFPMatch']
    ofmatch = ofmatch['oxm_fields']

    for match_field in ofmatch:
        key = match_field['OXMTlv']['field']
        mask = match_field['OXMTlv']['mask']
        value = match_field['OXMTlv']['value']
        if key == 'vlan_vid':
            value = ofctl_utils.match_vid_to_str(value, mask,
                                                 ofproto_v1_4.OFPVID_PRESENT)
        elif key == 'in_port':
            value = UTIL.ofp_port_to_user(value)
        else:
            if mask is not None:
                value = str(value) + '/' + str(mask)
        match.setdefault(key, value)

    return match


def wrap_dpid_dict(dp, value, to_user=True):
    if to_user:
        return {str(dp.id): value}

    return {dp.id: value}


def get_desc_stats(dp, waiters, to_user=True):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)
    s = {}

    for msg in msgs:
        stats = msg.body
        s = stats.to_jsondict()[stats.__class__.__name__]

    return wrap_dpid_dict(dp, s, to_user)


def get_queue_stats(dp, waiters, port_no=None, queue_id=None, to_user=True):
    if port_no is None:
        port_no = dp.ofproto.OFPP_ANY
    else:
        port_no = UTIL.ofp_port_from_user(port_no)
    if queue_id is None:
        queue_id = dp.ofproto.OFPQ_ALL
    else:
        queue_id = UTIL.ofp_queue_from_user(queue_id)

    stats = dp.ofproto_parser.OFPQueueStatsRequest(
        dp, 0, port_no, queue_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    desc = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s = stat.to_jsondict()[stat.__class__.__name__]
            properties = []
            for prop in stat.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]
                if to_user:
                    t = UTIL.ofp_queue_stats_prop_type_to_user(prop.type)
                    p['type'] = t if t != p['type'] else 'UNKNOWN'
                properties.append(p)
            s['properties'] = properties
            desc.append(s)

    return wrap_dpid_dict(dp, desc, to_user)


def get_queue_desc(dp, waiters, port_no=None, queue_id=None, to_user=True):
    if port_no is None:
        port_no = dp.ofproto.OFPP_ANY
    else:
        port_no = UTIL.ofp_port_from_user(port_no)
    if queue_id is None:
        queue_id = dp.ofproto.OFPQ_ALL
    else:
        queue_id = UTIL.ofp_queue_from_user(queue_id)

    stats = dp.ofproto_parser.OFPQueueDescStatsRequest(
        dp, 0, port_no, queue_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    configs = []
    for msg in msgs:
        for queue in msg.body:
            q = queue.to_jsondict()[queue.__class__.__name__]
            prop_list = []
            for prop in queue.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]
                if to_user:
                    t = UTIL.ofp_queue_desc_prop_type_to_user(prop.type)
                    p['type'] = t if t != prop.type else 'UNKNOWN'
                prop_list.append(p)
            q['properties'] = prop_list
            configs.append(q)

    return wrap_dpid_dict(dp, configs, to_user)


def get_flow_stats(dp, waiters, flow=None, to_user=True):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
    flags = int(flow.get('flags', 0))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            s = stats.to_jsondict()[stats.__class__.__name__]
            s['instructions'] = instructions_to_str(stats.instructions)
            s['match'] = match_to_str(stats.match)
            flows.append(s)

    return wrap_dpid_dict(dp, flows, to_user)


def get_aggregate_flow_stats(dp, waiters, flow=None, to_user=True):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
    flags = int(flow.get('flags', 0))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))

    stats = dp.ofproto_parser.OFPAggregateStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        stats = msg.body
        s = stats.to_jsondict()[stats.__class__.__name__]
        flows.append(s)

    return wrap_dpid_dict(dp, flows, to_user)


def get_table_stats(dp, waiters, to_user=True):
    stats = dp.ofproto_parser.OFPTableStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    tables = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s = stat.to_jsondict()[stat.__class__.__name__]

            if to_user:
                s['table_id'] = UTIL.ofp_table_to_user(stat.table_id)

            tables.append(s)

    return wrap_dpid_dict(dp, tables, to_user)


def get_table_features(dp, waiters, to_user=True):
    stats = dp.ofproto_parser.OFPTableFeaturesStatsRequest(dp, 0, [])
    msgs = []
    ofproto = dp.ofproto
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    p_type_instructions = [ofproto.OFPTFPT_INSTRUCTIONS,
                           ofproto.OFPTFPT_INSTRUCTIONS_MISS]

    p_type_next_tables = [ofproto.OFPTFPT_NEXT_TABLES,
                          ofproto.OFPTFPT_NEXT_TABLES_MISS,
                          ofproto.OFPTFPT_TABLE_SYNC_FROM]

    p_type_actions = [ofproto.OFPTFPT_WRITE_ACTIONS,
                      ofproto.OFPTFPT_WRITE_ACTIONS_MISS,
                      ofproto.OFPTFPT_APPLY_ACTIONS,
                      ofproto.OFPTFPT_APPLY_ACTIONS_MISS]

    p_type_oxms = [ofproto.OFPTFPT_MATCH,
                   ofproto.OFPTFPT_WILDCARDS,
                   ofproto.OFPTFPT_WRITE_SETFIELD,
                   ofproto.OFPTFPT_WRITE_SETFIELD_MISS,
                   ofproto.OFPTFPT_APPLY_SETFIELD,
                   ofproto.OFPTFPT_APPLY_SETFIELD_MISS]

    p_type_experimenter = [ofproto.OFPTFPT_EXPERIMENTER,
                           ofproto.OFPTFPT_EXPERIMENTER_MISS]

    tables = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s = stat.to_jsondict()[stat.__class__.__name__]
            properties = []
            for prop in stat.properties:
                p = {}
                t = UTIL.ofp_table_feature_prop_type_to_user(prop.type)
                p['type'] = t if t != prop.type else 'UNKNOWN'
                if prop.type in p_type_instructions:
                    instruction_ids = []
                    for id in prop.instruction_ids:
                        i = {'len': id.len,
                             'type': id.type}
                        instruction_ids.append(i)
                    p['instruction_ids'] = instruction_ids
                elif prop.type in p_type_next_tables:
                    table_ids = []
                    for id in prop.table_ids:
                        table_ids.append(id)
                    p['table_ids'] = table_ids
                elif prop.type in p_type_actions:
                    action_ids = []
                    for id in prop.action_ids:
                        i = id.to_jsondict()[id.__class__.__name__]
                        action_ids.append(i)
                    p['action_ids'] = action_ids
                elif prop.type in p_type_oxms:
                    oxm_ids = []
                    for id in prop.oxm_ids:
                        i = id.to_jsondict()[id.__class__.__name__]
                        oxm_ids.append(i)
                    p['oxm_ids'] = oxm_ids
                elif prop.type in p_type_experimenter:
                    pass
                properties.append(p)
            s['name'] = stat.name.decode('utf-8')
            s['properties'] = properties

            if to_user:
                s['table_id'] = UTIL.ofp_table_to_user(stat.table_id)

            tables.append(s)

    return wrap_dpid_dict(dp, tables, to_user)


def get_port_stats(dp, waiters, port_no=None, to_user=True):
    if port_no is None:
        port_no = dp.ofproto.OFPP_ANY
    else:
        port_no = UTIL.ofp_port_from_user(port_no)

    stats = dp.ofproto_parser.OFPPortStatsRequest(dp, 0, port_no)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    ports = []
    for msg in msgs:
        for stats in msg.body:
            s = stats.to_jsondict()[stats.__class__.__name__]
            properties = []
            for prop in stats.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]
                t = UTIL.ofp_port_stats_prop_type_to_user(prop.type)
                p['type'] = t if t != prop.type else 'UNKNOWN'
                properties.append(p)
            s['properties'] = properties

            if to_user:
                s['port_no'] = UTIL.ofp_port_to_user(stats.port_no)

            ports.append(s)

    return wrap_dpid_dict(dp, ports, to_user)


def get_meter_stats(dp, waiters, meter_id=None, to_user=True):
    if meter_id is None:
        meter_id = dp.ofproto.OFPM_ALL
    else:
        meter_id = UTIL.ofp_meter_from_user(meter_id)

    stats = dp.ofproto_parser.OFPMeterStatsRequest(
        dp, 0, meter_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    meters = []
    for msg in msgs:
        for stats in msg.body:
            s = stats.to_jsondict()[stats.__class__.__name__]
            bands = []
            for band in stats.band_stats:
                b = band.to_jsondict()[band.__class__.__name__]
                bands.append(b)
            s['band_stats'] = bands

            if to_user:
                s['meter_id'] = UTIL.ofp_meter_to_user(stats.meter_id)

            meters.append(s)

    return wrap_dpid_dict(dp, meters, to_user)


def get_meter_features(dp, waiters, to_user=True):
    ofp = dp.ofproto
    type_convert = {ofp.OFPMBT_DROP: 'DROP',
                    ofp.OFPMBT_DSCP_REMARK: 'DSCP_REMARK'}

    capa_convert = {ofp.OFPMF_KBPS: 'KBPS',
                    ofp.OFPMF_PKTPS: 'PKTPS',
                    ofp.OFPMF_BURST: 'BURST',
                    ofp.OFPMF_STATS: 'STATS'}

    stats = dp.ofproto_parser.OFPMeterFeaturesStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    features = []
    for msg in msgs:
        for feature in msg.body:
            band_types = []
            for k, v in type_convert.items():
                if (1 << k) & feature.band_types:

                    if to_user:
                        band_types.append(v)

                    else:
                        band_types.append(k)

            capabilities = []
            for k, v in sorted(capa_convert.items()):
                if k & feature.capabilities:

                    if to_user:
                        capabilities.append(v)

                    else:
                        capabilities.append(k)

            f = {'max_meter': feature.max_meter,
                 'band_types': band_types,
                 'capabilities': capabilities,
                 'max_bands': feature.max_bands,
                 'max_color': feature.max_color}
            features.append(f)

    return wrap_dpid_dict(dp, features, to_user)


def get_meter_config(dp, waiters, meter_id=None, to_user=True):
    flags = {dp.ofproto.OFPMF_KBPS: 'KBPS',
             dp.ofproto.OFPMF_PKTPS: 'PKTPS',
             dp.ofproto.OFPMF_BURST: 'BURST',
             dp.ofproto.OFPMF_STATS: 'STATS'}

    if meter_id is None:
        meter_id = dp.ofproto.OFPM_ALL
    else:
        meter_id = UTIL.ofp_meter_from_user(meter_id)

    stats = dp.ofproto_parser.OFPMeterConfigStatsRequest(
        dp, 0, meter_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    configs = []
    for msg in msgs:
        for config in msg.body:
            c = config.to_jsondict()[config.__class__.__name__]
            bands = []
            for band in config.bands:
                b = band.to_jsondict()[band.__class__.__name__]

                if to_user:
                    t = UTIL.ofp_meter_band_type_to_user(band.type)
                    b['type'] = t if t != band.type else 'UNKNOWN'

                bands.append(b)
            c_flags = []
            for k, v in sorted(flags.items()):
                if k & config.flags:
                    if to_user:
                        c_flags.append(v)

                    else:
                        c_flags.append(k)

            c['flags'] = c_flags
            c['bands'] = bands

            if to_user:
                c['meter_id'] = UTIL.ofp_meter_to_user(config.meter_id)

            configs.append(c)

    return wrap_dpid_dict(dp, configs, to_user)


def get_group_stats(dp, waiters, group_id=None, to_user=True):
    if group_id is None:
        group_id = dp.ofproto.OFPG_ALL
    else:
        group_id = UTIL.ofp_group_from_user(group_id)

    stats = dp.ofproto_parser.OFPGroupStatsRequest(
        dp, 0, group_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    groups = []
    for msg in msgs:
        for stats in msg.body:
            g = stats.to_jsondict()[stats.__class__.__name__]
            bucket_stats = []
            for bucket_stat in stats.bucket_stats:
                c = bucket_stat.to_jsondict()[bucket_stat.__class__.__name__]
                bucket_stats.append(c)
            g['bucket_stats'] = bucket_stats

            if to_user:
                g['group_id'] = UTIL.ofp_group_to_user(stats.group_id)

            groups.append(g)

    return wrap_dpid_dict(dp, groups, to_user)


def get_group_features(dp, waiters, to_user=True):

    ofp = dp.ofproto
    type_convert = {ofp.OFPGT_ALL: 'ALL',
                    ofp.OFPGT_SELECT: 'SELECT',
                    ofp.OFPGT_INDIRECT: 'INDIRECT',
                    ofp.OFPGT_FF: 'FF'}
    cap_convert = {ofp.OFPGFC_SELECT_WEIGHT: 'SELECT_WEIGHT',
                   ofp.OFPGFC_SELECT_LIVENESS: 'SELECT_LIVENESS',
                   ofp.OFPGFC_CHAINING: 'CHAINING',
                   ofp.OFPGFC_CHAINING_CHECKS: 'CHAINING_CHECKS'}
    act_convert = {ofp.OFPAT_OUTPUT: 'OUTPUT',
                   ofp.OFPAT_COPY_TTL_OUT: 'COPY_TTL_OUT',
                   ofp.OFPAT_COPY_TTL_IN: 'COPY_TTL_IN',
                   ofp.OFPAT_SET_MPLS_TTL: 'SET_MPLS_TTL',
                   ofp.OFPAT_DEC_MPLS_TTL: 'DEC_MPLS_TTL',
                   ofp.OFPAT_PUSH_VLAN: 'PUSH_VLAN',
                   ofp.OFPAT_POP_VLAN: 'POP_VLAN',
                   ofp.OFPAT_PUSH_MPLS: 'PUSH_MPLS',
                   ofp.OFPAT_POP_MPLS: 'POP_MPLS',
                   ofp.OFPAT_SET_QUEUE: 'SET_QUEUE',
                   ofp.OFPAT_GROUP: 'GROUP',
                   ofp.OFPAT_SET_NW_TTL: 'SET_NW_TTL',
                   ofp.OFPAT_DEC_NW_TTL: 'DEC_NW_TTL',
                   ofp.OFPAT_SET_FIELD: 'SET_FIELD',
                   ofp.OFPAT_PUSH_PBB: 'PUSH_PBB',
                   ofp.OFPAT_POP_PBB: 'POP_PBB',
                   ofp.OFPAT_EXPERIMENTER: 'EXPERIMENTER',
                   }

    stats = dp.ofproto_parser.OFPGroupFeaturesStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    features = []
    for msg in msgs:
        feature = msg.body
        types = []
        for k, v in type_convert.items():
            if (1 << k) & feature.types:
                if to_user:
                    types.append(v)

                else:
                    types.append(k)

        capabilities = []
        for k, v in cap_convert.items():
            if k & feature.capabilities:
                if to_user:
                    capabilities.append(v)

                else:
                    capabilities.append(k)

        if to_user:
            max_groups = []
            for k, v in type_convert.items():
                max_groups.append({v: feature.max_groups[k]})

        else:
            max_groups = feature.max_groups

        actions = []
        for k1, v1 in type_convert.items():
            acts = []
            for k2, v2 in act_convert.items():
                if (1 << k2) & feature.actions[k1]:
                    if to_user:
                        acts.append(v2)

                    else:
                        acts.append(k2)

            if to_user:
                actions.append({v1: acts})

            else:
                actions.append({k1: acts})

        f = {'types': types,
             'capabilities': capabilities,
             'max_groups': max_groups,
             'actions': actions}
        features.append(f)

    return wrap_dpid_dict(dp, features, to_user)


def get_group_desc(dp, waiters, to_user=True):
    stats = dp.ofproto_parser.OFPGroupDescStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    descs = []
    for msg in msgs:
        for stats in msg.body:
            d = stats.to_jsondict()[stats.__class__.__name__]
            buckets = []
            for bucket in stats.buckets:
                b = bucket.to_jsondict()[bucket.__class__.__name__]
                actions = []
                for action in bucket.actions:
                    if to_user:
                        actions.append(action_to_str(action))

                    else:
                        actions.append(action)
                b['actions'] = actions
                buckets.append(b)

            d['buckets'] = buckets
            if to_user:
                d['group_id'] = UTIL.ofp_group_to_user(stats.group_id)
                t = UTIL.ofp_group_type_to_user(stats.type)
                d['type'] = t if t != stats.type else 'UNKNOWN'

            descs.append(d)

    return wrap_dpid_dict(dp, descs, to_user)


def get_port_desc(dp, waiters, port_no=None, to_user=True):
    if port_no is None:
        port_no = dp.ofproto.OFPP_ANY
    else:
        port_no = UTIL.ofp_port_from_user(port_no)

    stats = dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0, port_no)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    descs = []

    for msg in msgs:
        stats = msg.body
        for stat in stats:
            d = stat.to_jsondict()[stat.__class__.__name__]
            properties = []
            for prop in stat.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]

                if to_user:
                    t = UTIL.ofp_port_desc_prop_type_to_user(prop.type)
                    p['type'] = t if t != prop.type else 'UNKNOWN'

                properties.append(p)
            d['name'] = stat.name.decode('utf-8')
            d['properties'] = properties

            if to_user:
                d['port_no'] = UTIL.ofp_port_to_user(stat.port_no)

            descs.append(d)

    return wrap_dpid_dict(dp, descs, to_user)


def mod_flow_entry(dp, flow, cmd):
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    table_id = UTIL.ofp_table_from_user(flow.get('table_id', 0))
    idle_timeout = int(flow.get('idle_timeout', 0))
    hard_timeout = int(flow.get('hard_timeout', 0))
    priority = int(flow.get('priority', 0))
    buffer_id = UTIL.ofp_buffer_from_user(
        flow.get('buffer_id', dp.ofproto.OFP_NO_BUFFER))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    importance = int(flow.get('importance', 0))
    flags = int(flow.get('flags', 0))
    match = to_match(dp, flow.get('match', {}))
    inst = to_instructions(dp, flow.get('instructions', []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        importance, flags, match, inst)

    ofctl_utils.send_msg(dp, flow_mod, LOG)


def mod_meter_entry(dp, meter, cmd):
    flags = 0
    if 'flags' in meter:
        meter_flags = meter['flags']
        if not isinstance(meter_flags, list):
            meter_flags = [meter_flags]
        for flag in meter_flags:
            t = UTIL.ofp_meter_flags_from_user(flag)
            f = t if t != flag else None
            if f is None:
                LOG.error('Unknown meter flag: %s', flag)
                continue
            flags |= f

    meter_id = UTIL.ofp_meter_from_user(meter.get('meter_id', 0))

    bands = []
    for band in meter.get('bands', []):
        band_type = band.get('type')
        rate = int(band.get('rate', 0))
        burst_size = int(band.get('burst_size', 0))
        if band_type == 'DROP':
            bands.append(
                dp.ofproto_parser.OFPMeterBandDrop(rate, burst_size))
        elif band_type == 'DSCP_REMARK':
            prec_level = int(band.get('prec_level', 0))
            bands.append(
                dp.ofproto_parser.OFPMeterBandDscpRemark(
                    rate, burst_size, prec_level))
        elif band_type == 'EXPERIMENTER':
            experimenter = int(band.get('experimenter', 0))
            bands.append(
                dp.ofproto_parser.OFPMeterBandExperimenter(
                    rate, burst_size, experimenter))
        else:
            LOG.error('Unknown band type: %s', band_type)

    meter_mod = dp.ofproto_parser.OFPMeterMod(
        dp, cmd, flags, meter_id, bands)

    ofctl_utils.send_msg(dp, meter_mod, LOG)


def mod_group_entry(dp, group, cmd):
    group_type = str(group.get('type', 'ALL'))
    t = UTIL.ofp_group_type_from_user(group_type)
    group_type = t if t != group_type else None
    if group_type is None:
        LOG.error('Unknown group type: %s', group.get('type'))

    group_id = UTIL.ofp_group_from_user(group.get('group_id', 0))

    buckets = []
    for bucket in group.get('buckets', []):
        weight = int(bucket.get('weight', 0))
        watch_port = int(bucket.get('watch_port', dp.ofproto.OFPP_ANY))
        watch_group = int(bucket.get('watch_group', dp.ofproto.OFPG_ANY))
        actions = []
        for dic in bucket.get('actions', []):
            action = to_action(dp, dic)
            if action is not None:
                actions.append(action)
        buckets.append(dp.ofproto_parser.OFPBucket(
            weight, watch_port, watch_group, actions))

    group_mod = dp.ofproto_parser.OFPGroupMod(
        dp, cmd, group_type, group_id, buckets)

    ofctl_utils.send_msg(dp, group_mod, LOG)


def mod_port_behavior(dp, port_config):
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    port_no = UTIL.ofp_port_from_user(port_config.get('port_no', 0))
    hw_addr = str(port_config.get('hw_addr'))
    config = int(port_config.get('config', 0))
    mask = int(port_config.get('mask', 0))
    properties = port_config.get('properties')

    prop = []
    for p in properties:
        type_ = UTIL.ofp_port_mod_prop_type_from_user(p['type'])
        length = None
        if type_ == ofp.OFPPDPT_ETHERNET:
            advertise = UTIL.ofp_port_features_from_user(p['advertise'])
            prop.append(
                parser.OFPPortModPropEthernet(type_, length, advertise))
        elif type_ == ofp.OFPPDPT_OPTICAL:
            prop.append(
                parser.OFPPortModPropOptical(
                    type_, length, p['configure'], p['freq_lmda'],
                    p['fl_offset'], p['grid_span'], p['tx_pwr']))
        elif type_ == ofp.OFPPDPT_EXPERIMENTER:
            prop.append(
                parser.OFPPortModPropExperimenter(
                    type_, length, p['experimenter'], p['exp_type'],
                    p['data']))
        else:
            LOG.error('Unknown port desc prop type: %s', type_)

    port_mod = dp.ofproto_parser.OFPPortMod(
        dp, port_no, hw_addr, config, mask, prop)

    ofctl_utils.send_msg(dp, port_mod, LOG)


# NOTE(jkoelker) Alias common funcitons
send_experimenter = ofctl_utils.send_experimenter
