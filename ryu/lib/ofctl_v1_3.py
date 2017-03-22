# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import base64
import logging

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib import ofctl_nicira_ext
from ryu.lib import ofctl_utils


LOG = logging.getLogger('ryu.lib.ofctl_v1_3')

DEFAULT_TIMEOUT = 1.0

UTIL = ofctl_utils.OFCtlUtil(ofproto_v1_3)
str_to_int = ofctl_utils.str_to_int


def to_action(dp, dic):
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    action_type = dic.get('type')
    return ofctl_utils.to_action(dic, ofp, parser, action_type, UTIL)


def to_actions(dp, acts):
    inst = []
    actions = []
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    for a in acts:
        action = to_action(dp, a)

        if action is not None:
            actions.append(action)
        else:
            action_type = a.get('type')
            if action_type == 'WRITE_ACTIONS':
                write_actions = []
                write_acts = a.get('actions')
                for act in write_acts:
                    action = to_action(dp, act)
                    if action is not None:
                        write_actions.append(action)
                    else:
                        LOG.error('Unknown action type: %s', action_type)
                if write_actions:
                    inst.append(
                        parser.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS,
                                                     write_actions))
            elif action_type == 'CLEAR_ACTIONS':
                inst.append(
                    parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, []))
            elif action_type == 'GOTO_TABLE':
                table_id = UTIL.ofp_table_from_user(a.get('table_id'))
                inst.append(parser.OFPInstructionGotoTable(table_id))
            elif action_type == 'WRITE_METADATA':
                metadata = str_to_int(a.get('metadata'))
                metadata_mask = (str_to_int(a['metadata_mask'])
                                 if 'metadata_mask' in a
                                 else parser.UINT64_MAX)
                inst.append(
                    parser.OFPInstructionWriteMetadata(
                        metadata, metadata_mask))
            elif action_type == 'METER':
                meter_id = UTIL.ofp_meter_from_user(a.get('meter_id'))
                inst.append(parser.OFPInstructionMeter(meter_id))
            else:
                LOG.error('Unknown action type: %s', action_type)

    if actions:
        inst.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions))
    return inst


def action_to_str(act):
    action_type = act.cls_action_type

    if action_type == ofproto_v1_3.OFPAT_OUTPUT:
        port = UTIL.ofp_port_to_user(act.port)
        buf = 'OUTPUT:' + str(port)
    elif action_type == ofproto_v1_3.OFPAT_COPY_TTL_OUT:
        buf = 'COPY_TTL_OUT'
    elif action_type == ofproto_v1_3.OFPAT_COPY_TTL_IN:
        buf = 'COPY_TTL_IN'
    elif action_type == ofproto_v1_3.OFPAT_SET_MPLS_TTL:
        buf = 'SET_MPLS_TTL:' + str(act.mpls_ttl)
    elif action_type == ofproto_v1_3.OFPAT_DEC_MPLS_TTL:
        buf = 'DEC_MPLS_TTL'
    elif action_type == ofproto_v1_3.OFPAT_PUSH_VLAN:
        buf = 'PUSH_VLAN:' + str(act.ethertype)
    elif action_type == ofproto_v1_3.OFPAT_POP_VLAN:
        buf = 'POP_VLAN'
    elif action_type == ofproto_v1_3.OFPAT_PUSH_MPLS:
        buf = 'PUSH_MPLS:' + str(act.ethertype)
    elif action_type == ofproto_v1_3.OFPAT_POP_MPLS:
        buf = 'POP_MPLS:' + str(act.ethertype)
    elif action_type == ofproto_v1_3.OFPAT_SET_QUEUE:
        queue_id = UTIL.ofp_queue_to_user(act.queue_id)
        buf = 'SET_QUEUE:' + str(queue_id)
    elif action_type == ofproto_v1_3.OFPAT_GROUP:
        group_id = UTIL.ofp_group_to_user(act.group_id)
        buf = 'GROUP:' + str(group_id)
    elif action_type == ofproto_v1_3.OFPAT_SET_NW_TTL:
        buf = 'SET_NW_TTL:' + str(act.nw_ttl)
    elif action_type == ofproto_v1_3.OFPAT_DEC_NW_TTL:
        buf = 'DEC_NW_TTL'
    elif action_type == ofproto_v1_3.OFPAT_SET_FIELD:
        buf = 'SET_FIELD: {%s:%s}' % (act.key, act.value)
    elif action_type == ofproto_v1_3.OFPAT_PUSH_PBB:
        buf = 'PUSH_PBB:' + str(act.ethertype)
    elif action_type == ofproto_v1_3.OFPAT_POP_PBB:
        buf = 'POP_PBB'
    elif action_type == ofproto_v1_3.OFPAT_EXPERIMENTER:
        if act.experimenter == ofproto_common.NX_EXPERIMENTER_ID:
            try:
                return ofctl_nicira_ext.action_to_str(act, action_to_str)
            except Exception:
                LOG.debug('Error parsing NX_ACTION(%s)',
                          act.__class__.__name__, exc_info=True)

        data_str = base64.b64encode(act.data)
        buf = 'EXPERIMENTER: {experimenter:%s, data:%s}' % \
            (act.experimenter, data_str.decode('utf-8'))
    else:
        buf = 'UNKNOWN'
    return buf


def actions_to_str(instructions):
    actions = []

    for instruction in instructions:
        if isinstance(instruction,
                      ofproto_v1_3_parser.OFPInstructionActions):
            if instruction.type == ofproto_v1_3.OFPIT_APPLY_ACTIONS:
                for a in instruction.actions:
                    actions.append(action_to_str(a))
            elif instruction.type == ofproto_v1_3.OFPIT_WRITE_ACTIONS:
                write_actions = []
                for a in instruction.actions:
                    write_actions.append(action_to_str(a))
                if write_actions:
                    actions.append({'WRITE_ACTIONS': write_actions})
            elif instruction.type == ofproto_v1_3.OFPIT_CLEAR_ACTIONS:
                actions.append('CLEAR_ACTIONS')
            else:
                actions.append('UNKNOWN')
        elif isinstance(instruction,
                        ofproto_v1_3_parser.OFPInstructionGotoTable):
            table_id = UTIL.ofp_table_to_user(instruction.table_id)
            buf = 'GOTO_TABLE:' + str(table_id)
            actions.append(buf)

        elif isinstance(instruction,
                        ofproto_v1_3_parser.OFPInstructionWriteMetadata):
            buf = ('WRITE_METADATA:0x%x/0x%x' % (instruction.metadata,
                                                 instruction.metadata_mask)
                   if instruction.metadata_mask
                   else 'WRITE_METADATA:0x%x' % instruction.metadata)
            actions.append(buf)

        elif isinstance(instruction,
                        ofproto_v1_3_parser.OFPInstructionMeter):
            meter_id = UTIL.ofp_meter_to_user(instruction.meter_id)
            buf = 'METER:' + str(meter_id)
            actions.append(buf)

        else:
            continue

    return actions


def to_match(dp, attrs):
    convert = {'in_port': UTIL.ofp_port_from_user,
               'in_phy_port': str_to_int,
               'metadata': ofctl_utils.to_match_masked_int,
               'dl_dst': ofctl_utils.to_match_eth,
               'dl_src': ofctl_utils.to_match_eth,
               'eth_dst': ofctl_utils.to_match_eth,
               'eth_src': ofctl_utils.to_match_eth,
               'dl_type': str_to_int,
               'eth_type': str_to_int,
               'dl_vlan': to_match_vid,
               'vlan_vid': to_match_vid,
               'vlan_pcp': str_to_int,
               'ip_dscp': str_to_int,
               'ip_ecn': str_to_int,
               'nw_proto': str_to_int,
               'ip_proto': str_to_int,
               'nw_src': ofctl_utils.to_match_ip,
               'nw_dst': ofctl_utils.to_match_ip,
               'ipv4_src': ofctl_utils.to_match_ip,
               'ipv4_dst': ofctl_utils.to_match_ip,
               'tp_src': str_to_int,
               'tp_dst': str_to_int,
               'tcp_src': str_to_int,
               'tcp_dst': str_to_int,
               'udp_src': str_to_int,
               'udp_dst': str_to_int,
               'sctp_src': str_to_int,
               'sctp_dst': str_to_int,
               'icmpv4_type': str_to_int,
               'icmpv4_code': str_to_int,
               'arp_op': str_to_int,
               'arp_spa': ofctl_utils.to_match_ip,
               'arp_tpa': ofctl_utils.to_match_ip,
               'arp_sha': ofctl_utils.to_match_eth,
               'arp_tha': ofctl_utils.to_match_eth,
               'ipv6_src': ofctl_utils.to_match_ip,
               'ipv6_dst': ofctl_utils.to_match_ip,
               'ipv6_flabel': str_to_int,
               'icmpv6_type': str_to_int,
               'icmpv6_code': str_to_int,
               'ipv6_nd_target': ofctl_utils.to_match_ip,
               'ipv6_nd_sll': ofctl_utils.to_match_eth,
               'ipv6_nd_tll': ofctl_utils.to_match_eth,
               'mpls_label': str_to_int,
               'mpls_tc': str_to_int,
               'mpls_bos': str_to_int,
               'pbb_isid': ofctl_utils.to_match_masked_int,
               'tunnel_id': ofctl_utils.to_match_masked_int,
               'ipv6_exthdr': ofctl_utils.to_match_masked_int}

    keys = {'dl_dst': 'eth_dst',
            'dl_src': 'eth_src',
            'dl_type': 'eth_type',
            'dl_vlan': 'vlan_vid',
            'nw_src': 'ipv4_src',
            'nw_dst': 'ipv4_dst',
            'nw_proto': 'ip_proto'}

    if attrs.get('dl_type') == ether.ETH_TYPE_ARP or \
            attrs.get('eth_type') == ether.ETH_TYPE_ARP:
        if 'nw_src' in attrs and 'arp_spa' not in attrs:
            attrs['arp_spa'] = attrs['nw_src']
            del attrs['nw_src']
        if 'nw_dst' in attrs and 'arp_tpa' not in attrs:
            attrs['arp_tpa'] = attrs['nw_dst']
            del attrs['nw_dst']

    kwargs = {}
    for key, value in attrs.items():
        if key in keys:
            # For old field name
            key = keys[key]
        if key in convert:
            value = convert[key](value)
            if key == 'tp_src' or key == 'tp_dst':
                # TCP/UDP port
                conv = {inet.IPPROTO_TCP: {'tp_src': 'tcp_src',
                                           'tp_dst': 'tcp_dst'},
                        inet.IPPROTO_UDP: {'tp_src': 'udp_src',
                                           'tp_dst': 'udp_dst'}}
                ip_proto = attrs.get('nw_proto', attrs.get('ip_proto', 0))
                key = conv[ip_proto][key]
                kwargs[key] = value
            else:
                # others
                kwargs[key] = value
        else:
            LOG.error('Unknown match field: %s', key)

    return dp.ofproto_parser.OFPMatch(**kwargs)


def to_match_vid(value):
    return ofctl_utils.to_match_vid(value, ofproto_v1_3.OFPVID_PRESENT)


def match_to_str(ofmatch):

    keys = {'eth_src': 'dl_src',
            'eth_dst': 'dl_dst',
            'eth_type': 'dl_type',
            'vlan_vid': 'dl_vlan',
            'ipv4_src': 'nw_src',
            'ipv4_dst': 'nw_dst',
            'ip_proto': 'nw_proto',
            'tcp_src': 'tp_src',
            'tcp_dst': 'tp_dst',
            'udp_src': 'tp_src',
            'udp_dst': 'tp_dst'}

    match = {}

    ofmatch = ofmatch.to_jsondict()['OFPMatch']
    ofmatch = ofmatch['oxm_fields']

    for match_field in ofmatch:
        key = match_field['OXMTlv']['field']
        if key in keys:
            key = keys[key]
        mask = match_field['OXMTlv']['mask']
        value = match_field['OXMTlv']['value']
        if key == 'dl_vlan':
            value = match_vid_to_str(value, mask)
        elif key == 'in_port':
            value = UTIL.ofp_port_to_user(value)
        else:
            if mask is not None:
                value = str(value) + '/' + str(mask)
        match.setdefault(key, value)

    return match


def match_vid_to_str(value, mask):
    return ofctl_utils.match_vid_to_str(
        value, mask, ofproto_v1_3.OFPVID_PRESENT)


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


def get_queue_stats(dp, waiters, port=None, queue_id=None, to_user=True):
    ofp = dp.ofproto

    if port is None:
        port = ofp.OFPP_ANY
    else:
        port = str_to_int(port)

    if queue_id is None:
        queue_id = ofp.OFPQ_ALL
    else:
        queue_id = str_to_int(queue_id)

    stats = dp.ofproto_parser.OFPQueueStatsRequest(dp, 0, port,
                                                   queue_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    s = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s.append({'duration_nsec': stat.duration_nsec,
                      'duration_sec': stat.duration_sec,
                      'port_no': stat.port_no,
                      'queue_id': stat.queue_id,
                      'tx_bytes': stat.tx_bytes,
                      'tx_errors': stat.tx_errors,
                      'tx_packets': stat.tx_packets})

    return wrap_dpid_dict(dp, s, to_user)


def get_queue_config(dp, waiters, port=None, to_user=True):
    ofp = dp.ofproto
    if port is None:
        port = ofp.OFPP_ANY
    else:
        port = UTIL.ofp_port_from_user(str_to_int(port))
    stats = dp.ofproto_parser.OFPQueueGetConfigRequest(dp, port)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    prop_type = {dp.ofproto.OFPQT_MIN_RATE: 'MIN_RATE',
                 dp.ofproto.OFPQT_MAX_RATE: 'MAX_RATE',
                 dp.ofproto.OFPQT_EXPERIMENTER: 'EXPERIMENTER'}

    configs = []
    for config in msgs:
        queue_list = []
        for queue in config.queues:
            prop_list = []
            for prop in queue.properties:
                p = {'property': prop_type.get(prop.property, 'UNKNOWN')}
                if prop.property == dp.ofproto.OFPQT_MIN_RATE or \
                   prop.property == dp.ofproto.OFPQT_MAX_RATE:
                    p['rate'] = prop.rate
                elif prop.property == dp.ofproto.OFPQT_EXPERIMENTER:
                    p['experimenter'] = prop.experimenter
                    p['data'] = prop.data
                prop_list.append(p)

            q = {'properties': prop_list}

            if to_user:
                q['port'] = UTIL.ofp_port_to_user(queue.port)
                q['queue_id'] = UTIL.ofp_queue_to_user(queue.queue_id)

            else:
                q['port'] = queue.port
                q['queue_id'] = queue.queue_id

            queue_list.append(q)

        c = {'queues': queue_list}

        if to_user:
            c['port'] = UTIL.ofp_port_to_user(config.port)

        else:
            c['port'] = config.port

        configs.append(c)

    return wrap_dpid_dict(dp, configs, to_user)


def get_flow_stats(dp, waiters, flow=None, to_user=True):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
    flags = str_to_int(flow.get('flags', 0))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = str_to_int(flow.get('cookie', 0))
    cookie_mask = str_to_int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))
    # Note: OpenFlow does not allow to filter flow entries by priority,
    # but for efficiency, ofctl provides the way to do it.
    priority = str_to_int(flow.get('priority', -1))

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            if 0 <= priority != stats.priority:
                continue

            s = {'priority': stats.priority,
                 'cookie': stats.cookie,
                 'idle_timeout': stats.idle_timeout,
                 'hard_timeout': stats.hard_timeout,
                 'byte_count': stats.byte_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'packet_count': stats.packet_count,
                 'length': stats.length,
                 'flags': stats.flags}

            if to_user:
                s['actions'] = actions_to_str(stats.instructions)
                s['match'] = match_to_str(stats.match)
                s['table_id'] = UTIL.ofp_table_to_user(stats.table_id)

            else:
                s['actions'] = stats.instructions
                s['instructions'] = stats.instructions
                s['match'] = stats.match
                s['table_id'] = stats.table_id

            flows.append(s)

    return wrap_dpid_dict(dp, flows, to_user)


def get_aggregate_flow_stats(dp, waiters, flow=None, to_user=True):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
    flags = str_to_int(flow.get('flags', 0))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = str_to_int(flow.get('cookie', 0))
    cookie_mask = str_to_int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))

    stats = dp.ofproto_parser.OFPAggregateStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        stats = msg.body
        s = {'packet_count': stats.packet_count,
             'byte_count': stats.byte_count,
             'flow_count': stats.flow_count}
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
            s = {'active_count': stat.active_count,
                 'lookup_count': stat.lookup_count,
                 'matched_count': stat.matched_count}

            if to_user:
                s['table_id'] = UTIL.ofp_table_to_user(stat.table_id)

            else:
                s['table_id'] = stat.table_id

            tables.append(s)

    return wrap_dpid_dict(dp, tables, to_user)


def get_table_features(dp, waiters, to_user=True):
    stats = dp.ofproto_parser.OFPTableFeaturesStatsRequest(dp, 0, [])
    msgs = []
    ofproto = dp.ofproto
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    prop_type = {ofproto.OFPTFPT_INSTRUCTIONS: 'INSTRUCTIONS',
                 ofproto.OFPTFPT_INSTRUCTIONS_MISS: 'INSTRUCTIONS_MISS',
                 ofproto.OFPTFPT_NEXT_TABLES: 'NEXT_TABLES',
                 ofproto.OFPTFPT_NEXT_TABLES_MISS: 'NEXT_TABLES_MISS',
                 ofproto.OFPTFPT_WRITE_ACTIONS: 'WRITE_ACTIONS',
                 ofproto.OFPTFPT_WRITE_ACTIONS_MISS: 'WRITE_ACTIONS_MISS',
                 ofproto.OFPTFPT_APPLY_ACTIONS: 'APPLY_ACTIONS',
                 ofproto.OFPTFPT_APPLY_ACTIONS_MISS: 'APPLY_ACTIONS_MISS',
                 ofproto.OFPTFPT_MATCH: 'MATCH',
                 ofproto.OFPTFPT_WILDCARDS: 'WILDCARDS',
                 ofproto.OFPTFPT_WRITE_SETFIELD: 'WRITE_SETFIELD',
                 ofproto.OFPTFPT_WRITE_SETFIELD_MISS: 'WRITE_SETFIELD_MISS',
                 ofproto.OFPTFPT_APPLY_SETFIELD: 'APPLY_SETFIELD',
                 ofproto.OFPTFPT_APPLY_SETFIELD_MISS: 'APPLY_SETFIELD_MISS',
                 ofproto.OFPTFPT_EXPERIMENTER: 'EXPERIMENTER',
                 ofproto.OFPTFPT_EXPERIMENTER_MISS: 'EXPERIMENTER_MISS'}

    if not to_user:
        prop_type = dict((k, k) for k in prop_type.keys())

    p_type_instructions = [ofproto.OFPTFPT_INSTRUCTIONS,
                           ofproto.OFPTFPT_INSTRUCTIONS_MISS]

    p_type_next_tables = [ofproto.OFPTFPT_NEXT_TABLES,
                          ofproto.OFPTFPT_NEXT_TABLES_MISS]

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
            properties = []
            for prop in stat.properties:
                p = {'type': prop_type.get(prop.type, 'UNKNOWN')}
                if prop.type in p_type_instructions:
                    instruction_ids = []
                    for i in prop.instruction_ids:
                        inst = {'len': i.len,
                                'type': i.type}
                        instruction_ids.append(inst)
                    p['instruction_ids'] = instruction_ids
                elif prop.type in p_type_next_tables:
                    table_ids = []
                    for i in prop.table_ids:
                        table_ids.append(i)
                    p['table_ids'] = table_ids
                elif prop.type in p_type_actions:
                    action_ids = []
                    for i in prop.action_ids:
                        act = {'len': i.len,
                               'type': i.type}
                        action_ids.append(act)
                    p['action_ids'] = action_ids
                elif prop.type in p_type_oxms:
                    oxm_ids = []
                    for i in prop.oxm_ids:
                        oxm = {'hasmask': i.hasmask,
                               'length': i.length,
                               'type': i.type}
                        oxm_ids.append(oxm)
                    p['oxm_ids'] = oxm_ids
                elif prop.type in p_type_experimenter:
                    pass
                properties.append(p)
            s = {
                'name': stat.name.decode('utf-8'),
                'metadata_match': stat.metadata_match,
                'metadata_write': stat.metadata_write,
                'config': stat.config,
                'max_entries': stat.max_entries,
                'properties': properties,
            }

            if to_user:
                s['table_id'] = UTIL.ofp_table_to_user(stat.table_id)

            else:
                s['table_id'] = stat.table_id

            tables.append(s)

    return wrap_dpid_dict(dp, tables, to_user)


def get_port_stats(dp, waiters, port=None, to_user=True):
    if port is None:
        port = dp.ofproto.OFPP_ANY
    else:
        port = str_to_int(port)

    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, 0, port)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    ports = []
    for msg in msgs:
        for stats in msg.body:
            s = {'rx_packets': stats.rx_packets,
                 'tx_packets': stats.tx_packets,
                 'rx_bytes': stats.rx_bytes,
                 'tx_bytes': stats.tx_bytes,
                 'rx_dropped': stats.rx_dropped,
                 'tx_dropped': stats.tx_dropped,
                 'rx_errors': stats.rx_errors,
                 'tx_errors': stats.tx_errors,
                 'rx_frame_err': stats.rx_frame_err,
                 'rx_over_err': stats.rx_over_err,
                 'rx_crc_err': stats.rx_crc_err,
                 'collisions': stats.collisions,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec}

            if to_user:
                s['port_no'] = UTIL.ofp_port_to_user(stats.port_no)

            else:
                s['port_no'] = stats.port_no

            ports.append(s)

    return wrap_dpid_dict(dp, ports, to_user)


def get_meter_stats(dp, waiters, meter_id=None, to_user=True):
    if meter_id is None:
        meter_id = dp.ofproto.OFPM_ALL
    else:
        meter_id = str_to_int(meter_id)

    stats = dp.ofproto_parser.OFPMeterStatsRequest(
        dp, 0, meter_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    meters = []
    for msg in msgs:
        for stats in msg.body:
            bands = []
            for band in stats.band_stats:
                b = {'packet_band_count': band.packet_band_count,
                     'byte_band_count': band.byte_band_count}
                bands.append(b)
            s = {'len': stats.len,
                 'flow_count': stats.flow_count,
                 'packet_in_count': stats.packet_in_count,
                 'byte_in_count': stats.byte_in_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'band_stats': bands}

            if to_user:
                s['meter_id'] = UTIL.ofp_meter_to_user(stats.meter_id)

            else:
                s['meter_id'] = stats.meter_id

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

    band_type = {dp.ofproto.OFPMBT_DROP: 'DROP',
                 dp.ofproto.OFPMBT_DSCP_REMARK: 'DSCP_REMARK',
                 dp.ofproto.OFPMBT_EXPERIMENTER: 'EXPERIMENTER'}

    if meter_id is None:
        meter_id = dp.ofproto.OFPM_ALL
    else:
        meter_id = str_to_int(meter_id)

    stats = dp.ofproto_parser.OFPMeterConfigStatsRequest(
        dp, 0, meter_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    configs = []
    for msg in msgs:
        for config in msg.body:
            bands = []
            for band in config.bands:
                b = {'rate': band.rate,
                     'burst_size': band.burst_size}

                if to_user:
                    b['type'] = band_type.get(band.type, '')

                else:
                    b['type'] = band.type

                if band.type == dp.ofproto.OFPMBT_DSCP_REMARK:
                    b['prec_level'] = band.prec_level
                elif band.type == dp.ofproto.OFPMBT_EXPERIMENTER:
                    b['experimenter'] = band.experimenter
                bands.append(b)
            c_flags = []
            for k, v in sorted(flags.items()):
                if k & config.flags:
                    if to_user:
                        c_flags.append(v)

                    else:
                        c_flags.append(k)

            c = {'flags': c_flags,
                 'bands': bands}

            if to_user:
                c['meter_id'] = UTIL.ofp_meter_to_user(config.meter_id)

            else:
                c['meter_id'] = config.meter_id

            configs.append(c)

    return wrap_dpid_dict(dp, configs, to_user)


def get_group_stats(dp, waiters, group_id=None, to_user=True):
    if group_id is None:
        group_id = dp.ofproto.OFPG_ALL
    else:
        group_id = str_to_int(group_id)

    stats = dp.ofproto_parser.OFPGroupStatsRequest(
        dp, 0, group_id)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    groups = []
    for msg in msgs:
        for stats in msg.body:
            bucket_stats = []
            for bucket_stat in stats.bucket_stats:
                c = {'packet_count': bucket_stat.packet_count,
                     'byte_count': bucket_stat.byte_count}
                bucket_stats.append(c)
            g = {'length': stats.length,
                 'ref_count': stats.ref_count,
                 'packet_count': stats.packet_count,
                 'byte_count': stats.byte_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'bucket_stats': bucket_stats}

            if to_user:
                g['group_id'] = UTIL.ofp_group_to_user(stats.group_id)

            else:
                g['group_id'] = stats.group_id

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
                   ofp.OFPAT_POP_PBB: 'POP_PBB'}

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

    type_convert = {dp.ofproto.OFPGT_ALL: 'ALL',
                    dp.ofproto.OFPGT_SELECT: 'SELECT',
                    dp.ofproto.OFPGT_INDIRECT: 'INDIRECT',
                    dp.ofproto.OFPGT_FF: 'FF'}

    stats = dp.ofproto_parser.OFPGroupDescStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    descs = []
    for msg in msgs:
        for stats in msg.body:
            buckets = []
            for bucket in stats.buckets:
                actions = []
                for action in bucket.actions:
                    if to_user:
                        actions.append(action_to_str(action))

                    else:
                        actions.append(action)

                b = {'weight': bucket.weight,
                     'watch_port': bucket.watch_port,
                     'watch_group': bucket.watch_group,
                     'actions': actions}
                buckets.append(b)

            d = {'buckets': buckets}
            if to_user:
                d['group_id'] = UTIL.ofp_group_to_user(stats.group_id)
                d['type'] = type_convert.get(stats.type)

            else:
                d['group_id'] = stats.group_id
                d['type'] = stats.type

            descs.append(d)

    return wrap_dpid_dict(dp, descs, to_user)


def get_port_desc(dp, waiters, to_user=True):

    stats = dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    descs = []

    for msg in msgs:
        stats = msg.body
        for stat in stats:
            d = {'hw_addr': stat.hw_addr,
                 'name': stat.name.decode('utf-8', errors='replace'),
                 'config': stat.config,
                 'state': stat.state,
                 'curr': stat.curr,
                 'advertised': stat.advertised,
                 'supported': stat.supported,
                 'peer': stat.peer,
                 'curr_speed': stat.curr_speed,
                 'max_speed': stat.max_speed}

            if to_user:
                d['port_no'] = UTIL.ofp_port_to_user(stat.port_no)

            else:
                d['port_no'] = stat.port_no

            descs.append(d)

    return wrap_dpid_dict(dp, descs, to_user)


def get_role(dp, waiters, to_user=True):
    return ofctl_utils.get_role(dp, waiters, to_user)


def mod_flow_entry(dp, flow, cmd):
    cookie = str_to_int(flow.get('cookie', 0))
    cookie_mask = str_to_int(flow.get('cookie_mask', 0))
    table_id = UTIL.ofp_table_from_user(flow.get('table_id', 0))
    idle_timeout = str_to_int(flow.get('idle_timeout', 0))
    hard_timeout = str_to_int(flow.get('hard_timeout', 0))
    priority = str_to_int(flow.get('priority', 0))
    buffer_id = UTIL.ofp_buffer_from_user(
        flow.get('buffer_id', dp.ofproto.OFP_NO_BUFFER))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    flags = str_to_int(flow.get('flags', 0))
    match = to_match(dp, flow.get('match', {}))
    inst = to_actions(dp, flow.get('actions', []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        flags, match, inst)

    ofctl_utils.send_msg(dp, flow_mod, LOG)


def mod_meter_entry(dp, meter, cmd):

    flags_convert = {'KBPS': dp.ofproto.OFPMF_KBPS,
                     'PKTPS': dp.ofproto.OFPMF_PKTPS,
                     'BURST': dp.ofproto.OFPMF_BURST,
                     'STATS': dp.ofproto.OFPMF_STATS}

    flags = 0
    if 'flags' in meter:
        meter_flags = meter['flags']
        if not isinstance(meter_flags, list):
            meter_flags = [meter_flags]
        for flag in meter_flags:
            if flag not in flags_convert:
                LOG.error('Unknown meter flag: %s', flag)
                continue
            flags |= flags_convert.get(flag)

    meter_id = UTIL.ofp_meter_from_user(meter.get('meter_id', 0))

    bands = []
    for band in meter.get('bands', []):
        band_type = band.get('type')
        rate = str_to_int(band.get('rate', 0))
        burst_size = str_to_int(band.get('burst_size', 0))
        if band_type == 'DROP':
            bands.append(
                dp.ofproto_parser.OFPMeterBandDrop(rate, burst_size))
        elif band_type == 'DSCP_REMARK':
            prec_level = str_to_int(band.get('prec_level', 0))
            bands.append(
                dp.ofproto_parser.OFPMeterBandDscpRemark(
                    rate, burst_size, prec_level))
        elif band_type == 'EXPERIMENTER':
            experimenter = str_to_int(band.get('experimenter', 0))
            bands.append(
                dp.ofproto_parser.OFPMeterBandExperimenter(
                    rate, burst_size, experimenter))
        else:
            LOG.error('Unknown band type: %s', band_type)

    meter_mod = dp.ofproto_parser.OFPMeterMod(
        dp, cmd, flags, meter_id, bands)

    ofctl_utils.send_msg(dp, meter_mod, LOG)


def mod_group_entry(dp, group, cmd):

    type_convert = {'ALL': dp.ofproto.OFPGT_ALL,
                    'SELECT': dp.ofproto.OFPGT_SELECT,
                    'INDIRECT': dp.ofproto.OFPGT_INDIRECT,
                    'FF': dp.ofproto.OFPGT_FF}

    type_ = type_convert.get(group.get('type', 'ALL'))
    if type_ is None:
        LOG.error('Unknown group type: %s', group.get('type'))

    group_id = UTIL.ofp_group_from_user(group.get('group_id', 0))

    buckets = []
    for bucket in group.get('buckets', []):
        weight = str_to_int(bucket.get('weight', 0))
        watch_port = str_to_int(
            bucket.get('watch_port', dp.ofproto.OFPP_ANY))
        watch_group = str_to_int(
            bucket.get('watch_group', dp.ofproto.OFPG_ANY))
        actions = []
        for dic in bucket.get('actions', []):
            action = to_action(dp, dic)
            if action is not None:
                actions.append(action)
        buckets.append(dp.ofproto_parser.OFPBucket(
            weight, watch_port, watch_group, actions))

    group_mod = dp.ofproto_parser.OFPGroupMod(
        dp, cmd, type_, group_id, buckets)

    ofctl_utils.send_msg(dp, group_mod, LOG)


def mod_port_behavior(dp, port_config):
    port_no = UTIL.ofp_port_from_user(port_config.get('port_no', 0))
    hw_addr = str(port_config.get('hw_addr'))
    config = str_to_int(port_config.get('config', 0))
    mask = str_to_int(port_config.get('mask', 0))
    advertise = str_to_int(port_config.get('advertise'))

    port_mod = dp.ofproto_parser.OFPPortMod(
        dp, port_no, hw_addr, config, mask, advertise)

    ofctl_utils.send_msg(dp, port_mod, LOG)


def set_role(dp, role):
    r = UTIL.ofp_role_from_user(role.get('role', dp.ofproto.OFPCR_ROLE_EQUAL))
    role_request = dp.ofproto_parser.OFPRoleRequest(dp, r, 0)
    ofctl_utils.send_msg(dp, role_request, LOG)


# NOTE(jkoelker) Alias common funcitons
send_experimenter = ofctl_utils.send_experimenter
