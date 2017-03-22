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

import logging
import netaddr

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.lib import ofctl_utils


LOG = logging.getLogger('ryu.lib.ofctl_v1_2')

DEFAULT_TIMEOUT = 1.0

UTIL = ofctl_utils.OFCtlUtil(ofproto_v1_2)
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
            else:
                LOG.error('Unknown action type: %s', action_type)

    if actions:
        inst.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions))
    return inst


def action_to_str(act):
    action_type = act.cls_action_type

    if action_type == ofproto_v1_2.OFPAT_OUTPUT:
        port = UTIL.ofp_port_to_user(act.port)
        buf = 'OUTPUT:' + str(port)
    elif action_type == ofproto_v1_2.OFPAT_COPY_TTL_OUT:
        buf = 'COPY_TTL_OUT'
    elif action_type == ofproto_v1_2.OFPAT_COPY_TTL_IN:
        buf = 'COPY_TTL_IN'
    elif action_type == ofproto_v1_2.OFPAT_SET_MPLS_TTL:
        buf = 'SET_MPLS_TTL:' + str(act.mpls_ttl)
    elif action_type == ofproto_v1_2.OFPAT_DEC_MPLS_TTL:
        buf = 'DEC_MPLS_TTL'
    elif action_type == ofproto_v1_2.OFPAT_PUSH_VLAN:
        buf = 'PUSH_VLAN:' + str(act.ethertype)
    elif action_type == ofproto_v1_2.OFPAT_POP_VLAN:
        buf = 'POP_VLAN'
    elif action_type == ofproto_v1_2.OFPAT_PUSH_MPLS:
        buf = 'PUSH_MPLS:' + str(act.ethertype)
    elif action_type == ofproto_v1_2.OFPAT_POP_MPLS:
        buf = 'POP_MPLS:' + str(act.ethertype)
    elif action_type == ofproto_v1_2.OFPAT_SET_QUEUE:
        queue_id = UTIL.ofp_queue_to_user(act.queue_id)
        buf = 'SET_QUEUE:' + str(queue_id)
    elif action_type == ofproto_v1_2.OFPAT_GROUP:
        group_id = UTIL.ofp_group_to_user(act.group_id)
        buf = 'GROUP:' + str(group_id)
    elif action_type == ofproto_v1_2.OFPAT_SET_NW_TTL:
        buf = 'SET_NW_TTL:' + str(act.nw_ttl)
    elif action_type == ofproto_v1_2.OFPAT_DEC_NW_TTL:
        buf = 'DEC_NW_TTL'
    elif action_type == ofproto_v1_2.OFPAT_SET_FIELD:
        buf = 'SET_FIELD: {%s:%s}' % (act.key, act.value)
    else:
        buf = 'UNKNOWN'
    return buf


def actions_to_str(instructions):
    actions = []

    for instruction in instructions:
        if isinstance(instruction,
                      ofproto_v1_2_parser.OFPInstructionActions):
            if instruction.type == ofproto_v1_2.OFPIT_APPLY_ACTIONS:
                for a in instruction.actions:
                    actions.append(action_to_str(a))
            elif instruction.type == ofproto_v1_2.OFPIT_WRITE_ACTIONS:
                write_actions = []
                for a in instruction.actions:
                    write_actions.append(action_to_str(a))
                if write_actions:
                    actions.append({'WRITE_ACTIONS': write_actions})
            elif instruction.type == ofproto_v1_2.OFPIT_CLEAR_ACTIONS:
                actions.append('CLEAR_ACTIONS')
            else:
                actions.append('UNKNOWN')
        elif isinstance(instruction,
                        ofproto_v1_2_parser.OFPInstructionGotoTable):
            table_id = UTIL.ofp_table_to_user(instruction.table_id)
            buf = 'GOTO_TABLE:' + str(table_id)
            actions.append(buf)

        elif isinstance(instruction,
                        ofproto_v1_2_parser.OFPInstructionWriteMetadata):
            buf = ('WRITE_METADATA:0x%x/0x%x' % (instruction.metadata,
                                                 instruction.metadata_mask)
                   if instruction.metadata_mask
                   else 'WRITE_METADATA:0x%x' % instruction.metadata)
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
               'mpls_tc': str_to_int}

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
    return ofctl_utils.to_match_vid(value, ofproto_v1_2.OFPVID_PRESENT)


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
        value, mask, ofproto_v1_2.OFPVID_PRESENT)


def get_desc_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    s = {}
    for msg in msgs:
        stats = msg.body
        s = stats.to_jsondict()[stats.__class__.__name__]

    return {str(dp.id): s}


def get_queue_stats(dp, waiters, port=None, queue_id=None):
    ofp = dp.ofproto

    if port is None:
        port = ofp.OFPP_ANY
    else:
        port = str_to_int(port)

    if queue_id is None:
        queue_id = ofp.OFPQ_ALL
    else:
        queue_id = str_to_int(queue_id)

    stats = dp.ofproto_parser.OFPQueueStatsRequest(dp, port,
                                                   queue_id, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    s = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s.append({'port_no': stat.port_no,
                      'queue_id': stat.queue_id,
                      'tx_bytes': stat.tx_bytes,
                      'tx_errors': stat.tx_errors,
                      'tx_packets': stat.tx_packets})

    return {str(dp.id): s}


def get_queue_config(dp, waiters, port=None):
    ofp = dp.ofproto
    if port is None:
        port = ofp.OFPP_ANY
    else:
        port = UTIL.ofp_port_from_user(str_to_int(port))
    stats = dp.ofproto_parser.OFPQueueGetConfigRequest(dp, port)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    prop_type = {
        dp.ofproto.OFPQT_MIN_RATE: 'MIN_RATE',
        dp.ofproto.OFPQT_MAX_RATE: 'MAX_RATE',
        dp.ofproto.OFPQT_EXPERIMENTER: 'EXPERIMENTER',
    }

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
            q = {'port': UTIL.ofp_port_to_user(queue.port),
                 'properties': prop_list,
                 'queue_id': UTIL.ofp_queue_to_user(queue.queue_id)}
            queue_list.append(q)
        c = {'port': UTIL.ofp_port_to_user(config.port),
             'queues': queue_list}
        configs.append(c)

    return {str(dp.id): configs}


def get_flow_stats(dp, waiters, flow=None):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
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
        dp, table_id, out_port, out_group, cookie, cookie_mask, match)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            if 0 <= priority != stats.priority:
                continue

            actions = actions_to_str(stats.instructions)
            match = match_to_str(stats.match)
            s = {'priority': stats.priority,
                 'cookie': stats.cookie,
                 'idle_timeout': stats.idle_timeout,
                 'hard_timeout': stats.hard_timeout,
                 'actions': actions,
                 'match': match,
                 'byte_count': stats.byte_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'packet_count': stats.packet_count,
                 'table_id': UTIL.ofp_table_to_user(stats.table_id),
                 'length': stats.length}
            flows.append(s)

    return {str(dp.id): flows}


def get_aggregate_flow_stats(dp, waiters, flow=None):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = str_to_int(flow.get('cookie', 0))
    cookie_mask = str_to_int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))

    stats = dp.ofproto_parser.OFPAggregateStatsRequest(
        dp, table_id, out_port, out_group, cookie, cookie_mask, match)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        stats = msg.body
        s = {'packet_count': stats.packet_count,
             'byte_count': stats.byte_count,
             'flow_count': stats.flow_count}
        flows.append(s)

    return {str(dp.id): flows}


def get_table_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPTableStatsRequest(dp)
    ofp = dp.ofproto
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    oxm_type_convert = {ofp.OFPXMT_OFB_IN_PORT: 'IN_PORT',
                        ofp.OFPXMT_OFB_IN_PHY_PORT: 'IN_PHY_PORT',
                        ofp.OFPXMT_OFB_METADATA: 'METADATA',
                        ofp.OFPXMT_OFB_ETH_DST: 'ETH_DST',
                        ofp.OFPXMT_OFB_ETH_SRC: 'ETH_SRC',
                        ofp.OFPXMT_OFB_ETH_TYPE: 'ETH_TYPE',
                        ofp.OFPXMT_OFB_VLAN_VID: 'VLAN_VID',
                        ofp.OFPXMT_OFB_VLAN_PCP: 'VLAN_PCP',
                        ofp.OFPXMT_OFB_IP_DSCP: 'IP_DSCP',
                        ofp.OFPXMT_OFB_IP_ECN: 'IP_ECN',
                        ofp.OFPXMT_OFB_IP_PROTO: 'IP_PROTO',
                        ofp.OFPXMT_OFB_IPV4_SRC: 'IPV4_SRC',
                        ofp.OFPXMT_OFB_IPV4_DST: 'IPV4_DST',
                        ofp.OFPXMT_OFB_TCP_SRC: 'TCP_SRC',
                        ofp.OFPXMT_OFB_TCP_DST: 'TCP_DST',
                        ofp.OFPXMT_OFB_UDP_SRC: 'UDP_SRC',
                        ofp.OFPXMT_OFB_UDP_DST: 'UDP_DST',
                        ofp.OFPXMT_OFB_SCTP_SRC: 'SCTP_SRC',
                        ofp.OFPXMT_OFB_SCTP_DST: 'SCTP_DST',
                        ofp.OFPXMT_OFB_ICMPV4_TYPE: 'ICMPV4_TYPE',
                        ofp.OFPXMT_OFB_ICMPV4_CODE: 'ICMPV4_CODE',
                        ofp.OFPXMT_OFB_ARP_OP: 'ARP_OP',
                        ofp.OFPXMT_OFB_ARP_SPA: 'ARP_SPA',
                        ofp.OFPXMT_OFB_ARP_TPA: 'ARP_TPA',
                        ofp.OFPXMT_OFB_ARP_SHA: 'ARP_SHA',
                        ofp.OFPXMT_OFB_ARP_THA: 'ARP_THA',
                        ofp.OFPXMT_OFB_IPV6_SRC: 'IPV6_SRC',
                        ofp.OFPXMT_OFB_IPV6_DST: 'IPV6_DST',
                        ofp.OFPXMT_OFB_IPV6_FLABEL: 'IPV6_FLABEL',
                        ofp.OFPXMT_OFB_ICMPV6_TYPE: 'ICMPV6_TYPE',
                        ofp.OFPXMT_OFB_ICMPV6_CODE: 'ICMPV6_CODE',
                        ofp.OFPXMT_OFB_IPV6_ND_TARGET: 'IPV6_ND_TARGET',
                        ofp.OFPXMT_OFB_IPV6_ND_SLL: 'IPV6_ND_SLL',
                        ofp.OFPXMT_OFB_IPV6_ND_TLL: 'IPV6_ND_TLL',
                        ofp.OFPXMT_OFB_MPLS_LABEL: 'MPLS_LABEL',
                        ofp.OFPXMT_OFB_MPLS_TC: 'MPLS_TC'}

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
                   ofp.OFPAT_SET_FIELD: 'SET_FIELD'}

    inst_convert = {ofp.OFPIT_GOTO_TABLE: 'GOTO_TABLE',
                    ofp.OFPIT_WRITE_METADATA: 'WRITE_METADATA',
                    ofp.OFPIT_WRITE_ACTIONS: 'WRITE_ACTIONS',
                    ofp.OFPIT_APPLY_ACTIONS: 'APPLY_ACTIONS',
                    ofp.OFPIT_CLEAR_ACTIONS: 'CLEAR_ACTIONS',
                    ofp.OFPIT_EXPERIMENTER: 'EXPERIMENTER'}

    table_conf_convert = {
        ofp.OFPTC_TABLE_MISS_CONTROLLER: 'TABLE_MISS_CONTROLLER',
        ofp.OFPTC_TABLE_MISS_CONTINUE: 'TABLE_MISS_CONTINUE',
        ofp.OFPTC_TABLE_MISS_DROP: 'TABLE_MISS_DROP',
        ofp.OFPTC_TABLE_MISS_MASK: 'TABLE_MISS_MASK'}

    tables = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            match = []
            wildcards = []
            write_setfields = []
            apply_setfields = []
            for k, v in oxm_type_convert.items():
                if (1 << k) & stat.match:
                    match.append(v)
                if (1 << k) & stat.wildcards:
                    wildcards.append(v)
                if (1 << k) & stat.write_setfields:
                    write_setfields.append(v)
                if (1 << k) & stat.apply_setfields:
                    apply_setfields.append(v)
            write_actions = []
            apply_actions = []
            for k, v in act_convert.items():
                if (1 << k) & stat.write_actions:
                    write_actions.append(v)
                if (1 << k) & stat.apply_actions:
                    apply_actions.append(v)
            instructions = []
            for k, v in inst_convert.items():
                if (1 << k) & stat.instructions:
                    instructions.append(v)
            config = []
            for k, v in table_conf_convert.items():
                if (1 << k) & stat.config:
                    config.append(v)
            s = {'table_id': UTIL.ofp_table_to_user(stat.table_id),
                 'name': stat.name.decode('utf-8'),
                 'match': match,
                 'wildcards': wildcards,
                 'write_actions': write_actions,
                 'apply_actions': apply_actions,
                 'write_setfields': write_setfields,
                 'apply_setfields': apply_setfields,
                 'metadata_match': stat.metadata_match,
                 'metadata_write': stat.metadata_write,
                 'instructions': instructions,
                 'config': config,
                 'max_entries': stat.max_entries,
                 'active_count': stat.active_count,
                 'lookup_count': stat.lookup_count,
                 'matched_count': stat.matched_count}
            tables.append(s)

    return {str(dp.id): tables}


def get_port_stats(dp, waiters, port=None):
    if port is None:
        port = dp.ofproto.OFPP_ANY
    else:
        port = str_to_int(port)

    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, port, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    ports = []
    for msg in msgs:
        for stats in msg.body:
            s = {'port_no': UTIL.ofp_port_to_user(stats.port_no),
                 'rx_packets': stats.rx_packets,
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
                 'collisions': stats.collisions}
            ports.append(s)

    return {str(dp.id): ports}


def get_group_stats(dp, waiters, group_id=None):
    if group_id is None:
        group_id = dp.ofproto.OFPG_ALL
    else:
        group_id = str_to_int(group_id)

    stats = dp.ofproto_parser.OFPGroupStatsRequest(
        dp, group_id, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    groups = []
    for msg in msgs:
        for stats in msg.body:
            bucket_counters = []
            for bucket_counter in stats.bucket_counters:
                c = {'packet_count': bucket_counter.packet_count,
                     'byte_count': bucket_counter.byte_count}
                bucket_counters.append(c)
            g = {'length': stats.length,
                 'group_id': UTIL.ofp_group_to_user(stats.group_id),
                 'ref_count': stats.ref_count,
                 'packet_count': stats.packet_count,
                 'byte_count': stats.byte_count,
                 'bucket_stats': bucket_counters}
            groups.append(g)

    return {str(dp.id): groups}


def get_group_features(dp, waiters):

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
                   ofp.OFPAT_SET_FIELD: 'SET_FIELD'}

    stats = dp.ofproto_parser.OFPGroupFeaturesStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    features = []
    for msg in msgs:
        feature = msg.body
        types = []
        for k, v in type_convert.items():
            if (1 << k) & feature.types:
                types.append(v)
        capabilities = []
        for k, v in cap_convert.items():
            if k & feature.capabilities:
                capabilities.append(v)
        max_groups = []
        for k, v in type_convert.items():
            max_groups.append({v: feature.max_groups[k]})
        actions = []
        for k1, v1 in type_convert.items():
            acts = []
            for k2, v2 in act_convert.items():
                if (1 << k2) & feature.actions[k1]:
                    acts.append(v2)
            actions.append({v1: acts})
        f = {'types': types,
             'capabilities': capabilities,
             'max_groups': max_groups,
             'actions': actions}
        features.append(f)

    return {str(dp.id): features}


def get_group_desc(dp, waiters):

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
                    actions.append(action_to_str(action))
                b = {'weight': bucket.weight,
                     'watch_port': bucket.watch_port,
                     'watch_group': bucket.watch_group,
                     'actions': actions}
                buckets.append(b)
            d = {'type': type_convert.get(stats.type),
                 'group_id': UTIL.ofp_group_to_user(stats.group_id),
                 'buckets': buckets}
            descs.append(d)

    return {str(dp.id): descs}


def get_port_desc(dp, waiters):

    stats = dp.ofproto_parser.OFPFeaturesRequest(dp)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    descs = []

    for msg in msgs:
        stats = msg.ports
        for stat in stats.values():
            d = {'port_no': UTIL.ofp_port_to_user(stat.port_no),
                 'hw_addr': stat.hw_addr,
                 'name': stat.name.decode('utf-8'),
                 'config': stat.config,
                 'state': stat.state,
                 'curr': stat.curr,
                 'advertised': stat.advertised,
                 'supported': stat.supported,
                 'peer': stat.peer,
                 'curr_speed': stat.curr_speed,
                 'max_speed': stat.max_speed}
            descs.append(d)

    return {str(dp.id): descs}


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
