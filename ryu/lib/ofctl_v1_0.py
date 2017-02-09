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

import struct
import socket
import logging

from ryu.ofproto import ofproto_v1_0
from ryu.lib import ofctl_utils
from ryu.lib.mac import haddr_to_bin, haddr_to_str


LOG = logging.getLogger('ryu.lib.ofctl_v1_0')

DEFAULT_TIMEOUT = 1.0   # TODO:XXX

UTIL = ofctl_utils.OFCtlUtil(ofproto_v1_0)
str_to_int = ofctl_utils.str_to_int


def to_actions(dp, acts):
    actions = []
    for a in acts:
        action_type = a.get('type')
        if action_type == 'OUTPUT':
            port = UTIL.ofp_port_from_user(
                a.get('port', ofproto_v1_0.OFPP_NONE))
            # NOTE: The reason of this magic number (0xffe5)
            #       is because there is no good constant in of1.0.
            #       The same value as OFPCML_MAX of of1.2 and of1.3 is used.
            max_len = str_to_int(a.get('max_len', 0xffe5))
            actions.append(dp.ofproto_parser.OFPActionOutput(port, max_len))
        elif action_type == 'SET_VLAN_VID':
            vlan_vid = str_to_int(a.get('vlan_vid', 0xffff))
            actions.append(dp.ofproto_parser.OFPActionVlanVid(vlan_vid))
        elif action_type == 'SET_VLAN_PCP':
            vlan_pcp = str_to_int(a.get('vlan_pcp', 0))
            actions.append(dp.ofproto_parser.OFPActionVlanPcp(vlan_pcp))
        elif action_type == 'STRIP_VLAN':
            actions.append(dp.ofproto_parser.OFPActionStripVlan())
        elif action_type == 'SET_DL_SRC':
            dl_src = haddr_to_bin(a.get('dl_src'))
            actions.append(dp.ofproto_parser.OFPActionSetDlSrc(dl_src))
        elif action_type == 'SET_DL_DST':
            dl_dst = haddr_to_bin(a.get('dl_dst'))
            actions.append(dp.ofproto_parser.OFPActionSetDlDst(dl_dst))
        elif action_type == 'SET_NW_SRC':
            nw_src = ipv4_to_int(a.get('nw_src'))
            actions.append(dp.ofproto_parser.OFPActionSetNwSrc(nw_src))
        elif action_type == 'SET_NW_DST':
            nw_dst = ipv4_to_int(a.get('nw_dst'))
            actions.append(dp.ofproto_parser.OFPActionSetNwDst(nw_dst))
        elif action_type == 'SET_NW_TOS':
            nw_tos = str_to_int(a.get('nw_tos', 0))
            actions.append(dp.ofproto_parser.OFPActionSetNwTos(nw_tos))
        elif action_type == 'SET_TP_SRC':
            tp_src = str_to_int(a.get('tp_src', 0))
            actions.append(dp.ofproto_parser.OFPActionSetTpSrc(tp_src))
        elif action_type == 'SET_TP_DST':
            tp_dst = str_to_int(a.get('tp_dst', 0))
            actions.append(dp.ofproto_parser.OFPActionSetTpDst(tp_dst))
        elif action_type == 'ENQUEUE':
            port = UTIL.ofp_port_from_user(
                a.get('port', ofproto_v1_0.OFPP_NONE))
            queue_id = UTIL.ofp_queue_from_user(a.get('queue_id', 0))
            actions.append(dp.ofproto_parser.OFPActionEnqueue(port, queue_id))
        else:
            LOG.error('Unknown action type')

    return actions


def actions_to_str(acts):
    actions = []
    for a in acts:
        action_type = a.cls_action_type

        if action_type == ofproto_v1_0.OFPAT_OUTPUT:
            port = UTIL.ofp_port_to_user(a.port)
            buf = 'OUTPUT:' + str(port)
        elif action_type == ofproto_v1_0.OFPAT_SET_VLAN_VID:
            buf = 'SET_VLAN_VID:' + str(a.vlan_vid)
        elif action_type == ofproto_v1_0.OFPAT_SET_VLAN_PCP:
            buf = 'SET_VLAN_PCP:' + str(a.vlan_pcp)
        elif action_type == ofproto_v1_0.OFPAT_STRIP_VLAN:
            buf = 'STRIP_VLAN'
        elif action_type == ofproto_v1_0.OFPAT_SET_DL_SRC:
            buf = 'SET_DL_SRC:' + haddr_to_str(a.dl_addr)
        elif action_type == ofproto_v1_0.OFPAT_SET_DL_DST:
            buf = 'SET_DL_DST:' + haddr_to_str(a.dl_addr)
        elif action_type == ofproto_v1_0.OFPAT_SET_NW_SRC:
            buf = 'SET_NW_SRC:' + \
                  socket.inet_ntoa(struct.pack('!I', a.nw_addr))
        elif action_type == ofproto_v1_0.OFPAT_SET_NW_DST:
            buf = 'SET_NW_DST:' + \
                  socket.inet_ntoa(struct.pack('!I', a.nw_addr))
        elif action_type == ofproto_v1_0.OFPAT_SET_NW_TOS:
            buf = 'SET_NW_TOS:' + str(a.tos)
        elif action_type == ofproto_v1_0.OFPAT_SET_TP_SRC:
            buf = 'SET_TP_SRC:' + str(a.tp)
        elif action_type == ofproto_v1_0.OFPAT_SET_TP_DST:
            buf = 'SET_TP_DST:' + str(a.tp)
        elif action_type == ofproto_v1_0.OFPAT_ENQUEUE:
            port = UTIL.ofp_port_to_user(a.port)
            queue = UTIL.ofp_queue_to_user(a.queue_id)
            buf = 'ENQUEUE:' + str(port) + ":" + str(queue)
        elif action_type == ofproto_v1_0.OFPAT_VENDOR:
            buf = 'VENDOR'
        else:
            buf = 'UNKNOWN'
        actions.append(buf)

    return actions


def ipv4_to_int(addr):
    ip = addr.split('.')
    assert len(ip) == 4
    i = 0
    for b in ip:
        b = int(b)
        i = (i << 8) | b
    return i


def to_match(dp, attrs):
    ofp = dp.ofproto

    wildcards = ofp.OFPFW_ALL
    in_port = 0
    dl_src = 0
    dl_dst = 0
    dl_vlan = 0
    dl_vlan_pcp = 0
    dl_type = 0
    nw_tos = 0
    nw_proto = 0
    nw_src = 0
    nw_dst = 0
    tp_src = 0
    tp_dst = 0

    for key, value in attrs.items():
        if key == 'in_port':
            in_port = UTIL.ofp_port_from_user(value)
            wildcards &= ~ofp.OFPFW_IN_PORT
        elif key == 'dl_src':
            dl_src = haddr_to_bin(value)
            wildcards &= ~ofp.OFPFW_DL_SRC
        elif key == 'dl_dst':
            dl_dst = haddr_to_bin(value)
            wildcards &= ~ofp.OFPFW_DL_DST
        elif key == 'dl_vlan':
            dl_vlan = str_to_int(value)
            wildcards &= ~ofp.OFPFW_DL_VLAN
        elif key == 'dl_vlan_pcp':
            dl_vlan_pcp = str_to_int(value)
            wildcards &= ~ofp.OFPFW_DL_VLAN_PCP
        elif key == 'dl_type':
            dl_type = str_to_int(value)
            wildcards &= ~ofp.OFPFW_DL_TYPE
        elif key == 'nw_tos':
            nw_tos = str_to_int(value)
            wildcards &= ~ofp.OFPFW_NW_TOS
        elif key == 'nw_proto':
            nw_proto = str_to_int(value)
            wildcards &= ~ofp.OFPFW_NW_PROTO
        elif key == 'nw_src':
            ip = value.split('/')
            nw_src = struct.unpack('!I', socket.inet_aton(ip[0]))[0]
            mask = 32
            if len(ip) == 2:
                mask = int(ip[1])
                assert 0 < mask <= 32
            v = (32 - mask) << ofp.OFPFW_NW_SRC_SHIFT | \
                ~ofp.OFPFW_NW_SRC_MASK
            wildcards &= v
        elif key == 'nw_dst':
            ip = value.split('/')
            nw_dst = struct.unpack('!I', socket.inet_aton(ip[0]))[0]
            mask = 32
            if len(ip) == 2:
                mask = int(ip[1])
                assert 0 < mask <= 32
            v = (32 - mask) << ofp.OFPFW_NW_DST_SHIFT | \
                ~ofp.OFPFW_NW_DST_MASK
            wildcards &= v
        elif key == 'tp_src':
            tp_src = str_to_int(value)
            wildcards &= ~ofp.OFPFW_TP_SRC
        elif key == 'tp_dst':
            tp_dst = str_to_int(value)
            wildcards &= ~ofp.OFPFW_TP_DST
        else:
            LOG.error("unknown match name %s, %s, %d", key, value, len(key))

    match = dp.ofproto_parser.OFPMatch(
        wildcards, in_port, dl_src, dl_dst, dl_vlan, dl_vlan_pcp,
        dl_type, nw_tos, nw_proto, nw_src, nw_dst, tp_src, tp_dst)

    return match


def match_to_str(m):

    match = {}

    if ~m.wildcards & ofproto_v1_0.OFPFW_IN_PORT:
        match['in_port'] = UTIL.ofp_port_to_user(m.in_port)

    if ~m.wildcards & ofproto_v1_0.OFPFW_DL_SRC:
        match['dl_src'] = haddr_to_str(m.dl_src)

    if ~m.wildcards & ofproto_v1_0.OFPFW_DL_DST:
        match['dl_dst'] = haddr_to_str(m.dl_dst)

    if ~m.wildcards & ofproto_v1_0.OFPFW_DL_VLAN:
        match['dl_vlan'] = m.dl_vlan

    if ~m.wildcards & ofproto_v1_0.OFPFW_DL_VLAN_PCP:
        match['dl_vlan_pcp'] = m.dl_vlan_pcp

    if ~m.wildcards & ofproto_v1_0.OFPFW_DL_TYPE:
        match['dl_type'] = m.dl_type

    if ~m.wildcards & ofproto_v1_0.OFPFW_NW_TOS:
        match['nw_tos'] = m.nw_tos

    if ~m.wildcards & ofproto_v1_0.OFPFW_NW_PROTO:
        match['nw_proto'] = m.nw_proto

    if ~m.wildcards & ofproto_v1_0.OFPFW_NW_SRC_ALL:
        match['nw_src'] = nw_src_to_str(m.wildcards, m.nw_src)

    if ~m.wildcards & ofproto_v1_0.OFPFW_NW_DST_ALL:
        match['nw_dst'] = nw_dst_to_str(m.wildcards, m.nw_dst)

    if ~m.wildcards & ofproto_v1_0.OFPFW_TP_SRC:
        match['tp_src'] = m.tp_src

    if ~m.wildcards & ofproto_v1_0.OFPFW_TP_DST:
        match['tp_dst'] = m.tp_dst

    return match


def nw_src_to_str(wildcards, addr):
    ip = socket.inet_ntoa(struct.pack('!I', addr))
    mask = 32 - ((wildcards & ofproto_v1_0.OFPFW_NW_SRC_MASK) >>
                 ofproto_v1_0.OFPFW_NW_SRC_SHIFT)
    if mask == 32:
        mask = 0
    if mask:
        ip += '/%d' % mask
    return ip


def nw_dst_to_str(wildcards, addr):
    ip = socket.inet_ntoa(struct.pack('!I', addr))
    mask = 32 - ((wildcards & ofproto_v1_0.OFPFW_NW_DST_MASK) >>
                 ofproto_v1_0.OFPFW_NW_DST_SHIFT)
    if mask == 32:
        mask = 0
    if mask:
        ip += '/%d' % mask
    return ip


def get_desc_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp, 0)
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)
    s = {}

    for msg in msgs:
        stats = msg.body
        s = {'mfr_desc': stats.mfr_desc,
             'hw_desc': stats.hw_desc,
             'sw_desc': stats.sw_desc,
             'serial_num': stats.serial_num,
             'dp_desc': stats.dp_desc}

    return {str(dp.id): s}


def get_queue_stats(dp, waiters, port=None, queue_id=None):
    if port is None:
        port = dp.ofproto.OFPP_ALL
    else:
        port = str_to_int(port)

    if queue_id is None:
        queue_id = dp.ofproto.OFPQ_ALL
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
            s.append({'port_no': stat.port_no,
                      'queue_id': stat.queue_id,
                      'tx_bytes': stat.tx_bytes,
                      'tx_errors': stat.tx_errors,
                      'tx_packets': stat.tx_packets})

    return {str(dp.id): s}


def get_flow_stats(dp, waiters, flow=None):
    flow = flow if flow else {}
    match = to_match(dp, flow.get('match', {}))
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', 0xff))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_NONE))
    # Note: OpenFlow does not allow to filter flow entries by priority,
    # but for efficiency, ofctl provides the way to do it.
    priority = str_to_int(flow.get('priority', -1))

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, 0, match, table_id, out_port)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            if 0 <= priority != stats.priority:
                continue

            actions = actions_to_str(stats.actions)
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
                 'table_id': UTIL.ofp_table_to_user(stats.table_id)}
            flows.append(s)

    return {str(dp.id): flows}


def get_aggregate_flow_stats(dp, waiters, flow=None):
    flow = flow if flow else {}
    match = to_match(dp, flow.get('match', {}))
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', 0xff))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_NONE))

    stats = dp.ofproto_parser.OFPAggregateStatsRequest(
        dp, 0, match, table_id, out_port)

    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    flows = []
    for msg in msgs:
        stats = msg.body
        for st in stats:
            s = {'packet_count': st.packet_count,
                 'byte_count': st.byte_count,
                 'flow_count': st.flow_count}
            flows.append(s)

    return {str(dp.id): flows}


def get_table_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPTableStatsRequest(dp, 0)
    ofp = dp.ofproto
    msgs = []
    ofctl_utils.send_stats_request(dp, stats, waiters, msgs, LOG)

    match_convert = {ofp.OFPFW_IN_PORT: 'IN_PORT',
                     ofp.OFPFW_DL_VLAN: 'DL_VLAN',
                     ofp.OFPFW_DL_SRC: 'DL_SRC',
                     ofp.OFPFW_DL_DST: 'DL_DST',
                     ofp.OFPFW_DL_TYPE: 'DL_TYPE',
                     ofp.OFPFW_NW_PROTO: 'NW_PROTO',
                     ofp.OFPFW_TP_SRC: 'TP_SRC',
                     ofp.OFPFW_TP_DST: 'TP_DST',
                     ofp.OFPFW_NW_SRC_SHIFT: 'NW_SRC_SHIFT',
                     ofp.OFPFW_NW_SRC_BITS: 'NW_SRC_BITS',
                     ofp.OFPFW_NW_SRC_MASK: 'NW_SRC_MASK',
                     ofp.OFPFW_NW_SRC: 'NW_SRC',
                     ofp.OFPFW_NW_SRC_ALL: 'NW_SRC_ALL',
                     ofp.OFPFW_NW_DST_SHIFT: 'NW_DST_SHIFT',
                     ofp.OFPFW_NW_DST_BITS: 'NW_DST_BITS',
                     ofp.OFPFW_NW_DST_MASK: 'NW_DST_MASK',
                     ofp.OFPFW_NW_DST: 'NW_DST',
                     ofp.OFPFW_NW_DST_ALL: 'NW_DST_ALL',
                     ofp.OFPFW_DL_VLAN_PCP: 'DL_VLAN_PCP',
                     ofp.OFPFW_NW_TOS: 'NW_TOS',
                     ofp.OFPFW_ALL: 'ALL',
                     ofp.OFPFW_ICMP_TYPE: 'ICMP_TYPE',
                     ofp.OFPFW_ICMP_CODE: 'ICMP_CODE'}

    tables = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            wildcards = []
            for k, v in match_convert.items():
                if (1 << k) & stat.wildcards:
                    wildcards.append(v)
            s = {'table_id': UTIL.ofp_table_to_user(stat.table_id),
                 'name': stat.name.decode('utf-8'),
                 'wildcards': wildcards,
                 'max_entries': stat.max_entries,
                 'active_count': stat.active_count,
                 'lookup_count': stat.lookup_count,
                 'matched_count': stat.matched_count}
            tables.append(s)

    return {str(dp.id): tables}


def get_port_stats(dp, waiters, port=None):
    if port is None:
        port = dp.ofproto.OFPP_NONE
    else:
        port = str_to_int(port)

    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, 0, port)
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
                 'peer': stat.peer}
            descs.append(d)

    return {str(dp.id): descs}


def mod_flow_entry(dp, flow, cmd):
    cookie = str_to_int(flow.get('cookie', 0))
    priority = str_to_int(
        flow.get('priority', dp.ofproto.OFP_DEFAULT_PRIORITY))
    buffer_id = UTIL.ofp_buffer_from_user(
        flow.get('buffer_id', dp.ofproto.OFP_NO_BUFFER))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_NONE))
    flags = str_to_int(flow.get('flags', 0))
    idle_timeout = str_to_int(flow.get('idle_timeout', 0))
    hard_timeout = str_to_int(flow.get('hard_timeout', 0))
    actions = to_actions(dp, flow.get('actions', []))
    match = to_match(dp, flow.get('match', {}))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        datapath=dp, match=match, cookie=cookie,
        command=cmd, idle_timeout=idle_timeout,
        hard_timeout=hard_timeout, priority=priority,
        buffer_id=buffer_id, out_port=out_port,
        flags=flags,
        actions=actions)

    ofctl_utils.send_msg(dp, flow_mod, LOG)


def delete_flow_entry(dp):
    match = dp.ofproto_parser.OFPMatch(
        dp.ofproto.OFPFW_ALL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        datapath=dp, match=match, cookie=0,
        command=dp.ofproto.OFPFC_DELETE)

    ofctl_utils.send_msg(dp, flow_mod, LOG)


def mod_port_behavior(dp, port_config):
    port_no = UTIL.ofp_port_from_user(port_config.get('port_no', 0))
    hw_addr = str(port_config.get('hw_addr'))
    config = str_to_int(port_config.get('config', 0))
    mask = str_to_int(port_config.get('mask', 0))
    advertise = str_to_int(port_config.get('advertise'))

    port_mod = dp.ofproto_parser.OFPPortMod(
        dp, port_no, hw_addr, config, mask, advertise)

    ofctl_utils.send_msg(dp, port_mod, LOG)
