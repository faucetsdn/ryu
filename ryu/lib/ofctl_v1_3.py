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
import struct
import socket
import logging
import netaddr

from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib import hub
from ryu.lib import mac


LOG = logging.getLogger('ryu.lib.ofctl_v1_3')

DEFAULT_TIMEOUT = 1.0


def str_to_int(src):
    if isinstance(src, str):
        if src.startswith("0x") or src.startswith("0X"):
            dst = int(src, 16)
        else:
            dst = int(src)
    else:
        dst = src
    return dst


def to_action(dp, dic):
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    result = None
    action_type = dic.get('type')
    if action_type == 'OUTPUT':
        out_port = int(dic.get('port', ofp.OFPP_ANY))
        max_len = int(dic.get('max_len', ofp.OFPCML_MAX))
        result = parser.OFPActionOutput(out_port, max_len)
    elif action_type == 'COPY_TTL_OUT':
        result = parser.OFPActionCopyTtlOut()
    elif action_type == 'COPY_TTL_IN':
        result = parser.OFPActionCopyTtlIn()
    elif action_type == 'SET_MPLS_TTL':
        mpls_ttl = int(dic.get('mpls_ttl'))
        result = parser.OFPActionSetMplsTtl(mpls_ttl)
    elif action_type == 'DEC_MPLS_TTL':
        result = parser.OFPActionDecMplsTtl()
    elif action_type == 'PUSH_VLAN':
        ethertype = int(dic.get('ethertype'))
        result = parser.OFPActionPushVlan(ethertype)
    elif action_type == 'POP_VLAN':
        result = parser.OFPActionPopVlan()
    elif action_type == 'PUSH_MPLS':
        ethertype = int(dic.get('ethertype'))
        result = parser.OFPActionPushMpls(ethertype)
    elif action_type == 'POP_MPLS':
        ethertype = int(dic.get('ethertype'))
        result = parser.OFPActionPopMpls(ethertype)
    elif action_type == 'SET_QUEUE':
        queue_id = int(dic.get('queue_id'))
        result = parser.OFPActionSetQueue(queue_id)
    elif action_type == 'GROUP':
        group_id = int(dic.get('group_id'))
        result = parser.OFPActionGroup(group_id)
    elif action_type == 'SET_NW_TTL':
        nw_ttl = int(dic.get('nw_ttl'))
        result = parser.OFPActionSetNwTtl(nw_ttl)
    elif action_type == 'DEC_NW_TTL':
        result = parser.OFPActionDecNwTtl()
    elif action_type == 'SET_FIELD':
        field = dic.get('field')
        value = dic.get('value')
        if field == 'eth_dst':
            field = ofp.OXM_OF_ETH_DST
            value = mac.haddr_to_bin(str(value))
        elif field == 'eth_src':
            field = ofp.OXM_OF_ETH_SRC
            value = mac.haddr_to_bin(str(value))
        elif field == 'vlan_vid':
            field = ofp.OXM_OF_VLAN_VID
            value = int(value)
        elif field == 'mpls_label':
            field = ofp.OXM_OF_MPLS_LABEL
            value = int(value)
        else:
            LOG.debug('Unknown field: %s' % field)
            return None
        f = parser.OFPMatchField.make(field, value)
        result = parser.OFPActionSetField(f)
    elif action_type == 'PUSH_PBB':
        ethertype = int(dic.get('ethertype'))
        result = parser.OFPActionPushPbb(ethertype)
    elif action_type == 'POP_PBB':
        result = parser.OFPActionPopPbb()
    else:
        LOG.debug('Unknown action type: %s' % action_type)

    return result


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
            if action_type == 'GOTO_TABLE':
                table_id = int(a.get('table_id'))
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
                meter_id = int(a.get('meter_id'))
                inst.append(parser.OFPInstructionMeter(meter_id))
            else:
                LOG.debug('Unknown action type: %s' % action_type)

    inst.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions))
    return inst


def action_to_str(act):
    action_type = act.cls_action_type

    if action_type == ofproto_v1_3.OFPAT_OUTPUT:
        buf = 'OUTPUT:' + str(act.port)
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
        buf = 'POP_MPLS'
    elif action_type == ofproto_v1_3.OFPAT_OFPAT_SET_QUEUE:
        buf = 'SET_QUEUE:' + str(act.queue_id)
    elif action_type == ofproto_v1_3.OFPAT_GROUP:
        pass
    elif action_type == ofproto_v1_3.OFPAT_SET_NW_TTL:
        buf = 'SET_NW_TTL:' + str(act.nw_ttl)
    elif action_type == ofproto_v1_3.OFPAT_DEC_NW_TTL:
        buf = 'DEC_NW_TTL'
    elif action_type == ofproto_v1_3.OFPAT_SET_FIELD:
        buf = 'SET_FIELD: {%s:%s}' % (act.field, act.value)
    elif action_type == ofproto_v1_3.OFPAT_PUSH_PBB:
        buf = 'PUSH_PBB:' + str(act.ethertype)
    elif action_type == ofproto_v1_3.OFPAT_POP_PBB:
        buf = 'POP_PBB'
    else:
        buf = 'UNKNOWN'
    return buf


def actions_to_str(instructions):
    actions = []

    for instruction in instructions:
        if isinstance(instruction,
                      ofproto_v1_3_parser.OFPInstructionActions):
            for a in instruction.actions:
                actions.append(action_to_str(a))

        elif isinstance(instruction,
                        ofproto_v1_3_parser.OFPInstructionGotoTable):
            buf = 'GOTO_TABLE:' + str(instruction.table_id)
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
            buf = 'METER:' + str(instruction.meter_id)
            actions.append(buf)

        else:
            continue

    return actions


def to_match(dp, attrs):
    match = dp.ofproto_parser.OFPMatch()

    convert = {'in_port': int,
               'dl_src': mac.haddr_to_bin,
               'dl_dst': mac.haddr_to_bin,
               'dl_type': int,
               'dl_vlan': int,
               'nw_src': to_match_ip,
               'nw_dst': to_match_ip,
               'nw_proto': int,
               'tp_src': int,
               'tp_dst': int,
               'mpls_label': int,
               'metadata': to_match_metadata,
               'eth_src': mac.haddr_to_bin,
               'eth_dst': mac.haddr_to_bin,
               'eth_type': int,
               'vlan_vid': int,
               'ipv4_src': to_match_ip,
               'ipv4_dst': to_match_ip,
               'ip_proto': int,
               'tcp_src': int,
               'tcp_dst': int,
               'udp_src': int,
               'udp_dst': int,
               'ipv6_src': to_match_ipv6,
               'ipv6_dst': to_match_ipv6}

    match_append = {'in_port': match.set_in_port,
                    'dl_src': match.set_dl_src,
                    'dl_dst': match.set_dl_dst,
                    'dl_type': match.set_dl_type,
                    'dl_vlan': match.set_vlan_vid,
                    'nw_src': match.set_ipv4_src_masked,
                    'nw_dst': match.set_ipv4_dst_masked,
                    'nw_proto': match.set_ip_proto,
                    'tp_src': to_match_tpsrc,
                    'tp_dst': to_match_tpdst,
                    'mpls_label': match.set_mpls_label,
                    'metadata': match.set_metadata_masked,
                    'eth_src': match.set_dl_src,
                    'eth_dst': match.set_dl_dst,
                    'eth_type': match.set_dl_type,
                    'vlan_vid': match.set_vlan_vid,
                    'ipv4_src': match.set_ipv4_src_masked,
                    'ipv4_dst': match.set_ipv4_dst_masked,
                    'ip_proto': match.set_ip_proto,
                    'tcp_src': to_match_tpsrc,
                    'tcp_dst': to_match_tpdst,
                    'udp_src': to_match_tpsrc,
                    'udp_dst': to_match_tpdst,
                    'ipv6_src': match.set_ipv6_src_masked,
                    'ipv6_dst': match.set_ipv6_dst_masked}

    for key, value in attrs.items():
        if key in convert:
            value = convert[key](value)
        if key in match_append:
            if key == 'nw_src' or key == 'nw_dst' or \
                    key == 'ipv4_src' or key == 'ipv4_dst' or \
                    key == 'ipv6_src' or key == 'ipv6_dst':
                # IP address
                ip = value[0]
                mask = value[1]
                match_append[key](ip, mask)
            elif key == 'tp_src' or key == 'tp_dst' or \
                    key == 'tcp_src' or key == 'tcp_dst' or \
                    key == 'udp_src' or key == 'udp_dst':
                # tp_src/dst
                match_append[key](value, match, attrs)
            elif key == 'metadata':
                # metadata
                metadata = value[0]
                metadata_mask = value[1]
                match_append[key](metadata, metadata_mask)
            else:
                # others
                match_append[key](value)

    return match


def to_match_tpsrc(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_src,
                    inet.IPPROTO_UDP: match.set_udp_src}

    nw_proto = rest.get('nw_proto', rest.get('ip_proto', 0))
    if nw_proto in match_append:
        match_append[nw_proto](value)

    return match


def to_match_tpdst(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_dst,
                    inet.IPPROTO_UDP: match.set_udp_dst}

    nw_proto = rest.get('nw_proto', rest.get('ip_proto', 0))
    if nw_proto in match_append:
        match_append[nw_proto](value)

    return match


def to_match_ip(value):
    ip_mask = value.split('/')
    # ip
    ipv4 = struct.unpack('!I', socket.inet_aton(ip_mask[0]))[0]
    # netmask
    mask = 32
    if len(ip_mask) == 2:
        mask = int(ip_mask[1])
    netmask = ofproto_v1_3_parser.UINT32_MAX << 32 - mask\
        & ofproto_v1_3_parser.UINT32_MAX

    return ipv4, netmask


def to_match_ipv6(value):
    ip = netaddr.IPNetwork(value)
    return ip.ip.words, ip.netmask.words


def to_match_metadata(value):
    if '/' in value:
        metadata = value.split('/')
        return str_to_int(metadata[0]), str_to_int(metadata[1])
    else:
        return str_to_int(value), ofproto_v1_3_parser.UINT64_MAX


def match_to_str(ofmatch):
    keys = {ofproto_v1_3.OXM_OF_IN_PORT: 'in_port',
            ofproto_v1_3.OXM_OF_ETH_SRC: 'dl_src',
            ofproto_v1_3.OXM_OF_ETH_DST: 'dl_dst',
            ofproto_v1_3.OXM_OF_ETH_TYPE: 'dl_type',
            ofproto_v1_3.OXM_OF_VLAN_VID: 'dl_vlan',
            ofproto_v1_3.OXM_OF_IPV4_SRC: 'nw_src',
            ofproto_v1_3.OXM_OF_IPV4_DST: 'nw_dst',
            ofproto_v1_3.OXM_OF_IPV4_SRC_W: 'nw_src',
            ofproto_v1_3.OXM_OF_IPV4_DST_W: 'nw_dst',
            ofproto_v1_3.OXM_OF_IP_PROTO: 'nw_proto',
            ofproto_v1_3.OXM_OF_TCP_SRC: 'tp_src',
            ofproto_v1_3.OXM_OF_TCP_DST: 'tp_dst',
            ofproto_v1_3.OXM_OF_UDP_SRC: 'tp_src',
            ofproto_v1_3.OXM_OF_UDP_DST: 'tp_dst',
            ofproto_v1_3.OXM_OF_METADATA: 'metadata',
            ofproto_v1_3.OXM_OF_METADATA_W: 'metadata',
            ofproto_v1_3.OXM_OF_IPV6_SRC: 'ipv6_src',
            ofproto_v1_3.OXM_OF_IPV6_DST: 'ipv6_dst',
            ofproto_v1_3.OXM_OF_IPV6_SRC_W: 'ipv6_src',
            ofproto_v1_3.OXM_OF_IPV6_DST_W: 'ipv6_dst'}

    match = {}
    for match_field in ofmatch.fields:
        key = keys[match_field.header]
        if key == 'dl_src' or key == 'dl_dst':
            value = mac.haddr_to_str(match_field.value)
        elif key == 'nw_src' or key == 'nw_dst':
            value = match_ip_to_str(match_field.value, match_field.mask)
        elif key == 'ipv6_src' or key == 'ipv6_dst':
            value = match_ipv6_to_str(match_field.value, match_field.mask)
        elif key == 'metadata':
            value = ('%d/%d' % (match_field.value, match_field.mask)
                     if match_field.mask else '%d' % match_field.value)
        else:
            value = match_field.value
        match.setdefault(key, value)

    return match


def match_ip_to_str(value, mask):
    ip = socket.inet_ntoa(struct.pack('!I', value))

    if mask is not None and mask != 0:
        binary_str = bin(mask)[2:].zfill(8)
        netmask = '/%d' % len(binary_str.rstrip('0'))
    else:
        netmask = ''

    return ip + netmask


def match_ipv6_to_str(value, mask):
    ip_list = []
    for word in value:
        ip_list.append('%04x' % word)
    ip = netaddr.IPNetwork(':'.join(ip_list))

    netmask = 128
    if mask is not None:
        mask_list = []
        for word in mask:
            mask_list.append('%04x' % word)
        mask_v = netaddr.IPNetwork(':'.join(mask_list))
        netmask = len(mask_v.ip.bits().replace(':', '').rstrip('0'))

    if netmask == 128:
        ip_str = str(ip.ip)
    else:
        ip.prefixlen = netmask
        ip_str = str(ip)

    return ip_str


def send_stats_request(dp, stats, waiters, msgs):
    dp.set_xid(stats)
    waiters_per_dp = waiters.setdefault(dp.id, {})
    lock = hub.Event()
    waiters_per_dp[stats.xid] = (lock, msgs)
    dp.send_msg(stats)

    try:
        lock.wait(timeout=DEFAULT_TIMEOUT)
    except hub.Timeout:
        del waiters_per_dp[stats.xid]


def get_desc_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    for msg in msgs:
        stats = msg.body
        s = {'mfr_desc': stats.mfr_desc,
             'hw_desc': stats.hw_desc,
             'sw_desc': stats.sw_desc,
             'serial_num': stats.serial_num,
             'dp_desc': stats.dp_desc}
    desc = {str(dp.id): s}
    return desc


def get_flow_stats(dp, waiters):
    table_id = 0
    flags = 0
    out_port = dp.ofproto.OFPP_ANY
    out_group = dp.ofproto.OFPG_ANY
    cookie = 0
    cookie_mask = 0
    match = dp.ofproto_parser.OFPMatch()

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    flows = []
    for msg in msgs:
        for stats in msg.body:
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
                 'table_id': stats.table_id}
            flows.append(s)
    flows = {str(dp.id): flows}

    return flows


def get_port_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, 0, dp.ofproto.OFPP_ANY)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    ports = []
    for msg in msgs:
        for stats in msg.body:
            s = {'port_no': stats.port_no,
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
    ports = {str(dp.id): ports}
    return ports


def get_meter_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPMeterStatsRequest(
        dp, 0, dp.ofproto.OFPM_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    meters = []
    for msg in msgs:
        for stats in msg.body:
            bands = []
            for band in stats.band_stats:
                b = {'packet_band_count': band.packet_band_count,
                     'byte_band_count': band.byte_band_count}
                bands.append(b)
            s = {'meter_id': stats.meter_id,
                 'len': stats.len,
                 'flow_count': stats.flow_count,
                 'packet_in_count': stats.packet_in_count,
                 'byte_in_count': stats.byte_in_count,
                 'band_stats': bands}
            meters.append(s)
    meters = {str(dp.id): meters}
    return meters


def get_meter_features(dp, waiters):
    stats = dp.ofproto_parser.OFPMeterFeaturesStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    features = []
    for msg in msgs:
        for feature in msg.body:
            f = {'max_meter': feature.max_meter,
                 'band_types': feature.band_types,
                 'max_band': feature.max_band,
                 'max_color': feature.max_color}
            features.append(f)
    features = {str(dp.id): features}
    return features


def get_meter_config(dp, waiters):
    flags = {dp.ofproto.OFPMF_KBPS: 'KBPS',
             dp.ofproto.OFPMF_PKTPS: 'PKTPS',
             dp.ofproto.OFPMF_BURST: 'BURST',
             dp.ofproto.OFPMF_STATS: 'STATS'}

    band_type = {dp.ofproto.OFPMBT_DROP: 'DROP',
                 dp.ofproto.OFPMBT_DSCP_REMARK: 'REMARK',
                 dp.ofproto.OFPMBT_EXPERIMENTER: 'EXPERIMENTER'}

    stats = dp.ofproto_parser.OFPMeterConfigStatsRequest(
        dp, 0, dp.ofproto.OFPM_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    configs = []
    for msg in msgs:
        for config in msg.body:
            bands = []
            for band in config.bands:
                b = {'type': band_type.get(band.type, ''),
                     'rate': band.rate,
                     'burst_size': band.burst_size}
                if band.type == dp.ofproto.OFPMBT_DSCP_REMARK:
                    b['prec_level'] = band.prec_level
                elif band.type == dp.ofproto.OFPMBT_EXPERIMENTER:
                    b['experimenter'] = band.experimenter
                bands.append(b)
            c = {'flags': flags.get(config.flags, 0),
                 'meter_id': config.meter_id,
                 'bands': bands}
            configs.append(c)
    configs = {str(dp.id): configs}
    return configs


def get_group_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPGroupStatsRequest(
        dp, 0, dp.ofproto.OFPG_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    groups = []
    for msg in msgs:
        for stats in msg.body:
            bucket_stats = []
            for bucket_stat in stats.bucket_stats:
                c = {'packet_count': bucket_stat.packet_count,
                     'byte_count': bucket_stat.byte_count}
                bucket_stats.append(c)
            g = {'group_id': stats.group_id,
                 'ref_count': stats.ref_count,
                 'packet_count': stats.packet_count,
                 'byte_count': stats.byte_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'bucket_stats': bucket_stats}
            groups.append(g)
    groups = {str(dp.id): groups}
    return groups


def get_group_features(dp, waiters):

    ofp = dp.ofproto
    type_convert = {ofp.OFPGT_ALL: 'ALL',
                    ofp.OFPGT_SELECT: 'SELECT',
                    ofp.OFPGT_INDIRECT: 'INDIRECT',
                    ofp.OFPGT_FF: 'FF'}
    cap_convert = {ofp.OFPGFC_SELECT_WEIGHT: 'SELECT_WEIGHT',
                   ofp.OFPGFC_SELECT_LIVENESS: 'SELECT_LIVENESS',
                   ofp.OFPGFC_CHAINING: 'CHAINING',
                   ofp.OFPGFC_CHAINING_CHECKS: 'CHAINING_CHCEKS'}
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
    send_stats_request(dp, stats, waiters, msgs)

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
    features = {str(dp.id): features}
    return features


def get_group_desc(dp, waiters):

    type_convert = {dp.ofproto.OFPGT_ALL: 'ALL',
                    dp.ofproto.OFPGT_SELECT: 'SELECT',
                    dp.ofproto.OFPGT_INDIRECT: 'INDIRECT',
                    dp.ofproto.OFPGT_FF: 'FF'}

    stats = dp.ofproto_parser.OFPGroupDescStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

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
                 'group_id': stats.group_id,
                 'buckets': buckets}
            descs.append(d)
    descs = {str(dp.id): descs}
    return descs


def mod_flow_entry(dp, flow, cmd):
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    table_id = int(flow.get('table_id', 0))
    idle_timeout = int(flow.get('idle_timeout', 0))
    hard_timeout = int(flow.get('hard_timeout', 0))
    priority = int(flow.get('priority', 0))
    buffer_id = int(flow.get('buffer_id', dp.ofproto.OFP_NO_BUFFER))
    out_port = int(flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = int(flow.get('out_group', dp.ofproto.OFPG_ANY))
    flags = int(flow.get('flags', 0))
    match = to_match(dp, flow.get('match', {}))
    inst = to_actions(dp, flow.get('actions', []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        flags, match, inst)

    dp.send_msg(flow_mod)


def mod_meter_entry(dp, flow, cmd):

    flags_convert = {'KBPS': dp.ofproto.OFPMF_KBPS,
                     'PKTPS': dp.ofproto.OFPMF_PKTPS,
                     'BURST': dp.ofproto.OFPMF_BURST,
                     'STATS': dp.ofproto.OFPMF_STATS}

    flags = flags_convert.get(flow.get('flags'))
    if not flags:
        LOG.debug('Unknown flags: %s', flow.get('flags'))

    meter_id = int(flow.get('meter_id', 0))

    bands = []
    for band in flow.get('bands', []):
        band_type = band.get('type')
        rate = int(band.get('rate', 0))
        burst_size = int(band.get('burst_size', 0))
        if band_type == 'DROP':
            bands.append(
                dp.ofproto_parser.OFPMeterBandDrop(rate, burst_size))
        elif band_type == 'REMARK':
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
            LOG.debug('Unknown band type: %s', band_type)

    meter_mod = dp.ofproto_parser.OFPMeterMod(
        dp, cmd, flags, meter_id, bands)

    dp.send_msg(meter_mod)


def mod_group_entry(dp, group, cmd):

    type_convert = {'ALL': dp.ofproto.OFPGT_ALL,
                    'SELECT': dp.ofproto.OFPGT_SELECT,
                    'INDIRECT': dp.ofproto.OFPGT_INDIRECT,
                    'FF': dp.ofproto.OFPGT_FF}

    type_ = type_convert.get(group.get('type'))
    if not type_:
        LOG.debug('Unknown type: %s', group.get('type'))

    group_id = int(group.get('group_id', 0))

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
        dp, cmd, type_, group_id, buckets)

    dp.send_msg(group_mod)


def send_experimenter(dp, exp):
    experimenter = exp.get('experimenter', 0)
    exp_type = exp.get('exp_type', 0)
    data_type = exp.get('data_type', 'ascii')
    if data_type != 'ascii' and data_type != 'base64':
        LOG.debug('Unknown data type: %s', data_type)
    data = exp.get('data', '')
    if data_type == 'base64':
        data = base64.b64decode(data)

    expmsg = dp.ofproto_parser.OFPExperimenter(
        dp, experimenter, exp_type, data)

    dp.send_msg(expmsg)
