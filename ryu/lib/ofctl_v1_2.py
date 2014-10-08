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

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.lib import hub
from ryu.lib import mac


LOG = logging.getLogger('ryu.lib.ofctl_v1_2')

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
        result = parser.OFPActionSetField(**{field: value})
    else:
        result = None

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
            else:
                LOG.debug('Unknown action type: %s' % action_type)

    inst.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions))
    return inst


def action_to_str(act):
    action_type = act.cls_action_type

    if action_type == ofproto_v1_2.OFPAT_OUTPUT:
        buf = 'OUTPUT:' + str(act.port)
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
        buf = 'SET_QUEUE:' + str(act.queue_id)
    elif action_type == ofproto_v1_2.OFPAT_GROUP:
        buf = 'GROUP:' + str(act.group_id)
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
            for a in instruction.actions:
                actions.append(action_to_str(a))

        elif isinstance(instruction,
                        ofproto_v1_2_parser.OFPInstructionGotoTable):
            buf = 'GOTO_TABLE:' + str(instruction.table_id)
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
    match = dp.ofproto_parser.OFPMatch()

    convert = {'in_port': int,
               'in_phy_port': int,
               'dl_src': to_match_eth,
               'dl_dst': to_match_eth,
               'dl_type': int,
               'dl_vlan': int,
               'vlan_pcp': int,
               'ip_dscp': int,
               'ip_ecn': int,
               'nw_src': to_match_ip,
               'nw_dst': to_match_ip,
               'nw_proto': int,
               'tp_src': int,
               'tp_dst': int,
               'mpls_label': int,
               'metadata': to_match_metadata,
               'eth_src': to_match_eth,
               'eth_dst': to_match_eth,
               'eth_type': int,
               'vlan_vid': int,
               'ipv4_src': to_match_ip,
               'ipv4_dst': to_match_ip,
               'ip_proto': int,
               'tcp_src': int,
               'tcp_dst': int,
               'udp_src': int,
               'udp_dst': int,
               'sctp_src': int,
               'sctp_dst': int,
               'icmpv4_type': int,
               'icmpv4_code': int,
               'arp_op': int,
               'arp_spa': to_match_ip,
               'arp_tpa': to_match_ip,
               'arp_sha': to_match_eth,
               'arp_tha': to_match_eth,
               'ipv6_src': to_match_ipv6,
               'ipv6_dst': to_match_ipv6,
               'ipv6_flabel': int,
               'icmpv6_type': int,
               'icmpv6_code': int,
               'ipv6_nd_target': to_match_ipv6,
               'ipv6_nd_sll': mac.haddr_to_bin,
               'ipv6_nd_tll': mac.haddr_to_bin,
               'mpls_tc': int}

    match_append = {'in_port': match.set_in_port,
                    'in_phy_port': match.set_in_phy_port,
                    'dl_src': match.set_dl_src_masked,
                    'dl_dst': match.set_dl_dst_masked,
                    'dl_type': match.set_dl_type,
                    'dl_vlan': match.set_vlan_vid,
                    'vlan_pcp': match.set_vlan_pcp,
                    'nw_src': match.set_ipv4_src_masked,
                    'nw_dst': match.set_ipv4_dst_masked,
                    'nw_proto': match.set_ip_proto,
                    'tp_src': to_match_tpsrc,
                    'tp_dst': to_match_tpdst,
                    'mpls_label': match.set_mpls_label,
                    'metadata': match.set_metadata_masked,
                    'eth_src': match.set_dl_src_masked,
                    'eth_dst': match.set_dl_dst_masked,
                    'eth_type': match.set_dl_type,
                    'vlan_vid': match.set_vlan_vid,
                    'ip_dscp': match.set_ip_dscp,
                    'ip_ecn': match.set_ip_ecn,
                    'ipv4_src': match.set_ipv4_src_masked,
                    'ipv4_dst': match.set_ipv4_dst_masked,
                    'ip_proto': match.set_ip_proto,
                    'tcp_src': to_match_tpsrc,
                    'tcp_dst': to_match_tpdst,
                    'udp_src': to_match_tpsrc,
                    'udp_dst': to_match_tpdst,
                    'sctp_src': match.set_sctp_src,
                    'sctp_dst': match.set_sctp_dst,
                    'icmpv4_type': match.set_icmpv4_type,
                    'icmpv4_code': match.set_icmpv4_code,
                    'arp_op': match.set_arp_opcode,
                    'arp_spa': match.set_arp_spa_masked,
                    'arp_tpa': match.set_arp_tpa_masked,
                    'arp_sha': match.set_arp_sha_masked,
                    'arp_tha': match.set_arp_tha_masked,
                    'ipv6_src': match.set_ipv6_src_masked,
                    'ipv6_dst': match.set_ipv6_dst_masked,
                    'ipv6_flabel': match.set_ipv6_flabel,
                    'icmpv6_type': match.set_icmpv6_type,
                    'icmpv6_code': match.set_icmpv6_code,
                    'ipv6_nd_target': match.set_ipv6_nd_target,
                    'ipv6_nd_sll': match.set_ipv6_nd_sll,
                    'ipv6_nd_tll': match.set_ipv6_nd_tll,
                    'mpls_tc': match.set_mpls_tc}

    if attrs.get('dl_type') == ether.ETH_TYPE_ARP or \
            attrs.get('eth_type') == ether.ETH_TYPE_ARP:
        if 'nw_src' in attrs and 'arp_spa' not in attrs:
            attrs['arp_spa'] = attrs['nw_src']
            del attrs['nw_src']
        if 'nw_dst' in attrs and 'arp_tpa' not in attrs:
            attrs['arp_tpa'] = attrs['nw_dst']
            del attrs['nw_dst']

    for key, value in attrs.items():
        if key in convert:
            value = convert[key](value)
        if key in match_append:
            if key == 'dl_src' or key == 'dl_dst' or \
                    key == 'eth_src' or key == 'eth_dst' or \
                    key == 'arp_sha' or key == 'arp_tha':
                # MAC address
                eth = value[0]
                mask = value[1]
                match_append[key](eth, mask)
            elif key == 'nw_src' or key == 'nw_dst' or \
                    key == 'ipv4_src' or key == 'ipv4_dst' or \
                    key == 'arp_spa' or key == 'arp_tpa' or \
                    key == 'ipv6_src' or key == 'ipv6_dst':
                # IP address
                ip = value[0]
                mask = value[1]
                match_append[key](ip, mask)
            elif key == 'ipv6_nd_target':
                match_append[key](value[0])
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


def to_match_eth(value):
    eth_mask = value.split('/')

    # MAC address
    eth = mac.haddr_to_bin(eth_mask[0])
    # mask
    mask = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')

    if len(eth_mask) == 2:
        mask = mac.haddr_to_bin(eth_mask[1])

    return eth, mask


def to_match_tpsrc(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_src,
                    inet.IPPROTO_UDP: match.set_udp_src}

    nw_proto = int(rest.get('nw_proto', rest.get('ip_proto', 0)))
    if nw_proto in match_append:
        match_append[nw_proto](value)

    return match


def to_match_tpdst(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_dst,
                    inet.IPPROTO_UDP: match.set_udp_dst}

    nw_proto = int(rest.get('nw_proto', rest.get('ip_proto', 0)))
    if nw_proto in match_append:
        match_append[nw_proto](value)

    return match


def to_match_ip(value):
    ip_mask = value.split('/')

    # IP address
    ipv4 = struct.unpack('!I', socket.inet_aton(ip_mask[0]))[0]
    # netmask
    netmask = ofproto_v1_2_parser.UINT32_MAX

    if len(ip_mask) == 2:
        # Check the mask is CIDR or not.
        if ip_mask[1].isdigit():
            netmask &= ofproto_v1_2_parser.UINT32_MAX << 32 - int(ip_mask[1])
        else:
            netmask = struct.unpack('!I', socket.inet_aton(ip_mask[1]))[0]

    return ipv4, netmask


def to_match_ipv6(value):
    ip_mask = value.split('/')

    if len(ip_mask) == 2 and ip_mask[1].isdigit() is False:
        # Both address and netmask are colon-hexadecimal.
        ipv6 = netaddr.IPAddress(ip_mask[0]).words
        netmask = netaddr.IPAddress(ip_mask[1]).words
    else:
        # For other formats.
        network = netaddr.IPNetwork(value)
        ipv6 = network.ip.words
        netmask = network.netmask.words

    return ipv6, netmask


def to_match_metadata(value):
    if '/' in value:
        metadata = value.split('/')
        return str_to_int(metadata[0]), str_to_int(metadata[1])
    else:
        return str_to_int(value), ofproto_v1_2_parser.UINT64_MAX


def match_to_str(ofmatch):
    keys = {ofproto_v1_2.OXM_OF_IN_PORT: 'in_port',
            ofproto_v1_2.OXM_OF_IN_PHY_PORT: 'in_phy_port',
            ofproto_v1_2.OXM_OF_ETH_SRC: 'dl_src',
            ofproto_v1_2.OXM_OF_ETH_DST: 'dl_dst',
            ofproto_v1_2.OXM_OF_ETH_SRC_W: 'dl_src',
            ofproto_v1_2.OXM_OF_ETH_DST_W: 'dl_dst',
            ofproto_v1_2.OXM_OF_ETH_TYPE: 'dl_type',
            ofproto_v1_2.OXM_OF_VLAN_VID: 'dl_vlan',
            ofproto_v1_2.OXM_OF_VLAN_PCP: 'vlan_pcp',
            ofproto_v1_2.OXM_OF_IP_DSCP: 'ip_dscp',
            ofproto_v1_2.OXM_OF_IP_ECN: 'ip_ecn',
            ofproto_v1_2.OXM_OF_IPV4_SRC: 'nw_src',
            ofproto_v1_2.OXM_OF_IPV4_DST: 'nw_dst',
            ofproto_v1_2.OXM_OF_IPV4_SRC_W: 'nw_src',
            ofproto_v1_2.OXM_OF_IPV4_DST_W: 'nw_dst',
            ofproto_v1_2.OXM_OF_IP_PROTO: 'nw_proto',
            ofproto_v1_2.OXM_OF_TCP_SRC: 'tp_src',
            ofproto_v1_2.OXM_OF_TCP_DST: 'tp_dst',
            ofproto_v1_2.OXM_OF_UDP_SRC: 'tp_src',
            ofproto_v1_2.OXM_OF_UDP_DST: 'tp_dst',
            ofproto_v1_2.OXM_OF_SCTP_SRC: 'sctp_src',
            ofproto_v1_2.OXM_OF_SCTP_DST: 'sctp_dst',
            ofproto_v1_2.OXM_OF_ICMPV4_TYPE: 'icmpv4_type',
            ofproto_v1_2.OXM_OF_ICMPV4_CODE: 'icmpv4_code',
            ofproto_v1_2.OXM_OF_MPLS_LABEL: 'mpls_label',
            ofproto_v1_2.OXM_OF_MPLS_TC: 'mpls_tc',
            ofproto_v1_2.OXM_OF_METADATA: 'metadata',
            ofproto_v1_2.OXM_OF_METADATA_W: 'metadata',
            ofproto_v1_2.OXM_OF_ARP_OP: 'arp_op',
            ofproto_v1_2.OXM_OF_ARP_SPA: 'arp_spa',
            ofproto_v1_2.OXM_OF_ARP_TPA: 'arp_tpa',
            ofproto_v1_2.OXM_OF_ARP_SPA_W: 'arp_spa',
            ofproto_v1_2.OXM_OF_ARP_TPA_W: 'arp_tpa',
            ofproto_v1_2.OXM_OF_ARP_SHA: 'arp_sha',
            ofproto_v1_2.OXM_OF_ARP_THA: 'arp_tha',
            ofproto_v1_2.OXM_OF_ARP_SHA_W: 'arp_sha',
            ofproto_v1_2.OXM_OF_ARP_THA_W: 'arp_tha',
            ofproto_v1_2.OXM_OF_IPV6_SRC: 'ipv6_src',
            ofproto_v1_2.OXM_OF_IPV6_DST: 'ipv6_dst',
            ofproto_v1_2.OXM_OF_IPV6_SRC_W: 'ipv6_src',
            ofproto_v1_2.OXM_OF_IPV6_DST_W: 'ipv6_dst',
            ofproto_v1_2.OXM_OF_IPV6_FLABEL: 'ipv6_flabel',
            ofproto_v1_2.OXM_OF_ICMPV6_TYPE: 'icmpv6_type',
            ofproto_v1_2.OXM_OF_ICMPV6_CODE: 'icmpv6_code',
            ofproto_v1_2.OXM_OF_IPV6_ND_TARGET: 'ipv6_nd_target',
            ofproto_v1_2.OXM_OF_IPV6_ND_SLL: 'ipv6_nd_sll',
            ofproto_v1_2.OXM_OF_IPV6_ND_TLL: 'ipv6_nd_tll'}

    match = {}
    for match_field in ofmatch.fields:
        key = keys[match_field.header]
        if key == 'dl_src' or key == 'dl_dst' or key == 'arp_sha' or \
                key == 'arp_tha':
            value = match_eth_to_str(match_field.value, match_field.mask)
        elif key == 'ipv6_nd_tll' or key == 'ipv6_nd_sll':
            value = mac.haddr_to_str(match_field.value)
        elif key == 'nw_src' or key == 'nw_dst' or \
                key == 'arp_spa' or key == 'arp_tpa':
            value = match_ip_to_str(match_field.value, match_field.mask)
        elif key == 'ipv6_src' or key == 'ipv6_dst':
            value = match_ipv6_to_str(match_field.value, match_field.mask)
        elif key == 'ipv6_nd_target':
            value = match_ipv6_to_str(match_field.value, None)
        elif key == 'metadata':
            value = ('%d/%d' % (match_field.value, match_field.mask)
                     if match_field.mask else '%d' % match_field.value)
        else:
            value = match_field.value
        match.setdefault(key, value)

    return match


def match_eth_to_str(value, mask):
    eth_str = mac.haddr_to_str(value)

    if mask is not None:
        eth_str = eth_str + '/' + mac.haddr_to_str(mask)

    return eth_str


def match_ip_to_str(value, mask):
    ip = socket.inet_ntoa(struct.pack('!I', value))

    if mask is not None and mask != 0:
        binary_str = bin(mask)[2:].zfill(32).rstrip('0')
        if binary_str.find('0') >= 0:
            netmask = '/%s' % socket.inet_ntoa(struct.pack('!I', mask))
        else:
            netmask = '/%d' % len(binary_str)
    else:
        netmask = ''

    return ip + netmask


def match_ipv6_to_str(value, mask):
    ip_list = []
    for word in value:
        ip_list.append('%04x' % word)
    ip = netaddr.IPNetwork(':'.join(ip_list))

    netmask = 128
    netmask_str = None
    if mask is not None:
        mask_list = []
        for word in mask:
            mask_list.append('%04x' % word)
        mask_v = netaddr.IPNetwork(':'.join(mask_list))
        binary_str = mask_v.ip.bits().replace(':', '').zfill(128).rstrip('0')
        if binary_str.find('0') >= 0:
            netmask_str = str(mask_v.ip)
        else:
            netmask = len(binary_str)

    if netmask_str is not None:
        ip_str = str(ip.ip) + '/' + netmask_str
    elif netmask == 128:
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

    lock.wait(timeout=DEFAULT_TIMEOUT)
    if not lock.is_set():
        del waiters_per_dp[stats.xid]


def get_desc_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    s = {}
    for msg in msgs:
        stats = msg.body
        s = {'mfr_desc': stats.mfr_desc,
             'hw_desc': stats.hw_desc,
             'sw_desc': stats.sw_desc,
             'serial_num': stats.serial_num,
             'dp_desc': stats.dp_desc}
    desc = {str(dp.id): s}
    return desc


def get_queue_stats(dp, waiters):
    ofp = dp.ofproto
    stats = dp.ofproto_parser.OFPQueueStatsRequest(dp, 0, ofp.OFPP_ANY,
                                                   ofp.OFPQ_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    s = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s.append({'port_no': stat.port_no,
                      'queue_id': stat.queue_id,
                      'tx_bytes': stat.tx_bytes,
                      'tx_errors': stat.tx_errors,
                      'tx_packets': stat.tx_packets})
    desc = {str(dp.id): s}
    return desc


def get_flow_stats(dp, waiters, flow={}):
    table_id = int(flow.get('table_id', dp.ofproto.OFPTT_ALL))
    out_port = int(flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = int(flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, table_id, out_port, out_group, cookie, cookie_mask, match)

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
                 'table_id': stats.table_id,
                 'length': stats.length}
            flows.append(s)
    flows = {str(dp.id): flows}

    return flows


def get_port_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, dp.ofproto.OFPP_ANY, 0)
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


def get_group_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPGroupStatsRequest(
        dp, dp.ofproto.OFPG_ALL, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    groups = []
    for msg in msgs:
        for stats in msg.body:
            bucket_counters = []
            for bucket_counter in stats.bucket_counters:
                c = {'packet_count': bucket_counter.packet_count,
                     'byte_count': bucket_counter.byte_count}
                bucket_counters.append(c)
            g = {'length': stats.length,
                 'group_id': stats.group_id,
                 'ref_count': stats.ref_count,
                 'packet_count': stats.packet_count,
                 'byte_count': stats.byte_count,
                 'bucket_stats': bucket_counters}
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


def get_port_desc(dp, waiters):

    stats = dp.ofproto_parser.OFPFeaturesRequest(dp)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    descs = []

    for msg in msgs:
        stats = msg.ports
        for stat in stats.values():
            d = {'port_no': stat.port_no,
                 'hw_addr': stat.hw_addr,
                 'name': stat.name,
                 'config': stat.config,
                 'state': stat.state,
                 'curr': stat.curr,
                 'advertised': stat.advertised,
                 'supported': stat.supported,
                 'peer': stat.peer,
                 'curr_speed': stat.curr_speed,
                 'max_speed': stat.max_speed}
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


def mod_group_entry(dp, group, cmd):

    type_convert = {'ALL': dp.ofproto.OFPGT_ALL,
                    'SELECT': dp.ofproto.OFPGT_SELECT,
                    'INDIRECT': dp.ofproto.OFPGT_INDIRECT,
                    'FF': dp.ofproto.OFPGT_FF}

    type_ = type_convert.get(group.get('type', 'ALL'))
    if type_ is None:
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


def mod_port_behavior(dp, port_config):
    port_no = int(port_config.get('port_no', 0))
    hw_addr = port_config.get('hw_addr')
    config = int(port_config.get('config', 0))
    mask = int(port_config.get('mask', 0))
    advertise = int(port_config.get('advertise'))

    port_mod = dp.ofproto_parser.OFPPortMod(
        dp, port_no, hw_addr, config, mask, advertise)

    dp.send_msg(port_mod)


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
