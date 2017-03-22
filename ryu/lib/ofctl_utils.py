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

import base64
import logging

import netaddr
import six

from ryu.lib import dpid
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_2


LOG = logging.getLogger(__name__)
DEFAULT_TIMEOUT = 1.0

# NOTE(jkoelker) Constants for converting actions
OUTPUT = 'OUTPUT'
COPY_TTL_OUT = 'COPY_TTL_OUT'
COPY_TTL_IN = 'COPY_TTL_IN'
SET_MPLS_TTL = 'SET_MPLS_TTL'
DEC_MPLS_TTL = 'DEC_MPLS_TTL'
PUSH_VLAN = 'PUSH_VLAN'
POP_VLAN = 'POP_VLAN'
PUSH_MPLS = 'PUSH_MPLS'
POP_MPLS = 'POP_MPLS'
SET_QUEUE = 'SET_QUEUE'
GROUP = 'GROUP'
SET_NW_TTL = 'SET_NW_TTL'
DEC_NW_TTL = 'DEC_NW_TTL'
SET_FIELD = 'SET_FIELD'
PUSH_PBB = 'PUSH_PBB'      # OpenFlow 1.3 or later
POP_PBB = 'POP_PBB'        # OpenFlow 1.3 or later
COPY_FIELD = 'COPY_FIELD'  # OpenFlow 1.5 or later
METER = 'METER'            # OpenFlow 1.5 or later
EXPERIMENTER = 'EXPERIMENTER'


def get_logger(logger=None):
    # NOTE(jkoelker) use the logger the calling code wants us to
    if logger is not None:
        return logger

    return LOG


def match_vid_to_str(value, mask, ofpvid_present):
    if mask is not None:
        return '0x%04x/0x%04x' % (value, mask)

    if value & ofpvid_present:
        return str(value & ~ofpvid_present)

    return '0x%04x' % value


def to_action(dic, ofp, parser, action_type, util):
    actions = {COPY_TTL_OUT: parser.OFPActionCopyTtlOut,
               COPY_TTL_IN: parser.OFPActionCopyTtlIn,
               DEC_MPLS_TTL: parser.OFPActionDecMplsTtl,
               POP_VLAN: parser.OFPActionPopVlan,
               DEC_NW_TTL: parser.OFPActionDecNwTtl}
    if ofp.OFP_VERSION > ofproto_v1_2.OFP_VERSION:
        actions[POP_PBB] = parser.OFPActionPopPbb

    need_ethertype = {PUSH_VLAN: parser.OFPActionPushVlan,
                      PUSH_MPLS: parser.OFPActionPushMpls,
                      POP_MPLS: parser.OFPActionPopMpls}
    if ofp.OFP_VERSION > ofproto_v1_2.OFP_VERSION:
        need_ethertype[PUSH_PBB] = parser.OFPActionPushPbb

    if action_type in actions:
        return actions[action_type]()

    elif action_type in need_ethertype:
        ethertype = str_to_int(dic.get('ethertype'))
        return need_ethertype[action_type](ethertype)

    elif action_type == OUTPUT:
        out_port = util.ofp_port_from_user(dic.get('port', ofp.OFPP_ANY))
        max_len = util.ofp_cml_from_user(dic.get('max_len', ofp.OFPCML_MAX))
        return parser.OFPActionOutput(out_port, max_len)

    elif action_type == SET_MPLS_TTL:
        mpls_ttl = str_to_int(dic.get('mpls_ttl'))
        return parser.OFPActionSetMplsTtl(mpls_ttl)

    elif action_type == SET_QUEUE:
        queue_id = util.ofp_queue_from_user(dic.get('queue_id'))
        return parser.OFPActionSetQueue(queue_id)

    elif action_type == GROUP:
        group_id = util.ofp_group_from_user(dic.get('group_id'))
        return parser.OFPActionGroup(group_id)

    elif action_type == SET_NW_TTL:
        nw_ttl = str_to_int(dic.get('nw_ttl'))
        return parser.OFPActionSetNwTtl(nw_ttl)

    elif action_type == SET_FIELD:
        field = dic.get('field')
        value = dic.get('value')
        return parser.OFPActionSetField(**{field: value})

    elif action_type == 'COPY_FIELD':
        n_bits = str_to_int(dic.get('n_bits'))
        src_offset = str_to_int(dic.get('src_offset'))
        dst_offset = str_to_int(dic.get('dst_offset'))
        oxm_ids = [parser.OFPOxmId(str(dic.get('src_oxm_id'))),
                   parser.OFPOxmId(str(dic.get('dst_oxm_id')))]
        return parser.OFPActionCopyField(
            n_bits, src_offset, dst_offset, oxm_ids)

    elif action_type == 'METER':
        if hasattr(parser, 'OFPActionMeter'):
            # OpenFlow 1.5 or later
            meter_id = str_to_int(dic.get('meter_id'))
            return parser.OFPActionMeter(meter_id)
        else:
            # OpenFlow 1.4 or earlier
            return None

    elif action_type == EXPERIMENTER:
        experimenter = str_to_int(dic.get('experimenter'))
        data_type = dic.get('data_type', 'ascii')

        if data_type not in ('ascii', 'base64'):
            LOG.error('Unknown data type: %s', data_type)
            return None

        data = dic.get('data', '')
        if data_type == 'base64':
            data = base64.b64decode(data)
        return parser.OFPActionExperimenterUnknown(experimenter, data)

    return None


def to_match_eth(value):
    if '/' in value:
        value = value.split('/')
        return value[0], value[1]

    return value


def to_match_ip(value):
    if '/' in value:
        (ip_addr, ip_mask) = value.split('/')

        if ip_mask.isdigit():
            ip = netaddr.ip.IPNetwork(value)
            ip_addr = str(ip.ip)
            ip_mask = str(ip.netmask)

        return ip_addr, ip_mask

    return value


def to_match_vid(value, ofpvid_present):
    # NOTE: If "vlan_id" field is described as decimal int value
    #       (and decimal string value), it is treated as values of
    #       VLAN tag, and OFPVID_PRESENT(0x1000) bit is automatically
    #       applied. OTOH, If it is described as hexadecimal string,
    #       treated as values of oxm_value (including OFPVID_PRESENT
    #       bit), and OFPVID_PRESENT bit is NOT automatically applied
    if isinstance(value, six.integer_types):
        # described as decimal int value
        return value | ofpvid_present

    else:
        if '/' in value:
            val = value.split('/')
            return str_to_int(val[0]), str_to_int(val[1])

        else:
            if value.isdigit():
                # described as decimal string value
                return int(value, 10) | ofpvid_present

            return str_to_int(value)


def to_match_masked_int(value):
    if isinstance(value, str) and '/' in value:
        value = value.split('/')
        return str_to_int(value[0]), str_to_int(value[1])

    return str_to_int(value)


def to_match_packet_type(value):
    if isinstance(value, (list, tuple)):
        return str_to_int(value[0]) << 16 | str_to_int(value[1])
    else:
        return str_to_int(value)


def send_experimenter(dp, exp, logger=None):
    experimenter = exp.get('experimenter', 0)
    exp_type = exp.get('exp_type', 0)
    data_type = exp.get('data_type', 'ascii')

    data = exp.get('data', '')
    if data_type == 'base64':
        data = base64.b64decode(data)
    elif data_type == 'ascii':
        data = data.encode('ascii')
    else:
        get_logger(logger).error('Unknown data type: %s', data_type)
        return

    expmsg = dp.ofproto_parser.OFPExperimenter(
        dp, experimenter, exp_type, data)
    send_msg(dp, expmsg, logger)


def send_msg(dp, msg, logger=None):
    if msg.xid is None:
        dp.set_xid(msg)

    log = get_logger(logger)
    # NOTE(jkoelker) Prevent unnecessary string formating by including the
    #                format rules in the log_msg
    log_msg = ('Sending message with xid(%x) to '
               'datapath(' + dpid._DPID_FMT + '): %s')
    log.debug(log_msg, msg.xid, dp.id, msg)
    dp.send_msg(msg)


def send_stats_request(dp, stats, waiters, msgs, logger=None):
    dp.set_xid(stats)
    waiters_per_dp = waiters.setdefault(dp.id, {})
    lock = hub.Event()
    previous_msg_len = len(msgs)
    waiters_per_dp[stats.xid] = (lock, msgs)
    send_msg(dp, stats, logger)

    lock.wait(timeout=DEFAULT_TIMEOUT)
    current_msg_len = len(msgs)

    while current_msg_len > previous_msg_len:
        previous_msg_len = current_msg_len
        lock.wait(timeout=DEFAULT_TIMEOUT)
        current_msg_len = len(msgs)

    if not lock.is_set():
        del waiters_per_dp[stats.xid]


def str_to_int(str_num):
    return int(str(str_num), 0)


def get_role(dp, waiters, to_user):
    stats = dp.ofproto_parser.OFPRoleRequest(
        dp, dp.ofproto.OFPCR_ROLE_NOCHANGE, generation_id=0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs, LOG)
    descs = []

    for msg in msgs:
        d = msg.to_jsondict()[msg.__class__.__name__]
        if to_user:
            d['role'] = OFCtlUtil(dp.ofproto).ofp_role_to_user(d['role'])
        descs.append(d)

    return {str(dp.id): descs}


class OFCtlUtil(object):

    def __init__(self, ofproto):
        self.ofproto = ofproto
        self.deprecated_value = [
            'OFPTFPT_EXPERIMENTER_SLAVE',
            'OFPTFPT_EXPERIMENTER_MASTER',
            'OFPQCFC_EPERM']

    def _reserved_num_from_user(self, num, prefix):
        try:
            return str_to_int(num)
        except ValueError:
            try:
                if num.startswith(prefix):
                    return getattr(self.ofproto, num.upper())
                else:
                    return getattr(self.ofproto, prefix + num.upper())
            except AttributeError:
                LOG.warning(
                    "Cannot convert argument to reserved number: %s", num)
        return num

    def _reserved_num_to_user(self, num, prefix):
        for k, v in self.ofproto.__dict__.items():
            if k not in self.deprecated_value and \
               k.startswith(prefix) and v == num:
                return k.replace(prefix, '')
        return num

    def ofp_port_features_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPPF_')

    def ofp_port_features_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPPF_')

    def ofp_port_mod_prop_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPPMPT_')

    def ofp_port_mod_prop_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPPMPT_')

    def ofp_port_desc_prop_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPPDPT_')

    def ofp_port_desc_prop_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPPDPT_')

    def ofp_action_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPAT_')

    def ofp_action_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPAT_')

    def ofp_instruction_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPIT_')

    def ofp_instruction_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPIT_')

    def ofp_group_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPGT_')

    def ofp_group_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPGT_')

    def ofp_meter_band_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPMBT_')

    def ofp_meter_band_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPMBT_')

    def ofp_table_feature_prop_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPTFPT_')

    def ofp_table_feature_prop_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPTFPT_')

    def ofp_port_stats_prop_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPPSPT_')

    def ofp_port_stats_prop_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPPSPT_')

    def ofp_queue_desc_prop_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPQDPT_')

    def ofp_queue_desc_prop_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPQDPT_')

    def ofp_queue_stats_prop_type_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPQSPT_')

    def ofp_queue_stats_prop_type_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPQSPT_')

    def ofp_meter_flags_from_user(self, act):
        return self._reserved_num_from_user(act, 'OFPMF_')

    def ofp_meter_flags_to_user(self, act):
        return self._reserved_num_to_user(act, 'OFPMF_')

    def ofp_port_from_user(self, port):
        return self._reserved_num_from_user(port, 'OFPP_')

    def ofp_port_to_user(self, port):
        return self._reserved_num_to_user(port, 'OFPP_')

    def ofp_table_from_user(self, table):
        return self._reserved_num_from_user(table, 'OFPTT_')

    def ofp_table_to_user(self, table):
        return self._reserved_num_to_user(table, 'OFPTT_')

    def ofp_cml_from_user(self, max_len):
        return self._reserved_num_from_user(max_len, 'OFPCML_')

    def ofp_cml_to_user(self, max_len):
        return self._reserved_num_to_user(max_len, 'OFPCML_')

    def ofp_group_from_user(self, group):
        return self._reserved_num_from_user(group, 'OFPG_')

    def ofp_group_to_user(self, group):
        return self._reserved_num_to_user(group, 'OFPG_')

    def ofp_group_capabilities_from_user(self, group):
        return self._reserved_num_from_user(group, 'OFPGFC_')

    def ofp_group_capabilities_to_user(self, group):
        return self._reserved_num_to_user(group, 'OFPGFC_')

    def ofp_group_bucket_prop_type_from_user(self, group):
        return self._reserved_num_from_user(group, 'OFPGBPT_')

    def ofp_group_bucket_prop_type_to_user(self, group):
        return self._reserved_num_to_user(group, 'OFPGBPT_')

    def ofp_buffer_from_user(self, buffer):
        if buffer in ['OFP_NO_BUFFER', 'NO_BUFFER']:
            return self.ofproto.OFP_NO_BUFFER
        else:
            return buffer

    def ofp_buffer_to_user(self, buffer):
        if self.ofproto.OFP_NO_BUFFER == buffer:
            return 'NO_BUFFER'
        else:
            return buffer

    def ofp_meter_from_user(self, meter):
        return self._reserved_num_from_user(meter, 'OFPM_')

    def ofp_meter_to_user(self, meter):
        return self._reserved_num_to_user(meter, 'OFPM_')

    def ofp_queue_from_user(self, queue):
        return self._reserved_num_from_user(queue, 'OFPQ_')

    def ofp_queue_to_user(self, queue):
        return self._reserved_num_to_user(queue, 'OFPQ_')

    def ofp_role_from_user(self, role):
        return self._reserved_num_from_user(role, 'OFPCR_ROLE_')

    def ofp_role_to_user(self, role):
        return self._reserved_num_to_user(role, 'OFPCR_ROLE_')
