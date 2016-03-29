# Copyright (C) 2016 Rackspace US, Inc.
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

from ryu.ofproto import nicira_ext


LOG = logging.getLogger(__name__)


def action_to_str(act, ofctl_action_to_str):
    sub_type = act.subtype

    if sub_type == nicira_ext.NXAST_RESUBMIT:
        return 'NX_RESUBMIT: {port: %s, table: %s}' % (act.in_port,
                                                       act.table_id)

    elif sub_type == nicira_ext.NXAST_REG_MOVE:
        src_start = act.src_ofs
        dst_start = act.dst_ofs
        src_end = src_start + act.n_bits
        dst_end = dst_start + act.n_bits
        return 'NX_MOVE: {%s[%s..%s]: %s[%s..%s]}' % (act.dst_field, dst_start,
                                                      dst_end, act.src_field,
                                                      src_start, src_end)

    elif sub_type == nicira_ext.NXAST_REG_LOAD:
        start = act.ofs
        end = start + act.nbits
        return 'NX_LOAD: {%s[%s..%s]: %x}' % (act.dst, start, end, act.value)

    elif sub_type == nicira_ext.NXAST_LEARN:
        specs = []
        add_spec = specs.append

        for spec in act.specs:
            dst_type = spec._dst_type

            if dst_type == 0:  # match
                if isinstance(spec.src, (tuple, list)):
                    src = spec.src[0]
                    start = spec.src[1]
                    end = start + spec.n_bits
                    start_end = '%s..%s' % (start, end)

                else:
                    src = spec.src
                    start_end = '[]'

                add_spec('%s[%s]' % (src, start_end))

            elif dst_type == 1:  # load
                if isinstance(spec.src, (tuple, list)):
                    src = spec.src[0]
                    start = spec.src[1]
                    end = start + spec.n_bits
                    src_start_end = '[%s..%s]' % (start, end)

                else:
                    src = spec.src
                    start_end = ''

                if isinstance(spec.dst, (tuple, list)):
                    dst = spec.dst[0]
                    start = spec.dst[1]
                    end = start + spec.n_bits
                    dst_start_end = '[%s..%s]' % (start, end)

                else:
                    dst = spec.dst
                    start_end = '[]'

                add_spec('NX_LOAD {%s%s: %s%s}' % (dst, dst_start_end,
                                                   src, src_start_end))

            elif dst_type == 2:  # output
                if isinstance(spec.src, (tuple, list)):
                    src = spec.src[0]
                    start = spec.src[1]
                    end = start + spec.n_bits
                    start_end = '%s..%s' % (start, end)

                else:
                    src = spec.src
                    start_end = '[]'

                add_spec('output:%s%s' % (src, start_end))

        return ('NX_LEARN: {idle_timeout: %s, '
                'hard_timeouts: %s, '
                'priority: %s, '
                'cookie: %s, '
                'flags: %s, '
                'table_id: %s, '
                'fin_idle_timeout: %s, '
                'fin_hard_timeout: %s, '
                'specs: %s}' % (act.idle_timeout, act.hard_timeout,
                                act.priority, act.cookie, act.flags,
                                act.fin_idle_timeout,
                                act.self.fin_hard_timeout,
                                specs))

    elif sub_type == nicira_ext.NXAST_CONJUNCTION:
        return ('NX_CONJUNCTION: {clause: %s, number_of_clauses: %s, id: %s}' %
                (act.clause, act.n_clauses, act.id))

    elif sub_type == nicira_ext.NXAST_CT:
        if act.zone_ofs_nbits != 0:
            start = act.zone_ofs_nbits
            end = start + 16
            zone = act.zone_src + ('[%s..%s]' % (start, end))

        else:
            zone = act.zone_src

        actions = [ofctl_action_to_str(action) for action in act.actions]

        return ('NX_CT: {flags: %s, '
                'zone: %s, '
                'table: %s, '
                'alg: %s, '
                'actions: %s}' % (act.flags, zone, act.recirc_table, act.alg,
                                  actions))

    elif sub_type == nicira_ext.NXAST_NAT:
        return ('NX_NAT: {flags: %s, '
                'range_ipv4_min: %s, '
                'range_ipv4_max: %s, '
                'range_ipv6_min: %s, '
                'range_ipv6_max: %s, '
                'range_proto_min: %s, '
                'range_proto_max: %s}' % (act.flags,
                                          act.range_ipv4_min,
                                          act.range_ipv4_max,
                                          act.range_ipv6_min,
                                          act.range_ipv6_max,
                                          act.range_proto_min,
                                          act.range_proto_max))

    data_str = base64.b64encode(act.data)
    return 'NX_UNKNOWN: {subtype: %s, data: %s}' % (sub_type,
                                                    data_str.decode('utf-8'))
