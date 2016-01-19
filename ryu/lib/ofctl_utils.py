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


LOG = logging.getLogger(__name__)


def str_to_int(str_num):
    return int(str(str_num), 0)


class OFCtlUtil(object):

    def __init__(self, ofproto):
        self.ofproto = ofproto

    def _reserved_num_from_user(self, num, prefix):
        if isinstance(num, int):
            return num
        else:
            if num.startswith(prefix):
                return getattr(self.ofproto, num)
            else:
                return getattr(self.ofproto, prefix + num.upper())

    def _reserved_num_to_user(self, num, prefix):
        for k, v in self.ofproto.__dict__.items():
            if k.startswith(prefix) and v == num:
                    return k.replace(prefix, '')
        return num

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
