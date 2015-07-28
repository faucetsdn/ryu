# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import re
import logging
import httplib

import view_base
from models import proxy


LOG = logging.getLogger('ryu.gui')


class FlowView(view_base.ViewBase):
    def __init__(self, host, port, dpid, flows=None):
        super(FlowView, self).__init__()
        self.host = host
        self.port = port
        self.dpid = dpid
        self.flows = flows

    def run(self):
        if not self.flows:
            # dump flows
            return self._dump_flows()

        # TODO: flow-mod
        return self.null_response()

    def _dump_flows(self):
        address = '%s:%s' % (self.host, self.port)
        res = {'host': self.host,
               'port': self.port,
               'dpid': self.dpid,
               'flows': []}

        flows = proxy.get_flows(address, int(self.dpid))
        for flow in flows:
            actions = self._to_client_actions(flow.pop('actions'))
            rules = self._to_client_rules(flow.pop('match'))
            stats = self._to_client_stats(flow)
            res['flows'].append({'stats': stats,
                                 'rules': rules,
                                 'actions': actions})
        return self.json_response(res)

    def _to_client_actions(self, actions):
        # TODO:XXX
        return actions

    def _to_client_rules(self, rules):
        for name, val in rules.items():
            # hide default values for GUI
            if name in ['in_port', 'dl_type', 'nw_proto', 'tp_src', 'tp_dst',
                        'dl_vlan', 'dl_vlan_pcp']:
                if val == 0:
                    del rules[name]

            if name in ['nw_dst', 'nw_src']:
                if val == '0.0.0.0':
                    del rules[name]

            if name in ['dl_dst', 'dl_src']:
                if val == '00:00:00:00:00:00':
                    del rules[name]
        return rules

    def _to_client_stats(self, stats):
        for name, val in stats.items():
            # hide default values for GUI
            if name in ['hard_timeout', 'idle_timeout',
                        'cookie']:
                if val == 0:
                    del stats[name]
        return stats
