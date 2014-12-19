# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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
"""
global flags
"""

from ryu import cfg

CONF = cfg.CONF

CONF.register_cli_opts([
    # app/quantum_adapter
    cfg.StrOpt('neutron-url', default='http://localhost:9696',
               help='URL for connecting to neutron',
               deprecated_name='quantum-url'),
    cfg.IntOpt('neutron-url-timeout', default=30,
               help='timeout value for connecting to neutron in seconds',
               deprecated_name='quantum-url-timeout'),
    cfg.StrOpt('neutron-admin-username', default='neutron',
               help='username for connecting to neutron in admin context',
               deprecated_name='quantum-admin-username'),
    cfg.StrOpt('neutron-admin-password', default='service_password',
               help='password for connecting to neutron in admin context',
               deprecated_name='quantum-admin-password'),
    cfg.StrOpt('neutron-admin-tenant-name', default='service',
               help='tenant name for connecting to neutron in admin context',
               deprecated_name='quantum-admin-tenant-name'),
    cfg.StrOpt('neutron-admin-auth-url', default='http://localhost:5000/v2.0',
               help='auth url for connecting to neutron in admin context',
               deprecated_name='quantum-admin-auth-url'),
    cfg.StrOpt('neutron-auth-strategy', default='keystone',
               help='auth strategy for connecting to neutron in admin'
               'context',
               deprecated_name='quantum-auth-strategy'),
    cfg.StrOpt('neutron-controller-addr', default=None,
               help='openflow method:address:port to set controller of'
               'ovs bridge',
               deprecated_name='quantum-controller-addr')
])

CONF.register_cli_opts([
    # tests/switch/tester
    cfg.StrOpt('target', default='0000000000000001', help='target sw dp-id'),
    cfg.StrOpt('tester', default='0000000000000002', help='tester sw dp-id'),
    cfg.IntOpt('target_recv_port', default=1,
               help='target sw receiving port '
               '(default: 1)'),
    cfg.IntOpt('target_send_port_1', default=2,
               help='target sw sending port 1 '
               '(default: 2)'),
    cfg.IntOpt('target_send_port_2', default=3,
               help='target sw sending port 2  '
               '(default: 3)'),
    cfg.IntOpt('tester_send_port', default=1,
               help='tester sw sending port '
               '(default: 1)'),
    cfg.IntOpt('tester_recv_port_1', default=2,
               help='tester sw receiving port 1 '
               '(default: 2)'),
    cfg.IntOpt('tester_recv_port_2', default=3,
               help='tester sw receiving port 2 '
               '(default: 3)'),
    cfg.StrOpt('dir', default='ryu/tests/switch/of13',
               help='test files directory'),
    cfg.StrOpt('target-version', default='openflow13',
               help='target sw OFP version [openflow13|openflow14] '
               '(default: openflow13)'),
    cfg.StrOpt('tester-version', default='openflow13',
               help='tester sw OFP version [openflow13|openflow14] '
               '(default: openflow13)')
], group='test-switch')
