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

from openstack.common import cfg

CONF = cfg.CONF

CONF.register_cli_opts([
    # GLOBAL flags
    cfg.BoolOpt('monkey_patch', default=False, help='do monkey patch'),
    # app/quantum_adapter
    cfg.StrOpt('quantum_url', default='http://localhost:9696',
               help='URL for connecting to quantum'),
    cfg.IntOpt('quantum_url_timeout', default=30,
               help='timeout value for connecting to quantum in seconds'),
    cfg.StrOpt('quantum_admin_username', default='quantum',
               help='username for connecting to quantum in admin context'),
    cfg.StrOpt('quantum_admin_password', default='service_password',
               help='password for connecting to quantum in admin context'),
    cfg.StrOpt('quantum_admin_tenant_name', default='service',
               help='tenant name for connecting to quantum in admin context'),
    cfg.StrOpt('quantum_admin_auth_url', default='http://localhost:5000/v2.0',
               help='auth url for connecting to quantum in admin context'),
    cfg.StrOpt('quantum_auth_strategy', default='keystone',
               help='auth strategy for connecting to quantum in admin'
               'context'),
    cfg.StrOpt('quantum_controller_addr', default=None,
               help='openflow mehod:address:port to set controller of'
               'ovs bridge')
])
