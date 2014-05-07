# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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
slimmed down version of OVSBridge in quantum agent
"""

import functools
from ryu import cfg
import logging

import ryu.exception as ryu_exc
import ryu.lib.dpid as dpid_lib
import ryu.lib.ovs.vsctl as ovs_vsctl

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts([
    cfg.IntOpt('ovsdb-timeout', default=2, help='ovsdb timeout')
])


class OVSBridgeNotFound(ryu_exc.RyuException):
    message = 'no bridge for datapath_id %(datapath_id)s'


class VifPort(object):

    def __init__(self, port_name, ofport, vif_id, vif_mac, switch):
        super(VifPort, self).__init__()
        self.port_name = port_name
        self.ofport = ofport
        self.vif_id = vif_id
        self.vif_mac = vif_mac
        self.switch = switch

    def __str__(self):
        return ('iface-id=%s, '
                'vif_mac=%s, '
                'port_name=%s, '
                'ofport=%d, '
                'bridge_name=%s' % (self.vif_id,
                                    self.vif_mac,
                                    self.port_name,
                                    self.ofport,
                                    self.switch.br_name))


class TunnelPort(object):

    def __init__(self, port_name, ofport, tunnel_type, local_ip, remote_ip):
        super(TunnelPort, self).__init__()
        self.port_name = port_name
        self.ofport = ofport
        self.tunnel_type = tunnel_type
        self.local_ip = local_ip
        self.remote_ip = remote_ip

    def __eq__(self, other):
        return (self.port_name == other.port_name and
                self.ofport == other.ofport and
                self.tunnel_type == other.tunnel_type and
                self.local_ip == other.local_ip and
                self.remote_ip == other.remote_ip)

    def __str__(self):
        return ('port_name=%s, '
                'ofport=%s, '
                'type=%s, '
                'local_ip=%s, '
                'remote_ip=%s' % (self.port_name,
                                  self.ofport,
                                  self.tunnel_type,
                                  self.local_ip,
                                  self.remote_ip))


class OVSBridge(object):

    def __init__(self, CONF, datapath_id, ovsdb_addr, timeout=None,
                 exception=None):
        super(OVSBridge, self).__init__()
        self.datapath_id = datapath_id
        self.vsctl = ovs_vsctl.VSCtl(ovsdb_addr)
        self.timeout = timeout or CONF.ovsdb_timeout
        self.exception = exception

        self.br_name = None

    def run_command(self, commands):
        self.vsctl.run_command(commands, self.timeout, self.exception)

    def init(self):
        if self.br_name is None:
            self.br_name = self._get_bridge_name()

    def _get_bridge_name(self):
        """ get Bridge name of a given 'datapath_id' """
        command = ovs_vsctl.VSCtlCommand(
            'find',
            ('Bridge',
             'datapath_id=%s' % dpid_lib.dpid_to_str(self.datapath_id)))
        self.run_command([command])
        result = command.result
        if len(result) == 0 or len(result) > 1:
            raise OVSBridgeNotFound(
                datapath_id=dpid_lib.dpid_to_str(self.datapath_id))
        return result[0].name

    def get_controller(self):
        command = ovs_vsctl.VSCtlCommand('get-controller', [self.br_name])
        self.run_command([command])
        return command.result[0]

    def set_controller(self, controllers):
        command = ovs_vsctl.VSCtlCommand('set-controller', [self.br_name])
        command.args.extend(controllers)
        self.run_command([command])

    def del_controller(self):
        command = ovs_vsctl.VSCtlCommand('del-controller', [self.br_name])
        self.run_command([command])

    def set_db_attribute(self, table_name, record, column, value):
        command = ovs_vsctl.VSCtlCommand(
            'set', (table_name, record, '%s=%s' % (column, value)))
        self.run_command([command])

    def clear_db_attribute(self, table_name, record, column):
        command = ovs_vsctl.VSCtlCommand('clear', (table_name, record, column))
        self.run_command([command])

    def db_get_val(self, table, record, column):
        command = ovs_vsctl.VSCtlCommand('get', (table, record, column))
        self.run_command([command])
        assert len(command.result) == 1
        return command.result[0]

    def db_get_map(self, table, record, column):
        val = self.db_get_val(table, record, column)
        assert type(val) == dict
        return val

    def get_datapath_id(self):
        return self.db_get_val('Bridge', self.br_name, 'datapath_id')

    def delete_port(self, port_name):
        command = ovs_vsctl.VSCtlCommand(
            'del-port', (self.br_name, port_name), ('--if-exists'))
        self.run_command([command])

    def get_ofport(self, port_name):
        ofport_list = self.db_get_val('Interface', port_name, 'ofport')
        assert len(ofport_list) == 1
        return int(ofport_list[0])

    def get_port_name_list(self):
        command = ovs_vsctl.VSCtlCommand('list-ports', (self.br_name, ))
        self.run_command([command])
        return command.result

    def add_tunnel_port(self, name, tunnel_type, local_ip, remote_ip,
                        key=None):
        options = 'local_ip=%(local_ip)s,remote_ip=%(remote_ip)s' % locals()
        if key:
            options += ',key=%(key)s' % locals()

        command_add = ovs_vsctl.VSCtlCommand('add-port', (self.br_name, name))
        command_set = ovs_vsctl.VSCtlCommand(
            'set', ('Interface', name,
                    'type=%s' % tunnel_type, 'options=%s' % options))
        self.run_command([command_add, command_set])

    def add_gre_port(self, name, local_ip, remote_ip, key=None):
        self.add_tunnel_port(name, 'gre', local_ip, remote_ip, key=key)

    def del_port(self, port_name):
        command = ovs_vsctl.VSCtlCommand('del-port', (self.br_name, port_name))
        self.run_command([command])

    def _get_ports(self, get_port):
        ports = []
        port_names = self.get_port_name_list()
        for name in port_names:
            if self.get_ofport(name) < 0:
                continue
            port = get_port(name)
            if port:
                ports.append(port)

        return ports

    def _vifport(self, name, external_ids):
        ofport = self.get_ofport(name)
        return VifPort(name, ofport, external_ids['iface-id'],
                       external_ids['attached-mac'], self)

    def _get_vif_port(self, name):
        external_ids = self.db_get_map('Interface', name, 'external_ids')
        if 'iface-id' in external_ids and 'attached-mac' in external_ids:
            return self._vifport(name, external_ids)

    def get_vif_ports(self):
        'returns a VIF object for each VIF port'
        return self._get_ports(self._get_vif_port)

    def _get_external_port(self, name):
        # exclude vif ports
        external_ids = self.db_get_map('Interface', name, 'external_ids')
        if external_ids:
            return

        # exclude tunnel ports
        options = self.db_get_map('Interface', name, 'options')
        if 'remote_ip' in options:
            return

        ofport = self.get_ofport(name)
        return VifPort(name, ofport, None, None, self)

    def get_external_ports(self):
        return self._get_ports(self._get_external_port)

    def get_tunnel_port(self, name, tunnel_type='gre'):
        type_ = self.db_get_val('Interface', name, 'type')
        if type_ != tunnel_type:
            return

        options = self.db_get_map('Interface', name, 'options')
        if 'local_ip' in options and 'remote_ip' in options:
            ofport = self.get_ofport(name)
            return TunnelPort(name, ofport, tunnel_type,
                              options['local_ip'], options['remote_ip'])

    def get_tunnel_ports(self, tunnel_type='gre'):
        get_tunnel_port = functools.partial(self.get_tunnel_port,
                                            tunnel_type=tunnel_type)
        return self._get_ports(get_tunnel_port)

    def get_quantum_ports(self, port_name):
        LOG.debug('port_name %s', port_name)
        command = ovs_vsctl.VSCtlCommand(
            'list-ifaces-verbose',
            [dpid_lib.dpid_to_str(self.datapath_id), port_name])
        self.run_command([command])
        if command.result:
            return command.result[0]
        return None

    def set_qos(self, port_name, type='linux-htb', max_rate=None, queues=[]):
        command_qos = ovs_vsctl.VSCtlCommand(
            'set-qos',
            [port_name, type, max_rate])
        command_queue = ovs_vsctl.VSCtlCommand(
            'set-queue',
            [port_name, queues])
        self.run_command([command_qos, command_queue])
        if command_qos.result and command_queue.result:
            return command_qos.result + command_queue.result
        return None

    def del_qos(self, port_name):
        command = ovs_vsctl.VSCtlCommand(
            'del-qos',
            [port_name])
        self.run_command([command])
