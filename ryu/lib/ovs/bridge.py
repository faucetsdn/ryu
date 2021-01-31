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
Wrapper utility library of :py:mod:`ryu.lib.ovs.vsctl`
"""

import functools
import logging

from ryu import cfg
import ryu.exception as ryu_exc
import ryu.lib.dpid as dpid_lib
import ryu.lib.ovs.vsctl as ovs_vsctl
from ryu.lib.ovs.vsctl import valid_ovsdb_addr


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
    """
    Class to provide wrapper utilities of :py:mod:`ryu.lib.ovs.vsctl.VSCtl`

    ``CONF`` is a instance of ``oslo_config.cfg.ConfigOpts``.
    Mostly ``self.CONF`` is sufficient to instantiate this class from your Ryu
    application.

    ``datapath_id`` specifies Datapath ID of the target OVS instance.

    ``ovsdb_addr`` specifies the address of the OVS instance.
    Automatically validated when you call ``init()`` method.
    Refer to :py:mod:`ryu.lib.ovs.vsctl.valid_ovsdb_addr` for the format of
    this address.

    if ``timeout`` is omitted, ``CONF.ovsdb_timeout`` will be used as the
    default value.

    Usage of ``timeout`` and ``exception`` is the same with ``timeout_sec``
    and ``exception`` of :py:mod:`ryu.lib.ovs.vsctl.VSCtl.run_command`.
    """

    def __init__(self, CONF, datapath_id, ovsdb_addr, timeout=None,
                 exception=None):
        super(OVSBridge, self).__init__()
        self.datapath_id = datapath_id
        self.ovsdb_addr = ovsdb_addr
        self.vsctl = ovs_vsctl.VSCtl(ovsdb_addr)
        self.timeout = timeout or CONF.ovsdb_timeout
        self.exception = exception

        self.br_name = None

    def run_command(self, commands):
        """
        Executes the given commands and sends OVSDB messages.

        ``commands`` must be a list of
        :py:mod:`ryu.lib.ovs.vsctl.VSCtlCommand`.

        The given ``timeout`` and ``exception`` when instantiation will be used
        to call :py:mod:`ryu.lib.ovs.vsctl.VSCtl.run_command`.
        """
        self.vsctl.run_command(commands, self.timeout, self.exception)

    def init(self):
        """
        Validates the given ``ovsdb_addr`` and connects to OVS instance.

        If failed to connect to OVS instance or the given ``datapath_id`` does
        not match with the Datapath ID of the connected OVS instance, raises
        :py:mod:`ryu.lib.ovs.bridge.OVSBridgeNotFound` exception.
        """
        if not valid_ovsdb_addr(self.ovsdb_addr):
            raise ValueError('Invalid OVSDB address: %s' % self.ovsdb_addr)
        if self.br_name is None:
            self.br_name = self._get_bridge_name()

    def _get_bridge_name(self):
        """ get Bridge name of a given 'datapath_id' """
        command = ovs_vsctl.VSCtlCommand(
            'find',
            ('Bridge',
             'datapath_id=%s' % dpid_lib.dpid_to_str(self.datapath_id)))
        self.run_command([command])
        if not isinstance(command.result, list) or len(command.result) != 1:
            raise OVSBridgeNotFound(
                datapath_id=dpid_lib.dpid_to_str(self.datapath_id))
        return command.result[0].name

    def get_controller(self):
        """
        Gets the configured OpenFlow controller address.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl get-controller <bridge>
        """
        command = ovs_vsctl.VSCtlCommand('get-controller', [self.br_name])
        self.run_command([command])
        result = command.result
        return result[0] if len(result) == 1 else result

    def set_controller(self, controllers):
        """
        Sets the OpenFlow controller address.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl set-controller <bridge> <target>...
        """
        command = ovs_vsctl.VSCtlCommand('set-controller', [self.br_name])
        command.args.extend(controllers)
        self.run_command([command])

    def del_controller(self):
        """
        Deletes the configured OpenFlow controller address.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl del-controller <bridge>
        """
        command = ovs_vsctl.VSCtlCommand('del-controller', [self.br_name])
        self.run_command([command])

    def list_db_attributes(self, table, record=None):
        """
        Lists 'record' (or all records) in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl list TBL [REC]
        """
        command = ovs_vsctl.VSCtlCommand('list', (table, record))
        self.run_command([command])
        if command.result:
            return command.result
        return []

    def find_db_attributes(self, table, *conditions):
        """
        Lists records satisfying 'conditions' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl find TBL CONDITION...

        .. Note::

            Currently, only '=' condition is supported.
            To support other condition is TODO.
        """
        args = [table]
        args.extend(conditions)
        command = ovs_vsctl.VSCtlCommand('find', args)
        self.run_command([command])
        if command.result:
            return command.result
        return []

    def get_db_attribute(self, table, record, column, key=None):
        """
        Gets values of 'column' in 'record' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl get TBL REC COL[:KEY]
        """
        if key is not None:
            column = '%s:%s' % (column, key)
        command = ovs_vsctl.VSCtlCommand(
            'get', (table, record, column))
        self.run_command([command])
        if command.result:
            return command.result[0]
        return None

    def set_db_attribute(self, table, record, column, value, key=None):
        """
        Sets 'value' into 'column' in 'record' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl set TBL REC COL[:KEY]=VALUE
        """
        if key is not None:
            column = '%s:%s' % (column, key)
        command = ovs_vsctl.VSCtlCommand(
            'set', (table, record, '%s=%s' % (column, value)))
        self.run_command([command])

    def add_db_attribute(self, table, record, column, value, key=None):
        """
        Adds ('key'=)'value' into 'column' in 'record' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl add TBL REC COL [KEY=]VALUE
        """
        if key is not None:
            value = '%s=%s' % (key, value)
        command = ovs_vsctl.VSCtlCommand(
            'add', (table, record, column, value))
        self.run_command([command])

    def remove_db_attribute(self, table, record, column, value, key=None):
        """
        Removes ('key'=)'value' into 'column' in 'record' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl remove TBL REC COL [KEY=]VALUE
        """
        if key is not None:
            value = '%s=%s' % (key, value)
        command = ovs_vsctl.VSCtlCommand(
            'remove', (table, record, column, value))
        self.run_command([command])

    def clear_db_attribute(self, table, record, column):
        """
        Clears values from 'column' in 'record' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl clear TBL REC COL
        """
        command = ovs_vsctl.VSCtlCommand('clear', (table, record, column))
        self.run_command([command])

    def db_get_val(self, table, record, column):
        """
        Gets values of 'column' in 'record' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl get TBL REC COL
        """
        command = ovs_vsctl.VSCtlCommand('get', (table, record, column))
        self.run_command([command])
        assert len(command.result) == 1
        return command.result[0]

    def db_get_map(self, table, record, column):
        """
        Gets dict type value of 'column' in 'record' in 'table'.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl get TBL REC COL
        """
        val = self.db_get_val(table, record, column)
        assert isinstance(val, dict)
        return val

    def get_datapath_id(self):
        """
        Gets Datapath ID of OVS instance.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl get Bridge <bridge> datapath_id
        """
        return self.db_get_val('Bridge', self.br_name, 'datapath_id')

    def delete_port(self, port_name):
        """
        Deletes a port on the OVS instance.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl --if-exists del-port <bridge> <port>
        """
        command = ovs_vsctl.VSCtlCommand(
            'del-port', (self.br_name, port_name), '--if-exists')
        self.run_command([command])

    def get_ofport(self, port_name):
        """
        Gets the OpenFlow port number.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl get Interface <port> ofport
        """
        ofport_list = self.db_get_val('Interface', port_name, 'ofport')
        assert len(ofport_list) == 1
        return int(ofport_list[0])

    def get_port_name_list(self):
        """
        Gets a list of all ports on OVS instance.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl list-ports <bridge>
        """
        command = ovs_vsctl.VSCtlCommand('list-ports', (self.br_name, ))
        self.run_command([command])
        return command.result

    def add_bond(self, name, ifaces, bond_mode=None, lacp=None):
        """
        Creates a bonded port.

        :param name: Port name to be created
        :param ifaces: List of interfaces containing at least 2 interfaces
        :param bond_mode: Bonding mode (active-backup, balance-tcp
                          or balance-slb)
        :param lacp: LACP mode (active, passive or off)
        """
        assert len(ifaces) >= 2

        options = ''
        if bond_mode:
            options += 'bond_mode=%(bond_mode)s' % locals()
        if lacp:
            options += 'lacp=%(lacp)s' % locals()

        command_add = ovs_vsctl.VSCtlCommand(
            'add-bond', (self.br_name, name, ifaces), options)
        self.run_command([command_add])

    def add_tunnel_port(self, name, tunnel_type, remote_ip,
                        local_ip=None, key=None, ofport=None):
        """
        Creates a tunnel port.

        :param name: Port name to be created
        :param tunnel_type: Type of tunnel (gre or vxlan)
        :param remote_ip: Remote IP address of tunnel
        :param local_ip: Local IP address of tunnel
        :param key: Key of GRE or VNI of VxLAN
        :param ofport: Requested OpenFlow port number
        """
        options = 'remote_ip=%(remote_ip)s' % locals()
        if key:
            options += ',key=%(key)s' % locals()
        if local_ip:
            options += ',local_ip=%(local_ip)s' % locals()

        args = ['Interface', name, 'type=%s' % tunnel_type,
                'options:%s' % options]
        if ofport:
            args.append('ofport_request=%(ofport)s' % locals())

        command_add = ovs_vsctl.VSCtlCommand('add-port', (self.br_name, name))
        command_set = ovs_vsctl.VSCtlCommand('set', args)
        self.run_command([command_add, command_set])

    def add_gre_port(self, name, remote_ip,
                     local_ip=None, key=None, ofport=None):
        """
        Creates a GRE tunnel port.

        See the description of ``add_tunnel_port()``.
        """
        self.add_tunnel_port(name, 'gre', remote_ip,
                             local_ip=local_ip, key=key, ofport=ofport)

    def add_vxlan_port(self, name, remote_ip,
                       local_ip=None, key=None, ofport=None):
        """
        Creates a VxLAN tunnel port.

        See the description of ``add_tunnel_port()``.
        """
        self.add_tunnel_port(name, 'vxlan', remote_ip,
                             local_ip=local_ip, key=key, ofport=ofport)

    def del_port(self, port_name):
        """
        Deletes a port on OVS instance.

        This method is corresponding to the following ovs-vsctl command::

            $ ovs-vsctl del-port <bridge> <port>
        """
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
        """ Returns a VIF object for each VIF port """
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

    def set_qos(self, port_name, type='linux-htb', max_rate=None, queues=None):
        """
        Sets a Qos rule and creates Queues on the given port.
        """
        queues = queues if queues else []
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
        """
        Deletes the Qos rule on the given port.
        """
        command = ovs_vsctl.VSCtlCommand(
            'del-qos',
            [port_name])
        self.run_command([command])
