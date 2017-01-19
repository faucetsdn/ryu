# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

from distutils.spawn import find_executable
import logging
import subprocess
import unittest

from nose.tools import eq_
from nose.tools import ok_

from ryu.lib.hub import sleep
from ryu.lib.ovs import vsctl


LOG = logging.getLogger(__name__)

DOCKER_IMAGE_MININET = 'osrg/ryu-book'

OVSDB_MANAGER_ADDR = 'ptcp:6640'
OVSDB_SWITCH_ADDR = 'tcp:%s:6640'


def setUpModule():
    if not find_executable('docker'):
        raise unittest.SkipTest(
            'Docker is not available. Test in %s will be skipped.' % __name__)


def _run(command):
    popen = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    popen.wait()
    result = popen.stdout.read().decode('utf-8')

    if result:
        return [str(r.strip('\r')) for r in result.split('\n')]
    else:
        return []


class TestVSCtl(unittest.TestCase):
    """
    Test cases for ryu.lib.ovs.vsctl.VSCtl
    """
    container_mn = None  # Container ID of Mininet
    container_mn_ip = None  # IP of Mininet container

    vsctl = None  # instance of vsctl.VSCtl

    @classmethod
    def _docker_exec(cls, container, command):
        return _run('docker exec -t %s %s' % (container, command))

    @classmethod
    def _docker_exec_mn(cls, command):
        return cls._docker_exec(cls.container_mn, command)

    @classmethod
    def _docker_run(cls, image):
        return _run('docker run --privileged -t -d %s' % image)[0]

    @classmethod
    def _docker_stop(cls, container):
        return _run('docker stop %s' % container)[0]

    @classmethod
    def _docker_rm(cls, container):
        return _run('docker rm %s' % container)[0]

    @classmethod
    def _docker_inspect_ip_addr(cls, container):
        return _run(
            'docker inspect --format="{{.NetworkSettings.IPAddress}}" %s' %
            container)[0]

    @classmethod
    def _set_up_mn_container(cls):
        cls.container_mn = cls._docker_run(DOCKER_IMAGE_MININET)
        cls.container_mn_ip = cls._docker_inspect_ip_addr(cls.container_mn)

        # Note: Wait for loading the OVS kernel module.
        # If the OVS kernel module is loaded at first time, it might take
        # a few seconds.
        sleep(5)

        cls._docker_exec_mn(
            'ovs-vsctl set-manager %s' % OVSDB_MANAGER_ADDR)

    @classmethod
    def _set_up_vsctl(cls):
        cls.vsctl = vsctl.VSCtl(OVSDB_SWITCH_ADDR % cls.container_mn_ip)

    @classmethod
    def setUpClass(cls):
        cls._set_up_mn_container()
        cls._set_up_vsctl()

    @classmethod
    def _tear_down_mn_container(cls):
        cls._docker_exec_mn('mn --clean')
        cls._docker_stop(cls.container_mn)
        cls._docker_rm(cls.container_mn)

    @classmethod
    def tearDownClass(cls):
        cls._tear_down_mn_container()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _run_commands(self, commands):
        self.vsctl.run_command(commands, timeout_sec=1)

    # 00: Open vSwitch commands

    def test_00_01_init(self):
        command = vsctl.VSCtlCommand('init')
        self._run_commands([command])

        ok_(command.result is None)

    def test_00_02_show(self):
        command = vsctl.VSCtlCommand('show')
        self._run_commands([command])

        ok_(command.result is not None)

    # 01: Bridge commands

    def test_01_01_add_br_bridge(self):
        bridge = 's1'
        command = vsctl.VSCtlCommand('add-br', (bridge,))
        self._run_commands([command])

        result = self._docker_exec_mn('ovs-vsctl list-br')
        ok_(bridge in result)

    def test_01_02_add_br_parent_vlan(self):
        bridge = 'sub-s1-100'
        parent = 's1'
        vlan = '100'
        command = vsctl.VSCtlCommand('add-br', (bridge, parent, vlan))
        self._run_commands([command])

        result = self._docker_exec_mn('ovs-vsctl list-br')
        ok_(bridge in result)
        result = self._docker_exec_mn(
            'ovs-vsctl br-to-parent %s' % bridge)
        eq_(parent, result[0])
        result = self._docker_exec_mn(
            'ovs-vsctl br-to-vlan %s' % bridge)
        eq_(vlan, result[0])

    def test_01_03_del_br(self):
        bridge = 's1'
        child = 'sub-s1-100'

        command = vsctl.VSCtlCommand('del-br', (bridge,))
        self._run_commands([command])

        result = self._docker_exec_mn('ovs-vsctl list-br')
        ok_(bridge not in result)
        ok_(child not in result)

    def test_01_04_list_br(self):
        bridge = 's1'
        child = 'sub-s1-100'
        vlan = '100'
        self._docker_exec_mn('ovs-vsctl add-br %s' % bridge)
        self._docker_exec_mn(
            'ovs-vsctl add-br %s %s %s' % (child, bridge, vlan))

        command = vsctl.VSCtlCommand('list-br')
        self._run_commands([command])

        ok_(bridge in command.result)
        ok_(child in command.result)

    def test_01_05_br_exists(self):
        bridge = 's1'

        command = vsctl.VSCtlCommand('br-exists', (bridge, ))
        self._run_commands([command])

        eq_(True, command.result)

    def test_01_06_br_to_vlan(self):
        bridge = 's1'

        command = vsctl.VSCtlCommand('br-to-vlan', (bridge, ))
        self._run_commands([command])

        eq_(0, command.result)

    def test_01_06_br_to_vlan_fake_bridge(self):
        bridge = 'sub-s1-100'

        command = vsctl.VSCtlCommand('br-to-vlan', (bridge, ))
        self._run_commands([command])

        eq_(100, command.result)

    def test_01_07_br_to_parent(self):
        bridge = 's1'
        parent = bridge

        command = vsctl.VSCtlCommand('br-to-parent', (bridge, ))
        self._run_commands([command])

        # result = <ryu.lib.ovs.vsctl.VSCtlBridge object>
        eq_(parent, command.result.name)

    def test_01_07_br_to_parent_fake_bridge(self):
        bridge = 'sub-s1-100'
        parent = 's1'

        command = vsctl.VSCtlCommand('br-to-parent', (bridge, ))
        self._run_commands([command])

        # result = <ryu.lib.ovs.vsctl.VSCtlBridge object>
        eq_(parent, command.result.name)

    def test_01_08_br_set_external_id_add(self):
        bridge = 's1'
        key = 'ext_id_key'
        value = 'ext_id_value'

        command = vsctl.VSCtlCommand(
            'br-set-external-id', (bridge, key, value))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl br-get-external-id %s %s' % (bridge, key))
        eq_(value, result[0])

    def test_01_09_br_get_external_id_value(self):
        bridge = 's1'
        key = 'ext_id_key'
        value = 'ext_id_value'

        command = vsctl.VSCtlCommand(
            'br-get-external-id', (bridge, key))
        self._run_commands([command])

        eq_(value, command.result)

    def test_01_10_br_get_external_id_dict(self):
        bridge = 's1'
        key = 'ext_id_key'
        value = 'ext_id_value'

        command = vsctl.VSCtlCommand(
            'br-get-external-id', (bridge,))
        self._run_commands([command])

        eq_({key: value}, command.result)

    def test_01_11_br_set_external_id_clear(self):
        bridge = 's1'
        key = 'ext_id_key'

        command = vsctl.VSCtlCommand(
            'br-set-external-id', (bridge, key))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl br-get-external-id %s %s' % (bridge, key))
        eq_([], result)

        # Clean up
        self._docker_exec_mn('mn --clean')

    # 02: Port commands

    def test_02_01_list_ports(self):
        bridge = 's1'
        interface_1 = 's1-eth1'
        interface_2 = 's1-eth2'

        self._docker_exec_mn(
            'ip link add %s type dummy' % interface_1)
        self._docker_exec_mn(
            'ip link add %s type dummy' % interface_2)
        self._docker_exec_mn(
            'ovs-vsctl add-br %(bridge)s'
            ' -- add-port %(bridge)s %(interface_1)s'
            ' -- add-port %(bridge)s %(interface_2)s' % locals())

        command = vsctl.VSCtlCommand('list-ports', (bridge,))
        self._run_commands([command])

        ok_(interface_1 in command.result)
        ok_(interface_2 in command.result)

    def test_02_02_add_port(self):
        bridge = 's1'
        interface_1 = 's1-eth1'
        self._docker_exec_mn(
            'ovs-vsctl del-port %s %s' % (bridge, interface_1))

        command = vsctl.VSCtlCommand('add-port', (bridge, interface_1))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl port-to-br %s' % interface_1)
        eq_(bridge, result[0])

    def test_02_03_add_bond(self):
        bridge = 's1'
        interface_1 = 's1-eth1'
        interface_2 = 's1-eth2'
        port = 's1-bond1'
        interface_list = [interface_1, interface_2]
        self._docker_exec_mn('ovs-vsctl del-br %s' % bridge)
        self._docker_exec_mn('ovs-vsctl add-br %s' % bridge)

        command = vsctl.VSCtlCommand(
            'add-bond', (bridge, port, interface_list))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl port-to-br %s' % port)
        eq_(bridge, result[0])

    def test_02_04_del_port(self):
        bridge = 's1'
        port = 's1-bond1'

        command = vsctl.VSCtlCommand('del-port', (bridge, port))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl list-ports %s' % bridge)
        eq_([], result)

    def test_02_05_port_to_br(self):
        bridge = 's1'
        port_1 = 's1-eth1'
        port_2 = 's1-eth2'
        self._docker_exec_mn('ovs-vsctl del-br %s' % bridge)
        self._docker_exec_mn(
            'ovs-vsctl add-br %(bridge)s'
            ' -- add-port %(bridge)s %(port_1)s'
            ' -- add-port %(bridge)s %(port_2)s' % locals())

        command = vsctl.VSCtlCommand('port-to-br', (port_1,))
        self._run_commands([command])

        eq_(bridge, command.result)

        # Clean up
        self._docker_exec_mn('mn --clean')

    # 03: Interface commands

    def test_03_01_list_ifaces(self):
        bridge = 's1'
        interface_1 = 's1-eth1'
        interface_2 = 's1-eth2'

        self._docker_exec_mn(
            'ip link add %s type dummy' % interface_1)
        self._docker_exec_mn(
            'ip link add %s type dummy' % interface_2)
        self._docker_exec_mn(
            'ovs-vsctl add-br %(bridge)s'
            ' -- add-port %(bridge)s %(interface_1)s'
            ' -- add-port %(bridge)s %(interface_2)s' % locals())

        command = vsctl.VSCtlCommand('list-ifaces', (bridge,))
        self._run_commands([command])

        ok_(interface_1 in command.result)
        ok_(interface_2 in command.result)

    def test_03_02_ifaces_to_br(self):
        bridge = 's1'
        interface_1 = 's1-eth1'

        command = vsctl.VSCtlCommand('iface-to-br', (interface_1,))
        self._run_commands([command])

        eq_(bridge, command.result)

        # Clean up
        self._docker_exec_mn('mn --clean')

    # 04: Controller commands

    def test_04_01_get_controller(self):
        bridge = 's1'
        controller = 'tcp:127.0.0.1:6653'
        self._docker_exec_mn(
            'ovs-vsctl add-br %(bridge)s'
            ' -- set-controller %(bridge)s %(controller)s' % locals())

        command = vsctl.VSCtlCommand('get-controller', (bridge,))
        self._run_commands([command])

        eq_(1, len(command.result))
        eq_(controller, command.result[0])

    def test_04_02_del_controller(self):
        bridge = 's1'

        command = vsctl.VSCtlCommand('del-controller', (bridge,))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get-controller %s' % bridge)
        eq_([], result)

    def test_04_03_set_controller(self):
        bridge = 's1'
        controller = 'tcp:127.0.0.1:6653'

        command = vsctl.VSCtlCommand('set-controller', (bridge, controller))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get-controller %s' % bridge)
        eq_(controller, result[0])

    def test_04_04_get_fail_mode(self):
        bridge = 's1'
        fai_mode = 'secure'
        self._docker_exec_mn(
            'ovs-vsctl set-fail-mode %s %s' % (bridge, fai_mode))

        command = vsctl.VSCtlCommand('get-fail-mode', (bridge,))
        self._run_commands([command])

        eq_(fai_mode, command.result)

    def test_04_05_del_fail_mode(self):
        bridge = 's1'

        command = vsctl.VSCtlCommand('del-fail-mode', (bridge,))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get-fail-mode %s' % bridge)
        eq_([], result)

    def test_04_06_set_fail_mode(self):
        bridge = 's1'
        fail_mode = 'secure'

        command = vsctl.VSCtlCommand('set-fail-mode', (bridge, fail_mode))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get-fail-mode %s' % bridge)
        eq_(fail_mode, result[0])

        # Clean up
        self._docker_exec_mn('mn --clean')

    # 05: Manager commands (not implemented yet)
    # 06: SSL commands (not implemented yet)
    # 07: Switch commands (not implemented yet)

    # 08: Database commands

    def test_08_01_list(self):
        table = 'Bridge'
        bridge = 's1'
        interface_1 = 's1-eth1'
        interface_2 = 's1-eth2'
        fail_mode = 'secure'
        protocols = 'OpenFlow10,OpenFlow13'
        datapath_id = '1111111111111111'

        self._docker_exec_mn(
            'ip link add %s type dummy' % interface_1)
        self._docker_exec_mn(
            'ip link add %s type dummy' % interface_2)
        self._docker_exec_mn(
            'ovs-vsctl add-br %(bridge)s'
            ' -- add-port %(bridge)s %(interface_1)s'
            ' -- add-port %(bridge)s %(interface_2)s' % locals())
        self._docker_exec_mn(
            'ovs-vsctl set %(table)s %(bridge)s '
            'fail_mode=%(fail_mode)s '
            'protocols=%(protocols)s '
            'other_config:datapath-id=%(datapath_id)s' % locals())

        command = vsctl.VSCtlCommand('list', (table,))
        self._run_commands([command])

        eq_(1, len(command.result))
        # command.result[0] = <ryu.lib.ovs.vsctl.VSCtlBridge object>
        eq_(bridge, command.result[0].name)

    def test_08_02_find(self):
        table = 'Bridge'
        bridge = 's1'

        command = vsctl.VSCtlCommand('find', (table, 'name=%s' % bridge))
        self._run_commands([command])

        eq_(1, len(command.result))
        # command.result[0] = <ovs.db.idl.Row object object> for Bridge
        eq_(bridge, command.result[0].name)

    def test_08_02_find_complex(self):
        table = 'Bridge'
        bridge = 's1'
        fail_mode = 'secure'
        protocols = 'OpenFlow10,OpenFlow13'
        datapath_id = '1111111111111111'

        command = vsctl.VSCtlCommand(
            'find', (table, 'fail_mode=%s' % fail_mode,
                     'protocols=%s' % protocols,
                     'other_config:datapath-id=%s' % datapath_id))
        self._run_commands([command])

        eq_(1, len(command.result))
        # command.result[0] = <ovs.db.idl.Row object object> for Bridge
        eq_(bridge, command.result[0].name)

    def test_08_03_get_01_value(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'fail_mode'
        value = 'secure'

        command = vsctl.VSCtlCommand('get', (table, bridge, column))
        self._run_commands([command])

        # command.result[0] is a list of return values
        eq_(value, command.result[0][0])

    def test_08_03_get_02_set(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'protocols'
        value = 'OpenFlow10,OpenFlow13'.split(',')

        command = vsctl.VSCtlCommand('get', (table, bridge, column))
        self._run_commands([command])

        # command.result[0] is a list
        eq_(value, command.result[0])

    def test_08_03_get_03_map(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'other_config'
        key = 'datapath-id'
        datapath_id = '1111111111111111'
        value = {key: datapath_id}

        command = vsctl.VSCtlCommand('get', (table, bridge, column))
        self._run_commands([command])

        # command.result[0] is a dict
        eq_(value, command.result[0])

    def test_08_03_get_04_map_value(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'other_config'
        key = 'datapath-id'
        datapath_id = '1111111111111111'
        value = datapath_id

        command = vsctl.VSCtlCommand(
            'get', (table, bridge, '%s:%s' % (column, key)))
        self._run_commands([command])

        # command.result[0] is a dict
        eq_(value, command.result[0])

    def test_08_04_set_01_value(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'fail_mode'
        value = 'standalone'

        command = vsctl.VSCtlCommand(
            'set', (table, bridge, '%s=%s' % (column, value)))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        eq_(value, result[0])

    def test_08_04_set_02_set(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'protocols'
        value = 'OpenFlow10,OpenFlow12,OpenFlow13'

        command = vsctl.VSCtlCommand(
            'set', (table, bridge, '%s=%s' % (column, value)))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '["OpenFlow10", "OpenFlow12", "OpenFlow13"]'
        eq_(expected_value, result[0])

    def test_08_04_set_03_map(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'other_config'
        key = 'datapath-id'
        value = '0000000000000001'

        command = vsctl.VSCtlCommand(
            'set', (table, bridge, '%s:%s=%s' % (column, key, value)))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s:%s' % (table, bridge, column, key))
        expected_value = '"0000000000000001"'
        eq_(expected_value, result[0])

    def test_08_05_add_01_value(self):
        table = 'Port'
        bridge = 's1'
        column = 'tag'
        value = '100'

        command = vsctl.VSCtlCommand(
            'add', (table, bridge, column, value))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        eq_(value, result[0])

    def test_08_05_add_02_set(self):
        table = 'Port'
        bridge = 's1'
        column = 'trunks'
        value = '100,200'

        command = vsctl.VSCtlCommand(
            'add', (table, bridge, column, value))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '[100, 200]'
        eq_(expected_value, result[0])

    def test_08_05_add_03_map(self):
        table = 'Bridge'
        bridge = 's1'
        column = 'other_config'
        key = 'datapath-id'
        value = '0000000000000011'

        command = vsctl.VSCtlCommand(
            'add', (table, bridge, column, '%s=%s' % (key, value)))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s:%s' % (table, bridge, column, key))
        expected_value = '"0000000000000011"'
        eq_(expected_value, result[0])

    def test_08_06_remove_01_value(self):
        table = 'Port'
        bridge = 's1'
        column = 'tag'
        value = '100'
        self._docker_exec_mn(
            'ovs-vsctl set %s %s %s=%s' % (table, bridge, column, value))

        command = vsctl.VSCtlCommand(
            'remove', (table, bridge, column, value))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '[]'
        eq_(expected_value, result[0])

    def test_08_06_remove_02_set(self):
        table = 'Port'
        bridge = 's1'
        column = 'trunks'
        init_value = '100,200,300'
        value = '100,200'
        self._docker_exec_mn(
            'ovs-vsctl set %s %s %s=%s' % (table, bridge, column, init_value))

        command = vsctl.VSCtlCommand(
            'remove', (table, bridge, column, value))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '[300]'
        eq_(expected_value, result[0])

    def test_08_06_remove_03_map(self):
        table = 'Port'
        bridge = 's1'
        column = 'other_config'
        key = 'priority-tag'
        value = 'true'
        self._docker_exec_mn(
            'ovs-vsctl set %s %s %s:%s=%s' %
            (table, bridge, column, key, value))

        command = vsctl.VSCtlCommand(
            'remove', (table, bridge, column, '%s=%s' % (key, value)))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '{}'
        eq_(expected_value, result[0])

    def test_08_07_clear_01_value(self):
        table = 'Port'
        bridge = 's1'
        column = 'tag'
        value = '100'
        self._docker_exec_mn(
            'ovs-vsctl set %s %s %s=%s' % (table, bridge, column, value))

        command = vsctl.VSCtlCommand(
            'clear', (table, bridge, column))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '[]'
        eq_(expected_value, result[0])

    def test_08_07_clear_02_set(self):
        table = 'Port'
        bridge = 's1'
        column = 'trunks'
        value = '100,200'
        self._docker_exec_mn(
            'ovs-vsctl set %s %s %s=%s' % (table, bridge, column, value))

        command = vsctl.VSCtlCommand(
            'clear', (table, bridge, column))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '[]'
        eq_(expected_value, result[0])

    def test_08_07_clear_03_map(self):
        table = 'Port'
        bridge = 's1'
        column = 'other_config'
        key = 'priority-tag'
        value = 'true'
        self._docker_exec_mn(
            'ovs-vsctl set %s %s %s:%s=%s' %
            (table, bridge, column, key, value))

        command = vsctl.VSCtlCommand(
            'clear', (table, bridge, column, '%s=%s' % (key, value)))
        self._run_commands([command])

        result = self._docker_exec_mn(
            'ovs-vsctl get %s %s %s' % (table, bridge, column))
        expected_value = '{}'
        eq_(expected_value, result[0])

        # Clean up
        self._docker_exec_mn('mn --clean')
