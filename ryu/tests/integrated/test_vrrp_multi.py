# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at valinux co jp>
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
Usage:
PYTHONPATH=. ./bin/ryu-manager --verbose \
             ./ryu/topology/switches.py \
             ./ryu/services/vrrp/manager.py \
             ./ryu/tests/integrated/test_vrrp.py \
             ./ryu/services/vrrp/dumper.py

./ryu/services/vrrp/dumper.py is optional.

  -----          --------------          -----
  |OVS|<--veth-->|Linux bridge|<--veth-->|OVS|
  -----          --------------          -----

configure OVSs to connect ryu
example
# brctl addbr b0
# ip link add veth0-ovs type veth peer name veth0-br
# ip link add veth1-ovs type veth peer name veth1-br
# brctl addif b0 veth0-br
# brctl addif b0 veth1-br
# brctl show
bridge name     bridge id               STP enabled     interfaces
b0              8000.6642e5822497       no              veth0-br
                                                        veth1-br
ovs-system              0000.122038293b55       no

# ovs-vsctl add-br s0
# ovs-vsctl add-port s0 veth0-ovs
# ovs-vsctl add-br s1
# ovs-vsctl add-port s1 veth1-ovs
# ovs-vsctl set-controller s0 tcp:127.0.0.1:6633
# ovs-vsctl set bridge s0 protocols='[OpenFlow12]'
# ovs-vsctl set-controller s1 tcp:127.0.0.1:6633
# ovs-vsctl set bridge s1 protocols='[OpenFlow12]'
# ovs-vsctl show
20c2a046-ae7e-4453-a576-11034db24985
    Manager "ptcp:6634"
    Bridge "s0"
        Controller "tcp:127.0.0.1:6633"
            is_connected: true
        Port "veth0-ovs"
            Interface "veth0-ovs"
        Port "s0"
            Interface "s0"
                type: internal
    Bridge "s1"
        Controller "tcp:127.0.0.1:6633"
            is_connected: true
        Port "veth1-ovs"
            Interface "veth1-ovs"
        Port "s1"
            Interface "s1"
                type: internal
    ovs_version: "1.9.90"
# ip link veth0-br set up
# ip link veth0-ovs set up
# ip link veth1-br set up
# ip link veth1-ovs set up
# ip link b0 set up
"""

import netaddr
import time

from ryu.base import app_manager
from ryu.controller import handler
from ryu.lib import dpid as lib_dpid
from ryu.lib import hub
from ryu.lib import mac as lib_mac
from ryu.lib.packet import vrrp
from ryu.services.vrrp import api as vrrp_api
from ryu.services.vrrp import event as vrrp_event
from ryu.topology import event as topo_event
from ryu.topology import api as topo_api


class VRRPConfigApp(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(VRRPConfigApp, self).__init__(*args, **kwargs)
        self.start_main = False

    @handler.set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        if self.start_main:
            return

        switches = topo_api.get_switch(self)
        if len(switches) < 2:
            return

        self.start_main = True
        hub.spawn(self._main)

    def _main(self):
        time.sleep(1)
        self.logger.debug('########## test start ##########')
        self._main_version(vrrp.VRRP_VERSION_V3)
        time.sleep(5)
        self._main_version(vrrp.VRRP_VERSION_V2)
        self.logger.debug('########## test done ##########')

    def _main_version(self, vrrp_version):
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_ADDRESS_OWNER)
        time.sleep(5)
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_BACKUP_MAX)
        time.sleep(5)
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_BACKUP_DEFAULT)
        time.sleep(5)
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_BACKUP_MIN)

    def _main_version_priority(self, vrrp_version, priority):
        self._main_version_priority_sleep(vrrp_version, priority, False)
        time.sleep(5)
        self._main_version_priority_sleep(vrrp_version, priority, True)

    def _config_switch(self, switches, switch_index,
                       vrrp_version, ip_addr, priority):
        self.logger.debug('%s', switches.dps)
        dpid = switches.dps.keys()[switch_index]
        self.logger.debug('%s', lib_dpid.dpid_to_str(dpid))
        self.logger.debug('%s', switches.port_state)
        port_no = switches.port_state[dpid].keys()[0]
        self.logger.debug('%d', port_no)
        port = switches.port_state[dpid][port_no]
        self.logger.debug('%s', port)
        mac = port.hw_addr
        self.logger.debug('%s', lib_mac.haddr_to_str(mac))

        ip_addr = netaddr.IPAddress(ip_addr).value
        interface = vrrp_event.VRRPInterfaceOpenFlow(
            mac, ip_addr, None, dpid, port_no)
        self.logger.debug('%s', interface)

        config = vrrp_event.VRRPConfig(
            version=vrrp_version, vrid=7, priority=priority,
            ip_addresses=[ip_addr])
        self.logger.debug('%s', config)

        rep = vrrp_api.vrrp_config(self, interface, config)
        self.logger.debug('%s', rep)
        return rep

    def _main_version_priority_sleep(self, vrrp_version, priority, do_sleep):
        self.logger.debug('########## '
                          'test vrrp_verson %s priority %d do_sleep %d '
                          '##########',
                          vrrp_version, priority, do_sleep)
        app_mgr = app_manager.AppManager.get_instance()
        self.logger.debug('%s', app_mgr.applications)
        vrrp_mgr = app_mgr.applications['VRRPManager']
        switches = app_mgr.applications['switches']

        rep1 = self._config_switch(switches, 1, vrrp_version, '10.0.0.2',
                                   vrrp.VRRP_PRIORITY_BACKUP_DEFAULT)
        if do_sleep:
            time.sleep(5)
        rep0 = self._config_switch(switches, 0, vrrp_version, '10.0.0.1',
                                   priority)

        self.logger.debug('%s', vrrp_mgr._instances)

        if do_sleep:
            time.sleep(10)

        vrrp_api.vrrp_shutdown(self, rep0.instance_name)
        if do_sleep:
            time.sleep(10)
        vrrp_api.vrrp_shutdown(self, rep1.instance_name)
