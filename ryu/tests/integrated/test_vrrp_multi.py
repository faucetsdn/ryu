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
             ryu.topology.switches \
             ryu.tests.integrated.test_vrrp_multi \
             ryu.services.protocols.vrrp.dumper

ryu.services.protocols.vrrp.dumper is optional.

         +---+          ----------------
      /--|OVS|<--veth-->|              |
   Ryu   +---+          | linux bridge |<--veth--> command to generate packets
      \--|OVS|<--veth-->|              |
         +---+          ----------------

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

from ryu.base import app_manager
from ryu.controller import handler
from ryu.lib import dpid as lib_dpid
from ryu.lib import hub
from ryu.lib.packet import vrrp
from ryu.services.protocols.vrrp import api as vrrp_api
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import monitor_openflow
from ryu.topology import event as topo_event
from ryu.topology import api as topo_api

from . import vrrp_common


class VRRPConfigApp(vrrp_common.VRRPCommon):
    _IFNAME0 = 0
    _IFNAME1 = 1

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
        app_mgr = app_manager.AppManager.get_instance()
        self.logger.debug('%s', app_mgr.applications)
        self.switches = app_mgr.applications['switches']
        hub.spawn(self._main)

    def _configure_vrrp_router(self, vrrp_version, priority,
                               ip_addr, switch_index, vrid):
        switches = self.switches
        self.logger.debug('%s', switches.dps)
        dpid = sorted(switches.dps.keys())[switch_index]
        self.logger.debug('%s', lib_dpid.dpid_to_str(dpid))
        self.logger.debug('%s', switches.port_state)
        # hack: use the smallest port no to avoid picking OVS local port
        port_no = sorted(switches.port_state[dpid].keys())[0]
        self.logger.debug('%d', port_no)
        port = switches.port_state[dpid][port_no]
        self.logger.debug('%s', port)
        mac = port.hw_addr
        self.logger.debug('%s', mac)

        interface = vrrp_event.VRRPInterfaceOpenFlow(
            mac, ip_addr, None, dpid, port_no)
        self.logger.debug('%s', interface)

        config = vrrp_event.VRRPConfig(
            version=vrrp_version, vrid=vrid, priority=priority,
            ip_addresses=[ip_addr])
        self.logger.debug('%s', config)

        rep = vrrp_api.vrrp_config(self, interface, config)
        self.logger.debug('%s', rep)
        return rep
