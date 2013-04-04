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
             ./ryu/services/vrrp/manager.py \
             ./ryu/services/vrrp/dumper.py \
             ./ryu/services/vrrp/sample_manager.py \
             ./ryu/tests/integrated/test_vrrp_linux_multi.py

./ryu/services/vrrp/dumper.py is optional.

Example:
Use namespace not to send VRRP packet to outside
another vrrp daemon can be run under vrrpd-ump name space if you like.

                   ----------------
      /--<--veth-->|              |
   Ryu             | linux bridge |<--veth--> command to generate packets
      \--<--veth-->|              |
                   ----------------


# ip link add veth0 type veth peer name veth0-br
# ip link add veth1 type veth peer name veth1-br
# ip link add veth2 type veth peer name veth2-br

# brctl addbr vrrpbr
# brctl addif vrrpbr veth0-br
# brctl addif vrrpbr veth1-br
# brctl addif vrrpbr veth2-br


# ip link set veth0 up
# ip link set veth0-br up
# ip link set veth1 up
# ip link set veth1-br up
# ip link set veth2 up
# ip link set veth2-br up
# ip link set vrrpbr up

if you like, capture packets on each interfaces like
# tshark -i vrrpbr
# tshark -i veth0
# tshark -i veth1
# tshark -i veth2

virtual router mac address: 00:00:5E:00:01:{VRID} = 00:00:5E:00:01:07
during working, send packets destined to mac address 00:00:5E:00:01:07
from veth2 by packet generator like packeth

NOTE: vrid: 7 and ip address: 10.0.0.1... are hardcoded below
"""

import netaddr
import time

from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib import mac as lib_mac
from ryu.lib.packet import vrrp
from ryu.services.vrrp import api as vrrp_api
from ryu.services.vrrp import event as vrrp_event


_VRID = 7
_IP_ADDRESS = '10.0.0.1'

_IFNAME0 = 'veth0'
_PRIMARY_IP_ADDRESS0 = '10.0.0.2'

_IFNAME1 = 'veth1'
_PRIMARY_IP_ADDRESS1 = '10.0.0.3'

# _IFNAME = 'eth2'
# _VRID = 1
# _IP_ADDRESS = '172.17.107.2'


class VRRPConfigApp(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(VRRPConfigApp, self).__init__(*args, **kwargs)
        self.logger.info(
            'virtual router mac address = %s',
            lib_mac.haddr_to_str(vrrp.vrrp_ipv4_src_mac_address(_VRID)))

    def start(self):
        hub.spawn(self._main)

    def _main(self):
        time.sleep(1)
        self._main_version(vrrp.VRRP_VERSION_V3)
        time.sleep(5)
        self._main_version(vrrp.VRRP_VERSION_V2)

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

    def _configure_vrrp_router(self, vrrp_version, priority,
                               primary_ip_address, ifname):
        primary_ip_address = netaddr.IPAddress(primary_ip_address)
        interface = vrrp_event.VRRPInterfaceNetworkDevice(
            lib_mac.DONTCARE, primary_ip_address, None, ifname)
        self.logger.debug('%s', interface)

        ip_addresses = [netaddr.IPAddress(_IP_ADDRESS).value]
        config = vrrp_event.VRRPConfig(
            version=vrrp_version, vrid=_VRID, priority=priority,
            ip_addresses=ip_addresses)
        self.logger.debug('%s', config)

        rep = vrrp_api.vrrp_config(self, interface, config)
        self.logger.debug('%s', rep)

        return rep

    def _main_version_priority_sleep(self, vrrp_version, priority, do_sleep):
        app_mgr = app_manager.AppManager.get_instance()
        self.logger.debug('%s', app_mgr.applications)
        vrrp_mgr = app_mgr.applications['VRRPManager']

        rep0 = self._configure_vrrp_router(vrrp_version, priority,
                                           _PRIMARY_IP_ADDRESS0, _IFNAME0)
        rep1 = self._configure_vrrp_router(
            vrrp_version, vrrp.VRRP_PRIORITY_BACKUP_DEFAULT,
            _PRIMARY_IP_ADDRESS1, _IFNAME1)

        self.logger.debug('%s', vrrp_mgr._instances)

        if do_sleep:
            time.sleep(10)

        vrrp_api.vrrp_shutdown(self, rep0.instance_name)
        if do_sleep:
            time.sleep(10)
        vrrp_api.vrrp_shutdown(self, rep1.instance_name)
