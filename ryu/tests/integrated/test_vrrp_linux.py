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
             ./ryu/tests/integrated/test_vrrp_linux.py \
             ./ryu/services/vrrp/dumper.py

./ryu/services/vrrp/dumper.py is optional.

Example:
Use namespace not to send VRRP packet to outside
another vrrp daemon can be run under vrrpd-ump name space if you like.

  -----          ----------------------
  |Ryu|<--veth-->|vrrp-dump name space|
  -----          ----------------------

# ip netns add vrrp-dump
# ip link add veth0 type veth peer name veth0-dump
# ip link set netns vrrp-dump veth0-dump
# ip netns exec vrrp-dump tshark -i veth0-dump
# ip link set veth0 up
# ip link set veth0-dump up

If you like, vrrpd can be run in vrrp-dump netns
# ip netns exec vrrp-dump vrrpd -i veth0-dump -v 7 10.0.0.1
NOTE: vrid: 7 and ip address: 10.0.0.1 are hardcoded below
"""

import netaddr
import time

from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib import mac as lib_mac
from ryu.lib.packet import vrrp
from ryu.services.vrrp import api as vrrp_api
from ryu.services.vrrp import event as vrrp_event


_IFNAME = 'veth0'
_VRID = 7
_IP_ADDRESS = '10.0.0.1'


class VRRPConfigApp(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(VRRPConfigApp, self).__init__(*args, **kwargs)

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
                                    vrrp.VRRP_PRIORITY_BACKUP_DEFAULT)

    def _main_version_priority(self, vrrp_version, priority):
        self._main_version_priority_sleep(vrrp_version, priority, False)
        time.sleep(5)
        self._main_version_priority_sleep(vrrp_version, priority, True)

    def _main_version_priority_sleep(self, vrrp_version, priority, do_sleep):
        app_mgr = app_manager.AppManager.get_instance()
        self.logger.debug('%s', app_mgr.applications)
        vrrp_mgr = app_mgr.applications['VRRPManager']

        ip_addr = _IP_ADDRESS
        ip_addr = netaddr.IPAddress(ip_addr).value
        ifname = _IFNAME
        interface = vrrp_event.VRRPInterfaceNetworkDevice(
            lib_mac.DONTCARE, ip_addr, None, ifname)
        self.logger.debug('%s', interface)

        config = vrrp_event.VRRPConfig(
            version=vrrp_version, vrid=_VRID, priority=priority,
            ip_addresses=[ip_addr])
        self.logger.debug('%s', config)

        rep = vrrp_api.vrrp_config(self, interface, config)
        self.logger.debug('%s', rep)

        self.logger.debug('%s', vrrp_mgr._instances)

        if do_sleep:
            time.sleep(10)

        vrrp_api.vrrp_shutdown(self, rep.instance_name)
