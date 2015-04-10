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

import time
import random

from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib import mac as lib_mac
from ryu.lib.packet import vrrp
from ryu.services.protocols.vrrp import api as vrrp_api
from ryu.services.protocols.vrrp import event as vrrp_event


_VRID = 7
_PRIMARY_IP_ADDRESS0 = '10.0.0.2'
_PRIMARY_IP_ADDRESS1 = '10.0.0.3'


class VRRPCommon(app_manager.RyuApp):
    _IFNAME0 = None
    _IFNAME1 = None

    def __init__(self, *args, **kwargs):
        super(VRRPCommon, self).__init__(*args, **kwargs)

    def _main(self):
        self._main_version(vrrp.VRRP_VERSION_V3)
        self._main_version(vrrp.VRRP_VERSION_V2)
        print("done!")

    def _main_version(self, vrrp_version):
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_ADDRESS_OWNER)
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_BACKUP_MAX)
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_BACKUP_DEFAULT)
        self._main_version_priority(vrrp_version,
                                    vrrp.VRRP_PRIORITY_BACKUP_MIN)

    def _main_version_priority(self, vrrp_version, priority):
        self._main_version_priority_sleep(vrrp_version, priority, False)
        self._main_version_priority_sleep(vrrp_version, priority, True)

    def _check(self, vrrp_api, instances):
        while True:
            while True:
                rep = vrrp_api.vrrp_list(self)
                if len(rep.instance_list) >= len(instances) * 2:
                    if any(i.state == vrrp_event.VRRP_STATE_INITIALIZE
                           for i in rep.instance_list):
                        continue
                    break
                print('%s / %s' % (len(rep.instance_list), len(instances) * 2))
                time.sleep(1)

#                for i in rep.instance_list:
#                    print('%s %s %s %s %s' % (i.instance_name,
#                          i.monitor_name,
#                          i.config,
#                          i.interface,
#                          i.state))
            assert len(rep.instance_list) == len(instances) * 2
            num_of_master = 0
            d = dict(((i.instance_name, i) for i in rep.instance_list))
            bad = 0
            for i in rep.instance_list:
                assert i.state in (vrrp_event.VRRP_STATE_MASTER,
                                   vrrp_event.VRRP_STATE_BACKUP)
                if i.state == vrrp_event.VRRP_STATE_MASTER:
                    num_of_master += 1

                vr = instances[i.config.vrid]
                if (vr[0].config.priority > vr[1].config.priority and
                        i.instance_name == vr[1].instance_name) or \
                   (vr[0].config.priority < vr[1].config.priority and
                        i.instance_name == vr[0].instance_name):
                    if i.state == vrrp_event.VRRP_STATE_MASTER:
                        print("bad master:")
                        print('%s %s' % (d[vr[0].instance_name].state,
                              d[vr[0].instance_name].config.priority))
                        print('%s %s' % (d[vr[1].instance_name].state,
                              d[vr[1].instance_name].config.priority))
                        bad += 1
#                       assert i.state != vrrp_event.VRRP_STATE_MASTER
            if bad > 0:
                # this could be a transient state
                print("%s bad masters" % bad)
                time.sleep(1)
                continue
            if num_of_master >= len(instances):
                assert num_of_master == len(instances)
                break
            print('%s / %s' % (num_of_master, len(instances)))
            time.sleep(1)
            continue

    def _main_version_priority_sleep(self, vrrp_version, priority, do_sleep):
        app_mgr = app_manager.AppManager.get_instance()
        self.logger.debug('%s', app_mgr.applications)
        vrrp_mgr = app_mgr.applications['VRRPManager']

        step = 5
        instances = {}
        for vrid in range(1, 256, step):
            if vrid == _VRID:
                continue
            print("vrid %s" % vrid)
            l = {}
            prio = max(vrrp.VRRP_PRIORITY_BACKUP_MIN,
                       min(vrrp.VRRP_PRIORITY_BACKUP_MAX, vrid))
            rep0 = self._configure_vrrp_router(vrrp_version,
                                               prio,
                                               _PRIMARY_IP_ADDRESS0,
                                               self._IFNAME0,
                                               vrid)
            assert rep0.instance_name is not None
            l[0] = rep0
            prio = max(vrrp.VRRP_PRIORITY_BACKUP_MIN,
                       min(vrrp.VRRP_PRIORITY_BACKUP_MAX, 256 - vrid))
            rep1 = self._configure_vrrp_router(vrrp_version,
                                               prio,
                                               _PRIMARY_IP_ADDRESS1,
                                               self._IFNAME1,
                                               vrid)
            assert rep1.instance_name is not None
            l[1] = rep1
            instances[vrid] = l

        print("vrid %s" % _VRID)
        l = {}
        rep0 = self._configure_vrrp_router(vrrp_version, priority,
                                           _PRIMARY_IP_ADDRESS0,
                                           self._IFNAME0, _VRID)
        assert rep0.instance_name is not None
        l[0] = rep0
        rep1 = self._configure_vrrp_router(
            vrrp_version, vrrp.VRRP_PRIORITY_BACKUP_DEFAULT,
            _PRIMARY_IP_ADDRESS1, self._IFNAME1, _VRID)
        assert rep1.instance_name is not None
        l[1] = rep1
        instances[_VRID] = l

        self.logger.debug('%s', vrrp_mgr._instances)

        if do_sleep:
            print("priority %s" % priority)
            print("waiting for instances starting")

            self._check(vrrp_api, instances)

        for vrid in instances.keys():
            if vrid == _VRID:
                continue
            which = vrid & 1
            new_priority = int(random.uniform(vrrp.VRRP_PRIORITY_BACKUP_MIN,
                                              vrrp.VRRP_PRIORITY_BACKUP_MAX))
            i = instances[vrid][which]
            vrrp_api.vrrp_config_change(self, i.instance_name,
                                        priority=new_priority)
            i.config.priority = new_priority

        if do_sleep:
            print("priority shuffled")

            self._check(vrrp_api, instances)

        for vrid in instances.keys():
            if vrid == _VRID:
                continue
            which = vrid & 1
            vrrp_api.vrrp_shutdown(self, instances[vrid][which].instance_name)
        vrrp_api.vrrp_shutdown(self, instances[_VRID][0].instance_name)

        if do_sleep:
            print("shutting down instances")
            while True:
                rep = vrrp_api.vrrp_list(self)
                if len(rep.instance_list) <= len(instances):
                    break
                print("left %s" % len(rep.instance_list))
                time.sleep(1)
            assert len(rep.instance_list) == len(instances)
            print("waiting for the rest becoming master")
            while True:
                rep = vrrp_api.vrrp_list(self)
                if all(i.state == vrrp_event.VRRP_STATE_MASTER
                       for i in rep.instance_list):
                    break
                time.sleep(1)

        vrrp_api.vrrp_shutdown(self, instances[_VRID][1].instance_name)
        for vrid in instances.keys():
            if vrid == _VRID:
                continue
            which = 1 - (vrid & 1)
            vrrp_api.vrrp_shutdown(self, instances[vrid][which].instance_name)

        print("waiting for instances shutting down")
        while True:
            rep = vrrp_api.vrrp_list(self)
            if not rep.instance_list:
                break
            print("left %s" % len(rep.instance_list))
            time.sleep(1)
