# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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
VRRP manager that manages VRRP router instances
VRRPManager creates/deletes VRRPRouter, VRRPInterfaceMonitor
dynamically as requested.

Usage example
PYTHONPATH=. ./bin/ryu-manager --verbose \
             ryu.services.protocols.vrrp.manager \
             ryu.services.protocols.vrrp.dumper
"""

import time

from ryu.base import app_manager
from ryu.controller import handler
from ryu.lib import hub
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import monitor as vrrp_monitor
from ryu.services.protocols.vrrp import router as vrrp_router


class VRRPInstance(object):
    def __init__(self, name, monitor_name, config, interface):
        super(VRRPInstance, self).__init__()
        self.name = name                        # vrrp_router.name
        self.monitor_name = monitor_name        # interface_monitor.name
        self.config = config
        self.interface = interface
        self.state = None

    def state_changed(self, new_state):
        self.state = new_state


class VRRPManager(app_manager.RyuApp):
    @staticmethod
    def _instance_name(interface, vrid, is_ipv6):
        ip_version = 'ipv6' if is_ipv6 else 'ipv4'
        return 'VRRP-Router-%s-%d-%s' % (str(interface), vrid, ip_version)

    def __init__(self, *args, **kwargs):
        super(VRRPManager, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs
        self.name = vrrp_event.VRRP_MANAGER_NAME
        self._instances = {}    # name -> VRRPInstance
        self.shutdown = hub.Queue()

    def start(self):
        t = hub.spawn(self._shutdown_loop)
        super(VRRPManager, self).start()
        return t

    @handler.set_ev_cls(vrrp_event.EventVRRPConfigRequest)
    def config_request_handler(self, ev):
        config = ev.config
        interface = ev.interface
        name = self._instance_name(interface, config.vrid, config.is_ipv6)
        if name in self._instances:
            rep = vrrp_event.EventVRRPConfigReply(None, interface, config)
            self.reply_to_request(ev, rep)
            return

        statistics = VRRPStatistics(name, config.resource_id,
                                    config.statistics_interval)
        monitor = vrrp_monitor.VRRPInterfaceMonitor.factory(
            interface, config, name, statistics, *self._args, **self._kwargs)
        router = vrrp_router.VRRPRouter.factory(name, monitor.name, interface,
                                                config, statistics,
                                                *self._args, **self._kwargs)
        # Event piping
        #  vrrp_router -> vrrp_manager
        #    EventVRRPStateChanged to vrrp_manager is handled by framework
        #  vrrp_manager -> vrrp_rouer
        self.register_observer(vrrp_event.EventVRRPShutdownRequest,
                               router.name)
        #  vrrp_router -> vrrp_monitor
        router.register_observer(vrrp_event.EventVRRPStateChanged,
                                 monitor.name)
        router.register_observer(vrrp_event.EventVRRPTransmitRequest,
                                 monitor.name)
        #  vrrp_interface_monitor -> vrrp_router
        monitor.register_observer(vrrp_event.EventVRRPReceived, router.name)

        instance = VRRPInstance(name, monitor.name, config, interface)
        self._instances[name] = instance
        # self.logger.debug('report_bricks')
        # app_manager.AppManager.get_instance().report_bricks()   # debug
        monitor.start()
        router.start()

        rep = vrrp_event.EventVRRPConfigReply(instance.name, interface, config)
        self.reply_to_request(ev, rep)

    def _proxy_event(self, ev):
        name = ev.instance_name
        instance = self._instances.get(name, None)
        if not instance:
            self.logger.info('unknown vrrp router %s', name)
            return
        self.send_event(instance.name, ev)

    @handler.set_ev_cls(vrrp_event.EventVRRPShutdownRequest)
    def shutdown_request_handler(self, ev):
        self._proxy_event(ev)

    @handler.set_ev_cls(vrrp_event.EventVRRPConfigChangeRequest)
    def config_change_request_handler(self, ev):
        self._proxy_event(ev)

    @handler.set_ev_cls(vrrp_event.EventVRRPStateChanged)
    def state_change_handler(self, ev):
        instance = self._instances.get(ev.instance_name, None)
        assert instance is not None
        instance.state_changed(ev.new_state)
        if ev.old_state and ev.new_state == vrrp_event.VRRP_STATE_INITIALIZE:
            self.shutdown.put(instance)

    def _shutdown_loop(self):
        app_mgr = app_manager.AppManager.get_instance()
        while self.is_active or not self.shutdown.empty():
            instance = self.shutdown.get()
            app_mgr.uninstantiate(instance.name)
            app_mgr.uninstantiate(instance.monitor_name)
            del self._instances[instance.name]

    @handler.set_ev_cls(vrrp_event.EventVRRPListRequest)
    def list_request_handler(self, ev):
        instance_name = ev.instance_name
        if instance_name is None:
            instance_list = [vrrp_event.VRRPInstance(
                instance.name, instance.monitor_name,
                instance.config, instance.interface, instance.state)
                for instance in self._instances.values()]
        else:
            instance = self._instances.get(instance_name, None)
            if instance is None:
                instance_list = []
            else:
                instance_list = [vrrp_event.VRRPInstance(
                    instance_name, instance.monitor_name,
                    instance.config, instance.interface, instance.state)]

        vrrp_list = vrrp_event.EventVRRPListReply(instance_list)
        self.reply_to_request(ev, vrrp_list)


class VRRPStatistics(object):
    def __init__(self, name, resource_id, statistics_interval):
        self.name = name
        self.resource_id = resource_id
        self.statistics_interval = statistics_interval
        self.tx_vrrp_packets = 0
        self.rx_vrrp_packets = 0
        self.rx_vrrp_zero_prio_packets = 0
        self.tx_vrrp_zero_prio_packets = 0
        self.rx_vrrp_invalid_packets = 0
        self.rx_vrrp_bad_auth = 0
        self.idle_to_master_transitions = 0
        self.idle_to_backup_transitions = 0
        self.backup_to_master_transitions = 0
        self.master_to_backup_transitions = 0

    def get_stats(self):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        stats_dict = dict(
            timestamp=ts,
            resource_id=self.resource_id,
            tx_vrrp_packets=self.tx_vrrp_packets,
            rx_vrrp_packets=self.rx_vrrp_packets,
            rx_vrrp_zero_prio_packets=self.rx_vrrp_zero_prio_packets,
            tx_vrrp_zero_prio_packets=self.tx_vrrp_zero_prio_packets,
            rx_vrrp_invalid_packets=self.rx_vrrp_invalid_packets,
            rx_vrrp_bad_auth=self.rx_vrrp_bad_auth,
            idle_to_master_transitions=self.idle_to_master_transitions,
            idle_to_backup_transitions=self.idle_to_backup_transitions,
            backup_to_master_transitions=self.backup_to_master_transitions,
            master_to_backup_transitions=self.master_to_backup_transitions
        )
        return stats_dict
