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
sample router manager.
(un-)instantiate routers
Usage example:
PYTHONPATH=. ./bin/ryu-manager --verbose \
             ryu.services.protocols.vrrp.manager \
             ryu.services.protocols.vrrp.dumper \
             ryu.services.protocols.vrrp.sample_manager
"""

from ryu.base import app_manager
from ryu.controller import handler
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import sample_router


class RouterManager(app_manager.RyuApp):
    _ROUTER_CLASSES = {
        vrrp_event.VRRPInterfaceNetworkDevice: {
            4: sample_router.RouterIPV4Linux,
            6: sample_router.RouterIPV6Linux,
        },
        vrrp_event.VRRPInterfaceOpenFlow: {
            4: sample_router.RouterIPV4OpenFlow,
            6: sample_router.RouterIPV6OpenFlow,
        },
    }

    def __init__(self, *args, **kwargs):
        super(RouterManager, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs
        self.routers = {}  # instance name -> router name

    def _router_factory(self, instance_name, monitor_name, interface, config):
        cls = None
        for interface_cls, router_clses in self._ROUTER_CLASSES.items():
            if isinstance(interface, interface_cls):
                if config.is_ipv6:
                    cls = router_clses[6]
                else:
                    cls = router_clses[4]
                break

        self.logger.debug('interface %s %s', type(interface), interface)
        self.logger.debug('cls %s', cls)
        if cls is None:
            raise ValueError('Unknown interface type %s %s' % (type(interface),
                                                               interface))
        kwargs = self._kwargs.copy()
        kwargs.update({
            'name': instance_name,
            'monitor_name': monitor_name,
            'config': config,
            'interface': interface,
        })
        app_mgr = app_manager.AppManager.get_instance()
        return app_mgr.instantiate(cls, *self._args, **kwargs)

    @handler.set_ev_cls(vrrp_event.EventVRRPStateChanged)
    def vrrp_state_changed_handler(self, ev):
        if ev.new_state == vrrp_event.VRRP_STATE_INITIALIZE:
            if ev.old_state:
                self._shutdown(ev)
            else:
                self._initialize(ev)
            return

        router_name = self.routers.get(ev.instance_name)
        self.send_event(router_name, ev)

    def _initialize(self, ev):
        router = self._router_factory(ev.instance_name, ev.monitor_name,
                                      ev.interface, ev.config)
        self.routers[ev.instance_name] = router.name
        self.send_event(router.name, ev)
        router.start()

    def _shutdown(self, ev):
        router_name = self.routers.pop(ev.instance_name)
        self.send_event(router_name, ev)
        app_mgr = app_manager.AppManager.get_instance()
        app_mgr.uninstantiate(router_name)
