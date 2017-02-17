# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
Sample Zebra Server application dumping received events.
"""

from ryu.base.app_manager import RyuApp
from ryu.controller.handler import set_ev_cls
from ryu.services.protocols.zebra import event
from ryu.services.protocols.zebra.server.zserver import ZServer
from ryu.services.protocols.zebra.server import event as zserver_event


class ZServerDumper(RyuApp):
    _CONTEXTS = {
        "zserver": ZServer,
    }

    def __init__(self, *args, **kwargs):
        super(ZServerDumper, self).__init__(*args, **kwargs)
        self.zserver = kwargs["zserver"]

    @set_ev_cls(zserver_event.EventZClientConnected)
    def _zclient_connected_handler(self, ev):
        self.logger.info('Zebra client connected: %s', ev.zclient.addr)

    @set_ev_cls(zserver_event.EventZClientDisconnected)
    def _zclient_disconnected_handler(self, ev):
        self.logger.info('Zebra client disconnected: %s', ev.zclient.addr)

    @set_ev_cls([event.EventZebraIPv4RouteAdd,
                 event.EventZebraIPv6RouteAdd])
    def _ip_route_add_handler(self, ev):
        self.logger.info(
            'Client %s advertised IP route: %s', ev.zclient.addr, ev.body)

    @set_ev_cls([event.EventZebraIPv4RouteDelete,
                 event.EventZebraIPv6RouteDelete])
    def _ip_route_delete_handler(self, ev):
        self.logger.info(
            'Client %s withdrew IP route: %s', ev.zclient.addr, ev.body)
