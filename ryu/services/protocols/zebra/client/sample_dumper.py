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
Sample Zebra Client application dumping received events.
"""

from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import zebra
from ryu.services.protocols.zebra import event
from ryu.services.protocols.zebra.client.zclient import ZClient
from ryu.services.protocols.zebra.client import event as zclient_event


class ZClientDumper(ZClient):

    @set_ev_cls(zclient_event.EventZServConnected)
    def _zserv_connected_handler(self, ev):
        self.logger.info(
            'Zebra server connected to %s: %s',
            ev.zserv.sock.getpeername(), ev.zserv.sock)

    @set_ev_cls(event.EventZebraRouterIDUpdate)
    def _router_id_update_handler(self, ev):
        self.logger.info(
            'ZEBRA_ROUTER_ID_UPDATE received: %s', ev.__dict__)

    @set_ev_cls(event.EventZebraInterfaceAdd)
    def _interface_add_handler(self, ev):
        self.logger.info(
            'ZEBRA_INTERFACE_ADD received: %s', ev.__dict__)

    @set_ev_cls(event.EventZebraInterfaceAddressAdd)
    def _interface_address_add_handler(self, ev):
        self.logger.info(
            'ZEBRA_INTERFACE_ADDRESS_ADD received: %s', ev.__dict__)

    @set_ev_cls(zclient_event.EventZServDisconnected)
    def _zserv_disconnected_handler(self, ev):
        self.logger.info(
            'Zebra server disconnected: %s', ev.zserv.sock)
