# Copyright (C) 2014 Stratosphere Inc.
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
Usage example

1. Run this application:
$ ryu-manager --verbose --observe-links ryu.app.ws_topology

2. Connect to this application by WebSocket (use your favorite client):
$ wscat -c ws://localhost:8080/v1.0/topology/ws

3. Join switches (use your favorite method):
$ sudo mn --controller=remote --topo linear,2

4. Topology change is notified:
< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_enter", "id": 1}
> {"id": 1, "jsonrpc": "2.0", "result": ""}

< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_leave", "id": 2}
> {"id": 2, "jsonrpc": "2.0", "result": ""}
...
"""  # noqa

from socket import error as SocketError
from tinyrpc.exc import InvalidReplyError


from ryu.app.wsgi import (
    ControllerBase,
    WSGIApplication,
    websocket,
    WebSocketRPCClient
)
from ryu.base import app_manager
from ryu.topology import event, switches
from ryu.controller.handler import set_ev_cls


class WebSocketTopology(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'switches': switches.Switches,
    }

    def __init__(self, *args, **kwargs):
        super(WebSocketTopology, self).__init__(*args, **kwargs)

        self.rpc_clients = []

        wsgi = kwargs['wsgi']
        wsgi.register(WebSocketTopologyController, {'app': self})

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        msg = ev.switch.to_dict()
        self._rpc_broadcall('event_switch_enter', msg)

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        msg = ev.switch.to_dict()
        self._rpc_broadcall('event_switch_leave', msg)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        msg = ev.link.to_dict()
        self._rpc_broadcall('event_link_add', msg)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        msg = ev.link.to_dict()
        self._rpc_broadcall('event_link_delete', msg)

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        msg = ev.host.to_dict()
        self._rpc_broadcall('event_host_add', msg)

    def _rpc_broadcall(self, func_name, msg):
        disconnected_clients = []
        for rpc_client in self.rpc_clients:
            # NOTE: Although broadcasting is desired,
            #       RPCClient#get_proxy(one_way=True) does not work well
            rpc_server = rpc_client.get_proxy()
            try:
                getattr(rpc_server, func_name)(msg)
            except SocketError:
                self.logger.debug('WebSocket disconnected: %s', rpc_client.ws)
                disconnected_clients.append(rpc_client)
            except InvalidReplyError as e:
                self.logger.error(e)

        for client in disconnected_clients:
            self.rpc_clients.remove(client)


class WebSocketTopologyController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(WebSocketTopologyController, self).__init__(
            req, link, data, **config)
        self.app = data['app']

    @websocket('topology', '/v1.0/topology/ws')
    def _websocket_handler(self, ws):
        rpc_client = WebSocketRPCClient(ws)
        self.app.rpc_clients.append(rpc_client)
        rpc_client.serve_forever()
