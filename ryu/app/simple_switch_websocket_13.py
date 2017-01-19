# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

Run this application:
$ PYTHONPATH=. ./bin/ryu run --verbose ryu.app.simple_switch_websocket_13

Install and run websocket client(in other terminal):
$ pip install websocket-client
$ wsdump.py ws://127.0.0.1:8080/simpleswitch/ws
< "ethernet(dst='ff:ff:ff:ff:ff:ff',ethertype=2054,src='32:1a:51:fb:91:77'), a
rp(dst_ip='10.0.0.2',dst_mac='00:00:00:00:00:00',hlen=6,hwtype=1,opcode=1,plen
=4,proto=2048,src_ip='10.0.0.1',src_mac='32:1a:51:fb:91:77')"
< "ethernet(dst='32:1a:51:fb:91:77',ethertype=2054,src='26:8c:15:0c:de:49'), a
rp(dst_ip='10.0.0.1',dst_mac='32:1a:51:fb:91:77',hlen=6,hwtype=1,opcode=2,plen
=4,proto=2048,src_ip='10.0.0.2',src_mac='26:8c:15:0c:de:49')"
< "ethernet(dst='26:8c:15:0c:de:49',ethertype=2048,src='32:1a:51:fb:91:77'), i
pv4(csum=9895,dst='10.0.0.2',flags=2,header_length=5,identification=0,offset=0
,option=None,proto=1,src='10.0.0.1',tos=0,total_length=84,ttl=64,version=4), i
cmp(code=0,csum=43748,data=echo(data='`\\xb9uS\\x00\\x00\\x00\\x00\\x7f\\'\\x0
1\\x00\\x00\\x00\\x00\\x00\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\
x1a\\x1b\\x1c\\x1d\\x1e\\x1f !\"#$%&\\'()*+,-./01234567',id=14355,seq=1),type=
8)"

Get arp table:
> {"jsonrpc": "2.0", "id": 1, "method": "get_arp_table", "params" : {}}
< {"jsonrpc": "2.0", "id": 1, "result": {"1": {"32:1a:51:fb:91:77": 1, "26:8c:
15:0c:de:49": 2}}}
"""

from ryu.app import simple_switch_13
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import rpc_public
from ryu.app.wsgi import websocket
from ryu.app.wsgi import WebSocketRPCServer
from ryu.app.wsgi import WSGIApplication
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet


simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/ws'


class SimpleSwitchWebSocket13(simple_switch_13.SimpleSwitch13):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchWebSocket13, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(
            SimpleSwitchWebSocketController,
            data={simple_switch_instance_name: self},
        )
        self._ws_manager = wsgi.websocketmanager

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def _packet_in_handler(self, ev):
        super(SimpleSwitchWebSocket13, self)._packet_in_handler(ev)

        pkt = packet.Packet(ev.msg.data)
        self._ws_manager.broadcast(str(pkt))

    @rpc_public
    def get_arp_table(self):
        return self.mac_to_port


class SimpleSwitchWebSocketController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SimpleSwitchWebSocketController, self).__init__(
            req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]

    @websocket('simpleswitch', url)
    def _websocket_handler(self, ws):
        simple_switch = self.simple_switch_app
        simple_switch.logger.debug('WebSocket connected: %s', ws)
        rpc_server = WebSocketRPCServer(ws, simple_switch)
        rpc_server.serve_forever()
        simple_switch.logger.debug('WebSocket disconnected: %s', ws)
