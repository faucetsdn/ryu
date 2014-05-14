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
"""

import json
from webob import Response

from ryu.app import simple_switch_13
from ryu.app.wsgi import route, ControllerBase, WSGIApplication
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet


simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/ws'


class SimpleSwitchWebSocket13(simple_switch_13.SimpleSwitch13):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchWebSocket13, self).__init__(*args, **kwargs)

        self.ws_send_queue = hub.Queue()
        self.ws_lock = hub.BoundedSemaphore()

        wsgi = kwargs['wsgi']
        wsgi.register(
            SimpleSwitchWebSocketController,
            data={simple_switch_instance_name: self},
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def _packet_in_handler(self, ev):
        super(SimpleSwitchWebSocket13, self)._packet_in_handler(ev)

        pkt = packet.Packet(ev.msg.data)
        self.ws_send_queue.put(str(pkt))


class SimpleSwitchWebSocketController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SimpleSwitchWebSocketController, self).__init__(
            req, link, data, **config)
        self.simpl_switch_spp = data[simple_switch_instance_name]

    def _websocket_handler(self, ws):
        simple_switch = self.simpl_switch_spp
        simple_switch.logger.debug('WebSocket connected: %s', ws)
        while True:
            data = simple_switch.ws_send_queue.get()
            ws.send(unicode(json.dumps(data)))

    @route('simpleswitch', url)
    def websocket(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        if simple_switch.ws_lock.acquire(blocking=False):
            try:
                self.websocket_handshake(req, self._websocket_handler)
                return
            finally:
                simple_switch.logger.debug('WebSocket disconnected')
                simple_switch.ws_lock.release()
        else:
            return Response(status=503)
