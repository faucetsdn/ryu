# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import logging
import json

import view_base
from models.topology import TopologyWatcher

LOG = logging.getLogger('ryu.gui')


class WebsocketView(view_base.ViewBase):
    def __init__(self, ws):
        super(WebsocketView, self).__init__()
        self.ws = ws
        self.address = None
        self.watcher = None

    def run(self):
        while True:
            msg = self.ws.receive()
            if msg is not None:
                try:
                    msg = json.loads(msg)
                except:
                    LOG.debug("json parse error: %s", msg)
                    continue
                self._recv_message(msg)
            else:
                if self.watcher:
                    self.watcher.stop()
                break

        self.ws.close()
        LOG.info('Websocket: closed.')
        return self.null_response()

    def _send_message(self, msg_name, address, body=None):
        message = {}
        message['message'] = msg_name
        message['host'], message['port'] = address.split(':')
        message['body'] = body
        LOG.debug("Websocket: send msg.\n%s", json.dumps(message, indent=2))
        self.ws.send(json.dumps(message))

    def _recv_message(self, msg):
        LOG.debug('Websocket: recv msg.\n%s', json.dumps(msg, indent=2))

        message = msg.get('message')
        body = msg.get('body')

        if message == 'rest_update':
            self._watcher_start(body)
        elif message == 'watching_switch_update':
            self._watching_switch_update(body)
        else:
            return

    def _watcher_start(self, body):
        address = '%s:%s' % (body['host'], body['port'])
        self.address = address
        if self.watcher:
            self.watcher.stop()

        self.watcher = TopologyWatcher(
            update_handler=self.update_handler,
            rest_error_handler=self.rest_error_handler)
        self.watcher.start(address)

    def _watching_switch_update(self, body):
        pass

    # called by watcher when topology update
    def update_handler(self, address, delta):
        if self.address != address:
            # user be watching the another controller already
            return

        LOG.debug(delta)
        self._send_message('rest_connected', address)
        self._send_del_links(address, delta.deleted)
        self._send_del_ports(address, delta.deleted)
        self._send_del_switches(address, delta.deleted)
        self._send_add_switches(address, delta.added)
        self._send_add_ports(address, delta.added)
        self._send_add_links(address, delta.added)

    def _send_add_switches(self, address, topo):
        body = self._build_switches_message(topo)
        if body:
            self._send_message('add_switches', address, body)

    def _send_del_switches(self, address, topo):
        body = self._build_switches_message(topo)
        if body:
            self._send_message('del_switches', address, body)

    def _build_switches_message(self, topo):
        body = []
        for s in topo['switches']:
            S = {'dpid': s.dpid, 'ports': {}}
            for p in s.ports:
                S['ports'][p.port_no] = p.to_dict()

            body.append(S)

        return body

    def _send_add_ports(self, address, topo):
        body = self._build_ports_message(topo)
        if body:
            self._send_message('add_ports', address, body)

    def _send_del_ports(self, address, topo):
        body = self._build_ports_message(topo)
        if body:
            self._send_message('del_ports', address, body)

    def _build_ports_message(self, topo):
        # send only except new added switches
        ports = set(topo['ports'])
        for s in topo['switches']:
            ports -= set(s.ports)

        body = []
        for p in ports:
            body.append(p.to_dict())

        return body

    def _send_add_links(self, address, topo):
        body = self._build_links_message(topo)
        if body:
            self._send_message('add_links', address, body)

    def _send_del_links(self, address, topo):
        body = self._build_links_message(topo)
        if body:
            self._send_message('del_links', address, body)

    def _build_links_message(self, topo):
        body = []
        for link in topo['links']:
            # handle link as undirected
            if link.src.dpid > link.dst.dpid:
                continue

            p1 = link.src.to_dict()
            p2 = link.dst.to_dict()
            L = {'p1': p1.copy(), 'p2': p2.copy()}
            L['p1']['peer'] = p2.copy()
            L['p2']['peer'] = p1.copy()

            body.append(L)

        return body

    # called by watcher when rest api error
    def rest_error_handler(self, address, e):
        LOG.debug('REST API Error: %s', e)
        self._send_message('rest_disconnected', address)
