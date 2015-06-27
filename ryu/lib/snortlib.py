# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import logging
import six

from ryu.lib import hub, alert
from ryu.base import app_manager
from ryu.controller import event


BUFSIZE = alert.AlertPkt._ALERTPKT_SIZE
SOCKFILE = "/tmp/snort_alert"


class EventAlert(event.EventBase):
    def __init__(self, msg):
        super(EventAlert, self).__init__()
        self.msg = msg


class SnortLib(app_manager.RyuApp):

    def __init__(self):
        super(SnortLib, self).__init__()
        self.name = 'snortlib'
        self.config = {'unixsock': True}
        self._set_logger()

    def set_config(self, config):
        assert isinstance(config, dict)
        self.config = config

    def start_socket_server(self):
        if not self.config.get('unixsock'):

            if self.config.get('port') is None:
                self.config['port'] = 51234

            self._start_recv_nw_sock(self.config.get('port'))
        else:
            self._start_recv()

        self.logger.info(self.config)

    def _recv_loop(self):
        self.logger.info("Unix socket start listening...")
        while True:
            data = self.sock.recv(BUFSIZE)
            msg = alert.AlertPkt.parser(data)
            if msg:
                self.send_event_to_observers(EventAlert(msg))

    def _start_recv(self):
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        self.sock = hub.socket.socket(hub.socket.AF_UNIX,
                                      hub.socket.SOCK_DGRAM)
        self.sock.bind(SOCKFILE)
        hub.spawn(self._recv_loop)

    def _start_recv_nw_sock(self, port):

        self.nwsock = hub.socket.socket(hub.socket.AF_INET,
                                        hub.socket.SOCK_STREAM)
        self.nwsock.setsockopt(hub.socket.SOL_SOCKET,
                               hub.socket.SO_REUSEADDR, 1)
        self.nwsock.bind(('0.0.0.0', port))
        self.nwsock.listen(5)

        hub.spawn(self._accept_loop_nw_sock)

    def _accept_loop_nw_sock(self):
        self.logger.info("Network socket server start listening...")
        while True:
            conn, addr = self.nwsock.accept()
            self.logger.info("Connected with %s", addr[0])
            hub.spawn(self._recv_loop_nw_sock, conn, addr)

    def _recv_loop_nw_sock(self, conn, addr):
        buf = six.binary_type()
        while True:
            ret = conn.recv(BUFSIZE)
            if len(ret) == 0:
                self.logger.info("Disconnected from %s", addr[0])
                break

            buf += ret
            while len(buf) >= BUFSIZE:
                # self.logger.debug("Received buffer size: %d", len(buf))
                data = buf[:BUFSIZE]
                msg = alert.AlertPkt.parser(data)
                if msg:
                    self.send_event_to_observers(EventAlert(msg))
                buf = buf[BUFSIZE:]

    def _set_logger(self):
        """change log format."""
        self.logger.propagate = False
        hdl = logging.StreamHandler()
        fmt_str = '[snort][%(levelname)s] %(message)s'
        hdl.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdl)
