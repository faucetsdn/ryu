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

import socket
import logging
logging.basicConfig(level=logging.DEBUG)

from ryu.base import app_manager

from ryu.lib import hub
from ryu.lib.hub import StreamServer
from ryu.lib.packet import bmp

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 11019


class BMPStation(app_manager.RyuApp):
    def __init__(self):
        super(BMPStation, self).__init__()
        self.name = 'bmpstation'

    def start(self):
        super(BMPStation, self).start()

        return hub.spawn(StreamServer((SERVER_HOST, SERVER_PORT),
                                      self.loop).serve_forever)

    def loop(self, sock, addr):
        logging.debug("started bmp loop.")
        is_active = True
        buf = bytearray()
        required_len = bmp.BMPMessage._HDR_LEN

        while is_active:
            ret = sock.recv(required_len)
            if len(ret) == 0:
                is_active = False
                break
            buf += ret
            while len(buf) >= required_len:
                version, len_, _ = bmp.BMPMessage.parse_header(buf)
                if version != bmp.VERSION:
                    logging.error("unsupported bmp version: %d" % version)
                    is_active = False
                    break

                required_len = len_
                if len(buf) < required_len:
                    break

                msg, rest = bmp.BMPMessage.parser(buf)
                print msg, '\n'

                buf = rest
                required_len = bmp.BMPMessage._HDR_LEN
