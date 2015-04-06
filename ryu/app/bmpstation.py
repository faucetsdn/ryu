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

import os
import socket
import time

from ryu.base import app_manager

from ryu.lib import hub
from ryu.lib.hub import StreamServer
from ryu.lib.packet import bmp


class BMPStation(app_manager.RyuApp):
    def __init__(self):
        super(BMPStation, self).__init__()
        self.name = 'bmpstation'
        self.server_host = os.environ.get('RYU_BMP_SERVER_HOST', '0.0.0.0')
        self.server_port = int(os.environ.get('RYU_BMP_SERVER_PORT', 11019))
        output_file = os.environ.get('RYU_BMP_OUTPUT_FILE', 'ryu_bmp.log')
        failed_dump = os.environ.get('RYU_BMP_FAILED_DUMP',
                                     'ryu_bmp_failed.dump')

        self.output_fd = open(output_file, 'w')
        self.failed_dump_fd = open(failed_dump, 'w')

        self.failed_pkt_count = 0

    def start(self):
        super(BMPStation, self).start()
        self.logger.debug("listening on %s:%s", self.server_host,
                          self.server_port)

        return hub.spawn(StreamServer((self.server_host, self.server_port),
                                      self.loop).serve_forever)

    def loop(self, sock, addr):
        self.logger.debug("BMP client connected, ip=%s, port=%s", addr[0],
                          addr[1])
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
                    self.logger.error("unsupported bmp version: %d", version)
                    is_active = False
                    break

                required_len = len_
                if len(buf) < required_len:
                    break

                try:
                    msg, rest = bmp.BMPMessage.parser(buf)
                except Exception as e:
                    pkt = buf[:len_]
                    self.failed_dump_fd.write(pkt)
                    self.failed_dump_fd.flush()
                    buf = buf[len_:]
                    self.failed_pkt_count += 1
                    self.logger.error("failed to parse: %s"
                                      " (total fail count: %d)",
                                      e, self.failed_pkt_count)
                else:
                    t = time.strftime("%Y %b %d %H:%M:%S", time.localtime())
                    self.logger.debug("%s | %s | %s\n", t, addr[0], msg)
                    self.output_fd.write("%s | %s | %s\n\n" % (t, addr[0],
                                                               msg))
                    self.output_fd.flush()
                    buf = rest

                required_len = bmp.BMPMessage._HDR_LEN

        self.logger.debug("BMP client disconnected, ip=%s, port=%s", addr[0],
                          addr[1])

        sock.close()
