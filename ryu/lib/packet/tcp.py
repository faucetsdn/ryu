# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

import struct
import socket
from . import packet_base
from . import packet_utils
import ipv4


class tcp(packet_base.PacketBase):
    _PACK_STR = '!HHIIBBHHH'

    def __init__(self, src_port, dst_port, seq, ack, offset,
                 bits, window_size, csum, urgent):
        super(tcp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.offset = offset
        self.bits = bits
        self.window_size = window_size
        self.csum = csum
        self.urgent = urgent
        self.length = self.offset * 4

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, seq, ack, offset, bits, window_size,
         csum, urgent) = struct.unpack_from(cls._PACK_STR, buf)
        offset = offset >> 4
        bits = bits & 0x3f
        msg = cls(src_port, dst_port, seq, ack, offset, bits,
                  window_size, csum, urgent)
        return msg, None

    def serialize(self, payload, prev):
        offset = self.offset << 4
        h = struct.pack(tcp._PACK_STR, self.src_port, self.dst_port,
                        self.seq, self.ack, offset, self.bits,
                        self.window_size, self.csum, self.urgent)
        if self.csum == 0:
            length = self.length + len(payload)
            ph = struct.pack('!IIBBH', prev.src, prev.dst, 0, 6, length)
            f = ph + h + payload
            if len(f) % 2:
                f += '\0'
            self.csum = socket.htons(packet_utils.checksum(f))
            h = struct.pack(tcp._PACK_STR, self.src_port, self.dst_port,
                            self.seq, self.ack, offset, self.bits,
                            self.window_size, self.csum, self.urgent)
        return h
