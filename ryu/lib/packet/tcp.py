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
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, src_port, dst_port, seq, ack, offset,
                 bits, window_size, csum, urgent, option=None):
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
        self.option = option

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, seq, ack, offset, bits, window_size,
         csum, urgent) = struct.unpack_from(cls._PACK_STR, buf)
        offset = offset >> 4
        bits = bits & 0x3f
        msg = cls(src_port, dst_port, seq, ack, offset, bits,
                  window_size, csum, urgent)

        if msg.length > tcp._MIN_LEN:
            msg.option = buf[tcp._MIN_LEN:msg.length]

        return msg, None

    def serialize(self, payload, prev):
        h = bytearray(self.length)
        offset = self.offset << 4
        struct.pack_into(tcp._PACK_STR, h, 0, self.src_port, self.dst_port,
                         self.seq, self.ack, offset, self.bits,
                         self.window_size, self.csum, self.urgent)

        if self.option:
            assert (self.length - tcp._MIN_LEN) >= len(self.option)
            h[tcp._MIN_LEN:tcp._MIN_LEN + len(self.option)] = self.option

        if self.csum == 0:
            length = self.length + len(payload)
            if prev.version == 4:
                ph = struct.pack('!IIBBH', prev.src, prev.dst, 0, 6, length)
            elif prev.version == 6:
                ph = struct.pack('!16s16sBBH', prev.src, prev.dst, 0, 6,
                                 length)
            f = ph + h + payload
            if len(f) % 2:
                f += '\x00'
            self.csum = socket.htons(packet_utils.checksum(f))
            struct.pack_into('!H', h, 16, self.csum)
        return h
