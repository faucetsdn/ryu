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


class udp(packet_base.PacketBase):
    _PACK_STR = '!HHHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, src_port, dst_port, total_length=0, csum=0):
        super(udp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.total_length = total_length
        self.csum = csum
        self.length = udp._MIN_LEN

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, total_length, csum) = struct.unpack_from(
            cls._PACK_STR, buf)
        msg = cls(src_port, dst_port, total_length, csum)
        return msg, None

    def serialize(self, payload, prev):
        if self.total_length == 0:
            self.total_length = udp._MIN_LEN + len(payload)
        h = struct.pack(udp._PACK_STR, self.src_port, self.dst_port,
                        self.total_length, self.csum)
        if self.csum == 0:
            ph = struct.pack('!IIBBH', prev.src, prev.dst, 0, 17,
                             self.total_length)
            f = ph + h + payload
            if len(f) % 2:
                f += '\x00'
            self.csum = socket.htons(packet_utils.checksum(f))
            h = struct.pack(udp._PACK_STR, self.src_port, self.dst_port,
                            self.total_length, self.csum)
        return h
