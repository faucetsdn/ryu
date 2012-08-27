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
from . import packet_base


class udp(packet_base.PacketBase):
    _PACK_STR = '!HHHH'

    def __init__(self, src_port, dst_port, length, csum=0, data=None):
        super(udp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.csum = csum
        self.data = data

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, length, csum) = struct.unpack_from(cls._PACK_STR,
                                                                buf)
        msg = cls(src_port, dst_port, length, csum)
        if length > struct.calcsize(cls._PACK_STR):
            msg.data = buf[struct.calcsize(cls._PACK_STR):length]

        return msg, None

    def serialize(self, payload, prev):
        return struct.pack(udp._PACK_STR, self.src_port, self.dst_port,
                           self.length, self.csum)
