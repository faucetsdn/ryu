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
from . import ipv4
from ryu.ofproto import ether


class mpls(packet_base.PacketBase):
    _PACK_STR = '!I'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, label, exp, bsb, ttl):
        super(mpls, self).__init__()
        self.label = label
        self.exp = exp
        self.bsb = bsb
        self.ttl = ttl
        self.length = mpls._MIN_LEN

    @classmethod
    def parser(cls, buf):
        (label,) = struct.unpack_from(cls._PACK_STR, buf)
        ttl = label & 0xff
        bsb = (label >> 8) & 1
        exp = (label >> 9) & 7
        label = label >> 12
        msg = cls(label, exp, bsb, ttl)
        if bsb:
            return msg, ipv4.ipv4
        else:
            return msg, mpls

    def serialize(self, payload, prev):
        val = self.label << 12 | self.exp << 9 | self.bsb << 8 | self.ttl
        return struct.pack(mpls._PACK_STR, val)
