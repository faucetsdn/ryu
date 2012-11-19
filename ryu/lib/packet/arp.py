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

ARP_HW_TYPE_ETHERNET = 1  # ethernet hardware type

# arp operation codes
ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REV_REQUEST = 3
ARP_REV_REPLY = 4


class arp(packet_base.PacketBase):
    _PACK_STR = '!HHBBH6sI6sI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, hwtype, proto, hlen, plen, opcode,
                 src_mac, src_ip, dst_mac, dst_ip):
        super(arp, self).__init__()
        self.hwtype = hwtype
        self.proto = proto
        self.hlen = hlen
        self.plen = plen
        self.opcode = opcode
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.dst_ip = dst_ip
        self.length = arp._MIN_LEN

    @classmethod
    def parser(cls, buf):
        (hwtype, proto, hlen, plen, opcode, src_mac, src_ip,
         dst_mac, dst_ip) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(hwtype, proto, hlen, plen, opcode, src_mac, src_ip,
                   dst_mac, dst_ip), None

    def serialize(self, payload, prev):
        return struct.pack(arp._PACK_STR, self.hwtype, self.proto,
                           self.hlen, self.plen, self.opcode,
                           self.src_mac, self.src_ip, self.dst_mac,
                           self.dst_ip)
