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
from . import udp
from ryu.ofproto.ofproto_parser import msg_pack_into
from ryu.ofproto import inet

class ipv4(packet_base.PacketBase):
    _PACK_STR = '!BBHHHBBHII'

    def __init__(self, version, header_length, tos, total_length,
                 identification, flags, offset, ttl, proto, csum,
                 src, dst):
        super(ipv4, self).__init__()
        self.version = version
        self.header_length = header_length
        self.tos = tos
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.offset = offset
        self.ttl = ttl
        self.proto = proto
        self.csum = csum
        self.src = src
        self.dst = dst
        self.length = header_length * 4

    @classmethod
    def parser(cls, buf):
        (version, tos, total_length, identification, flags, ttl, proto, csum,
         src, dst) = struct.unpack_from(cls._PACK_STR, buf)
        header_length = version & 0xf
        version = version >> 4
        offset = flags & ((1 << 15) - 1)
        flags = flags >> 15
        msg = cls(version, header_length, tos, total_length, identification,
                  flags, offset, ttl, proto, csum, src, dst)

        if msg.length > struct.calcsize(ipv4._PACK_STR):
            self.extra = buf[struct.calcsize(ipv4._PACK_STR):msg.length]

        return msg, ipv4.get_packet_type(proto)

    @staticmethod
    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    def checksum(self, data):
        s = 0
        for i in range(0, len(data), 2):
            w = data[i] + (data[i+1] << 8)
            s = self.carry_around_add(s, w)
        return ~s & 0xffff

    def serialize(self, buf, offset):
        version = self.version << 4 | self.header_length
        flags = self.flags << 15 | self.offset
        msg_pack_into(ipv4._PACK_STR, buf, offset, version, self.tos,
                      self.total_length, self.identification, flags,
                      self.ttl, self.proto, 0, self.src, self.dst)
        self.csum = self.checksum(buf[offset:offset+self.length])
        msg_pack_into('H', buf, offset + 10, self.csum)

ipv4.register_packet_type(udp.udp, inet.IPPROTO_UDP)
