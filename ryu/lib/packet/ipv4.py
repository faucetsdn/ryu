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
from . import packet_utils
from . import udp
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

    def serialize(self, payload, prev):
        hdr = bytearray().zfill(self.header_length * 4)
        version = self.version << 4 | self.header_length
        flags = self.flags << 15 | self.offset
        if self.total_length == 0:
            self.total_length = self.header_length * 4 + len(payload)
        struct.pack_into(ipv4._PACK_STR, hdr, 0, version, self.tos,
                         self.total_length, self.identification, flags,
                         self.ttl, self.proto, 0, self.src, self.dst)
        self.csum = packet_utils.checksum(hdr)
        struct.pack_into('H', hdr, 10, self.csum)
        return hdr

ipv4.register_packet_type(udp.udp, inet.IPPROTO_UDP)
