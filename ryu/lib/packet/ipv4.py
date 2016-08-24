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
from . import icmp
from . import igmp
from . import udp
from . import tcp
from . import sctp
from . import ospf
from . import gre
from . import in_proto as inet
from ryu.lib import addrconv


IPV4_ADDRESS_PACK_STR = '!I'
IPV4_ADDRESS_LEN = struct.calcsize(IPV4_ADDRESS_PACK_STR)
IPV4_PSEUDO_HEADER_PACK_STR = '!4s4s2xHH'


class ipv4(packet_base.PacketBase):
    """IPv4 (RFC 791) header encoder/decoder class.

    NOTE: When decoding, this implementation tries to decode the upper
    layer protocol even for a fragmented datagram.  It isn't likely
    what a user would want.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    IPv4 addresses are represented as a string like '192.0.2.1'.
    __init__ takes the corresponding args in this order.

    ============== ======================================== ==================
    Attribute      Description                              Example
    ============== ======================================== ==================
    version        Version
    header_length  IHL
    tos            Type of Service
    total_length   Total Length
                   (0 means automatically-calculate
                   when encoding)
    identification Identification
    flags          Flags
    offset         Fragment Offset
    ttl            Time to Live
    proto          Protocol
    csum           Header Checksum
                   (Ignored and automatically-calculated
                   when encoding)
    src            Source Address                           '192.0.2.1'
    dst            Destination Address                      '192.0.2.2'
    option         A bytearray which contains the entire
                   Options, or None for  no Options
    ============== ======================================== ==================
    """

    _PACK_STR = '!BBHHHBBH4s4s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = {
        'ascii': [
            'src', 'dst'
        ]
    }

    def __init__(self, version=4, header_length=5, tos=0,
                 total_length=0, identification=0, flags=0,
                 offset=0, ttl=255, proto=0, csum=0,
                 src='10.0.0.1',
                 dst='10.0.0.2',
                 option=None):
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
        self.option = option

    def __len__(self):
        return self.header_length * 4

    @classmethod
    def parser(cls, buf):
        (version, tos, total_length, identification, flags, ttl, proto, csum,
         src, dst) = struct.unpack_from(cls._PACK_STR, buf)
        header_length = version & 0xf
        version = version >> 4
        offset = flags & ((1 << 13) - 1)
        flags = flags >> 13
        length = header_length * 4
        if length > ipv4._MIN_LEN:
            option = buf[ipv4._MIN_LEN:length]
        else:
            option = None
        msg = cls(version, header_length, tos, total_length, identification,
                  flags, offset, ttl, proto, csum,
                  addrconv.ipv4.bin_to_text(src),
                  addrconv.ipv4.bin_to_text(dst), option)

        return msg, ipv4.get_packet_type(proto), buf[length:total_length]

    def serialize(self, payload, prev):
        length = len(self)
        hdr = bytearray(length)
        version = self.version << 4 | self.header_length
        flags = self.flags << 13 | self.offset
        if self.total_length == 0:
            self.total_length = self.header_length * 4 + len(payload)
        struct.pack_into(ipv4._PACK_STR, hdr, 0, version, self.tos,
                         self.total_length, self.identification, flags,
                         self.ttl, self.proto, 0,
                         addrconv.ipv4.text_to_bin(self.src),
                         addrconv.ipv4.text_to_bin(self.dst))

        if self.option:
            assert (length - ipv4._MIN_LEN) >= len(self.option)
            hdr[ipv4._MIN_LEN:ipv4._MIN_LEN + len(self.option)] = self.option

        self.csum = packet_utils.checksum(hdr)
        struct.pack_into('!H', hdr, 10, self.csum)
        return hdr

ipv4.register_packet_type(icmp.icmp, inet.IPPROTO_ICMP)
ipv4.register_packet_type(igmp.igmp, inet.IPPROTO_IGMP)
ipv4.register_packet_type(tcp.tcp, inet.IPPROTO_TCP)
ipv4.register_packet_type(udp.udp, inet.IPPROTO_UDP)
ipv4.register_packet_type(sctp.sctp, inet.IPPROTO_SCTP)
ipv4.register_packet_type(ospf.ospf, inet.IPPROTO_OSPF)
ipv4.register_packet_type(gre.gre, inet.IPPROTO_GRE)
