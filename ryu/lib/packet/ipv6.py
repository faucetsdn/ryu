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
from . import icmpv6
from . import tcp
from ryu.ofproto import inet
from ryu.lib import addrconv


IPV6_ADDRESS_PACK_STR = '!16s'
IPV6_ADDRESS_LEN = struct.calcsize(IPV6_ADDRESS_PACK_STR)
IPV6_PSEUDO_HEADER_PACK_STR = '!16s16s3xB'


class ipv6(packet_base.PacketBase):
    """IPv6 (RFC 2460) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    IPv6 addresses are represented as a string like 'ff02::1'.
    __init__ takes the correspondig args in this order.

    ============== ======================================== ==================
    Attribute      Description                              Example
    ============== ======================================== ==================
    version        Version
    traffic_class  Traffic Class
    flow_label     When decoding, Flow Label.
                   When encoding, the most significant 8
                   bits of Flow Label.
    payload_length Payload Length
    nxt            Next Header
    hop_limit      Hop Limit
    src            Source Address                           'ff02::1'
    dst            Destination Address                      '::'
    ============== ======================================== ==================
    """

    _PACK_STR = '!IHBB16s16s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, version, traffic_class, flow_label, payload_length,
                 nxt, hop_limit, src, dst):
        super(ipv6, self).__init__()
        self.version = version
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.payload_length = payload_length
        self.nxt = nxt
        self.hop_limit = hop_limit
        self.src = src
        self.dst = dst

    @classmethod
    def parser(cls, buf):
        (v_tc_flow, payload_length, nxt, hlim, src, dst) = struct.unpack_from(
            cls._PACK_STR, buf)
        version = v_tc_flow >> 28
        traffic_class = (v_tc_flow >> 20) & 0xff
        flow_label = v_tc_flow & 0xfffff
        hop_limit = hlim
        msg = cls(version, traffic_class, flow_label, payload_length,
                  nxt, hop_limit, addrconv.ipv6.bin_to_text(src),
                  addrconv.ipv6.bin_to_text(dst))
        return (msg, ipv6.get_packet_type(nxt),
                buf[cls._MIN_LEN:cls._MIN_LEN+payload_length])

    def serialize(self, payload, prev):
        hdr = bytearray(40)
        v_tc_flow = (self.version << 28 | self.traffic_class << 20 |
                     self.flow_label << 12)
        struct.pack_into(ipv6._PACK_STR, hdr, 0, v_tc_flow,
                         self.payload_length, self.nxt, self.hop_limit,
                         addrconv.ipv6.text_to_bin(self.src),
                         addrconv.ipv6.text_to_bin(self.dst))
        return hdr

ipv6.register_packet_type(icmpv6.icmpv6, inet.IPPROTO_ICMPV6)
ipv6.register_packet_type(tcp.tcp, inet.IPPROTO_TCP)
