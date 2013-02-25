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


class ipv6(packet_base.PacketBase):
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
        self.length = 40

    @classmethod
    def parser(cls, buf):
        (v_tc_flow, plen, nxt, hlim, src, dst) = struct.unpack_from(
            cls._PACK_STR, buf)
        version = v_tc_flow >> 28
        traffic_class = (v_tc_flow >> 20) & 0xff
        flow_label = v_tc_flow & 0xfffff
        payload_length = plen
        hop_limit = hlim
        msg = cls(version, traffic_class, flow_label, payload_length,
                  nxt, hop_limit, src, dst)

        if msg.length > ipv6._MIN_LEN:
            msg.option = buf[ipv6._MIN_LEN:msg.length]

        return msg, ipv6.get_packet_type(nxt)

    def serialize(self, payload, prev):
        hdr = bytearray(40)
        v_tc_flow = (self.version << 28 | self.traffic_class << 20 |
                     self.flow_label << 12)
        struct.pack_into(ipv6._PACK_STR, hdr, 0, v_tc_flow,
                         self.payload_length, self.nxt, self.hop_limit,
                         self.src, self.dst)
        return hdr

ipv6.register_packet_type(icmpv6.icmpv6, inet.IPPROTO_ICMPV6)
ipv6.register_packet_type(tcp.tcp, inet.IPPROTO_TCP)
