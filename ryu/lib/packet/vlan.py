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
from . import arp
from . import ipv4
from ryu.ofproto import ether
from ryu.ofproto.ofproto_parser import msg_pack_into


class vlan(packet_base.PacketBase):
    _PACK_STR = "!HH"

    def __init__(self, pcp, cfi, vid, ethertype):
        super(vlan, self).__init__()
        self.pcp = pcp
        self.cfi = cfi
        self.vid = vid
        self.ethertype = ethertype
        self.length = struct.calcsize(vlan._PACK_STR)

    @classmethod
    def parser(cls, buf):
        tci, ethertype = struct.unpack_from(cls._PACK_STR, buf)
        pcp = tci >> 15
        cfi = (tci >> 12) & 1
        vid = tci & ((1 << 12) - 1)
        return cls(pcp, cfi, vid, ethertype), vlan.get_packet_type(ethertype)

    def serialize(self, buf, offset):
        tci = self.pcp << 15 | self.cfi << 12 | self.vid
        msg_pack_into(vlan._PACK_STR, buf, offset, tci, self.ethertype)

vlan.register_packet_type(arp.arp, ether.ETH_TYPE_ARP)
vlan.register_packet_type(ipv4.ipv4, ether.ETH_TYPE_IP)
