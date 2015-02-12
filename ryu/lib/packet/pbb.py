# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
from ryu.lib.packet import packet_base


class itag(packet_base.PacketBase):
    """I-TAG (IEEE 802.1ah-2008) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    pcp            Priority Code Point
    dei            Drop Eligible Indication
    uca            Use Customer Address
    sid            Service Instance ID
    ============== ====================
    """

    _PACK_STR = "!I"
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, pcp=0, dei=0, uca=0, sid=0):
        super(itag, self).__init__()
        self.pcp = pcp
        self.dei = dei
        self.uca = uca
        self.sid = sid

    @classmethod
    def parser(cls, buf):
        (data, ) = struct.unpack_from(cls._PACK_STR, buf)
        pcp = data >> 29
        dei = data >> 28 & 1
        uca = data >> 27 & 1
        sid = data & 0x00ffffff
        # circular import: ethernet -> vlan -> pbb
        from ryu.lib.packet import ethernet
        return (cls(pcp, dei, uca, sid), ethernet.ethernet,
                buf[cls._MIN_LEN:])

    def serialize(self, payload, prev):
        data = self.pcp << 29 | self.dei << 28 | self.uca << 27 | self.sid
        return struct.pack(self._PACK_STR, data)
