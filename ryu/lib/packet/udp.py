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


class udp(packet_base.PacketBase):
    """UDP (RFC 768) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    src_port       Source Port
    dst_port       Destination Port
    total_length   Length \
                   (0 means automatically-calculate when encoding)
    csum           Checksum \
                   (0 means automatically-calculate when encoding)
    ============== ====================
    """

    _PACK_STR = '!HHHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, src_port=0, dst_port=0, total_length=0, csum=0):
        super(udp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.total_length = total_length
        self.csum = csum

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, total_length, csum) = struct.unpack_from(
            cls._PACK_STR, buf)
        msg = cls(src_port, dst_port, total_length, csum)
        return msg, None, buf[msg._MIN_LEN:total_length]

    def serialize(self, payload, prev):
        if self.total_length == 0:
            self.total_length = udp._MIN_LEN + len(payload)
        h = struct.pack(udp._PACK_STR, self.src_port, self.dst_port,
                        self.total_length, self.csum)
        if self.csum == 0:
            self.csum = packet_utils.checksum_ip(
                prev, self.total_length, h + payload)
            h = struct.pack(udp._PACK_STR, self.src_port, self.dst_port,
                            self.total_length, self.csum)
        return h
