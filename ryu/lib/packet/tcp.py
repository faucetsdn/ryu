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


class tcp(packet_base.PacketBase):
    """TCP (RFC 793) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    src_port       Source Port
    dst_port       Destination Port
    seq            Sequence Number
    ack            Acknowledgement Number
    offset         Data Offset \
                   (0 means automatically-calculate when encoding)
    bits           Control Bits
    window_size    Window
    csum           Checksum \
                   (0 means automatically-calculate when encoding)
    urgent         Urgent Pointer
    option         An bytearray containing Options and following Padding. \
                   None if no options.
    ============== ====================
    """

    _PACK_STR = '!HHIIBBHHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, src_port=0, dst_port=0, seq=0, ack=0, offset=0,
                 bits=0, window_size=0, csum=0, urgent=0, option=None):
        super(tcp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.offset = offset
        self.bits = bits
        self.window_size = window_size
        self.csum = csum
        self.urgent = urgent
        self.option = option

    def __len__(self):
        return self.offset * 4

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, seq, ack, offset, bits, window_size,
         csum, urgent) = struct.unpack_from(cls._PACK_STR, buf)
        offset = offset >> 4
        bits = bits & 0x3f
        length = offset * 4
        if length > tcp._MIN_LEN:
            option = buf[tcp._MIN_LEN:length]
        else:
            option = None
        msg = cls(src_port, dst_port, seq, ack, offset, bits,
                  window_size, csum, urgent, option)

        return msg, None, buf[length:]

    def serialize(self, payload, prev):
        offset = self.offset << 4
        h = bytearray(struct.pack(
            tcp._PACK_STR, self.src_port, self.dst_port, self.seq,
            self.ack, offset, self.bits, self.window_size, self.csum,
            self.urgent))

        if self.option:
            h.extend(self.option)
            mod = len(self.option) % 4
            if mod:
                h.extend(bytearray(4 - mod))
            if self.offset:
                offset = self.offset << 2
                if len(h) < offset:
                    h.extend(bytearray(offset - len(h)))

        if 0 == self.offset:
            self.offset = len(h) >> 2
            offset = self.offset << 4
            struct.pack_into('!B', h, 12, offset)

        if self.csum == 0:
            total_length = len(h) + len(payload)
            self.csum = packet_utils.checksum_ip(prev, total_length,
                                                 h + payload)
            struct.pack_into('!H', h, 16, self.csum)
        return str(h)
