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


ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_SRC_QUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8


class icmp(packet_base.PacketBase):
    _PACK_STR = '!BBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _ICMP_TYPES = {}

    @staticmethod
    def register_icmp_type(*args):
        def _register_icmp_type(cls):
            for type_ in args:
                icmp._ICMP_TYPES[type_] = cls
            return cls
        return _register_icmp_type

    def __init__(self, type_, code, csum, data=None):
        super(icmp, self).__init__()
        self.type = type_
        self.code = code
        self.csum = csum
        self.data = data

    @classmethod
    def parser(cls, buf):
        (type_, code, csum) = struct.unpack_from(cls._PACK_STR, buf)
        msg = cls(type_, code, csum)
        offset = cls._MIN_LEN

        if len(buf) > offset:
            cls_ = cls._ICMP_TYPES.get(type_, None)
            if cls_:
                msg.data = cls_.parser(buf, offset)
            else:
                msg.data = buf[offset:]

        return msg, None

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(icmp._PACK_STR, self.type,
                                    self.code, self.csum))

        if self.data is not None:
            if self.type in icmp._ICMP_TYPES:
                hdr += self.data.serialize()
            else:
                hdr += self.data

        if self.csum == 0:
            if len(hdr) % 2:
                hdr += '\0'
            self.csum = socket.htons(packet_utils.checksum(hdr))
            struct.pack_into('!H', hdr, 2, self.csum)

        return hdr


@icmp.register_icmp_type(ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST)
class echo(object):
    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, id_, seq, data=None):
        self.id = id_
        self.seq = seq
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (id_, seq) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(id_, seq)
        offset += cls._MIN_LEN

        if len(buf) > offset:
            msg.data = buf[offset:]

        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(echo._PACK_STR, self.id,
                                    self.seq))

        if self.data is not None:
            hdr += self.data

        return hdr
