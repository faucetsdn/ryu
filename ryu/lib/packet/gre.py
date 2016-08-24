# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
from . import ether_types as ether
from ryu.lib.pack_utils import msg_pack_into


GRE_CHECKSUM_FLG = 1 << 7
GRE_KEY_FLG = 1 << 5
GRE_SEQUENCE_NUM_FLG = 1 << 4


class gre(packet_base.PacketBase):
    """GRE (RFC2784,RFC2890) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ========================================================
    Attribute      Description
    ============== ========================================================
    protocol       Protocol Type field.
                   The Protocol Type is defined as "ETHER TYPES".
    checksum       Checksum field(optional).
                   When you set a value other than None,
                   this field will be automatically calculated.
    key            Key field(optional)
                   This field is intended to be used for identifying
                   an individual traffic flow within a tunnel.
    seq_number     Sequence Number field(optional)
    ============== ========================================================
    """
    _PACK_STR = "!BBH"
    _CHECKSUM_PACK_STR = "!H2x"
    _KEY_PACK_STR = "!I"
    _SEQNUM_PACK_STR = "!I"
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _CHECKSUM_LEN = struct.calcsize(_CHECKSUM_PACK_STR)
    _KEY_LEN = struct.calcsize(_KEY_PACK_STR)

    def __init__(self, protocol=ether.ETH_TYPE_IP,
                 checksum=None, key=None, seq_number=None):
        super(gre, self).__init__()

        self.protocol = protocol
        self.checksum = checksum
        self.key = key
        self.seq_number = seq_number

    @classmethod
    def parser(cls, buf):
        present, version, protocol = struct.unpack_from(cls._PACK_STR, buf)
        gre_offset = gre._MIN_LEN
        checksum = None
        key = None
        seq_number = None

        if present & GRE_CHECKSUM_FLG:
            checksum, = struct.unpack_from(cls._CHECKSUM_PACK_STR,
                                           buf, gre_offset)
            gre_offset += cls._CHECKSUM_LEN
        if present & GRE_KEY_FLG:
            key, = struct.unpack_from(cls._KEY_PACK_STR, buf, gre_offset)
            gre_offset += cls._KEY_LEN
        if present & GRE_SEQUENCE_NUM_FLG:
            seq_number, = struct.unpack_from(cls._SEQNUM_PACK_STR,
                                             buf, gre_offset)

        msg = cls(protocol, checksum, key, seq_number)

        from . import ethernet
        # Because the protocol type field could either Ethertype is set,
        # Set the _TYPES of ethernet, which owns the Ethernet types
        # available in Ryu.
        gre._TYPES = ethernet.ethernet._TYPES

        return msg, gre.get_packet_type(protocol), buf[gre_offset:]

    def serialize(self, payload=None, prev=None):
        present = 0
        version = 0
        hdr = bytearray()
        optional = bytearray()

        if self.checksum:
            present += GRE_CHECKSUM_FLG

            # For purposes of computing the checksum,
            # the value of the checksum field is zero.
            # Also, because Reserved1 is always 0x00 of 2 bytes,
            # Set in conjunction with checksum.
            optional += b'\x00' * self._CHECKSUM_LEN

        if self.key:
            present += GRE_KEY_FLG
            optional += struct.pack(self._KEY_PACK_STR, self.key)

        if self.seq_number:
            present += GRE_SEQUENCE_NUM_FLG
            optional += struct.pack(self._SEQNUM_PACK_STR, self.seq_number)

        msg_pack_into(self._PACK_STR, hdr, 0,
                      present, version, self.protocol)

        hdr += optional

        if self.checksum:
            self.checksum = packet_utils.checksum(hdr)
            struct.pack_into(self._CHECKSUM_PACK_STR, hdr, self._MIN_LEN,
                             self.checksum)

        return hdr
