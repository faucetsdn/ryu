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

from ryu.lib.pack_utils import msg_pack_into
from . import packet_base
from . import packet_utils
from . import ether_types


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
    version        Version.
    protocol       Protocol Type field.
                   The Protocol Type is defined as "ETHER TYPES".
    checksum       Checksum field(optional).
                   When you set a value other than None,
                   this field will be automatically calculated.
    key            Key field(optional)
                   This field is intended to be used for identifying
                   an individual traffic flow within a tunnel.
    vsid           Virtual Subnet ID field(optional)
                   This field is a 24-bit value that is used
                   to identify the NVGRE-based Virtual Layer 2 Network.
    flow_id        FlowID field(optional)
                   This field is an 8-bit value that is used to provide
                   per-flow entropy for flows in the same VSID.
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
    _SEQNUM_PACK_LEN = struct.calcsize(_SEQNUM_PACK_STR)

    # GRE header
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |C| |K|S| Reserved0       | Ver |         Protocol Type         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |      Checksum (optional)      |       Reserved1 (Optional)    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Key (optional)                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                 Sequence Number (Optional)                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    def __init__(self, version=0, protocol=ether_types.ETH_TYPE_IP,
                 checksum=None, key=None, vsid=None, flow_id=None,
                 seq_number=None):
        super(gre, self).__init__()

        self.version = version
        self.protocol = protocol
        self.checksum = checksum
        self.seq_number = seq_number

        if key is not None:
            self._key = key
            self._vsid = self._key >> 8
            self._flow_id = self._key & 0xff
        elif (vsid is not None) and (flow_id is not None):
            self._key = vsid << 8 | flow_id
            self._vsid = vsid
            self._flow_id = flow_id
        else:
            self._key = None
            self._vsid = None
            self._flow_id = None

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        if key is not None:
            self._key = key
            self._vsid = self._key >> 8
            self._flow_id = self._key & 0xff
        else:
            self._key = None
            self._vsid = None
            self._flow_id = None

    @property
    def vsid(self):
        return self._vsid

    @vsid.setter
    def vsid(self, vsid):
        self._key = vsid << 8 | (self._key & 0xff)
        self._vsid = vsid

    @property
    def flow_id(self):
        return self._flow_id

    @flow_id.setter
    def flow_id(self, flow_id):
        self._key = (self._key & 0xffffff00) | flow_id
        self._flow_id = flow_id

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
            gre_offset += cls._SEQNUM_PACK_LEN

        msg = cls(version=version, protocol=protocol, checksum=checksum,
                  key=key, seq_number=seq_number)

        from . import ethernet
        gre._TYPES = ethernet.ethernet._TYPES
        gre.register_packet_type(ethernet.ethernet,
                                 ether_types.ETH_TYPE_TEB)

        return msg, gre.get_packet_type(protocol), buf[gre_offset:]

    def serialize(self, payload=None, prev=None):
        present = 0
        hdr = bytearray()
        optional = bytearray()

        if self.checksum is not None:
            present |= GRE_CHECKSUM_FLG

            # For purposes of computing the checksum,
            # the value of the checksum field is zero.
            # Also, because Reserved1 is always 0x00 of 2 bytes,
            # Set in conjunction with checksum.
            optional += b'\x00' * self._CHECKSUM_LEN

        if self._key is not None:
            present |= GRE_KEY_FLG
            optional += struct.pack(self._KEY_PACK_STR, self._key)

        if self.seq_number is not None:
            present |= GRE_SEQUENCE_NUM_FLG
            optional += struct.pack(self._SEQNUM_PACK_STR, self.seq_number)

        msg_pack_into(self._PACK_STR, hdr, 0, present, self.version,
                      self.protocol)

        hdr += optional

        if self.checksum:
            self.checksum = packet_utils.checksum(hdr)
            struct.pack_into(self._CHECKSUM_PACK_STR, hdr, self._MIN_LEN,
                             self.checksum)

        return hdr


def nvgre(version=0, vsid=0, flow_id=0):
    """
    Generate instance of GRE class with information for NVGRE (RFC7637).

    :param version: Version.
    :param vsid: Virtual Subnet ID.
    :param flow_id: FlowID.
    :return: Instance of GRE class with information for NVGRE.
    """

    # NVGRE header
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |0| |1|0|   Reserved0     | Ver |   Protocol Type 0x6558        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |               Virtual Subnet ID (VSID)        |    FlowID     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    return gre(version=version, protocol=ether_types.ETH_TYPE_TEB,
               vsid=vsid, flow_id=flow_id)
