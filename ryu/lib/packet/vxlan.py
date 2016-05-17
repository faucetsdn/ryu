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

"""
VXLAN packet parser/serializer

RFC 7348
VXLAN Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|R|R|R|I|R|R|R|            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                VXLAN Network Identifier (VNI) |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- Flags (8 bits): where the I flag MUST be set to 1 for a valid
  VXLAN Network ID (VNI).  The other 7 bits (designated "R") are
  reserved fields and MUST be set to zero on transmission and
  ignored on receipt.

- VXLAN Segment ID/VXLAN Network Identifier (VNI): this is a
  24-bit value used to designate the individual VXLAN overlay
  network on which the communicating VMs are situated.  VMs in
  different VXLAN overlay networks cannot communicate with each
  other.

- Reserved fields (24 bits and 8 bits): MUST be set to zero on
  transmission and ignored on receipt.
"""

import struct
import logging

from . import packet_base


LOG = logging.getLogger(__name__)

UDP_DST_PORT = 4789
UDP_DST_PORT_OLD = 8472  # for backward compatibility like Linux


class vxlan(packet_base.PacketBase):
    """VXLAN (RFC 7348) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    vni            VXLAN Network Identifier
    ============== ====================
    """

    # Note: Python has no format character for 24 bits field.
    # we use uint32 format character instead and bit-shift at serializing.
    _PACK_STR = '!II'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, vni):
        super(vxlan, self).__init__()
        self.vni = vni

    @classmethod
    def parser(cls, buf):
        (flags_reserved, vni_rserved) = struct.unpack_from(cls._PACK_STR, buf)

        # Check VXLAN flags is valid
        assert (1 << 3) == (flags_reserved >> 24)

        # Note: To avoid cyclic import, import ethernet module here
        from ryu.lib.packet import ethernet
        return cls(vni_rserved >> 8), ethernet.ethernet, buf[cls._MIN_LEN:]

    def serialize(self, payload, prev):
        return struct.pack(self._PACK_STR,
                           1 << (3 + 24), self.vni << 8)
