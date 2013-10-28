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

"""
Internet Group Management Protocol(IGMP) packet parser/serializer

RFC 1112
IGMP v1 format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Type  |    Unused     |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

RFC 2236
IGMP v2 format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Type     | Max Resp Time |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import struct

from ryu.lib import addrconv
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet_utils


IGMP_TYPE_QUERY = 0x11
IGMP_TYPE_REPORT_V1 = 0x12
IGMP_TYPE_REPORT_V2 = 0x16
IGMP_TYPE_LEAVE = 0x17
IGMP_TYPE_REPORT_V3 = 0x22

QUERY_RESPONSE_INTERVAL = 10.0
LAST_MEMBER_QUERY_INTERVAL = 1.0

MULTICAST_IP_ALL_HOST = '224.0.0.1'
MULTICAST_MAC_ALL_HOST = '01:00:5e:00:00:01'


class igmp(packet_base.PacketBase):
    """
    Internet Group Management Protocol(IGMP, RFC 1112, RFC 2236)
    header encoder/decoder class.

    http://www.ietf.org/rfc/rfc1112.txt

    http://www.ietf.org/rfc/rfc2236.txt

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    =============== ====================================================
    Attribute       Description
    =============== ====================================================
    msgtype         a message type for v2, or a combination of
                    version and a message type for v1.
    maxresp         max response time in unit of 1/10 second. it is
                    meaningful only in Query Message.
    csum            a check sum value. 0 means automatically-calculate
                    when encoding.
    address         a group address value.
    =============== ====================================================

    * NOTE: IGMP v3(RFC 3376) is not supported yet.
    """
    _PACK_STR = '!BBH4s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, msgtype, maxresp, csum, address):
        super(igmp, self).__init__()
        self.msgtype = msgtype
        self.maxresp = maxresp
        self.csum = csum
        self.address = address

    @classmethod
    def parser(cls, buf):
        assert cls._MIN_LEN <= len(buf)
        (msgtype, maxresp, csum, address
         ) = struct.unpack_from(cls._PACK_STR, buf)
        return (cls(msgtype, maxresp, csum,
                    addrconv.ipv4.bin_to_text(address)),
                None,
                buf[cls._MIN_LEN:])

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(self._PACK_STR, self.msgtype,
                        self.maxresp, self.csum,
                        addrconv.ipv4.text_to_bin(self.address)))

        if self.csum == 0:
            self.csum = packet_utils.checksum(hdr)
            struct.pack_into('!H', hdr, 2, self.csum)

        return hdr
