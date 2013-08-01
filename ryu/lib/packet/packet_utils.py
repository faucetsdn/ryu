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

import array
import socket
import struct
from ryu.lib import addrconv


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(data):
    if len(data) % 2:
        data += '\x00'

    data = str(data)    # input can be bytearray.
    s = sum(array.array('H', data))
    s = (s & 0xffff) + (s >> 16)
    s += (s >> 16)
    return socket.ntohs(~s & 0xffff)


# avoid circular import
_IPV4_PSEUDO_HEADER_PACK_STR = '!4s4sxBH'
_IPV6_PSEUDO_HEADER_PACK_STR = '!16s16sI3xB'


def checksum_ip(ipvx, length, payload):
    """
    calculate checksum of IP pseudo header

    IPv4 pseudo header
    UDP RFC768
    TCP RFC793 3.1

     0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |          source address           |
    +--------+--------+--------+--------+
    |        destination address        |
    +--------+--------+--------+--------+
    |  zero  |protocol|    length       |
    +--------+--------+--------+--------+


    IPv6 pseudo header
    RFC2460 8.1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                         Source Address                        +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                      Destination Address                      +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Upper-Layer Packet Length                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      zero                     |  Next Header  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    if ipvx.version == 4:
        header = struct.pack(_IPV4_PSEUDO_HEADER_PACK_STR,
                             addrconv.ipv4.text_to_bin(ipvx.src),
                             addrconv.ipv4.text_to_bin(ipvx.dst),
                             ipvx.proto, length)
    elif ipvx.version == 6:
        header = struct.pack(_IPV6_PSEUDO_HEADER_PACK_STR,
                             addrconv.ipv6.text_to_bin(ipvx.src),
                             addrconv.ipv6.text_to_bin(ipvx.dst),
                             length, ipvx.nxt)
    else:
        raise ValueError('Unknown IP version %d' % ipvx.version)

    buf = header + payload
    return checksum(buf)
