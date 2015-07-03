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
import six
import socket
import struct
from ryu.lib import addrconv


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(data):
    data = six.binary_type(data)    # input can be bytearray.
    if len(data) % 2:
        data += b'\x00'

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

_MODX = 4102


def fletcher_checksum(data, offset):
    """
    Fletcher Checksum -- Refer to RFC1008

    calling with offset == _FLETCHER_CHECKSUM_VALIDATE will validate the
    checksum without modifying the buffer; a valid checksum returns 0.
    """
    c0 = 0
    c1 = 0
    pos = 0
    length = len(data)
    data = bytearray(data)
    data[offset:offset + 2] = [0] * 2

    while pos < length:
        tlen = min(length - pos, _MODX)
        for d in data[pos:pos + tlen]:
            c0 += d
            c1 += c0
        c0 %= 255
        c1 %= 255
        pos += tlen

    x = ((length - offset - 1) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255

    data[offset] = x
    data[offset + 1] = y
    return (x << 8) | (y & 0xff)
