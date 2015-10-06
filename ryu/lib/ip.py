# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

from ryu.lib import addrconv


def ipv4_to_bin(ip):
    """
    Converts human readable IPv4 string to binary representation.
    :param str ip: IPv4 address string
    :return: binary representation of IPv4 address
    """
    return addrconv.ipv4.text_to_bin(ip)


def ipv4_to_int(ip):
    """
    Converts human readable IPv4 string to int type representation.
    :param str ip: IPv4 address string w.x.y.z
    :returns: unsigned int of form w << 24 | x << 16 | y << 8 | z
    """
    return struct.unpack("!I", addrconv.ipv4.text_to_bin(ip))[0]


def ipv4_to_str(ip):
    """
    Converts binary or int type representation to human readable IPv4 string.
    :param str ip: binary or int type representation of IPv4 address
    :return: IPv4 address string
    """
    if isinstance(ip, int):
        return addrconv.ipv4.bin_to_text(struct.pack("!I", ip))
    else:
        return addrconv.ipv4.bin_to_text(ip)


def ipv6_to_bin(ip):
    """
    Converts human readable IPv6 string to binary representation.
    :param str ip: IPv6 address string
    :return: binary representation of IPv6 address
    """
    return addrconv.ipv6.text_to_bin(ip)


def ipv6_to_str(ip):
    """
    Converts binary representation to human readable IPv6 string.
    :param str ip: binary representation of IPv6 address
    :return: IPv6 address string
    """
    return addrconv.ipv6.bin_to_text(ip)
