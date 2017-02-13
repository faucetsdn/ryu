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

import numbers
import struct

import netaddr

from ryu.lib import addrconv
from ryu.lib import type_desc


def _valid_ip(strategy, bits, addr, flags=0):
    addr = addr.split('/')
    if len(addr) == 1:
        return strategy(addr[0], flags)
    elif len(addr) == 2:
        return strategy(addr[0], flags) and 0 <= int(addr[1]) <= bits
    else:
        return False


def valid_ipv4(addr, flags=0):
    """
    Wrapper function of "netaddr.valid_ipv4()".

    The function extends "netaddr.valid_ipv4()" to enable to validate
    IPv4 network address in "xxx.xxx.xxx.xxx/xx" format.

    :param addr: IP address to be validated.
    :param flags: See the "netaddr.valid_ipv4()" docs for details.
    :return: True is valid. False otherwise.
    """
    return _valid_ip(netaddr.valid_ipv4, 32, addr, flags)


def valid_ipv6(addr, flags=0):
    """
    Wrapper function of "netaddr.valid_ipv6()".

    The function extends "netaddr.valid_ipv6()" to enable to validate
    IPv4 network address in "xxxx:xxxx:xxxx::/xx" format.

    :param addr: IP address to be validated.
    :param flags: See the "netaddr.valid_ipv6()" docs for details.
    :return: True is valid. False otherwise.
    """
    return _valid_ip(netaddr.valid_ipv6, 128, addr, flags)


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
    :param ip: binary or int type representation of IPv4 address
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


def ipv6_to_int(ip):
    """
    Converts human readable IPv6 string to int type representation.
    :param str ip: IPv6 address string
    :returns: int type representation of IPv6 address
    """
    return type_desc.Int16.to_user(addrconv.ipv6.text_to_bin(ip))


def ipv6_to_str(ip):
    """
    Converts binary or int type representation to human readable IPv6 string.
    :param ip: binary or int type representation of IPv6 address
    :return: IPv6 address string
    """
    if isinstance(ip, numbers.Integral):
        return addrconv.ipv6.bin_to_text(type_desc.Int16.from_user(ip))
    else:
        return addrconv.ipv6.bin_to_text(ip)


def text_to_bin(ip):
    """
    Converts human readable IPv4 or IPv6 string to binary representation.
    :param str ip: IPv4 or IPv6 address string
    :return: binary representation of IPv4 or IPv6 address
    """

    if ':' not in ip:
        return ipv4_to_bin(ip)
    else:
        return ipv6_to_bin(ip)


def text_to_int(ip):
    """
    Converts human readable IPv4 or IPv6 string to int type representation.
    :param str ip: IPv4 or IPv6 address string
    :return: int type representation of IPv4 or IPv6 address
    """

    if ':' not in ip:
        return ipv4_to_int(ip)
    else:
        return ipv6_to_int(ip)


def bin_to_text(ip):
    """
    Converts binary representation to human readable IPv4 or IPv6 string.
    :param ip: binary representation of IPv4 or IPv6 address
    :return: IPv4 or IPv6 address string
    """
    if len(ip) == 4:
        return ipv4_to_str(ip)
    elif len(ip) == 16:
        return ipv6_to_str(ip)
    else:
        raise struct.error('Invalid ip address length: %s' % len(ip))
