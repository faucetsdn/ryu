# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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

import itertools

# string representation
HADDR_PATTERN = r'([0-9a-f]{2}:){5}[0-9a-f]{2}'

# Internal representation of mac address is string[6]
_HADDR_LEN = 6

DONTCARE = '\x00' * 6
BROADCAST = '\xff' * 6
MULTICAST = '\xfe' + '\xff' * 5
UNICAST = '\x01' + '\x00' * 5


def is_multicast(addr):
    return bool(ord(addr[0]) & 0x01)


def haddr_to_str(addr):
    """Format mac address in internal representation into human readable
    form"""
    if addr is None:
        return 'None'
    assert len(addr) == _HADDR_LEN
    return ':'.join('%02x' % ord(char) for char in addr)


def haddr_to_bin(string):
    """Parse mac address string in human readable format into
    internal representation"""
    hexes = string.split(':')
    if len(hexes) != _HADDR_LEN:
        raise ValueError('Invalid format for mac address: %s' % string)
    return ''.join(chr(int(h, 16)) for h in hexes)


def haddr_bitand(addr, mask):
    return ''.join(chr(ord(a) & ord(m)) for (a, m)
                   in itertools.izip(addr, mask))
