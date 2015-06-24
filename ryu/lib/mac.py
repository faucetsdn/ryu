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

import six

from ryu.lib import addrconv

if six.PY3:
    _ord = int
else:
    _ord = ord

# string representation
HADDR_PATTERN = r'([0-9a-f]{2}:){5}[0-9a-f]{2}'

DONTCARE = b'\x00' * 6
BROADCAST = b'\xff' * 6
DONTCARE_STR = '00:00:00:00:00:00'
BROADCAST_STR = 'ff:ff:ff:ff:ff:ff'
MULTICAST = 'fe:ff:ff:ff:ff:ff'
UNICAST = '01:00:00:00:00:00'


def is_multicast(addr):
    return bool(_ord(addr[0]) & 0x01)


def haddr_to_str(addr):
    """Format mac address in internal representation into human readable
    form"""
    if addr is None:
        return 'None'
    try:
        return addrconv.mac.bin_to_text(addr)
    except:
        raise AssertionError


def haddr_to_bin(string):
    """Parse mac address string in human readable format into
    internal representation"""
    try:
        return addrconv.mac.text_to_bin(string)
    except:
        raise ValueError


def haddr_bitand(addr, mask):
    return b''.join(six.int2byte(_ord(a) & _ord(m)) for (a, m)
                    in zip(addr, mask))
