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

DONTCARE = '\x00' * 6
BROADCAST = '\xff' * 6
MULTICAST = '\xfe' + '\xff' * 5
UNICAST = '\x01' + '\x00' * 5


def is_multicast(addr):
    return bool(ord(addr[0]) & 0x01)


def haddr_to_str(addr):
    return ''.join(['%02x:' % ord(char) for char in addr[0:6]])[:-1]


def haddr_to_bin(string):
    return ''.join(['%c' % chr(int(i, 16)) for i in
                    string.split(':')])
