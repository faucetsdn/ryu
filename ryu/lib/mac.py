# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


DONTCARE = '\x00' * 6
BROADCAST = '\xff' * 6


def is_multicast(addr):
    return bool(ord(addr[0]) & 0x01)


def haddr_to_str(addr):
    return ''.join(['%02x:' % ord(char) for char in addr[0:6]])[:-1]


def haddr_to_bin(string):
    return ''.join(['%c' % chr(int(i, 16)) for i in
                    string.split(':')])
