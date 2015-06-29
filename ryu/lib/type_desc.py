# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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


class TypeDescr(object):
    pass


class IntDescr(TypeDescr):
    def __init__(self, size):
        self.size = size

    def to_user(self, bin):
        i = 0
        for x in range(self.size):
            c = bin[:1]
            i = i * 256 + ord(c)
            bin = bin[1:]
        return i

    def from_user(self, i):
        bin = b''
        for x in range(self.size):
            bin = six.int2byte(i & 255) + bin
            i //= 256
        return bin

Int1 = IntDescr(1)
Int2 = IntDescr(2)
Int3 = IntDescr(3)
Int4 = IntDescr(4)
Int8 = IntDescr(8)


def _split_str(s, n):
    """
    split string into list of strings by specified number.
    """
    length = len(s)
    return [s[i:i + n] for i in range(0, length, n)]


class IntDescrMlt(TypeDescr):
    def __init__(self, length, num):
        self.length = length
        self.num = num
        self.size = length * num

    def to_user(self, bin):
        assert len(bin) == self.size
        lb = _split_str(bin, self.length)
        li = []
        for b in lb:
            i = 0
            for x in range(self.length):
                c = b[:1]
                i = i * 256 + ord(c)
                b = b[1:]
            li.append(i)
        return tuple(li)

    def from_user(self, li):
        assert len(li) == self.num
        bin = b''
        for i in li:
            b = b''
            for x in range(self.length):
                b = six.int2byte(i & 255) + b
                i //= 256
            bin += b
        return bin

Int4Double = IntDescrMlt(4, 2)


class MacAddr(TypeDescr):
    size = 6
    to_user = addrconv.mac.bin_to_text
    from_user = addrconv.mac.text_to_bin


class IPv4Addr(TypeDescr):
    size = 4
    to_user = addrconv.ipv4.bin_to_text
    from_user = addrconv.ipv4.text_to_bin


class IPv6Addr(TypeDescr):
    size = 16
    to_user = addrconv.ipv6.bin_to_text
    from_user = addrconv.ipv6.text_to_bin


class UnknownType(TypeDescr):
    import base64

    b64encode = base64.b64encode
    if six.PY3:
        @classmethod
        def to_user(cls, data):
            return cls.b64encode(data).decode('ascii')
    else:
        to_user = staticmethod(base64.b64encode)
    from_user = staticmethod(base64.b64decode)
