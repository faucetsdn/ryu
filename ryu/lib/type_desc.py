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

import base64

import six

from ryu.lib import addrconv


class TypeDescr(object):
    pass


class IntDescr(TypeDescr):
    def __init__(self, size):
        self.size = size

    def to_user(self, binary):
        i = 0
        for _ in range(self.size):
            c = binary[:1]
            i = i * 256 + ord(c)
            binary = binary[1:]
        return i

    def from_user(self, i):
        binary = b''
        for _ in range(self.size):
            binary = six.int2byte(i & 255) + binary
            i //= 256
        return binary

Int1 = IntDescr(1)
Int2 = IntDescr(2)
Int3 = IntDescr(3)
Int4 = IntDescr(4)
Int8 = IntDescr(8)
Int9 = IntDescr(9)
Int16 = IntDescr(16)


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

    def to_user(self, binary):
        assert len(binary) == self.size
        lb = _split_str(binary, self.length)
        li = []
        for b in lb:
            i = 0
            for _ in range(self.length):
                c = b[:1]
                i = i * 256 + ord(c)
                b = b[1:]
            li.append(i)
        return tuple(li)

    def from_user(self, li):
        assert len(li) == self.num
        binary = b''
        for i in li:
            b = b''
            for _ in range(self.length):
                b = six.int2byte(i & 255) + b
                i //= 256
            binary += b
        return binary

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

    @staticmethod
    def to_user(data):
        if six.PY3:
            return base64.b64encode(data).decode('ascii')
        else:
            return base64.b64encode(data)

    from_user = staticmethod(base64.b64decode)


class TypeDisp(object):
    _TYPES = {}
    _REV_TYPES = None
    _UNKNOWN_TYPE = None

    @classmethod
    def register_unknown_type(cls):
        def _register_type(subcls):
            cls._UNKNOWN_TYPE = subcls
            return subcls
        return _register_type

    @classmethod
    def register_type(cls, type_):
        cls._TYPES = cls._TYPES.copy()

        def _register_type(subcls):
            cls._TYPES[type_] = subcls
            cls._REV_TYPES = None
            return subcls
        return _register_type

    @classmethod
    def _lookup_type(cls, type_):
        try:
            return cls._TYPES[type_]
        except KeyError:
            return cls._UNKNOWN_TYPE

    @classmethod
    def _rev_lookup_type(cls, targ_cls):
        if cls._REV_TYPES is None:
            rev = dict((v, k) for k, v in cls._TYPES.items())
            cls._REV_TYPES = rev
        return cls._REV_TYPES[targ_cls]
