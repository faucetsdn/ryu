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

import struct

import six

from . import packet_base
from ryu.lib import type_desc


class mpls(packet_base.PacketBase):
    """MPLS (RFC 3032) header encoder/decoder class.

    NOTE: When decoding, this implementation assumes that the inner protocol
    is IPv4.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    label          Label Value
    exp            Experimental Use
    bsb            Bottom of Stack
    ttl            Time To Live
    ============== ====================
    """

    _PACK_STR = '!I'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, label=0, exp=0, bsb=1, ttl=255):
        super(mpls, self).__init__()
        self.label = label
        self.exp = exp
        self.bsb = bsb
        self.ttl = ttl

    @classmethod
    def parser(cls, buf):
        (label,) = struct.unpack_from(cls._PACK_STR, buf)
        ttl = label & 0xff
        bsb = (label >> 8) & 1
        exp = (label >> 9) & 7
        label = label >> 12
        msg = cls(label, exp, bsb, ttl)
        if bsb:
            from . import ipv4
            return msg, ipv4.ipv4, buf[msg._MIN_LEN:]
        else:
            return msg, mpls, buf[msg._MIN_LEN:]

    def serialize(self, payload, prev):
        val = self.label << 12 | self.exp << 9 | self.bsb << 8 | self.ttl
        return struct.pack(mpls._PACK_STR, val)


def label_from_bin(buf):
    """
    Converts binary representation label to integer.

    :param buf: Binary representation of label.
    :return: MPLS Label and BoS bit.
    """

    mpls_label = type_desc.Int3.to_user(six.binary_type(buf))
    return mpls_label >> 4, mpls_label & 1


def label_to_bin(mpls_label, is_bos=True):
    """
    Converts integer label to binary representation.

    :param mpls_label: MPLS Label.
    :param is_bos: BoS bit.
    :return: Binary representation of label.
    """
    return type_desc.Int3.from_user(mpls_label << 4 | is_bos)
