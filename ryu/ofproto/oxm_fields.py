# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# there are two representations of value and mask this module deal with.
#
# "user"
#   (value, mask) or value.  the latter means no mask.
#   value and mask are strings.
#
# "internal"
#   value and mask are on-wire bytes.
#   mask is None if no mask.

import itertools
import struct
from ofproto_parser import msg_pack_into

from ryu.lib import addrconv


class TypeDescr(object):
    pass


class IntDescr(TypeDescr):
    def __init__(self, size):
        self.size = size

    def to_user(self, bin):
        i = 0
        for x in xrange(self.size):
            c = bin[:1]
            i = i * 256 + ord(c)
            bin = bin[1:]
        return i

    def from_user(self, i):
        bin = ''
        for x in xrange(self.size):
            bin = chr(i & 255) + bin
            i /= 256
        return bin

Int1 = IntDescr(1)
Int2 = IntDescr(2)
Int3 = IntDescr(3)
Int4 = IntDescr(4)
Int8 = IntDescr(8)


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

    to_user = staticmethod(base64.b64encode)
    from_user = staticmethod(base64.b64decode)


OFPXMC_OPENFLOW_BASIC = 0x8000


class OpenFlowBasic(object):
    _class = OFPXMC_OPENFLOW_BASIC

    def __init__(self, name, num, type_):
        self.name = name
        self.num = num | (self._class << 7)
        self.type = type_


def generate(modname):
    import sys
    import string
    import functools

    mod = sys.modules[modname]

    def add_attr(k, v):
        setattr(mod, k, v)

    for i in mod.oxm_types:
        uk = string.upper(i.name)
        oxm_class = i.num >> 7
        if oxm_class != OFPXMC_OPENFLOW_BASIC:
            continue
        ofpxmt = i.num & 0x3f
        td = i.type
        add_attr('OFPXMT_OFB_' + uk, ofpxmt)
        add_attr('OXM_OF_' + uk, mod.oxm_tlv_header(ofpxmt, td.size))
        add_attr('OXM_OF_' + uk + '_W', mod.oxm_tlv_header_w(ofpxmt, td.size))

    name_to_field = dict((f.name, f) for f in mod.oxm_types)
    num_to_field = dict((f.num, f) for f in mod.oxm_types)
    add_attr('oxm_from_user', functools.partial(from_user, name_to_field))
    add_attr('oxm_to_user', functools.partial(to_user, num_to_field))
    add_attr('oxm_normalize_user', functools.partial(normalize_user, mod))
    add_attr('oxm_parse', functools.partial(parse, mod))
    add_attr('oxm_serialize', serialize)
    add_attr('oxm_to_jsondict', to_jsondict)
    add_attr('oxm_from_jsondict', from_jsondict)


def from_user(name_to_field, name, user_value):
    try:
        f = name_to_field[name]
        t = f.type
        num = f.num
    except KeyError:
        t = UnknownType
        if name.startswith('field_'):
            num = int(name.split('_')[1])
        else:
            raise KeyError('unknown match field ' + name)
    # the 'list' case below is a bit hack; json.dumps silently maps
    # python tuples into json lists.
    if isinstance(user_value, (tuple, list)):
        (value, mask) = user_value
    else:
        value = user_value
        mask = None
    if not value is None:
        value = t.from_user(value)
    if not mask is None:
        mask = t.from_user(mask)
    return num, value, mask


def to_user(num_to_field, n, v, m):
    try:
        f = num_to_field[n]
        t = f.type
        name = f.name
    except KeyError:
        t = UnknownType
        name = 'field_%d' % n
    if not v is None:
        value = t.to_user(v)
    else:
        value = None
    if m is None:
        user_value = value
    else:
        user_value = (value, t.to_user(m))
    return name, user_value


def normalize_user(mod, k, uv):
    (n, v, m) = mod.oxm_from_user(k, uv)
    # apply mask
    if not m is None:
        v = ''.join(chr(ord(x) & ord(y)) for (x, y)
            in itertools.izip(v, m))
    (k2, uv2) = mod.oxm_to_user(n, v, m)
    assert k2 == k
    return (k2, uv2)


def parse(mod, buf, offset):
    hdr_pack_str = '!I'
    (header, ) = struct.unpack_from(hdr_pack_str, buf, offset)
    hdr_len = struct.calcsize(hdr_pack_str)
    oxm_type = header >> 9  # class|field
    oxm_hasmask = mod.oxm_tlv_header_extract_hasmask(header)
    value_len = mod.oxm_tlv_header_extract_length(header)
    value_pack_str = '!%ds' % value_len
    assert struct.calcsize(value_pack_str) == value_len
    (value, ) = struct.unpack_from(value_pack_str, buf,
                                   offset + hdr_len)
    if oxm_hasmask:
        (mask, ) = struct.unpack_from(value_pack_str, buf,
                                      offset + hdr_len + value_len)
    else:
        mask = None
    field_len = hdr_len + (header & 0xff)
    return oxm_type, value, mask, field_len


def serialize(n, value, mask, buf, offset):
    if mask:
        assert len(value) == len(mask)
        pack_str = "!I%ds%ds" % (len(value), len(mask))
        msg_pack_into(pack_str, buf, offset,
                      (n << 9) | (1 << 8) | (len(value) * 2), value, mask)
    else:
        pack_str = "!I%ds" % (len(value),)
        msg_pack_into(pack_str, buf, offset,
                      (n << 9) | (0 << 8) | len(value), value)
    return struct.calcsize(pack_str)


def to_jsondict(k, uv):
    if isinstance(uv, tuple):
        (value, mask) = uv
    else:
        value = uv
        mask = None
    return {"OXMTlv": {"field": k, "value": value, "mask": mask}}


def from_jsondict(j):
    tlv = j['OXMTlv']
    field = tlv['field']
    value = tlv['value']
    mask = tlv.get('mask')
    if mask is None:
        uv = value
    else:
        uv = (value, mask)
    return (field, uv)
