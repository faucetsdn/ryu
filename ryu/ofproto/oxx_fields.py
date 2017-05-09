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

# there are two representations of value and mask this module deal with.
#
# "user"
#   (value, mask) or value.  the latter means no mask.
#   value and mask are strings.
#
# "internal"
#   value and mask are on-wire bytes.
#   mask is None if no mask.

import six
import struct

from ryu.ofproto import ofproto_common
from ryu.lib.pack_utils import msg_pack_into
from ryu.lib import type_desc

if six.PY3:
    _ord = int
else:
    _ord = ord

# 'OFPXXC_EXPERIMENTER' has not corresponding field in the specification.
# This is transparently value for Experimenter class ID for OXM/OXS.
OFPXXC_EXPERIMENTER = 0xffff


def _get_field_info_by_name(oxx, name_to_field, name):
    try:
        f = name_to_field[name]
        t = f.type
        num = f.num
    except KeyError:
        t = type_desc.UnknownType
        if name.startswith('field_'):
            num = int(name.split('_')[1])
        else:
            raise KeyError('unknown %s field: %s' % (oxx.upper(), name))
    return num, t


def _from_user_header(oxx, name_to_field, name):
    (num, t) = _get_field_info_by_name(oxx, name_to_field, name)
    return num


def _from_user(oxx, name_to_field, name, user_value):
    (num, t) = _get_field_info_by_name(oxx, name_to_field, name)
    # the 'list' case below is a bit hack; json.dumps silently maps
    # python tuples into json lists.
    if oxx == 'oxm' and isinstance(user_value, (tuple, list)):
        (value, mask) = user_value
    else:
        value = user_value
        mask = None
    if value is not None:
        value = t.from_user(value)
    if mask is not None:
        mask = t.from_user(mask)
    elif isinstance(value, tuple):
        # This hack is to accomodate CIDR notations with IPv[46]Addr.
        value, mask = value
    return num, value, mask


def _get_field_info_by_number(oxx, num_to_field, n):
    try:
        f = num_to_field[n]
        t = f.type
        name = f.name
    except KeyError:
        t = type_desc.UnknownType
        if isinstance(n, six.integer_types):
            name = 'field_%d' % (n,)
        else:
            raise KeyError('unknown %s field number: %s' % (oxx.upper(), n))
    return name, t


def _to_user_header(oxx, num_to_field, n):
    (name, t) = _get_field_info_by_number(oxx, num_to_field, n)
    return name


def _to_user(oxx, num_to_field, n, v, m):
    (name, t) = _get_field_info_by_number(oxx, num_to_field, n)
    if v is not None:
        if isinstance(v, (tuple, list)):
            v_len = len(v) * len(v[0])
        else:
            v_len = len(v)
        if hasattr(t, 'size') and t.size != v_len:
            raise Exception(
                'Unexpected %s payload length %d for %s (expected %d)'
                % (oxx.upper(), v_len, name, t.size))
        value = t.to_user(v)
    else:
        value = None
    if m is None:
        user_value = value
    else:
        user_value = (value, t.to_user(m))
    return name, user_value


def _field_desc(num_to_field, n):
    return num_to_field[n]


def _normalize_user(oxx, mod, k, uv):
    try:
        from_user = getattr(mod, oxx + '_from_user')
        (n, v, m) = from_user(k, uv)
    except:
        return (k, uv)
    # apply mask
    if m is not None:
        v = b''.join(six.int2byte(_ord(x) & _ord(y)) for (x, y) in zip(v, m))
    try:
        to_user = getattr(mod, oxx + '_to_user')
        (k2, uv2) = to_user(n, v, m)
    except:
        return (k, uv)
    assert k2 == k
    return (k2, uv2)


def _parse_header_impl(mod, buf, offset):
    hdr_pack_str = '!I'
    (header, ) = struct.unpack_from(hdr_pack_str, buf, offset)
    hdr_len = struct.calcsize(hdr_pack_str)
    oxx_type = header >> 9  # class|field
    oxm_hasmask = mod.oxm_tlv_header_extract_hasmask(header)
    oxx_class = oxx_type >> 7
    oxx_length = header & 0xff
    if oxx_class == OFPXXC_EXPERIMENTER:
        # Experimenter OXMs/OXSs have 64-bit header.
        # (vs 32-bit for other OXMs/OXSs)
        exp_hdr_pack_str = '!I'  # experimenter_id
        (exp_id, ) = struct.unpack_from(exp_hdr_pack_str, buf,
                                        offset + hdr_len)
        exp_hdr_len = struct.calcsize(exp_hdr_pack_str)
        assert exp_hdr_len == 4
        oxx_field = oxx_type & 0x7f
        if exp_id == ofproto_common.ONF_EXPERIMENTER_ID and oxx_field == 0:
            # XXX
            # This block implements EXT-256 style experimenter OXM.
            onf_exp_type_pack_str = '!H'
            (exp_type, ) = struct.unpack_from(onf_exp_type_pack_str, buf,
                                              offset + hdr_len + exp_hdr_len)
            exp_hdr_len += struct.calcsize(onf_exp_type_pack_str)
            assert exp_hdr_len == 4 + 2
            num = (exp_id, exp_type)
        else:
            num = (exp_id, oxx_type)
    else:
        num = oxx_type
        exp_hdr_len = 0
    value_len = oxx_length - exp_hdr_len
    if oxm_hasmask:
        value_len //= 2
    assert value_len > 0
    field_len = hdr_len + oxx_length
    total_hdr_len = hdr_len + exp_hdr_len
    return num, total_hdr_len, oxm_hasmask, value_len, field_len


def _parse_header(mod, buf, offset):
    (oxx_type_num, total_hdr_len, hasmask, value_len,
     field_len) = _parse_header_impl(mod, buf, offset)
    return oxx_type_num, field_len - value_len


def _parse(mod, buf, offset):
    (oxx_type_num, total_hdr_len, hasmask, value_len,
     field_len) = _parse_header_impl(mod, buf, offset)
    # Note: OXM/OXS payload length (oxx_len) includes Experimenter ID
    # (exp_hdr_len) for experimenter OXMs/OXSs.
    value_offset = offset + total_hdr_len
    value_pack_str = '!%ds' % value_len
    assert struct.calcsize(value_pack_str) == value_len
    (value, ) = struct.unpack_from(value_pack_str, buf, value_offset)
    if hasmask:
        (mask, ) = struct.unpack_from(value_pack_str, buf,
                                      value_offset + value_len)
    else:
        mask = None
    return oxx_type_num, value, mask, field_len


def _make_exp_hdr(oxx, mod, n):
    exp_hdr = bytearray()
    try:
        get_desc = getattr(mod, '_' + oxx + '_field_desc')
        desc = get_desc(n)
    except KeyError:
        return n, exp_hdr
    if desc._class == OFPXXC_EXPERIMENTER:
        (exp_id, exp_type) = n
        assert desc.experimenter_id == exp_id
        oxx_type = getattr(desc, oxx + '_type')
        if desc.exp_type == 2560:
            # XXX
            # This block implements EXT-256 style experimenter OXM.
            exp_hdr_pack_str = '!IH'  # experimenter_id, exp_type
            msg_pack_into(exp_hdr_pack_str, exp_hdr, 0,
                          desc.experimenter_id, desc.exp_type)
        else:
            assert oxx_type == exp_type | (OFPXXC_EXPERIMENTER << 7)
            exp_hdr_pack_str = '!I'  # experimenter_id
            msg_pack_into(exp_hdr_pack_str, exp_hdr, 0,
                          desc.experimenter_id)
        assert len(exp_hdr) == struct.calcsize(exp_hdr_pack_str)
        n = oxx_type
        assert (n >> 7) == OFPXXC_EXPERIMENTER
    return n, exp_hdr


def _serialize_header(oxx, mod, n, buf, offset):
    try:
        get_desc = getattr(mod, '_' + oxx + '_field_desc')
        desc = get_desc(n)
        value_len = desc.type.size
    except KeyError:
        value_len = 0
    n, exp_hdr = _make_exp_hdr(oxx, mod, n)
    exp_hdr_len = len(exp_hdr)
    pack_str = "!I%ds" % (exp_hdr_len,)
    msg_pack_into(pack_str, buf, offset,
                  (n << 9) | (0 << 8) | (exp_hdr_len + value_len),
                  bytes(exp_hdr))
    return struct.calcsize(pack_str)


def _serialize(oxx, mod, n, value, mask, buf, offset):
    n, exp_hdr = _make_exp_hdr(oxx, mod, n)
    exp_hdr_len = len(exp_hdr)
    value_len = len(value)
    if mask:
        assert value_len == len(mask)
        pack_str = "!I%ds%ds%ds" % (exp_hdr_len, value_len, len(mask))
        msg_pack_into(pack_str, buf, offset,
                      (n << 9) | (1 << 8) | (exp_hdr_len + value_len * 2),
                      bytes(exp_hdr), value, mask)
    else:
        pack_str = "!I%ds%ds" % (exp_hdr_len, value_len,)
        msg_pack_into(pack_str, buf, offset,
                      (n << 9) | (0 << 8) | (exp_hdr_len + value_len),
                      bytes(exp_hdr), value)
    return struct.calcsize(pack_str)
