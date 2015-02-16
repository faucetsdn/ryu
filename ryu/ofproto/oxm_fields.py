# Copyright (C) 2013-2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013-2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# There are two types of OXM/NXM headers.
#
# 32-bit OXM/NXM header
# +-------------------------------+-------------+-+---------------+
# | class                         | field       |m| length        |
# +-------------------------------+-------------+-+---------------+
#
# 64-bit experimenter OXM header
# +-------------------------------+-------------+-+---------------+
# | class (OFPXMC_EXPERIMENTER)   | field       |m| length        |
# +-------------------------------+-------------+-+---------------+
# | experimenter ID                                               |
# +---------------------------------------------------------------+

# NOTE: EXT-256 had a variation of experimenter OXM header.
# It has been rectified since then.  Currently this implementation
# supports only the old version.
#
# ONF EXT-256 (old, exp_type = 2560)
# +-------------------------------+-------------+-+---------------+
# | class (OFPXMC_EXPERIMENTER)   | ?????       |m| length        |
# +-------------------------------+-------------+-+---------------+
# | experimenter ID (ONF_EXPERIMENTER_ID)                         |
# +-------------------------------+---------------+---------------+
# | exp_type (PBB_UCA=2560)       | pbb_uca       |
# +-------------------------------+---------------+
#
# ONF EXT-256 (new, oxm_field = 41)
# +-------------------------------+-------------+-+---------------+
# | class (OFPXMC_EXPERIMENTER)   | PBB_UCA=41  |m| length        |
# +-------------------------------+-------------+-+---------------+
# | experimenter ID (ONF_EXPERIMENTER_ID)                         |
# +-------------------------------+---------------+---------------+
# | reserved, should be zero      | pbb_uca       |
# +-------------------------------+---------------+

import itertools
import struct
import ofproto_common
from ryu.lib.pack_utils import msg_pack_into
from ryu.lib import type_desc


OFPXMC_NXM_0 = 0  # Nicira Extended Match (NXM_OF_)
OFPXMC_NXM_1 = 1  # Nicira Extended Match (NXM_NX_)
OFPXMC_OPENFLOW_BASIC = 0x8000
OFPXMC_PACKET_REGS = 0x8001
OFPXMC_EXPERIMENTER = 0xffff


class _OxmClass(object):
    def __init__(self, name, num, type_):
        self.name = name
        self.oxm_type = num | (self._class << 7)
        # TODO(yamamoto): Clean this up later.
        # Probably when we drop EXT-256 style experimenter OXMs.
        self.num = self.oxm_type
        self.type = type_


class OpenFlowBasic(_OxmClass):
    _class = OFPXMC_OPENFLOW_BASIC


class PacketRegs(_OxmClass):
    _class = OFPXMC_PACKET_REGS


class _Experimenter(_OxmClass):
    _class = OFPXMC_EXPERIMENTER

    def __init__(self, name, num, type_):
        super(_Experimenter, self).__init__(name, num, type_)
        self.num = (self.experimenter_id, self.oxm_type)


class ONFExperimenter(_Experimenter):
    experimenter_id = ofproto_common.ONF_EXPERIMENTER_ID


class OldONFExperimenter(_Experimenter):
    # This class is for the old version of EXT-256
    experimenter_id = ofproto_common.ONF_EXPERIMENTER_ID

    def __init__(self, name, num, type_):
        super(OldONFExperimenter, self).__init__(name, 0, type_)
        self.num = (self.experimenter_id, num)
        self.exp_type = num


class NiciraExperimenter(_Experimenter):
    experimenter_id = ofproto_common.NX_EXPERIMENTER_ID


class NiciraExtended0(_OxmClass):
    """Nicira Extended Match (NXM_0)

    NXM header format is same as 32-bit (non-experimenter) OXMs.
    """

    _class = OFPXMC_NXM_0


class NiciraExtended1(_OxmClass):
    """Nicira Extended Match (NXM_1)

    NXM header format is same as 32-bit (non-experimenter) OXMs.
    """

    _class = OFPXMC_NXM_1


def generate(modname):
    import sys
    import string
    import functools

    mod = sys.modules[modname]

    def add_attr(k, v):
        setattr(mod, k, v)

    for i in mod.oxm_types:
        uk = string.upper(i.name)
        if isinstance(i.num, tuple):
            continue
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
    add_attr('oxm_from_user', functools.partial(_from_user, name_to_field))
    add_attr('oxm_from_user_header',
             functools.partial(_from_user_header, name_to_field))
    add_attr('oxm_to_user', functools.partial(_to_user, num_to_field))
    add_attr('oxm_to_user_header',
             functools.partial(_to_user_header, num_to_field))
    add_attr('_oxm_field_desc', functools.partial(_field_desc, num_to_field))
    add_attr('oxm_normalize_user', functools.partial(_normalize_user, mod))
    add_attr('oxm_parse', functools.partial(_parse, mod))
    add_attr('oxm_parse_header', functools.partial(_parse_header, mod))
    add_attr('oxm_serialize', functools.partial(_serialize, mod))
    add_attr('oxm_serialize_header', functools.partial(_serialize_header, mod))
    add_attr('oxm_to_jsondict', _to_jsondict)
    add_attr('oxm_from_jsondict', _from_jsondict)


def _get_field_info_by_name(name_to_field, name):
    try:
        f = name_to_field[name]
        t = f.type
        num = f.num
    except KeyError:
        t = type_desc.UnknownType
        if name.startswith('field_'):
            num = int(name.split('_')[1])
        else:
            raise KeyError('unknown match field ' + name)
    return num, t


def _from_user_header(name_to_field, name):
    (num, t) = _get_field_info_by_name(name_to_field, name)
    return num


def _from_user(name_to_field, name, user_value):
    (num, t) = _get_field_info_by_name(name_to_field, name)
    # the 'list' case below is a bit hack; json.dumps silently maps
    # python tuples into json lists.
    if isinstance(user_value, (tuple, list)):
        (value, mask) = user_value
    else:
        value = user_value
        mask = None
    if value is not None:
        value = t.from_user(value)
    if mask is not None:
        mask = t.from_user(mask)
    return num, value, mask


def _get_field_info_by_number(num_to_field, n):
    try:
        f = num_to_field[n]
        t = f.type
        name = f.name
    except KeyError:
        t = type_desc.UnknownType
        name = 'field_%d' % (n,)
    return name, t


def _to_user_header(num_to_field, n):
    (name, t) = _get_field_info_by_number(num_to_field, n)
    return name


def _to_user(num_to_field, n, v, m):
    (name, t) = _get_field_info_by_number(num_to_field, n)
    if v is not None:
        if hasattr(t, 'size') and t.size != len(v):
            raise Exception(
                'Unexpected OXM payload length %d for %s (expected %d)'
                % (len(v), name, t.size))
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


def _normalize_user(mod, k, uv):
    (n, v, m) = mod.oxm_from_user(k, uv)
    # apply mask
    if m is not None:
        v = ''.join(chr(ord(x) & ord(y)) for (x, y) in itertools.izip(v, m))
    (k2, uv2) = mod.oxm_to_user(n, v, m)
    assert k2 == k
    return (k2, uv2)


def _parse_header_impl(mod, buf, offset):
    hdr_pack_str = '!I'
    (header, ) = struct.unpack_from(hdr_pack_str, buf, offset)
    hdr_len = struct.calcsize(hdr_pack_str)
    oxm_type = header >> 9  # class|field
    oxm_hasmask = mod.oxm_tlv_header_extract_hasmask(header)
    oxm_class = oxm_type >> 7
    oxm_length = header & 0xff
    if oxm_class == OFPXMC_EXPERIMENTER:
        # Experimenter OXMs have 64-bit header.  (vs 32-bit for other OXMs)
        exp_hdr_pack_str = '!I'  # experimenter_id
        (exp_id, ) = struct.unpack_from(exp_hdr_pack_str, buf,
                                        offset + hdr_len)
        exp_hdr_len = struct.calcsize(exp_hdr_pack_str)
        assert exp_hdr_len == 4
        oxm_field = oxm_type & 0x7f
        if exp_id == ofproto_common.ONF_EXPERIMENTER_ID and oxm_field == 0:
            # XXX
            # This block implements EXT-256 style experimenter OXM.
            onf_exp_type_pack_str = '!H'
            (exp_type, ) = struct.unpack_from(onf_exp_type_pack_str, buf,
                                              offset + hdr_len + exp_hdr_len)
            exp_hdr_len += struct.calcsize(onf_exp_type_pack_str)
            assert exp_hdr_len == 4 + 2
            num = (exp_id, exp_type)
        else:
            num = (exp_id, oxm_type)
    else:
        num = oxm_type
        exp_hdr_len = 0
    value_len = oxm_length - exp_hdr_len
    if oxm_hasmask:
        value_len /= 2
    assert value_len > 0
    field_len = hdr_len + oxm_length
    total_hdr_len = hdr_len + exp_hdr_len
    return num, total_hdr_len, oxm_hasmask, value_len, field_len


def _parse_header(mod, buf, offset):
    (oxm_type_num, total_hdr_len, hasmask, value_len,
     field_len) = _parse_header_impl(mod, buf, offset)
    return oxm_type_num, field_len - value_len


def _parse(mod, buf, offset):
    (oxm_type_num, total_hdr_len, hasmask, value_len,
     field_len) = _parse_header_impl(mod, buf, offset)
    # Note: OXM payload length (oxm_len) includes Experimenter ID (exp_hdr_len)
    # for experimenter OXMs.
    value_offset = offset + total_hdr_len
    value_pack_str = '!%ds' % value_len
    assert struct.calcsize(value_pack_str) == value_len
    (value, ) = struct.unpack_from(value_pack_str, buf, value_offset)
    if hasmask:
        (mask, ) = struct.unpack_from(value_pack_str, buf,
                                      value_offset + value_len)
    else:
        mask = None
    return oxm_type_num, value, mask, field_len


def _make_exp_hdr(mod, n):
    exp_hdr = bytearray()
    try:
        desc = mod._oxm_field_desc(n)
    except KeyError:
        return n, exp_hdr
    if isinstance(desc, _Experimenter):  # XXX
        (exp_id, exp_type) = n
        assert desc.experimenter_id == exp_id
        if isinstance(desc, OldONFExperimenter):  # XXX
            # XXX
            # This block implements EXT-256 style experimenter OXM.
            exp_hdr_pack_str = '!IH'  # experimenter_id, exp_type
            msg_pack_into(exp_hdr_pack_str, exp_hdr, 0,
                          desc.experimenter_id, desc.exp_type)
        else:
            assert desc.oxm_type == exp_type
            exp_hdr_pack_str = '!I'  # experimenter_id
            msg_pack_into(exp_hdr_pack_str, exp_hdr, 0,
                          desc.experimenter_id)
        assert len(exp_hdr) == struct.calcsize(exp_hdr_pack_str)
        n = desc.oxm_type
        assert (n >> 7) == OFPXMC_EXPERIMENTER
    return n, exp_hdr


def _serialize_header(mod, n, buf, offset):
    try:
        desc = mod._oxm_field_desc(n)
        value_len = desc.type.size
    except KeyError:
        value_len = 0
    n, exp_hdr = _make_exp_hdr(mod, n)
    exp_hdr_len = len(exp_hdr)
    pack_str = "!I%ds" % (exp_hdr_len,)
    msg_pack_into(pack_str, buf, offset,
                  (n << 9) | (0 << 8) | (exp_hdr_len + value_len),
                  bytes(exp_hdr))
    return struct.calcsize(pack_str)


def _serialize(mod, n, value, mask, buf, offset):
    n, exp_hdr = _make_exp_hdr(mod, n)
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


def _to_jsondict(k, uv):
    if isinstance(uv, tuple):
        (value, mask) = uv
    else:
        value = uv
        mask = None
    return {"OXMTlv": {"field": k, "value": value, "mask": mask}}


def _from_jsondict(j):
    tlv = j['OXMTlv']
    field = tlv['field']
    value = tlv['value']
    mask = tlv.get('mask')
    if mask is None:
        uv = value
    else:
        uv = (value, mask)
    return (field, uv)
