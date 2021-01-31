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

# NOTE: OpenFlow Spec 1.5 mandates that Experimenter OXMs encode
# the experimenter type in the oxm_field field of the OXM header
# (EXT-380).

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

from ryu.ofproto.oxx_fields import (
    _get_field_info_by_name,
    _from_user,
    _from_user_header,
    _to_user,
    _to_user_header,
    _field_desc,
    _normalize_user,
    _parse,
    _parse_header,
    _serialize,
    _serialize_header)
from ryu.ofproto import ofproto_common


OFPXMC_NXM_0 = 0  # Nicira Extended Match (NXM_OF_)
OFPXMC_NXM_1 = 1  # Nicira Extended Match (NXM_NX_)
OFPXMC_OPENFLOW_BASIC = 0x8000
OFPXMC_PACKET_REGS = 0x8001
OFPXMC_EXPERIMENTER = 0xffff


class _OxmClass(object):
    def __init__(self, name, num, type_):
        self.name = name
        self.oxm_field = num
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
        self.exp_type = self.oxm_field


class ONFExperimenter(_Experimenter):
    experimenter_id = ofproto_common.ONF_EXPERIMENTER_ID


class OldONFExperimenter(_Experimenter):
    # This class is for the old version of EXT-256
    experimenter_id = ofproto_common.ONF_EXPERIMENTER_ID

    def __init__(self, name, num, type_):
        super(OldONFExperimenter, self).__init__(name, 0, type_)
        self.num = (self.experimenter_id, num)
        self.exp_type = 2560


class NiciraExperimenter(_Experimenter):
    experimenter_id = ofproto_common.NX_EXPERIMENTER_ID


class NiciraNshExperimenter(_Experimenter):
    experimenter_id = ofproto_common.NX_NSH_EXPERIMENTER_ID


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
    import functools

    mod = sys.modules[modname]

    def add_attr(k, v):
        setattr(mod, k, v)

    for i in mod.oxm_types:
        if isinstance(i.num, tuple):
            continue
        if i._class != OFPXMC_OPENFLOW_BASIC:
            continue
        uk = i.name.upper()
        ofpxmt = i.oxm_field
        td = i.type
        add_attr('OFPXMT_OFB_' + uk, ofpxmt)
        add_attr('OXM_OF_' + uk, mod.oxm_tlv_header(ofpxmt, td.size))
        add_attr('OXM_OF_' + uk + '_W', mod.oxm_tlv_header_w(ofpxmt, td.size))

    # 'oxx' indicates the OpenFlow Extensible class type.
    # eg.) 'oxm' indicates that this class is OXM class.
    oxx = 'oxm'
    name_to_field = dict((f.name, f) for f in mod.oxm_types)
    num_to_field = dict((f.num, f) for f in mod.oxm_types)

    # create functions by using oxx_fields module.
    add_attr('oxm_get_field_info_by_name',
             functools.partial(_get_field_info_by_name, oxx, name_to_field))
    add_attr('oxm_from_user',
             functools.partial(_from_user, oxx, name_to_field))
    add_attr('oxm_from_user_header',
             functools.partial(_from_user_header, oxx, name_to_field))
    add_attr('oxm_to_user',
             functools.partial(_to_user, oxx, num_to_field))
    add_attr('oxm_to_user_header',
             functools.partial(_to_user_header, oxx, num_to_field))
    add_attr('_oxm_field_desc',  # oxx is not required
             functools.partial(_field_desc, num_to_field))
    add_attr('oxm_normalize_user',
             functools.partial(_normalize_user, oxx, mod))
    add_attr('oxm_parse',  # oxx is not required
             functools.partial(_parse, mod))
    add_attr('oxm_parse_header',  # oxx is not required
             functools.partial(_parse_header, mod))
    add_attr('oxm_serialize',
             functools.partial(_serialize, oxx, mod))
    add_attr('oxm_serialize_header',
             functools.partial(_serialize_header, oxx, mod))

    add_attr('oxm_to_jsondict', _to_jsondict)
    add_attr('oxm_from_jsondict', _from_jsondict)


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
