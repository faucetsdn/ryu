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

# there are two representations of value which this module deal with.
#
# "user"
#   the readable value which are strings.
#
# "internal"
#   the on-wire bytes value.

# There are two types of OXS headers.
#
# 32-bit OXS header
#  31                           16 15          9 8 7             0
# +-------------------------------+-------------+-+---------------+
# | class                         | field       |r| length        |
# +-------------------------------+-------------+-+---------------+
#
# 64-bit experimenter OXS header
#  31                           16 15          9 8 7             0
# +-------------------------------+-------------+-+---------------+
# | class (OFPXSC_EXPERIMENTER)   | field       |r| length        |
# +-------------------------------+-------------+-+---------------+
# | experimenter ID                                               |
# +---------------------------------------------------------------+
#
# Description of OXS header fields
# +----------------------+-------+--------------------------------------------+
# | Name                 | Width | Usage                                      |
# +----------+-----------+-------+--------------------------------------------+
# | oxs_type | oxs_class | 16    | Stat class: member class or reserved class |
# |          +-----------+-------+--------------------------------------------+
# |          | oxs_field | 7     | Stat field within the class                |
# +----------+-----------+-------+--------------------------------------------+
# | reserved             | 1     | Reserved for future use                    |
# +----------------------+-------+--------------------------------------------+
# | length               | 8     | Length of OXS payload                      |
# +----------------------+-------+--------------------------------------------+

# Assumption: The followings can be applied for OXSs too.
# OpenFlow Spec 1.5 mandates that Experimenter OXMs encode the experimenter
# type in the oxm_field field of the OXM header (EXT-380).

from ryu.ofproto.oxx_fields import (
    _from_user,
    _from_user_header,
    _to_user,
    _to_user_header,
    _field_desc,
    _parse,
    _parse_header,
    _serialize,
    _serialize_header)


OFPXSC_OPENFLOW_BASIC = 0x8002
OFPXSC_EXPERIMENTER = 0xFFFF


OFPXSC_HEADER_PACK_STR = '!I'
OFPXSC_EXP_HEADER_PACK_STR = '!I'


class _OxsClass(object):
    # _class = OFPXSC_* must be an attribute of subclass.
    def __init__(self, name, num, type_):
        self.name = name
        self.oxs_field = num
        self.oxs_type = num | (self._class << 7)
        # 'num' has not corresponding field in the specification.
        # This is specific to this implementation and used to retrieve
        # _OxsClass subclass from 'num_to_field' dictionary.
        self.num = self.oxs_type
        self.type = type_


class OpenFlowBasic(_OxsClass):
    _class = OFPXSC_OPENFLOW_BASIC


class _Experimenter(_OxsClass):
    _class = OFPXSC_EXPERIMENTER
    # experimenter_id must be an attribute of subclass.

    def __init__(self, name, num, type_):
        super(_Experimenter, self).__init__(name, num, type_)
        self.num = (self.experimenter_id, self.oxs_type)
        self.exp_type = self.oxs_field


def generate(modname):
    import sys
    import functools

    mod = sys.modules[modname]

    def add_attr(k, v):
        setattr(mod, k, v)

    for i in mod.oxs_types:
        if isinstance(i.num, tuple):
            continue
        if i._class != OFPXSC_OPENFLOW_BASIC:
            continue
        uk = i.name.upper()
        ofpxst = i.oxs_field
        td = i.type
        add_attr('OFPXST_OFB_' + uk, ofpxst)
        add_attr('OXS_OF_' + uk, mod.oxs_tlv_header(ofpxst, td.size))

    # 'oxx' indicates the OpenFlow Extensible class type.
    # eg.) 'oxs' indicates that this class is OXS class.
    oxx = 'oxs'
    name_to_field = dict((f.name, f) for f in mod.oxs_types)
    num_to_field = dict((f.num, f) for f in mod.oxs_types)

    # create functions by using oxx_fields module.
    add_attr('oxs_from_user',
             functools.partial(_from_user, oxx, name_to_field))
    add_attr('oxs_from_user_header',
             functools.partial(_from_user_header, oxx, name_to_field))
    add_attr('oxs_to_user',
             functools.partial(_to_user, oxx, num_to_field))
    add_attr('oxs_to_user_header',
             functools.partial(_to_user_header, oxx, num_to_field))
    add_attr('_oxs_field_desc',  # oxx is not required
             functools.partial(_field_desc, num_to_field))
    add_attr('oxs_parse',  # oxx is not required
             functools.partial(_parse, mod))
    add_attr('oxs_parse_header',  # oxx is not required
             functools.partial(_parse_header, mod))
    add_attr('oxs_serialize',
             functools.partial(_serialize, oxx, mod))
    add_attr('oxs_serialize_header',
             functools.partial(_serialize_header, oxx, mod))

    add_attr('oxs_to_jsondict', _to_jsondict)
    add_attr('oxs_from_jsondict', _from_jsondict)


def _to_jsondict(k, uv):
    return {"OXSTlv": {"field": k, "value": uv}}


def _from_jsondict(j):
    tlv = j['OXSTlv']
    field = tlv['field']
    value = tlv['value']
    return (field, value)
