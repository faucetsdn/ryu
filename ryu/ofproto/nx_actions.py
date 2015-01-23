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

import struct

from ryu import utils
from ryu.ofproto import nicira_ext
from ryu.ofproto import ofproto_common
from ryu.ofproto.ofproto_parser import msg_pack_into


def generate(ofp_name, ofpp_name):
    import sys
    import string
    import functools

    ofp = sys.modules[ofp_name]
    ofpp = sys.modules[ofpp_name]

    class NXAction(ofpp.OFPActionExperimenter):
        _fmt_str = '!H'  # subtype
        _subtypes = {}
        experimenter = ofproto_common.NX_EXPERIMENTER_ID

        def __init__(self):
            super(NXAction, self).__init__(experimenter=self.experimenter)
            self.subtype = self.subtype

        @classmethod
        def parse(cls, buf):
            fmt_str = NXAction._fmt_str
            (subtype,) = struct.unpack_from(fmt_str, buf, 0)
            subtype_cls = cls._subtypes.get(subtype)
            rest = buf[struct.calcsize(fmt_str):]
            if subtype_cls is None:
                return NXActionUnknown(subtype, rest)
            return subtype_cls.parse(rest)

        def serialize(self, buf, offset):
            super(NXAction, self).serialize(buf, offset)
            msg_pack_into(NXAction._fmt_str,
                          buf,
                          offset + ofp.OFP_ACTION_EXPERIMENTER_HEADER_SIZE,
                          self.subtype)

        @classmethod
        def register(cls, subtype_cls):
            assert subtype_cls.subtype is not cls._subtypes
            cls._subtypes[subtype_cls.subtype] = subtype_cls

    class NXActionUnknown(NXAction):
        def __init__(self, subtype, data=None,
                     type_=None, len_=None, experimenter=None):
            super(NXActionUnknown, self).__init__()
            self.data = data

        @classmethod
        def parse(cls, subtype, buf):
            return cls(data=buf)

        def serialize(self, buf, offset):
            # fixup
            data = self.data
            if data is None:
                data = bytearray()
            payload_offset = (
                ofp.OFP_ACTION_EXPERIMENTER_HEADER_SIZE +
                struct.calcsize(NXAction._fmt_str)
            )
            self.len = utils.round_up(payload_offset + len(data), 8)
            super(NXActionUnknown, self).serialize(buf, offset)
            buf += data

    class NXActionRegMove(NXAction):
        subtype = nicira_ext.NXAST_REG_MOVE
        _fmt_str = '!HHH'  # n_bits, src_ofs, dst_ofs
        # Followed by OXM fields (src, dst) and padding to 8 bytes boundary

        def __init__(self, src_field, dst_field, n_bits, src_ofs=0, dst_ofs=0,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionRegMove, self).__init__()
            self.n_bits = n_bits
            self.src_ofs = src_ofs
            self.dst_ofs = dst_ofs
            self.src_field = src_field
            self.dst_field = dst_field

        @classmethod
        def parse(cls, buf):
            (n_bits, src_ofs, dst_ofs,) = struct.unpack_from(
                NXActionRegMove._fmt_str, buf, 0)
            rest = buf[struct.calcsize(NXActionRegMove._fmt_str):]
            # src field
            (n, len) = ofp.oxm_parse_header(rest, 0)
            src_field = ofp.oxm_to_user_header(n)
            rest = rest[len:]
            # dst field
            (n, len) = ofp.oxm_parse_header(rest, 0)
            dst_field = ofp.oxm_to_user_header(n)
            rest = rest[len:]
            # ignore padding
            return cls(src_field, dst_field=dst_field, n_bits=n_bits,
                       src_ofs=src_ofs, dst_ofs=dst_ofs)

        def serialize(self, buf, offset):
            # fixup
            data = bytearray()
            msg_pack_into(NXActionRegMove._fmt_str, data, 0,
                          self.n_bits, self.src_ofs, self.dst_ofs)
            # src field
            n = ofp.oxm_from_user_header(self.src_field)
            ofp.oxm_serialize_header(n, data, len(data))
            # dst field
            n = ofp.oxm_from_user_header(self.dst_field)
            ofp.oxm_serialize_header(n, data, len(data))
            payload_offset = (
                ofp.OFP_ACTION_EXPERIMENTER_HEADER_SIZE +
                struct.calcsize(NXAction._fmt_str)
            )
            self.len = utils.round_up(payload_offset + len(data), 8)
            super(NXActionRegMove, self).serialize(buf, offset)
            msg_pack_into('!%ds' % len(data), buf, offset + payload_offset,
                          bytes(data))

    def add_attr(k, v):
        setattr(ofpp, k, v)

    add_attr('NXAction', NXAction)
    add_attr('NXActionUnknown', NXActionUnknown)

    actions = [
        'NXActionRegMove',
    ]
    vars = locals()
    for a in actions:
        cls = vars[a]
        add_attr(a, cls)
        NXAction.register(cls)
