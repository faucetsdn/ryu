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

import struct

from ryu import utils
from ryu.lib import type_desc
from ryu.ofproto import nicira_ext
from ryu.ofproto import ofproto_common
from ryu.lib.pack_utils import msg_pack_into
from ryu.ofproto.ofproto_parser import StringifyMixin


def generate(ofp_name, ofpp_name):
    import sys

    ofp = sys.modules[ofp_name]
    ofpp = sys.modules[ofpp_name]

    class _NXFlowSpec(StringifyMixin):
        _hdr_fmt_str = '!H'  # 2 bit 0s, 1 bit src, 2 bit dst, 11 bit n_bits
        _dst_type = None
        _subclasses = {}
        _TYPE = {
            'nx-flow-spec-field': [
                'src',
                'dst',
            ]
        }

        def __init__(self, src, dst, n_bits):
            self.src = src
            self.dst = dst
            self.n_bits = n_bits

        @classmethod
        def register(cls, subcls):
            assert issubclass(subcls, cls)
            assert subcls._dst_type not in cls._subclasses
            cls._subclasses[subcls._dst_type] = subcls

        @classmethod
        def parse(cls, buf):
            (hdr,) = struct.unpack_from(cls._hdr_fmt_str, buf, 0)
            rest = buf[struct.calcsize(cls._hdr_fmt_str):]
            if hdr == 0:
                return None, rest  # all-0 header is no-op for padding
            src_type = (hdr >> 13) & 0x1
            dst_type = (hdr >> 11) & 0x3
            n_bits = hdr & 0x3ff
            subcls = cls._subclasses[dst_type]
            if src_type == 0:  # subfield
                src = cls._parse_subfield(rest)
                rest = rest[6:]
            elif src_type == 1:  # immediate
                src_len = (n_bits + 15) // 16 * 2
                src_bin = rest[:src_len]
                src = type_desc.IntDescr(size=src_len).to_user(src_bin)
                rest = rest[src_len:]
            if dst_type == 0:  # match
                dst = cls._parse_subfield(rest)
                rest = rest[6:]
            elif dst_type == 1:  # load
                dst = cls._parse_subfield(rest)
                rest = rest[6:]
            elif dst_type == 2:  # output
                dst = ''  # empty
            return subcls(src=src, dst=dst, n_bits=n_bits), rest

        def serialize(self):
            buf = bytearray()
            if isinstance(self.src, tuple):
                src_type = 0  # subfield
            else:
                src_type = 1  # immediate
            # header
            val = (src_type << 13) | (self._dst_type << 11) | self.n_bits
            msg_pack_into(self._hdr_fmt_str, buf, 0, val)
            # src
            if src_type == 0:  # subfield
                buf += self._serialize_subfield(self.src)
            elif src_type == 1:  # immediate
                src_len = (self.n_bits + 15) // 16 * 2
                buf += type_desc.IntDescr(size=src_len).from_user(self.src)
            # dst
            if self._dst_type == 0:  # match
                buf += self._serialize_subfield(self.dst)
            elif self._dst_type == 1:  # load
                buf += self._serialize_subfield(self.dst)
            elif self._dst_type == 2:  # output
                pass  # empty
            return buf

        @staticmethod
        def _parse_subfield(buf):
            (n, len) = ofp.oxm_parse_header(buf, 0)
            assert len == 4  # only 4-bytes NXM/OXM are defined
            field = ofp.oxm_to_user_header(n)
            rest = buf[len:]
            (ofs,) = struct.unpack_from('!H', rest, 0)
            return (field, ofs)

        @staticmethod
        def _serialize_subfield(subfield):
            (field, ofs) = subfield
            buf = bytearray()
            n = ofp.oxm_from_user_header(field)
            ofp.oxm_serialize_header(n, buf, 0)
            assert len(buf) == 4  # only 4-bytes NXM/OXM are defined
            msg_pack_into('!H', buf, 4, ofs)
            return buf

    class NXFlowSpecMatch(_NXFlowSpec):
        # Add a match criteria
        # an example of the corresponding ovs-ofctl syntax:
        #    NXM_OF_VLAN_TCI[0..11]
        _dst_type = 0

    class NXFlowSpecLoad(_NXFlowSpec):
        # Add NXAST_REG_LOAD actions
        # an example of the corresponding ovs-ofctl syntax:
        #    NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[]
        _dst_type = 1

    class NXFlowSpecOutput(_NXFlowSpec):
        # Add an OFPAT_OUTPUT action
        # an example of the corresponding ovs-ofctl syntax:
        #    output:NXM_OF_IN_PORT[]
        _dst_type = 2

        def __init__(self, src, n_bits, dst=''):
            assert dst == ''
            super(NXFlowSpecOutput, self).__init__(src=src, dst=dst,
                                                   n_bits=n_bits)

    class NXAction(ofpp.OFPActionExperimenter):
        _fmt_str = '!H'  # subtype
        _subtypes = {}
        _experimenter = ofproto_common.NX_EXPERIMENTER_ID

        def __init__(self):
            super(NXAction, self).__init__(self._experimenter)
            self.subtype = self._subtype

        @classmethod
        def parse(cls, buf):
            fmt_str = NXAction._fmt_str
            (subtype,) = struct.unpack_from(fmt_str, buf, 0)
            subtype_cls = cls._subtypes.get(subtype)
            rest = buf[struct.calcsize(fmt_str):]
            if subtype_cls is None:
                return NXActionUnknown(subtype, rest)
            return subtype_cls.parser(rest)

        def serialize(self, buf, offset):
            data = self.serialize_body()
            payload_offset = (
                ofp.OFP_ACTION_EXPERIMENTER_HEADER_SIZE +
                struct.calcsize(NXAction._fmt_str)
            )
            self.len = utils.round_up(payload_offset + len(data), 8)
            super(NXAction, self).serialize(buf, offset)
            msg_pack_into(NXAction._fmt_str,
                          buf,
                          offset + ofp.OFP_ACTION_EXPERIMENTER_HEADER_SIZE,
                          self.subtype)
            buf += data

        @classmethod
        def register(cls, subtype_cls):
            assert subtype_cls._subtype is not cls._subtypes
            cls._subtypes[subtype_cls._subtype] = subtype_cls

    class NXActionUnknown(NXAction):
        def __init__(self, subtype, data=None,
                     type_=None, len_=None, experimenter=None):
            self._subtype = subtype
            super(NXActionUnknown, self).__init__()
            self.data = data

        @classmethod
        def parser(cls, buf):
            return cls(data=buf)

        def serialize_body(self):
            # fixup
            return bytearray() if self.data is None else self.data

    # For OpenFlow1.0 only
    class NXActionSetQueue(NXAction):
        _subtype = nicira_ext.NXAST_SET_QUEUE

        # queue_id
        _fmt_str = '!2xI'

        def __init__(self, queue_id,
                     type_=None, len_=None, vendor=None, subtype=None):
            super(NXActionSetQueue, self).__init__()
            self.queue_id = queue_id

        @classmethod
        def parser(cls, buf):
            (queue_id,) = struct.unpack_from(cls._fmt_str, buf, 0)
            return cls(queue_id)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0, self.queue_id)
            return data

    class NXActionPopQueue(NXAction):
        _subtype = nicira_ext.NXAST_POP_QUEUE

        _fmt_str = '!6x'

        def __init__(self,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionPopQueue, self).__init__()

        @classmethod
        def parser(cls, buf):
            return cls()

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0)
            return data

    class NXActionRegLoad(NXAction):
        _subtype = nicira_ext.NXAST_REG_LOAD
        _fmt_str = '!HIQ'  # ofs_nbits, dst, value
        _TYPE = {
            'ascii': [
                'dst',
            ]
        }

        def __init__(self, start, end, dst, value,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionRegLoad, self).__init__()
            self.start = start
            self.end = end
            self.dst = dst
            self.value = value

        @classmethod
        def parser(cls, buf):
            (ofs_nbits, dst, value,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            start = ofs_nbits >> 6
            end = (ofs_nbits & 0x3f) + start
            # Right-shift instead of using oxm_parse_header for simplicity...
            dst_name = ofp.oxm_to_user_header(dst >> 9)
            return cls(start, end, dst_name, value)

        def serialize_body(self):
            hdr_data = bytearray()
            n = ofp.oxm_from_user_header(self.dst)
            ofp.oxm_serialize_header(n, hdr_data, 0)
            (dst_num,) = struct.unpack_from('!I', six.binary_type(hdr_data), 0)

            ofs_nbits = (self.start << 6) + (self.end - self.start)
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          ofs_nbits, dst_num, self.value)
            return data

    class NXActionRegLoad2(NXAction):
        _subtype = nicira_ext.NXAST_REG_LOAD2
        _TYPE = {
            'ascii': [
                'dst',
                'value',
            ]
        }

        def __init__(self, dst, value, mask=None,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionRegLoad2, self).__init__()
            self.dst = dst
            self.value = value
            self.mask = mask

        @classmethod
        def parser(cls, buf):
            (n, uv, mask, _len) = ofp.oxm_parse(buf, 0)
            dst, value = ofp.oxm_to_user(n, uv, mask)

            if isinstance(value, (tuple, list)):
                return cls(dst, value[0], value[1])
            else:
                return cls(dst, value, None)

        def serialize_body(self):
            data = bytearray()
            if self.mask is None:
                value = self.value
            else:
                value = (self.value, self.mask)
                self._TYPE['ascii'].append('mask')

            n, value, mask = ofp.oxm_from_user(self.dst, value)
            len_ = ofp.oxm_serialize(n, value, mask, data, 0)
            msg_pack_into("!%dx" % (14 - len_), data, len_)

            return data

    class NXActionNote(NXAction):
        _subtype = nicira_ext.NXAST_NOTE

        # note
        _fmt_str = '!%dB'

        # set the integer array in a note
        def __init__(self,
                     note,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionNote, self).__init__()
            self.note = note

        @classmethod
        def parser(cls, buf):
            note = struct.unpack_from(
                cls._fmt_str % len(buf), buf, 0)
            return cls(list(note))

        def serialize_body(self):
            assert isinstance(self.note, (tuple, list))
            for n in self.note:
                assert isinstance(n, six.integer_types)

            pad = (len(self.note) + nicira_ext.NX_ACTION_HEADER_0_SIZE) % 8
            if pad:
                self.note += [0x0 for i in range(8 - pad)]
            note_len = len(self.note)
            data = bytearray()
            msg_pack_into(self._fmt_str % note_len, data, 0,
                          *self.note)
            return data

    class _NXActionSetTunnelBase(NXAction):
        # _subtype, _fmt_str must be attributes of subclass.

        def __init__(self,
                     tun_id,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(_NXActionSetTunnelBase, self).__init__()
            self.tun_id = tun_id

        @classmethod
        def parser(cls, buf):
            (tun_id,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return cls(tun_id)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.tun_id)
            return data

    class NXActionSetTunnel(_NXActionSetTunnelBase):
        _subtype = nicira_ext.NXAST_SET_TUNNEL

        # tun_id
        _fmt_str = '!2xI'

    class NXActionSetTunnel64(_NXActionSetTunnelBase):
        _subtype = nicira_ext.NXAST_SET_TUNNEL64

        # tun_id
        _fmt_str = '!6xQ'

    class NXActionRegMove(NXAction):
        _subtype = nicira_ext.NXAST_REG_MOVE
        _fmt_str = '!HHH'  # n_bits, src_ofs, dst_ofs
        # Followed by OXM fields (src, dst) and padding to 8 bytes boundary
        _TYPE = {
            'ascii': [
                'src_field',
                'dst_field',
            ]
        }

        def __init__(self, src_field, src_start, src_end,
                     dst_field, dst_start, dst_end,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionRegMove, self).__init__()
            self.src_field = src_field
            self.src_start = src_start
            self.src_end = src_end
            self.dst_field = dst_field
            self.dst_start = dst_start
            self.dst_end = dst_end

        @classmethod
        def parser(cls, buf):
            (n_bits, src_ofs, dst_ofs,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            rest = buf[struct.calcsize(NXActionRegMove._fmt_str):]

            src_start = src_ofs
            src_end = src_ofs + n_bits - 1
            dst_start = dst_ofs
            dst_end = dst_ofs + n_bits - 1

            # src field
            (n, len) = ofp.oxm_parse_header(rest, 0)
            src_field = ofp.oxm_to_user_header(n)
            rest = rest[len:]
            # dst field
            (n, len) = ofp.oxm_parse_header(rest, 0)
            dst_field = ofp.oxm_to_user_header(n)
            rest = rest[len:]
            # ignore padding
            return cls(src_field, src_start, src_end,
                       dst_field, dst_start, dst_end)

        def serialize_body(self):
            # fixup
            data = bytearray()
            n_bits = self.src_end - self.src_start + 1
            assert n_bits == self.dst_end - self.dst_start + 1

            msg_pack_into(self._fmt_str, data, 0,
                          n_bits, self.src_start, self.dst_start)
            # src field
            n = ofp.oxm_from_user_header(self.src_field)
            ofp.oxm_serialize_header(n, data, len(data))
            # dst field
            n = ofp.oxm_from_user_header(self.dst_field)
            ofp.oxm_serialize_header(n, data, len(data))
            return data

    class NXActionResubmit(NXAction):
        _subtype = nicira_ext.NXAST_RESUBMIT

        # in_port
        _fmt_str = '!H4x'

        def __init__(self,
                     in_port=0xfff8,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionResubmit, self).__init__()
            self.in_port = in_port

        @classmethod
        def parser(cls, buf):
            (in_port,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return cls(in_port)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.in_port)
            return data

    class NXActionResubmitTable(NXAction):
        _subtype = nicira_ext.NXAST_RESUBMIT_TABLE

        # in_port, table_id
        _fmt_str = '!HB3x'

        def __init__(self,
                     in_port=0xfff8,
                     table_id=0xff,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionResubmitTable, self).__init__()
            self.in_port = in_port
            self.table_id = table_id

        @classmethod
        def parser(cls, buf):
            (in_port,
             table_id) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return cls(in_port, table_id)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.in_port, self.table_id)
            return data

    class NXActionOutputReg(NXAction):
        _subtype = nicira_ext.NXAST_OUTPUT_REG

        # ofs_nbits, src, max_len
        _fmt_str = '!H4sH6x'
        _TYPE = {
            'ascii': [
                'src',
            ]
        }

        def __init__(self,
                     start,
                     end,
                     src,
                     max_len,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionOutputReg, self).__init__()
            self.start = start
            self.end = end
            self.src = src
            self.max_len = max_len

        @classmethod
        def parser(cls, buf):
            (ofs_nbits, oxm_data, max_len) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            start = ofs_nbits >> 6
            end = (ofs_nbits & 0x3f) + start
            (n, len_) = ofp.oxm_parse_header(oxm_data, 0)
            src = ofp.oxm_to_user_header(n)
            return cls(start,
                       end,
                       src,
                       max_len)

        def serialize_body(self):
            data = bytearray()
            src = bytearray()
            ofs_nbits = (self.start << 6) + (self.end - self.start)
            oxm = ofp.oxm_from_user_header(self.src)
            ofp.oxm_serialize_header(oxm, src, 0),
            msg_pack_into(self._fmt_str, data, 0,
                          ofs_nbits,
                          six.binary_type(src),
                          self.max_len)
            return data

    class NXActionOutputReg2(NXAction):
        _subtype = nicira_ext.NXAST_OUTPUT_REG2

        # start, end, src, max_len
        _fmt_str = '!HH4s'
        _TYPE = {
            'ascii': [
                'src',
            ]
        }

        def __init__(self,
                     start,
                     end,
                     src,
                     max_len,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionOutputReg2, self).__init__()
            self.start = start
            self.end = end
            self.src = src
            self.max_len = max_len

        @classmethod
        def parser(cls, buf):
            (ofs_nbits,
             max_len,
             oxm_data) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            start = ofs_nbits >> 6
            end = (ofs_nbits & 0x3f) + start
            (n, len_) = ofp.oxm_parse_header(oxm_data, 0)
            src = ofp.oxm_to_user_header(n)
            return cls(start,
                       end,
                       src,
                       max_len)

        def serialize_body(self):
            data = bytearray()
            oxm_data = bytearray()
            ofs_nbits = (self.start << 6) + (self.end - self.start)
            oxm = ofp.oxm_from_user_header(self.src)
            ofp.oxm_serialize_header(oxm, oxm_data, 0),
            msg_pack_into(self._fmt_str, data, 0,
                          ofs_nbits,
                          self.max_len,
                          six.binary_type(oxm_data))
            offset = len(data)
            msg_pack_into("!%dx" % (14 - offset), data, offset)
            return data

    class NXActionLearn(NXAction):
        _subtype = nicira_ext.NXAST_LEARN

        # idle_timeout, hard_timeout, priority, cookie, flags,
        # table_id, pad, fin_idle_timeout, fin_hard_timeout
        _fmt_str = '!HHHQHBxHH'
        # Followed by flow_mod_specs

        def __init__(self,
                     table_id,
                     specs,
                     idle_timeout=0,
                     hard_timeout=0,
                     priority=ofp.OFP_DEFAULT_PRIORITY,
                     cookie=0,
                     flags=0,
                     fin_idle_timeout=0,
                     fin_hard_timeout=0,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionLearn, self).__init__()
            self.idle_timeout = idle_timeout
            self.hard_timeout = hard_timeout
            self.priority = priority
            self.cookie = cookie
            self.flags = flags
            self.table_id = table_id
            self.fin_idle_timeout = fin_idle_timeout
            self.fin_hard_timeout = fin_hard_timeout
            self.specs = specs

        @classmethod
        def parser(cls, buf):
            (idle_timeout,
             hard_timeout,
             priority,
             cookie,
             flags,
             table_id,
             fin_idle_timeout,
             fin_hard_timeout,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            rest = buf[struct.calcsize(cls._fmt_str):]
            # specs
            specs = []
            while len(rest) > 0:
                spec, rest = _NXFlowSpec.parse(rest)
                if spec is None:
                    continue
                specs.append(spec)
            return cls(idle_timeout=idle_timeout,
                       hard_timeout=hard_timeout,
                       priority=priority,
                       cookie=cookie,
                       flags=flags,
                       table_id=table_id,
                       fin_idle_timeout=fin_idle_timeout,
                       fin_hard_timeout=fin_hard_timeout,
                       specs=specs)

        def serialize_body(self):
            # fixup
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.idle_timeout,
                          self.hard_timeout,
                          self.priority,
                          self.cookie,
                          self.flags,
                          self.table_id,
                          self.fin_idle_timeout,
                          self.fin_hard_timeout)
            for spec in self.specs:
                data += spec.serialize()
            return data

    class NXActionExit(NXAction):
        _subtype = nicira_ext.NXAST_EXIT

        _fmt_str = '!6x'

        def __init__(self,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionExit, self).__init__()

        @classmethod
        def parser(cls, buf):
            return cls()

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0)
            return data

    # For OpenFlow1.0 only
    class NXActionDecTtl(NXAction):
        _subtype = nicira_ext.NXAST_DEC_TTL

        _fmt_str = '!6x'

        def __init__(self,
                     type_=None, len_=None, vendor=None, subtype=None):
            super(NXActionDecTtl, self).__init__()

        @classmethod
        def parser(cls, buf):
            return cls()

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0)
            return data

    class NXActionController(NXAction):
        _subtype = nicira_ext.NXAST_CONTROLLER

        # max_len, controller_id, reason
        _fmt_str = '!HHBx'

        def __init__(self,
                     max_len,
                     controller_id,
                     reason,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionController, self).__init__()
            self.max_len = max_len
            self.controller_id = controller_id
            self.reason = reason

        @classmethod
        def parser(cls, buf):
            (max_len,
             controller_id,
             reason) = struct.unpack_from(
                cls._fmt_str, buf)
            return cls(max_len,
                       controller_id,
                       reason)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.max_len,
                          self.controller_id,
                          self.reason)
            return data

    class NXActionController2(NXAction):
        _subtype = nicira_ext.NXAST_CONTROLLER2
        _fmt_str = '!6x'
        _PACK_STR = '!HH'

        def __init__(self,
                     type_=None, len_=None, vendor=None, subtype=None,
                     **kwargs):
            super(NXActionController2, self).__init__()

            for arg in kwargs:
                if arg in NXActionController2Prop._NAMES:
                    setattr(self, arg, kwargs[arg])

        @classmethod
        def parser(cls, buf):
            cls_data = {}
            offset = 6
            buf_len = len(buf)
            while buf_len > offset:
                (type_, length) = struct.unpack_from(cls._PACK_STR, buf, offset)
                offset += 4
                try:
                    subcls = NXActionController2Prop._TYPES[type_]
                except KeyError:
                    subcls = NXActionController2PropUnknown
                data, size = subcls.parser_prop(buf[offset:], length - 4)
                offset += size
                cls_data[subcls._arg_name] = data
            return cls(**cls_data)

        def serialize_body(self):
            body = bytearray()
            msg_pack_into(self._fmt_str, body, 0)
            prop_list = []
            for arg in self.__dict__:
                if arg in NXActionController2Prop._NAMES:
                    prop_list.append((NXActionController2Prop._NAMES[arg],
                                      self.__dict__[arg]))
            prop_list.sort(key=lambda x: x[0].type)

            for subcls, value in prop_list:
                body += subcls.serialize_prop(value)

            return body

    class NXActionController2Prop(object):
        _TYPES = {}
        _NAMES = {}

        @classmethod
        def register_type(cls, type_):
            def _register_type(subcls):
                subcls.type = type_
                NXActionController2Prop._TYPES[type_] = subcls
                NXActionController2Prop._NAMES[subcls._arg_name] = subcls
                return subcls

            return _register_type

    class NXActionController2PropUnknown(NXActionController2Prop):

        @classmethod
        def parser_prop(cls, buf, length):
            size = 4
            return buf, size

        @classmethod
        def serialize_prop(cls, argment):
            data = bytearray()
            return data

    @NXActionController2Prop.register_type(nicira_ext.NXAC2PT_MAX_LEN)
    class NXActionController2PropMaxLen(NXActionController2Prop):
        # max_len
        _fmt_str = "!H2x"
        _arg_name = "max_len"

        @classmethod
        def parser_prop(cls, buf, length):
            size = 4
            (max_len,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return max_len, size

        @classmethod
        def serialize_prop(cls, max_len):
            data = bytearray()
            msg_pack_into("!HHH2x", data, 0,
                          nicira_ext.NXAC2PT_MAX_LEN,
                          8,
                          max_len)
            return data

    @NXActionController2Prop.register_type(nicira_ext.NXAC2PT_CONTROLLER_ID)
    class NXActionController2PropControllerId(NXActionController2Prop):
        # controller_id
        _fmt_str = "!H2x"
        _arg_name = "controller_id"

        @classmethod
        def parser_prop(cls, buf, length):
            size = 4
            (controller_id,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return controller_id, size

        @classmethod
        def serialize_prop(cls, controller_id):
            data = bytearray()
            msg_pack_into("!HHH2x", data, 0,
                          nicira_ext.NXAC2PT_CONTROLLER_ID,
                          8,
                          controller_id)
            return data

    @NXActionController2Prop.register_type(nicira_ext.NXAC2PT_REASON)
    class NXActionController2PropReason(NXActionController2Prop):
        # reason
        _fmt_str = "!B3x"
        _arg_name = "reason"

        @classmethod
        def parser_prop(cls, buf, length):
            size = 4
            (reason,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return reason, size

        @classmethod
        def serialize_prop(cls, reason):
            data = bytearray()
            msg_pack_into("!HHB3x", data, 0,
                          nicira_ext.NXAC2PT_REASON,
                          5,
                          reason)
            return data

    @NXActionController2Prop.register_type(nicira_ext.NXAC2PT_USERDATA)
    class NXActionController2PropUserData(NXActionController2Prop):
        # userdata
        _fmt_str = "!B"
        _arg_name = "userdata"

        @classmethod
        def parser_prop(cls, buf, length):
            userdata = []
            offset = 0

            while offset < length:
                u = struct.unpack_from(cls._fmt_str, buf, offset)
                userdata.append(u[0])
                offset += 1

            user_size = utils.round_up(length, 4)

            if user_size > 4 and (user_size % 8) == 0:
                size = utils.round_up(length, 4) + 4
            else:
                size = utils.round_up(length, 4)

            return userdata, size

        @classmethod
        def serialize_prop(cls, userdata):
            data = bytearray()
            user_buf = bytearray()
            user_offset = 0
            for user in userdata:
                msg_pack_into('!B', user_buf, user_offset,
                              user)
                user_offset += 1

            msg_pack_into("!HH", data, 0,
                          nicira_ext.NXAC2PT_USERDATA,
                          4 + user_offset)
            data += user_buf

            if user_offset > 4:
                user_len = utils.round_up(user_offset, 4)
                brank_size = 0
                if (user_len % 8) == 0:
                    brank_size = 4
                msg_pack_into("!%dx" % (user_len - user_offset + brank_size),
                              data, 4 + user_offset)
            else:
                user_len = utils.round_up(user_offset, 4)

                msg_pack_into("!%dx" % (user_len - user_offset),
                              data, 4 + user_offset)
            return data

    @NXActionController2Prop.register_type(nicira_ext.NXAC2PT_PAUSE)
    class NXActionController2PropPause(NXActionController2Prop):
        _arg_name = "pause"

        @classmethod
        def parser_prop(cls, buf, length):
            pause = True
            size = 4
            return pause, size

        @classmethod
        def serialize_prop(cls, pause):
            data = bytearray()
            msg_pack_into("!HH4x", data, 0,
                          nicira_ext.NXAC2PT_PAUSE,
                          4)
            return data

    class NXActionDecTtlCntIds(NXAction):
        _subtype = nicira_ext.NXAST_DEC_TTL_CNT_IDS

        # controllers
        _fmt_str = '!H4x'
        _fmt_len = 6

        def __init__(self,
                     cnt_ids,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionDecTtlCntIds, self).__init__()

            self.cnt_ids = cnt_ids

        @classmethod
        def parser(cls, buf):
            (controllers,) = struct.unpack_from(
                cls._fmt_str, buf)

            offset = cls._fmt_len
            cnt_ids = []

            for i in range(0, controllers):
                id_ = struct.unpack_from('!H', buf, offset)
                cnt_ids.append(id_[0])
                offset += 2

            return cls(cnt_ids)

        def serialize_body(self):
            assert isinstance(self.cnt_ids, (tuple, list))
            for i in self.cnt_ids:
                assert isinstance(i, six.integer_types)

            controllers = len(self.cnt_ids)

            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          controllers)
            offset = self._fmt_len

            for id_ in self.cnt_ids:
                msg_pack_into('!H', data, offset, id_)
                offset += 2

            id_len = (utils.round_up(controllers, 4) -
                      controllers)

            if id_len != 0:
                msg_pack_into('%dx' % id_len * 2, data, offset)

            return data

    # Use in only OpenFlow1.0
    class NXActionMplsBase(NXAction):
        # ethertype
        _fmt_str = '!H4x'

        def __init__(self,
                     ethertype,
                     type_=None, len_=None, vendor=None, subtype=None):
            super(NXActionMplsBase, self).__init__()
            self.ethertype = ethertype

        @classmethod
        def parser(cls, buf):
            (ethertype,) = struct.unpack_from(
                cls._fmt_str, buf)
            return cls(ethertype)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.ethertype)
            return data

    # For OpenFlow1.0 only
    class NXActionPushMpls(NXActionMplsBase):
        _subtype = nicira_ext.NXAST_PUSH_MPLS

    # For OpenFlow1.0 only
    class NXActionPopMpls(NXActionMplsBase):
        _subtype = nicira_ext.NXAST_POP_MPLS

    # For OpenFlow1.0 only
    class NXActionSetMplsTtl(NXAction):
        _subtype = nicira_ext.NXAST_SET_MPLS_TTL

        # ethertype
        _fmt_str = '!B5x'

        def __init__(self,
                     ttl,
                     type_=None, len_=None, vendor=None, subtype=None):
            super(NXActionSetMplsTtl, self).__init__()
            self.ttl = ttl

        @classmethod
        def parser(cls, buf):
            (ttl,) = struct.unpack_from(
                cls._fmt_str, buf)
            return cls(ttl)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.ttl)
            return data

    # For OpenFlow1.0 only
    class NXActionDecMplsTtl(NXAction):
        _subtype = nicira_ext.NXAST_DEC_MPLS_TTL

        # ethertype
        _fmt_str = '!6x'

        def __init__(self,
                     type_=None, len_=None, vendor=None, subtype=None):
            super(NXActionDecMplsTtl, self).__init__()

        @classmethod
        def parser(cls, buf):
            return cls()

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0)
            return data

    # For OpenFlow1.0 only
    class NXActionSetMplsLabel(NXAction):
        _subtype = nicira_ext.NXAST_SET_MPLS_LABEL

        # ethertype
        _fmt_str = '!2xI'

        def __init__(self,
                     label,
                     type_=None, len_=None, vendor=None, subtype=None):
            super(NXActionSetMplsLabel, self).__init__()
            self.label = label

        @classmethod
        def parser(cls, buf):
            (label,) = struct.unpack_from(
                cls._fmt_str, buf)
            return cls(label)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.label)
            return data

    # For OpenFlow1.0 only
    class NXActionSetMplsTc(NXAction):
        _subtype = nicira_ext.NXAST_SET_MPLS_TC

        # ethertype
        _fmt_str = '!B5x'

        def __init__(self,
                     tc,
                     type_=None, len_=None, vendor=None, subtype=None):
            super(NXActionSetMplsTc, self).__init__()
            self.tc = tc

        @classmethod
        def parser(cls, buf):
            (tc,) = struct.unpack_from(
                cls._fmt_str, buf)
            return cls(tc)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.tc)
            return data

    class NXActionStackBase(NXAction):
        # start, field, end
        _fmt_str = '!H4sH'
        _TYPE = {
            'ascii': [
                'field',
            ]
        }

        def __init__(self,
                     field,
                     start,
                     end,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionStackBase, self).__init__()
            self.field = field
            self.start = start
            self.end = end

        @classmethod
        def parser(cls, buf):
            (start, oxm_data, end) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            (n, len_) = ofp.oxm_parse_header(oxm_data, 0)
            field = ofp.oxm_to_user_header(n)
            return cls(field, start, end)

        def serialize_body(self):
            data = bytearray()
            oxm_data = bytearray()
            oxm = ofp.oxm_from_user_header(self.field)
            ofp.oxm_serialize_header(oxm, oxm_data, 0)
            msg_pack_into(self._fmt_str, data, 0,
                          self.start,
                          six.binary_type(oxm_data),
                          self.end)
            offset = len(data)
            msg_pack_into("!%dx" % (12 - offset), data, offset)
            return data

    class NXActionStackPush(NXActionStackBase):
        _subtype = nicira_ext.NXAST_STACK_PUSH

    class NXActionStackPop(NXActionStackBase):
        _subtype = nicira_ext.NXAST_STACK_POP

    class NXActionSample(NXAction):
        _subtype = nicira_ext.NXAST_SAMPLE

        # probability, collector_set_id, obs_domain_id, obs_point_id
        _fmt_str = '!HIII'

        def __init__(self,
                     probability,
                     collector_set_id=0,
                     obs_domain_id=0,
                     obs_point_id=0,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionSample, self).__init__()
            self.probability = probability
            self.collector_set_id = collector_set_id
            self.obs_domain_id = obs_domain_id
            self.obs_point_id = obs_point_id

        @classmethod
        def parser(cls, buf):
            (probability,
             collector_set_id,
             obs_domain_id,
             obs_point_id) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return cls(probability,
                       collector_set_id,
                       obs_domain_id,
                       obs_point_id)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.probability,
                          self.collector_set_id,
                          self.obs_domain_id,
                          self.obs_point_id)
            return data

    class NXActionFinTimeout(NXAction):
        _subtype = nicira_ext.NXAST_FIN_TIMEOUT

        # fin_idle_timeout, fin_hard_timeout
        _fmt_str = '!HH2x'

        def __init__(self,
                     fin_idle_timeout,
                     fin_hard_timeout,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionFinTimeout, self).__init__()
            self.fin_idle_timeout = fin_idle_timeout
            self.fin_hard_timeout = fin_hard_timeout

        @classmethod
        def parser(cls, buf):
            (fin_idle_timeout,
             fin_hard_timeout) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return cls(fin_idle_timeout,
                       fin_hard_timeout)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.fin_idle_timeout,
                          self.fin_hard_timeout)
            return data

    class NXActionConjunction(NXAction):
        _subtype = nicira_ext.NXAST_CONJUNCTION

        # clause, n_clauses, id
        _fmt_str = '!BBI'

        def __init__(self,
                     clause,
                     n_clauses,
                     id_,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionConjunction, self).__init__()
            self.clause = clause
            self.n_clauses = n_clauses
            self.id = id_

        @classmethod
        def parser(cls, buf):
            (clause,
             n_clauses,
             id_,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            return cls(clause, n_clauses, id_)

        def serialize_body(self):
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.clause,
                          self.n_clauses,
                          self.id)
            return data

    class NXActionMultipath(NXAction):
        _subtype = nicira_ext.NXAST_MULTIPATH

        # fields, basis, algorithm, max_link,
        # arg, ofs_nbits, dst
        _fmt_str = '!HH2xHHI2xH4s'
        _TYPE = {
            'ascii': [
                'dst',
            ]
        }

        def __init__(self,
                     fields,
                     basis,
                     algorithm,
                     max_link,
                     arg,
                     start,
                     end,
                     dst,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionMultipath, self).__init__()
            self.fields = fields
            self.basis = basis
            self.algorithm = algorithm
            self.max_link = max_link
            self.arg = arg
            self.start = start
            self.end = end
            self.dst = dst

        @classmethod
        def parser(cls, buf):
            (fields,
             basis,
             algorithm,
             max_link,
             arg,
             ofs_nbits,
             oxm_data) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            start = ofs_nbits >> 6
            end = (ofs_nbits & 0x3f) + start
            (n, len_) = ofp.oxm_parse_header(oxm_data, 0)
            dst = ofp.oxm_to_user_header(n)
            return cls(fields,
                       basis,
                       algorithm,
                       max_link,
                       arg,
                       start,
                       end,
                       dst)

        def serialize_body(self):
            data = bytearray()
            dst = bytearray()
            ofs_nbits = (self.start << 6) + (self.end - self.start)
            oxm = ofp.oxm_from_user_header(self.dst)
            ofp.oxm_serialize_header(oxm, dst, 0),
            msg_pack_into(self._fmt_str, data, 0,
                          self.fields,
                          self.basis,
                          self.algorithm,
                          self.max_link,
                          self.arg,
                          ofs_nbits,
                          six.binary_type(dst))

            return data

    class _NXActionBundleBase(NXAction):
        # algorithm, fields, basis, slave_type, n_slaves
        # ofs_nbits
        _fmt_str = '!HHHIHH'

        def __init__(self, algorithm, fields, basis, slave_type, n_slaves,
                     start, end, dst, slaves):
            super(_NXActionBundleBase, self).__init__()
            self.len = utils.round_up(
                nicira_ext.NX_ACTION_BUNDLE_0_SIZE + len(slaves) * 2, 8)

            self.algorithm = algorithm
            self.fields = fields
            self.basis = basis
            self.slave_type = slave_type
            self.n_slaves = n_slaves
            self.start = start
            self.end = end
            self.dst = dst

            assert isinstance(slaves, (list, tuple))
            for s in slaves:
                assert isinstance(s, six.integer_types)

            self.slaves = slaves

        @classmethod
        def parser(cls, buf):
            # Add dst ('I') to _fmt_str
            (algorithm, fields, basis,
             slave_type, n_slaves, ofs_nbits, dst) = struct.unpack_from(
                cls._fmt_str + 'I', buf, 0)
            start = ofs_nbits >> 6
            end = (ofs_nbits & 0x3f) + start

            offset = (nicira_ext.NX_ACTION_BUNDLE_0_SIZE -
                      nicira_ext.NX_ACTION_HEADER_0_SIZE - 8)

            if dst != 0:
                (n, len_) = ofp.oxm_parse_header(buf, offset)
                dst = ofp.oxm_to_user_header(n)

            slave_offset = (nicira_ext.NX_ACTION_BUNDLE_0_SIZE -
                            nicira_ext.NX_ACTION_HEADER_0_SIZE)

            slaves = []
            for i in range(0, n_slaves):
                s = struct.unpack_from('!H', buf, slave_offset)
                slaves.append(s[0])
                slave_offset += 2

            return cls(algorithm, fields, basis, slave_type,
                       n_slaves, start, end, dst, slaves)

        def serialize_body(self):
            ofs_nbits = (self.start << 6) + (self.end - self.start)
            data = bytearray()
            slave_offset = (nicira_ext.NX_ACTION_BUNDLE_0_SIZE -
                            nicira_ext.NX_ACTION_HEADER_0_SIZE)
            self.n_slaves = len(self.slaves)
            for s in self.slaves:
                msg_pack_into('!H', data, slave_offset, s)
                slave_offset += 2
            pad_len = (utils.round_up(self.n_slaves, 4) -
                       self.n_slaves)

            if pad_len != 0:
                msg_pack_into('%dx' % pad_len * 2, data, slave_offset)

            msg_pack_into(self._fmt_str, data, 0,
                          self.algorithm, self.fields, self.basis,
                          self.slave_type, self.n_slaves,
                          ofs_nbits)
            offset = (nicira_ext.NX_ACTION_BUNDLE_0_SIZE -
                      nicira_ext.NX_ACTION_HEADER_0_SIZE - 8)

            if self.dst == 0:
                msg_pack_into('I', data, offset, self.dst)
            else:
                oxm_data = ofp.oxm_from_user_header(self.dst)
                ofp.oxm_serialize_header(oxm_data, data, offset)
            return data

    class NXActionBundle(_NXActionBundleBase):
        _subtype = nicira_ext.NXAST_BUNDLE

        def __init__(self, algorithm, fields, basis, slave_type, n_slaves,
                     start, end, dst, slaves):
            # NXAST_BUNDLE actions should have 'start' 'end' and 'dst' zeroed.
            super(NXActionBundle, self).__init__(
                algorithm, fields, basis, slave_type, n_slaves,
                start=0, end=0, dst=0, slaves=slaves)

    class NXActionBundleLoad(_NXActionBundleBase):
        _subtype = nicira_ext.NXAST_BUNDLE_LOAD
        _TYPE = {
            'ascii': [
                'dst',
            ]
        }

        def __init__(self, algorithm, fields, basis, slave_type, n_slaves,
                     start, end, dst, slaves):
            super(NXActionBundleLoad, self).__init__(
                algorithm, fields, basis, slave_type, n_slaves,
                start, end, dst, slaves)

    class NXActionCT(NXAction):
        _subtype = nicira_ext.NXAST_CT

        # flags, zone_src, zone_ofs_nbits, recirc_table,
        # pad, alg
        _fmt_str = '!HIHB3xH'
        # Followed by actions

        def __init__(self,
                     flags,
                     zone_src,
                     zone_start,
                     zone_end,
                     recirc_table,
                     alg,
                     actions,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionCT, self).__init__()
            self.flags = flags
            self.zone_src = zone_src
            self.zone_start = zone_start
            self.zone_end = zone_end
            self.recirc_table = recirc_table
            self.alg = alg
            self.actions = actions

        @classmethod
        def parser(cls, buf):
            (flags,
             zone_src,
             zone_ofs_nbits,
             recirc_table,
             alg,) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            zone_start = zone_ofs_nbits >> 6
            zone_end = (zone_ofs_nbits & 0x3f) + zone_start
            rest = buf[struct.calcsize(cls._fmt_str):]
            # actions
            actions = []
            while len(rest) > 0:
                action = ofpp.OFPAction.parser(rest, 0)
                actions.append(action)
                rest = rest[action.len:]

            return cls(flags, zone_src, zone_start, zone_end, recirc_table,
                       alg, actions)

        def serialize_body(self):
            zone_ofs_nbits = ((self.zone_start << 6) +
                              (self.zone_end - self.zone_start))
            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.flags,
                          self.zone_src,
                          zone_ofs_nbits,
                          self.recirc_table,
                          self.alg)
            for a in self.actions:
                a.serialize(data, len(data))
            return data

    class NXActionNAT(NXAction):
        _subtype = nicira_ext.NXAST_NAT

        # pad, flags, range_present
        _fmt_str = '!2xHH'
        # Followed by optional parameters

        _TYPE = {
            'ascii': [
                'range_ipv4_max',
                'range_ipv4_min',
                'range_ipv6_max',
                'range_ipv6_min',
            ]
        }

        def __init__(self,
                     flags,
                     range_ipv4_min='',
                     range_ipv4_max='',
                     range_ipv6_min='',
                     range_ipv6_max='',
                     range_proto_min=None,
                     range_proto_max=None,
                     type_=None, len_=None, experimenter=None, subtype=None):
            super(NXActionNAT, self).__init__()
            self.flags = flags
            self.range_ipv4_min = range_ipv4_min
            self.range_ipv4_max = range_ipv4_max
            self.range_ipv6_min = range_ipv6_min
            self.range_ipv6_max = range_ipv6_max
            self.range_proto_min = range_proto_min
            self.range_proto_max = range_proto_max

        @classmethod
        def parser(cls, buf):
            (flags,
             range_present) = struct.unpack_from(
                cls._fmt_str, buf, 0)
            rest = buf[struct.calcsize(cls._fmt_str):]
            # optional parameters
            kwargs = dict()
            if range_present & nicira_ext.NX_NAT_RANGE_IPV4_MIN:
                kwargs['range_ipv4_min'] = type_desc.IPv4Addr.to_user(rest[:4])
                rest = rest[4:]
            if range_present & nicira_ext.NX_NAT_RANGE_IPV4_MAX:
                kwargs['range_ipv4_max'] = type_desc.IPv4Addr.to_user(rest[:4])
                rest = rest[4:]
            if range_present & nicira_ext.NX_NAT_RANGE_IPV6_MIN:
                kwargs['range_ipv6_min'] = (
                    type_desc.IPv6Addr.to_user(rest[:16]))
                rest = rest[16:]
            if range_present & nicira_ext.NX_NAT_RANGE_IPV6_MAX:
                kwargs['range_ipv6_max'] = (
                    type_desc.IPv6Addr.to_user(rest[:16]))
                rest = rest[16:]
            if range_present & nicira_ext.NX_NAT_RANGE_PROTO_MIN:
                kwargs['range_proto_min'] = type_desc.Int2.to_user(rest[:2])
                rest = rest[2:]
            if range_present & nicira_ext.NX_NAT_RANGE_PROTO_MAX:
                kwargs['range_proto_max'] = type_desc.Int2.to_user(rest[:2])

            return cls(flags, **kwargs)

        def serialize_body(self):
            # Pack optional parameters first, as range_present needs
            # to be calculated.
            optional_data = b''
            range_present = 0
            if self.range_ipv4_min != '':
                range_present |= nicira_ext.NX_NAT_RANGE_IPV4_MIN
                optional_data += type_desc.IPv4Addr.from_user(
                    self.range_ipv4_min)
            if self.range_ipv4_max != '':
                range_present |= nicira_ext.NX_NAT_RANGE_IPV4_MAX
                optional_data += type_desc.IPv4Addr.from_user(
                    self.range_ipv4_max)
            if self.range_ipv6_min != '':
                range_present |= nicira_ext.NX_NAT_RANGE_IPV6_MIN
                optional_data += type_desc.IPv6Addr.from_user(
                    self.range_ipv6_min)
            if self.range_ipv6_max != '':
                range_present |= nicira_ext.NX_NAT_RANGE_IPV6_MAX
                optional_data += type_desc.IPv6Addr.from_user(
                    self.range_ipv6_max)
            if self.range_proto_min is not None:
                range_present |= nicira_ext.NX_NAT_RANGE_PROTO_MIN
                optional_data += type_desc.Int2.from_user(
                    self.range_proto_min)
            if self.range_proto_max is not None:
                range_present |= nicira_ext.NX_NAT_RANGE_PROTO_MAX
                optional_data += type_desc.Int2.from_user(
                    self.range_proto_max)

            data = bytearray()
            msg_pack_into(self._fmt_str, data, 0,
                          self.flags,
                          range_present)
            msg_pack_into('!%ds' % len(optional_data), data, len(data),
                          optional_data)

            return data

    def add_attr(k, v):
        v.__module__ = ofpp.__name__  # Necessary for stringify stuff
        setattr(ofpp, k, v)

    add_attr('NXAction', NXAction)
    add_attr('NXActionUnknown', NXActionUnknown)

    classes = [
        'NXActionSetQueue',
        'NXActionPopQueue',
        'NXActionRegLoad',
        'NXActionRegLoad2',
        'NXActionNote',
        'NXActionSetTunnel',
        'NXActionSetTunnel64',
        'NXActionRegMove',
        'NXActionResubmit',
        'NXActionResubmitTable',
        'NXActionOutputReg',
        'NXActionOutputReg2',
        'NXActionLearn',
        'NXActionExit',
        'NXActionDecTtl',
        'NXActionController',
        'NXActionController2',
        'NXActionDecTtlCntIds',
        'NXActionPushMpls',
        'NXActionPopMpls',
        'NXActionSetMplsTtl',
        'NXActionDecMplsTtl',
        'NXActionSetMplsLabel',
        'NXActionSetMplsTc',
        'NXActionStackPush',
        'NXActionStackPop',
        'NXActionSample',
        'NXActionFinTimeout',
        'NXActionConjunction',
        'NXActionMultipath',
        'NXActionBundle',
        'NXActionBundleLoad',
        'NXActionCT',
        'NXActionNAT',
        '_NXFlowSpec',  # exported for testing
        'NXFlowSpecMatch',
        'NXFlowSpecLoad',
        'NXFlowSpecOutput',
    ]
    vars = locals()
    for name in classes:
        cls = vars[name]
        add_attr(name, cls)
        if issubclass(cls, NXAction):
            NXAction.register(cls)
        if issubclass(cls, _NXFlowSpec):
            _NXFlowSpec.register(cls)
