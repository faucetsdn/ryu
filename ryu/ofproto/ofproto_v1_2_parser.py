# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>
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
import itertools

from ryu.lib import mac
from ryu import utils
from ofproto_parser import StringifyMixin, MsgBase, msg_pack_into, msg_str_attr
from . import ofproto_parser
from . import ofproto_v1_2

import logging
LOG = logging.getLogger('ryu.ofproto.ofproto_v1_2_parser')

_MSG_PARSERS = {}


def _set_msg_type(msg_type):
    def _set_cls_msg_type(cls):
        cls.cls_msg_type = msg_type
        return cls
    return _set_cls_msg_type


def _register_parser(cls):
    '''class decorator to register msg parser'''
    assert cls.cls_msg_type is not None
    assert cls.cls_msg_type not in _MSG_PARSERS
    _MSG_PARSERS[cls.cls_msg_type] = cls.parser
    return cls


@ofproto_parser.register_msg_parser(ofproto_v1_2.OFP_VERSION)
def msg_parser(datapath, version, msg_type, msg_len, xid, buf):
    parser = _MSG_PARSERS.get(msg_type)
    return parser(datapath, version, msg_type, msg_len, xid, buf)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_HELLO)
class OFPHello(MsgBase):
    def __init__(self, datapath):
        super(OFPHello, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_ERROR)
class OFPErrorMsg(MsgBase):
    def __init__(self, datapath, type_=None, code=None, data=None):
        super(OFPErrorMsg, self).__init__(datapath)
        self.type = type_
        self.code = code
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        type_, = struct.unpack_from('!H', buffer(buf),
                                    ofproto_v1_2.OFP_HEADER_SIZE)
        if type_ == ofproto_v1_2.OFPET_EXPERIMENTER:
            return OFPErrorExperimenterMsg.parser(datapath, version, msg_type,
                                                  msg_len, xid, buf)

        msg = super(OFPErrorMsg, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        msg.type, msg.code = struct.unpack_from(
            ofproto_v1_2.OFP_ERROR_MSG_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_2.OFP_ERROR_MSG_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        msg_pack_into(ofproto_v1_2.OFP_ERROR_MSG_PACK_STR, self.buf,
                      ofproto_v1_2.OFP_HEADER_SIZE, self.type, self.code)
        self.buf += self.data


class OFPErrorExperimenterMsg(MsgBase):
    def __init__(self, datapath, exp_type=None, experimenter=None, data=None):
        super(OFPErrorExperimenterMsg, self).__init__(datapath)
        self._type = None
        self.exp_type = exp_type
        self.experimenter = experimenter
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        cls.cls_msg_type = msg_type
        msg = super(OFPErrorExperimenterMsg, cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)
        msg._type, msg.exp_type, msg.experimenter = struct.unpack_from(
            ofproto_v1_2.OFP_ERROR_EXPERIMENTER_MSG_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_2.OFP_ERROR_EXPERIMENTER_SIZE:]
        return msg


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_ECHO_REQUEST)
class OFPEchoRequest(MsgBase):
    def __init__(self, datapath, data=None):
        super(OFPEchoRequest, self).__init__(datapath)
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoRequest, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)
        msg.data = msg.buf[ofproto_v1_2.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        if self.data is not None:
            self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_ECHO_REPLY)
class OFPEchoReply(MsgBase):
    def __init__(self, datapath, data=None):
        super(OFPEchoReply, self).__init__(datapath)
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoReply, cls).parser(datapath, version, msg_type,
                                              msg_len, xid, buf)
        msg.data = msg.buf[ofproto_v1_2.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_EXPERIMENTER)
class OFPExperimenter(MsgBase):
    def __init__(self, datapath, experimenter=None, exp_type=None, data=None):
        super(OFPExperimenter, self).__init__(datapath)
        self.experimenter = experimenter
        self.exp_type = exp_type
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPExperimenter, cls).parser(datapath, version, msg_type,
                                                 msg_len, xid, buf)
        (msg.experimenter, msg.exp_type) = struct.unpack_from(
            ofproto_v1_2.OFP_EXPERIMENTER_HEADER_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_2.OFP_EXPERIMENTER_HEADER_SIZE:]

        return msg


class OFPPort(ofproto_parser.namedtuple('OFPPort', (
        'port_no', 'hw_addr', 'name', 'config', 'state', 'curr',
        'advertised', 'supported', 'peer', 'curr_speed', 'max_speed'))):

    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto_v1_2.OFP_PORT_PACK_STR, buf, offset)
        return cls(*port)


@_set_msg_type(ofproto_v1_2.OFPT_FEATURES_REQUEST)
class OFPFeaturesRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPFeaturesRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_FEATURES_REPLY)
class OFPSwitchFeatures(MsgBase):
    def __init__(self, datapath, datapath_id=None, n_buffers=None,
                 n_tables=None, capabilities=None, ports=None):
        super(OFPSwitchFeatures, self).__init__(datapath)
        self.datapath_id = datapath_id
        self.n_buffers = n_buffers
        self.n_tables = n_tables
        self.capabilities = capabilities
        self.ports = ports

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSwitchFeatures, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        (msg.datapath_id,
         msg.n_buffers,
         msg.n_tables,
         msg.capabilities,
         msg._reserved) = struct.unpack_from(
            ofproto_v1_2.OFP_SWITCH_FEATURES_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)

        msg.ports = {}
        n_ports = ((msg_len - ofproto_v1_2.OFP_SWITCH_FEATURES_SIZE) /
                   ofproto_v1_2.OFP_PORT_SIZE)
        offset = ofproto_v1_2.OFP_SWITCH_FEATURES_SIZE
        for i in range(n_ports):
            port = OFPPort.parser(msg.buf, offset)
            msg.ports[port.port_no] = port
            offset += ofproto_v1_2.OFP_PORT_SIZE

        return msg


@_set_msg_type(ofproto_v1_2.OFPT_GET_CONFIG_REQUEST)
class OFPGetConfigRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPGetConfigRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_GET_CONFIG_REPLY)
class OFPGetConfigReply(MsgBase):
    def __init__(self, datapath, flags=None, miss_send_len=None):
        super(OFPGetConfigReply, self).__init__(datapath)
        self.flags = flags
        self.miss_send_len = miss_send_len

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPGetConfigReply, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        msg.flags, msg.miss_send_len = struct.unpack_from(
            ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
        return msg


@_set_msg_type(ofproto_v1_2.OFPT_SET_CONFIG)
class OFPSetConfig(MsgBase):
    def __init__(self, datapath, flags=0, miss_send_len=0):
        super(OFPSetConfig, self).__init__(datapath)
        self.flags = flags
        self.miss_send_len = miss_send_len

    def _serialize_body(self):
        assert self.flags is not None
        assert self.miss_send_len is not None
        msg_pack_into(ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE,
                      self.flags, self.miss_send_len)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_PACKET_IN)
class OFPPacketIn(MsgBase):
    def __init__(self, datapath, buffer_id=None, total_len=None, reason=None,
                 table_id=None, match=None, data=None):
        super(OFPPacketIn, self).__init__(datapath)
        self.buffer_id = buffer_id
        self.total_len = total_len
        self.reason = reason
        self.table_id = table_id
        self.match = match
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPacketIn, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        (msg.buffer_id, msg.total_len, msg.reason,
         msg.table_id) = struct.unpack_from(
            ofproto_v1_2.OFP_PACKET_IN_PACK_STR,
            msg.buf, ofproto_v1_2.OFP_HEADER_SIZE)

        msg.match = OFPMatch.parser(msg.buf, ofproto_v1_2.OFP_PACKET_IN_SIZE -
                                    ofproto_v1_2.OFP_MATCH_SIZE)

        match_len = utils.round_up(msg.match._length, 8)
        msg.data = msg.buf[(ofproto_v1_2.OFP_PACKET_IN_SIZE -
                            ofproto_v1_2.OFP_MATCH_SIZE + match_len + 2):]

        if msg.total_len < len(msg.data):
            # discard padding for 8-byte alignment of OFP packet
            msg.data = msg.data[:msg.total_len]

        return msg


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_FLOW_REMOVED)
class OFPFlowRemoved(MsgBase):
    def __init__(self, datapath, cookie=None, priority=None, reason=None,
                 table_id=None, duration_sec=None, duration_nsec=None,
                 idle_timeout=None, hard_timeout=None, packet_count=None,
                 byte_count=None, match=None):
        super(OFPFlowRemoved, self).__init__(datapath)
        self.cookie = cookie
        self.priority = priority
        self.reason = reason
        self.table_id = table_id
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.match = match

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPFlowRemoved, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)

        (msg.cookie, msg.priority, msg.reason,
         msg.table_id, msg.duration_sec, msg.duration_nsec,
         msg.idle_timeout, msg.hard_timeout, msg.packet_count,
         msg.byte_count) = struct.unpack_from(
            ofproto_v1_2.OFP_FLOW_REMOVED_PACK_STR0,
            msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)

        offset = (ofproto_v1_2.OFP_FLOW_REMOVED_SIZE -
                  ofproto_v1_2.OFP_MATCH_SIZE)

        msg.match = OFPMatch.parser(msg.buf, offset)

        return msg


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_PORT_STATUS)
class OFPPortStatus(MsgBase):
    def __init__(self, datapath, reason=None, desc=None):
        super(OFPPortStatus, self).__init__(datapath)
        self.reason = reason
        self.desc = desc

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPortStatus, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        msg.reason = struct.unpack_from(
            ofproto_v1_2.OFP_PORT_STATUS_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)[0]
        msg.desc = OFPPort.parser(msg.buf,
                                  ofproto_v1_2.OFP_PORT_STATUS_DESC_OFFSET)
        return msg


@_set_msg_type(ofproto_v1_2.OFPT_PACKET_OUT)
class OFPPacketOut(MsgBase):
    def __init__(self, datapath, buffer_id=None, in_port=None, actions=None,
                 data=None):

        # The in_port field is the ingress port that must be associated
        # with the packet for OpenFlow processing.
        assert in_port is not None

        super(OFPPacketOut, self).__init__(datapath)
        self.buffer_id = buffer_id
        self.in_port = in_port
        self._actions_len = 0
        self.actions = actions
        self.data = data

    def _serialize_body(self):
        self._actions_len = 0
        offset = ofproto_v1_2.OFP_PACKET_OUT_SIZE
        for a in self.actions:
            a.serialize(self.buf, offset)
            offset += a.len
            self._actions_len += a.len

        if self.data is not None:
            assert self.buffer_id == 0xffffffff
            self.buf += self.data

        msg_pack_into(ofproto_v1_2.OFP_PACKET_OUT_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE,
                      self.buffer_id, self.in_port, self._actions_len)


@_set_msg_type(ofproto_v1_2.OFPT_FLOW_MOD)
class OFPFlowMod(MsgBase):
    def __init__(self, datapath, cookie, cookie_mask, table_id, command,
                 idle_timeout, hard_timeout, priority, buffer_id, out_port,
                 out_group, flags, match, instructions):
        super(OFPFlowMod, self).__init__(datapath)
        self.cookie = cookie
        self.cookie_mask = cookie_mask
        self.table_id = table_id
        self.command = command
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.priority = priority
        self.buffer_id = buffer_id
        self.out_port = out_port
        self.out_group = out_group
        self.flags = flags
        self.match = match
        self.instructions = instructions

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_2.OFP_FLOW_MOD_PACK_STR0, self.buf,
                      ofproto_v1_2.OFP_HEADER_SIZE,
                      self.cookie, self.cookie_mask, self.table_id,
                      self.command, self.idle_timeout, self.hard_timeout,
                      self.priority, self.buffer_id, self.out_port,
                      self.out_group, self.flags)

        offset = (ofproto_v1_2.OFP_FLOW_MOD_SIZE -
                  ofproto_v1_2.OFP_MATCH_SIZE)

        match_len = self.match.serialize(self.buf, offset)
        offset += match_len

        for inst in self.instructions:
            inst.serialize(self.buf, offset)
            offset += inst.len


class OFPInstruction(StringifyMixin):
    _INSTRUCTION_TYPES = {}

    @staticmethod
    def register_instruction_type(types):
        def _register_instruction_type(cls):
            for type_ in types:
                OFPInstruction._INSTRUCTION_TYPES[type_] = cls
            return cls
        return _register_instruction_type

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from('!HH', buf, offset)
        cls_ = cls._INSTRUCTION_TYPES.get(type_)
        return cls_.parser(buf, offset)


@OFPInstruction.register_instruction_type([ofproto_v1_2.OFPIT_GOTO_TABLE])
class OFPInstructionGotoTable(StringifyMixin):
    _base_attributes = ['type', 'len']

    def __init__(self, table_id):
        super(OFPInstructionGotoTable, self).__init__()
        self.type = ofproto_v1_2.OFPIT_GOTO_TABLE
        self.len = ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_SIZE
        self.table_id = table_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, table_id) = struct.unpack_from(
            ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR,
            buf, offset)
        return cls(table_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR,
                      buf, offset, self.type, self.len, self.table_id)


@OFPInstruction.register_instruction_type([ofproto_v1_2.OFPIT_WRITE_METADATA])
class OFPInstructionWriteMetadata(StringifyMixin):
    _base_attributes = ['type', 'len']

    def __init__(self, metadata, metadata_mask):
        super(OFPInstructionWriteMetadata, self).__init__()
        self.type = ofproto_v1_2.OFPIT_WRITE_METADATA
        self.len = ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_SIZE
        self.metadata = metadata
        self.metadata_mask = metadata_mask

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, metadata, metadata_mask) = struct.unpack_from(
            ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_PACK_STR,
            buf, offset)
        return cls(metadata, metadata_mask)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_PACK_STR,
                      buf, offset, self.type, self.len, self.metadata,
                      self.metadata_mask)


@OFPInstruction.register_instruction_type([ofproto_v1_2.OFPIT_WRITE_ACTIONS,
                                           ofproto_v1_2.OFPIT_APPLY_ACTIONS,
                                           ofproto_v1_2.OFPIT_CLEAR_ACTIONS])
class OFPInstructionActions(StringifyMixin):
    _base_attributes = ['len']

    def __init__(self, type_, actions=None):
        super(OFPInstructionActions, self).__init__()
        self.type = type_
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_PACK_STR,
            buf, offset)

        offset += ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_SIZE
        actions = []
        actions_len = len_ - ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_SIZE
        while actions_len > 0:
            a = OFPAction.parser(buf, offset)
            actions.append(a)
            actions_len -= a.len
            offset += a.len

        inst = cls(type_, actions)
        inst.len = len_
        return inst

    def serialize(self, buf, offset):
        action_offset = offset + ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_SIZE
        if self.actions:
            for a in self.actions:
                assert isinstance(a, OFPAction)
                a.serialize(buf, action_offset)
                action_offset += a.len

        self.len = action_offset - offset
        pad_len = utils.round_up(self.len, 8) - self.len
        ofproto_parser.msg_pack_into("%dx" % pad_len, buf, action_offset)
        self.len += pad_len

        msg_pack_into(ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_PACK_STR,
                      buf, offset, self.type, self.len)


class OFPActionHeader(StringifyMixin):
    _base_attributes = ['type', 'len']

    def __init__(self, type_, len_):
        self.type = type_
        self.len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR,
                      buf, offset, self.type, self.len)


class OFPAction(OFPActionHeader):
    _ACTION_TYPES = {}

    @staticmethod
    def register_action_type(type_, len_):
        def _register_action_type(cls):
            cls.cls_action_type = type_
            cls.cls_action_len = len_
            OFPAction._ACTION_TYPES[cls.cls_action_type] = cls
            return cls
        return _register_action_type

    def __init__(self):
        cls = self.__class__
        super(OFPAction, self).__init__(cls.cls_action_type,
                                        cls.cls_action_len)

    @classmethod
    def parser(cls, buf, offset):
        type_, len_ = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        cls_ = cls._ACTION_TYPES.get(type_)
        assert cls_ is not None
        return cls_.parser(buf, offset)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf,
                      offset, self.type, self.len)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_OUTPUT,
                                ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE)
class OFPActionOutput(OFPAction):
    def __init__(self, port, max_len):
        super(OFPActionOutput, self).__init__()
        self.port = port
        self.max_len = max_len

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, port, max_len = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR, buf, offset)
        return cls(port, max_len)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR, buf,
                      offset, self.type, self.len, self.port, self.max_len)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_GROUP,
                                ofproto_v1_2.OFP_ACTION_GROUP_SIZE)
class OFPActionGroup(OFPAction):
    def __init__(self, group_id):
        super(OFPActionGroup, self).__init__()
        self.group_id = group_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, group_id) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_GROUP_PACK_STR, buf, offset)
        return cls(group_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_GROUP_PACK_STR, buf,
                      offset, self.type, self.len, self.group_id)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_SET_QUEUE,
                                ofproto_v1_2.OFP_ACTION_SET_QUEUE_SIZE)
class OFPActionSetQueue(OFPAction):
    def __init__(self, queue_id):
        super(OFPActionSetQueue, self).__init__()
        self.queue_id = queue_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, queue_id) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_SET_QUEUE_PACK_STR, buf, offset)
        return cls(queue_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_SET_QUEUE_PACK_STR, buf,
                      offset, self.type, self.len, self.queue_id)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_SET_MPLS_TTL,
                                ofproto_v1_2.OFP_ACTION_MPLS_TTL_SIZE)
class OFPActionSetMplsTtl(OFPAction):
    def __init__(self, mpls_ttl):
        super(OFPActionSetMplsTtl, self).__init__()
        self.mpls_ttl = mpls_ttl

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, mpls_ttl) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_MPLS_TTL_PACK_STR, buf, offset)
        return cls(mpls_ttl)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_MPLS_TTL_PACK_STR, buf,
                      offset, self.type, self.len, self.mpls_ttl)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_DEC_MPLS_TTL,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionDecMplsTtl(OFPAction):
    def __init__(self):
        super(OFPActionDecMplsTtl, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_SET_NW_TTL,
                                ofproto_v1_2.OFP_ACTION_NW_TTL_SIZE)
class OFPActionSetNwTtl(OFPAction):
    def __init__(self, nw_ttl):
        super(OFPActionSetNwTtl, self).__init__()
        self.nw_ttl = nw_ttl

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, nw_ttl) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_NW_TTL_PACK_STR, buf, offset)
        return cls(nw_ttl)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_NW_TTL_PACK_STR, buf, offset,
                      self.type, self.len, self.nw_ttl)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_DEC_NW_TTL,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionDecNwTtl(OFPAction):
    def __init__(self):
        super(OFPActionDecNwTtl, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_COPY_TTL_OUT,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlOut(OFPAction):
    def __init__(self):
        super(OFPActionCopyTtlOut, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_COPY_TTL_IN,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlIn(OFPAction):
    def __init__(self):
        super(OFPActionCopyTtlIn, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_PUSH_VLAN,
                                ofproto_v1_2.OFP_ACTION_PUSH_SIZE)
class OFPActionPushVlan(OFPAction):
    def __init__(self, ethertype):
        super(OFPActionPushVlan, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_PUSH_MPLS,
                                ofproto_v1_2.OFP_ACTION_PUSH_SIZE)
class OFPActionPushMpls(OFPAction):
    def __init__(self, ethertype):
        super(OFPActionPushMpls, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_POP_VLAN,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionPopVlan(OFPAction):
    def __init__(self):
        super(OFPActionPopVlan, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_POP_MPLS,
                                ofproto_v1_2.OFP_ACTION_POP_MPLS_SIZE)
class OFPActionPopMpls(OFPAction):
    def __init__(self, ethertype):
        super(OFPActionPopMpls, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_POP_MPLS_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_POP_MPLS_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_SET_FIELD,
                                ofproto_v1_2.OFP_ACTION_SET_FIELD_SIZE)
class OFPActionSetField(OFPAction):
    def __init__(self, field):
        super(OFPActionSetField, self).__init__()
        self.field = field

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from('!HH', buf, offset)
        field = OFPMatchField.parser(buf, offset + 4)
        action = cls(field)
        action.len = len_
        return action

    def serialize(self, buf, offset):
        len_ = ofproto_v1_2.OFP_ACTION_SET_FIELD_SIZE + self.field.oxm_len()
        self.len = utils.round_up(len_, 8)
        pad_len = self.len - len_

        msg_pack_into('!HH', buf, offset, self.type, self.len)
        self.field.serialize(buf, offset + 4)
        offset += len_
        ofproto_parser.msg_pack_into("%dx" % pad_len, buf, offset)


@OFPAction.register_action_type(
    ofproto_v1_2.OFPAT_EXPERIMENTER,
    ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_SIZE)
class OFPActionExperimenter(OFPAction):
    def __init__(self, experimenter):
        super(OFPActionExperimenter, self).__init__()
        self.experimenter = experimenter

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, experimenter) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR, buf, offset)
        ex = cls(experimenter)
        ex.len = len_
        return ex

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR,
                      buf, offset, self.type, self.len, self.experimenter)


class OFPBucket(StringifyMixin):
    def __init__(self, weight, watch_port, watch_group, actions):
        super(OFPBucket, self).__init__()
        self.weight = weight
        self.watch_port = watch_port
        self.watch_group = watch_group
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        (len_, weigth, watch_port, watch_group) = struct.unpack_from(
            ofproto_v1_2.OFP_BUCKET_PACK_STR, buf, offset)

        length = ofproto_v1_2.OFP_BUCKET_SIZE
        offset += ofproto_v1_2.OFP_BUCKET_SIZE
        actions = []
        while length < len_:
            action = OFPAction.parser(buf, offset)
            actions.append(action)
            offset += action.len
            length += action.len

        m = cls(weigth, watch_port, watch_group, actions)
        m._len = len_
        return m

    def serialize(self, buf, offset):
        action_offset = offset + ofproto_v1_2.OFP_BUCKET_SIZE
        action_len = 0
        for a in self.actions:
            a.serialize(buf, action_offset)
            action_offset += a.len
            action_len += a.len

        self._len = utils.round_up(ofproto_v1_2.OFP_BUCKET_SIZE + action_len,
                                   8)
        msg_pack_into(ofproto_v1_2.OFP_BUCKET_PACK_STR, buf, offset,
                      self._len, self.weight, self.watch_port,
                      self.watch_group)


@_set_msg_type(ofproto_v1_2.OFPT_GROUP_MOD)
class OFPGroupMod(MsgBase):
    def __init__(self, datapath, command, type_, group_id, buckets):
        super(OFPGroupMod, self).__init__(datapath)
        self.command = command
        self.type = type_
        self.group_id = group_id
        self.buckets = buckets

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_2.OFP_GROUP_MOD_PACK_STR, self.buf,
                      ofproto_v1_2.OFP_HEADER_SIZE,
                      self.command, self.type, self.group_id)

        offset = ofproto_v1_2.OFP_GROUP_MOD_SIZE
        for b in self.buckets:
            b.serialize(self.buf, offset)
            offset += b._len


@_set_msg_type(ofproto_v1_2.OFPT_PORT_MOD)
class OFPPortMod(MsgBase):
    def __init__(self, datapath, port_no, hw_addr, config, mask, advertise):
        super(OFPPortMod, self).__init__(datapath)
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.config = config
        self.mask = mask
        self.advertise = advertise

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_2.OFP_PORT_MOD_PACK_STR, self.buf,
                      ofproto_v1_2.OFP_HEADER_SIZE,
                      self.port_no, self.hw_addr, self.config,
                      self.mask, self.advertise)


@_set_msg_type(ofproto_v1_2.OFPT_TABLE_MOD)
class OFPTableMod(MsgBase):
    def __init__(self, datapath, table_id, config):
        super(OFPTableMod, self).__init__(datapath)
        self.table_id = table_id
        self.config = config

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_2.OFP_TABLE_MOD_PACK_STR, self.buf,
                      ofproto_v1_2.OFP_HEADER_SIZE,
                      self.table_id, self.config)


class OFPStatsRequest(MsgBase):
    def __init__(self, datapath, type_, flags=0):
        super(OFPStatsRequest, self).__init__(datapath)
        self.type = type_
        self.flags = flags

    def to_jsondict(self):
        # remove some redundant attributes
        d = super(OFPStatsRequest, self).to_jsondict()
        v = d[self.__class__.__name__]
        del v['type']  # implied by subclass
        return d

    def _serialize_stats_body(self):
        pass

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE,
                      self.type, self.flags)

        self._serialize_stats_body()


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_STATS_REPLY)
class OFPStatsReply(MsgBase):
    _STATS_TYPES = {}

    @staticmethod
    def register_stats_reply_type(type_, body_single_struct=False):
        def _register_stats_reply_type(cls):
            OFPStatsReply._STATS_TYPES[type_] = cls
            cls.cls_body_single_struct = body_single_struct
            return cls
        return _register_stats_reply_type

    def __init__(self, datapath, type_=None, flags=None, body=None):
        super(OFPStatsReply, self).__init__(datapath)
        self.type = type_
        self.flags = flags
        self.body = body

    def to_jsondict(self):
        # remove some redundant attributes
        d = super(OFPStatsReply, self).to_jsondict()
        v = d[self.__class__.__name__]
        del v['type']  # implied by subclass
        return d

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPStatsReply, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        msg.type, msg.flags = struct.unpack_from(
            ofproto_v1_2.OFP_STATS_REPLY_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
        stats_type_cls = cls._STATS_TYPES.get(msg.type)

        offset = ofproto_v1_2.OFP_STATS_REPLY_SIZE
        body = []
        while offset < msg_len:
            r = stats_type_cls.parser(msg.buf, offset)
            body.append(r)
            offset += r._length

        if stats_type_cls.cls_body_single_struct:
            msg.body = body[0]
        else:
            msg.body = body

        return msg


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPDescStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags=0):
        super(OFPDescStatsRequest, self).__init__(datapath,
                                                  ofproto_v1_2.OFPST_DESC,
                                                  flags)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_DESC,
                                         body_single_struct=True)
class OFPDescStats(ofproto_parser.namedtuple('OFPDescStats', (
        'mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc'))):
    @classmethod
    def parser(cls, buf, offset):
        desc = struct.unpack_from(ofproto_v1_2.OFP_DESC_STATS_PACK_STR,
                                  buf, offset)
        stats = cls(*desc)
        stats._length = ofproto_v1_2.OFP_DESC_STATS_SIZE
        return stats


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPFlowStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, table_id, out_port, out_group,
                 cookie, cookie_mask, match, flags=0):
        super(OFPFlowStatsRequest, self).__init__(datapath,
                                                  ofproto_v1_2.OFPST_FLOW,
                                                  flags)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        self.cookie = cookie
        self.cookie_mask = cookie_mask
        self.match = match

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_2.OFP_FLOW_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_STATS_REQUEST_SIZE,
                      self.table_id, self.out_port, self.out_group,
                      self.cookie, self.cookie_mask)

        offset = (ofproto_v1_2.OFP_STATS_REQUEST_SIZE +
                  ofproto_v1_2.OFP_FLOW_STATS_REQUEST_SIZE -
                  ofproto_v1_2.OFP_MATCH_SIZE)

        self.match.serialize(self.buf, offset)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_FLOW)
class OFPFlowStats(StringifyMixin):
    def __init__(self, table_id, duration_sec, duration_nsec,
                 priority, idle_timeout, hard_timeout, cookie, packet_count,
                 byte_count, match, instructions=None):
        super(OFPFlowStats, self).__init__()
        self.table_id = table_id
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.priority = priority
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.cookie = cookie
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.match = match
        self.instructions = instructions

    @classmethod
    def parser(cls, buf, offset):
        (length, table_id, duration_sec,
         duration_nsec, priority,
         idle_timeout, hard_timeout,
         cookie, packet_count, byte_count) = struct.unpack_from(
            ofproto_v1_2.OFP_FLOW_STATS_PACK_STR,
            buf, offset)
        offset += (ofproto_v1_2.OFP_FLOW_STATS_SIZE -
                   ofproto_v1_2.OFP_MATCH_SIZE)
        match = OFPMatch.parser(buf, offset)

        match_length = utils.round_up(match._length, 8)
        inst_length = (length - (ofproto_v1_2.OFP_FLOW_STATS_SIZE -
                                 ofproto_v1_2.OFP_MATCH_SIZE + match_length))
        offset += match_length
        instructions = []
        while inst_length > 0:
            inst = OFPInstruction.parser(buf, offset)
            instructions.append(inst)
            offset += inst.len
            inst_length -= inst.len

        o = cls(table_id, duration_sec, duration_nsec, priority,
                idle_timeout, hard_timeout, cookie, packet_count,
                byte_count, match, instructions)
        o._length = length
        return o


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPAggregateStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, table_id, out_port, out_group,
                 cookie, cookie_mask, match, flags=0):
        super(OFPAggregateStatsRequest, self).__init__(
            datapath,
            ofproto_v1_2.OFPST_AGGREGATE,
            flags)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        self.cookie = cookie
        self.cookie_mask = cookie_mask
        self.match = match

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_2.OFP_AGGREGATE_STATS_REQUEST_PACK_STR,
                      self.buf,
                      ofproto_v1_2.OFP_STATS_REQUEST_SIZE,
                      self.table_id, self.out_port, self.out_group,
                      self.cookie, self.cookie_mask)

        offset = (ofproto_v1_2.OFP_STATS_REQUEST_SIZE +
                  ofproto_v1_2.OFP_AGGREGATE_STATS_REQUEST_SIZE -
                  ofproto_v1_2.OFP_MATCH_SIZE)

        self.match.serialize(self.buf, offset)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_AGGREGATE,
                                         body_single_struct=True)
class OFPAggregateStatsReply(ofproto_parser.namedtuple('OFPAggregateStats', (
        'packet_count', 'byte_count', 'flow_count'))):
    @classmethod
    def parser(cls, buf, offset):
        desc = struct.unpack_from(
            ofproto_v1_2.OFP_AGGREGATE_STATS_REPLY_PACK_STR,
            buf, offset)
        stats = cls(*desc)
        stats._length = ofproto_v1_2.OFP_AGGREGATE_STATS_REPLY_SIZE
        return stats


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPTableStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags=0):
        super(OFPTableStatsRequest, self).__init__(datapath,
                                                   ofproto_v1_2.OFPST_TABLE,
                                                   flags)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_TABLE)
class OFPTableStats(
    ofproto_parser.namedtuple('OFPTableStats',
                              ('table_id', 'name', 'match', 'wildcards',
                               'write_actions', 'apply_actions',
                               'write_setfields', 'apply_setfields',
                               'metadata_match', 'metadata_write',
                               'instructions', 'config',
                               'max_entries', 'active_count',
                               'lookup_count', 'matched_count'))):
    @classmethod
    def parser(cls, buf, offset):
        table = struct.unpack_from(
            ofproto_v1_2.OFP_TABLE_STATS_PACK_STR,
            buf, offset)
        stats = cls(*table)
        stats._length = ofproto_v1_2.OFP_TABLE_STATS_SIZE
        return stats


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPPortStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, port_no, flags=0):
        super(OFPPortStatsRequest, self).__init__(datapath,
                                                  ofproto_v1_2.OFPST_PORT,
                                                  flags)
        self.port_no = port_no

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_2.OFP_PORT_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_STATS_REQUEST_SIZE,
                      self.port_no)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_PORT)
class OFPPortStats(
    ofproto_parser.namedtuple('OFPPortStats',
                              ('port_no', 'rx_packets', 'tx_packets',
                               'rx_bytes', 'tx_bytes',
                               'rx_dropped', 'tx_dropped',
                               'rx_errors', 'tx_errors',
                               'rx_frame_err', 'rx_over_err',
                               'rx_crc_err', 'collisions'))):
    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto_v1_2.OFP_PORT_STATS_PACK_STR,
                                  buf, offset)
        stats = cls(*port)
        stats._length = ofproto_v1_2.OFP_PORT_STATS_SIZE
        return stats


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPQueueStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, port_no, queue_id, flags=0):
        super(OFPQueueStatsRequest, self).__init__(datapath,
                                                   ofproto_v1_2.OFPST_QUEUE,
                                                   flags)
        self.port_no = port_no
        self.queue_id = queue_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_2.OFP_QUEUE_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_STATS_REQUEST_SIZE,
                      self.port_no, self.queue_id)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_QUEUE)
class OFPQueueStats(
    ofproto_parser.namedtuple('OFPQueueStats',
                              ('port_no', 'queue_id', 'tx_bytes',
                               'tx_packets', 'tx_errors'))):
    @classmethod
    def parser(cls, buf, offset):
        queue = struct.unpack_from(ofproto_v1_2.OFP_QUEUE_STATS_PACK_STR,
                                   buf, offset)
        stats = cls(*queue)
        stats._length = ofproto_v1_2.OFP_QUEUE_STATS_SIZE
        return stats


class OFPBucketCounter(StringifyMixin):
    def __init__(self, packet_count, byte_count):
        super(OFPBucketCounter, self).__init__()
        self.packet_count = packet_count
        self.byte_count = byte_count

    @classmethod
    def parser(cls, buf, offset):
        packet, byte = struct.unpack_from(
            ofproto_v1_2.OFP_BUCKET_COUNTER_PACK_STR,
            buf, offset)
        return cls(packet, byte)


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPGroupStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, group_id, flags=0):
        super(OFPGroupStatsRequest, self).__init__(datapath,
                                                   ofproto_v1_2.OFPST_GROUP,
                                                   flags)
        self.group_id = group_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_2.OFP_GROUP_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_STATS_REQUEST_SIZE,
                      self.group_id)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_GROUP)
class OFPGroupStats(StringifyMixin):
    def __init__(self, group_id, ref_count, packet_count,
                 byte_count, bucket_counters):
        super(OFPGroupStats, self).__init__()
        self.group_id = group_id
        self.ref_count = ref_count
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.bucket_counters = bucket_counters

    @classmethod
    def parser(cls, buf, offset):
        (length, group_id, ref_count, packet_count,
         byte_count) = struct.unpack_from(
            ofproto_v1_2.OFP_GROUP_STATS_PACK_STR,
            buf, offset)

        bucket_len = length - ofproto_v1_2.OFP_GROUP_STATS_SIZE
        offset += ofproto_v1_2.OFP_GROUP_STATS_SIZE
        bucket_counters = []
        while bucket_len > 0:
            bucket_counters.append(OFPBucketCounter.parser(buf, offset))
            offset += ofproto_v1_2.OFP_BUCKET_COUNTER_SIZE
            bucket_len -= ofproto_v1_2.OFP_BUCKET_COUNTER_SIZE

        o = cls(group_id, ref_count, packet_count,
                byte_count, bucket_counters)
        o._length = length
        return o


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPGroupDescStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags=0):
        super(OFPGroupDescStatsRequest, self).__init__(
            datapath,
            ofproto_v1_2.OFPST_GROUP_DESC,
            flags)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_GROUP_DESC)
class OFPGroupDescStats(StringifyMixin):
    def __init__(self, type_, group_id, buckets):
        self.type = type_
        self.group_id = group_id
        self.buckets = buckets

    @classmethod
    def parser(cls, buf, offset):
        (length, type_, group_id) = struct.unpack_from(
            ofproto_v1_2.OFP_GROUP_DESC_STATS_PACK_STR,
            buf, offset)

        bucket_len = length - ofproto_v1_2.OFP_GROUP_DESC_STATS_SIZE
        offset += ofproto_v1_2.OFP_GROUP_DESC_STATS_SIZE
        buckets = []
        while bucket_len > 0:
            bucket = OFPBucket.parser(buf, offset)
            buckets.append(bucket)
            offset += bucket._len
            bucket_len -= bucket._len

        o = cls(type_, group_id, buckets)
        o._length = length
        return o


@_set_msg_type(ofproto_v1_2.OFPT_STATS_REQUEST)
class OFPGroupFeaturesStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags=0):
        super(OFPGroupFeaturesStatsRequest, self).__init__(
            datapath,
            ofproto_v1_2.OFPST_GROUP_FEATURES,
            flags)


@OFPStatsReply.register_stats_reply_type(ofproto_v1_2.OFPST_GROUP_FEATURES,
                                         body_single_struct=True)
class OFPGroupFeaturesStats(StringifyMixin):
    def __init__(self, types, capabilities, max_groups, actions):
        self.types = types
        self.capabilities = capabilities
        self.max_groups = max_groups
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        stats = struct.unpack_from(
            ofproto_v1_2.OFP_GROUP_FEATURES_STATS_PACK_STR, buf, offset)
        types = stats[0]
        capabilities = stats[1]
        max_groups = list(stats[2:6])
        actions = list(stats[6:10])

        o = cls(types, capabilities, max_groups, actions)
        o._length = ofproto_v1_2.OFP_GROUP_FEATURES_STATS_SIZE
        return o


@_set_msg_type(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST)
class OFPQueueGetConfigRequest(MsgBase):
    def __init__(self, datapath, port):
        super(OFPQueueGetConfigRequest, self).__init__(datapath)
        self.port = port

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE, self.port)


class OFPQueuePropHeader(StringifyMixin):
    def __init__(self, property_, len_):
        self._property = property_
        self._len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR,
                      buf, offset, self._property, self._len)


class OFPQueueProp(OFPQueuePropHeader):
    _QUEUE_PROP_PROPERTIES = {}

    @staticmethod
    def register_property(property_, len_):
        def _register_property(cls):
            cls.cls_property = property_
            cls.cls_len = len_
            OFPQueueProp._QUEUE_PROP_PROPERTIES[cls.cls_property] = cls
            return cls
        return _register_property

    def __init__(self):
        cls = self.__class__
        super(OFPQueueProp, self).__init__(cls.cls_property,
                                           cls.cls_len)

    @classmethod
    def parser(cls, buf, offset):
        (property_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR,
            buf, offset)
        cls_ = cls._QUEUE_PROP_PROPERTIES.get(property_)
        offset += ofproto_v1_2.OFP_QUEUE_PROP_HEADER_SIZE
        return cls_.parser(buf, offset)


class OFPPacketQueue(StringifyMixin):
    def __init__(self, queue_id, port, properties):
        super(OFPPacketQueue, self).__init__()
        self.queue_id = queue_id
        self.port = port
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (queue_id, port, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_PACKET_QUEUE_PACK_STR, buf, offset)
        length = ofproto_v1_2.OFP_PACKET_QUEUE_SIZE
        offset += ofproto_v1_2.OFP_PACKET_QUEUE_SIZE
        properties = []
        while length < len_:
            queue_prop = OFPQueueProp.parser(buf, offset)
            properties.append(queue_prop)
            offset += queue_prop._len
            length += queue_prop._len
        o = cls(queue_id, port, properties)
        o._len = len_
        return o


@OFPQueueProp.register_property(ofproto_v1_2.OFPQT_MIN_RATE,
                                ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_SIZE)
class OFPQueuePropMinRate(OFPQueueProp):
    def __init__(self, rate):
        super(OFPQueuePropMinRate, self).__init__()
        self.rate = rate

    @classmethod
    def parser(cls, buf, offset):
        (rate,) = struct.unpack_from(
            ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_PACK_STR, buf, offset)
        return cls(rate)


@OFPQueueProp.register_property(ofproto_v1_2.OFPQT_MAX_RATE,
                                ofproto_v1_2.OFP_QUEUE_PROP_MAX_RATE_SIZE)
class OFPQueuePropMaxRate(OFPQueueProp):
    def __init__(self, rate):
        super(OFPQueuePropMaxRate, self).__init__()
        self.rate = rate

    @classmethod
    def parser(cls, buf, offset):
        (rate,) = struct.unpack_from(
            ofproto_v1_2.OFP_QUEUE_PROP_MAX_RATE_PACK_STR, buf, offset)
        return cls(rate)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REPLY)
class OFPQueueGetConfigReply(MsgBase):
    def __init__(self, datapath, port=None, queues=None):
        super(OFPQueueGetConfigReply, self).__init__(datapath)
        self.port = port
        self.queues = queues

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPQueueGetConfigReply, cls).parser(datapath, version,
                                                        msg_type,
                                                        msg_len, xid, buf)
        (msg.port,) = struct.unpack_from(
            ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)

        msg.queues = []
        length = ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REPLY_SIZE
        offset = ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REPLY_SIZE
        while length < msg.msg_len:
            queue = OFPPacketQueue.parser(msg.buf, offset)
            msg.queues.append(queue)

            offset += queue._len
            length += queue._len

        return msg


@_set_msg_type(ofproto_v1_2.OFPT_BARRIER_REQUEST)
class OFPBarrierRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPBarrierRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_BARRIER_REPLY)
class OFPBarrierReply(MsgBase):
    def __init__(self, datapath):
        super(OFPBarrierReply, self).__init__(datapath)


@_set_msg_type(ofproto_v1_2.OFPT_ROLE_REQUEST)
class OFPRoleRequest(MsgBase):
    def __init__(self, datapath, role, generation_id):
        super(OFPRoleRequest, self).__init__(datapath)
        self.role = role
        self.generation_id = generation_id

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_2.OFP_ROLE_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE,
                      self.role, self.generation_id)


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_ROLE_REPLY)
class OFPRoleReply(MsgBase):
    def __init__(self, datapath, role=None, generation_id=None):
        super(OFPRoleReply, self).__init__(datapath)
        self.role = role
        self.generation_id = generation_id

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPRoleReply, cls).parser(datapath, version,
                                              msg_type,
                                              msg_len, xid, buf)
        (msg.role, msg.generation_id) = struct.unpack_from(
            ofproto_v1_2.OFP_ROLE_REQUEST_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)

        return msg


UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
UINT16_MAX = (1 << 16) - 1


class Flow(object):
    def __init__(self):
        self.in_port = 0
        self.in_phy_port = 0
        self.metadata = 0
        self.dl_dst = mac.DONTCARE
        self.dl_src = mac.DONTCARE
        self.dl_type = 0
        self.vlan_vid = 0
        self.vlan_pcp = 0
        self.ip_dscp = 0
        self.ip_ecn = 0
        self.ip_proto = 0
        self.ipv4_src = 0
        self.ipv4_dst = 0
        self.tcp_src = 0
        self.tcp_dst = 0
        self.udp_src = 0
        self.udp_dst = 0
        self.sctp_src = 0
        self.sctp_dst = 0
        self.icmpv4_type = 0
        self.icmpv4_code = 0
        self.arp_op = 0
        self.arp_spa = 0
        self.arp_tpa = 0
        self.arp_sha = 0
        self.arp_tha = 0
        self.ipv6_src = []
        self.ipv6_dst = []
        self.ipv6_flabel = 0
        self.icmpv6_type = 0
        self.icmpv6_code = 0
        self.ipv6_nd_target = []
        self.ipv6_nd_sll = 0
        self.ipv6_nd_tll = 0
        self.mpls_label = 0
        self.mpls_tc = 0


class FlowWildcards(object):
    def __init__(self):
        self.metadata_mask = 0
        self.dl_dst_mask = 0
        self.dl_src_mask = 0
        self.vlan_vid_mask = 0
        self.ipv4_src_mask = 0
        self.ipv4_dst_mask = 0
        self.arp_spa_mask = 0
        self.arp_tpa_mask = 0
        self.arp_sha_mask = 0
        self.arp_tha_mask = 0
        self.ipv6_src_mask = []
        self.ipv6_dst_mask = []
        self.ipv6_flabel_mask = 0
        self.wildcards = (1 << 64) - 1

    def ft_set(self, shift):
        self.wildcards &= ~(1 << shift)

    def ft_test(self, shift):
        return not self.wildcards & (1 << shift)


class OFPMatch(StringifyMixin):
    def __init__(self, fields=[], type_=None):
        super(OFPMatch, self).__init__()
        self._wc = FlowWildcards()
        self._flow = Flow()
        self.fields = []
        # accept type_ and length to be compatible with parser
        if not type_ is None:
            self.type = type_
        if fields:
            # we are doing de-stringify.
            # we have two goals:
            #   - the resulted object should be serialize()-able.
            #   - the resulted object should be inspectable by applications.
            #     ie. fields[] should be filled.
            # mimic appropriate set_foo calls and the first half of serialize.
            import sys
            this_module = sys.modules[__name__]
            for o in fields:
                assert len(o) == 1
                for k, v in o.iteritems():
                    cls = getattr(this_module, k)
                    mask = v.get("mask", None)
                    header = OFPMatchField.cls_to_header(cls, not mask is None)
                    value = v["value"]
                    value = self._decode_value(value)
                    if not mask is None:
                        mask = self._decode_value(mask)
                    f = cls(header, value, mask)
                    self.fields.append(f)

    def append_field(self, header, value, mask=None):
        self.fields.append(OFPMatchField.make(header, value, mask))

    def serialize(self, buf, offset):
        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IN_PORT):
            self.append_field(ofproto_v1_2.OXM_OF_IN_PORT,
                              self._flow.in_port)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IN_PHY_PORT):
            self.append_field(ofproto_v1_2.OXM_OF_IN_PHY_PORT,
                              self._flow.in_phy_port)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_METADATA):
            if self._wc.metadata_mask == UINT64_MAX:
                header = ofproto_v1_2.OXM_OF_METADATA
            else:
                header = ofproto_v1_2.OXM_OF_METADATA_W
            self.append_field(header, self._flow.metadata,
                              self._wc.metadata_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ETH_DST):
            if self._wc.dl_dst_mask:
                header = ofproto_v1_2.OXM_OF_ETH_DST_W
            else:
                header = ofproto_v1_2.OXM_OF_ETH_DST
            self.append_field(header, self._flow.dl_dst, self._wc.dl_dst_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ETH_SRC):
            if self._wc.dl_src_mask:
                header = ofproto_v1_2.OXM_OF_ETH_SRC_W
            else:
                header = ofproto_v1_2.OXM_OF_ETH_SRC
            self.append_field(header, self._flow.dl_src, self._wc.dl_src_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ETH_TYPE):
            self.append_field(ofproto_v1_2.OXM_OF_ETH_TYPE, self._flow.dl_type)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_VLAN_VID):
            if self._wc.vlan_vid_mask == UINT16_MAX:
                header = ofproto_v1_2.OXM_OF_VLAN_VID
            else:
                header = ofproto_v1_2.OXM_OF_VLAN_VID_W
            self.append_field(header, self._flow.vlan_vid,
                              self._wc.vlan_vid_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_VLAN_PCP):
            self.append_field(ofproto_v1_2.OXM_OF_VLAN_PCP,
                              self._flow.vlan_pcp)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IP_DSCP):
            self.append_field(ofproto_v1_2.OXM_OF_IP_DSCP, self._flow.ip_dscp)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IP_ECN):
            self.append_field(ofproto_v1_2.OXM_OF_IP_ECN, self._flow.ip_ecn)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IP_PROTO):
            self.append_field(ofproto_v1_2.OXM_OF_IP_PROTO,
                              self._flow.ip_proto)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV4_SRC):
            if self._wc.ipv4_src_mask == UINT32_MAX:
                header = ofproto_v1_2.OXM_OF_IPV4_SRC
            else:
                header = ofproto_v1_2.OXM_OF_IPV4_SRC_W
            self.append_field(header, self._flow.ipv4_src,
                              self._wc.ipv4_src_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV4_DST):
            if self._wc.ipv4_dst_mask == UINT32_MAX:
                header = ofproto_v1_2.OXM_OF_IPV4_DST
            else:
                header = ofproto_v1_2.OXM_OF_IPV4_DST_W
            self.append_field(header, self._flow.ipv4_dst,
                              self._wc.ipv4_dst_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_TCP_SRC):
            self.append_field(ofproto_v1_2.OXM_OF_TCP_SRC, self._flow.tcp_src)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_TCP_DST):
            self.append_field(ofproto_v1_2.OXM_OF_TCP_DST, self._flow.tcp_dst)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_UDP_SRC):
            self.append_field(ofproto_v1_2.OXM_OF_UDP_SRC, self._flow.udp_src)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_UDP_DST):
            self.append_field(ofproto_v1_2.OXM_OF_UDP_DST, self._flow.udp_dst)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_SCTP_SRC):
            self.append_field(ofproto_v1_2.OXM_OF_SCTP_SRC,
                              self._flow.sctp_src)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_SCTP_DST):
            self.append_field(ofproto_v1_2.OXM_OF_SCTP_DST,
                              self._flow.sctp_dst)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ICMPV4_TYPE):
            self.append_field(ofproto_v1_2.OXM_OF_ICMPV4_TYPE,
                              self._flow.icmpv4_type)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ICMPV4_CODE):
            self.append_field(ofproto_v1_2.OXM_OF_ICMPV4_CODE,
                              self._flow.icmpv4_code)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ARP_OP):
            self.append_field(ofproto_v1_2.OXM_OF_ARP_OP, self._flow.arp_op)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ARP_SPA):
            if self._wc.arp_spa_mask == UINT32_MAX:
                header = ofproto_v1_2.OXM_OF_ARP_SPA
            else:
                header = ofproto_v1_2.OXM_OF_ARP_SPA_W
            self.append_field(header, self._flow.arp_spa,
                              self._wc.arp_spa_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ARP_TPA):
            if self._wc.arp_tpa_mask == UINT32_MAX:
                header = ofproto_v1_2.OXM_OF_ARP_TPA
            else:
                header = ofproto_v1_2.OXM_OF_ARP_TPA_W
            self.append_field(header, self._flow.arp_tpa,
                              self._wc.arp_tpa_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ARP_SHA):
            if self._wc.arp_sha_mask:
                header = ofproto_v1_2.OXM_OF_ARP_SHA_W
            else:
                header = ofproto_v1_2.OXM_OF_ARP_SHA
            self.append_field(header, self._flow.arp_sha,
                              self._wc.arp_sha_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ARP_THA):
            if self._wc.arp_tha_mask:
                header = ofproto_v1_2.OXM_OF_ARP_THA_W
            else:
                header = ofproto_v1_2.OXM_OF_ARP_THA
            self.append_field(header, self._flow.arp_tha,
                              self._wc.arp_tha_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV6_SRC):
            if len(self._wc.ipv6_src_mask):
                header = ofproto_v1_2.OXM_OF_IPV6_SRC_W
            else:
                header = ofproto_v1_2.OXM_OF_IPV6_SRC
            self.append_field(header, self._flow.ipv6_src,
                              self._wc.ipv6_src_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV6_DST):
            if len(self._wc.ipv6_dst_mask):
                header = ofproto_v1_2.OXM_OF_IPV6_DST_W
            else:
                header = ofproto_v1_2.OXM_OF_IPV6_DST
            self.append_field(header, self._flow.ipv6_dst,
                              self._wc.ipv6_dst_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV6_FLABEL):
            if self._wc.ipv6_flabel_mask == UINT32_MAX:
                header = ofproto_v1_2.OXM_OF_IPV6_FLABEL
            else:
                header = ofproto_v1_2.OXM_OF_IPV6_FLABEL_W
            self.append_field(header, self._flow.ipv6_flabel,
                              self._wc.ipv6_flabel_mask)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ICMPV6_TYPE):
            self.append_field(ofproto_v1_2.OXM_OF_ICMPV6_TYPE,
                              self._flow.icmpv6_type)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_ICMPV6_CODE):
            self.append_field(ofproto_v1_2.OXM_OF_ICMPV6_CODE,
                              self._flow.icmpv6_code)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_TARGET):
            self.append_field(ofproto_v1_2.OXM_OF_IPV6_ND_TARGET,
                              self._flow.ipv6_nd_target)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_SLL):
            self.append_field(ofproto_v1_2.OXM_OF_IPV6_ND_SLL,
                              self._flow.ipv6_nd_sll)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_TLL):
            self.append_field(ofproto_v1_2.OXM_OF_IPV6_ND_TLL,
                              self._flow.ipv6_nd_tll)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_MPLS_LABEL):
            self.append_field(ofproto_v1_2.OXM_OF_MPLS_LABEL,
                              self._flow.mpls_label)

        if self._wc.ft_test(ofproto_v1_2.OFPXMT_OFB_MPLS_TC):
            self.append_field(ofproto_v1_2.OXM_OF_MPLS_TC,
                              self._flow.mpls_tc)

        field_offset = offset + 4
        for f in self.fields:
            f.serialize(buf, field_offset)
            field_offset += f.length

        length = field_offset - offset
        msg_pack_into('!HH', buf, offset, ofproto_v1_2.OFPMT_OXM, length)

        pad_len = utils.round_up(length, 8) - length
        ofproto_parser.msg_pack_into("%dx" % pad_len, buf, field_offset)

        return length + pad_len

    @classmethod
    def parser(cls, buf, offset):
        match = OFPMatch()
        type_, length = struct.unpack_from('!HH', buf, offset)

        match.type = type_
        match._length = length

        # ofp_match adjustment
        offset += 4
        length -= 4
        while length > 0:
            field = OFPMatchField.parser(buf, offset)
            offset += field.length
            length -= field.length
            match.fields.append(field)

        return match

    def set_in_port(self, port):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IN_PORT)
        self._flow.in_port = port

    def set_in_phy_port(self, phy_port):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IN_PHY_PORT)
        self._flow.in_phy_port = phy_port

    def set_metadata(self, metadata):
        self.set_metadata_masked(metadata, UINT64_MAX)

    def set_metadata_masked(self, metadata, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_METADATA)
        self._wc.metadata_mask = mask
        self._flow.metadata = metadata & mask

    def set_dl_dst(self, dl_dst):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ETH_DST)
        self._flow.dl_dst = dl_dst

    def set_dl_dst_masked(self, dl_dst, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ETH_DST)
        self._wc.dl_dst_mask = mask
        # bit-wise and of the corresponding elements of dl_dst and mask
        self._flow.dl_dst = mac.haddr_bitand(dl_dst, mask)

    def set_dl_src(self, dl_src):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ETH_SRC)
        self._flow.dl_src = dl_src

    def set_dl_src_masked(self, dl_src, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ETH_SRC)
        self._wc.dl_src_mask = mask
        self._flow.dl_src = mac.haddr_bitand(dl_src, mask)

    def set_dl_type(self, dl_type):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ETH_TYPE)
        self._flow.dl_type = dl_type

    def set_vlan_vid(self, vid):
        self.set_vlan_vid_masked(vid, UINT16_MAX)

    def set_vlan_vid_masked(self, vid, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_VLAN_VID)
        self._wc.vlan_vid_mask = mask
        self._flow.vlan_vid = vid

    def set_vlan_pcp(self, pcp):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_VLAN_PCP)
        self._flow.vlan_pcp = pcp

    def set_ip_dscp(self, ip_dscp):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IP_DSCP)
        self._flow.ip_dscp = ip_dscp

    def set_ip_ecn(self, ip_ecn):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IP_ECN)
        self._flow.ip_ecn = ip_ecn

    def set_ip_proto(self, ip_proto):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IP_PROTO)
        self._flow.ip_proto = ip_proto

    def set_ipv4_src(self, ipv4_src):
        self.set_ipv4_src_masked(ipv4_src, UINT32_MAX)

    def set_ipv4_src_masked(self, ipv4_src, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV4_SRC)
        self._flow.ipv4_src = ipv4_src
        self._wc.ipv4_src_mask = mask

    def set_ipv4_dst(self, ipv4_dst):
        self.set_ipv4_dst_masked(ipv4_dst, UINT32_MAX)

    def set_ipv4_dst_masked(self, ipv4_dst, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV4_DST)
        self._flow.ipv4_dst = ipv4_dst
        self._wc.ipv4_dst_mask = mask

    def set_tcp_src(self, tcp_src):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_TCP_SRC)
        self._flow.tcp_src = tcp_src

    def set_tcp_dst(self, tcp_dst):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_TCP_DST)
        self._flow.tcp_dst = tcp_dst

    def set_udp_src(self, udp_src):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_UDP_SRC)
        self._flow.udp_src = udp_src

    def set_udp_dst(self, udp_dst):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_UDP_DST)
        self._flow.udp_dst = udp_dst

    def set_sctp_src(self, sctp_src):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_SCTP_SRC)
        self._flow.sctp_src = sctp_src

    def set_sctp_dst(self, sctp_dst):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_SCTP_DST)
        self._flow.sctp_dst = sctp_dst

    def set_icmpv4_type(self, icmpv4_type):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ICMPV4_TYPE)
        self._flow.icmpv4_type = icmpv4_type

    def set_icmpv4_code(self, icmpv4_code):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ICMPV4_CODE)
        self._flow.icmpv4_code = icmpv4_code

    def set_arp_opcode(self, arp_op):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ARP_OP)
        self._flow.arp_op = arp_op

    def set_arp_spa(self, arp_spa):
        self.set_arp_spa_masked(arp_spa, UINT32_MAX)

    def set_arp_spa_masked(self, arp_spa, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ARP_SPA)
        self._wc.arp_spa_mask = mask
        self._flow.arp_spa = arp_spa

    def set_arp_tpa(self, arp_tpa):
        self.set_arp_tpa_masked(arp_tpa, UINT32_MAX)

    def set_arp_tpa_masked(self, arp_tpa, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ARP_TPA)
        self._wc.arp_tpa_mask = mask
        self._flow.arp_tpa = arp_tpa

    def set_arp_sha(self, arp_sha):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ARP_SHA)
        self._flow.arp_sha = arp_sha

    def set_arp_sha_masked(self, arp_sha, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ARP_SHA)
        self._wc.arp_sha_mask = mask
        self._flow.arp_sha = mac.haddr_bitand(arp_sha, mask)

    def set_arp_tha(self, arp_tha):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ARP_THA)
        self._flow.arp_tha = arp_tha

    def set_arp_tha_masked(self, arp_tha, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ARP_THA)
        self._wc.arp_tha_mask = mask
        self._flow.arp_tha = mac.haddr_bitand(arp_tha, mask)

    def set_ipv6_src(self, src):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_SRC)
        self._flow.ipv6_src = src

    def set_ipv6_src_masked(self, src, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_SRC)
        self._wc.ipv6_src_mask = mask
        self._flow.ipv6_src = [x & y for (x, y) in itertools.izip(src, mask)]

    def set_ipv6_dst(self, dst):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_DST)
        self._flow.ipv6_dst = dst

    def set_ipv6_dst_masked(self, dst, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_DST)
        self._wc.ipv6_dst_mask = mask
        self._flow.ipv6_dst = [x & y for (x, y) in itertools.izip(dst, mask)]

    def set_ipv6_flabel(self, flabel):
        self.set_ipv6_flabel_masked(flabel, UINT32_MAX)

    def set_ipv6_flabel_masked(self, flabel, mask):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_FLABEL)
        self._wc.ipv6_flabel_mask = mask
        self._flow.ipv6_flabel = flabel

    def set_icmpv6_type(self, icmpv6_type):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ICMPV6_TYPE)
        self._flow.icmpv6_type = icmpv6_type

    def set_icmpv6_code(self, icmpv6_code):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_ICMPV6_CODE)
        self._flow.icmpv6_code = icmpv6_code

    def set_ipv6_nd_target(self, target):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_TARGET)
        self._flow.ipv6_nd_target = target

    def set_ipv6_nd_sll(self, ipv6_nd_sll):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_SLL)
        self._flow.ipv6_nd_sll = ipv6_nd_sll

    def set_ipv6_nd_tll(self, ipv6_nd_tll):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_TLL)
        self._flow.ipv6_nd_tll = ipv6_nd_tll

    def set_mpls_label(self, mpls_label):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_MPLS_LABEL)
        self._flow.mpls_label = mpls_label

    def set_mpls_tc(self, mpls_tc):
        self._wc.ft_set(ofproto_v1_2.OFPXMT_OFB_MPLS_TC)
        self._flow.mpls_tc = mpls_tc


class OFPMatchField(StringifyMixin):
    _FIELDS_HEADERS = {}

    @staticmethod
    def register_field_header(headers):
        def _register_field_header(cls):
            for header in headers:
                OFPMatchField._FIELDS_HEADERS[header] = cls
            return cls
        return _register_field_header

    def __init__(self, header):
        self.header = header
        self.n_bytes = ofproto_v1_2.oxm_tlv_header_extract_length(header)
        self.length = 0

    @classmethod
    def cls_to_header(cls, cls_, hasmask):
        # XXX efficiency
        inv = dict((v, k) for k, v in cls._FIELDS_HEADERS.iteritems()
                   if (((k >> 8) & 1) != 0) == hasmask)
        return inv[cls_]

    @staticmethod
    def make(header, value, mask=None):
        cls_ = OFPMatchField._FIELDS_HEADERS.get(header)
        return cls_(header, value, mask)

    @classmethod
    def parser(cls, buf, offset):
        (header,) = struct.unpack_from('!I', buf, offset)
        cls_ = OFPMatchField._FIELDS_HEADERS.get(header)
        if cls_:
            field = cls_.field_parser(header, buf, offset)
        else:
            field = OFPMatchField(header)
        field.length = (header & 0xff) + 4
        return field

    @classmethod
    def field_parser(cls, header, buf, offset):
        mask = None
        if ofproto_v1_2.oxm_tlv_header_extract_hasmask(header):
            pack_str = '!' + cls.pack_str[1:] * 2
            (value, mask) = struct.unpack_from(pack_str, buf, offset + 4)
        else:
            (value,) = struct.unpack_from(cls.pack_str, buf, offset + 4)
        return cls(header, value, mask)

    def serialize(self, buf, offset):
        if ofproto_v1_2.oxm_tlv_header_extract_hasmask(self.header):
            self.put_w(buf, offset, self.value, self.mask)
        else:
            self.put(buf, offset, self.value)

    def _put_header(self, buf, offset):
        ofproto_parser.msg_pack_into('!I', buf, offset, self.header)
        self.length += 4

    def _put(self, buf, offset, value):
        ofproto_parser.msg_pack_into(self.pack_str, buf, offset, value)
        self.length += self.n_bytes

    def put_w(self, buf, offset, value, mask):
        self._put_header(buf, offset)
        self._put(buf, offset + self.length, value)
        self._put(buf, offset + self.length, mask)

    def put(self, buf, offset, value):
        self._put_header(buf, offset)
        self._put(buf, offset + self.length, value)

    def _putv6(self, buf, offset, value):
        ofproto_parser.msg_pack_into(self.pack_str, buf, offset,
                                     *value)
        self.length += self.n_bytes

    def putv6(self, buf, offset, value, mask=None):
        self._put_header(buf, offset)
        self._putv6(buf, offset + self.length, value)
        if mask and len(mask):
            self._putv6(buf, offset + self.length, mask)

    def oxm_len(self):
        return self.header & 0xff

    def to_jsondict(self):
        # remove some redundant attributes
        d = super(OFPMatchField, self).to_jsondict()
        v = d[self.__class__.__name__]
        del v['header']
        del v['length']
        del v['n_bytes']
        return d

    @classmethod
    def from_jsondict(cls, dict_):
        # just pass the dict around.
        # it will be converted by OFPMatch.__init__().
        return {cls.__name__: dict_}

    def stringify_attrs(self):
        f = super(OFPMatchField, self).stringify_attrs
        if not ofproto_v1_2.oxm_tlv_header_extract_hasmask(self.header):
            # something like the following, but yield two values (k,v)
            # return itertools.ifilter(lambda k, v: k != 'mask', iter())
            def g():
                for k, v in f():
                    if k != 'mask':
                        yield (k, v)
            return g()
        else:
            return f()


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IN_PORT])
class MTInPort(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTInPort, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_METADATA,
                                      ofproto_v1_2.OXM_OF_METADATA_W])
class MTMetadata(OFPMatchField):
    pack_str = '!Q'

    def __init__(self, header, value, mask=None):
        super(MTMetadata, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IN_PHY_PORT])
class MTInPhyPort(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTInPhyPort, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ETH_DST,
                                      ofproto_v1_2.OXM_OF_ETH_DST_W])
class MTEthDst(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTEthDst, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ETH_SRC,
                                      ofproto_v1_2.OXM_OF_ETH_SRC_W])
class MTEthSrc(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTEthSrc, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ETH_TYPE])
class MTEthType(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTEthType, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_VLAN_VID,
                                      ofproto_v1_2.OXM_OF_VLAN_VID_W])
class MTVlanVid(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTVlanVid, self).__init__(header)
        self.value = value
        self.mask = mask

    @classmethod
    def field_parser(cls, header, buf, offset):
        m = super(MTVlanVid, cls).field_parser(header, buf, offset)
        m.value &= ~ofproto_v1_2.OFPVID_PRESENT
        return m

    def serialize(self, buf, offset):
        self.value |= ofproto_v1_2.OFPVID_PRESENT
        super(MTVlanVid, self).serialize(buf, offset)


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_VLAN_PCP])
class MTVlanPcp(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTVlanPcp, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IP_DSCP])
class MTIPDscp(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTIPDscp, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IP_ECN])
class MTIPECN(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTIPECN, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IP_PROTO])
class MTIPProto(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTIPProto, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV4_SRC,
                                      ofproto_v1_2.OXM_OF_IPV4_SRC_W])
class MTIPV4Src(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTIPV4Src, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV4_DST,
                                      ofproto_v1_2.OXM_OF_IPV4_DST_W])
class MTIPV4Dst(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTIPV4Dst, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_TCP_SRC])
class MTTCPSrc(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTTCPSrc, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_TCP_DST])
class MTTCPDst(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTTCPDst, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_UDP_SRC])
class MTUDPSrc(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTUDPSrc, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_UDP_DST])
class MTUDPDst(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTUDPDst, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_SCTP_SRC])
class MTSCTPSrc(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTSCTPSrc, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_SCTP_DST])
class MTSCTPDst(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTSCTPDst, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ICMPV4_TYPE])
class MTICMPV4Type(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV4Type, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ICMPV4_CODE])
class MTICMPV4Code(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV4Code, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ARP_OP])
class MTArpOp(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTArpOp, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ARP_SPA,
                                      ofproto_v1_2.OXM_OF_ARP_SPA_W])
class MTArpSpa(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTArpSpa, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ARP_TPA,
                                      ofproto_v1_2.OXM_OF_ARP_TPA_W])
class MTArpTpa(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTArpTpa, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ARP_SHA,
                                      ofproto_v1_2.OXM_OF_ARP_SHA_W])
class MTArpSha(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTArpSha, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ARP_THA,
                                      ofproto_v1_2.OXM_OF_ARP_THA_W])
class MTArpTha(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTArpTha, self).__init__(header)
        self.value = value
        self.mask = mask


class MTIPv6(object):
    @classmethod
    def field_parser(cls, header, buf, offset):
        if ofproto_v1_2.oxm_tlv_header_extract_hasmask(header):
            pack_str = '!' + cls.pack_str[1:] * 2
            value = struct.unpack_from(pack_str, buf, offset + 4)
            return cls(header, list(value[:8]), list(value[8:]))
        else:
            value = struct.unpack_from(cls.pack_str, buf, offset + 4)
            return cls(header, list(value))

    def serialize(self, buf, offset):
        self.putv6(buf, offset, self.value, self.mask)


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV6_SRC,
                                      ofproto_v1_2.OXM_OF_IPV6_SRC_W])
class MTIPv6Src(MTIPv6, OFPMatchField):
    pack_str = '!8H'

    def __init__(self, header, value, mask=None):
        super(MTIPv6Src, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV6_DST,
                                      ofproto_v1_2.OXM_OF_IPV6_DST_W])
class MTIPv6Dst(MTIPv6, OFPMatchField):
    pack_str = '!8H'

    def __init__(self, header, value, mask=None):
        super(MTIPv6Dst, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV6_FLABEL,
                                      ofproto_v1_2.OXM_OF_IPV6_FLABEL_W])
class MTIPv6Flabel(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTIPv6Flabel, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_MPLS_LABEL])
class MTMplsLabel(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTMplsLabel, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ICMPV6_TYPE])
class MTICMPV6Type(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV6Type, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_ICMPV6_CODE])
class MTICMPV6Code(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV6Code, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV6_ND_TARGET])
class MTIPv6NdTarget(MTIPv6, OFPMatchField):
    pack_str = '!8H'

    def __init__(self, header, value, mask=None):
        super(MTIPv6NdTarget, self).__init__(header)
        self.value = value

    def serialize(self, buf, offset):
        self.putv6(buf, offset, self.value)


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV6_ND_SLL])
class MTIPv6NdSll(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTIPv6NdSll, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_IPV6_ND_TLL])
class MTIPv6NdTll(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTIPv6NdTll, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto_v1_2.OXM_OF_MPLS_TC])
class MTMplsTc(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTMplsTc, self).__init__(header)
        self.value = value
