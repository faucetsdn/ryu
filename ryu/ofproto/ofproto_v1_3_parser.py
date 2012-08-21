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

import collections
import struct

from ofproto_parser import MsgBase, msg_pack_into, msg_str_attr
from . import ofproto_parser
from . import ofproto_v1_3

import logging
LOG = logging.getLogger('ryu.ofproto.ofproto_v1_3_parser')

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


@ofproto_parser.register_msg_parser(ofproto_v1_3.OFP_VERSION)
def msg_parser(datapath, version, msg_type, msg_len, xid, buf):
    parser = _MSG_PARSERS.get(msg_type)
    return parser(datapath, version, msg_type, msg_len, xid, buf)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_HELLO)
class OFPHello(MsgBase):
    def __init__(self, datapath):
        super(OFPHello, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_ERROR)
class OFPErrorMsg(MsgBase):
    def __init__(self, datapath):
        super(OFPErrorMsg, self).__init__(datapath)
        self.type = None
        self.code = None
        self.data = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPErrorMsg, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        msg.type, msg.code = struct.unpack_from(
            ofproto_v1_3.OFP_ERROR_MSG_PACK_STR, msg.buf,
            ofproto_v1_3.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_3.OFP_ERROR_MSG_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        msg_pack_into(ofproto_v1_3.OFP_ERROR_MSG_PACK_STR, self.buf,
                      ofproto_v1_3.OFP_HEADER_SIZE, self.type, self.code)
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_ECHO_REQUEST)
class OFPEchoRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPEchoRequest, self).__init__(datapath)
        self.data = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoRequest, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)
        msg.data = msg.buf[ofproto_v1_3.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        if self.data is not None:
            self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_ECHO_REPLY)
class OFPEchoReply(MsgBase):
    def __init__(self, datapath):
        super(OFPEchoReply, self).__init__(datapath)
        self.data = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoReply, cls).parser(datapath, version, msg_type,
                                              msg_len, xid, buf)
        msg.data = msg.buf[ofproto_v1_3.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_EXPERIMENTER)
class OFPExperimenter(MsgBase):
    def __init__(self, datapath, experimenter=None, exp_type=None):
        super(OFPExperimenter, self).__init__(datapath)
        self.experimenter = experimenter
        self.exp_type = exp_type

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPExperimenter, cls).parser(datapath, version,
                                                 msg_type, msg_len,
                                                 xid, buf)
        (msg.experimenter, msg.exp_type) = struct.unpack_from(
            ofproto_v1_3.OFP_EXPERIMENTER_HEADER_PACK_STR, msg.buf,
            ofproto_v1_3.OFP_HEADER_SIZE)
        return msg

    def _serialize_body(self):
        msg.pack_into(ofproto_v1_3.OFP_EXPERIMENTER_HEADERPACK_STR,
                      self.buf, ofproto_v1_3.OFP_HEADER_SIZE,
                      self.experimenter, self.exp_type)


@_set_msg_type(ofproto_v1_3.OFPT_FEATURES_REQUEST)
class OFPFeaturesRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPFeaturesRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_FEATURES_REPLY)
class OFPSwitchFeatures(MsgBase):
    def __init__(self, datapath):
        super(OFPSwitchFeatures, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSwitchFeatures, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        (msg.datapath_id,
         msg.n_buffers,
         msg.n_tables,
         msg.auxiliary_id,
         msg.capabilities,
         msg.reserved) = struct.unpack_from(
             ofproto_v1_3.OFP_SWITCH_FEATURES_PACK_STR, msg.buf,
             ofproto_v1_3.OFP_HEADER_SIZE)
        return msg


@_set_msg_type(ofproto_v1_3.OFPT_GET_CONFIG_REQUEST)
class OFPGetConfigRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPGetConfigRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_GET_CONFIG_REPLY)
class OFPGetConfigReply(MsgBase):
    def __init__(self, datapath):
        super(OFPGetConfigReply, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPGetConfigReply, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        msg.flags, msg.miss_send_len = struct.unpack_from(
            ofproto_v1_3.OFP_SWITCH_CONFIG_PACK_STR, buf,
            ofproto_v1_3.OFP_HEADER_SIZE)
        return msg


@_set_msg_type(ofproto_v1_3.OFPT_SET_CONFIG)
class OFPSetConfig(MsgBase):
    def __init__(self, datapath, flags=None, miss_send_len=None):
        super(OFPSetConfig, self).__init__(datapath)
        self.flags = flags
        self.miss_send_len = miss_send_len

    def _serialize_body(self):
        assert self.flags is not None
        assert self.miss_send_len is not None
        msg_pack_into(ofproto_v1_3.OFP_SWITCH_CONFIG_PACK_STR,
                      self.buf, ofproto_v1_3.OFP_HEADER_SIZE,
                      self.flags, self.miss_send_len)


class OFPMatch(object):
    def __init__(self):
        super(OFPMatch, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        pass


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_PACKET_IN)
class OFPPacketIn(MsgBase):
    def __init__(self, datapath):
        super(OFPPacketIn, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPacketIn, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        (msg.buffer_id, msg.total_len, msg.reason,
         msg.table_id, msg.cookie) = struct.unpack_from(
             ofproto_v1_3.OFP_PACKET_IN_PACK_STR,
             msg.buf, ofproto_v1_3.OFP_HEADER_SIZE)

        offset = ofproto_v1_3.OFP_HEADER_SIZE + ofproto_v1_3.OFP_PACKET_IN_SIZE
        msg.match = OFPMatch.parser(buf, offset - ofproto_v1_3.OFP_MATCH_SIZE)
        return msg


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_FLOW_REMOVED)
class OFPFlowRemoved(MsgBase):
    def __init__(self, datapath):
        super(OFPFlowRemoved, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPFlowRemoved, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)

        (msg.cookie, msg.priority, msg.reason,
         msg.table_id, msg.duration_sec, msg.duration_nsec,
         msg.idle_timeout, msg.hard_timeout, msg.packet_count,
         msg.byte_count) = struct.unpack_from(
             ofproto_v1_3.OFP_FLOW_REMOVED_PACK_STR0,
             msg.buf, ofproto_v1_3.OFP_HEADER_SIZE)

        offset = (ofproto_v1_3.OFP_FLOW_REMOVED_SIZE -
                  ofproto_v1_3.OFP_MATCH_SIZE)

        msg.match = OFPMatch(buf, offset)

        return msg


class OFPPort(collections.namedtuple('OFPPort', (
        'port_no', 'hw_addr', 'name', 'config', 'state', 'curr',
        'advertised', 'supported', 'peer', 'curr_speed', 'max_speed'))):

    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto_v1_3.OFP_PORT_PACK_STR, buf, offset)
        return cls(*port)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_PORT_STATUS)
class OFPPortStatus(MsgBase):
    def __init__(self, datapath):
        super(OFPPortStatus, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPortStatus, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        (msg.reason,) = struct.unpack_from(
            ofproto_v1_3.OFP_PORT_STATUS_PACK_STR, msg.buf,
            ofproto_v1_3.OFP_HEADER_SIZE)
        msg.desc = OFPPort.parser(msg.buf,
                                  ofproto_v1_3.OFP_PORT_STATUS_DESC_OFFSET)
        return msg


@_set_msg_type(ofproto_v1_3.OFPT_PACKET_OUT)
class OFPPacketOut(MsgBase):
    def __init__(self, datapath, buffer_id=None, inport=None, actions=None,
                 data=None):
        assert in_port is not None

        super(OFPPacketOut, self).__init__(datapath)
        self.buffer_id = buffer_id
        self.in_port = in_port
        self.actions_len = 0
        self.actions = actions
        self.data = data

    def _serialize_body(self):
        self.actions_len = 0
        offset = ofproto_v1_3.OFP_PACKET_OUT_SIZE
        for a in self.actions:
            a.serialize(self.buf, offset)
            offset += a.len
            self.actions_len += a.len

        if self.data is not None:
            assert self.buffer_id == 0xffffffff
            self.buf += self.data

        msg_pack_into(ofproto_v1_3.OFP_PACKET_OUT_PACK_STR,
                      self.buf, ofproto_v1_3.OFP_HEADER_SIZE,
                      self.buffer_id, self.in_port, self.actions_len)


@_set_msg_type(ofproto_v1_3.OFPT_FLOW_MOD)
class OFPFlowMod(MsgBase):
    def __init__(self, datapath, cookie, cookie_mask, table_id, command,
                 idle_timeout, hard_timeout, priority, buffer_id, out_port,
                 out_group, flags, match):
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

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_3.OFP_FLOW_MOD_PACK_STR0, self.buf,
                      ofproto_v1_3.OFP_HEADER_SIZE,
                      self.cookie, self.cookie_mask, self.table_id,
                      self.command, self.idle_timeout, self.hard_timeout,
                      self.priority, self.buffer_id, self.out_port,
                      self.out_group, self.flags)

        offset = (ofproto_v1_3.OFP_OFP_FLOW_MOD_SIZE -
                  ofproto_v1_3.OFP_MATCH_SIZE - ofproto_v1_3.OFP_HEADER_SIZE)
        self.match.serialize(self.buf, offset)


class OFPActionHeader(object):
    def __init__(self, type_, len_):
        self.type = type_
        self.len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_HEADER_PACK_STR,
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
            ofproto_v1_3.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        cls_ = cls._ACTION_TYPES.get(type_)
        assert cls_ is not None
        return cls_.parser(buf, offset)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_OUTPUT,
                                ofproto_v1_3.OFP_ACTION_OUTPUT_SIZE)
class OFPActionOutput(OFPAction):
    def __init__(self, port, max_len):
        super(OFPActionOutput, self).__init__()
        self.port = port
        self.max_len = max_len

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, port, max_len = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_OUTPUT_PACK_STR, buf, offset)
        return cls(port, max_len)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_OUTPUT_PACK_STR, buf,
                      offset, self.type, self.len, self.port, self.max_len)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_GROUP,
                                ofproto_v1_3.OFP_ACTION_GROUP_SIZE)
class OFPActionGroup(OFPAction):
    def __init__(self, group_id):
        super(OFPActionGroup, self).__init__()
        self.group_id = group_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, group_id) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_GROUP_PACK_STR, buf, offset)
        return cls(group_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_GROUP_PACK_STR, buf,
                      offset, self.type, self.len, self.group_id)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_SET_QUEUE,
                                ofproto_v1_3.OFP_ACTION_SET_QUEUE_SIZE)
class OFPActionSetQueue(OFPAction):
    def __init__(self, queue_id):
        super(OFPActionSetQueue, self).__init__()
        self.queue_id = queue_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, queue_id) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_SET_QUEUE_PACK_STR, buf, offset)
        return cls(queue_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_SET_QUEUE_PACK_STR, buf,
                      offset, self.type, self.len, self.queue_id)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_SET_MPLS_TTL,
                                ofproto_v1_3.OFP_ACTION_MPLS_TTL_SIZE)
class OFPActionSetMplsTtl(OFPAction):
    def __init__(self, mpls_ttl):
        super(OFPActionSetMplsTtl, self).__init__()
        self.mpls_ttl = mpls_ttl

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, mpls_ttl) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_MPLS_TTL_PACK_STR, buf, offset)
        return cls(mpls_ttl)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_MPLS_TTL_PACK_STR, buf,
                      offset, self.type, self.len, self.mpls_ttl)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_DEC_MPLS_TTL,
                                ofproto_v1_3.OFP_ACTION_HEADER_SIZE)
class OFPActionDecMplsTtl(OFPAction):
    def __init__(self):
        super(OFPActionDecMplsTtl, self).__init__()


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_SET_NW_TTL,
                                ofproto_v1_3.OFP_ACTION_NW_TTL_SIZE)
class OFPActionSetNwTtl(OFPAction):
    def __init__(self, nw_ttl):
        super(OFPActionSetNwTtl, self).__init__()
        self.nw_ttl = nw_ttl

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, nw_ttl) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_NW_TTL_PACK_STR, buf, offset)
        return cls(nw_ttl)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_NW_TTL_PACK_STR, buf, offset,
                      self.type, self.len, self.nw_ttl)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_DEC_NW_TTL,
                                ofproto_v1_3.OFP_ACTION_HEADER_SIZE)
class OFPActionDecNwTtl(OFPAction):
    def __init__(self):
        super(OFPActionDecNwTtl, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_COPY_TTL_OUT,
                                ofproto_v1_3.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlOut(OFPAction):
    def __init__(self):
        super(OFPActionCopyTtlOut, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_COPY_TTL_IN,
                                ofproto_v1_3.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlIn(OFPAction):
    def __init__(self):
        super(OFPActionCopyTtlIn, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_PUSH_VLAN,
                                ofproto_v1_3.OFP_ACTION_PUSH_SIZE)
class OFPActionPushVlan(OFPAction):
    def __init__(self, ethertype):
        super(OFPActionPushVlan, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_PUSH_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_PUSH_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_PUSH_MPLS,
                                ofproto_v1_3.OFP_ACTION_PUSH_SIZE)
class OFPActionPushMpls(OFPAction):
    def __init__(self, ethertype):
        super(OFPActionPushMpls, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_PUSH_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_PUSH_PACK_STR, buf, offset,
                      self.ethertype)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_POP_VLAN,
                                ofproto_v1_3.OFP_ACTION_HEADER_SIZE)
class OFPActionPopVlan(OFPAction):
    def __init__(self):
        super(OFPActionPopVlan, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_POP_MPLS,
                                ofproto_v1_3.OFP_ACTION_POP_MPLS_SIZE)
class OFPActionPopMpls(OFPAction):
    def __init__(self, ethertype):
        super(OFPActionPopMpls, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_POP_MPLS_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_POP_MPLS_PACK_STR, buff, offset,
                      self.ethertype)


@OFPAction.register_action_type(ofproto_v1_3.OFPAT_SET_FIELD,
                                ofproto_v1_3.OFP_ACTION_SET_FIELD_SIZE)
class OFPActionSetField(OFPAction):
    def __init__(self):
        super(OFPActionSetField, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_SET_FIELD_PACK_STR, buf, offset)
        action = cls()
        # TODO: parse OXM
        return action

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_SET_FIELD_PACK_STR, buf, offset)
        # TODO: serialize OXM


@OFPAction.register_action_type(
    ofproto_v1_3.OFPAT_EXPERIMENTER,
    ofproto_v1_3.OFP_ACTION_EXPERIMENTER_HEADER_SIZE)
class OFPActionExperimenter(OFPAction):
    def __init__(self, experimenter):
        super(OFPActionExperimenter, self).__init__()
        self.experimenter = experimenter

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, experimenter) = struct.unpack_from(
            ofproto_v1_3.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR, buf, offset)
        return cls(experimenter)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR,
                      buf, offset, self.type, self.len, self.experimenter)


class OFPBucket(object):
    def __init__(self, len_, weight, watch_port, watch_group, actions):
        super(OFPBucket, self).__init__()
        self.len = len_
        self.weight = weight
        self.watch_port = watch_port
        self.watch_group = watch_group
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        (msg.len, msg.weigth, msg.watch_port,
         msg.watch_group) = struct.unpack_from(
             ofproto_v1_3.OFP_BUCKET_PACK_STR, buf, offset)

        length = ofproto_v1_3.OFP_BUCKET_SIZE
        offset += ofproto_v1_3.OFP_BUCKET_SIZE
        msg.actions = []
        while length < msg.len:
            action = OFPAction.parser(buf, offset)
            msg.actions.append(action)
            offset += action.len
            length += action.len

        return msg


@_set_msg_type(ofproto_v1_3.OFPT_GROUP_MOD)
class OFPGroupMod(MsgBase):
    def __init__(self, datapath, command, type_, group_id, buckets):
        super(OFPGroupMod, self).__init__(datapath)
        self.command = command
        self.type = type_
        self.group_id = group_id
        self.buckets = buckets

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_3.OFP_GROUP_MOD_PACK_STR, self.buf,
                      ofproto_v1_3.OFP_HEADER_SIZE,
                      self.command, self.type, self.group_id)

        offset = ofproto_v1_3.OFP_HEADER_SIZE + ofproto_v1_3.OFP_GROUP_MOD_SIZE
        for b in self.buckets:
            b.serialize(self, buf, offset)
            offset += b.len


@_set_msg_type(ofproto_v1_3.OFPT_PORT_MOD)
class OFPPortMod(MsgBase):
    def __init__(self, datapath, port_no, hw_addr, config, mask, advertise):
        super(OFPPortMod, self).__init__(datapath)
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.config = config
        self.mask = mask
        self.advertise = advertise

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_3.OFP_PORT_MOD_PACK_STR, self.buf,
                      ofproto_v1_3.OFP_HEADER_SIZE,
                      self.port_no, self.hw_addr, self.config,
                      self.mask, self.advertise)


@_set_msg_type(ofproto_v1_3.OFPT_TABLE_MOD)
class OFPTableMod(MsgBase):
    def __init__(self, datapath, table_id, config):
        super(OFPTableMod, self).__init__(datapath)
        self.table_id = table_id
        self.config = config

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_3.OFP_TABLE_MOD_PACK_STR, self.buf,
                      ofproto_v1_3.OFP_HEADER_SIZE,
                      self.table_id, self.config)


def _set_stats_type(stats_type, stats_body_cls):
    def _set_cls_stats_type(cls):
        cls.cls_stats_type = stats_type
        cls.cls_stats_body_cls = stats_body_cls
        return cls
    return _set_cls_stats_type


@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPMultipartRequest(MsgBase):
    def __init__(self, datapath, flags):
        assert flags == 0      # none yet defined

        super(OFPMultipartRequest, self).__init__(datapath)
        self.type = self.__class__cls.stats_type
        self.flags = flags

    def _serialize_stats_body():
        pass

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_3.OFP_MULTIPART_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_3.OFP_HEADER_SIZE,
                      self.type, self.flags)
        self._serialize_stats_body()


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPMultipartReply(MsgBase):
    _STATS_MSG_TYPES = {}

    @staticmethod
    def register_stats_type(body_single_struct=False):
        def _register_stats_type(cls):
            assert cls.cls_stats_type is not None
            assert cls.cls_stats_type not in OFPMultipartReply._STATS_MSG_TYPES
            assert cls.cls_stats_body_cls is not None
            cls.cls_body_single_struct = body_single_struct
            OFPMultipartReply._STATS_MSG_TYPES[cls.cls_stats_type] = cls
            return cls
        return _register_stats_type

    def __init__(self, datapath, type_, flags):
        super(OFPMultipartReply, self).__init__(datapath)
        self.type = type_
        self.flags = flags
        self.body = None

    @classmethod
    def parser_stats_body(cls, buf, msg_len, offset):
        body_cls = cls.cls_stats_body_cls
        body = []
        while offset < msg_len:
            entry = body_cls.parser(buf, offset)
            body.append(entry)
            offset += entry.length

        if cls.cls_body_single_struct:
            return body[0]
        return body

    @classmethod
    def parser_stats(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = MsgBase.parser.__func__(
            cls, datapath, version, msg_type, msg_len, xid, buf)
        msg.body = msg.parser_stats_body(msg.buf, msg.msg_len,
                                         ofproto_v1_3.OFP_MULTIPART_REPLY_SIZE)
        return msg

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        type_, flags = struct.unpack_from(
            ofproto_v1_3.OFP_MULTIPART_REPLY_PACK_STR, buffer(buf),
            ofproto_v1_3.OFP_HEADER_SIZE)
        stats_type_cls = cls._STATS_MSG_TYPES.get(type_)
        msg = stats_type_cls.parser_stats(
            datapath, version, msg_type, msg_len, xid, buf)
        msg.type = type_
        msg.flags = flags
        return msg


class OFPDescStats(collections.namedtuple('OFPDescStats', (
        'mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc'))):
    @classmethod
    def parser(cls, buf, offset):
        desc = struct.unpack_from(ofproto_v1_3.OFP_DESC_PACK_STR,
                                  buf, offset)
        stats = cls(*desc)
        stats.length = ofproto_v1_3.OFP_DESC_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_DESC, OFPDescStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPDescStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags):
        super(OFPDescStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto_v1_3.OFPMP_DESC, OFPDescStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPDescStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPDescStatsReply, self).__init__(datapath)


class OFPFlowStats(object):
    def __init__(self):
        super(OFPFlowStats, self).__init__()
        self.length = None
        self.table_id = None
        self.duration_sec = None
        self.duration_nsec = None
        self.priority = None
        self.idle_timeout = None
        self.hard_timeout = None
        self.flags
        self.cookie = None
        self.packet_count = None
        self.byte_count = None
        self.match = None

    @classmethod
    def parser(cls, buf, offset):
        flow_stats = cls()

        (flow_stats.length, flow_stats.table_id,
         flow_stats.duration_sec, flow_stats.duration_nsec,
         flow_stats.priority, flow_stats.idle_timeout,
         flow_stats.cookie, flow_stats.packet_count,
         flow_stats.byte_count) = struct.unpack_from(
             ofproto_v1_3.OFP_FLOW_STATS_0_PACK_STR, buf, offset)
        offset += ofproto_v1_3.OFP_FLOW_STATS_0_SIZE

        flow_stats.match = OFPMatch.parse(buf, offset)

        return flow_stats


class OFPFlowStatsRequestBase(OFPMultipartRequest):
    def __init__(self, datapath, flags, table_id, out_port, out_group,
                 cookie, cookie_mask):
        super(OFPFlowStatsRequestBase, self).__init__(datapath, flags)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        self.cookie = cookie
        self.cookie_mask = cookie_mask
        self.match = match

    def _serialize_stats_body(self):
        offset = ofproto_v1_3.OFP_MULTIPART_REQUEST_SIZE
        msg_pack_into(ofproto_v1_3.OFP_FLOW_STATS_REQUEST_0_PACK_STR,
                      self.buf, offset, self.table_id, self.out_port,
                      self.out_group, self.cookie, self.cookie_mask)

        offset += OFP_FLOWSTAT_REQUEST_0_SIZE
        self.match.serialize(self.buf, offset)


@_set_stats_type(ofproto_v1_3.OFPMP_FLOW, OFPFlowStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPFlowStatsRequest(OFPFlowStatsRequestBase):
    def __init__(self, datapath, flags, table_id, out_port, out_group,
                 cookie, cookie_mask):
        super(OFPFlowStatsRequest, self).__init__(datapath, table_id,
                                                  out_port, out_group,
                                                  cookie, cookie_mask)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_FLOW, OFPFlowStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPFlowStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPFlowStatsReply, self).__init__(datapath)


class OFPAggregateStats(collections.namedtuple('OFPAggregateStats', (
        'packet_count', 'byte_count', 'flow_count'))):
    @classmethod
    def parser(cls, buf, offset):
        agg = struct.unpack_from(
            ofproto_v1_3.OFP_AGGREGATE_STATS_REPLY_PACK_STR, buf, offset)
        stats = cls(*agg)
        stats.length = ofproto_v1_3.OFP_AGGREGATE_STATS_REPLY_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPST_AGGREGATE, OFPAggregateStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPAggregateStatsRequest(OFPFlowStatsRequestBase):
    def __init__(self, datapath, flags, table_id, out_port, out_group,
                 cookie, cookie_mask):
        super(OFPAggregateStatsRequest, self).__init__(datapath,
                                                       table_id,
                                                       out_port,
                                                       out_group,
                                                       cookie,
                                                       cookie_mask)


@OFPmultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_AGGREGATE, OFPAggregateStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPAggregateStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPAggregateStatsReply, self).__init__(datapath)


class OFPTableStats(collections.namedtuple('OFPTableStats', (
        'table_id', 'active_count', 'lookup_count',
        'matched_count'))):
    @classmethod
    def parser(cls, buf, offset):
        tbl = struct.unpack_from(ofproto_v1_3.OFP_TABLE_STATS_PACK_STR,
                                 buf, offset)
        stats = cls(*tbl)
        stats.length = ofproto_v1_3.OFP_TABLE_STATS_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_TABLE, OFPTableStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPTableStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags):
        super(OFPTableStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_TABLE, OFPTableStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPTableStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPTableStatsReply, self).__init__(datapath)


class OFPPortStats(collections.namedtuple('OFPPortStats', (
        'port_no', 'rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
        'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors',
        'rx_frame_err', 'rx_over_err', 'rx_crc_err', 'collisions',
        'duration_sec', 'duration_nsec'))):
    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto_v1_3.OFP_PORT_STATS_PACK_STR,
                                  buf, offset)
        stats = cls(*port)
        stats.length = ofproto_v1_3.OFP_PORT_STATS_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_PORT_STATS, OFPPortStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPPortStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, port_no):
        super(OFPPortStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_3.OFP_PORT_STATS_REQUEST_PACK_STR,
                      self.buf,
                      ofproto_v1_3.OFP_MULTIPART_REQUEST_SIZE,
                      self.port_no)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_PORT_STATS, OFPPortStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPPortStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPPortStatsReply, self).__init__(datapath)


class OFPQueueStats(collections.namedtuple('OFPQueueStats', (
        'port_no', 'queue_id', 'tx_bytes', 'tx_packets', 'tx_errors',
        'duration_sec', 'duration_nsec'))):
    @classmethod
    def parser(cls, buf, offset):
        queue = struct.unpack_from(ofproto_v1_3.OFP_QUEUE_STATS_PACK_STR,
                                   buf, offset)
        stats = cls(*queue)
        stats.length = ofproto_v1_3.OFP_QUEUE_STATS_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_QUEUE, OFPQueueStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPQueueStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, port_no, queue_id):
        super(OFPQueueStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no
        self.queue_id = queue_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_3.OFP_QUEUE_STATS_REQUEST_PACK_STR,
                      self.buf,
                      ofproto_v1_3.OFP_MULTIPART_REQUEST_SIZE,
                      self.port_no, self.queue_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_QUEUE, OFPQueueStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPQueueStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPQueueStatsReply, self).__init__(datapath)


class OFPGroupStats(collections.namedtuple('OFPGroupStats', (
        'length', 'group_id', 'ref_count', 'packet_count',
        'byte_count', 'duration_sec', 'duration_nsec'))):
    @classmethod
    def parser(cls, buf, offset):
        group = struct.unpack_from(ofproto_v1_3.OFP_GROUP_STATS_PACK_STR,
                                   buf, offset)
        stats = cls(*group)
        stats.length = ofproto_v1_3.OFP_GROUP_STATS_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_GROUP, OFPGroupStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPGroupStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, group_id):
        super(OFPGroupStatsRequest, self).__init__(datapath, flags)
        self.group_id = group_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_3.OFP_GROUP_STATS_REQUEST_PACK_STR,
                      self.buf,
                      ofproto_v1_3.OFP_MULTIPART_REQUEST_SIZE,
                      self.group_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_GROUP, OFPGroupStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPGroupStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPGroupStatsReply, self).__init__(datapath)


class OFPGroupDescStats(object):
    def __init__(self):
        super(OFPGroupDescStats).__init__()
        self.length = None
        self.type = None
        self.group_id = None
        self.ofp_bucket = None

    @classmethod
    def parser(cls, buf, offset):
        stats = cls()

        (stats.length, stats.type, stats.group_id) = struct.unpack_from(
            ofproto_v1_3.OFP_GROUP_DESC_STATS_PACK_STR, buf, offset)
        offset += ofproto_v1_3.OFP_GROUP_DESC_STATS_SIZE

        stats.bucket = []
        length = ofproto_v1_3.OFP_GROUP_DESC_STATS_SIZE
        while length < stats.length:
            bucket = OFPBucket.parser(buf, offset)
            stats.bucket.append(bucket)

            offset += bucket.len
            length += bucket.len

        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_GROUP_DESC, OFPGroupDescStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPGroupDescStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, port_no):
        super(OFPGroupDescStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_GROUP_DESC, OFPGroupDescStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPGroupDescStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPGroupDescStatsReply, self).__init__(datapath)


class OFPGroupFeaturesStats(collections.namedtuple('OFPGroupFeaturesStats', (
        'types', 'capabilities', 'max_groups', 'actions'))):
    @classmethod
    def parser(cls, buf, offset):
        group_features = struct.unpack_from(
            ofproto_v1_3.OFP_GROUP_FEATURES_PACK_STR, buf, offset)
        stats = cls(*group_features)
        stats.length = ofproto_v1_3.OFP_GROUP_FEATURES_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_GROUP_FEATURES, OFPGroupFeaturesStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPGroupFeaturesStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, port_no):
        super(OFPGroupFeaturesRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_GROUP_FEATURES, OFPGroupFeaturesStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPGroupFeaturesStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPGroupFeaturesStatsReply, self).__init__(datapath)


class OFPMeterBandStats(object):
    def __init__(self, packet_band_count, byte_band_count):
        super(OFPMeterBandStats, self).__init__()
        self.packet_band_count = packet_bound_count
        self.byte_band_count = byte_band_count

    @classmethod
    def parser(cls, buf, offset):
        band_stats = struct.unpack_from(
            ofproto_v1_3.OFP_METER_BAND_STATS_PACK_STR, buf, offset)
        return cls(*band_stats)


class OFPMeterStats(object):
    def __init__(self):
        super(OFPMeterStats, self).__init__()
        self.meter_id = None
        self.len = None
        self.flow_count = None
        self.packet_in_count = None
        self.byte_in_count = None
        self.duration_sec = None
        self.duration_nsec = None
        self.band_stats = None

    @classmethod
    def parser(cls, buf, offset):
        meter_stats = cls()

        (meter_stats.meter_id, meter_stats.len,
         meter_stats.flow_count, meter_stats.packet_in_count,
         meter_stats.byte_in_count, meter_stats.duration_sec,
         meter_stats.duration_nsec) = struct.unpack_from(
             ofproto_v1_3.OFP_METER_STATS_PACK_STR, buf, offset)
        offset += ofproto_v1_3.OFP_METER_STATS_SIZE

        meter_stats.band_stats = []
        length = ofproto_v1_3.OFP_METER_STATS_SIZE
        while length < meter_stats.len:
            band_stats = OFPMeterBandStats.parser(buf, offset)
            meter_stats.band_stats.append(band_stats)
            offset += ofproto_v1_3.OFP_METER_BAND_STATS_SIZE
            length += ofproto_v1_3.OFP_METER_BAND_STATS_SIZE

        return meter_stats


@_set_stats_type(ofproto_v1_3.OFPMP_METER, OFPMeterStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPMeterStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, meter_id):
        super(OFPMeterStatsRequest, self).__init__(datapath, flags)
        self.meter_id = meter_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_3.OFP_METER_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto_v1_3.OFP_MULTIPART_REQUEST_SIZE,
                      self.meter_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_METER, OFPMeterStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPMeterStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPMeterStatsReply, self).__init__(datapath)


class OFPMeterBandHeader(object):
    def __init__(self, type_, len_, rate, burst_size):
        self.type = type_
        self.len = len_
        self.rate = rate
        self.burst_size = burst_size

    @classmethod
    def parser(cls, buf, offset):
        band_header = struct.unpack_from(
            ofproto_v1_3.OFP_METER_BAND_HEADER_PACK_STR, buf, offset)
        return cls(*band_header)


class OFPMeterConfigStats(object):
    def __init__(self):
        super(OFPMeterConfigStats, self).__init__()
        self.length = None
        self.flags = None
        self.meter_id = None
        self.bands = None

    @classmethod
    def parser(cls, buf, offset):
        meter_config = cls()

        (meter_config.length, meter_config.flags,
         meter_config.meter_id) = struct.unpack_from(
             ofproto_v1_3.OFP_METER_CONFIG_PACK_STR, buf, offset)
        offset += ofproto_v1_3.OFP_METER_CONFIG_SIZE

        meter_config.bands = []
        length = ofproto_v1_3.OFP_METER_CONFIG_SIZE
        while length < meter_config.length:
            band_header = OFPMeterBandHeader.parser(buf, offset)
            meter_config.bands.append(band_header)
            offset += band_header.len
            length += band_header.len

        return meter_config


@_set_stats_type(ofproto_v1_3.OFPMP_METER_CONFIG, OFPMeterConfigStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPMeterConfigStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, meter_id):
        super(OFPMeterConfigStatsRequest, self).__init__(datapath, flags)
        self.meter_id = meter_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_3.OFP_METER_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto_v1_3.OFP_MULTIPART_REQUEST_SIZE,
                      self.meter_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_METER_CONFIG, OFPMeterCOnfigStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPMeterConfigStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPMeterConfigStatsReply, self).__init__(datapath)


class OFPMeterFeaturesStats(collections.namedtuple('OFPMeterFeaturesStats', (
        'max_meter', 'band_types', 'capabilities', 'max_band',
        'max_color'))):
    @classmethod
    def parser(cls, buf, offset):
        meter_features = struct.unpack_from(
            ofproto_v1_3.OFP_METER_FEATURES_PACK_STR, buf, offset)
        stats = cls(*meter_features)
        stats.length = ofproto_v1_3.OFP_METER_FEATURES_SIZE
        return stats


@_set_stats_type(ofproto_v1_3.OFPMP_METER_FEATUERS, OFPMeterFeaturesStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPMeterFeaturesStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, port_no):
        super(OFPMeterFeaturesStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_METER_FEATURES, OFPMeterFeaturesStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPMeterFeaturesStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPMeterFeaturesStatsReply, self).__init__(datapath)


class OFPTableFeaturesStats(object):
    def __init__(self):
        super(OFPTableFeaturesStats, self).__init__()
        self.length = None
        self.table_id = None
        self.name = None
        self.metadata_match = None
        self.metadata_write = None
        self.config = None
        self.max_entries = None
        self.properties = None

    @classmethod
    def parser(cls, buf, offset):
        table_features = cls()
        (table_features.length, table_features.table_id,
         table_features.name, table_features.metadata_match,
         table_features.write, table_features.config,
         table_features.max_entries, table_features.properties
         ) = struct.unpack_from(ofproto_v1_3.OFP_TABLE_FEATURES_PACK_STR,
                                buf, offset)
        offset += ofproto_v1_3.OFP_TABLE_FEATURES_SIZE

        # TODO: parse ofp_table_feature_prop_header

        return table_features


@_set_stats_type(ofproto_v1_3.OFPMP_TABLE_FEATURES, OFPTableFeaturesStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPTableFeaturesStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, length, table_id, name,
                 metadata_match, metadata_write, config, max_entries,
                 properties):
        super(OFPTableFeaturesStatsRequest, self).__init__(datapath, flags)
        self.length = length
        self.table_id = table_id
        self.name = name
        self.metadata_match = metadata_match
        self.metadata_write = metadata_write
        self.config = config
        self.max_entries = max_entries

    def _serialize_stats_body(self):
        # TODO
        pass


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_TABLE_FEATURES, OFPTableFeaturesStats)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPTableFeaturesStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPTableFeaturesStatsReply, self).__init__(datapath)


@_set_stats_type(ofproto_v1_3.OFPMP_PORT_DESC, OFPPort)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REQUEST)
class OFPPortDescStatsRequest(OFPMultipartRequest):
    def __init__(self, datapath, flags, port_no):
        super(OFPPortDescStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto_v1_3.OFPMP_PORT_DESC, OFPPort)
@_set_msg_type(ofproto_v1_3.OFPT_MULTIPART_REPLY)
class OFPPortDescStatsReply(OFPMultipartReply):
    def __init__(self, datapath):
        super(OFPPortDescStatsReply, self).__init__(datapath)


# TODO: OFPMP_EXPERIMENTER


@_set_msg_type(ofproto_v1_3.OFPT_BARRIER_REQUEST)
class OFPBarrierRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPBarrierRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_BARRIER_REPLY)
class OFPBarrierReply(MsgBase):
    def __init__(self, datapath):
        super(OFPBarrierReply, self).__init__(datapath)


@_set_msg_type(ofproto_v1_3.OFPT_QUEUE_GET_CONFIG_REQUEST)
class OFPQueueGetConfigRequest(MsgBase):
    def __init__(self, datapath, port):
        super(OFPQueueGetConfigRequest, self).__init__(datapath)
        self.port = port

    def _serialized_body(self):
        msg_pack_into(ofproto_v1_3.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_3.OFP_HEADER_SIZE, self.port)


class OFPQueuePropHeader(object):
    def __init__(self, property_, len_):
        self.property = property_
        self.len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_3.OFP_QUEUE_PROP_HEADER_PACK_STR,
                      buf, offset, self.property, self.len)


class OFPQueueProp(OFPQueuePropHeader):
    _QUEUE_PROP_PROPERTIES = {}

    @staticmethod
    def register_queue_property(property_, len_):
        def _register_property(cls):
            cls.cls_property = property_
            cls.cls_len = len_
            OFPQueueProp._QUEUE_PROP_PROPERTIES[cls.cls_property] = cls
            return cls
        return _register_queue_property

    def __init__(self):
        cls = self.__class__
        super(OFPQueueProp, self).__init__(cls.cls_property,
                                           cls.cls_len)

    @classmethod
    def parser(cls, buf, offset):
        (property_, len_) = struct.unpack_from(
            ofproto_v1_3.OFP_QUEUE_PROP_HEADER_PACK_STR,
            buf, offset)
        cls_ = cls._QUEUE_PROP_PROPERTIES.get(property_)
        return cls_.parser(buf, offset)


@OFPQueueProp.register_queue_property(
    ofproto_v1_3.OFPQT_MIN_RATE,
    ofproto_v1_3.OFP_QUEUE_PROP_MIN_RATE_SIZE)
class OFPQueuePropMinRate(OFPQueueProp):
    def __init__(self, rate):
        super(OFPQueuePropMinRate, self).__init__()
        self.rate = rate

    @classmethod
    def parser(cls, buf, offset):
        msg = super(OFPQueuePropMinRate, cls).parser(cls, buf, offset)
        offset += ofproto_v1_3.OFP_QUEUE_PROP_MIN_RATE_SIZE
        (msg.rate,) = struct.unpack_from(
            ofproto_v1_3.OFP_QUEUE_PROP_MIN_RATE_PACK_STR, buf,
            offset)
        return msg


@OFPQueueProp.register_queue_property(
    ofproto_v1_3.OFPQT_MAX_RATE,
    ofproto_v1_3.OFP_QUEUE_PROP_MAX_RATE_SIZE)
class OFPQueuePropMaxRate(OFPQueueProp):
    def __init__(self, rate):
        super(OFPQueuePropMinRate, self).__init__()
        self.rate = rate

    @classmethod
    def parser(cls, buf, offset):
        msg = super(OFPQueuePropMinRate, cls).parser(cls, buf, offset)
        offset += ofproto_v1_3.OFP_QUEUE_PROP_MIN_RATE_SIZE
        (msg.rate,) = struct.unpack_from(
            ofproto_v1_3.OFP_QUEUE_PROP_MIN_RATE_PACK_STR, buf,
            offset)
        return msg


# TODO: add ofp_queue_prop_experimenter


class OFPPacketQueue(MsgBase):
    def __init__(self, datapath):
        super(OFPPacketQueue, self).__init__(datapath)

    @clasmethod
    def parser(cls, buf, offset):
        (msg.queue_id, msg.port, msg.len) = struct.unpack_from(
            ofproto_v1_3.OFP_PACKET_QUEUE_PACK_STR, buf, offset)

        length = ofproto_v1_3.OFP_PACKET_QUEUE_SIZE
        offset += ofproto_v1_3.OFP_PACKET_QUEUE_SIZE
        msg.properties = []
        while length < msg.len:
            properties = OFPQueueProp.parser(buf, offset)
            msg.properties.append(properties)
            offset += properties.len
            length += properties.len

        return msg


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_QUEUE_GET_CONFIG_REPLY)
class OFPQueueGetConfigReply(MsgBase):
    def __init__(self, datapath):
        super(OFPQueueGetConfigReply, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPQueueGetConfigReply, cls).parser(datapath, version,
                                                        msg_type,
                                                        msg_len, xid, buf)
        offset = ofproto_v1_3.OFP_HEADER_SIZE
        (msg.port,) = struct.unpack_from(
            ofproto_v1_3.OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR, msg.buf,
            offset)

        msg.queues = []
        offset += ofproto_v1_3.OFP_QUEUE_GET_CONFIG_REPLY_SIZE
        while offset < msg.length:
            queue = OFPPacketQueue.parser(buf, offset)
            msg.queues.append(queue)
            offset += queue.len

        return msg


@_set_msg_type(ofproto_v1_3.OFPT_ROLE_REQUEST)
class OFPRoleRequest(MsgBase):
    def __init__(self, datapath, role=None, generation_id=None):
        super(OFPRoleRequest, self).__init__(datapath)
        self.role = role
        self.generation_id = generation_id

    def __serialize_body(self):
        assert self.role is not None
        assert self.generation_id is not None
        msg_pack_into(ofproto_v1_3.OFP_ROLE_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_3.OFP_HEADER_SIZE,
                      self.role, self.generation_id)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_ROLE_REPLY)
class OFPRoleReply(MsgBase):
    def __init__(self, datapath):
        super(OFPRoleReply, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPRoleReply, cls).parser(datapath, version,
                                              msg_type, msg_len, xid,
                                              buf)
        (msg.role, msg.generation_id) = struct.unpack_from(
            ofproto_v1_3.OFP_ROLE_REQUEST_PACK_STR, msg.buf,
            ofproto_v1_3.OFP_HEADER_SIZE)


@_set_msg_type(ofproto_v1_3.OFPT_GET_ASYNC_REQUEST)
class OFPGetAsyncRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPGetAsyncRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_GET_ASYNC_REPLY)
class OFPGetAsyncReply(MsgBase):
    def __init__(self, datapath):
        super(OFPGetAsyncReply, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPGetAsyncReply, cls).parser(datapath, version,
                                                  msg_type, msg_len,
                                                  xid, buf)
        (msg.packet_in_mask, msg.port_status_mask,
         msg.flow_removed_mask) = struct.unpack_from(
             ofproto_v1_3.OFP_ASYNC_CONFIG_PACK_STR, msg.buf,
             ofproto_v1_3.OFP_HEADER_SIZE)


@_register_parser
@_set_msg_type(ofproto_v1_3.OFPT_SET_ASYNC)
class OFPGetAsyncReply(MsgBase):
    def __init__(self, datapath):
        super(OFPSetAsync, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSetAsync, cls).parser(datapath, version,
                                             msg_type, msg_len,
                                             xid, buf)
        (msg.packet_in_mask, msg.port_status_mask,
         msg.flow_removed_mask) = struct.unpack_from(
             ofproto_v1_3.OFP_ASYNC_CONFIG_PACK_STR, msg.buf,
             ofproto_v1_3.OFP_HEADER_SIZE)
