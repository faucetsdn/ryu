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
            ofproto_v1_2.OFP_ERROR_MSG_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_2.OFP_ERROR_MSG_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        msg_pack_into(ofproto_v1_2.OFP_ERROR_MSG_PACK_STR, self.buf,
                      ofproto_v1_2.OFP_HEADER_SIZE, self.type, self.code)
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_ECHO_REQUEST)
class OFPEchoRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPEchoRequest, self).__init__(datapath)
        self.data = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoRequest, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)
        msg.data = msg.buf[ofproto_v1_2.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_ECHO_REPLY)
class OFPEchoReply(MsgBase):
    def __init__(self, datapath):
        super(OFPEchoReply, self).__init__(datapath)
        self.data = None

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
    def __init__(self, datapath):
        super(OFPExperimenter, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPExperimenter, cls).parser(datapath, version, msg_type,
                                                 msg_len, xid, buf)
        (experimenter, exp_type) = struct.unpack_from(
            ofproto_v1_2.OFP_EXPERIMENTER_HEADER_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)


class OFPPort(collections.namedtuple('OFPPort', (
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
    def __init__(self, datapath):
        super(OFPSwitchFeatures, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSwitchFeatures, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        (msg.datapath_id,
         msg.n_buffers,
         msg.n_tables,
         msg.capabilities,
         msg.reserved) = struct.unpack_from(
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
    def __init__(self, datapath):
        super(OFPGetConfigReply, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPGetConfigReply, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        msg.flags, msg.miss_send_len = struct.unpack_from(
            ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR, buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
        return msg


@_set_msg_type(ofproto_v1_2.OFPT_SET_CONFIG)
class OFPSetConfig(MsgBase):
    def __init__(self, datapath, flags=None, miss_send_len=None):
        super(OFPSetConfig, self).__init__(datapath)
        self.flags = flags
        self.miss_send_len = miss_send_len

    def _serialize_body(self):
        assert self.flags is not None
        assert self.miss_send_len is not None
        msg_pack_into(ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE,
                      self.flags, self.miss_send_len)


class OFPMatch(object):
    def __init__(self):
        super(OFPMatch, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        pass


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_PACKET_IN)
class OFPPacketIn(MsgBase):
    def __init__(self, datapath):
        super(OFPPacketIn, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPacketIn, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        (msg.buffer_id, msg.total_len, msg.reason,
         msg.table_id) = struct.unpack_from(
            ofproto_v1_2.OFP_PACKET_IN_PACK_STR,
            msg.buf, ofproto_v1_2.OFP_HEADER_SIZE)

        offset = ofproto_v1_2.OFP_HEADER_SIZE + ofproto_v1_2.OFP_PACKET_IN_SIZE
        msg.match = OFPMatch.parser(buf, offset - ofproto_v1_2.OFP_MATCH_SIZE)
        return msg


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_FLOW_REMOVED)
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
            ofproto_v1_2.OFP_FLOW_REMOVED_PACK_STR0,
            msg.buf, ofproto_v1_2.OFP_HEADER_SIZE + ofproto_v1_2.OFP_MATCH_SIZE)

        offset = (ofproto_v1_2.OFP_HEADER_SIZE +
                  ofproto_v1_2.OFP_FLOW_REMOVED_SIZE)

        msg.match = OFPMatch.parser(buf, offset - ofproto_v1_2.OFP_MATCH_SIZE)

        return msg


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_PORT_STATUS)
class OFPPortStatus(MsgBase):
    def __init__(self, datapath):
        super(OFPPortStatus, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPortStatus, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        (msg.reason,) = struct.unpack_from(
            ofproto_v1_2.OFP_PORT_STATUS_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)
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
        self.actions_len = 0
        self.actions = actions
        self.data = data

    def _serialize_body(self):
        self.actions_len = 0
        offset = ofproto_v1_2.OFP_PACKET_OUT_SIZE
        for a in self.actions:
            a.serialize(self.buf, offset)
            offset += a.len
            self.actions_len += a.len

        if self.data is not None:
            assert self.buffer_id == 0xffffffff
            self.buf += self.data

        msg_pack_into(ofproto_v1_2.OFP_PACKET_OUT_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE,
                      self.buffer_id, self.in_port, self.actions_len)


@_set_msg_type(ofproto_v1_2.OFPT_FLOW_MOD)
class OFPFlowMod(MsgBase):
    def __init__(self, datapath, cookie, cookie_mask, table_id, command,
                 idle_timeout, hard_timeout, priority, buffer_id, out_port,
                 out_group, flags, match):
        super(OFPFLowMod, self).__init__(datapath)
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
        msg_pack_into(ofproto_v1_2.OFP_FLOW_MOD_PACK_STR0, self.buf,
                      ofproto_v1_2.OFP_HEADER_SIZE,
                      self.cookie, self.cookie_mask, self.table_id,
                      self.command, self.idle_timeout, self.hard_timeout,
                      self.priority, self.buffer_id, self.out_port,
                      self.out_group, self.flag)

        offset += (ofproto_v1_2.OFP_OFP_FLOW_MOD_SIZE -
                   ofproto_v1_2.OFP_MATCH_SIZE - ofproto_v1_2.OFP_HEADER_SIZE)
        self.match.serialize(self.buf, offset)


class OFPActionHeader(object):
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
        msg_pack_into(ofproto_v1_2.OFP_ACTION_MPLS_TTL, buf,
                      offset, self.type, self.len, self.mpls_ttl)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_DEC_MPLS_TTL,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionDecMplsTtl(OFPAction):
    def __init__(self):
        super(OFPActionDecMplsTtl, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
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
        msg_pack_into(ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_COPY_TTL_OUT,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlOut(OFPAction):
    def __init__(self):
        super(OFPActionCopyTtlOut, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_COPY_TTL_IN,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlIn(OFPAction):
    def __init__(self):
        super(OFPActionCopyTtlIn, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
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
        msg_pack_into(ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR, buff, offset,
                      self.ethertype)


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
        msg_pack_into(ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR, buff, offset,
                      self.ethertype)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_POP_VLAN,
                                ofproto_v1_2.OFP_ACTION_HEADER_SIZE)
class OFPActionPopVlan(OFPAction):
    def __init__(self):
        super(OFPActionPopVlan, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR, buf, offset)
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
        msg_pack_into(ofproto_v1_2.OFP_ACTION_POP_MPLS_PACK_STR, buff, offset,
                      self.ethertype)


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_SET_FIELD,
                                ofproto_v1_2.OFP_ACTION_SET_FIELD_SIZE)
class OFPActionSetField(OFPAction):
    def __init__(self):
        super(OFPActionSetField, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_SET_FIELD_PACK_STR, buf, offset)
        action = cls()
        # TODO: parse OXM
        return action

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_SET_FIELD_PACK_STR, buf, offset)
        # TODO: serialize OXM


@OFPAction.register_action_type(ofproto_v1_2.OFPAT_EXPERIMENTER,
                                ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_SIZE)
class OFPActionExperimenter(OFPAction):
    def __init__(self, experimenter):
        super(OFPActionExperimenter, self).__init__()
        self.experimenter = experimenter

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, experimenter) = struct.unpack_from(
            ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR, buf, offset)
        return cls(experimenter)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR,
                      buf, offset)


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
            ofproto_v1_2.OFP_BUCKET_PACK_STR, buf, offset)

        length = ofproto_v1_2.OFP_BUCKET_SIZE
        offset += ofproto_v1_2.OFP_BUCKET_SIZE
        msg.actions = []
        while length < msg.len:
            action = OFPAction.parser(buf, offset)
            msg.actions.append(action)
            offset += action.len
            length += action.len

        return msg


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

        offset = ofproto_v1_2.OFP_HEADER_SIZE + ofproto_v1_2.OFP_GROUP_MOD_SIZE
        for b in self.buckets:
            b.serialize(self, buf, offset)
            offset += b.len


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


# class OFPStatsRequest
# class OFPStatsReply


@_set_msg_type(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST)
class OFPQueueGetConfigRequest(MsgBase):
    def __init__(self, datapath, port):
        super(OFPQueueGetConfigRequest, self).__init__(datapath)
        self.port = port

    def _serialized_body(self):
        msg_pack_into(ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_2.OFP_HEADER_SIZE, self.port)


class OFPQueuePropHeader(object):
    def __init__(self, property_, len_):
        self.property = property_
        self.len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR,
                      buf, offset, self.property, self.len)


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
        return cls_.parser(buf, offset)


class OFPPacketQueue(object):
    def __init__(self, queue_id, port, len_, properties):
        super(OFPPacketQueue, self).__init__()
        self.queue_id = queue_id
        self.port = port
        self.len = len_
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (msg.queue_id, msg.port, msg.len) = struct.unpack_from(
            ofproto_v1_2.OFP_PACKET_QUEUE_PACK_STR, buf, offset)
        length = ofproto_v1_2.OFP_PACKET_QUEUE_SIZE
        offset += ofproto_v1_2.OFP_PACKET_QUEUE_SIZE
        msg.properties = []
        while length < msg.len:
            queue_prop = OFPQueueProp.parser(buf, offset)
            msg.properties.append(queue_prop)
            offset += queue_prop.len
            length += queue_prop
        return msg


@_register_parser
@_set_msg_type(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REPLY)
class OFPQueueGetConfigReply(MsgBase):
    def __init__(self, datapath):
        super(OFPQueueGetConfigReply, self).__init__(datapath)

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
        while length < msg.length:
            queue = OFPPacketQueue.parser(buf, offset)
            msg.queues.append(queue)

            offset += queue.len
            length += queue.len

        return msg


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
    def __init__(self, datapath):
        super(OFPRoleReply, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPRoleReply, cls).parser(datapath, version,
                                              msg_type,
                                              msg_len, xid, buf)
        (msg.role, msg.generation_id) = struct.unpack_from(
            ofproto_v1_2.OFP_ROLE_REQUEST_PACK_STR, msg.buf,
            ofproto_v1_2.OFP_HEADER_SIZE)

        return msg
