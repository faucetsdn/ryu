# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import collections
import struct

from . import ofproto_parser
from . import ofproto_v1_0

import logging
LOG = logging.getLogger('ryu.ofproto.ofproto_v1_0_parser')

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


@ofproto_parser.register_msg_parser(ofproto_v1_0.OFP_VERSION)
def msg_parser(datapath, version, msg_type, msg_len, xid, buf):
    parser = _MSG_PARSERS.get(msg_type)
    return parser(datapath, version, msg_type, msg_len, xid, buf)


class MsgBase(object):
    def __init__(self, datapath):
        self.datapath = datapath
        self.version = None
        self.msg_type = None
        self.msg_len = None
        self.xid = None
        self.buf = None

    def set_headers(self, version, msg_type, msg_len, xid):
        assert msg_type == self.cls_msg_type

        self.version = version
        self.msg_type = msg_type
        self.msg_len = msg_len
        self.xid = xid

    def set_buf(self, buf):
        self.buf = buffer(buf)

    def __str__(self):
        return 'version: 0x%x msg_type 0x%x xid 0x%x' % (self.version,
                                                         self.msg_type,
                                                         self.xid)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = cls(datapath)
        msg.set_headers(version, msg_type, msg_len, xid)
        msg.set_buf(buf)
        return msg

    def _serialize_pre(self):
        assert self.version is None
        assert self.msg_type is None
        assert self.buf is None

        self.version = self.datapath.ofproto.OFP_VERSION
        self.msg_type = self.cls_msg_type
        self.buf = bytearray().zfill(self.datapath.ofproto.OFP_HEADER_SIZE)

    def _serialize_header(self):
        # buffer length is determined after trailing data is formated.
        assert self.version is not None
        assert self.msg_type is not None
        assert self.msg_len is None
        assert self.xid is None
        assert self.buf is not None
        assert len(self.buf) >= self.datapath.ofproto.OFP_HEADER_SIZE

        self.msg_len = len(self.buf)
        self.xid = 0  # TODO:XXX

        struct.pack_into(self.datapath.ofproto.OFP_HEADER_PACK_STR, self.buf, 0,
                         self.version, self.msg_type, self.msg_len, self.xid)

    def _serialize_body(self):
        pass

    def serialize(self):
        self._serialize_pre()
        self._serialize_body()
        self._serialize_header()


def _pack_into(fmt, buf, offset, *args):
    if len(buf) < offset:
        buf += bytearray().zfill(offset - len(buf))

    if len(buf) == offset:
        buf += struct.pack(fmt, *args)
        return

    needed_len = offset + struct.calcsize(fmt)
    if len(buf) < needed_len:
        buf += bytearray().zfill(needed_len - len(buf))

    struct.pack_into(fmt, buf, offset, *args)


def _str_attr(msg, buf, attr_list):
    for attr in attr_list:
        val = getattr(msg, attr, None)
        if val is not None:
            buf += ' %s %s' % (attr, val)

    return buf


#
# common structures
#

class OFPPhyPort(collections.namedtuple('OFPPhyPort', (
    'port_no', 'hw_addr', 'name', 'config', 'state', 'curr', 'advertised',
    'supported', 'peer'))):

    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto_v1_0.OFP_PHY_PORT_PACK_STR,
                                  buf, offset)
        return cls(*port)


class OFPMatch(collections.namedtuple('OFPMatchBase', (
            'wildcards', 'in_port', 'dl_src', 'dl_dst', 'dl_vlan',
            'dl_vlan_pcp', 'dl_type', 'nw_tos', 'nw_proto',
            'nw_src', 'nw_dst', 'tp_src', 'tp_dst'))):

    def serialize(self, buf, offset):
        _pack_into(ofproto_v1_0.OFP_MATCH_PACK_STR, buf, offset, *self)

    @classmethod
    def parse(cls, buf, offset):
        match = struct.unpack_from(ofproto_v1_0.OFP_MATCH_PACK_STR,
                                   buf, offset)
        return cls(*match)


class OFPActionHeader(object):
    def __init__(self, type, len):
        self.type = type
        self.len = len

    def serlize(self, buf, offset):
        _pack_into(ofproto_v1_0.OFP_ACTION_HEADER_PACK_STR,
                   buf, offset, self.type, self.len)


class OFPActionOutput(OFPActionHeader):
    def __init__(self, port, max_len=0):
        super(OFPActionOutput,
              self).__init__(ofproto_v1_0.OFPAT_OUTPUT,
                             ofproto_v1_0.OFP_ACTION_OUTPUT_LEN)
        self.port = port
        self.max_len = max_len

    def serialize(self, buf, offset):
        _pack_into(ofproto_v1_0.OFP_ACTION_OUTPUT_PACK_STR,
                   buf, offset, self.type, self.len, self.port, self.max_len)


# TODO:XXX more actions


#
# Symmetric messages
# parser + serializer
#


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_HELLO)
class OFPHello(MsgBase):
    def __init__(self, datapath):
        super(OFPHello, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_ERROR)
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
            ofproto_v1_0.OFP_ERROR_MSG_PACK_STR, msg.buf,
            ofproto_v1_0.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_0.OFP_ERROR_MSG_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        _pack_into(ofproto_v1_0.OFP_ERROR_MSG_PACK_STR, self.buf,
                   ofproto_v1_0.OFP_HEADER_SIZE, self.type, self.code)
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_ECHO_REQUEST)
class OFPEchoRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPEchoRequest, self).__init__(datapath)
        self.data = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoRequest, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)
        msg.data = msg.buf[ofproto_v1_0.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_ECHO_REPLY)
class OFPEchoReply(MsgBase):
    def __init__(self, datapath):
        super(OFPEchoReply, self).__init__(datapath)
        self.data = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoReply, cls).parser(datapath, version, msg_type,
                                              msg_len, xid, buf)
        msg.data = msg.buf[ofproto_v1_0.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_VENDOR)
class OFPVendor(MsgBase):
    def __init__(self, datapath):
        super(OFPVendor, self).__init__(datapath)
        self.data = None

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPVendor, cls).parser(datapath, version, msg_type,
                                           msg_len, xid, buf)
        msg.vendor = struct.unpack_from(
            ofproto_v1_0.OFP_VENDOR_HEADER_PACK_STR, msg.buf,
            ofproto_v1_0.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_0.OFP_VENDOR_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        _pack_into(ofproto_v1_0.OFP_VENDOR_HEADER_PACK_STR,
                   self.buf, ofproto_v1_0.OFP_HEADER_SIZE, self.vendor)
        self.buf += self.data


#
# asymmetric message (datapath -> controller)
# parser only
#


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_FEATURES_REPLY)
class OFPSwitchFeatures(MsgBase):
    def __init__(self, datapath):
        super(OFPSwitchFeatures, self).__init__(datapath)

    def __str__(self):
        buf = super(OFPSwitchFeatures, self).__str__() + ' port'
        for port_no, p in getattr(self, 'ports', {}).items():
            buf += ' ' + str(p)
        return buf

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSwitchFeatures, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        (msg.datapath_id,
         msg.n_buffers,
         msg.n_tables,
         msg.capabilities,
         msg.actions) = struct.unpack_from(
            ofproto_v1_0.OFP_SWITCH_FEATURES_PACK_STR, msg.buf,
            ofproto_v1_0.OFP_HEADER_SIZE)

        msg.ports = {}
        n_ports = ((msg_len - ofproto_v1_0.OFP_SWITCH_FEATURES_SIZE) /
                   ofproto_v1_0.OFP_PHY_PORT_SIZE)
        offset = ofproto_v1_0.OFP_SWITCH_FEATURES_SIZE
        for i in range(n_ports):
            port = OFPPhyPort.parser(msg.buf, offset)
            # print 'port = %s' % str(port)
            msg.ports[port.port_no] = port
            offset += ofproto_v1_0.OFP_PHY_PORT_SIZE

        return msg


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_PORT_STATUS)
class OFPPortStatus(MsgBase):
    def __init__(self, datapath):
        super(OFPPortStatus, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPortStatus, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        msg.reason = struct.unpack_from(
            ofproto_v1_0.OFP_PORT_STATUS_PACK_STR,
            msg.buf, ofproto_v1_0.OFP_HEADER_SIZE)[0]
        msg.desc = OFPPhyPort.parser(msg.buf,
                                     ofproto_v1_0.OFP_PORT_STATUS_DESC_OFFSET)
        return msg


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_PACKET_IN)
class OFPPacketIn(MsgBase):
    def __init__(self, datapath):
        super(OFPPacketIn, self).__init__(datapath)

    def __str__(self):
        buf = super(OFPPacketIn, self).__str__()
        return _str_attr(self, buf,
                         ('buffer_id', 'total_len', 'in_port', 'reason'))

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPacketIn, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        (msg.buffer_id,
         msg.total_len,
         msg.in_port,
         msg.reason) = struct.unpack_from(
            ofproto_v1_0.OFP_PACKET_IN_PACK_STR,
            msg.buf, ofproto_v1_0.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto_v1_0.OFP_PACKET_IN_DATA_OFFSET:]
        return msg


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_GET_CONFIG_REPLY)
class OFPSwitchConfig(MsgBase):
    def __init__(self, datapath):
        super(OFPSwitchConfig, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSwitchConfig, cls).parser(datapath, version, msg_type,
                                                 msg_len, xid, buf)
        (msg.flags, msg.miss_send_len) = struct.unpack_from(
            ofproto_v1_0.OFP_SWITCH_CONFIG_PACK_STR,
            msg.buf, ofproto_v1_0.OFP_HEADER_SIZE)
        return msg


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_BARRIER_REPLY)
class OFPBarrierReply(MsgBase):
    def __init__(self, datapath):
        super(OFPBarrierReply, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_FLOW_REMOVED)
class OFPFlowRemoved(MsgBase):
    def __init__(self, datapath):
        super(OFPFlowRemoved, self).__init__(datapath)

    def __str__(self):
        buf = super(OFPFlowRemoved, self).__str__()
        return _str_attr(self, buf,
                         ('match', 'cookie', 'priority', 'reason',
                          'duration_sec', 'duration_nsec',
                          'idle_timeout', 'packet_count', 'idle_count'))

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPFlowRemoved, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)

        msg.match = OFPMatch.parse(msg.buf, ofproto_v1_0.OFP_HEADER_SIZE)

        (msg.cookie,
         msg.priority,
         msg.reason,
         msg.duration_sec,
         msg.duration_nsec,
         msg.idle_timeout,
         msg.packet_count,
         msg.byte_count) = struct.unpack_from(
            ofproto_v1_0.OFP_FLOW_REMOVED_PACK_STR0, msg.buf,
            ofproto_v1_0.OFP_HEADER_SIZE + ofproto_v1_0.OFP_MATCH_SIZE)

        return msg

#
# controller-to-switch message
# serializer only
#


@_set_msg_type(ofproto_v1_0.OFPT_FEATURES_REQUEST)
class OFPFeaturesRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPFeaturesRequest, self).__init__(datapath)


@_set_msg_type(ofproto_v1_0.OFPT_GET_CONFIG_REQUEST)
class OFPGetConfigRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPGetConfigRequest, self).__init__(datapath)


@_set_msg_type(ofproto_v1_0.OFPT_SET_CONFIG)
class OFPSetConfig(MsgBase):
    def __init__(self, datapath, flags=None, miss_send_len=None):
        super(OFPSetConfig, self).__init__(datapath)
        self.flags = flags
        self.miss_send_len = miss_send_len

    def _serialize_body(self):
        assert self.flags is not None
        assert self.miss_send_len is not None
        _pack_into(ofproto_v1_0.OFP_SWITCH_CONFIG_PACK_STR,
                   self.buf, ofproto_v1_0.OFP_HEADER_SIZE,
                   self.flags, self.miss_send_len)


@_set_msg_type(ofproto_v1_0.OFPT_PACKET_OUT)
class OFPPacketOut(MsgBase):
    def __init__(self, datapath, buffer_id=None, in_port=None, actions=None,
                 data=None):
        super(OFPPacketOut, self).__init__(datapath)
        self.buffer_id = buffer_id
        self.in_port = in_port
        self.actions_len = None
        self.actions = actions
        self.data = data

    def _serialize_body(self):
        assert self.buffer_id is not None
        assert self.in_port is not None
        assert self.actions_len is None
        assert self.actions is not None

        self.actions_len = 0
        offset = ofproto_v1_0.OFP_PACKET_OUT_SIZE
        for a in self.actions:
            a.serialize(self.buf, offset)
            offset += a.len
            self.actions_len += a.len

        if self.data is not None:
            assert self.buffer_id == -1
            self.buf += self.data

        _pack_into(ofproto_v1_0.OFP_PACKET_OUT_PACK_STR,
                   self.buf, ofproto_v1_0.OFP_HEADER_SIZE,
                   self.buffer_id, self.in_port, self.actions_len)


@_set_msg_type(ofproto_v1_0.OFPT_FLOW_MOD)
class OFPFlowMod(MsgBase):
    def __init__(self, datapath, match=None, cookie=None,
                 command=None, idle_timeout=None, hard_timeout=None,
                 priority=None, buffer_id=None, out_port=None,
                 flags=None, actions=None):
        super(OFPFlowMod, self).__init__(datapath)
        self.match = match
        self.cookie = cookie
        self.command = command
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.priority = priority
        self.buffer_id = buffer_id
        self.out_port = out_port
        self.flags = flags
        self.actions = actions

    def _serialize_body(self):
        offset = ofproto_v1_0.OFP_HEADER_SIZE
        self.match.serialize(self.buf, offset)

        offset += ofproto_v1_0.OFP_MATCH_SIZE
        _pack_into(ofproto_v1_0.OFP_FLOW_MOD_PACK_STR0, self.buf, offset,
                   self.cookie, self.command,
                   self.idle_timeout, self.hard_timeout,
                   self.priority, self.buffer_id, self.out_port,
                   self.flags)

        offset = ofproto_v1_0.OFP_FLOW_MOD_SIZE
        if self.actions is not None:
            for a in self.actions:
                a.serialize(self.buf, offset)
                offset += a.len


@_set_msg_type(ofproto_v1_0.OFPT_BARRIER_REQUEST)
class OFPBarrierRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPBarrierRequest, self).__init__(datapath)
