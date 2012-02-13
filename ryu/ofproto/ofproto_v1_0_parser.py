# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

from ofproto_parser import MsgBase, msg_pack_into, msg_str_attr
from ryu.lib import mac
from . import ofproto_parser
from . import ofproto_v1_0

import logging
LOG = logging.getLogger('ryu.ofproto.ofproto_v1_0_parser')

_MSG_PARSERS = {}


def _set_msg_type(msg_type):
    '''Annotate corresponding OFP message type'''
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


# OFP_MSG_REPLY = {
#     OFPFeaturesRequest: OFPSwitchFeatures,
#     OFPBarrierRequest: OFPBarrierReplay,
#     OFPQueueGetConfigRequest: OFPQueueGetConfigReply,
#
#     # ofp_stats_request -> ofp_stats_reply
#     OFPDescStatsRequest: OFPDescStatsReply,
#     OFPFlowStatsRequest: OFPFlowStatsReply,
#     OFPAggregateStatsRequest: OFPAggregateStatsReply,
#     OFPTableStatsRequest: OFPTableStatsReply,
#     OFPPortStatsRequest: OFPPortStatsReply,
#     OFPQueueStatsRequest: OFPQueueStatsReply,
#     OFPVendorStatsRequest: OFPVendorStatsReply,
#     }
def _set_msg_reply(msg_reply):
    '''Annotate OFP reply message class'''
    def _set_cls_msg_reply(cls):
        cls.cls_msg_reply = msg_reply
        return cls
    return _set_cls_msg_reply


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

    def __new__(cls, *args):
        # for convenience when dl_src/dl_dst are wildcard
        if args[2] != 0 and args[3] != 0:
            return super(cls, OFPMatch).__new__(cls, *args)

        tmp = list(args)
        if tmp[2] == 0:
            tmp[2] = mac.DONTCARE
        if tmp[3] == 0:
            tmp[3] = mac.DONTCARE
        return super(cls, OFPMatch).__new__(cls, *tmp)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_MATCH_PACK_STR, buf, offset, *self)

    @classmethod
    def parse(cls, buf, offset):
        match = struct.unpack_from(ofproto_v1_0.OFP_MATCH_PACK_STR,
                                   buf, offset)
        return cls(*match)


class OFPActionHeader(object):
    def __init__(self, type_, len_):
        self.type = type_
        self.len = len_

    def serlize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_HEADER_PACK_STR,
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
            ofproto_v1_0.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        offset += ofproto_v1_0.OFP_ACTION_HEADER_SIZE
        return cls.parser(buf, offset)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_OUTPUT,
                                ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)
class OFPActionOutput(OFPAction):
    def __init__(self, port, max_len=0):
        super(OFPActionOutput, self).__init__()
        self.port = port
        self.max_len = max_len

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, port, max_len = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_OUTPUT_PACK_STR, buf, offset)
        assert type_ == ofproto_v1_0.OFPAT_OUTPUT
        assert len_ == ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE
        return cls(port, max_len)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_OUTPUT_PACK_STR, buf,
                      offset, self.type, self.len, self.port, self.max_len)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_VLAN_VID,
                                ofproto_v1_0.OFP_ACTION_VLAN_VID_SIZE)
class OFPActionVlanVid(OFPAction):
    def __init__(self, vlan_vid):
        super(OFPActionVlanVid, self).__init__()
        self.vlan_vid = vlan_vid

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, vlan_vid = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_VLAN_VID_PACK_STR, buf, offset)
        assert type_ == ofproto_v1_0.OFPAT_SET_VLAN_VID
        assert len_ == ofproto_v1_0.OFP_ACTION_VLAN_VID_SIZE
        return cls(vlan_vid)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_VLAN_VID_PACK_STR,
                      buf, offset, self.type, self.len, self.vlan_vid)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_VLAN_PCP,
                                ofproto_v1_0.OFP_ACTION_VLAN_PCP_SIZE)
class OFPActionVlanPcp(OFPAction):
    def __init__(self, vlan_pcp):
        super(OFPActionVlanPcp, self).__init__()
        self.vlan_pcp = vlan_pcp

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, vlan_pcp = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_VLAN_PCP_PACK_STR, buf, offset)
        assert type_ == ofproto_v1_0.OFPAT_SET_VLAN_PCP
        assert len_ == ofproto_v1_0.OFP_ACTION_VLAN_PCP_SIZE
        return cls(vlan_pcp)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_VLAN_PCP_PACK_STR,
                      buf, offset, self.type, self.len, self.vlan_pcp)


class OFPActionDlAddr(OFPAction):
    def __init__(self, dl_addr):
        super(OFPActionDlAddr, self).__init__()
        self.dl_addr = dl_addr

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, dl_addr = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_DL_ADDR_PACK_STR, buf, offset)
        assert type_ in (ofproto_v1_0.OFPAT_SET_DL_SRC,
                         ofproto_v1_0.OFPAT_SET_DL_DST)
        assert len_ == ofproto_v1_0.OFP_ACTION_DL_ADDR_SIZE
        return cls(dl_addr)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_DL_ADDR_PACK_STR,
                      buf, offset, self.type, self.len, self.dl_addr)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_DL_SRC,
                                ofproto_v1_0.OFP_ACTION_DL_ADDR_SIZE)
class OFPActionSetDlSrc(OFPActionDlAddr):
    def __init__(self, dl_addr):
        super(OFPActionSetDlSrc, self).__init__(dl_addr)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_DL_DST,
                                ofproto_v1_0.OFP_ACTION_DL_ADDR_SIZE)
class OFPActionSetDlDst(OFPActionDlAddr):
    def __init__(self, dl_addr):
        super(OFPActionSetDlDst, self).__init__(dl_addr)


class OFPActionNwAddr(OFPAction):
    def __init__(self, nw_addr):
        super(OFPActionNwAddr, self).__init__()
        self.nw_addr = nw_addr

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, nw_addr = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_NW_ADDR_PACK_STR, buf, offset)
        assert type_ in (ofproto_v1_0.OFPAT_SET_NW_SRC,
                         ofproto_v1_0.OFPAT_SET_NW_DST)
        assert len_ == ofproto_v1_0.OFP_ACTION_NW_ADDR_SIZE
        return cls(nw_addr)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_NW_ADDR_PACK_STR,
                      buf, offset, self.type, self.len, self.nw_addr)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_NW_SRC,
                                ofproto_v1_0.OFP_ACTION_NW_ADDR_SIZE)
class OFPActionSetNwSrc(OFPActionNwAddr):
    def __init__(self, nw_addr):
        super(OFPActionSetNwSrc, self).__init__(nw_addr)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_NW_DST,
                                ofproto_v1_0.OFP_ACTION_NW_ADDR_SIZE)
class OFPActionSetNwDst(OFPActionNwAddr):
    def __init__(self, nw_addr):
        super(OFPActionSetNwDst, self).__init__(nw_addr)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_NW_TOS,
                                ofproto_v1_0.OFP_ACTION_NW_TOS_SIZE)
class OFPActionSetNwTos(OFPAction):
    def __init__(self, tos):
        super(OFPActionSetNwTos, self).__init__()
        self.tos = tos

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, tos = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_NW_TOS_PACK_STR, buf, offset)
        assert type_ == ofproto_v1_0.OFPAT_SET_NW_TOS
        assert len_ == ofproto_v1_0.OFP_ACTION_NW_TOS_SIZE
        return cls(tos)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_NW_TOS_PACK_STR,
                      buf, offset, self.type, self.len, self.tos)


class OFPActionTpPort(OFPAction):
    def __init__(self, tp):
        super(OFPActionTpPort, self).__init__()
        self.tp = tp

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, tp = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_TP_PORT_PACK_STR, buf, offset)
        assert type_ in (ofproto_v1_0.OFPAT_SET_TP_SRC,
                         ofproto_v1_0.OFPAT_SET_TP_DST)
        assert len_ == ofproto_v1_0.OFP_ACTION_TP_PORT_SIZE
        return cls(tp)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_TP_PORT_PACK_STR,
                      buf, offset, self.type, self.len, self.tp)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_TP_SRC,
                                ofproto_v1_0.OFP_ACTION_TP_PORT_SIZE)
class OFPActionSetTpSrc(OFPActionTpPort):
    def __init__(self, tp):
        super(OFPActionSetTpSrc, self).__init__(tp)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_SET_TP_DST,
                                ofproto_v1_0.OFP_ACTION_TP_PORT_SIZE)
class OFPActionSetTpDst(OFPActionTpPort):
    def __init__(self, tp):
        super(OFPActionSetTpDst, self).__init__(tp)


@OFPAction.register_action_type(ofproto_v1_0.OFPAT_ENQUEUE,
                                ofproto_v1_0.OFP_ACTION_ENQUEUE_SIZE)
class OFPActionEnqueue(OFPAction):
    def __init__(self, port, queue_id):
        super(OFPActionEnqueue, self).__init__()
        self.port = port
        self.queue_id = queue_id

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, port, queue_id = struct.unpack_from(
            ofproto_v1_0.OFP_ACTION_ENQUEUE_PACK_STR, buf, offset)
        assert type_ == ofproto_v1_0.OFPAT_ENQUEUE
        assert len_ == ofproto_v1_0.OFP_ACTION_ENQUEUE_SIZE
        return cls(port, queue_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto_v1_0.OFP_ACTION_ENQUEUE_PACK_STR, buf, offset,
                      self.type, self.len, self.port, self.queue_id)


# TODO:XXX OFPActionVendor


class OFPDescStats(collections.namedtuple('OFPDescStats',
        ('mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc'))):
    @classmethod
    def parser(cls, buf, offset):
        desc = struct.unpack_from(ofproto_v1_0.OFP_DESC_STATS_PACK_STR,
                                  buf, offset)
        return cls(*desc)


class OFPFlowStats(object):
    def __init__(self):
        super(OFPFlowStats, self).__init__()
        self.length = None
        self.table_id = None
        self.match = None
        self.duration_sec = None
        self.duration_nsec = None
        self.priority = None
        self.idle_timeout = None
        self.hard_timeout = None
        self.cookie = None
        self.packet_count = None
        self.byte_count = None
        self.actions = None

    @classmethod
    def parser(cls, buf, offset):
        flow_stats = cls()

        flow_stats.length, flow_stats.table_id = struct.unpack(
            ofproto_v1_0.OFP_FLOW_STATS_0_PACK_STR, buf, offset)
        offset += ofproto_v1_0.OFP_FLOW_STATS_0_SIZE

        flow_stats.match = OFPMatch.parse(buf, offset)
        offset += ofproto_v1_0.OFP_MATCH_SIZE

        (flow_stats.duration_sec,
         flow_stats.duration_nsec,
         flow_stats.priority,
         flow_stats.idle_timeout,
         flow_stats.hard_timeout,
         flow_stats.cookie,
         flow_stats.packet_count,
         flow_stats.byte_conunt) = struct.unpack_from(
            ofproto_v1_0.OFP_FLOW_STATS_1_PACK_STR, buf, offset)

        flow_stats.actions = []
        length = ofproto_v1_0.OFP_FLOW_STATS_SIZE
        while length < flow_stats.length:
            action = OFPAction.parser(buf, offset)
            flow_stats.actions.append(action)

            offset += action.len
            length += action.len

        return flow_stats


class OFPAggregateStats(collections.namedtuple('OFPAggregateStats',
        ('packet_count', 'byte_count', 'flow_count'))):
    @classmethod
    def parser(cls, buf, offset):
        agg = struct.unpack_from(
            ofproto_v1_0.OFP_AGGREGATE_STATS_REPLY_PACK_STR, buf, offset)
        return cls(*agg)


class OFPTableStats(collections.namedtuple('OFPTableStats',
        ('table_id', 'name', 'wildcards', 'max_entries', 'active_count',
         'lookup_count', 'matched_count'))):
    @classmethod
    def parser(cls, buf, offset):
        tbl = struct.unpack_from(ofproto_v1_0.OFP_TABLE_STATS_PACK_STR,
                                 buf, offset)
        return cls(*tbl)


class OFPPortStats(collections.namedtuple('OFPPortStats',
        ('port_no', 'rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
         'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors',
         'rx_frame_err', 'rx_over_err', 'rx_crc_err', 'collisions'))):
    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto_v1_0.OFP_PORT_STATS_PACK_STR,
                                  buf, offset)
        return cls(*port)


class OFPQueueStats(collections.namedtuple('OFPQueueStats',
        ('port_no', 'queue_id', 'tx_bytes', 'tx_packets', 'tx_errors'))):
    @classmethod
    def parser(cls, buf, offset):
        queue = struct.unpack_from(ofproto_v1_0.OFP_QUEUE_STATS_PACK_STR,
                                   buf, offset)
        return cls(*queue)


class OFPVendorStats(collections.namedtuple('OFPVendorStats',
                                            ('specific_data'))):
    @classmethod
    def parser(cls, buf, offset):
        return cls((buf[offset:], ))


class OFPQueuePropHeader(object):
    _QUEUE_PROPERTIES = {}

    @staticmethod
    def register_queue_property(prop_type, prop_len):
        def _register_queue_propery(cls):
            cls.cls_prop_type = prop_type
            cls.cls_prop_len = prop_len
            OFPQueuePropHeader._QUEUE_PROPERTIES[prop_type] = cls
            return cls
        return _register_queue_propery

    def __init__(self):
        self.property = self.cls_prop_type
        self.len = self.cls_prop_len

    def __str__(self):
        buf = super(OFPQueuePropHeader, self).__str__()
        return msg_str_attr(self, buf, ('property', 'len'))

    @classmethod
    def parser(cls, buf, offset):
        property_, len_ = struct.unpack_from(
            ofproto_v1_0.OFP_QUEUE_PROP_HEADER_PACK_STR, buf, offset)
        prop_cls = cls._QUEUE_PROPERTIES[property_]
        assert property_ == prop_cls.cls_prop_type
        assert len_ == prop_cls.cls_prop_len

        offset += ofproto_v1_0.OFP_QUEUE_PROP_HEADER_SIZE
        return prop_cls.parser(buf, offset)


@OFPQueuePropHeader.register_queue_property(
    ofproto_v1_0.OFPQT_NONE, ofproto_v1_0.OFP_QUEUE_PROP_HEADER_SIZE)
class OFPQueuePropNone(OFPQueuePropHeader):
    def __init__(self):
        super(OFPQueuePropNone, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        return cls()


@OFPQueuePropHeader.register_queue_property(
    ofproto_v1_0.OFPQT_MIN_RATE, ofproto_v1_0.OFP_QUEUE_PROP_MIN_RATE_SIZE)
class OFPQueuePropMinRate(OFPQueuePropHeader):
    def __init__(self, rate):
        super(OFPQueuePropMinRate, self).__init__()
        self.rate = rate

    def __str__(self):
        buf = super(OFPQueuePropMinRate, self).__str__()
        return msg_str_attr(self, buf, ('rate'))

    @classmethod
    def parser(cls, buf, offset):
        rate = struct.pack_from(ofproto_v1_0.OFP_QUEUE_PROP_MIN_RATE_PACK_STR,
                                buf, offset)
        return cls(rate)


class OFPPacketQueue(object):
    def __init__(self, queue_id, len_):
        self.queue_id = queue_id
        self.len = len_
        self.properties = None

    @classmethod
    def parser(cls, buf, offset):
        queue_id, len_ = struct.unpack_from(
            ofproto_v1_0.OFP_PACKET_QUEUE_PQCK_STR, buf, offset)
        packet_queue = cls(queue_id, len_)

        packet_queue.properties = []
        cur_len = ofproto_v1_0.OFP_PACKET_QUEUE_SIZE
        offset += ofproto_v1_0.OFP_PACKET_QUEUE_SIZE
        while (cur_len + ofproto_v1_0.OFP_QUEUE_PROP_HEADER_SIZE <=
               packet_queue.len):
            prop = OFPQueuePropHeader.parser(buf, offset)
            offset.properties.append(prop)

            cur_len += prop.len
            offset += prop.len

        return packet_queue

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
        msg_pack_into(ofproto_v1_0.OFP_ERROR_MSG_PACK_STR, self.buf,
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
        self.vendor = None

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
        msg_pack_into(ofproto_v1_0.OFP_VENDOR_HEADER_PACK_STR,
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
        for _port_no, p in getattr(self, 'ports', {}).items():
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
        for _i in range(n_ports):
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
        return msg_str_attr(self, buf,
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
        return msg_str_attr(self, buf,
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


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_QUEUE_GET_CONFIG_REPLY)
class OFPQueueGetConfigReply(MsgBase):
    def __init__(self, datapath):
        super(OFPQueueGetConfigReply, self).__init__(datapath)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPQueueGetConfigReply, cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)

        offset = ofproto_v1_0.OFP_HEADER_SIZE
        msg.port = struct.unpack_from(
            ofproto_v1_0.OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR, msg.buf, offset)

        msg.queues = []
        offset = ofproto_v1_0.OFP_QUEUE_GET_CONFIG_REPLY_SIZE
        while offset + ofproto_v1_0.OFP_PACKET_QUEUE_SIZE <= msg_len:
            queue = OFPPacketQueue.parser(msg.buf, offset)
            msg.queues.append(queue)

            offset += queue.len

        return msg


def _set_stats_type(stats_type, stats_body_cls):
    def _set_cls_stats_type(cls):
        cls.cls_stats_type = stats_type
        cls.cls_stats_body_cls = stats_body_cls
        return cls
    return _set_cls_stats_type


@_register_parser
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPStatsReply(MsgBase):
    _STATS_MSG_TYPES = {}

    @staticmethod
    def register_stats_type(body_cls_size=0):
        def _register_stats_type(cls):
            assert cls.cls_stats_type is not None
            assert cls.cls_stats_type not in OFPStatsReply._STATS_MSG_TYPES
            assert cls.cls_stats_body_cls is not None
            cls.cls_stats_body_cls_size = body_cls_size
            OFPStatsReply._STATS_MSG_TYPES[cls.cls_stats_type] = cls
            return cls
        return _register_stats_type

    def __init__(self, datapath):
        super(OFPStatsReply, self).__init__(datapath)
        self.type = None
        self.flags = None
        self.body = None

    @classmethod
    def parser_stats_body_array(cls, buf, msg_len, offset, entry_size):
        body_cls = cls.cls_stats_body_cls
        body = []
        while offset + entry_size <= msg_len:
            entry = body_cls.parser(buf, offset)
            body.append(entry)
            offset += entry_size
        return body

    @classmethod
    def parser_stats_body(cls, buf, msg_len, offset):
        if cls.cls_stats_body_cls_size == 0:
            return cls.cls_stats_body_cls.parser(buf, offset)

        return cls.parser_stats_body_array(buf, msg_len, offset,
                                           cls.cls_stats_body_cls_size)

    @classmethod
    def parser_stats(cls, datapath, version, msg_type, msg_len, xid, buf):
        # call MsgBase::parser, not OFPStatsReply::parser
        msg = MsgBase.parser.__func__(
            cls, datapath, version, msg_type, msg_len, xid, buf)
        msg.body = msg.parser_stats_body(msg.buf, msg.msg_len,
                                         ofproto_v1_0.OFP_STATS_MSG_SIZE)
        return msg

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        type_, flags = struct.unpack_from(ofproto_v1_0.OFP_STATS_MSG_PACK_STR,
                                          buffer(buf),
                                          ofproto_v1_0.OFP_HEADER_SIZE)
        stats_type_cls = cls._STATS_MSG_TYPES.get(type_)
        msg = stats_type_cls.parser_stats(
            datapath, version, msg_type, msg_len, xid, buf)
        msg.type = type_
        msg.flags = flags
        return msg


@OFPStatsReply.register_stats_type()
@_set_stats_type(ofproto_v1_0.OFPST_DESC, OFPDescStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPDescStatsReply(OFPStatsReply):
    def __init__(self, datapath):
        super(OFPDescStatsReply, self).__init__(datapath)


@OFPStatsReply.register_stats_type(ofproto_v1_0.OFP_FLOW_STATS_SIZE)
@_set_stats_type(ofproto_v1_0.OFPST_FLOW, OFPFlowStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPFlowStatsReply(OFPStatsReply):
    def __init__(self, datapath):
        super(OFPFlowStatsReply, self).__init__(datapath)


@OFPStatsReply.register_stats_type(ofproto_v1_0.OFP_AGGREGATE_STATS_REPLY_SIZE)
@_set_stats_type(ofproto_v1_0.OFPST_AGGREGATE, OFPAggregateStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPAggregateStatsReply(OFPStatsReply):
    def __init__(self, datapath):
        super(OFPAggregateStatsReply, self).__init__(datapath)


@OFPStatsReply.register_stats_type(ofproto_v1_0.OFP_TABLE_STATS_SIZE)
@_set_stats_type(ofproto_v1_0.OFPST_TABLE, OFPTableStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPTableStatsReply(OFPStatsReply):
    def __init__(self, datapath):
        super(OFPTableStatsReply, self).__init__(datapath)


@OFPStatsReply.register_stats_type(ofproto_v1_0.OFP_PORT_STATS_SIZE)
@_set_stats_type(ofproto_v1_0.OFPST_PORT, OFPPortStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPPortStatsReply(OFPStatsReply):
    def __init__(self, datapath):
        super(OFPPortStatsReply, self).__init__(datapath)


@OFPStatsReply.register_stats_type(ofproto_v1_0.OFP_QUEUE_STATS_SIZE)
@_set_stats_type(ofproto_v1_0.OFPST_QUEUE, OFPQueueStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPQueueStatsReply(OFPStatsReply):
    def __init__(self, datapath):
        super(OFPQueueStatsReply, self).__init__(datapath)


@OFPStatsReply.register_stats_type()
@_set_stats_type(ofproto_v1_0.OFPST_VENDOR, OFPVendorStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REPLY)
class OFPVendorStatsReply(OFPStatsReply):
    def __init__(self, datapath):
        super(OFPVendorStatsReply, self).__init__(datapath)


#
# controller-to-switch message
# serializer only
#


@_set_msg_reply(OFPSwitchFeatures)
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
        msg_pack_into(ofproto_v1_0.OFP_SWITCH_CONFIG_PACK_STR,
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

        msg_pack_into(ofproto_v1_0.OFP_PACKET_OUT_PACK_STR,
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
        msg_pack_into(ofproto_v1_0.OFP_FLOW_MOD_PACK_STR0, self.buf, offset,
                      self.cookie, self.command,
                      self.idle_timeout, self.hard_timeout,
                      self.priority, self.buffer_id, self.out_port,
                      self.flags)

        offset = ofproto_v1_0.OFP_FLOW_MOD_SIZE
        if self.actions is not None:
            for a in self.actions:
                a.serialize(self.buf, offset)
                offset += a.len


@_set_msg_reply(OFPBarrierReply)
@_set_msg_type(ofproto_v1_0.OFPT_BARRIER_REQUEST)
class OFPBarrierRequest(MsgBase):
    def __init__(self, datapath):
        super(OFPBarrierRequest, self).__init__(datapath)


@_set_msg_reply(OFPQueueGetConfigReply)
@_set_msg_type(ofproto_v1_0.OFPT_QUEUE_GET_CONFIG_REQUEST)
class OFPQueueGetConfigRequest(MsgBase):
    def __init__(self, datapath, port):
        super(OFPQueueGetConfigRequest, self).__init__(datapath)
        self.port = port

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_0.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_0.OFP_HEADER_SIZE, self.port)


class OFPStatsRequest(MsgBase):
    def __init__(self, datapath, flags):
        assert flags == 0       # none yet defined

        super(OFPStatsRequest, self).__init__(datapath)
        self.type = self.__class__.cls_stats_type
        self.flags = flags

    def _serialize_stats_body(self):
        pass

    def _serialize_body(self):
        msg_pack_into(ofproto_v1_0.OFP_STATS_MSG_PACK_STR,
                      self.buf, ofproto_v1_0.OFP_HEADER_SIZE,
                      self.type, self.flags)
        self._serialize_stats_body()


@_set_msg_reply(OFPDescStatsReply)
@_set_stats_type(ofproto_v1_0.OFPST_DESC, OFPDescStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REQUEST)
class OFPDescStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags):
        super(OFPDescStatsRequest, self).__init__(datapath, flags)


class OFPFlowStatsRequestBase(OFPStatsRequest):
    def __init__(self, datapath, flags, match, table_id, out_port):
        super(OFPFlowStatsRequest. self).__init__(datapath, flags)
        self.match = match
        self.table_id = table_id
        self.out_port = out_port

    def _serialize_stats_body(self):
        offset = ofproto_v1_0.OFP_STATS_MSG_SIZE
        self.match.serialize(self.buf, offset)

        offset += ofproto_v1_0.OFP_MATCH_SIZE
        msg_pack_into(ofproto_v1_0.OFP_FLOW_STATS_REQUEST_ID_PORT_STR,
                      self.buf, offset, self.table_id, self.out_port)


@_set_msg_reply(OFPFlowStatsReply)
@_set_stats_type(ofproto_v1_0.OFPST_FLOW, OFPFlowStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REQUEST)
class OFPFlowStatsRequest(OFPFlowStatsRequestBase):
    def __init__(self, datapath, flags, match, table_id, out_port):
        super(OFPFlowStatsRequest, self).__init__(
            datapath, flags, match, table_id, out_port)


@_set_msg_reply(OFPAggregateStatsReply)
@_set_stats_type(ofproto_v1_0.OFPST_AGGREGATE, OFPAggregateStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REQUEST)
class OFPAggregateStatsRequest(OFPFlowStatsRequestBase):
    def __init__(self, datapath, flags, match, table_id, out_port):
        super(OFPAggregateStatsRequest, self).__init__(
            datapath, flags, match, table_id, out_port)


@_set_msg_reply(OFPTableStatsReply)
@_set_stats_type(ofproto_v1_0.OFPST_TABLE, OFPTableStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REQUEST)
class OFPTableStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags):
        super(OFPTableStatsRequest, self).__init__(datapath, flags)


@_set_msg_reply(OFPPortStatsReply)
@_set_stats_type(ofproto_v1_0.OFPST_PORT, OFPPortStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REQUEST)
class OFPPortStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags, port_no):
        super(OFPPortStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_0.OFP_PORT_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_0.OFP_STATS_MSG_SIZE, self.port_no)


@_set_msg_reply(OFPQueueStatsReply)
@_set_stats_type(ofproto_v1_0.OFPST_QUEUE, OFPQueueStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REQUEST)
class OFPQueueStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags, port_no, queue_id):
        super(OFPQueueStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no
        self.queue_id = queue_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_0.OFP_QUEUE_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto_v1_0.OFP_STATS_MSG_SIZE,
                      self.port_no, self.queue_id)


@_set_msg_reply(OFPVendorStatsReply)
@_set_stats_type(ofproto_v1_0.OFPST_VENDOR, OFPVendorStats)
@_set_msg_type(ofproto_v1_0.OFPT_STATS_REQUEST)
class OFPVendorStatsRequest(OFPStatsRequest):
    def __init__(self, datapath, flags, vendor, specific_data):
        super(OFPVendorStatsRequest, self).__init__(datapath, flags)
        self.vendor = vendor
        self.specific_data = specific_data

    def _serialize_stats_body(self):
        msg_pack_into(ofproto_v1_0.OFP_VENDOR_STATS_MSG_PACK_STR,
                      self.buf, ofproto_v1_0.OFP_STATS_MSG_SIZE,
                      self.vendor)
        self.buf += self.specific_data
