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

"""
Decoder/Encoder implementations of OpenFlow 1.2.
"""

import six
import struct

from ryu.lib import addrconv
from ryu.lib import mac
from ryu.lib.pack_utils import msg_pack_into
from ryu import utils
from ryu.ofproto.ofproto_parser import StringifyMixin, MsgBase
from ryu.ofproto import ether
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_2 as ofproto

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


@ofproto_parser.register_msg_parser(ofproto.OFP_VERSION)
def msg_parser(datapath, version, msg_type, msg_len, xid, buf):
    parser = _MSG_PARSERS.get(msg_type)
    return parser(datapath, version, msg_type, msg_len, xid, buf)


@_register_parser
@_set_msg_type(ofproto.OFPT_HELLO)
class OFPHello(MsgBase):
    """
    Hello message

    When connection is started, the hello message is exchanged between a
    switch and a controller.

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.
    """
    def __init__(self, datapath):
        super(OFPHello, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto.OFPT_ERROR)
class OFPErrorMsg(MsgBase):
    """
    Error message

    The switch notifies controller of problems by this message.

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    type       High level type of error
    code       Details depending on the type
    data       Variable length data depending on the type and code
    ========== =========================================================

    ``type`` attribute corresponds to ``type_`` parameter of __init__.

    Types and codes are defined in ``ryu.ofproto.ofproto``.

    ============================= ===========
    Type                          Code
    ============================= ===========
    OFPET_HELLO_FAILED            OFPHFC_*
    OFPET_BAD_REQUEST             OFPBRC_*
    OFPET_BAD_ACTION              OFPBAC_*
    OFPET_BAD_INSTRUCTION         OFPBIC_*
    OFPET_BAD_MATCH               OFPBMC_*
    OFPET_FLOW_MOD_FAILED         OFPFMFC_*
    OFPET_GROUP_MOD_FAILED        OFPGMFC_*
    OFPET_PORT_MOD_FAILED         OFPPMFC_*
    OFPET_TABLE_MOD_FAILED        OFPTMFC_*
    OFPET_QUEUE_OP_FAILED         OFPQOFC_*
    OFPET_SWITCH_CONFIG_FAILED    OFPSCFC_*
    OFPET_ROLE_REQUEST_FAILED     OFPRRFC_*
    OFPET_EXPERIMENTER            N/A
    ============================= ===========

    Example::

        @set_ev_cls(ofp_event.EventOFPErrorMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
        def error_msg_handler(self, ev):
            msg = ev.msg

            self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                              'message=%s',
                              msg.type, msg.code, utils.hex_array(msg.data))
    """
    def __init__(self, datapath, type_=None, code=None, data=None):
        super(OFPErrorMsg, self).__init__(datapath)
        self.type = type_
        self.code = code
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        type_, = struct.unpack_from('!H', six.binary_type(buf),
                                    ofproto.OFP_HEADER_SIZE)
        if type_ == ofproto.OFPET_EXPERIMENTER:
            return OFPErrorExperimenterMsg.parser(datapath, version, msg_type,
                                                  msg_len, xid, buf)

        msg = super(OFPErrorMsg, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        msg.type, msg.code = struct.unpack_from(
            ofproto.OFP_ERROR_MSG_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto.OFP_ERROR_MSG_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        msg_pack_into(ofproto.OFP_ERROR_MSG_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE, self.type, self.code)
        self.buf += self.data


class OFPErrorExperimenterMsg(MsgBase):
    def __init__(self, datapath, type_=None, exp_type=None, experimenter=None,
                 data=None):
        super(OFPErrorExperimenterMsg, self).__init__(datapath)
        self.type = ofproto.OFPET_EXPERIMENTER
        self.exp_type = exp_type
        self.experimenter = experimenter
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        cls.cls_msg_type = msg_type
        msg = super(OFPErrorExperimenterMsg, cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)
        msg.type, msg.exp_type, msg.experimenter = struct.unpack_from(
            ofproto.OFP_ERROR_EXPERIMENTER_MSG_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto.OFP_ERROR_EXPERIMENTER_MSG_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        msg_pack_into(ofproto.OFP_ERROR_EXPERIMENTER_MSG_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.type, self.exp_type, self.experimenter)
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto.OFPT_ECHO_REQUEST)
class OFPEchoRequest(MsgBase):
    """
    Echo request message

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    data       An arbitrary length data
    ========== =========================================================

    Example::

        def send_echo_request(self, datapath, data):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPEchoRequest(datapath, data)
            datapath.send_msg(req)

        @set_ev_cls(ofp_event.EventOFPEchoRequest,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
        def echo_request_handler(self, ev):
            self.logger.debug('OFPEchoRequest received: data=%s',
                              utils.hex_array(ev.msg.data))
    """
    def __init__(self, datapath, data=None):
        super(OFPEchoRequest, self).__init__(datapath)
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoRequest, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)
        msg.data = msg.buf[ofproto.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        if self.data is not None:
            self.buf += self.data


@_register_parser
@_set_msg_type(ofproto.OFPT_ECHO_REPLY)
class OFPEchoReply(MsgBase):
    """
    Echo reply message

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    data       An arbitrary length data
    ========== =========================================================

    Example::

        def send_echo_reply(self, datapath, data):
            ofp_parser = datapath.ofproto_parser

            reply = ofp_parser.OFPEchoReply(datapath, data)
            datapath.send_msg(reply)

        @set_ev_cls(ofp_event.EventOFPEchoReply,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
        def echo_reply_handler(self, ev):
            self.logger.debug('OFPEchoReply received: data=%s',
                              utils.hex_array(ev.msg.data))
    """
    def __init__(self, datapath, data=None):
        super(OFPEchoReply, self).__init__(datapath)
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPEchoReply, cls).parser(datapath, version, msg_type,
                                              msg_len, xid, buf)
        msg.data = msg.buf[ofproto.OFP_HEADER_SIZE:]
        return msg

    def _serialize_body(self):
        assert self.data is not None
        self.buf += self.data


@_register_parser
@_set_msg_type(ofproto.OFPT_EXPERIMENTER)
class OFPExperimenter(MsgBase):
    """
    Experimenter extension message

    ============= =========================================================
    Attribute     Description
    ============= =========================================================
    experimenter  Experimenter ID
    exp_type      Experimenter defined
    data          Experimenter defined arbitrary additional data
    ============= =========================================================
    """
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
            ofproto.OFP_EXPERIMENTER_HEADER_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
        msg.data = msg.buf[ofproto.OFP_EXPERIMENTER_HEADER_SIZE:]

        return msg

    def _serialize_body(self):
        assert self.data is not None
        msg_pack_into(ofproto.OFP_EXPERIMENTER_HEADER_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.experimenter, self.exp_type)
        self.buf += self.data


class OFPPort(ofproto_parser.namedtuple('OFPPort', (
        'port_no', 'hw_addr', 'name', 'config', 'state', 'curr',
        'advertised', 'supported', 'peer', 'curr_speed', 'max_speed'))):
    """
    Description of a port

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    port_no    Port number and it uniquely identifies a port within
               a switch.
    hw_addr    MAC address for the port.
    name       Null-terminated string containing a human-readable name
               for the interface.
    config     Bitmap of port configration flags.

               | OFPPC_PORT_DOWN
               | OFPPC_NO_RECV
               | OFPPC_NO_FWD
               | OFPPC_NO_PACKET_IN
    state      Bitmap of port state flags.

               | OFPPS_LINK_DOWN
               | OFPPS_BLOCKED
               | OFPPS_LIVE
    curr       Current features.
    advertised Features being advertised by the port.
    supported  Features supported by the port.
    peer       Features advertised by peer.
    curr_speed Current port bitrate in kbps.
    max_speed  Max port bitrate in kbps.
    ========== =========================================================
    """

    _TYPE = {
        'ascii': [
            'hw_addr',
        ],
        'utf-8': [
            # OF spec is unclear about the encoding of name.
            # we assumes UTF-8, which is used by OVS.
            'name',
        ]
    }

    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto.OFP_PORT_PACK_STR, buf, offset)
        port = list(port)
        i = cls._fields.index('hw_addr')
        port[i] = addrconv.mac.bin_to_text(port[i])
        i = cls._fields.index('name')
        port[i] = port[i].rstrip(b'\0')
        return cls(*port)


@_set_msg_type(ofproto.OFPT_FEATURES_REQUEST)
class OFPFeaturesRequest(MsgBase):
    """
    Features request message

    The controller sends a feature request to the switch upon session
    establishment.

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.

    Example::

        def send_features_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPFeaturesRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath):
        super(OFPFeaturesRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto.OFPT_FEATURES_REPLY)
class OFPSwitchFeatures(MsgBase):
    """
    Features reply message

    The switch responds with a features reply message to a features
    request.

    This message is handled by the Ryu framework, so the Ryu application
    do not need to process this typically.

    Example::

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            msg = ev.msg

            self.logger.debug('OFPSwitchFeatures received: '
                              'datapath_id=0x%016x n_buffers=%d '
                              'n_tables=%d capabilities=0x%08x ports=%s',
                              msg.datapath_id, msg.n_buffers, msg.n_tables,
                              msg.capabilities, msg.ports)
    """
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
            ofproto.OFP_SWITCH_FEATURES_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)

        msg.ports = {}
        n_ports = ((msg_len - ofproto.OFP_SWITCH_FEATURES_SIZE) //
                   ofproto.OFP_PORT_SIZE)
        offset = ofproto.OFP_SWITCH_FEATURES_SIZE
        for i in range(n_ports):
            port = OFPPort.parser(msg.buf, offset)
            msg.ports[port.port_no] = port
            offset += ofproto.OFP_PORT_SIZE

        return msg


@_set_msg_type(ofproto.OFPT_GET_CONFIG_REQUEST)
class OFPGetConfigRequest(MsgBase):
    """
    Get config request message

    The controller sends a get config request to query configuration
    parameters in the switch.

    Example::

        def send_get_config_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGetConfigRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath):
        super(OFPGetConfigRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto.OFPT_GET_CONFIG_REPLY)
class OFPGetConfigReply(MsgBase):
    """
    Get config reply message

    The switch responds to a configuration request with a get config reply
    message.

    ============= =========================================================
    Attribute     Description
    ============= =========================================================
    flags         One of the following configuration flags.

                  | OFPC_FRAG_NORMAL
                  | OFPC_FRAG_DROP
                  | OFPC_FRAG_REASM
                  | OFPC_FRAG_MASK
                  | OFPC_INVALID_TTL_TO_CONTROLLER
    miss_send_len Max bytes of new flow that datapath should send to the
                  controller
    ============= =========================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
        def get_config_reply_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.flags == ofp.OFPC_FRAG_NORMAL:
                flags = 'NORMAL'
            elif msg.flags == ofp.OFPC_FRAG_DROP:
                flags = 'DROP'
            elif msg.flags == ofp.OFPC_FRAG_REASM:
                flags = 'REASM'
            elif msg.flags == ofp.OFPC_FRAG_MASK:
                flags = 'MASK'
            elif msg.flags == ofp.OFPC_INVALID_TTL_TO_CONTROLLER:
                flags = 'INVALID TTL TO CONTROLLER'
            else:
                flags = 'unknown'
            self.logger.debug('OFPGetConfigReply received: '
                              'flags=%s miss_send_len=%d',
                              flags, msg.miss_send_len)
    """
    def __init__(self, datapath, flags=None, miss_send_len=None):
        super(OFPGetConfigReply, self).__init__(datapath)
        self.flags = flags
        self.miss_send_len = miss_send_len

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPGetConfigReply, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        msg.flags, msg.miss_send_len = struct.unpack_from(
            ofproto.OFP_SWITCH_CONFIG_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
        return msg


@_set_msg_type(ofproto.OFPT_SET_CONFIG)
class OFPSetConfig(MsgBase):
    """
    Set config request message

    The controller sends a set config request message to set configuraion
    parameters.

    ============= =========================================================
    Attribute     Description
    ============= =========================================================
    flags         One of the following configuration flags.

                  | OFPC_FRAG_NORMAL
                  | OFPC_FRAG_DROP
                  | OFPC_FRAG_REASM
                  | OFPC_FRAG_MASK
                  | OFPC_INVALID_TTL_TO_CONTROLLER
    miss_send_len Max bytes of new flow that datapath should send to the
                  controller
    ============= =========================================================

    Example::

        def send_set_config(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_NORMAL, 256)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, miss_send_len=0):
        super(OFPSetConfig, self).__init__(datapath)
        self.flags = flags
        self.miss_send_len = miss_send_len

    def _serialize_body(self):
        assert self.flags is not None
        assert self.miss_send_len is not None
        msg_pack_into(ofproto.OFP_SWITCH_CONFIG_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.flags, self.miss_send_len)


@_register_parser
@_set_msg_type(ofproto.OFPT_PACKET_IN)
class OFPPacketIn(MsgBase):
    """
    Packet-In message

    The switch sends the packet that received to the controller by this
    message.

    ============= =========================================================
    Attribute     Description
    ============= =========================================================
    buffer_id     ID assigned by datapath
    total_len     Full length of frame
    reason        Reason packet is being sent.

                  | OFPR_NO_MATCH
                  | OFPR_ACTION
                  | OFPR_INVALID_TTL
    table_id      ID of the table that was looked up
    match         Instance of ``OFPMatch``
    data          Ethernet frame
    ============= =========================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.OFPR_NO_MATCH:
                reason = 'NO MATCH'
            elif msg.reason == ofp.OFPR_ACTION:
                reason = 'ACTION'
            elif msg.reason == ofp.OFPR_INVALID_TTL:
                reason = 'INVALID TTL'
            else:
                reason = 'unknown'

            self.logger.debug('OFPPacketIn received: '
                              'buffer_id=%x total_len=%d reason=%s '
                              'table_id=%d match=%s data=%s',
                              msg.buffer_id, msg.total_len, reason,
                              msg.table_id, msg.match,
                              utils.hex_array(msg.data))
    """
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
            ofproto.OFP_PACKET_IN_PACK_STR,
            msg.buf, ofproto.OFP_HEADER_SIZE)

        msg.match = OFPMatch.parser(msg.buf, ofproto.OFP_PACKET_IN_SIZE -
                                    ofproto.OFP_MATCH_SIZE)

        match_len = utils.round_up(msg.match.length, 8)
        msg.data = msg.buf[(ofproto.OFP_PACKET_IN_SIZE -
                            ofproto.OFP_MATCH_SIZE + match_len + 2):]

        if msg.total_len < len(msg.data):
            # discard padding for 8-byte alignment of OFP packet
            msg.data = msg.data[:msg.total_len]

        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_FLOW_REMOVED)
class OFPFlowRemoved(MsgBase):
    """
    Flow removed message

    When flow entries time out or are deleted, the switch notifies controller
    with this message.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    cookie           Opaque controller-issued identifier
    priority         Priority level of flow entry
    reason           One of the following values.

                     | OFPRR_IDLE_TIMEOUT
                     | OFPRR_HARD_TIMEOUT
                     | OFPRR_DELETE
                     | OFPRR_GROUP_DELETE
    table_id         ID of the table
    duration_sec     Time flow was alive in seconds
    duration_nsec    Time flow was alive in nanoseconds beyond duration_sec
    idle_timeout     Idle timeout from original flow mod
    hard_timeout     Hard timeout from original flow mod
    packet_count     Number of packets that was associated with the flow
    byte_count       Number of bytes that was associated with the flow
    match            Instance of ``OFPMatch``
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
        def flow_removed_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
                reason = 'IDLE TIMEOUT'
            elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
                reason = 'HARD TIMEOUT'
            elif msg.reason == ofp.OFPRR_DELETE:
                reason = 'DELETE'
            elif msg.reason == ofp.OFPRR_GROUP_DELETE:
                reason = 'GROUP DELETE'
            else:
                reason = 'unknown'

            self.logger.debug('OFPFlowRemoved received: '
                              'cookie=%d priority=%d reason=%s table_id=%d '
                              'duration_sec=%d duration_nsec=%d '
                              'idle_timeout=%d hard_timeout=%d '
                              'packet_count=%d byte_count=%d match.fields=%s',
                              msg.cookie, msg.priority, reason, msg.table_id,
                              msg.duration_sec, msg.duration_nsec,
                              msg.idle_timeout, msg.hard_timeout,
                              msg.packet_count, msg.byte_count, msg.match)
    """
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
            ofproto.OFP_FLOW_REMOVED_PACK_STR0,
            msg.buf,
            ofproto.OFP_HEADER_SIZE)

        offset = (ofproto.OFP_FLOW_REMOVED_SIZE -
                  ofproto.OFP_MATCH_SIZE)

        msg.match = OFPMatch.parser(msg.buf, offset)

        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_PORT_STATUS)
class OFPPortStatus(MsgBase):
    """
    Port status message

    The switch notifies controller of change of ports.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    reason           One of the following values.

                     | OFPPR_ADD
                     | OFPPR_DELETE
                     | OFPPR_MODIFY
    desc             instance of ``OFPPort``
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
        def port_status_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.OFPPR_ADD:
                reason = 'ADD'
            elif msg.reason == ofp.OFPPR_DELETE:
                reason = 'DELETE'
            elif msg.reason == ofp.OFPPR_MODIFY:
                reason = 'MODIFY'
            else:
                reason = 'unknown'

            self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
                              reason, msg.desc)
    """
    def __init__(self, datapath, reason=None, desc=None):
        super(OFPPortStatus, self).__init__(datapath)
        self.reason = reason
        self.desc = desc

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPortStatus, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        msg.reason = struct.unpack_from(
            ofproto.OFP_PORT_STATUS_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)[0]
        msg.desc = OFPPort.parser(msg.buf,
                                  ofproto.OFP_PORT_STATUS_DESC_OFFSET)
        return msg


@_set_msg_type(ofproto.OFPT_PACKET_OUT)
class OFPPacketOut(MsgBase):
    """
    Packet-Out message

    The controller uses this message to send a packet out throught the
    switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    buffer_id        ID assigned by datapath (OFP_NO_BUFFER if none)
    in_port          Packet's input port or ``OFPP_CONTROLLER``
    actions          list of OpenFlow action class
    data             Packet data
    ================ ======================================================

    Example::

        def send_packet_out(self, datapath, buffer_id, in_port):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
            req = ofp_parser.OFPPacketOut(datapath, buffer_id,
                                          in_port, actions)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, buffer_id=None, in_port=None, actions=None,
                 data=None, actions_len=None):
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
        offset = ofproto.OFP_PACKET_OUT_SIZE
        for a in self.actions:
            a.serialize(self.buf, offset)
            offset += a.len
            self.actions_len += a.len

        if self.data is not None:
            assert self.buffer_id == 0xffffffff
            self.buf += self.data

        msg_pack_into(ofproto.OFP_PACKET_OUT_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.buffer_id, self.in_port, self.actions_len)


@_set_msg_type(ofproto.OFPT_FLOW_MOD)
class OFPFlowMod(MsgBase):
    """
    Modify Flow entry message

    The controller sends this message to modify the flow table.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    cookie           Opaque controller-issued identifier
    cookie_mask      Mask used to restrict the cookie bits that must match
                     when the command is ``OPFFC_MODIFY*`` or
                     ``OFPFC_DELETE*``
    table_id         ID of the table to put the flow in
    command          One of the following values.

                     | OFPFC_ADD
                     | OFPFC_MODIFY
                     | OFPFC_MODIFY_STRICT
                     | OFPFC_DELETE
                     | OFPFC_DELETE_STRICT
    idle_timeout     Idle time before discarding (seconds)
    hard_timeout     Max time before discarding (seconds)
    priority         Priority level of flow entry
    buffer_id        Buffered packet to apply to (or OFP_NO_BUFFER)
    out_port         For ``OFPFC_DELETE*`` commands, require matching
                     entries to include this as an output port
    out_group        For ``OFPFC_DELETE*`` commands, require matching
                     entries to include this as an output group
    flags            One of the following values.

                     | OFPFF_SEND_FLOW_REM
                     | OFPFF_CHECK_OVERLAP
                     | OFPFF_RESET_COUNTS
    match            Instance of ``OFPMatch``
    instructions     list of ``OFPInstruction*`` instance
    ================ ======================================================

    Example::

        def send_flow_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            cookie = cookie_mask = 0
            table_id = 0
            idle_timeout = hard_timeout = 0
            priority = 32768
            buffer_id = ofp.OFP_NO_BUFFER
            match = ofp_parser.OFPMatch(in_port=1, eth_dst='ff:ff:ff:ff:ff:ff')
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                        table_id, ofp.OFPFC_ADD,
                                        idle_timeout, hard_timeout,
                                        priority, buffer_id,
                                        ofp.OFPP_ANY, ofp.OFPG_ANY,
                                        ofp.OFPFF_SEND_FLOW_REM,
                                        match, inst)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, cookie=0, cookie_mask=0, table_id=0,
                 command=ofproto.OFPFC_ADD,
                 idle_timeout=0, hard_timeout=0, priority=0,
                 buffer_id=ofproto.OFP_NO_BUFFER,
                 out_port=0, out_group=0, flags=0,
                 match=None,
                 instructions=None):
        instructions = instructions if instructions else []
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
        if match is None:
            match = OFPMatch()
        assert isinstance(match, OFPMatch)
        self.match = match
        for i in instructions:
            assert isinstance(i, OFPInstruction)
        self.instructions = instructions

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_FLOW_MOD_PACK_STR0, self.buf,
                      ofproto.OFP_HEADER_SIZE,
                      self.cookie, self.cookie_mask, self.table_id,
                      self.command, self.idle_timeout, self.hard_timeout,
                      self.priority, self.buffer_id, self.out_port,
                      self.out_group, self.flags)

        offset = (ofproto.OFP_FLOW_MOD_SIZE -
                  ofproto.OFP_MATCH_SIZE)

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


@OFPInstruction.register_instruction_type([ofproto.OFPIT_GOTO_TABLE])
class OFPInstructionGotoTable(OFPInstruction):
    """
    Goto table instruction

    This instruction indicates the next table in the processing pipeline.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         Next table
    ================ ======================================================
    """
    def __init__(self, table_id, type_=None, len_=None):
        super(OFPInstructionGotoTable, self).__init__()
        self.type = ofproto.OFPIT_GOTO_TABLE
        self.len = ofproto.OFP_INSTRUCTION_GOTO_TABLE_SIZE
        self.table_id = table_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, table_id) = struct.unpack_from(
            ofproto.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR,
            buf, offset)
        return cls(table_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR,
                      buf, offset, self.type, self.len, self.table_id)


@OFPInstruction.register_instruction_type([ofproto.OFPIT_WRITE_METADATA])
class OFPInstructionWriteMetadata(OFPInstruction):
    """
    Write metadata instruction

    This instruction writes the masked metadata value into the metadata field.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    metadata         Metadata value to write
    metadata_mask    Metadata write bitmask
    ================ ======================================================
    """
    def __init__(self, metadata, metadata_mask, type_=None, len_=None):
        super(OFPInstructionWriteMetadata, self).__init__()
        self.type = ofproto.OFPIT_WRITE_METADATA
        self.len = ofproto.OFP_INSTRUCTION_WRITE_METADATA_SIZE
        self.metadata = metadata
        self.metadata_mask = metadata_mask

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, metadata, metadata_mask) = struct.unpack_from(
            ofproto.OFP_INSTRUCTION_WRITE_METADATA_PACK_STR,
            buf, offset)
        return cls(metadata, metadata_mask)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_INSTRUCTION_WRITE_METADATA_PACK_STR,
                      buf, offset, self.type, self.len, self.metadata,
                      self.metadata_mask)


@OFPInstruction.register_instruction_type([ofproto.OFPIT_WRITE_ACTIONS,
                                           ofproto.OFPIT_APPLY_ACTIONS,
                                           ofproto.OFPIT_CLEAR_ACTIONS])
class OFPInstructionActions(OFPInstruction):
    """
    Actions instruction

    This instruction writes/applies/clears the actions.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    type             One of following values.

                     | OFPIT_WRITE_ACTIONS
                     | OFPIT_APPLY_ACTIONS
                     | OFPIT_CLEAR_ACTIONS
    actions          list of OpenFlow action class
    ================ ======================================================

    ``type`` attribute corresponds to ``type_`` parameter of __init__.
    """
    def __init__(self, type_, actions=None, len_=None):
        super(OFPInstructionActions, self).__init__()
        self.type = type_
        for a in actions:
            assert isinstance(a, OFPAction)
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_INSTRUCTION_ACTIONS_PACK_STR,
            buf, offset)

        offset += ofproto.OFP_INSTRUCTION_ACTIONS_SIZE
        actions = []
        actions_len = len_ - ofproto.OFP_INSTRUCTION_ACTIONS_SIZE
        while actions_len > 0:
            a = OFPAction.parser(buf, offset)
            actions.append(a)
            actions_len -= a.len
            offset += a.len

        inst = cls(type_, actions)
        inst.len = len_
        return inst

    def serialize(self, buf, offset):
        action_offset = offset + ofproto.OFP_INSTRUCTION_ACTIONS_SIZE
        if self.actions:
            for a in self.actions:
                assert isinstance(a, OFPAction)
                a.serialize(buf, action_offset)
                action_offset += a.len

        self.len = action_offset - offset
        pad_len = utils.round_up(self.len, 8) - self.len
        msg_pack_into("%dx" % pad_len, buf, action_offset)
        self.len += pad_len

        msg_pack_into(ofproto.OFP_INSTRUCTION_ACTIONS_PACK_STR,
                      buf, offset, self.type, self.len)


class OFPActionHeader(StringifyMixin):
    def __init__(self, type_, len_):
        self.type = type_
        self.len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_HEADER_PACK_STR,
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
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        cls_ = cls._ACTION_TYPES.get(type_)
        assert cls_ is not None
        return cls_.parser(buf, offset)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_HEADER_PACK_STR, buf,
                      offset, self.type, self.len)


@OFPAction.register_action_type(ofproto.OFPAT_OUTPUT,
                                ofproto.OFP_ACTION_OUTPUT_SIZE)
class OFPActionOutput(OFPAction):
    """
    Output action

    This action indicates output a packet to the switch port.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port             Output port
    max_len          Max length to send to controller
    ================ ======================================================
    """
    def __init__(self, port, max_len=ofproto.OFPCML_MAX,
                 type_=None, len_=None):
        super(OFPActionOutput, self).__init__()
        self.port = port
        self.max_len = max_len

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, port, max_len = struct.unpack_from(
            ofproto.OFP_ACTION_OUTPUT_PACK_STR, buf, offset)
        return cls(port, max_len)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_OUTPUT_PACK_STR, buf,
                      offset, self.type, self.len, self.port, self.max_len)


@OFPAction.register_action_type(ofproto.OFPAT_GROUP,
                                ofproto.OFP_ACTION_GROUP_SIZE)
class OFPActionGroup(OFPAction):
    """
    Group action

    This action indicates the group used to process the packet.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    group_id         Group identifier
    ================ ======================================================
    """
    def __init__(self, group_id=0, type_=None, len_=None):
        super(OFPActionGroup, self).__init__()
        self.group_id = group_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, group_id) = struct.unpack_from(
            ofproto.OFP_ACTION_GROUP_PACK_STR, buf, offset)
        return cls(group_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_GROUP_PACK_STR, buf,
                      offset, self.type, self.len, self.group_id)


@OFPAction.register_action_type(ofproto.OFPAT_SET_QUEUE,
                                ofproto.OFP_ACTION_SET_QUEUE_SIZE)
class OFPActionSetQueue(OFPAction):
    """
    Set queue action

    This action sets the queue id that will be used to map a flow to an
    already-configured queue on a port.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    queue_id         Queue ID for the packets
    ================ ======================================================
    """
    def __init__(self, queue_id, type_=None, len_=None):
        super(OFPActionSetQueue, self).__init__()
        self.queue_id = queue_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, queue_id) = struct.unpack_from(
            ofproto.OFP_ACTION_SET_QUEUE_PACK_STR, buf, offset)
        return cls(queue_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_SET_QUEUE_PACK_STR, buf,
                      offset, self.type, self.len, self.queue_id)


@OFPAction.register_action_type(ofproto.OFPAT_SET_MPLS_TTL,
                                ofproto.OFP_ACTION_MPLS_TTL_SIZE)
class OFPActionSetMplsTtl(OFPAction):
    """
    Set MPLS TTL action

    This action sets the MPLS TTL.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    mpls_ttl         MPLS TTL
    ================ ======================================================
    """
    def __init__(self, mpls_ttl, type_=None, len_=None):
        super(OFPActionSetMplsTtl, self).__init__()
        self.mpls_ttl = mpls_ttl

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, mpls_ttl) = struct.unpack_from(
            ofproto.OFP_ACTION_MPLS_TTL_PACK_STR, buf, offset)
        return cls(mpls_ttl)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_MPLS_TTL_PACK_STR, buf,
                      offset, self.type, self.len, self.mpls_ttl)


@OFPAction.register_action_type(ofproto.OFPAT_DEC_MPLS_TTL,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionDecMplsTtl(OFPAction):
    """
    Decrement MPLS TTL action

    This action decrements the MPLS TTL.
    """
    def __init__(self, type_=None, len_=None):
        super(OFPActionDecMplsTtl, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto.OFPAT_SET_NW_TTL,
                                ofproto.OFP_ACTION_NW_TTL_SIZE)
class OFPActionSetNwTtl(OFPAction):
    """
    Set IP TTL action

    This action sets the IP TTL.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    nw_ttl           IP TTL
    ================ ======================================================
    """
    def __init__(self, nw_ttl, type_=None, len_=None):
        super(OFPActionSetNwTtl, self).__init__()
        self.nw_ttl = nw_ttl

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, nw_ttl) = struct.unpack_from(
            ofproto.OFP_ACTION_NW_TTL_PACK_STR, buf, offset)
        return cls(nw_ttl)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_NW_TTL_PACK_STR, buf, offset,
                      self.type, self.len, self.nw_ttl)


@OFPAction.register_action_type(ofproto.OFPAT_DEC_NW_TTL,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionDecNwTtl(OFPAction):
    """
    Decrement IP TTL action

    This action decrements the IP TTL.
    """
    def __init__(self, type_=None, len_=None):
        super(OFPActionDecNwTtl, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto.OFPAT_COPY_TTL_OUT,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlOut(OFPAction):
    """
    Copy TTL Out action

    This action copies the TTL from the next-to-outermost header with TTL to
    the outermost header with TTL.
    """
    def __init__(self, type_=None, len_=None):
        super(OFPActionCopyTtlOut, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto.OFPAT_COPY_TTL_IN,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlIn(OFPAction):
    """
    Copy TTL In action

    This action copies the TTL from the outermost header with TTL to the
    next-to-outermost header with TTL.
    """
    def __init__(self, type_=None, len_=None):
        super(OFPActionCopyTtlIn, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto.OFPAT_PUSH_VLAN,
                                ofproto.OFP_ACTION_PUSH_SIZE)
class OFPActionPushVlan(OFPAction):
    """
    Push VLAN action

    This action pushes a new VLAN tag to the packet.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    ethertype        Ether type.  The default is 802.1Q. (0x8100)
    ================ ======================================================
    """
    def __init__(self, ethertype=ether.ETH_TYPE_8021Q, type_=None, len_=None):
        super(OFPActionPushVlan, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto.OFP_ACTION_PUSH_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_PUSH_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto.OFPAT_PUSH_MPLS,
                                ofproto.OFP_ACTION_PUSH_SIZE)
class OFPActionPushMpls(OFPAction):
    """
    Push MPLS action

    This action pushes a new MPLS header to the packet.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    ethertype        Ether type
    ================ ======================================================
    """
    def __init__(self, ethertype=ether.ETH_TYPE_MPLS, type_=None, len_=None):
        super(OFPActionPushMpls, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto.OFP_ACTION_PUSH_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_PUSH_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto.OFPAT_POP_VLAN,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionPopVlan(OFPAction):
    """
    Pop VLAN action

    This action pops the outermost VLAN tag from the packet.
    """
    def __init__(self, type_=None, len_=None):
        super(OFPActionPopVlan, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto.OFPAT_POP_MPLS,
                                ofproto.OFP_ACTION_POP_MPLS_SIZE)
class OFPActionPopMpls(OFPAction):
    """
    Pop MPLS action

    This action pops the MPLS header from the packet.
    """
    def __init__(self, ethertype=ether.ETH_TYPE_IP, type_=None, len_=None):
        super(OFPActionPopMpls, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto.OFP_ACTION_POP_MPLS_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_POP_MPLS_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto.OFPAT_SET_FIELD,
                                ofproto.OFP_ACTION_SET_FIELD_SIZE)
class OFPActionSetField(OFPAction):
    """
    Set field action

    This action modifies a header field in the packet.

    The set of keywords available for this is same as OFPMatch.

    Example::

        set_field = OFPActionSetField(eth_src="00:00:00:00:00:00")
    """
    def __init__(self, field=None, **kwargs):
        # old api
        #   OFPActionSetField(field)
        # new api
        #   OFPActionSetField(eth_src="00:00:00:00:00")
        super(OFPActionSetField, self).__init__()
        if isinstance(field, OFPMatchField):
            # old api compat
            assert len(kwargs) == 0
            self.field = field
        else:
            # new api
            assert len(kwargs) == 1
            key = list(kwargs.keys())[0]
            value = kwargs[key]
            assert isinstance(key, (str, six.text_type))
            assert not isinstance(value, tuple)  # no mask
            self.key = key
            self.value = value

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from('!HH', buf, offset)
        (n, value, mask, _len) = ofproto.oxm_parse(buf, offset + 4)
        k, uv = ofproto.oxm_to_user(n, value, mask)
        action = cls(**{k: uv})
        action.len = len_

        # old api compat
        action.field = OFPMatchField.parser(buf, offset + 4)

        return action

    def serialize(self, buf, offset):
        # old api compat
        if self._composed_with_old_api():
            return self.serialize_old(buf, offset)

        n, value, mask = ofproto.oxm_from_user(self.key, self.value)
        len_ = ofproto.oxm_serialize(n, value, mask, buf, offset + 4)
        self.len = utils.round_up(4 + len_, 8)
        msg_pack_into('!HH', buf, offset, self.type, self.len)
        pad_len = self.len - (4 + len_)
        msg_pack_into("%dx" % pad_len, buf, offset + 4 + len_)

    # XXX old api compat
    def serialize_old(self, buf, offset):
        len_ = ofproto.OFP_ACTION_SET_FIELD_SIZE + self.field.oxm_len()
        self.len = utils.round_up(len_, 8)
        pad_len = self.len - len_

        msg_pack_into('!HH', buf, offset, self.type, self.len)
        self.field.serialize(buf, offset + 4)
        offset += len_
        msg_pack_into("%dx" % pad_len, buf, offset)

    # XXX old api compat
    def _composed_with_old_api(self):
        return not hasattr(self, 'value')

    def to_jsondict(self):
        return {
            self.__class__.__name__: {
                'field': ofproto.oxm_to_jsondict(self.key, self.value),
                "len": self.len,
                "type": self.type
            }
        }

    @classmethod
    def from_jsondict(cls, dict_):
        k, v = ofproto.oxm_from_jsondict(dict_['field'])
        o = OFPActionSetField(**{k: v})

        # XXX old api compat
        # serialize and parse to fill old attributes
        buf = bytearray()
        o.serialize(buf, 0)
        return OFPActionSetField.parser(six.binary_type(buf), 0)

    # XXX old api compat
    def __str__(self):
        # XXX old api compat
        if self._composed_with_old_api():
            # copy object first because serialize_old is destructive
            o2 = OFPActionSetField(self.field)
            # serialize and parse to fill new fields
            buf = bytearray()
            o2.serialize(buf, 0)
            o = OFPActionSetField.parser(six.binary_type(buf), 0)
        else:
            o = self
        return super(OFPActionSetField, o).__str__()

    __repr__ = __str__

    def stringify_attrs(self):
        yield (self.key, self.value)


@OFPAction.register_action_type(
    ofproto.OFPAT_EXPERIMENTER,
    ofproto.OFP_ACTION_EXPERIMENTER_HEADER_SIZE)
class OFPActionExperimenter(OFPAction):
    """
    Experimenter action

    This action is an extensible action for the experimenter.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    experimenter     Experimenter ID
    ================ ======================================================

    .. Note::

        For the list of the supported Nicira experimenter actions,
        please refer to :ref:`ryu.ofproto.nx_actions <nx_actions_structures>`.
    """
    def __init__(self, experimenter, type_=None, len_=None):
        super(OFPActionExperimenter, self).__init__()
        self.experimenter = experimenter

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, experimenter) = struct.unpack_from(
            ofproto.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR, buf, offset)
        ex = cls(experimenter)
        ex.len = len_
        return ex

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR,
                      buf, offset, self.type, self.len, self.experimenter)


class OFPBucket(StringifyMixin):
    def __init__(self, weight=0, watch_port=ofproto.OFPP_ANY,
                 watch_group=ofproto.OFPG_ANY, actions=None, len_=None):
        super(OFPBucket, self).__init__()
        self.weight = weight
        self.watch_port = watch_port
        self.watch_group = watch_group
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        (len_, weigth, watch_port, watch_group) = struct.unpack_from(
            ofproto.OFP_BUCKET_PACK_STR, buf, offset)

        length = ofproto.OFP_BUCKET_SIZE
        offset += ofproto.OFP_BUCKET_SIZE
        actions = []
        while length < len_:
            action = OFPAction.parser(buf, offset)
            actions.append(action)
            offset += action.len
            length += action.len

        m = cls(weigth, watch_port, watch_group, actions)
        m.len = len_
        return m

    def serialize(self, buf, offset):
        action_offset = offset + ofproto.OFP_BUCKET_SIZE
        action_len = 0
        for a in self.actions:
            a.serialize(buf, action_offset)
            action_offset += a.len
            action_len += a.len

        self.len = utils.round_up(ofproto.OFP_BUCKET_SIZE + action_len, 8)
        msg_pack_into(ofproto.OFP_BUCKET_PACK_STR, buf, offset,
                      self.len, self.weight, self.watch_port,
                      self.watch_group)


@_set_msg_type(ofproto.OFPT_GROUP_MOD)
class OFPGroupMod(MsgBase):
    """
    Modify group entry message

    The controller sends this message to modify the group table.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    command          One of the following values.

                     | OFPGC_ADD
                     | OFPGC_MODIFY
                     | OFPGC_DELETE
    type             One of the following values.

                     | OFPGT_ALL
                     | OFPGT_SELECT
                     | OFPGT_INDIRECT
                     | OFPGT_FF
    group_id         Group identifier
    buckets          list of ``OFPBucket``
    ================ ======================================================

    ``type`` attribute corresponds to ``type_`` parameter of __init__.

    Example::

        def send_group_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            port = 1
            max_len = 2000
            actions = [ofp_parser.OFPActionOutput(port, max_len)]

            weight = 100
            watch_port = 0
            watch_group = 0
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,
                                            actions)]

            group_id = 1
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                         ofp.OFPGT_SELECT, group_id, buckets)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, command=ofproto.OFPGC_ADD,
                 type_=ofproto.OFPGT_ALL, group_id=0, buckets=None):
        buckets = buckets if buckets else []
        super(OFPGroupMod, self).__init__(datapath)
        self.command = command
        self.type = type_
        self.group_id = group_id
        self.buckets = buckets

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_GROUP_MOD_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE,
                      self.command, self.type, self.group_id)

        offset = ofproto.OFP_GROUP_MOD_SIZE
        for b in self.buckets:
            b.serialize(self.buf, offset)
            offset += b.len


@_set_msg_type(ofproto.OFPT_PORT_MOD)
class OFPPortMod(MsgBase):
    """
    Port modification message

    The controller sneds this message to modify the behavior of the port.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port_no          Port number to modify
    hw_addr          The hardware address that must be the same as hw_addr
                     of ``OFPPort`` of ``OFPSwitchFeatures``
    config           Bitmap of configuration flags.

                     | OFPPC_PORT_DOWN
                     | OFPPC_NO_RECV
                     | OFPPC_NO_FWD
                     | OFPPC_NO_PACKET_IN
    mask             Bitmap of configuration flags above to be changed
    advertise        Bitmap of the following flags.

                     | OFPPF_10MB_HD
                     | OFPPF_10MB_FD
                     | OFPPF_100MB_HD
                     | OFPPF_100MB_FD
                     | OFPPF_1GB_HD
                     | OFPPF_1GB_FD
                     | OFPPF_10GB_FD
                     | OFPPF_40GB_FD
                     | OFPPF_100GB_FD
                     | OFPPF_1TB_FD
                     | OFPPF_OTHER
                     | OFPPF_COPPER
                     | OFPPF_FIBER
                     | OFPPF_AUTONEG
                     | OFPPF_PAUSE
                     | OFPPF_PAUSE_ASYM
    ================ ======================================================

    Example::

        def send_port_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            port_no = 3
            hw_addr = 'fa:c8:e8:76:1d:7e'
            config = 0
            mask = (ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV |
                    ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN)
            advertise = (ofp.OFPPF_10MB_HD | ofp.OFPPF_100MB_FD |
                         ofp.OFPPF_1GB_FD | ofp.OFPPF_COPPER |
                         ofp.OFPPF_AUTONEG | ofp.OFPPF_PAUSE |
                         ofp.OFPPF_PAUSE_ASYM)
            req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config,
                                        mask, advertise)
            datapath.send_msg(req)
    """

    _TYPE = {
        'ascii': [
            'hw_addr',
        ]
    }

    def __init__(self, datapath, port_no=0, hw_addr='00:00:00:00:00:00',
                 config=0, mask=0, advertise=0):
        super(OFPPortMod, self).__init__(datapath)
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.config = config
        self.mask = mask
        self.advertise = advertise

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_PORT_MOD_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE,
                      self.port_no, addrconv.mac.text_to_bin(self.hw_addr),
                      self.config,
                      self.mask, self.advertise)


@_set_msg_type(ofproto.OFPT_TABLE_MOD)
class OFPTableMod(MsgBase):
    """
    Flow table configuration message

    The controller sends this message to configure table state.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         ID of the table (OFPTT_ALL indicates all tables)
    config           Bitmap of the following flags.

                     | OFPTC_TABLE_MISS_CONTROLLER
                     | OFPTC_TABLE_MISS_CONTINUE
                     | OFPTC_TABLE_MISS_DROP
                     | OFPTC_TABLE_MISS_MASK
    ================ ======================================================

    Example::

        def send_table_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPTableMod(datapath, ofp.OFPTT_ALL,
                                         ofp.OFPTC_TABLE_MISS_DROP)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, table_id, config):
        super(OFPTableMod, self).__init__(datapath)
        self.table_id = table_id
        self.config = config

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_TABLE_MOD_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE,
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
        msg_pack_into(ofproto.OFP_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.type, self.flags)

        self._serialize_stats_body()


@_register_parser
@_set_msg_type(ofproto.OFPT_STATS_REPLY)
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

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPStatsReply, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        msg.type, msg.flags = struct.unpack_from(
            ofproto.OFP_STATS_REPLY_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
        stats_type_cls = cls._STATS_TYPES.get(msg.type)

        offset = ofproto.OFP_STATS_REPLY_SIZE
        body = []
        while offset < msg_len:
            r = stats_type_cls.parser(msg.buf, offset)
            body.append(r)
            offset += r.length

        if stats_type_cls.cls_body_single_struct:
            msg.body = body[0]
        else:
            msg.body = body

        return msg


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPDescStatsRequest(OFPStatsRequest):
    """
    Description statistics request message

    The controller uses this message to query description of the switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPDescStatsRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0):
        super(OFPDescStatsRequest, self).__init__(datapath,
                                                  ofproto.OFPST_DESC,
                                                  flags)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_DESC,
                                         body_single_struct=True)
class OFPDescStats(ofproto_parser.namedtuple('OFPDescStats', (
        'mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc'))):
    """
    Description statistics reply message

    The switch responds with a stats reply that include this message to
    a description statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    mfr_desc         Manufacturer description
    hw_desc          Hardware description
    sw_desc          Software description
    serial_num       Serial number
    dp_desc          Human readable description of datapath
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_DESC:
                self.desc_stats_reply_handler(body)

        def desc_stats_reply_handler(self, body):
            self.logger.debug('DescStats: mfr_desc=%s hw_desc=%s sw_desc=%s '
                              'serial_num=%s dp_desc=%s',
                              body.mfr_desc, body.hw_desc, body.sw_desc,
                              body.serial_num, body.dp_desc)
    """

    _TYPE = {
        'ascii': [
            'mfr_desc',
            'hw_desc',
            'sw_desc',
            'serial_num',
            'dp_desc',
        ]
    }

    @classmethod
    def parser(cls, buf, offset):
        desc = struct.unpack_from(ofproto.OFP_DESC_STATS_PACK_STR,
                                  buf, offset)
        desc = list(desc)
        desc = [x.rstrip(b'\0') for x in desc]
        stats = cls(*desc)
        stats.length = ofproto.OFP_DESC_STATS_SIZE
        return stats


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPFlowStatsRequest(OFPStatsRequest):
    """
    Individual flow statistics request message

    The controller uses this message to query individual flow statistics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         ID of table to read
    out_port         Require matching entries to include this as an output
                     port
    out_group        Require matching entries to include this as an output
                     group
    cookie           Require matching entries to contain this cookie value
    cookie_mask      Mask used to restrict the cookie bits that must match
    match            Instance of ``OFPMatch``
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_flow_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            cookie = cookie_mask = 0
            match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPFlowStatsRequest(datapath,
                                                 ofp.OFPTT_ALL,
                                                 ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                 cookie, cookie_mask, match)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, table_id=ofproto.OFPTT_ALL,
                 out_port=ofproto.OFPP_ANY,
                 out_group=ofproto.OFPG_ANY,
                 cookie=0, cookie_mask=0, match=None, flags=0):
        super(OFPFlowStatsRequest, self).__init__(datapath,
                                                  ofproto.OFPST_FLOW,
                                                  flags)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        self.cookie = cookie
        self.cookie_mask = cookie_mask
        if match is None:
            match = OFPMatch()
        self.match = match

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_FLOW_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_STATS_REQUEST_SIZE,
                      self.table_id, self.out_port, self.out_group,
                      self.cookie, self.cookie_mask)

        offset = (ofproto.OFP_STATS_REQUEST_SIZE +
                  ofproto.OFP_FLOW_STATS_REQUEST_SIZE -
                  ofproto.OFP_MATCH_SIZE)

        self.match.serialize(self.buf, offset)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_FLOW)
class OFPFlowStats(StringifyMixin):
    """
    Individual flow statistics reply message

    The switch responds with a stats reply that include this message to
    an individual flow statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         ID of table flow came from
    duration_sec     Time flow has been alive in seconds
    duration_nsec    Time flow has been alive in nanoseconds beyond
                     duration_sec
    priority         Priority of the entry
    idle_timeout     Number of seconds idle before expiration
    hard_timeout     Number of seconds before expiration
    cookie           Opaque controller-issued identifier
    packet_count     Number of packets in flow
    byte_count       Number of bytes in flow
    match            Instance of ``OFPMatch``
    instructions     list of ``OFPInstruction*`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_FLOW:
                 self.flow_stats_reply_handler(body)

        def flow_stats_reply_handler(self, body):
            flows = []
            for stat in body:
                flows.append('table_id=%s '
                             'duration_sec=%d duration_nsec=%d '
                             'priority=%d '
                             'idle_timeout=%d hard_timeout=%d '
                             'cookie=%d packet_count=%d byte_count=%d '
                             'match=%s instructions=%s' %
                             (stat.table_id,
                              stat.duration_sec, stat.duration_nsec,
                              stat.priority,
                              stat.idle_timeout, stat.hard_timeout,
                              stat.cookie, stat.packet_count, stat.byte_count,
                              stat.match, stat.instructions))
            self.logger.debug('FlowStats: %s', flows)
    """
    def __init__(self, table_id, duration_sec, duration_nsec,
                 priority, idle_timeout, hard_timeout, cookie, packet_count,
                 byte_count, match, instructions=None, length=None):
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
        self.length = length

    @classmethod
    def parser(cls, buf, offset):
        (length, table_id, duration_sec,
         duration_nsec, priority,
         idle_timeout, hard_timeout,
         cookie, packet_count, byte_count) = struct.unpack_from(
            ofproto.OFP_FLOW_STATS_PACK_STR,
            buf, offset)
        offset += (ofproto.OFP_FLOW_STATS_SIZE -
                   ofproto.OFP_MATCH_SIZE)
        match = OFPMatch.parser(buf, offset)

        match_length = utils.round_up(match.length, 8)
        inst_length = (length - (ofproto.OFP_FLOW_STATS_SIZE -
                                 ofproto.OFP_MATCH_SIZE + match_length))
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
        o.length = length
        return o


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPAggregateStatsRequest(OFPStatsRequest):
    """
    Aggregate flow statistics request message

    The controller uses this message to query aggregate flow statictics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         ID of table to read
    out_port         Require matching entries to include this as an output
                     port
    out_group        Require matching entries to include this as an output
                     group
    cookie           Require matching entries to contain this cookie value
    cookie_mask      Mask used to restrict the cookie bits that must match
    match            Instance of ``OFPMatch``
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_aggregate_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            cookie = cookie_mask = 0
            match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPAggregateStatsRequest(datapath, 0,
                                                      ofp.OFPTT_ALL,
                                                      ofp.OFPP_ANY,
                                                      ofp.OFPG_ANY,
                                                      cookie, cookie_mask,
                                                      match)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, table_id=ofproto.OFPTT_ALL,
                 out_port=ofproto.OFPP_ANY,
                 out_group=ofproto.OFPP_ANY,
                 cookie=0, cookie_mask=0, match=None, flags=0):
        super(OFPAggregateStatsRequest, self).__init__(
            datapath,
            ofproto.OFPST_AGGREGATE,
            flags)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        self.cookie = cookie
        self.cookie_mask = cookie_mask
        if match is None:
            match = OFPMatch()
        self.match = match

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_AGGREGATE_STATS_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_STATS_REQUEST_SIZE,
                      self.table_id, self.out_port, self.out_group,
                      self.cookie, self.cookie_mask)

        offset = (ofproto.OFP_STATS_REQUEST_SIZE +
                  ofproto.OFP_AGGREGATE_STATS_REQUEST_SIZE -
                  ofproto.OFP_MATCH_SIZE)

        self.match.serialize(self.buf, offset)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_AGGREGATE,
                                         body_single_struct=True)
class OFPAggregateStatsReply(ofproto_parser.namedtuple('OFPAggregateStats', (
        'packet_count', 'byte_count', 'flow_count'))):
    """
    Aggregate flow statistics reply message

    The switch responds with a stats reply that include this message to
    an aggregate flow statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    packet_count     Number of packets in flows
    byte_count       Number of bytes in flows
    flow_count       Number of flows
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_AGGREGATE:
                self.aggregate_stats_reply_handler(body)

        def aggregate_stats_reply_handler(self, body):
            self.logger.debug('AggregateStats: packet_count=%d byte_count=%d '
                              'flow_count=%d',
                              body.packet_count, body.byte_count,
                              body.flow_count)
    """

    @classmethod
    def parser(cls, buf, offset):
        desc = struct.unpack_from(
            ofproto.OFP_AGGREGATE_STATS_REPLY_PACK_STR,
            buf, offset)
        stats = cls(*desc)
        stats.length = ofproto.OFP_AGGREGATE_STATS_REPLY_SIZE
        return stats


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPTableStatsRequest(OFPStatsRequest):
    """
    Table statistics request message

    The controller uses this message to query flow table statictics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_table_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPTableStatsRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0):
        super(OFPTableStatsRequest, self).__init__(datapath,
                                                   ofproto.OFPST_TABLE,
                                                   flags)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_TABLE)
class OFPTableStats(
    ofproto_parser.namedtuple('OFPTableStats',
                              ('table_id', 'name', 'match', 'wildcards',
                               'write_actions', 'apply_actions',
                               'write_setfields', 'apply_setfields',
                               'metadata_match', 'metadata_write',
                               'instructions', 'config',
                               'max_entries', 'active_count',
                               'lookup_count', 'matched_count'))):
    """
    Table statistics reply message

    The switch responds with a stats reply that include this message to
    a table statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         ID of table
    name             table name
    match            Bitmap of (1 << OFPXMT_*) that indicate the fields
                     the table can match on
    wildcards        Bitmap of (1 << OFPXMT_*) wildcards that are supported
                     by the table
    write_actions    Bitmap of OFPAT_* that are supported by the table with
                     OFPIT_WRITE_ACTIONS
    apply_actions    Bitmap of OFPAT_* that are supported by the table with
                     OFPIT_APPLY_ACTIONS
    write_setfields  Bitmap of (1 << OFPXMT_*) header fields that can be set
                     with OFPIT_WRITE_ACTIONS
    apply_setfields  Bitmap of (1 << OFPXMT_*) header fields that can be set
                     with OFPIT_APPLY_ACTIONS
    metadata_match   Bits of metadata table can match
    metadata_write   Bits of metadata table can write
    instructions     Bitmap of OFPIT_* values supported
    config           Bitmap of OFPTC_* values
    max_entries      Max number of entries supported
    active_count     Number of active entries
    lookup_count     Number of packets looked up in table
    matched_count    Number of packets that hit table
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_TABLE:
                self.table_stats_reply_handler(body)

        def table_stats_reply_handler(self, body):
            tables = []
            for stat in body:
                tables.append('table_id=%d active_count=%d lookup_count=%d '
                              ' matched_count=%d' %
                              (stat.table_id, stat.active_count,
                               stat.lookup_count, stat.matched_count))
            self.logger.debug('TableStats: %s', tables)
    """

    _TYPE = {
        'utf-8': [
            # OF spec is unclear about the encoding of name.
            # we assumes UTF-8.
            'name',
        ]
    }

    @classmethod
    def parser(cls, buf, offset):
        table = struct.unpack_from(
            ofproto.OFP_TABLE_STATS_PACK_STR,
            buf, offset)
        table = list(table)
        i = cls._fields.index('name')
        table[i] = table[i].rstrip(b'\0')
        stats = cls(*table)
        stats.length = ofproto.OFP_TABLE_STATS_SIZE
        return stats


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPPortStatsRequest(OFPStatsRequest):
    """
    Port statistics request message

    The controller uses this message to query information about ports
    statistics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port_no          Port number to read (OFPP_ANY to all ports)
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_port_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPPortStatsRequest(datapath, ofp.OFPP_ANY)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, port_no=ofproto.OFPP_ANY, flags=0):
        super(OFPPortStatsRequest, self).__init__(datapath,
                                                  ofproto.OFPST_PORT,
                                                  flags)
        self.port_no = port_no

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_PORT_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_STATS_REQUEST_SIZE,
                      self.port_no)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_PORT)
class OFPPortStats(
    ofproto_parser.namedtuple('OFPPortStats',
                              ('port_no', 'rx_packets', 'tx_packets',
                               'rx_bytes', 'tx_bytes',
                               'rx_dropped', 'tx_dropped',
                               'rx_errors', 'tx_errors',
                               'rx_frame_err', 'rx_over_err',
                               'rx_crc_err', 'collisions'))):
    """
    Port statistics reply message

    The switch responds with a stats reply that include this message to
    a port statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port_no          Port number
    rx_packets       Number of received packets
    tx_packets       Number of transmitted packets
    rx_bytes         Number of received bytes
    tx_bytes         Number of transmitted bytes
    rx_dropped       Number of packets dropped by RX
    tx_dropped       Number of packets dropped by TX
    rx_errors        Number of receive errors
    tx_errors        Number of transmit errors
    rx_frame_err     Number of frame alignment errors
    rx_over_err      Number of packet with RX overrun
    rx_crc_err       Number of CRC errors
    collisions       Number of collisions
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_PORT:
                self.port_stats_reply_handler(body)

        def port_stats_reply_handler(self, body):
            ports = []
            for stat in body:
                ports.append('port_no=%d '
                             'rx_packets=%d tx_packets=%d '
                             'rx_bytes=%d tx_bytes=%d '
                             'rx_dropped=%d tx_dropped=%d '
                             'rx_errors=%d tx_errors=%d '
                             'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                             'collisions=%d' %
                             (stat.port_no,
                              stat.rx_packets, stat.tx_packets,
                              stat.rx_bytes, stat.tx_bytes,
                              stat.rx_dropped, stat.tx_dropped,
                              stat.rx_errors, stat.tx_errors,
                              stat.rx_frame_err, stat.rx_over_err,
                              stat.rx_crc_err, stat.collisions))
            self.logger.debug('PortStats: %s', ports)
    """
    @classmethod
    def parser(cls, buf, offset):
        port = struct.unpack_from(ofproto.OFP_PORT_STATS_PACK_STR,
                                  buf, offset)
        stats = cls(*port)
        stats.length = ofproto.OFP_PORT_STATS_SIZE
        return stats


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPQueueStatsRequest(OFPStatsRequest):
    """
    Queue statistics request message

    The controller uses this message to query queue statictics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port_no          Port number to read
    queue_id         ID of queue to read
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_queue_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPQueueStatsRequest(datapath, ofp.OFPP_ANY,
                                                  ofp.OFPQ_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, port_no=ofproto.OFPP_ANY,
                 queue_id=ofproto.OFPQ_ALL, flags=0):
        super(OFPQueueStatsRequest, self).__init__(datapath,
                                                   ofproto.OFPST_QUEUE,
                                                   flags)
        self.port_no = port_no
        self.queue_id = queue_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_QUEUE_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_STATS_REQUEST_SIZE,
                      self.port_no, self.queue_id)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_QUEUE)
class OFPQueueStats(
    ofproto_parser.namedtuple('OFPQueueStats',
                              ('port_no', 'queue_id', 'tx_bytes',
                               'tx_packets', 'tx_errors'))):
    """
    Queue statistics reply message

    The switch responds with a stats reply that include this message to
    an aggregate flow statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port_no          Port number
    queue_id         ID of queue
    tx_bytes         Number of transmitted bytes
    tx_packets       Number of transmitted packets
    tx_errors        Number of packets dropped due to overrun
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_QUEUE:
                self.queue_stats_reply_handler(body)

        def queue_stats_reply_handler(self, body):
            queues = []
            for stat in body:
                queues.append('port_no=%d queue_id=%d '
                              'tx_bytes=%d tx_packets=%d tx_errors=%d ' %
                              (stat.port_no, stat.queue_id,
                               stat.tx_bytes, stat.tx_packets, stat.tx_errors))
            self.logger.debug('QueueStats: %s', queues)
    """
    @classmethod
    def parser(cls, buf, offset):
        queue = struct.unpack_from(ofproto.OFP_QUEUE_STATS_PACK_STR,
                                   buf, offset)
        stats = cls(*queue)
        stats.length = ofproto.OFP_QUEUE_STATS_SIZE
        return stats


class OFPBucketCounter(StringifyMixin):
    def __init__(self, packet_count, byte_count):
        super(OFPBucketCounter, self).__init__()
        self.packet_count = packet_count
        self.byte_count = byte_count

    @classmethod
    def parser(cls, buf, offset):
        packet, byte = struct.unpack_from(
            ofproto.OFP_BUCKET_COUNTER_PACK_STR,
            buf, offset)
        return cls(packet, byte)


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPGroupStatsRequest(OFPStatsRequest):
    """
    Group statistics request message

    The controller uses this message to query statistics of one or more
    groups.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    group_id         ID of group to read (OFPG_ALL to all groups)
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_group_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGroupStatsRequest(datapath, ofp.OFPG_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, group_id=ofproto.OFPG_ALL, flags=0):
        super(OFPGroupStatsRequest, self).__init__(datapath,
                                                   ofproto.OFPST_GROUP,
                                                   flags)
        self.group_id = group_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_GROUP_STATS_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_STATS_REQUEST_SIZE,
                      self.group_id)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_GROUP)
class OFPGroupStats(StringifyMixin):
    """
    Group statistics reply message

    The switch responds with a stats reply that include this message to
    a group statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    group_id         Group identifier
    ref_count        Number of flows or groups that directly forward to
                     this group
    packet_count     Number of packets processed by group
    byte_count       Number of bytes processed by group
    bucket_counters  List of ``OFPBucketCounter`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_GROUP:
                self.group_stats_reply_handler(body)

        def group_stats_reply_handler(self, body):
            groups = []
            for stat in body:
                groups.append('group_id=%d ref_count=%d packet_count=%d '
                              'byte_count=%d bucket_counters=%s' %
                              (stat.group_id,
                               stat.ref_count, stat.packet_count,
                               stat.byte_count, stat.bucket_counters))
            self.logger.debug('GroupStats: %s', groups)
    """

    def __init__(self, group_id, ref_count, packet_count,
                 byte_count, bucket_counters, length=None):
        super(OFPGroupStats, self).__init__()
        self.group_id = group_id
        self.ref_count = ref_count
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.bucket_counters = bucket_counters
        self.length = length

    @classmethod
    def parser(cls, buf, offset):
        (length, group_id, ref_count, packet_count,
         byte_count) = struct.unpack_from(
            ofproto.OFP_GROUP_STATS_PACK_STR,
            buf, offset)

        bucket_len = length - ofproto.OFP_GROUP_STATS_SIZE
        offset += ofproto.OFP_GROUP_STATS_SIZE
        bucket_counters = []
        while bucket_len > 0:
            bucket_counters.append(OFPBucketCounter.parser(buf, offset))
            offset += ofproto.OFP_BUCKET_COUNTER_SIZE
            bucket_len -= ofproto.OFP_BUCKET_COUNTER_SIZE

        o = cls(group_id, ref_count, packet_count,
                byte_count, bucket_counters)
        o.length = length
        return o


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPGroupDescStatsRequest(OFPStatsRequest):
    """
    Group description request message

    The controller uses this message to list the set of groups on a switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_group_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGroupDescStatsRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0):
        super(OFPGroupDescStatsRequest, self).__init__(
            datapath,
            ofproto.OFPST_GROUP_DESC,
            flags)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_GROUP_DESC)
class OFPGroupDescStats(StringifyMixin):
    """
    Group description reply message

    The switch responds with a stats reply that include this message to
    a group description request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    type             One of OFPGT_*
    group_id         Group identifier
    buckets          List of ``OFPBucket`` instance
    ================ ======================================================

    ``type`` attribute corresponds to ``type_`` parameter of __init__.

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_GROUP_DESC:
                self.group_desc_stats_reply_handler(body)

        def group_desc_stats_reply_handler(self, body):
            descs = []
            for stat in body:
                descs.append('type=%d group_id=%d buckets=%s' %
                             (stat.type, stat.group_id, stat.buckets))
            self.logger.debug('GroupDescStats: %s', descs)
    """
    def __init__(self, type_, group_id, buckets, length=None):
        self.type = type_
        self.group_id = group_id
        self.buckets = buckets

    @classmethod
    def parser(cls, buf, offset):
        (length, type_, group_id) = struct.unpack_from(
            ofproto.OFP_GROUP_DESC_STATS_PACK_STR,
            buf, offset)

        bucket_len = length - ofproto.OFP_GROUP_DESC_STATS_SIZE
        offset += ofproto.OFP_GROUP_DESC_STATS_SIZE
        buckets = []
        while bucket_len > 0:
            bucket = OFPBucket.parser(buf, offset)
            buckets.append(bucket)
            offset += bucket.len
            bucket_len -= bucket.len

        o = cls(type_, group_id, buckets)
        o.length = length
        return o


@_set_msg_type(ofproto.OFPT_STATS_REQUEST)
class OFPGroupFeaturesStatsRequest(OFPStatsRequest):
    """
    Group features request message

    The controller uses this message to list the capabilities of groups on
    a switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero (none yet defined in the spec)
    ================ ======================================================

    Example::

        def send_group_features_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGroupFeaturesStatsRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0):
        super(OFPGroupFeaturesStatsRequest, self).__init__(
            datapath,
            ofproto.OFPST_GROUP_FEATURES,
            flags)


@OFPStatsReply.register_stats_reply_type(ofproto.OFPST_GROUP_FEATURES,
                                         body_single_struct=True)
class OFPGroupFeaturesStats(StringifyMixin):
    """
    Group features reply message

    The switch responds with a stats reply that include this message to
    a group features request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    types            Bitmap of OFPGT_* values supported
    capabilities     Bitmap of OFPGFC_* capability supported
    max_groups       Maximum number of groups for each type
    actions          Bitmaps of OFPAT_* that are supported
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
        def stats_reply_handler(self, ev):
            msg = ev.msg
            ofp = msg.datapath.ofproto
            body = ev.msg.body

            if msg.type == ofp.OFPST_GROUP_FEATURES:
                self.group_features_stats_reply_handler(body)

        def group_features_stats_reply_handler(self, body):
            self.logger.debug('GroupFeaturesStats: types=%d '
                              'capabilities=0x%08x max_groups=%s '
                              'actions=%s',
                              body.types, body.capabilities, body.max_groups,
                              body.actions)
    """
    def __init__(self, types, capabilities, max_groups, actions, length=None):
        self.types = types
        self.capabilities = capabilities
        self.max_groups = max_groups
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        stats = struct.unpack_from(
            ofproto.OFP_GROUP_FEATURES_STATS_PACK_STR, buf, offset)
        types = stats[0]
        capabilities = stats[1]
        max_groups = list(stats[2:6])
        actions = list(stats[6:10])

        o = cls(types, capabilities, max_groups, actions)
        o.length = ofproto.OFP_GROUP_FEATURES_STATS_SIZE
        return o


@_set_msg_type(ofproto.OFPT_QUEUE_GET_CONFIG_REQUEST)
class OFPQueueGetConfigRequest(MsgBase):
    """
    Queue configuration request message

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port             Port to be queried (OFPP_ANY to all configured queues)
    ================ ======================================================

    Example::

        def send_queue_get_config_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPQueueGetConfigRequest(datapath, ofp.OFPP_ANY)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, port):
        super(OFPQueueGetConfigRequest, self).__init__(datapath)
        self.port = port

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE, self.port)


class OFPQueuePropHeader(StringifyMixin):
    def __init__(self, property_, len_=None):
        self.property = property_
        self.len = len_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_QUEUE_PROP_HEADER_PACK_STR,
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
            ofproto.OFP_QUEUE_PROP_HEADER_PACK_STR,
            buf, offset)
        cls_ = cls._QUEUE_PROP_PROPERTIES.get(property_)
        offset += ofproto.OFP_QUEUE_PROP_HEADER_SIZE
        return cls_.parser(buf, offset)


class OFPPacketQueue(StringifyMixin):
    def __init__(self, queue_id, port, properties, len_=None):
        super(OFPPacketQueue, self).__init__()
        self.queue_id = queue_id
        self.port = port
        self.len = len_
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (queue_id, port, len_) = struct.unpack_from(
            ofproto.OFP_PACKET_QUEUE_PACK_STR, buf, offset)
        length = ofproto.OFP_PACKET_QUEUE_SIZE
        offset += ofproto.OFP_PACKET_QUEUE_SIZE
        properties = []
        while length < len_:
            queue_prop = OFPQueueProp.parser(buf, offset)
            properties.append(queue_prop)
            offset += queue_prop.len
            length += queue_prop.len
        o = cls(queue_id, port, properties)
        o.len = len_
        return o


@OFPQueueProp.register_property(ofproto.OFPQT_MIN_RATE,
                                ofproto.OFP_QUEUE_PROP_MIN_RATE_SIZE)
class OFPQueuePropMinRate(OFPQueueProp):
    def __init__(self, rate, property_=None, len_=None):
        super(OFPQueuePropMinRate, self).__init__()
        self.rate = rate

    @classmethod
    def parser(cls, buf, offset):
        (rate,) = struct.unpack_from(
            ofproto.OFP_QUEUE_PROP_MIN_RATE_PACK_STR, buf, offset)
        return cls(rate)


@OFPQueueProp.register_property(ofproto.OFPQT_MAX_RATE,
                                ofproto.OFP_QUEUE_PROP_MAX_RATE_SIZE)
class OFPQueuePropMaxRate(OFPQueueProp):
    def __init__(self, rate, property_=None, len_=None):
        super(OFPQueuePropMaxRate, self).__init__()
        self.rate = rate

    @classmethod
    def parser(cls, buf, offset):
        (rate,) = struct.unpack_from(
            ofproto.OFP_QUEUE_PROP_MAX_RATE_PACK_STR, buf, offset)
        return cls(rate)


@_register_parser
@_set_msg_type(ofproto.OFPT_QUEUE_GET_CONFIG_REPLY)
class OFPQueueGetConfigReply(MsgBase):
    """
    Queue configuration reply message

    The switch responds with this message to a queue configuration request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    port             Port which was queried
    queues           list of ``OFPPacketQueue`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPQueueGetConfigReply, MAIN_DISPATCHER)
        def queue_get_config_reply_handler(self, ev):
            msg = ev.msg

            self.logger.debug('OFPQueueGetConfigReply received: '
                              'port=%s queues=%s',
                              msg.port, msg.queues)
    """
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
            ofproto.OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)

        msg.queues = []
        length = ofproto.OFP_QUEUE_GET_CONFIG_REPLY_SIZE
        offset = ofproto.OFP_QUEUE_GET_CONFIG_REPLY_SIZE
        while length < msg.msg_len:
            queue = OFPPacketQueue.parser(msg.buf, offset)
            msg.queues.append(queue)

            offset += queue.len
            length += queue.len

        return msg


@_set_msg_type(ofproto.OFPT_BARRIER_REQUEST)
class OFPBarrierRequest(MsgBase):
    """
    Barrier request message

    The controller sends this message to ensure message dependencies have
    been met or receive notifications for completed operations.

    Example::

        def send_barrier_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPBarrierRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath):
        super(OFPBarrierRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto.OFPT_BARRIER_REPLY)
class OFPBarrierReply(MsgBase):
    """
    Barrier reply message

    The switch responds with this message to a barrier request.

    Example::

        @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
        def barrier_reply_handler(self, ev):
            self.logger.debug('OFPBarrierReply received')
    """
    def __init__(self, datapath):
        super(OFPBarrierReply, self).__init__(datapath)


@_set_msg_type(ofproto.OFPT_ROLE_REQUEST)
class OFPRoleRequest(MsgBase):
    """
    Role request message

    The controller uses this message to change its role.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    role             One of the following values.

                     | OFPCR_ROLE_NOCHANGE
                     | OFPCR_ROLE_EQUAL
                     | OFPCR_ROLE_MASTER
                     | OFPCR_ROLE_SLAVE
    generation_id    Master Election Generation ID
    ================ ======================================================

    Example::

        def send_role_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPRoleRequest(datapath, ofp.OFPCR_ROLE_EQUAL, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, role, generation_id):
        super(OFPRoleRequest, self).__init__(datapath)
        self.role = role
        self.generation_id = generation_id

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_ROLE_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.role, self.generation_id)


@_register_parser
@_set_msg_type(ofproto.OFPT_ROLE_REPLY)
class OFPRoleReply(MsgBase):
    """
    Role reply message

    The switch responds with this message to a role request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    role             One of the following values.

                     | OFPCR_ROLE_NOCHANGE
                     | OFPCR_ROLE_EQUAL
                     | OFPCR_ROLE_MASTER
                     | OFPCR_ROLE_SLAVE
    generation_id    Master Election Generation ID
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
        def role_reply_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.role == ofp.OFPCR_ROLE_NOCHANGE:
                role = 'NOCHANGE'
            elif msg.role == ofp.OFPCR_ROLE_EQUAL:
                role = 'EQUAL'
            elif msg.role == ofp.OFPCR_ROLE_MASTER:
                role = 'MASTER'
            elif msg.role == ofp.OFPCR_ROLE_SLAVE:
                role = 'SLAVE'
            else:
                role = 'unknown'

            self.logger.debug('OFPRoleReply received: '
                              'role=%s generation_id=%d',
                              role, msg.generation_id)
    """
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
            ofproto.OFP_ROLE_REQUEST_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)

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
    """
    Flow Match Structure

    This class is implementation of the flow match structure having
    compose/query API.
    There are new API and old API for compatibility. the old API is
    supposed to be removed later.

    You can define the flow match by the keyword arguments.
    The following arguments are available.

    ================ =============== ==================================
    Argument         Value           Description
    ================ =============== ==================================
    in_port          Integer 32bit   Switch input port
    in_phy_port      Integer 32bit   Switch physical input port
    metadata         Integer 64bit   Metadata passed between tables
    eth_dst          MAC address     Ethernet destination address
    eth_src          MAC address     Ethernet source address
    eth_type         Integer 16bit   Ethernet frame type
    vlan_vid         Integer 16bit   VLAN id
    vlan_pcp         Integer 8bit    VLAN priority
    ip_dscp          Integer 8bit    IP DSCP (6 bits in ToS field)
    ip_ecn           Integer 8bit    IP ECN (2 bits in ToS field)
    ip_proto         Integer 8bit    IP protocol
    ipv4_src         IPv4 address    IPv4 source address
    ipv4_dst         IPv4 address    IPv4 destination address
    tcp_src          Integer 16bit   TCP source port
    tcp_dst          Integer 16bit   TCP destination port
    udp_src          Integer 16bit   UDP source port
    udp_dst          Integer 16bit   UDP destination port
    sctp_src         Integer 16bit   SCTP source port
    sctp_dst         Integer 16bit   SCTP destination port
    icmpv4_type      Integer 8bit    ICMP type
    icmpv4_code      Integer 8bit    ICMP code
    arp_op           Integer 16bit   ARP opcode
    arp_spa          IPv4 address    ARP source IPv4 address
    arp_tpa          IPv4 address    ARP target IPv4 address
    arp_sha          MAC address     ARP source hardware address
    arp_tha          MAC address     ARP target hardware address
    ipv6_src         IPv6 address    IPv6 source address
    ipv6_dst         IPv6 address    IPv6 destination address
    ipv6_flabel      Integer 32bit   IPv6 Flow Label
    icmpv6_type      Integer 8bit    ICMPv6 type
    icmpv6_code      Integer 8bit    ICMPv6 code
    ipv6_nd_target   IPv6 address    Target address for ND
    ipv6_nd_sll      MAC address     Source link-layer for ND
    ipv6_nd_tll      MAC address     Target link-layer for ND
    mpls_label       Integer 32bit   MPLS label
    mpls_tc          Integer 8bit    MPLS TC
    pbb_uca          Integer 8bit    PBB UCA header field
                                     (EXT-256 Old version of ONF Extension)
    tcp_flags        Integer 16bit   TCP flags
                                     (EXT-109 ONF Extension)
    actset_output    Integer 32bit   Output port from action set metadata
                                     (EXT-233 ONF Extension)
    ================ =============== ==================================

    Example::

        >>> # compose
        >>> match = parser.OFPMatch(
        ...     in_port=1,
        ...     eth_type=0x86dd,
        ...     ipv6_src=('2001:db8:bd05:1d2:288a:1fc0:1:10ee',
        ...               'ffff:ffff:ffff:ffff::'),
        ...     ipv6_dst='2001:db8:bd05:1d2:288a:1fc0:1:10ee')
        >>> # query
        >>> if 'ipv6_src' in match:
        ...     print match['ipv6_src']
        ...
        ('2001:db8:bd05:1d2:288a:1fc0:1:10ee', 'ffff:ffff:ffff:ffff::')

    .. Note::

        For the list of the supported Nicira experimenter matches,
        please refer to :ref:`ryu.ofproto.nx_match <nx_match_structures>`.

    .. Note::

        For VLAN id match field, special values are defined in OpenFlow Spec.

        1) Packets with and without a VLAN tag

            - Example::

                match = parser.OFPMatch()

            - Packet Matching

                ====================== =====
                non-VLAN-tagged        MATCH
                VLAN-tagged(vlan_id=3) MATCH
                VLAN-tagged(vlan_id=5) MATCH
                ====================== =====

        2) Only packets without a VLAN tag

            - Example::

                match = parser.OFPMatch(vlan_vid=0x0000)

            - Packet Matching

                ====================== =====
                non-VLAN-tagged        MATCH
                VLAN-tagged(vlan_id=3)   x
                VLAN-tagged(vlan_id=5)   x
                ====================== =====

        3) Only packets with a VLAN tag regardless of its value

            - Example::

                match = parser.OFPMatch(vlan_vid=(0x1000, 0x1000))

            - Packet Matching

                ====================== =====
                non-VLAN-tagged          x
                VLAN-tagged(vlan_id=3) MATCH
                VLAN-tagged(vlan_id=5) MATCH
                ====================== =====

        4) Only packets with VLAN tag and VID equal

            - Example::

                match = parser.OFPMatch(vlan_vid=(0x1000 | 3))

            - Packet Matching

                ====================== =====
                non-VLAN-tagged          x
                VLAN-tagged(vlan_id=3) MATCH
                VLAN-tagged(vlan_id=5)   x
                ====================== =====
    """

    def __init__(self, type_=None, length=None, _ordered_fields=None,
                 **kwargs):
        super(OFPMatch, self).__init__()
        self._wc = FlowWildcards()
        self._flow = Flow()
        self.fields = []
        self.type = ofproto.OFPMT_OXM
        self.length = length

        if _ordered_fields is not None:
            assert not kwargs
            self._fields2 = _ordered_fields
        else:
            # eg.
            #   OFPMatch(eth_src=('ff:ff:ff:00:00:00'), eth_type=0x800,
            #            ipv4_src='10.0.0.1')
            kwargs = dict(ofproto.oxm_normalize_user(k, v) for
                          (k, v) in kwargs.items())
            fields = [ofproto.oxm_from_user(k, v) for (k, v)
                      in kwargs.items()]
            # assumption: sorting by OXM type values makes fields
            # meet ordering requirements (eg. eth_type before ipv4_src)
            fields.sort(
                key=lambda x: x[0][0] if isinstance(x[0], tuple) else x[0])
            self._fields2 = [ofproto.oxm_to_user(n, v, m) for (n, v, m)
                             in fields]

    def __getitem__(self, key):
        return dict(self._fields2)[key]

    def __contains__(self, key):
        return key in dict(self._fields2)

    def iteritems(self):
        return iter(dict(self._fields2).items())

    def items(self):
        return self._fields2

    def get(self, key, default=None):
        return dict(self._fields2).get(key, default)

    def stringify_attrs(self):
        yield "oxm_fields", dict(self._fields2)

    def to_jsondict(self):
        """
        Returns a dict expressing the flow match.
        """
        # XXX old api compat
        if self._composed_with_old_api():
            # copy object first because serialize_old is destructive
            o2 = OFPMatch()
            o2.fields = self.fields[:]
            # serialize and parse to fill OFPMatch._fields2
            buf = bytearray()
            o2.serialize(buf, 0)
            o = OFPMatch.parser(six.binary_type(buf), 0)
        else:
            o = self

        body = {"oxm_fields": [ofproto.oxm_to_jsondict(k, uv) for k, uv
                               in o._fields2],
                "length": o.length,
                "type": o.type}
        return {self.__class__.__name__: body}

    @classmethod
    def from_jsondict(cls, dict_):
        """
        Returns an object which is generated from a dict.

        Exception raises:
        KeyError -- Unknown match field is defined in dict
        """
        fields = [ofproto.oxm_from_jsondict(f) for f
                  in dict_['oxm_fields']]
        o = OFPMatch(_ordered_fields=fields)
        # XXX old api compat
        # serialize and parse to fill OFPMatch.fields
        buf = bytearray()
        o.serialize(buf, 0)
        return OFPMatch.parser(six.binary_type(buf), 0)

    def __str__(self):
        # XXX old api compat
        if self._composed_with_old_api():
            # copy object first because serialize_old is destructive
            o2 = OFPMatch()
            o2.fields = self.fields[:]
            # serialize and parse to fill OFPMatch._fields2
            buf = bytearray()
            o2.serialize(buf, 0)
            o = OFPMatch.parser(six.binary_type(buf), 0)
        else:
            o = self
        return super(OFPMatch, o).__str__()

    __repr__ = __str__

    def append_field(self, header, value, mask=None):
        """
        Append a match field.

        ========= =======================================================
        Argument  Description
        ========= =======================================================
        header    match field header ID which is defined automatically in
                  ``ofproto_v1_3``
        value     match field value
        mask      mask value to the match field
        ========= =======================================================

        The available ``header`` is as follows.

        ====================== ===================================
        Header ID              Description
        ====================== ===================================
        OXM_OF_IN_PORT         Switch input port
        OXM_OF_IN_PHY_PORT     Switch physical input port
        OXM_OF_METADATA        Metadata passed between tables
        OXM_OF_ETH_DST         Ethernet destination address
        OXM_OF_ETH_SRC         Ethernet source address
        OXM_OF_ETH_TYPE        Ethernet frame type
        OXM_OF_VLAN_VID        VLAN id
        OXM_OF_VLAN_PCP        VLAN priority
        OXM_OF_IP_DSCP         IP DSCP (6 bits in ToS field)
        OXM_OF_IP_ECN          IP ECN (2 bits in ToS field)
        OXM_OF_IP_PROTO        IP protocol
        OXM_OF_IPV4_SRC        IPv4 source address
        OXM_OF_IPV4_DST        IPv4 destination address
        OXM_OF_TCP_SRC         TCP source port
        OXM_OF_TCP_DST         TCP destination port
        OXM_OF_UDP_SRC         UDP source port
        OXM_OF_UDP_DST         UDP destination port
        OXM_OF_SCTP_SRC        SCTP source port
        OXM_OF_SCTP_DST        SCTP destination port
        OXM_OF_ICMPV4_TYPE     ICMP type
        OXM_OF_ICMPV4_CODE     ICMP code
        OXM_OF_ARP_OP          ARP opcode
        OXM_OF_ARP_SPA         ARP source IPv4 address
        OXM_OF_ARP_TPA         ARP target IPv4 address
        OXM_OF_ARP_SHA         ARP source hardware address
        OXM_OF_ARP_THA         ARP target hardware address
        OXM_OF_IPV6_SRC        IPv6 source address
        OXM_OF_IPV6_DST        IPv6 destination address
        OXM_OF_IPV6_FLABEL     IPv6 Flow Label
        OXM_OF_ICMPV6_TYPE     ICMPv6 type
        OXM_OF_ICMPV6_CODE     ICMPv6 code
        OXM_OF_IPV6_ND_TARGET  Target address for ND
        OXM_OF_IPV6_ND_SLL     Source link-layer for ND
        OXM_OF_IPV6_ND_TLL     Target link-layer for ND
        OXM_OF_MPLS_LABEL      MPLS label
        OXM_OF_MPLS_TC         MPLS TC
        ====================== ===================================
        """
        self.fields.append(OFPMatchField.make(header, value, mask))

    def _composed_with_old_api(self):
        return (self.fields and not self._fields2) or \
            self._wc.__dict__ != FlowWildcards().__dict__

    def serialize(self, buf, offset):
        """
        Outputs the expression of the wire protocol of the flow match into
        the buf.
        Returns the output length.
        """
        # XXX compat
        if self._composed_with_old_api():
            return self.serialize_old(buf, offset)

        fields = [ofproto.oxm_from_user(k, uv) for (k, uv)
                  in self._fields2]

        hdr_pack_str = '!HH'
        field_offset = offset + struct.calcsize(hdr_pack_str)
        for (n, value, mask) in fields:
            field_offset += ofproto.oxm_serialize(n, value, mask, buf,
                                                  field_offset)

        length = field_offset - offset
        msg_pack_into(hdr_pack_str, buf, offset,
                      ofproto.OFPMT_OXM, length)
        self.length = length

        pad_len = utils.round_up(length, 8) - length
        msg_pack_into("%dx" % pad_len, buf, field_offset)

        return length + pad_len

    def serialize_old(self, buf, offset):
        if hasattr(self, '_serialized'):
            raise Exception('serializing an OFPMatch composed with '
                            'old API multiple times is not supported')
        self._serialized = True

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IN_PORT):
            self.append_field(ofproto.OXM_OF_IN_PORT,
                              self._flow.in_port)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IN_PHY_PORT):
            self.append_field(ofproto.OXM_OF_IN_PHY_PORT,
                              self._flow.in_phy_port)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_METADATA):
            if self._wc.metadata_mask == UINT64_MAX:
                header = ofproto.OXM_OF_METADATA
            else:
                header = ofproto.OXM_OF_METADATA_W
            self.append_field(header, self._flow.metadata,
                              self._wc.metadata_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ETH_DST):
            if self._wc.dl_dst_mask:
                header = ofproto.OXM_OF_ETH_DST_W
            else:
                header = ofproto.OXM_OF_ETH_DST
            self.append_field(header, self._flow.dl_dst, self._wc.dl_dst_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ETH_SRC):
            if self._wc.dl_src_mask:
                header = ofproto.OXM_OF_ETH_SRC_W
            else:
                header = ofproto.OXM_OF_ETH_SRC
            self.append_field(header, self._flow.dl_src, self._wc.dl_src_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ETH_TYPE):
            self.append_field(ofproto.OXM_OF_ETH_TYPE, self._flow.dl_type)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_VLAN_VID):
            if self._wc.vlan_vid_mask == UINT16_MAX:
                header = ofproto.OXM_OF_VLAN_VID
            else:
                header = ofproto.OXM_OF_VLAN_VID_W
            self.append_field(header, self._flow.vlan_vid,
                              self._wc.vlan_vid_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_VLAN_PCP):
            self.append_field(ofproto.OXM_OF_VLAN_PCP,
                              self._flow.vlan_pcp)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IP_DSCP):
            self.append_field(ofproto.OXM_OF_IP_DSCP, self._flow.ip_dscp)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IP_ECN):
            self.append_field(ofproto.OXM_OF_IP_ECN, self._flow.ip_ecn)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IP_PROTO):
            self.append_field(ofproto.OXM_OF_IP_PROTO,
                              self._flow.ip_proto)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV4_SRC):
            if self._wc.ipv4_src_mask == UINT32_MAX:
                header = ofproto.OXM_OF_IPV4_SRC
            else:
                header = ofproto.OXM_OF_IPV4_SRC_W
            self.append_field(header, self._flow.ipv4_src,
                              self._wc.ipv4_src_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV4_DST):
            if self._wc.ipv4_dst_mask == UINT32_MAX:
                header = ofproto.OXM_OF_IPV4_DST
            else:
                header = ofproto.OXM_OF_IPV4_DST_W
            self.append_field(header, self._flow.ipv4_dst,
                              self._wc.ipv4_dst_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_TCP_SRC):
            self.append_field(ofproto.OXM_OF_TCP_SRC, self._flow.tcp_src)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_TCP_DST):
            self.append_field(ofproto.OXM_OF_TCP_DST, self._flow.tcp_dst)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_UDP_SRC):
            self.append_field(ofproto.OXM_OF_UDP_SRC, self._flow.udp_src)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_UDP_DST):
            self.append_field(ofproto.OXM_OF_UDP_DST, self._flow.udp_dst)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_SCTP_SRC):
            self.append_field(ofproto.OXM_OF_SCTP_SRC,
                              self._flow.sctp_src)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_SCTP_DST):
            self.append_field(ofproto.OXM_OF_SCTP_DST,
                              self._flow.sctp_dst)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ICMPV4_TYPE):
            self.append_field(ofproto.OXM_OF_ICMPV4_TYPE,
                              self._flow.icmpv4_type)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ICMPV4_CODE):
            self.append_field(ofproto.OXM_OF_ICMPV4_CODE,
                              self._flow.icmpv4_code)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ARP_OP):
            self.append_field(ofproto.OXM_OF_ARP_OP, self._flow.arp_op)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ARP_SPA):
            if self._wc.arp_spa_mask == UINT32_MAX:
                header = ofproto.OXM_OF_ARP_SPA
            else:
                header = ofproto.OXM_OF_ARP_SPA_W
            self.append_field(header, self._flow.arp_spa,
                              self._wc.arp_spa_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ARP_TPA):
            if self._wc.arp_tpa_mask == UINT32_MAX:
                header = ofproto.OXM_OF_ARP_TPA
            else:
                header = ofproto.OXM_OF_ARP_TPA_W
            self.append_field(header, self._flow.arp_tpa,
                              self._wc.arp_tpa_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ARP_SHA):
            if self._wc.arp_sha_mask:
                header = ofproto.OXM_OF_ARP_SHA_W
            else:
                header = ofproto.OXM_OF_ARP_SHA
            self.append_field(header, self._flow.arp_sha,
                              self._wc.arp_sha_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ARP_THA):
            if self._wc.arp_tha_mask:
                header = ofproto.OXM_OF_ARP_THA_W
            else:
                header = ofproto.OXM_OF_ARP_THA
            self.append_field(header, self._flow.arp_tha,
                              self._wc.arp_tha_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV6_SRC):
            if len(self._wc.ipv6_src_mask):
                header = ofproto.OXM_OF_IPV6_SRC_W
            else:
                header = ofproto.OXM_OF_IPV6_SRC
            self.append_field(header, self._flow.ipv6_src,
                              self._wc.ipv6_src_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV6_DST):
            if len(self._wc.ipv6_dst_mask):
                header = ofproto.OXM_OF_IPV6_DST_W
            else:
                header = ofproto.OXM_OF_IPV6_DST
            self.append_field(header, self._flow.ipv6_dst,
                              self._wc.ipv6_dst_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV6_FLABEL):
            if self._wc.ipv6_flabel_mask == UINT32_MAX:
                header = ofproto.OXM_OF_IPV6_FLABEL
            else:
                header = ofproto.OXM_OF_IPV6_FLABEL_W
            self.append_field(header, self._flow.ipv6_flabel,
                              self._wc.ipv6_flabel_mask)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ICMPV6_TYPE):
            self.append_field(ofproto.OXM_OF_ICMPV6_TYPE,
                              self._flow.icmpv6_type)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_ICMPV6_CODE):
            self.append_field(ofproto.OXM_OF_ICMPV6_CODE,
                              self._flow.icmpv6_code)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV6_ND_TARGET):
            self.append_field(ofproto.OXM_OF_IPV6_ND_TARGET,
                              self._flow.ipv6_nd_target)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV6_ND_SLL):
            self.append_field(ofproto.OXM_OF_IPV6_ND_SLL,
                              self._flow.ipv6_nd_sll)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_IPV6_ND_TLL):
            self.append_field(ofproto.OXM_OF_IPV6_ND_TLL,
                              self._flow.ipv6_nd_tll)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_MPLS_LABEL):
            self.append_field(ofproto.OXM_OF_MPLS_LABEL,
                              self._flow.mpls_label)

        if self._wc.ft_test(ofproto.OFPXMT_OFB_MPLS_TC):
            self.append_field(ofproto.OXM_OF_MPLS_TC,
                              self._flow.mpls_tc)

        field_offset = offset + 4
        for f in self.fields:
            f.serialize(buf, field_offset)
            field_offset += f.length

        length = field_offset - offset
        msg_pack_into('!HH', buf, offset, ofproto.OFPMT_OXM, length)

        pad_len = utils.round_up(length, 8) - length
        msg_pack_into("%dx" % pad_len, buf, field_offset)

        return length + pad_len

    @classmethod
    def parser(cls, buf, offset):
        """
        Returns an object which is generated from a buffer including the
        expression of the wire protocol of the flow match.
        """
        match = OFPMatch()
        type_, length = struct.unpack_from('!HH', buf, offset)

        match.type = type_
        match.length = length

        # ofp_match adjustment
        offset += 4
        length -= 4

        # XXXcompat
        cls.parser_old(match, buf, offset, length)

        fields = []
        while length > 0:
            n, value, mask, field_len = ofproto.oxm_parse(buf, offset)
            k, uv = ofproto.oxm_to_user(n, value, mask)
            fields.append((k, uv))
            offset += field_len
            length -= field_len
        match._fields2 = fields
        return match

    @staticmethod
    def parser_old(match, buf, offset, length):
        while length > 0:
            field = OFPMatchField.parser(buf, offset)
            offset += field.length
            length -= field.length
            match.fields.append(field)

    def set_in_port(self, port):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IN_PORT)
        self._flow.in_port = port

    def set_in_phy_port(self, phy_port):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IN_PHY_PORT)
        self._flow.in_phy_port = phy_port

    def set_metadata(self, metadata):
        self.set_metadata_masked(metadata, UINT64_MAX)

    def set_metadata_masked(self, metadata, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_METADATA)
        self._wc.metadata_mask = mask
        self._flow.metadata = metadata & mask

    def set_dl_dst(self, dl_dst):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ETH_DST)
        self._flow.dl_dst = dl_dst

    def set_dl_dst_masked(self, dl_dst, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ETH_DST)
        self._wc.dl_dst_mask = mask
        # bit-wise and of the corresponding elements of dl_dst and mask
        self._flow.dl_dst = mac.haddr_bitand(dl_dst, mask)

    def set_dl_src(self, dl_src):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ETH_SRC)
        self._flow.dl_src = dl_src

    def set_dl_src_masked(self, dl_src, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ETH_SRC)
        self._wc.dl_src_mask = mask
        self._flow.dl_src = mac.haddr_bitand(dl_src, mask)

    def set_dl_type(self, dl_type):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ETH_TYPE)
        self._flow.dl_type = dl_type

    def set_vlan_vid_none(self):
        self._wc.ft_set(ofproto.OFPXMT_OFB_VLAN_VID)
        self._wc.vlan_vid_mask = UINT16_MAX
        self._flow.vlan_vid = ofproto.OFPVID_NONE

    def set_vlan_vid(self, vid):
        self.set_vlan_vid_masked(vid, UINT16_MAX)

    def set_vlan_vid_masked(self, vid, mask):
        vid |= ofproto.OFPVID_PRESENT
        self._wc.ft_set(ofproto.OFPXMT_OFB_VLAN_VID)
        self._wc.vlan_vid_mask = mask
        self._flow.vlan_vid = vid

    def set_vlan_pcp(self, pcp):
        self._wc.ft_set(ofproto.OFPXMT_OFB_VLAN_PCP)
        self._flow.vlan_pcp = pcp

    def set_ip_dscp(self, ip_dscp):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IP_DSCP)
        self._flow.ip_dscp = ip_dscp

    def set_ip_ecn(self, ip_ecn):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IP_ECN)
        self._flow.ip_ecn = ip_ecn

    def set_ip_proto(self, ip_proto):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IP_PROTO)
        self._flow.ip_proto = ip_proto

    def set_ipv4_src(self, ipv4_src):
        self.set_ipv4_src_masked(ipv4_src, UINT32_MAX)

    def set_ipv4_src_masked(self, ipv4_src, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV4_SRC)
        self._flow.ipv4_src = ipv4_src
        self._wc.ipv4_src_mask = mask

    def set_ipv4_dst(self, ipv4_dst):
        self.set_ipv4_dst_masked(ipv4_dst, UINT32_MAX)

    def set_ipv4_dst_masked(self, ipv4_dst, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV4_DST)
        self._flow.ipv4_dst = ipv4_dst
        self._wc.ipv4_dst_mask = mask

    def set_tcp_src(self, tcp_src):
        self._wc.ft_set(ofproto.OFPXMT_OFB_TCP_SRC)
        self._flow.tcp_src = tcp_src

    def set_tcp_dst(self, tcp_dst):
        self._wc.ft_set(ofproto.OFPXMT_OFB_TCP_DST)
        self._flow.tcp_dst = tcp_dst

    def set_udp_src(self, udp_src):
        self._wc.ft_set(ofproto.OFPXMT_OFB_UDP_SRC)
        self._flow.udp_src = udp_src

    def set_udp_dst(self, udp_dst):
        self._wc.ft_set(ofproto.OFPXMT_OFB_UDP_DST)
        self._flow.udp_dst = udp_dst

    def set_sctp_src(self, sctp_src):
        self._wc.ft_set(ofproto.OFPXMT_OFB_SCTP_SRC)
        self._flow.sctp_src = sctp_src

    def set_sctp_dst(self, sctp_dst):
        self._wc.ft_set(ofproto.OFPXMT_OFB_SCTP_DST)
        self._flow.sctp_dst = sctp_dst

    def set_icmpv4_type(self, icmpv4_type):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ICMPV4_TYPE)
        self._flow.icmpv4_type = icmpv4_type

    def set_icmpv4_code(self, icmpv4_code):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ICMPV4_CODE)
        self._flow.icmpv4_code = icmpv4_code

    def set_arp_opcode(self, arp_op):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ARP_OP)
        self._flow.arp_op = arp_op

    def set_arp_spa(self, arp_spa):
        self.set_arp_spa_masked(arp_spa, UINT32_MAX)

    def set_arp_spa_masked(self, arp_spa, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ARP_SPA)
        self._wc.arp_spa_mask = mask
        self._flow.arp_spa = arp_spa

    def set_arp_tpa(self, arp_tpa):
        self.set_arp_tpa_masked(arp_tpa, UINT32_MAX)

    def set_arp_tpa_masked(self, arp_tpa, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ARP_TPA)
        self._wc.arp_tpa_mask = mask
        self._flow.arp_tpa = arp_tpa

    def set_arp_sha(self, arp_sha):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ARP_SHA)
        self._flow.arp_sha = arp_sha

    def set_arp_sha_masked(self, arp_sha, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ARP_SHA)
        self._wc.arp_sha_mask = mask
        self._flow.arp_sha = mac.haddr_bitand(arp_sha, mask)

    def set_arp_tha(self, arp_tha):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ARP_THA)
        self._flow.arp_tha = arp_tha

    def set_arp_tha_masked(self, arp_tha, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ARP_THA)
        self._wc.arp_tha_mask = mask
        self._flow.arp_tha = mac.haddr_bitand(arp_tha, mask)

    def set_ipv6_src(self, src):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_SRC)
        self._flow.ipv6_src = src

    def set_ipv6_src_masked(self, src, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_SRC)
        self._wc.ipv6_src_mask = mask
        self._flow.ipv6_src = [x & y for (x, y) in zip(src, mask)]

    def set_ipv6_dst(self, dst):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_DST)
        self._flow.ipv6_dst = dst

    def set_ipv6_dst_masked(self, dst, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_DST)
        self._wc.ipv6_dst_mask = mask
        self._flow.ipv6_dst = [x & y for (x, y) in zip(dst, mask)]

    def set_ipv6_flabel(self, flabel):
        self.set_ipv6_flabel_masked(flabel, UINT32_MAX)

    def set_ipv6_flabel_masked(self, flabel, mask):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_FLABEL)
        self._wc.ipv6_flabel_mask = mask
        self._flow.ipv6_flabel = flabel

    def set_icmpv6_type(self, icmpv6_type):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ICMPV6_TYPE)
        self._flow.icmpv6_type = icmpv6_type

    def set_icmpv6_code(self, icmpv6_code):
        self._wc.ft_set(ofproto.OFPXMT_OFB_ICMPV6_CODE)
        self._flow.icmpv6_code = icmpv6_code

    def set_ipv6_nd_target(self, target):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_ND_TARGET)
        self._flow.ipv6_nd_target = target

    def set_ipv6_nd_sll(self, ipv6_nd_sll):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_ND_SLL)
        self._flow.ipv6_nd_sll = ipv6_nd_sll

    def set_ipv6_nd_tll(self, ipv6_nd_tll):
        self._wc.ft_set(ofproto.OFPXMT_OFB_IPV6_ND_TLL)
        self._flow.ipv6_nd_tll = ipv6_nd_tll

    def set_mpls_label(self, mpls_label):
        self._wc.ft_set(ofproto.OFPXMT_OFB_MPLS_LABEL)
        self._flow.mpls_label = mpls_label

    def set_mpls_tc(self, mpls_tc):
        self._wc.ft_set(ofproto.OFPXMT_OFB_MPLS_TC)
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
        self.n_bytes = ofproto.oxm_tlv_header_extract_length(header)
        self.length = 0

    @classmethod
    def cls_to_header(cls, cls_, hasmask):
        # XXX efficiency
        inv = dict((v, k) for k, v in cls._FIELDS_HEADERS.items()
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
        if ofproto.oxm_tlv_header_extract_hasmask(header):
            pack_str = '!' + cls.pack_str[1:] * 2
            (value, mask) = struct.unpack_from(pack_str, buf, offset + 4)
        else:
            (value,) = struct.unpack_from(cls.pack_str, buf, offset + 4)
        return cls(header, value, mask)

    def serialize(self, buf, offset):
        if ofproto.oxm_tlv_header_extract_hasmask(self.header):
            self.put_w(buf, offset, self.value, self.mask)
        else:
            self.put(buf, offset, self.value)

    def _put_header(self, buf, offset):
        msg_pack_into('!I', buf, offset, self.header)
        self.length = 4

    def _put(self, buf, offset, value):
        msg_pack_into(self.pack_str, buf, offset, value)
        self.length += self.n_bytes

    def put_w(self, buf, offset, value, mask):
        self._put_header(buf, offset)
        self._put(buf, offset + self.length, value)
        self._put(buf, offset + self.length, mask)

    def put(self, buf, offset, value):
        self._put_header(buf, offset)
        self._put(buf, offset + self.length, value)

    def _putv6(self, buf, offset, value):
        msg_pack_into(self.pack_str, buf, offset, *value)
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
        if not ofproto.oxm_tlv_header_extract_hasmask(self.header):
            # something like the following, but yield two values (k,v)
            # return itertools.ifilter(lambda k, v: k != 'mask', iter())
            def g():
                for k, v in f():
                    if k != 'mask':
                        yield (k, v)
            return g()
        else:
            return f()


@OFPMatchField.register_field_header([ofproto.OXM_OF_IN_PORT])
class MTInPort(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTInPort, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_METADATA,
                                      ofproto.OXM_OF_METADATA_W])
class MTMetadata(OFPMatchField):
    pack_str = '!Q'

    def __init__(self, header, value, mask=None):
        super(MTMetadata, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_IN_PHY_PORT])
class MTInPhyPort(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTInPhyPort, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_ETH_DST,
                                      ofproto.OXM_OF_ETH_DST_W])
class MTEthDst(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTEthDst, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_ETH_SRC,
                                      ofproto.OXM_OF_ETH_SRC_W])
class MTEthSrc(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTEthSrc, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_ETH_TYPE])
class MTEthType(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTEthType, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_VLAN_VID,
                                      ofproto.OXM_OF_VLAN_VID_W])
class MTVlanVid(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTVlanVid, self).__init__(header)
        self.value = value
        self.mask = mask

    @classmethod
    def field_parser(cls, header, buf, offset):
        m = super(MTVlanVid, cls).field_parser(header, buf, offset)
        m.value &= ~ofproto.OFPVID_PRESENT
        return m


@OFPMatchField.register_field_header([ofproto.OXM_OF_VLAN_PCP])
class MTVlanPcp(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTVlanPcp, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_IP_DSCP])
class MTIPDscp(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTIPDscp, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_IP_ECN])
class MTIPECN(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTIPECN, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_IP_PROTO])
class MTIPProto(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTIPProto, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV4_SRC,
                                      ofproto.OXM_OF_IPV4_SRC_W])
class MTIPV4Src(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTIPV4Src, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV4_DST,
                                      ofproto.OXM_OF_IPV4_DST_W])
class MTIPV4Dst(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTIPV4Dst, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_TCP_SRC])
class MTTCPSrc(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTTCPSrc, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_TCP_DST])
class MTTCPDst(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTTCPDst, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_UDP_SRC])
class MTUDPSrc(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTUDPSrc, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_UDP_DST])
class MTUDPDst(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTUDPDst, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_SCTP_SRC])
class MTSCTPSrc(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTSCTPSrc, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_SCTP_DST])
class MTSCTPDst(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTSCTPDst, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_ICMPV4_TYPE])
class MTICMPV4Type(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV4Type, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_ICMPV4_CODE])
class MTICMPV4Code(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV4Code, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_ARP_OP])
class MTArpOp(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTArpOp, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_ARP_SPA,
                                      ofproto.OXM_OF_ARP_SPA_W])
class MTArpSpa(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTArpSpa, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_ARP_TPA,
                                      ofproto.OXM_OF_ARP_TPA_W])
class MTArpTpa(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTArpTpa, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_ARP_SHA,
                                      ofproto.OXM_OF_ARP_SHA_W])
class MTArpSha(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTArpSha, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_ARP_THA,
                                      ofproto.OXM_OF_ARP_THA_W])
class MTArpTha(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTArpTha, self).__init__(header)
        self.value = value
        self.mask = mask


class MTIPv6(object):
    @classmethod
    def field_parser(cls, header, buf, offset):
        if ofproto.oxm_tlv_header_extract_hasmask(header):
            pack_str = '!' + cls.pack_str[1:] * 2
            value = struct.unpack_from(pack_str, buf, offset + 4)
            return cls(header, list(value[:8]), list(value[8:]))
        else:
            value = struct.unpack_from(cls.pack_str, buf, offset + 4)
            return cls(header, list(value))

    def serialize(self, buf, offset):
        self.putv6(buf, offset, self.value, self.mask)


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV6_SRC,
                                      ofproto.OXM_OF_IPV6_SRC_W])
class MTIPv6Src(MTIPv6, OFPMatchField):
    pack_str = '!8H'

    def __init__(self, header, value, mask=None):
        super(MTIPv6Src, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV6_DST,
                                      ofproto.OXM_OF_IPV6_DST_W])
class MTIPv6Dst(MTIPv6, OFPMatchField):
    pack_str = '!8H'

    def __init__(self, header, value, mask=None):
        super(MTIPv6Dst, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV6_FLABEL,
                                      ofproto.OXM_OF_IPV6_FLABEL_W])
class MTIPv6Flabel(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTIPv6Flabel, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_MPLS_LABEL])
class MTMplsLabel(OFPMatchField):
    pack_str = '!I'

    def __init__(self, header, value, mask=None):
        super(MTMplsLabel, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_ICMPV6_TYPE])
class MTICMPV6Type(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV6Type, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_ICMPV6_CODE])
class MTICMPV6Code(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTICMPV6Code, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV6_ND_TARGET])
class MTIPv6NdTarget(MTIPv6, OFPMatchField):
    pack_str = '!8H'

    def __init__(self, header, value, mask=None):
        super(MTIPv6NdTarget, self).__init__(header)
        self.value = value

    def serialize(self, buf, offset):
        self.putv6(buf, offset, self.value)


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV6_ND_SLL])
class MTIPv6NdSll(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTIPv6NdSll, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV6_ND_TLL])
class MTIPv6NdTll(OFPMatchField):
    pack_str = '!6s'

    def __init__(self, header, value, mask=None):
        super(MTIPv6NdTll, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_MPLS_TC])
class MTMplsTc(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTMplsTc, self).__init__(header)
        self.value = value
