# Copyright (C) 2012, 2013, 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012, 2013 Isaku Yamahata <yamahata at valinux co jp>
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
Decoder/Encoder implementations of OpenFlow 1.5.
"""

import six
import struct

from ryu.lib import addrconv
from ryu.lib.pack_utils import msg_pack_into
from ryu import utils
from ryu.ofproto.ofproto_parser import StringifyMixin, MsgBase, MsgInMsgBase
from ryu.ofproto import ether
from ryu.ofproto import nx_actions
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_v1_5 as ofproto

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

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    elements   list of ``OFPHelloElemVersionBitmap`` instance
    ========== =========================================================
    """
    def __init__(self, datapath, elements=None):
        elements = elements if elements else []
        super(OFPHello, self).__init__(datapath)
        self.elements = elements

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPHello, cls).parser(datapath, version, msg_type,
                                          msg_len, xid, buf)

        offset = ofproto.OFP_HELLO_HEADER_SIZE
        elems = []
        while offset < msg.msg_len:
            type_, length = struct.unpack_from(
                ofproto.OFP_HELLO_ELEM_HEADER_PACK_STR, msg.buf, offset)

            # better to register Hello Element classes but currently
            # Only VerisonBitmap is supported so let's be simple.

            if type_ == ofproto.OFPHET_VERSIONBITMAP:
                elem = OFPHelloElemVersionBitmap.parser(msg.buf, offset)
                elems.append(elem)

            offset += length
        msg.elements = elems
        return msg


class OFPHelloElemVersionBitmap(StringifyMixin):
    """
    Version bitmap Hello Element

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    versions   list of versions of OpenFlow protocol a device supports
    ========== =========================================================
    """
    def __init__(self, versions, type_=None, length=None):
        super(OFPHelloElemVersionBitmap, self).__init__()
        self.type = ofproto.OFPHET_VERSIONBITMAP
        self.length = None
        self._bitmaps = None
        self.versions = versions

    @classmethod
    def parser(cls, buf, offset):
        type_, length = struct.unpack_from(
            ofproto.OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_PACK_STR,
            buf, offset)
        assert type_ == ofproto.OFPHET_VERSIONBITMAP

        bitmaps_len = (length -
                       ofproto.OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_SIZE)
        offset += ofproto.OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_SIZE
        bitmaps = []
        while bitmaps_len >= 4:
            bitmap = struct.unpack_from('!I', buf, offset)
            bitmaps.append(bitmap[0])
            offset += 4
            bitmaps_len -= 4

        versions = [i * 32 + shift
                    for i, bitmap in enumerate(bitmaps)
                    for shift in range(31) if bitmap & (1 << shift)]
        elem = cls(versions)
        elem.length = length
        elem._bitmaps = bitmaps
        return elem


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
    OFPET_METER_MOD_FAILED        OFPMMFC_*
    OFPET_TABLE_FEATURES_FAILED   OFPTFFC_*
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
        msg = super(OFPExperimenter, cls).parser(datapath, version,
                                                 msg_type, msg_len,
                                                 xid, buf)
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
                              'n_tables=%d auxiliary_id=%d '
                              'capabilities=0x%08x',
                              msg.datapath_id, msg.n_buffers, msg.n_tables,
                              msg.auxiliary_id, msg.capabilities)
    """
    def __init__(self, datapath, datapath_id=None, n_buffers=None,
                 n_tables=None, auxiliary_id=None, capabilities=None):
        super(OFPSwitchFeatures, self).__init__(datapath)
        self.datapath_id = datapath_id
        self.n_buffers = n_buffers
        self.n_tables = n_tables
        self.auxiliary_id = auxiliary_id
        self.capabilities = capabilities

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPSwitchFeatures, cls).parser(datapath, version, msg_type,
                                                   msg_len, xid, buf)
        (msg.datapath_id,
         msg.n_buffers,
         msg.n_tables,
         msg.auxiliary_id,
         msg.capabilities,
         msg._reserved) = struct.unpack_from(
            ofproto.OFP_SWITCH_FEATURES_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
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
    flags         Bitmap of the following flags.

                  | OFPC_FRAG_NORMAL
                  | OFPC_FRAG_DROP
                  | OFPC_FRAG_REASM
    miss_send_len Max bytes of new flow that datapath should send to the
                  controller
    ============= =========================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
        def get_config_reply_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto
            flags = []

            if msg.flags & ofp.OFPC_FRAG_NORMAL:
                flags.append('NORMAL')
            if msg.flags & ofp.OFPC_FRAG_DROP:
                flags.append('DROP')
            if msg.flags & ofp.OFPC_FRAG_REASM:
                flags.append('REASM')
            self.logger.debug('OFPGetConfigReply received: '
                              'flags=%s miss_send_len=%d',
                              ','.join(flags), msg.miss_send_len)
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
    flags         Bitmap of the following flags.

                  | OFPC_FRAG_NORMAL
                  | OFPC_FRAG_DROP
                  | OFPC_FRAG_REASM
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


class OFPMatch(StringifyMixin):
    """
    Flow Match Structure

    This class is implementation of the flow match structure having
    compose/query API.

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
    mpls_bos         Integer 8bit    MPLS BoS bit
    pbb_isid         Integer 24bit   PBB I-SID
    tunnel_id        Integer 64bit   Logical Port Metadata
    ipv6_exthdr      Integer 16bit   IPv6 Extension Header pseudo-field
    pbb_uca          Integer 8bit    PBB UCA header field
    tcp_flags        Integer 16bit   TCP flags
    actset_output    Integer 32bit   Output port from action set metadata
    packet_type      Integer 32bit   Packet type value
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
        self.type = ofproto.OFPMT_OXM
        self.length = length

        if _ordered_fields is not None:
            assert not kwargs
            self._fields2 = _ordered_fields
        else:
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

        fields = []
        while length > 0:
            n, value, mask, field_len = ofproto.oxm_parse(buf, offset)
            k, uv = ofproto.oxm_to_user(n, value, mask)
            fields.append((k, uv))
            offset += field_len
            length -= field_len
        match._fields2 = fields
        return match

    def serialize(self, buf, offset):
        """
        Outputs the expression of the wire protocol of the flow match into
        the buf.
        Returns the output length.
        """
        fields = [ofproto.oxm_from_user(k, uv) for (k, uv)
                  in self._fields2]

        hdr_pack_str = '!HH'
        field_offset = offset + struct.calcsize(hdr_pack_str)
        for (n, value, mask) in fields:
            field_offset += ofproto.oxm_serialize(n, value, mask, buf,
                                                  field_offset)

        length = field_offset - offset
        msg_pack_into(hdr_pack_str, buf, offset, ofproto.OFPMT_OXM, length)
        self.length = length

        pad_len = utils.round_up(length, 8) - length
        msg_pack_into("%dx" % pad_len, buf, field_offset)

        return length + pad_len

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
        body = {"oxm_fields": [ofproto.oxm_to_jsondict(k, uv) for k, uv
                               in self._fields2],
                "length": self.length,
                "type": self.type}
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
        return OFPMatch(_ordered_fields=fields)


class OFPStats(StringifyMixin):
    """
    Flow Stats Structure

    This class is implementation of the flow stats structure having
    compose/query API.

    You can define the flow stats by the keyword arguments.
    The following arguments are available.

    ============= ================ ============================================
    Argument      Value            Description
    ============= ================ ============================================
    duration      Integer 32bit*2  Time flow entry has been alive. This field
                                   is a tuple of two Integer 32bit. The first
                                   value is duration_sec and the second is
                                   duration_nsec.
    idle_time     Integer 32bit*2  Time flow entry has been idle.
    flow_count    Integer 32bit    Number of aggregated flow entries.
    packet_count  Integer 64bit    Number of packets matched by a flow entry.
    byte_count    Integer 64bit    Number of bytes matched by a flow entry.
    ============= ================ ============================================

    Example::

        >>> # compose
        >>> stats = parser.OFPStats(
        ...     packet_count=100,
        ...     duration=(100, 200)
        >>> # query
        >>> if 'duration' in stats:
        ...     print stats['duration']
        ...
        (100, 200)
    """

    def __init__(self, length=None, _ordered_fields=None, **kwargs):
        super(OFPStats, self).__init__()
        self.length = length

        if _ordered_fields is not None:
            assert not kwargs
            self.fields = _ordered_fields
        else:
            fields = [ofproto.oxs_from_user(k, v) for (k, v)
                      in kwargs.items()]
            # sort by OXS type values
            fields.sort(
                key=lambda x: x[0][0] if isinstance(x[0], tuple) else x[0])
            # No mask
            self.fields = [ofproto.oxs_to_user(n, v, None) for (n, v, _)
                           in fields]

    @classmethod
    def parser(cls, buf, offset):
        """
        Returns an object which is generated from a buffer including the
        expression of the wire protocol of the flow stats.
        """
        stats = OFPStats()
        reserved, length = struct.unpack_from('!HH', buf, offset)

        stats.length = length

        # ofp_stats adjustment
        offset += 4
        length -= 4

        fields = []
        while length > 0:
            n, value, _, field_len = ofproto.oxs_parse(buf, offset)
            k, uv = ofproto.oxs_to_user(n, value, None)  # No mask
            fields.append((k, uv))
            offset += field_len
            length -= field_len
        stats.fields = fields
        return stats

    def serialize(self, buf, offset):
        """
        Outputs the expression of the wire protocol of the flow stats into
        the buf.
        Returns the output length.
        """
        fields = [ofproto.oxs_from_user(k, uv) for (k, uv)
                  in self.fields]

        hdr_pack_str = '!HH'
        field_offset = offset + struct.calcsize(hdr_pack_str)
        for (n, value, _) in fields:
            # No mask
            field_offset += ofproto.oxs_serialize(n, value, None, buf,
                                                  field_offset)

        reserved = 0
        length = field_offset - offset
        msg_pack_into(hdr_pack_str, buf, offset, reserved, length)
        self.length = length

        pad_len = utils.round_up(length, 8) - length
        msg_pack_into("%dx" % pad_len, buf, field_offset)

        return length + pad_len

    def __getitem__(self, key):
        return dict(self.fields)[key]

    def __contains__(self, key):
        return key in dict(self.fields)

    def iteritems(self):
        return dict(self.fields).items()

    def items(self):
        return self.fields

    def get(self, key, default=None):
        return dict(self.fields).get(key, default)

    def stringify_attrs(self):
        yield "oxs_fields", dict(self.fields)

    def to_jsondict(self):
        """
        Returns a dict expressing the flow stats.
        """
        body = {"oxs_fields": [ofproto.oxs_to_jsondict(k, uv) for k, uv
                               in self.fields],
                "length": self.length}
        return {self.__class__.__name__: body}

    @classmethod
    def from_jsondict(cls, dict_):
        """
        Returns an object which is generated from a dict.

        Exception raises:
        KeyError -- Unknown stats field is defined in dict
        """
        fields = [ofproto.oxs_from_jsondict(f) for f
                  in dict_['oxs_fields']]
        return OFPStats(_ordered_fields=fields)


class OFPPropUnknown(StringifyMixin):
    def __init__(self, type_=None, length=None, buf=None):
        self.buf = buf

    @classmethod
    def parser(cls, buf):
        return cls(buf=buf)


class OFPPropBase(StringifyMixin):
    _PACK_STR = '!HH'
    # _TYPES = {} must be an attribute of subclass

    def __init__(self, type_, length=None):
        self.type = type_
        self.length = length

    @classmethod
    def register_type(cls, type_):
        def _register_type(subcls):
            cls._TYPES[type_] = subcls
            return subcls
        return _register_type

    @classmethod
    def parse(cls, buf):
        (type_, length) = struct.unpack_from(cls._PACK_STR, buf, 0)
        rest = buf[utils.round_up(length, 8):]
        try:
            subcls = cls._TYPES[type_]
        except KeyError:
            subcls = OFPPropUnknown
        prop = subcls.parser(buf)
        prop.type = type_
        prop.length = length
        return prop, rest

    @classmethod
    def get_rest(cls, buf):
        (type_, length) = struct.unpack_from(cls._PACK_STR, buf, 0)
        offset = struct.calcsize(cls._PACK_STR)
        return buf[offset:length]

    def serialize(self):
        # Body
        # serialize_body should be implemented by subclass
        body = bytearray()
        body += self.serialize_body()

        # fixup
        self.length = len(body) + struct.calcsize(self._PACK_STR)

        # Header
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type, self.length)
        buf += body

        # Pad
        pad_len = utils.round_up(self.length, 8) - self.length
        msg_pack_into("%dx" % pad_len, buf, len(buf))

        return buf


class OFPPropCommonExperimenter4ByteData(StringifyMixin):
    _PACK_STR = '!HHII'
    _EXPERIMENTER_DATA_PACK_STR = '!I'
    _EXPERIMENTER_DATA_SIZE = 4

    def __init__(self, type_=None, length=None, experimenter=None,
                 exp_type=None, data=bytearray()):
        self.type = type_
        self.length = length
        self.experimenter = experimenter
        self.exp_type = exp_type
        self.data = data

    @classmethod
    def parser(cls, buf):
        (type_, length, experimenter, exp_type) = struct.unpack_from(
            ofproto.OFP_PROP_EXPERIMENTER_PACK_STR, buf, 0)

        rest = buf[ofproto.OFP_PROP_EXPERIMENTER_SIZE:length]
        data = []
        while rest:
            (d,) = struct.unpack_from(
                cls._EXPERIMENTER_DATA_PACK_STR, rest, 0)
            data.append(d)
            rest = rest[cls._EXPERIMENTER_DATA_SIZE:]

        return cls(type_, length, experimenter, exp_type, data)

    def serialize(self):
        offset = 0
        bin_data = bytearray()
        for d in self.data:
            msg_pack_into(self._EXPERIMENTER_DATA_PACK_STR,
                          bin_data, offset, d)
            offset += self._EXPERIMENTER_DATA_SIZE

        # fixup
        self.length = struct.calcsize(self._PACK_STR)
        self.length += len(bin_data)

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf,
                      0, self.type, self.length, self.experimenter,
                      self.exp_type)
        buf += bin_data

        # Pad
        pad_len = utils.round_up(self.length, 8) - self.length
        msg_pack_into("%dx" % pad_len, buf, len(buf))

        return buf


class OFPPortDescProp(OFPPropBase):
    _TYPES = {}


@OFPPortDescProp.register_type(ofproto.OFPPDPT_ETHERNET)
class OFPPortDescPropEthernet(OFPPortDescProp):
    def __init__(self, type_=None, length=None, curr=None, advertised=None,
                 supported=None, peer=None, curr_speed=None, max_speed=None):
        self.type = type_
        self.length = length
        self.curr = curr
        self.advertised = advertised
        self.supported = supported
        self.peer = peer
        self.curr_speed = curr_speed
        self.max_speed = max_speed

    @classmethod
    def parser(cls, buf):
        ether = cls()
        (ether.type, ether.length, ether.curr,
         ether.advertised, ether.supported,
         ether.peer, ether.curr_speed, ether.max_speed) = struct.unpack_from(
            ofproto.OFP_PORT_DESC_PROP_ETHERNET_PACK_STR, buf, 0)
        return ether


@OFPPortDescProp.register_type(ofproto.OFPPDPT_OPTICAL)
class OFPPortDescPropOptical(OFPPortDescProp):
    def __init__(self, type_=None, length=None, supported=None,
                 tx_min_freq_lmda=None, tx_max_freq_lmda=None,
                 tx_grid_freq_lmda=None, rx_min_freq_lmda=None,
                 rx_max_freq_lmda=None, rx_grid_freq_lmda=None,
                 tx_pwr_min=None, tx_pwr_max=None):
        self.type = type_
        self.length = length
        self.supported = supported
        self.tx_min_freq_lmda = tx_min_freq_lmda
        self.tx_max_freq_lmda = tx_max_freq_lmda
        self.tx_grid_freq_lmda = tx_grid_freq_lmda
        self.rx_min_freq_lmda = rx_min_freq_lmda
        self.rx_max_freq_lmda = rx_max_freq_lmda
        self.rx_grid_freq_lmda = rx_grid_freq_lmda
        self.tx_pwr_min = tx_pwr_min
        self.tx_pwr_max = tx_pwr_max

    @classmethod
    def parser(cls, buf):
        optical = cls()
        (optical.type, optical.length, optical.supported,
         optical.tx_min_freq_lmda, optical.tx_max_freq_lmda,
         optical.tx_grid_freq_lmda, optical.rx_min_freq_lmda,
         optical.rx_max_freq_lmda, optical.rx_grid_freq_lmda,
         optical.tx_pwr_min, optical.tx_pwr_max) = struct.unpack_from(
            ofproto.OFP_PORT_DESC_PROP_OPTICAL_PACK_STR, buf, 0)
        return optical


@OFPPortDescProp.register_type(ofproto.OFPPDPT_PIPELINE_INPUT)
@OFPPortDescProp.register_type(ofproto.OFPPDPT_PIPELINE_OUTPUT)
class OFPPortDescPropOxm(OFPPortDescProp):
    def __init__(self, type_=None, length=None, oxm_ids=None):
        oxm_ids = oxm_ids if oxm_ids else []
        super(OFPPortDescPropOxm, self).__init__(type_, length)
        self.oxm_ids = oxm_ids

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            i, rest = OFPOxmId.parse(rest)
            ids.append(i)
        return cls(oxm_ids=ids)

    def serialize_body(self):
        bin_ids = bytearray()
        for i in self.oxm_ids:
            bin_ids += i.serialize()
        return bin_ids


@OFPPortDescProp.register_type(ofproto.OFPPDPT_RECIRCULATE)
class OFPPortDescPropRecirculate(OFPPortDescProp):
    _PORT_NO_PACK_STR = '!I'

    def __init__(self, type_=None, length=None, port_nos=None):
        port_nos = port_nos if port_nos else []
        super(OFPPortDescPropRecirculate, self).__init__(type_, length)
        self.port_nos = port_nos

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        nos = []
        while rest:
            (n,) = struct.unpack_from(cls._PORT_NO_PACK_STR,
                                      six.binary_type(rest), 0)
            rest = rest[struct.calcsize(cls._PORT_NO_PACK_STR):]
            nos.append(n)
        return cls(port_nos=nos)

    def serialize_body(self):
        bin_nos = bytearray()
        for n in self.port_nos:
            bin_no = bytearray()
            msg_pack_into(self._PORT_NO_PACK_STR, bin_no, 0, n)
            bin_nos += bin_no
        return bin_nos


@OFPPortDescProp.register_type(ofproto.OFPPDPT_EXPERIMENTER)
class OFPPortDescPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPTableModProp(OFPPropBase):
    _TYPES = {}


@OFPTableModProp.register_type(ofproto.OFPTMPT_EVICTION)
class OFPTableModPropEviction(OFPTableModProp):
    def __init__(self, type_=None, length=None, flags=None):
        self.type = type_
        self.length = length
        self.flags = flags

    @classmethod
    def parser(cls, buf):
        eviction = cls()
        (eviction.type, eviction.length, eviction.flags) = struct.unpack_from(
            ofproto.OFP_TABLE_MOD_PROP_EVICTION_PACK_STR, buf, 0)
        return eviction

    def serialize(self):
        # fixup
        self.length = ofproto.OFP_TABLE_MOD_PROP_EVICTION_SIZE

        buf = bytearray()
        msg_pack_into(ofproto.OFP_TABLE_MOD_PROP_EVICTION_PACK_STR, buf, 0,
                      self.type, self.length, self.flags)
        return buf


@OFPTableModProp.register_type(ofproto.OFPTMPT_VACANCY)
class OFPTableModPropVacancy(OFPTableModProp):
    def __init__(self, type_=None, length=None, vacancy_down=None,
                 vacancy_up=None, vacancy=None):
        self.type = type_
        self.length = length
        self.vacancy_down = vacancy_down
        self.vacancy_up = vacancy_up
        self.vacancy = vacancy

    @classmethod
    def parser(cls, buf):
        vacancy = cls()
        (vacancy.type, vacancy.length, vacancy.vacancy_down,
         vacancy.vacancy_up, vacancy.vacancy) = struct.unpack_from(
            ofproto.OFP_TABLE_MOD_PROP_VACANCY_PACK_STR, buf, 0)
        return vacancy

    def serialize(self):
        # fixup
        self.length = ofproto.OFP_TABLE_MOD_PROP_VACANCY_SIZE

        buf = bytearray()
        msg_pack_into(ofproto.OFP_TABLE_MOD_PROP_VACANCY_PACK_STR, buf, 0,
                      self.type, self.length, self.vacancy_down,
                      self.vacancy_up, self.vacancy)
        return buf


@OFPTableModProp.register_type(ofproto.OFPTMPT_EXPERIMENTER)
class OFPTableModPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPQueueDescProp(OFPPropBase):
    _TYPES = {}


@OFPQueueDescProp.register_type(ofproto.OFPQDPT_MIN_RATE)
class OFPQueueDescPropMinRate(OFPQueueDescProp):
    def __init__(self, type_=None, length=None, rate=None):
        self.type = type_
        self.length = length
        self.rate = rate

    @classmethod
    def parser(cls, buf):
        minrate = cls()
        (minrate.type, minrate.length, minrate.rate) = struct.unpack_from(
            ofproto.OFP_QUEUE_DESC_PROP_MIN_RATE_PACK_STR, buf, 0)
        return minrate


@OFPQueueDescProp.register_type(ofproto.OFPQDPT_MAX_RATE)
class OFPQueueDescPropMaxRate(OFPQueueDescProp):
    def __init__(self, type_=None, length=None, rate=None):
        self.type = type_
        self.length = length
        self.rate = rate

    @classmethod
    def parser(cls, buf):
        maxrate = cls()
        (maxrate.type, maxrate.length, maxrate.rate) = struct.unpack_from(
            ofproto.OFP_QUEUE_DESC_PROP_MAX_RATE_PACK_STR, buf, 0)
        return maxrate


@OFPQueueDescProp.register_type(ofproto.OFPQDPT_EXPERIMENTER)
class OFPQueueDescPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPRoleProp(OFPPropBase):
    _TYPES = {}


@OFPRoleProp.register_type(ofproto.OFPRPT_EXPERIMENTER)
class OFPRolePropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPTime(StringifyMixin):
    def __init__(self, seconds=None, nanoseconds=None):
        self.seconds = seconds
        self.nanoseconds = nanoseconds

    @classmethod
    def parser(cls, buf, offset):
        cls_ = cls()
        (cls_.seconds, cls_.nanoseconds) = struct.unpack_from(
            ofproto.OFP_TIME_PACK_STR, buf, offset)
        return cls_

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_TIME_PACK_STR, buf, offset,
                      self.seconds, self.nanoseconds)
        return ofproto.OFP_TIME_SIZE


class OFPBundleProp(OFPPropBase):
    _TYPES = {}


@OFPBundleProp.register_type(ofproto.OFPBPT_TIME)
class OFPBundlePropTime(OFPBundleProp):
    def __init__(self, type_=None, length=None, scheduled_time=None):
        super(OFPBundlePropTime, self).__init__(type_, length)
        self.scheduled_time = scheduled_time

    @classmethod
    def parser(cls, buf):
        prop = cls()
        offset = ofproto.OFP_BUNDLE_PROP_TIME_PACK_STR0_SIZE
        prop.scheduled_time = OFPTime.parser(buf, offset)
        return prop

    def serialize(self):
        # fixup
        self.length = ofproto.OFP_BUNDLE_PROP_TIME_PACK_STR_SIZE

        buf = bytearray()
        msg_pack_into(ofproto.OFP_BUNDLE_PROP_TIME_PACK_STR0, buf, 0,
                      self.type, self.length)
        offset = ofproto.OFP_BUNDLE_PROP_TIME_PACK_STR0_SIZE
        self.scheduled_time.serialize(buf, offset)
        return buf


@OFPBundleProp.register_type(ofproto.OFPRPT_EXPERIMENTER)
class OFPBundlePropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


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

                  | OFPR_TABLE_MISS
                  | OFPR_APPLY_ACTION
                  | OFPR_INVALID_TTL
                  | OFPR_ACTION_SET
                  | OFPR_GROUP
                  | OFPR_PACKET_OUT
    table_id      ID of the table that was looked up
    cookie        Cookie of the flow entry that was looked up
    match         Instance of ``OFPMatch``
    data          Ethernet frame
    ============= =========================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.TABLE_MISS:
                reason = 'TABLE MISS'
            elif msg.reason == ofp.OFPR_APPLY_ACTION:
                reason = 'APPLY ACTION'
            elif msg.reason == ofp.OFPR_INVALID_TTL:
                reason = 'INVALID TTL'
            elif msg.reason == ofp.OFPR_ACTION_SET:
                reason = 'ACTION SET'
            elif msg.reason == ofp.OFPR_GROUP:
                reason = 'GROUP'
            elif msg.reason == ofp.OFPR_PACKET_OUT:
                reason = 'PACKET OUT'
            else:
                reason = 'unknown'

            self.logger.debug('OFPPacketIn received: '
                              'buffer_id=%x total_len=%d reason=%s '
                              'table_id=%d cookie=%d match=%s data=%s',
                              msg.buffer_id, msg.total_len, reason,
                              msg.table_id, msg.cookie, msg.match,
                              utils.hex_array(msg.data))
    """
    def __init__(self, datapath, buffer_id=None, total_len=None, reason=None,
                 table_id=None, cookie=None, match=None, data=None):
        super(OFPPacketIn, self).__init__(datapath)
        self.buffer_id = buffer_id
        self.total_len = total_len
        self.reason = reason
        self.table_id = table_id
        self.cookie = cookie
        self.match = match
        self.data = data

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPPacketIn, cls).parser(datapath, version, msg_type,
                                             msg_len, xid, buf)
        (msg.buffer_id, msg.total_len, msg.reason,
         msg.table_id, msg.cookie) = struct.unpack_from(
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
    table_id         ID of the table
    reason           One of the following values.

                     | OFPRR_IDLE_TIMEOUT
                     | OFPRR_HARD_TIMEOUT
                     | OFPRR_DELETE
                     | OFPRR_GROUP_DELETE
                     | OFPRR_METER_DELETE
                     | OFPRR_EVICTION
    priority         Priority level of flow entry
    idle_timeout     Idle timeout from original flow mod
    hard_timeout     Hard timeout from original flow mod
    cookie           Opaque controller-issued identifier
    match            Instance of ``OFPMatch``
    stats            Instance of ``OFPStats``
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
            elif msg.reason == ofp.OFPRR_METER_DELETE:
                reason = 'METER DELETE'
            elif msg.reason == ofp.OFPRR_EVICTION:
                reason = 'EVICTION'
            else:
                reason = 'unknown'

            self.logger.debug('OFPFlowRemoved received: '
                              'table_id=%d reason=%s priority=%d '
                              'idle_timeout=%d hard_timeout=%d cookie=%d '
                              'match=%s stats=%s',
                              msg.table_id, reason, msg.priority,
                              msg.idle_timeout, msg.hard_timeout, msg.cookie,
                              msg.match, msg.stats)
    """
    def __init__(self, datapath, table_id=None, reason=None, priority=None,
                 idle_timeout=None, hard_timeout=None, cookie=None,
                 match=None, stats=None):
        super(OFPFlowRemoved, self).__init__(datapath)
        self.table_id = table_id
        self.reason = reason
        self.priority = priority
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.cookie = cookie
        self.match = match
        self.stats = stats

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPFlowRemoved, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)

        (msg.table_id, msg.reason, msg.priority, msg.idle_timeout,
         msg.hard_timeout, msg.cookie) = struct.unpack_from(
            ofproto.OFP_FLOW_REMOVED_PACK_STR0,
            msg.buf, ofproto.OFP_HEADER_SIZE)
        offset = (ofproto.OFP_FLOW_REMOVED_SIZE - ofproto.OFP_MATCH_SIZE)

        msg.match = OFPMatch.parser(msg.buf, offset)
        offset += utils.round_up(msg.match.length, 8)

        stats_length = msg.msg_len - offset
        if stats_length > 0:
            msg.stats = OFPStats.parser(buf, offset)

        return msg


class OFPPort(StringifyMixin):

    """
    Description of a port

    ========== =========================================================
    Attribute  Description
    ========== =========================================================
    port_no    Port number and it uniquely identifies a port within
               a switch.
    length     Length of ofp_port (excluding padding).
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
    properties List of ``OFPPortDescProp`` subclass instance
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

    def __init__(self, port_no=None, length=None, hw_addr=None, name=None,
                 config=None, state=None, properties=None):
        super(OFPPort, self).__init__()
        self.port_no = port_no
        self.length = length
        self.hw_addr = hw_addr
        self.name = name
        self.config = config
        self.state = state
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (port_no, length, hw_addr, name, config, state) = struct.unpack_from(
            ofproto.OFP_PORT_PACK_STR, buf, offset)
        hw_addr = addrconv.mac.bin_to_text(hw_addr)
        name = name.rstrip(b'\0')
        props = []
        rest = buf[offset + ofproto.OFP_PORT_SIZE:offset + length]
        while rest:
            p, rest = OFPPortDescProp.parse(rest)
            props.append(p)
        ofpport = cls(port_no, length, hw_addr, name, config, state, props)
        return ofpport


class OFPTableDesc(StringifyMixin):
    def __init__(self, length=None, table_id=None, config=None,
                 properties=None):
        super(OFPTableDesc, self).__init__()
        self.table_id = table_id
        self.length = length
        self.config = config
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (length, table_id, config) = struct.unpack_from(
            ofproto.OFP_TABLE_DESC_PACK_STR, buf, offset)
        props = []
        rest = buf[offset + ofproto.OFP_TABLE_DESC_SIZE:offset + length]
        while rest:
            p, rest = OFPTableModProp.parse(rest)
            props.append(p)
        ofptabledesc = cls(length, table_id, config, props)
        return ofptabledesc


class OFPQueueDesc(StringifyMixin):
    def __init__(self, port_no=None, queue_id=None, len_=None,
                 properties=None):
        super(OFPQueueDesc, self).__init__()
        self.port_no = port_no
        self.queue_id = queue_id
        self.len = len_
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (port_no, queue_id, len_) = struct.unpack_from(
            ofproto.OFP_QUEUE_DESC_PACK_STR, buf, offset)
        props = []
        rest = buf[offset + ofproto.OFP_QUEUE_DESC_SIZE:offset + len_]
        while rest:
            p, rest = OFPQueueDescProp.parse(rest)
            props.append(p)
        ofpqueuedesc = cls(port_no, queue_id, len_, props)
        return ofpqueuedesc


def _set_stats_type(stats_type, stats_body_cls):
    def _set_cls_stats_type(cls):
        cls.cls_stats_type = stats_type
        cls.cls_stats_body_cls = stats_body_cls
        return cls
    return _set_cls_stats_type


@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMultipartRequest(MsgBase):
    def __init__(self, datapath, flags):
        super(OFPMultipartRequest, self).__init__(datapath)
        self.type = self.__class__.cls_stats_type
        self.flags = flags

    def _serialize_stats_body(self):
        pass

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_MULTIPART_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.type, self.flags)
        self._serialize_stats_body()


@_register_parser
@_set_msg_type(ofproto.OFPT_METER_MOD)
class OFPMeterMod(MsgBase):
    """
    Meter modification message

    The controller sends this message to modify the meter.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    command          One of the following values.

                     | OFPMC_ADD
                     | OFPMC_MODIFY
                     | OFPMC_DELETE
    flags            Bitmap of the following flags.

                     | OFPMF_KBPS
                     | OFPMF_PKTPS
                     | OFPMF_BURST
                     | OFPMF_STATS
    meter_id         Meter instance
    bands            list of the following class instance.

                     | OFPMeterBandDrop
                     | OFPMeterBandDscpRemark
                     | OFPMeterBandExperimenter
    ================ ======================================================
    """
    def __init__(self, datapath, command=ofproto.OFPMC_ADD,
                 flags=ofproto.OFPMF_KBPS, meter_id=1, bands=None):
        bands = bands if bands else []
        super(OFPMeterMod, self).__init__(datapath)
        self.command = command
        self.flags = flags
        self.meter_id = meter_id
        self.bands = bands

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPMeterMod, cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)

        (msg.command, msg.flags, msg.meter_id) = struct.unpack_from(
            ofproto.OFP_METER_MOD_PACK_STR, buf, ofproto.OFP_HEADER_SIZE)
        offset = ofproto.OFP_METER_MOD_SIZE

        msg.bands = []
        while offset < msg.msg_len:
            band = OFPMeterBandHeader.parser(buf, offset)
            msg.bands.append(band)
            offset += band.len

        return msg

    def _serialize_body(self):
        msg_pack_into(ofproto.OFP_METER_MOD_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE,
                      self.command, self.flags, self.meter_id)

        offset = ofproto.OFP_METER_MOD_SIZE
        for b in self.bands:
            b.serialize(self.buf, offset)
            offset += b.len


@_set_msg_type(ofproto.OFPT_TABLE_MOD)
class OFPTableMod(MsgBase):
    """
    Flow table configuration message

    The controller sends this message to configure table state.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         ID of the table (OFPTT_ALL indicates all tables)
    config           Bitmap of configuration flags.

                     | OFPTC_EVICTION
                     | OFPTC_VACANCY_EVENTS
    properties       List of ``OFPTableModProp`` subclass instance
    ================ ======================================================

    Example::

        def send_table_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPTableMod(datapath, 1, 3)
            flags = ofp.OFPTC_VACANCY_EVENTS
            properties = [ofp_parser.OFPTableModPropEviction(flags)]
            req = ofp_parser.OFPTableMod(datapath, 1, 3, properties)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, table_id, config, properties):
        super(OFPTableMod, self).__init__(datapath)
        self.table_id = table_id
        self.config = config
        self.properties = properties

    def _serialize_body(self):
        props_buf = bytearray()
        for p in self.properties:
            props_buf += p.serialize()

        msg_pack_into(ofproto.OFP_TABLE_MOD_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE,
                      self.table_id, self.config)

        self.buf += props_buf


@_register_parser
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
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

    def __init__(self, datapath, body=None, flags=None):
        super(OFPMultipartReply, self).__init__(datapath)
        self.body = body
        self.flags = flags

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
                                         ofproto.OFP_MULTIPART_REPLY_SIZE)
        return msg

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        type_, flags = struct.unpack_from(
            ofproto.OFP_MULTIPART_REPLY_PACK_STR, six.binary_type(buf),
            ofproto.OFP_HEADER_SIZE)
        stats_type_cls = cls._STATS_MSG_TYPES.get(type_)
        msg = super(OFPMultipartReply, stats_type_cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)
        msg.type = type_
        msg.flags = flags

        offset = ofproto.OFP_MULTIPART_REPLY_SIZE
        body = []
        while offset < msg_len:
            b = stats_type_cls.cls_stats_body_cls.parser(msg.buf, offset)
            body.append(b)
            offset += b.length if hasattr(b, 'length') else b.len

        if stats_type_cls.cls_body_single_struct:
            msg.body = body[0]
        else:
            msg.body = body
        return msg


class OFPDescStats(ofproto_parser.namedtuple('OFPDescStats', (
        'mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc'))):

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
        desc = struct.unpack_from(ofproto.OFP_DESC_PACK_STR,
                                  buf, offset)
        desc = list(desc)
        desc = [x.rstrip(b'\0') for x in desc]
        stats = cls(*desc)
        stats.length = ofproto.OFP_DESC_SIZE
        return stats


@_set_stats_type(ofproto.OFPMP_DESC, OFPDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPDescStatsRequest(OFPMultipartRequest):
    """
    Description statistics request message

    The controller uses this message to query description of the switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    ================ ======================================================

    Example::

        def send_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPDescStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, type_=None):
        super(OFPDescStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_DESC, OFPDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPDescStatsReply(OFPMultipartReply):
    """
    Description statistics reply message

    The switch responds with this message to a description statistics
    request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             Instance of ``OFPDescStats``
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
        def desc_stats_reply_handler(self, ev):
            body = ev.msg.body

            self.logger.debug('DescStats: mfr_desc=%s hw_desc=%s sw_desc=%s '
                              'serial_num=%s dp_desc=%s',
                              body.mfr_desc, body.hw_desc, body.sw_desc,
                              body.serial_num, body.dp_desc)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPDescStatsReply, self).__init__(datapath, **kwargs)


class OFPTableFeaturesStats(StringifyMixin):

    _TYPE = {
        'utf-8': [
            # OF spec is unclear about the encoding of name.
            # we assumes UTF-8.
            'name',
        ]
    }

    def __init__(self, table_id=None, command=None, features=None, name=None,
                 metadata_match=None, metadata_write=None, capabilities=None,
                 max_entries=None, properties=None, length=None):
        super(OFPTableFeaturesStats, self).__init__()
        self.length = length
        self.table_id = table_id
        self.command = command
        self.features = features
        self.name = name
        self.metadata_match = metadata_match
        self.metadata_write = metadata_write
        self.capabilities = capabilities
        self.max_entries = max_entries
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        tbl = cls()
        (tbl.length, tbl.table_id, tbl.command, tbl.features,
         name, tbl.metadata_match, tbl.metadata_write,
         tbl.capabilities, tbl.max_entries
         ) = struct.unpack_from(ofproto.OFP_TABLE_FEATURES_PACK_STR,
                                buf, offset)
        tbl.name = name.rstrip(b'\0')

        props = []
        rest = buf[offset + ofproto.OFP_TABLE_FEATURES_SIZE:
                   offset + tbl.length]
        while rest:
            p, rest = OFPTableFeatureProp.parse(rest)
            props.append(p)
        tbl.properties = props

        return tbl

    def serialize(self):
        # fixup
        bin_props = bytearray()
        for p in self.properties:
            bin_props += p.serialize()
        self.length = ofproto.OFP_TABLE_FEATURES_SIZE + len(bin_props)

        buf = bytearray()
        msg_pack_into(ofproto.OFP_TABLE_FEATURES_PACK_STR, buf, 0,
                      self.length, self.table_id, self.command, self.features,
                      self.name, self.metadata_match, self.metadata_write,
                      self.capabilities, self.max_entries)
        return buf + bin_props


class OFPTableFeatureProp(OFPPropBase):
    _TYPES = {}


class OFPInstructionId(StringifyMixin):
    _PACK_STR = '!HH'  # type, len

    def __init__(self, type_, len_=None):
        self.type = type_
        self.len = len_
        # XXX experimenter

    @classmethod
    def parse(cls, buf):
        (type_, len_,) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf), 0)
        rest = buf[len_:]
        return cls(type_=type_, len_=len_), rest

    def serialize(self):
        # fixup
        self.len = struct.calcsize(self._PACK_STR)

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type, self.len)
        return buf


@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_INSTRUCTIONS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_INSTRUCTIONS_MISS)
class OFPTableFeaturePropInstructions(OFPTableFeatureProp):
    def __init__(self, type_=None, length=None, instruction_ids=None):
        instruction_ids = instruction_ids if instruction_ids else []
        super(OFPTableFeaturePropInstructions, self).__init__(type_, length)
        self.instruction_ids = instruction_ids

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            i, rest = OFPInstructionId.parse(rest)
            ids.append(i)
        return cls(instruction_ids=ids)

    def serialize_body(self):
        bin_ids = bytearray()
        for i in self.instruction_ids:
            bin_ids += i.serialize()

        return bin_ids


# Implementation note: While OpenFlow 1.3.2 shares the same ofp_action_header
# for flow_mod and table_features, we have separate classes.  We named this
# class to match with OpenFlow 1.4's name.  (ofp_action_id)
class OFPActionId(StringifyMixin):
    _PACK_STR = '!HH'  # type, len

    def __init__(self, type_, len_=None):
        self.type = type_
        self.len = len_
        # XXX experimenter

    @classmethod
    def parse(cls, buf):
        (type_, len_,) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf), 0)
        rest = buf[len_:]
        return cls(type_=type_, len_=len_), rest

    def serialize(self):
        # fixup
        self.len = struct.calcsize(self._PACK_STR)

        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type, self.len)
        return buf


@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_ACTIONS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_ACTIONS_MISS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_ACTIONS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_ACTIONS_MISS)
class OFPTableFeaturePropActions(OFPTableFeatureProp):
    def __init__(self, type_=None, length=None, action_ids=None):
        action_ids = action_ids if action_ids else []
        super(OFPTableFeaturePropActions, self).__init__(type_, length)
        self.action_ids = action_ids

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            i, rest = OFPActionId.parse(rest)
            ids.append(i)
        return cls(action_ids=ids)

    def serialize_body(self):
        bin_ids = bytearray()
        for i in self.action_ids:
            bin_ids += i.serialize()
        return bin_ids


@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_NEXT_TABLES)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_NEXT_TABLES_MISS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_TABLE_SYNC_FROM)
class OFPTableFeaturePropNextTables(OFPTableFeatureProp):
    _TABLE_ID_PACK_STR = '!B'

    def __init__(self, type_=None, length=None, table_ids=None):
        table_ids = table_ids if table_ids else []
        super(OFPTableFeaturePropNextTables, self).__init__(type_, length)
        self.table_ids = table_ids

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            (i,) = struct.unpack_from(cls._TABLE_ID_PACK_STR, six.binary_type(rest), 0)
            rest = rest[struct.calcsize(cls._TABLE_ID_PACK_STR):]
            ids.append(i)
        return cls(table_ids=ids)

    def serialize_body(self):
        bin_ids = bytearray()
        for i in self.table_ids:
            bin_id = bytearray()
            msg_pack_into(self._TABLE_ID_PACK_STR, bin_id, 0, i)
            bin_ids += bin_id
        return bin_ids


# Implementation note: OFPOxmId is specific to this implementation.
# It does not have a corresponding structure in the specification.
# (the specification uses plain uint32_t for non-experimenter OXMs
# and uint64_t for experimenter OXMs.)
#
# i have taken a look at some of software switch implementations
# but they all look broken or incomplete.  according to the spec,
# oxm_hasmask should be 1 if a switch supports masking for the type.
# the right value for oxm_length is not clear from the spec.
# update: OpenFlow 1.3.3 "clarified" that oxm_length here is the payload
# length.  it's still unclear if it should be doubled for hasmask or not,
# though.
#   ofsoftswitch13
#     oxm_hasmask  always 0
#     oxm_length   same as ofp_match etc (as without mask)
#   linc/of_protocol
#     oxm_hasmask  always 0
#     oxm_length   always 0
#   ovs:
#     seems in flux as of writing this [20141003]
class OFPOxmId(StringifyMixin):
    _PACK_STR = '!I'  # oxm header
    _EXPERIMENTER_ID_PACK_STR = '!I'

    _TYPE = {
        'ascii': [
            'type',
        ],
    }

    def __init__(self, type_, hasmask=False, length=None):
        self.type = type_
        self.hasmask = hasmask
        self.length = length

    @classmethod
    def parse(cls, buf):
        (oxm,) = struct.unpack_from(cls._PACK_STR, six.binary_type(buf), 0)
        # oxm (32 bit) == class (16) | field (7) | hasmask (1) | length (8)
        # in case of experimenter OXMs, another 32 bit value
        # (experimenter id) follows.
        (type_, _v) = ofproto.oxm_to_user(oxm >> (1 + 8), None, None)
        rest = buf[struct.calcsize(cls._PACK_STR):]
        hasmask = ofproto.oxm_tlv_header_extract_hasmask(oxm)
        length = oxm & 0xff  # XXX see the comment on OFPOxmId
        class_ = oxm >> (7 + 1 + 8)
        if class_ == ofproto.OFPXMC_EXPERIMENTER:
            (exp_id,) = struct.unpack_from(cls._EXPERIMENTER_ID_PACK_STR,
                                           six.binary_type(rest), 0)
            rest = rest[struct.calcsize(cls._EXPERIMENTER_ID_PACK_STR):]
            subcls = OFPExperimenterOxmId
            return subcls(type_=type_, exp_id=exp_id, hasmask=hasmask,
                          length=length), rest
        else:
            return cls(type_=type_, hasmask=hasmask, length=length), rest

    def serialize(self):
        # fixup
        self.length = 0  # XXX see the comment on OFPOxmId

        (n, _v, _m) = ofproto.oxm_from_user(self.type, None)
        oxm = (n << (1 + 8)) | (self.hasmask << 8) | self.length
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, oxm)
        assert n >> 7 != ofproto.OFPXMC_EXPERIMENTER
        return buf


class OFPExperimenterOxmId(OFPOxmId):
    def __init__(self, type_, exp_id, hasmask=False, length=None):
        super(OFPExperimenterOxmId, self).__init__(type_=type_,
                                                   hasmask=hasmask,
                                                   length=length)
        self.exp_id = exp_id

    def serialize(self):
        buf = super(OFPExperimenterOxmId, self).serialize()
        msg_pack_into(self._EXPERIMENTER_ID_PACK_STR, buf,
                      struct.calcsize(self._PACK_STR), self.exp_id)


@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_MATCH)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WILDCARDS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_SETFIELD)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_SETFIELD_MISS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_SETFIELD)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_SETFIELD_MISS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_COPYFIELD)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_COPYFIELD_MISS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_COPYFIELD)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_COPYFIELD_MISS)
class OFPTableFeaturePropOxm(OFPTableFeatureProp):
    def __init__(self, type_=None, length=None, oxm_ids=None):
        oxm_ids = oxm_ids if oxm_ids else []
        super(OFPTableFeaturePropOxm, self).__init__(type_, length)
        self.oxm_ids = oxm_ids

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            i, rest = OFPOxmId.parse(rest)
            ids.append(i)
        return cls(oxm_ids=ids)

    def serialize_body(self):
        bin_ids = bytearray()
        for i in self.oxm_ids:
            bin_ids += i.serialize()
        return bin_ids


@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_PACKET_TYPES)
class OFPTableFeaturePropOxmValues(OFPTableFeatureProp):
    def __init__(self, type_=None, length=None, _ordered_values=None,
                 **kwargs):
        super(OFPTableFeaturePropOxmValues, self).__init__(type_, length)
        if _ordered_values is not None:
            assert not kwargs
            self.oxm_values = _ordered_values
        else:
            kwargs = dict(ofproto.oxm_normalize_user(k, v) for
                          (k, v) in kwargs.items())
            values = [ofproto.oxm_from_user(k, v) for (k, v)
                      in kwargs.items()]
            # assumption: sorting by OXM type values makes fields
            # meet ordering requirements (eg. eth_type before ipv4_src)
            values.sort(
                key=lambda x: x[0][0] if isinstance(x[0], tuple) else x[0])
            self.oxm_values = [ofproto.oxm_to_user(n, v, m) for (n, v, m)
                               in values]

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        values = []
        while rest:
            n, value, mask, field_len = ofproto.oxm_parse(rest, 0)
            k, uv = ofproto.oxm_to_user(n, value, mask)
            values.append((k, uv))
            rest = rest[field_len:]
        return cls(_ordered_values=values)

    def serialize_body(self):
        values = [ofproto.oxm_from_user(k, uv) for (k, uv)
                  in self.oxm_values]
        offset = 0
        buf = bytearray()
        for (n, value, mask) in values:
            offset += ofproto.oxm_serialize(n, value, mask, buf, offset)
        return buf

    def __getitem__(self, key):
        return dict(self.oxm_values)[key]

    def __contains__(self, key):
        return key in dict(self.oxm_values)

    def iteritems(self):
        return iter(dict(self.oxm_values).items())

    def items(self):
        return self.oxm_values

    def get(self, key, default=None):
        return dict(self.oxm_values).get(key, default)

    def stringify_attrs(self):
        yield "oxm_values", dict(self.oxm_values)

    def to_jsondict(self):
        """
        Returns a dict expressing the OXM values.
        """
        body = {"oxm_values": [ofproto.oxm_to_jsondict(k, uv) for k, uv
                               in self.oxm_values],
                "length": self.length,
                "type": self.type}
        return {self.__class__.__name__: body}

    @classmethod
    def from_jsondict(cls, dict_):
        """
        Returns an object which is generated from a dict.
        Exception raises:
        KeyError -- Unknown OXM value is defined in dict
        """
        type_ = dict_['type']
        values = [ofproto.oxm_from_jsondict(f) for f
                  in dict_['oxm_values']]
        return cls(type_=type_, _ordered_values=values)


@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_EXPERIMENTER)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_EXPERIMENTER_MISS)
class OFPTableFeaturePropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


@_set_stats_type(ofproto.OFPMP_TABLE_FEATURES, OFPTableFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPTableFeaturesStatsRequest(OFPMultipartRequest):
    """
    Table features statistics request message

    The controller uses this message to query table features.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPTableFeaturesStats`` instances.
                     The default is [].
    ================ ======================================================
    """
    def __init__(self, datapath, flags=0, body=None, type_=None):
        body = body if body else []
        super(OFPTableFeaturesStatsRequest, self).__init__(datapath, flags)
        self.body = body

    def _serialize_stats_body(self):
        bin_body = bytearray()
        for p in self.body:
            bin_body += p.serialize()
        self.buf += bin_body


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_TABLE_FEATURES, OFPTableFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPTableFeaturesStatsReply(OFPMultipartReply):
    """
    Table features statistics reply message

    The switch responds with this message to a table features statistics
    request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPTableFeaturesStats`` instance
    ================ ======================================================
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPTableFeaturesStatsReply, self).__init__(datapath, **kwargs)


@_set_stats_type(ofproto.OFPMP_PORT_DESC, OFPPort)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPPortDescStatsRequest(OFPMultipartRequest):
    """
    Port description request message

    The controller uses this message to query description of one or all the ports.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    port_no          Port number to read (OFPP_ANY to all ports)
    ================ ======================================================

    Example::

        def send_port_desc_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPPortDescStatsRequest(datapath, 0, ofp.OFPP_ANY)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, port_no=ofproto.OFPP_ANY, type_=None):
        super(OFPPortDescStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_PORT_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.port_no)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_PORT_DESC, OFPPort)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPPortDescStatsReply(OFPMultipartReply):
    """
    Port description reply message

    The switch responds with this message to a port description request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPPort`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
        def port_desc_stats_reply_handler(self, ev):
            ports = []
            for p in ev.msg.body:
                ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                             'state=0x%08x properties=%s' %
                             (p.port_no, p.hw_addr,
                              p.name, p.config, p.state, repr(p.properties)))
            self.logger.debug('OFPPortDescStatsReply received: %s', ports)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPPortDescStatsReply, self).__init__(datapath, **kwargs)


@_set_stats_type(ofproto.OFPMP_TABLE_DESC, OFPTableDesc)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPTableDescStatsRequest(OFPMultipartRequest):
    """
    Table description request message

    The controller uses this message to query description of all the tables.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    ================ ======================================================

    Example::

        def send_table_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPTableDescStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, type_=None):
        super(OFPTableDescStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_TABLE_DESC, OFPTableDesc)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPTableDescStatsReply(OFPMultipartReply):
    """
    Table description reply message

    The switch responds with this message to a table description request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPTableDesc`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPTableDescStatsReply, MAIN_DISPATCHER)
        def table_desc_stats_reply_handler(self, ev):
            tables = []
            for p in ev.msg.body:
                tables.append('table_id=%d config=0x%08x properties=%s' %
                             (p.table_id, p.config, repr(p.properties)))
            self.logger.debug('OFPTableDescStatsReply received: %s', tables)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPTableDescStatsReply, self).__init__(datapath, **kwargs)


@_set_stats_type(ofproto.OFPMP_QUEUE_DESC, OFPQueueDesc)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPQueueDescStatsRequest(OFPMultipartRequest):
    """
    Queue description request message

    The controller uses this message to query description of all the queues.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    port_no          Port number to read (OFPP_ANY for all ports)
    queue_id         ID of queue to read (OFPQ_ALL for all queues)
    ================ ======================================================

    Example::

        def send_queue_desc_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPQueueDescStatsRequest(datapath, 0,
                                                      ofp.OFPP_ANY,
                                                      ofp.OFPQ_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, port_no=ofproto.OFPP_ANY,
                 queue_id=ofproto.OFPQ_ALL, type_=None):
        super(OFPQueueDescStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no
        self.queue_id = queue_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_QUEUE_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.port_no, self.queue_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_QUEUE_DESC, OFPQueueDesc)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPQueueDescStatsReply(OFPMultipartReply):
    """
    Queue description reply message

    The switch responds with this message to a queue description request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPQueueDesc`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPQueueDescStatsReply, MAIN_DISPATCHER)
        def queue_desc_stats_reply_handler(self, ev):
            queues = []
            for q in ev.msg.body:
                queues.append('port_no=%d queue_id=0x%08x properties=%s' %
                             (q.port_no, q.queue_id, repr(q.properties)))
            self.logger.debug('OFPQueueDescStatsReply received: %s', queues)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPQueueDescStatsReply, self).__init__(datapath, **kwargs)


class OFPQueueStatsProp(OFPPropBase):
    _TYPES = {}


@OFPQueueStatsProp.register_type(ofproto.OFPQSPT_EXPERIMENTER)
class OFPQueueStatsPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPQueueStats(StringifyMixin):
    def __init__(self, length=None, port_no=None, queue_id=None,
                 tx_bytes=None, tx_packets=None, tx_errors=None,
                 duration_sec=None, duration_nsec=None, properties=None):
        super(OFPQueueStats, self).__init__()
        self.length = length
        self.port_no = port_no
        self.queue_id = queue_id
        self.tx_bytes = tx_bytes
        self.tx_packets = tx_packets
        self.tx_errors = tx_errors
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (length, port_no, queue_id, tx_bytes, tx_packets, tx_errors,
         duration_sec, duration_nsec) = struct.unpack_from(
            ofproto.OFP_QUEUE_STATS_PACK_STR, buf, offset)
        props = []
        rest = buf[offset + ofproto.OFP_QUEUE_STATS_SIZE:offset + length]
        while rest:
            p, rest = OFPQueueStatsProp.parse(rest)
            props.append(p)
        stats = cls(length, port_no, queue_id, tx_bytes, tx_packets, tx_errors,
                    duration_sec, duration_nsec, props)
        return stats


@_set_stats_type(ofproto.OFPMP_QUEUE_STATS, OFPQueueStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPQueueStatsRequest(OFPMultipartRequest):
    """
    Queue statistics request message

    The controller uses this message to query queue statictics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    port_no          Port number to read
    queue_id         ID of queue to read
    ================ ======================================================

    Example::

        def send_queue_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPQueueStatsRequest(datapath, 0, ofp.OFPP_ANY,
                                                  ofp.OFPQ_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, port_no=ofproto.OFPP_ANY,
                 queue_id=ofproto.OFPQ_ALL, type_=None):
        super(OFPQueueStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no
        self.queue_id = queue_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_QUEUE_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.port_no, self.queue_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_QUEUE_STATS, OFPQueueStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPQueueStatsReply(OFPMultipartReply):
    """
    Queue statistics reply message

    The switch responds with this message to an aggregate flow statistics
    request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPQueueStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
        def queue_stats_reply_handler(self, ev):
            queues = []
            for stat in ev.msg.body:
                queues.append('port_no=%d queue_id=%d '
                              'tx_bytes=%d tx_packets=%d tx_errors=%d '
                              'duration_sec=%d duration_nsec=%d'
                              'properties=%s' %
                              (stat.port_no, stat.queue_id,
                               stat.tx_bytes, stat.tx_packets, stat.tx_errors,
                               stat.duration_sec, stat.duration_nsec,
                               repr(stat.properties)))
            self.logger.debug('QueueStats: %s', queues)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPQueueStatsReply, self).__init__(datapath, **kwargs)


class OFPBucketCounter(StringifyMixin):
    def __init__(self, packet_count, byte_count):
        super(OFPBucketCounter, self).__init__()
        self.packet_count = packet_count
        self.byte_count = byte_count

    @classmethod
    def parser(cls, buf, offset):
        packet_count, byte_count = struct.unpack_from(
            ofproto.OFP_BUCKET_COUNTER_PACK_STR, buf, offset)
        return cls(packet_count, byte_count)


class OFPGroupStats(StringifyMixin):
    def __init__(self, length=None, group_id=None, ref_count=None,
                 packet_count=None, byte_count=None, duration_sec=None,
                 duration_nsec=None, bucket_stats=None):
        super(OFPGroupStats, self).__init__()
        self.length = length
        self.group_id = group_id
        self.ref_count = ref_count
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.bucket_stats = bucket_stats

    @classmethod
    def parser(cls, buf, offset):
        group = struct.unpack_from(ofproto.OFP_GROUP_STATS_PACK_STR,
                                   buf, offset)
        group_stats = cls(*group)

        group_stats.bucket_stats = []
        total_len = group_stats.length + offset
        offset += ofproto.OFP_GROUP_STATS_SIZE
        while total_len > offset:
            b = OFPBucketCounter.parser(buf, offset)
            group_stats.bucket_stats.append(b)
            offset += ofproto.OFP_BUCKET_COUNTER_SIZE

        return group_stats


@_set_stats_type(ofproto.OFPMP_GROUP_STATS, OFPGroupStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPGroupStatsRequest(OFPMultipartRequest):
    """
    Group statistics request message

    The controller uses this message to query statistics of one or more
    groups.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    group_id         ID of group to read (OFPG_ALL to all groups)
    ================ ======================================================

    Example::

        def send_group_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGroupStatsRequest(datapath, 0, ofp.OFPG_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, group_id=ofproto.OFPG_ALL,
                 type_=None):
        super(OFPGroupStatsRequest, self).__init__(datapath, flags)
        self.group_id = group_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_GROUP_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.group_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_GROUP_STATS, OFPGroupStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPGroupStatsReply(OFPMultipartReply):
    """
    Group statistics reply message

    The switch responds with this message to a group statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPGroupStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPGroupStatsReply, MAIN_DISPATCHER)
        def group_stats_reply_handler(self, ev):
            groups = []
            for stat in ev.msg.body:
                groups.append('length=%d group_id=%d '
                              'ref_count=%d packet_count=%d byte_count=%d '
                              'duration_sec=%d duration_nsec=%d' %
                              (stat.length, stat.group_id,
                               stat.ref_count, stat.packet_count,
                               stat.byte_count, stat.duration_sec,
                               stat.duration_nsec))
            self.logger.debug('GroupStats: %s', groups)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPGroupStatsReply, self).__init__(datapath, **kwargs)


class OFPGroupDescStats(StringifyMixin):
    def __init__(self, type_=None, group_id=None, buckets=None, properties=None,
                 length=None, bucket_array_len=None):
        buckets = buckets if buckets else []
        properties = properties if properties else []
        super(OFPGroupDescStats, self).__init__()
        self.length = length
        self.type = type_
        self.group_id = group_id
        self.buckets = buckets
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        stats = cls()

        (stats.length, stats.type, stats.group_id,
         stats.bucket_array_len) = struct.unpack_from(
            ofproto.OFP_GROUP_DESC_STATS_PACK_STR, buf, offset)
        offset += ofproto.OFP_GROUP_DESC_STATS_SIZE

        bucket_buf = buf[offset:offset + stats.bucket_array_len]
        stats.buckets = []
        while bucket_buf:
            bucket = OFPBucket.parser(bucket_buf, 0)
            stats.buckets.append(bucket)
            bucket_buf = bucket_buf[bucket.len:]
        offset += stats.bucket_array_len

        rest = buf[offset:offset + stats.length]
        while rest:
            p, rest = OFPGroupProp.parse(rest)
            stats.properties.append(p)

        return stats


@_set_stats_type(ofproto.OFPMP_GROUP_DESC, OFPGroupDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPGroupDescStatsRequest(OFPMultipartRequest):
    """
    Group description request message

    The controller uses this message to list the set of groups on a switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    group_id         ID of group to read (OFPG_ALL to all groups)
    ================ ======================================================

    Example::

        def send_group_desc_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGroupDescStatsRequest(datapath, 0, ofp.OFPG_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, group_id=ofproto.OFPG_ALL,
                 type_=None):
        super(OFPGroupDescStatsRequest, self).__init__(datapath, flags)
        self.group_id = group_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_GROUP_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.group_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_GROUP_DESC, OFPGroupDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPGroupDescStatsReply(OFPMultipartReply):
    """
    Group description reply message

    The switch responds with this message to a group description request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPGroupDescStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPGroupDescStatsReply, MAIN_DISPATCHER)
        def group_desc_stats_reply_handler(self, ev):
            descs = []
            for stat in ev.msg.body:
                descs.append('length=%d type=%d group_id=%d '
                             'buckets=%s properties=%s' %
                             (stat.length, stat.type, stat.group_id,
                              stat.bucket, repr(stat.properties)))
            self.logger.debug('GroupDescStats: %s', descs)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPGroupDescStatsReply, self).__init__(datapath, **kwargs)


class OFPGroupFeaturesStats(ofproto_parser.namedtuple('OFPGroupFeaturesStats',
                            ('types', 'capabilities', 'max_groups',
                             'actions'))):
    @classmethod
    def parser(cls, buf, offset):
        group_features = struct.unpack_from(
            ofproto.OFP_GROUP_FEATURES_PACK_STR, buf, offset)
        types = group_features[0]
        capabilities = group_features[1]
        max_groups = list(group_features[2:6])
        actions = list(group_features[6:10])
        stats = cls(types, capabilities, max_groups, actions)
        stats.length = ofproto.OFP_GROUP_FEATURES_SIZE
        return stats


@_set_stats_type(ofproto.OFPMP_GROUP_FEATURES, OFPGroupFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPGroupFeaturesStatsRequest(OFPMultipartRequest):
    """
    Group features request message

    The controller uses this message to list the capabilities of groups on
    a switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    ================ ======================================================

    Example::

        def send_group_features_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGroupFeaturesStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, type_=None):
        super(OFPGroupFeaturesStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_GROUP_FEATURES, OFPGroupFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPGroupFeaturesStatsReply(OFPMultipartReply):
    """
    Group features reply message

    The switch responds with this message to a group features request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             Instance of ``OFPGroupFeaturesStats``
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPGroupFeaturesStatsReply, MAIN_DISPATCHER)
        def group_features_stats_reply_handler(self, ev):
            body = ev.msg.body

            self.logger.debug('GroupFeaturesStats: types=%d '
                              'capabilities=0x%08x max_groups=%s '
                              'actions=%s',
                              body.types, body.capabilities,
                              body.max_groups, body.actions)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPGroupFeaturesStatsReply, self).__init__(datapath, **kwargs)


class OFPMeterBandStats(StringifyMixin):
    def __init__(self, packet_band_count, byte_band_count):
        super(OFPMeterBandStats, self).__init__()
        self.packet_band_count = packet_band_count
        self.byte_band_count = byte_band_count

    @classmethod
    def parser(cls, buf, offset):
        band_stats = struct.unpack_from(
            ofproto.OFP_METER_BAND_STATS_PACK_STR, buf, offset)
        return cls(*band_stats)


class OFPMeterStats(StringifyMixin):
    def __init__(self, meter_id=None, ref_count=None, packet_in_count=None,
                 byte_in_count=None, duration_sec=None, duration_nsec=None,
                 band_stats=None, len_=None):
        super(OFPMeterStats, self).__init__()
        self.meter_id = meter_id
        self.len = 0
        self.ref_count = ref_count
        self.packet_in_count = packet_in_count
        self.byte_in_count = byte_in_count
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.band_stats = band_stats

    @classmethod
    def parser(cls, buf, offset):
        meter_stats = cls()

        (meter_stats.meter_id, meter_stats.len,
         meter_stats.ref_count, meter_stats.packet_in_count,
         meter_stats.byte_in_count, meter_stats.duration_sec,
         meter_stats.duration_nsec) = struct.unpack_from(
            ofproto.OFP_METER_STATS_PACK_STR, buf, offset)
        offset += ofproto.OFP_METER_STATS_SIZE

        meter_stats.band_stats = []
        length = ofproto.OFP_METER_STATS_SIZE
        while length < meter_stats.len:
            band_stats = OFPMeterBandStats.parser(buf, offset)
            meter_stats.band_stats.append(band_stats)
            offset += ofproto.OFP_METER_BAND_STATS_SIZE
            length += ofproto.OFP_METER_BAND_STATS_SIZE

        return meter_stats


@_set_stats_type(ofproto.OFPMP_METER_STATS, OFPMeterStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMeterStatsRequest(OFPMultipartRequest):
    """
    Meter statistics request message

    The controller uses this message to query statistics for one or more
    meters.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    meter_id         ID of meter to read (OFPM_ALL to all meters)
    ================ ======================================================

    Example::

        def send_meter_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPMeterStatsRequest(datapath, 0, ofp.OFPM_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, meter_id=ofproto.OFPM_ALL,
                 type_=None):
        super(OFPMeterStatsRequest, self).__init__(datapath, flags)
        self.meter_id = meter_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_METER_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.meter_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_METER_STATS, OFPMeterStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPMeterStatsReply(OFPMultipartReply):
    """
    Meter statistics reply message

    The switch responds with this message to a meter statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPMeterStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
        def meter_stats_reply_handler(self, ev):
            meters = []
            for stat in ev.msg.body:
                meters.append('meter_id=0x%08x len=%d ref_count=%d '
                              'packet_in_count=%d byte_in_count=%d '
                              'duration_sec=%d duration_nsec=%d '
                              'band_stats=%s' %
                              (stat.meter_id, stat.len, stat.ref_count,
                               stat.packet_in_count, stat.byte_in_count,
                               stat.duration_sec, stat.duration_nsec,
                               stat.band_stats))
            self.logger.debug('MeterStats: %s', meters)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPMeterStatsReply, self).__init__(datapath, **kwargs)


class OFPMeterBand(StringifyMixin):
    def __init__(self, type_, len_):
        super(OFPMeterBand, self).__init__()
        self.type = type_
        self.len = len_


class OFPMeterBandHeader(OFPMeterBand):
    _METER_BAND = {}

    @staticmethod
    def register_meter_band_type(type_, len_):
        def _register_meter_band_type(cls):
            OFPMeterBandHeader._METER_BAND[type_] = cls
            cls.cls_meter_band_type = type_
            cls.cls_meter_band_len = len_
            return cls
        return _register_meter_band_type

    def __init__(self):
        cls = self.__class__
        super(OFPMeterBandHeader, self).__init__(cls.cls_meter_band_type,
                                                 cls.cls_meter_band_len)

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, _rate, _burst_size = struct.unpack_from(
            ofproto.OFP_METER_BAND_HEADER_PACK_STR, buf, offset)
        cls_ = cls._METER_BAND[type_]
        assert cls_.cls_meter_band_len == len_
        return cls_.parser(buf, offset)


@OFPMeterBandHeader.register_meter_band_type(
    ofproto.OFPMBT_DROP, ofproto.OFP_METER_BAND_DROP_SIZE)
class OFPMeterBandDrop(OFPMeterBandHeader):
    def __init__(self, rate=0, burst_size=0, type_=None, len_=None):
        super(OFPMeterBandDrop, self).__init__()
        self.rate = rate
        self.burst_size = burst_size

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_METER_BAND_DROP_PACK_STR, buf, offset,
                      self.type, self.len, self.rate, self.burst_size)

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, rate, burst_size = struct.unpack_from(
            ofproto.OFP_METER_BAND_DROP_PACK_STR, buf, offset)
        assert cls.cls_meter_band_type == type_
        assert cls.cls_meter_band_len == len_
        return cls(rate, burst_size)


@OFPMeterBandHeader.register_meter_band_type(
    ofproto.OFPMBT_DSCP_REMARK,
    ofproto.OFP_METER_BAND_DSCP_REMARK_SIZE)
class OFPMeterBandDscpRemark(OFPMeterBandHeader):
    def __init__(self, rate=0, burst_size=0, prec_level=0,
                 type_=None, len_=None):
        super(OFPMeterBandDscpRemark, self).__init__()
        self.rate = rate
        self.burst_size = burst_size
        self.prec_level = prec_level

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_METER_BAND_DSCP_REMARK_PACK_STR, buf,
                      offset, self.type, self.len, self.rate,
                      self.burst_size, self.prec_level)

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, rate, burst_size, prec_level = struct.unpack_from(
            ofproto.OFP_METER_BAND_DSCP_REMARK_PACK_STR, buf, offset)
        assert cls.cls_meter_band_type == type_
        assert cls.cls_meter_band_len == len_
        return cls(rate, burst_size, prec_level)


@OFPMeterBandHeader.register_meter_band_type(
    ofproto.OFPMBT_EXPERIMENTER,
    ofproto.OFP_METER_BAND_EXPERIMENTER_SIZE)
class OFPMeterBandExperimenter(OFPMeterBandHeader):
    def __init__(self, rate=0, burst_size=0, experimenter=None,
                 type_=None, len_=None):
        super(OFPMeterBandExperimenter, self).__init__()
        self.rate = rate
        self.burst_size = burst_size
        self.experimenter = experimenter

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_METER_BAND_EXPERIMENTER_PACK_STR, buf,
                      offset, self.type, self.len, self.rate,
                      self.burst_size, self.experimenter)

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, rate, burst_size, experimenter = struct.unpack_from(
            ofproto.OFP_METER_BAND_EXPERIMENTER_PACK_STR, buf, offset)
        assert cls.cls_meter_band_type == type_
        assert cls.cls_meter_band_len == len_
        return cls(rate, burst_size, experimenter)


class OFPMeterDescStats(StringifyMixin):
    def __init__(self, flags=None, meter_id=None, bands=None, length=None):
        super(OFPMeterDescStats, self).__init__()
        self.length = None
        self.flags = flags
        self.meter_id = meter_id
        self.bands = bands

    @classmethod
    def parser(cls, buf, offset):
        meter_config = cls()

        (meter_config.length, meter_config.flags,
         meter_config.meter_id) = struct.unpack_from(
            ofproto.OFP_METER_DESC_PACK_STR, buf, offset)
        offset += ofproto.OFP_METER_DESC_SIZE

        meter_config.bands = []
        length = ofproto.OFP_METER_DESC_SIZE
        while length < meter_config.length:
            band = OFPMeterBandHeader.parser(buf, offset)
            meter_config.bands.append(band)
            offset += band.len
            length += band.len

        return meter_config


@_set_stats_type(ofproto.OFPMP_METER_DESC, OFPMeterDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMeterDescStatsRequest(OFPMultipartRequest):
    """
    Meter description statistics request message

    The controller uses this message to query configuration for one or more
    meters.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    meter_id         ID of meter to read (OFPM_ALL to all meters)
    ================ ======================================================

    Example::

        def send_meter_desc_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPMeterDescStatsRequest(datapath, 0,
                                                        ofp.OFPM_ALL)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, meter_id=ofproto.OFPM_ALL,
                 type_=None):
        super(OFPMeterDescStatsRequest, self).__init__(datapath, flags)
        self.meter_id = meter_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_METER_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.meter_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_METER_DESC, OFPMeterDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPMeterDescStatsReply(OFPMultipartReply):
    """
    Meter description statistics reply message

    The switch responds with this message to a meter description
    statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPMeterDescStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPMeterDescStatsReply, MAIN_DISPATCHER)
        def meter_desc_stats_reply_handler(self, ev):
            configs = []
            for stat in ev.msg.body:
                configs.append('length=%d flags=0x%04x meter_id=0x%08x '
                               'bands=%s' %
                               (stat.length, stat.flags, stat.meter_id,
                                stat.bands))
            self.logger.debug('MeterDescStats: %s', configs)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPMeterDescStatsReply, self).__init__(datapath, **kwargs)


class OFPMeterFeaturesStats(ofproto_parser.namedtuple('OFPMeterFeaturesStats',
                            ('max_meter', 'band_types', 'capabilities',
                             'max_bands', 'max_color', 'features'))):
    @classmethod
    def parser(cls, buf, offset):
        meter_features = struct.unpack_from(
            ofproto.OFP_METER_FEATURES_PACK_STR, buf, offset)
        stats = cls(*meter_features)
        stats.length = ofproto.OFP_METER_FEATURES_SIZE
        return stats


@_set_stats_type(ofproto.OFPMP_METER_FEATURES, OFPMeterFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMeterFeaturesStatsRequest(OFPMultipartRequest):
    """
    Meter features statistics request message

    The controller uses this message to query the set of features of the
    metering subsystem.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    ================ ======================================================

    Example::

        def send_meter_features_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPMeterFeaturesStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, type_=None):
        super(OFPMeterFeaturesStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_METER_FEATURES, OFPMeterFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPMeterFeaturesStatsReply(OFPMultipartReply):
    """
    Meter features statistics reply message

    The switch responds with this message to a meter features statistics
    request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPMeterFeaturesStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPMeterFeaturesStatsReply, MAIN_DISPATCHER)
        def meter_features_stats_reply_handler(self, ev):
            features = []
            for stat in ev.msg.body:
                features.append('max_meter=%d band_types=0x%08x '
                                'capabilities=0x%08x max_bands=%d '
                                'max_color=%d' %
                                (stat.max_meter, stat.band_types,
                                 stat.capabilities, stat.max_bands,
                                 stat.max_color))
            self.logger.debug('MeterFeaturesStats: %s', features)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPMeterFeaturesStatsReply, self).__init__(datapath, **kwargs)


class OFPFlowUpdate(StringifyMixin):
    def __init__(self, length, event):
        super(OFPFlowUpdate, self).__init__()
        self.length = length
        self.event = event


class OFPFlowUpdateHeader(OFPFlowUpdate):
    _EVENT = {}

    @staticmethod
    def register_flow_update_event(event, length):
        def _register_flow_update_event(cls):
            OFPFlowUpdateHeader._EVENT[event] = cls
            cls.cls_flow_update_event = event
            cls.cls_flow_update_length = length
            return cls
        return _register_flow_update_event

    def __init__(self, length=None, event=None):
        cls = self.__class__
        super(OFPFlowUpdateHeader, self).__init__(length,
                                                  cls.cls_flow_update_event)
        self.length = length

    @classmethod
    def parser(cls, buf, offset):
        length, event = struct.unpack_from(
            ofproto.OFP_FLOW_UPDATE_HEADER_PACK_STR, buf, offset)
        cls_ = cls._EVENT[event]
        return cls_.parser(buf, offset)


@OFPFlowUpdateHeader.register_flow_update_event(
    ofproto.OFPFME_INITIAL, ofproto.OFP_FLOW_UPDATE_FULL_SIZE)
@OFPFlowUpdateHeader.register_flow_update_event(
    ofproto.OFPFME_ADDED, ofproto.OFP_FLOW_UPDATE_FULL_SIZE)
@OFPFlowUpdateHeader.register_flow_update_event(
    ofproto.OFPFME_REMOVED, ofproto.OFP_FLOW_UPDATE_FULL_SIZE)
@OFPFlowUpdateHeader.register_flow_update_event(
    ofproto.OFPFME_MODIFIED, ofproto.OFP_FLOW_UPDATE_FULL_SIZE)
class OFPFlowUpdateFull(OFPFlowUpdateHeader):
    def __init__(self, length=None, event=None, table_id=None, reason=None,
                 idle_timeout=None, hard_timeout=None, priority=None,
                 cookie=None, match=None, instructions=None):
        instructions = instructions if instructions else []
        super(OFPFlowUpdateFull, self).__init__(length, event)
        self.table_id = table_id
        self.reason = reason
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.priority = priority
        self.cookie = cookie
        self.match = match
        assert (event != ofproto.OFPFME_REMOVED or len(instructions) == 0)
        for i in instructions:
            assert isinstance(i, OFPInstruction)
        self.instructions = instructions

    @classmethod
    def parser(cls, buf, offset):
        (length, event, table_id, reason, idle_timeout, hard_timeout, priority,
         cookie) = struct.unpack_from(ofproto.OFP_FLOW_UPDATE_FULL_0_PACK_STR,
                                      buf, offset)
        offset += ofproto.OFP_FLOW_UPDATE_FULL_0_SIZE
        assert cls.cls_flow_update_length <= length
        assert cls.cls_flow_update_event == event

        match = OFPMatch.parser(buf, offset)
        match_length = utils.round_up(match.length, 8)
        offset += match_length

        inst_length = (length - ofproto.OFP_FLOW_UPDATE_FULL_0_SIZE -
                       match_length)
        instructions = []
        while inst_length > 0:
            inst = OFPInstruction.parser(buf, offset)
            instructions.append(inst)
            offset += inst.len
            inst_length -= inst.len

        return cls(length, event, table_id, reason, idle_timeout,
                   hard_timeout, priority, cookie, match, instructions)


@OFPFlowUpdateHeader.register_flow_update_event(
    ofproto.OFPFME_ABBREV, ofproto.OFP_FLOW_UPDATE_ABBREV_SIZE)
class OFPFlowUpdateAbbrev(OFPFlowUpdateHeader):
    def __init__(self, length=None, event=None, xid=None):
        super(OFPFlowUpdateAbbrev, self).__init__(length, event)
        self.xid = xid

    @classmethod
    def parser(cls, buf, offset):
        length, event, xid = struct.unpack_from(
            ofproto.OFP_FLOW_UPDATE_ABBREV_PACK_STR, buf, offset)
        assert cls.cls_flow_update_length == length
        assert cls.cls_flow_update_event == event

        return cls(length, event, xid)


@OFPFlowUpdateHeader.register_flow_update_event(
    ofproto.OFPFME_PAUSED, ofproto.OFP_FLOW_UPDATE_PAUSED_SIZE)
@OFPFlowUpdateHeader.register_flow_update_event(
    ofproto.OFPFME_RESUMED, ofproto.OFP_FLOW_UPDATE_PAUSED_SIZE)
class OFPFlowUpdatePaused(OFPFlowUpdateHeader):
    @classmethod
    def parser(cls, buf, offset):
        length, event = struct.unpack_from(
            ofproto.OFP_FLOW_UPDATE_PAUSED_PACK_STR, buf, offset)
        assert cls.cls_flow_update_length == length
        assert cls.cls_flow_update_event == event

        return cls(length, event)


class OFPFlowMonitorRequestBase(OFPMultipartRequest):
    def __init__(self, datapath, flags, monitor_id, out_port, out_group,
                 monitor_flags, table_id, command, match):
        super(OFPFlowMonitorRequestBase, self).__init__(datapath, flags)
        self.monitor_id = monitor_id
        self.out_port = out_port
        self.out_group = out_group
        self.monitor_flags = monitor_flags
        self.table_id = table_id
        self.command = command
        self.match = match

    def _serialize_stats_body(self):
        offset = ofproto.OFP_MULTIPART_REQUEST_SIZE
        msg_pack_into(ofproto.OFP_FLOW_MONITOR_REQUEST_0_PACK_STR, self.buf,
                      offset, self.monitor_id, self.out_port, self.out_group,
                      self.monitor_flags, self.table_id, self.command)

        offset += ofproto.OFP_FLOW_MONITOR_REQUEST_0_SIZE
        self.match.serialize(self.buf, offset)


@_set_stats_type(ofproto.OFPMP_FLOW_MONITOR, OFPFlowUpdateHeader)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPFlowMonitorRequest(OFPFlowMonitorRequestBase):
    """
    Flow monitor request message

    The controller uses this message to query flow monitors.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    monitor_id       Controller-assigned ID for this monitor
    out_port         Require matching entries to include this as an output
                     port
    out_group        Require matching entries to include this as an output
                     group
    monitor_flags    Bitmap of the following flags.

                     | OFPFMF_INITIAL
                     | OFPFMF_ADD
                     | OFPFMF_REMOVED
                     | OFPFMF_MODIFY
                     | OFPFMF_INSTRUCTIONS
                     | OFPFMF_NO_ABBREV
                     | OFPFMF_ONLY_OWN
    table_id         ID of table to monitor
    command          One of the following values.

                     | OFPFMC_ADD
                     | OFPFMC_MODIFY
                     | OFPFMC_DELETE
    match            Instance of ``OFPMatch``
    ================ ======================================================

    Example::

        def send_flow_monitor_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            monitor_flags = [ofp.OFPFMF_INITIAL, ofp.OFPFMF_ONLY_OWN]
            match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPFlowMonitorRequest(datapath, 0, 10000,
                                                   ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                   monitor_flags,
                                                   ofp.OFPTT_ALL,
                                                   ofp.OFPFMC_ADD, match)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, monitor_id=0,
                 out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                 monitor_flags=0, table_id=ofproto.OFPTT_ALL,
                 command=ofproto.OFPFMC_ADD, match=None, type_=None):
        if match is None:
            match = OFPMatch()
        super(OFPFlowMonitorRequest, self).__init__(datapath, flags,
                                                    monitor_id, out_port,
                                                    out_group, monitor_flags,
                                                    table_id, command, match)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_FLOW_MONITOR, OFPFlowUpdateHeader)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPFlowMonitorReply(OFPMultipartReply):
    """
    Flow monitor reply message

    The switch responds with this message to a flow monitor request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of list of the following class instance.

                     | OFPFlowMonitorFull
                     | OFPFlowMonitorAbbrev
                     | OFPFlowMonitorPaused
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPFlowMonitorReply, MAIN_DISPATCHER)
        def flow_monitor_reply_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto
            flow_updates = []

            for update in msg.body:
                update_str = 'length=%d event=%d' %
                             (update.length, update.event)
                if (update.event == ofp.OFPFME_INITIAL or
                    update.event == ofp.OFPFME_ADDED or
                    update.event == ofp.OFPFME_REMOVED or
                    update.event == ofp.OFPFME_MODIFIED):
                    update_str += 'table_id=%d reason=%d idle_timeout=%d '
                                  'hard_timeout=%d priority=%d cookie=%d '
                                  'match=%d instructions=%s' %
                                  (update.table_id, update.reason,
                                   update.idle_timeout, update.hard_timeout,
                                   update.priority, update.cookie,
                                   update.match, update.instructions)
                elif update.event == ofp.OFPFME_ABBREV:
                    update_str += 'xid=%d' % (update.xid)
                flow_updates.append(update_str)
            self.logger.debug('FlowUpdates: %s', flow_updates)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPFlowMonitorReply, self).__init__(datapath, **kwargs)


class OFPBundleFeaturesProp(OFPPropBase):
    _TYPES = {}


@OFPBundleFeaturesProp.register_type(ofproto.OFPTMPBF_TIME_CAPABILITY)
class OFPBundleFeaturesPropTime(OFPBundleFeaturesProp):
    def __init__(self, type_=None, length=None, sched_accuracy=None,
                 sched_max_future=None, sched_max_past=None, timestamp=None):
        super(OFPBundleFeaturesPropTime, self).__init__(type_, length)
        self.sched_accuracy = sched_accuracy
        self.sched_max_future = sched_max_future
        self.sched_max_past = sched_max_past
        self.timestamp = timestamp

    @classmethod
    def parser(cls, buf):
        prop = cls()
        (prop.type, prop.length) = struct.unpack_from(
            ofproto.OFP_BUNDLE_FEATURES_PROP_TIME_0_PACK_STR, buf)
        offset = ofproto.OFP_BUNDLE_FEATURES_PROP_TIME_0_SIZE

        for f in ['sched_accuracy', 'sched_max_future', 'sched_max_past',
                  'timestamp']:
            t = OFPTime.parser(buf, offset)
            setattr(prop, f, t)
            offset += ofproto.OFP_TIME_SIZE

        return prop

    def serialize(self):
        # fixup
        self.length = ofproto.OFP_BUNDLE_FEATURES_PROP_TIME_SIZE

        buf = bytearray()
        msg_pack_into(ofproto.OFP_BUNDLE_FEATURES_PROP_TIME_0_PACK_STR, buf, 0,
                      self.type, self.length)
        offset = ofproto.OFP_BUNDLE_FEATURES_PROP_TIME_0_SIZE

        for f in [self.sched_accuracy, self.sched_max_future,
                  self.sched_max_past, self.timestamp]:
            f.serialize(buf, offset)
            offset += ofproto.OFP_TIME_SIZE

        return buf


@OFPBundleFeaturesProp.register_type(ofproto.OFPTMPBF_EXPERIMENTER)
class OFPBundleFeaturesPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPBundleFeaturesStats(ofproto_parser.namedtuple(
        'OFPBundleFeaturesStats', ('capabilities', 'properties'))):
    @classmethod
    def parser(cls, buf, offset):
        (capabilities, ) = struct.unpack_from(
            ofproto.OFP_BUNDLE_FEATURES_PACK_STR, buf, offset)

        properties = []
        length = ofproto.OFP_BUNDLE_FEATURES_SIZE
        rest = buf[offset + length:]
        while rest:
            p, rest = OFPBundleFeaturesProp.parse(rest)
            properties.append(p)
            length += p.length

        bndl = cls(capabilities, properties)
        # Note: length field is not defined in the specification and
        # is specific to this implementation.
        bndl.length = length
        return bndl


@_set_stats_type(ofproto.OFPMP_BUNDLE_FEATURES, OFPBundleFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPBundleFeaturesStatsRequest(OFPMultipartRequest):
    """
    Bundle features request message

    The controller uses this message to query a switch about its bundle
    capabilities, including whether it supports atomic bundles, ordered
    bundles, and scheduled bundles.

    ====================== ====================================================
    Attribute              Description
    ====================== ====================================================
    flags                  Zero or ``OFPMPF_REQ_MORE``
    feature_request_flags  Bitmap of the following flags.

                           | OFPBF_TIMESTAMP
                           | OFPBF_TIME_SET_SCHED
    properties             List of ``OFPBundleFeaturesProp`` subclass instance
    ====================== ====================================================

    Example::

        def send_bundle_features_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPBundleFeaturesStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, feature_request_flags=0,
                 properties=None, type_=None):
        properties = properties if properties else []
        super(OFPBundleFeaturesStatsRequest, self).__init__(datapath, flags)
        self.feature_request_flags = feature_request_flags
        self.properties = properties

    def _serialize_stats_body(self):
        bin_props = bytearray()
        for p in self.properties:
            bin_props += p.serialize()

        msg_pack_into(ofproto.OFP_BUNDLE_FEATURES_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.feature_request_flags)
        self.buf += bin_props


@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_BUNDLE_FEATURES, OFPBundleFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPBundleFeaturesStatsReply(OFPMultipartReply):
    """
    Bundle features reply message

    The switch responds with this message to a bundle features request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             Instance of ``OFPBundleFeaturesStats``
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPBundleFeaturesStatsReply, MAIN_DISPATCHER)
        def bundle_features_stats_reply_handler(self, ev):
            body = ev.msg.body

            self.logger.debug('OFPBundleFeaturesStats: capabilities=%0x%08x '
                              'properties=%s',
                              body.capabilities, repr(body.properties))
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPBundleFeaturesStatsReply, self).__init__(datapath, **kwargs)


class OFPExperimenterMultipart(ofproto_parser.namedtuple(
                               'OFPExperimenterMultipart',
                               ('experimenter', 'exp_type', 'data'))):
    """
    The body of OFPExperimenterStatsReply multipart messages.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    experimenter     Experimenter ID
    exp_type         Experimenter defined
    data             Experimenter defined additional data
    ================ ======================================================
    """

    @classmethod
    def parser(cls, buf, offset):
        args = struct.unpack_from(
            ofproto.OFP_EXPERIMENTER_MULTIPART_HEADER_PACK_STR, buf,
            offset)
        args = list(args)
        args.append(buf[offset +
                        ofproto.OFP_EXPERIMENTER_MULTIPART_HEADER_SIZE:])
        stats = cls(*args)
        stats.length = ofproto.OFP_METER_FEATURES_SIZE
        return stats

    def serialize(self):
        buf = bytearray()
        msg_pack_into(ofproto.OFP_EXPERIMENTER_MULTIPART_HEADER_PACK_STR,
                      buf, 0,
                      self.experimenter, self.exp_type)
        return buf + self.data


class OFPExperimenterStatsRequestBase(OFPMultipartRequest):
    def __init__(self, datapath, flags,
                 experimenter, exp_type,
                 type_=None):
        super(OFPExperimenterStatsRequestBase, self).__init__(datapath, flags)
        self.experimenter = experimenter
        self.exp_type = exp_type


@_set_stats_type(ofproto.OFPMP_EXPERIMENTER, OFPExperimenterMultipart)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPExperimenterStatsRequest(OFPExperimenterStatsRequestBase):
    """
    Experimenter multipart request message

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    experimenter     Experimenter ID
    exp_type         Experimenter defined
    data             Experimenter defined additional data
    ================ ======================================================
    """
    def __init__(self, datapath, flags,
                 experimenter, exp_type, data,
                 type_=None):
        super(OFPExperimenterStatsRequest, self).__init__(datapath, flags,
                                                          experimenter,
                                                          exp_type, type_)
        self.data = data

    def _serialize_stats_body(self):
        body = OFPExperimenterMultipart(experimenter=self.experimenter,
                                        exp_type=self.exp_type,
                                        data=self.data)
        self.buf += body.serialize()


@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_EXPERIMENTER, OFPExperimenterMultipart)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPExperimenterStatsReply(OFPMultipartReply):
    """
    Experimenter multipart reply message

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             An ``OFPExperimenterMultipart`` instance
    ================ ======================================================
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPExperimenterStatsReply, self).__init__(datapath, **kwargs)


class OFPFlowDesc(StringifyMixin):
    def __init__(self, table_id=None, priority=None,
                 idle_timeout=None, hard_timeout=None, flags=None,
                 importance=None, cookie=None, match=None, stats=None,
                 instructions=None, length=None):
        super(OFPFlowDesc, self).__init__()
        self.length = length
        self.table_id = table_id
        self.priority = priority
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.flags = flags
        self.importance = importance
        self.cookie = cookie
        self.match = match
        self.stats = stats
        self.instructions = instructions

    @classmethod
    def parser(cls, buf, offset):
        flow_desc = cls()

        (flow_desc.length, flow_desc.table_id,
         flow_desc.priority, flow_desc.idle_timeout,
         flow_desc.hard_timeout, flow_desc.flags,
         flow_desc.importance,
         flow_desc.cookie) = struct.unpack_from(
            ofproto.OFP_FLOW_DESC_0_PACK_STR, buf, offset)
        offset += ofproto.OFP_FLOW_DESC_0_SIZE

        flow_desc.match = OFPMatch.parser(buf, offset)
        match_length = utils.round_up(flow_desc.match.length, 8)
        offset += match_length

        flow_desc.stats = OFPStats.parser(buf, offset)
        stats_length = utils.round_up(flow_desc.stats.length, 8)
        offset += stats_length

        instructions = []
        inst_length = (flow_desc.length - (ofproto.OFP_FLOW_DESC_0_SIZE +
                                           match_length + stats_length))
        while inst_length > 0:
            inst = OFPInstruction.parser(buf, offset)
            instructions.append(inst)
            offset += inst.len
            inst_length -= inst.len

        flow_desc.instructions = instructions
        return flow_desc


class OFPFlowStats(StringifyMixin):
    def __init__(self, table_id=None, reason=None, priority=None,
                 match=None, stats=None, length=None):
        super(OFPFlowStats, self).__init__()
        self.table_id = table_id
        self.reason = reason
        self.priority = priority
        self.match = match
        self.stats = stats
        self.length = length

    @classmethod
    def parser(cls, buf, offset):
        flow_stats = cls()

        (flow_stats.length, flow_stats.table_id, flow_stats.reason,
         flow_stats.priority) = struct.unpack_from(
            ofproto.OFP_FLOW_STATS_0_PACK_STR, buf, offset)
        offset += ofproto.OFP_FLOW_STATS_0_SIZE

        flow_stats.match = OFPMatch.parser(buf, offset)
        match_length = utils.round_up(flow_stats.match.length, 8)
        offset += match_length

        stats_length = (flow_stats.length - (ofproto.OFP_FLOW_STATS_0_SIZE +
                                             match_length))
        if stats_length > 0:
            flow_stats.stats = OFPStats.parser(buf, offset)

        return flow_stats


class OFPFlowStatsRequestBase(OFPMultipartRequest):
    def __init__(self, datapath, flags, table_id, out_port, out_group,
                 cookie, cookie_mask, match):
        super(OFPFlowStatsRequestBase, self).__init__(datapath, flags)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        self.cookie = cookie
        self.cookie_mask = cookie_mask
        self.match = match

    def _serialize_stats_body(self):
        offset = ofproto.OFP_MULTIPART_REQUEST_SIZE
        msg_pack_into(ofproto.OFP_FLOW_STATS_REQUEST_0_PACK_STR,
                      self.buf, offset, self.table_id, self.out_port,
                      self.out_group, self.cookie, self.cookie_mask)

        offset += ofproto.OFP_FLOW_STATS_REQUEST_0_SIZE
        self.match.serialize(self.buf, offset)


@_set_stats_type(ofproto.OFPMP_FLOW_DESC, OFPFlowDesc)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPFlowDescStatsRequest(OFPFlowStatsRequestBase):
    """
    Individual flow descriptions request message

    The controller uses this message to query individual flow descriptions.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    table_id         ID of table to read
    out_port         Require matching entries to include this as an output
                     port
    out_group        Require matching entries to include this as an output
                     group
    cookie           Require matching entries to contain this cookie value
    cookie_mask      Mask used to restrict the cookie bits that must match
    match            Instance of ``OFPMatch``
    ================ ======================================================

    Example::

        def send_flow_desc_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            cookie = cookie_mask = 0
            match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPFlowDescStatsRequest(datapath, 0,
                                                     ofp.OFPTT_ALL,
                                                     ofp.OFPP_ANY,
                                                     ofp.OFPG_ANY,
                                                     cookie, cookie_mask,
                                                     match)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, table_id=ofproto.OFPTT_ALL,
                 out_port=ofproto.OFPP_ANY,
                 out_group=ofproto.OFPG_ANY,
                 cookie=0, cookie_mask=0, match=None, type_=None):
        if match is None:
            match = OFPMatch()
        super(OFPFlowDescStatsRequest, self).__init__(
            datapath, flags, table_id, out_port, out_group, cookie,
            cookie_mask, match)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_FLOW_DESC, OFPFlowDesc)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPFlowDescStatsReply(OFPMultipartReply):
    """
    Individual flow descriptions reply message

    The switch responds with this message to an individual flow descriptions
    request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPFlowDesc`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPFlowDescStatsReply, MAIN_DISPATCHER)
        def flow_desc_reply_handler(self, ev):
            flows = []
            for stat in ev.msg.body:
                flows.append('table_id=%s priority=%d '
                             'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                             'importance=%d cookie=%d match=%s '
                             'stats=%s instructions=%s' %
                             (stat.table_id, stat.priority,
                              stat.idle_timeout, stat.hard_timeout,
                              stat.flags, stat.importance,
                              stat.cookie, stat.match,
                              stat.stats, stat.instructions))
            self.logger.debug('FlowDesc: %s', flows)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPFlowDescStatsReply, self).__init__(datapath, **kwargs)


@_set_stats_type(ofproto.OFPMP_FLOW_STATS, OFPFlowStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPFlowStatsRequest(OFPFlowStatsRequestBase):
    """
    Individual flow statistics request message

    The controller uses this message to query individual flow statistics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    table_id         ID of table to read
    out_port         Require matching entries to include this as an output
                     port
    out_group        Require matching entries to include this as an output
                     group
    cookie           Require matching entries to contain this cookie value
    cookie_mask      Mask used to restrict the cookie bits that must match
    match            Instance of ``OFPMatch``
    ================ ======================================================

    Example::

        def send_flow_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            cookie = cookie_mask = 0
            match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                                 ofp.OFPTT_ALL,
                                                 ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                 cookie, cookie_mask,
                                                 match)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, table_id=ofproto.OFPTT_ALL,
                 out_port=ofproto.OFPP_ANY,
                 out_group=ofproto.OFPG_ANY,
                 cookie=0, cookie_mask=0, match=None, type_=None):
        if match is None:
            match = OFPMatch()
        super(OFPFlowStatsRequest, self).__init__(datapath, flags, table_id,
                                                  out_port, out_group,
                                                  cookie, cookie_mask, match)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_FLOW_STATS, OFPFlowStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPFlowStatsReply(OFPMultipartReply):
    """
    Individual flow statistics reply message

    The switch responds with this message to an individual flow statistics
    request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPFlowStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            flows = []
            for stat in ev.msg.body:
                flows.append('table_id=%s reason=%d priority=%d '
                             'match=%s stats=%s' %
                             (stat.table_id, stat.reason, stat.priority,
                              stat.match, stat.stats))
            self.logger.debug('FlowStats: %s', flows)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPFlowStatsReply, self).__init__(datapath, **kwargs)


class OFPAggregateStats(StringifyMixin):
    def __init__(self, stats=None, length=None):
        super(OFPAggregateStats, self).__init__()
        self.stats = stats
        # Note: length field is specific to this implementation.
        # It does not have a corresponding field in the specification.
        self.length = length

    @classmethod
    def parser(cls, buf, offset):
        stats = OFPStats.parser(buf, offset)
        agg = cls(stats)
        agg.length = utils.round_up(stats.length, 8)
        return agg


@_set_stats_type(ofproto.OFPMP_AGGREGATE_STATS, OFPAggregateStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPAggregateStatsRequest(OFPFlowStatsRequestBase):
    """
    Aggregate flow statistics request message

    The controller uses this message to query aggregate flow statictics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    table_id         ID of table to read
    out_port         Require matching entries to include this as an output
                     port
    out_group        Require matching entries to include this as an output
                     group
    cookie           Require matching entries to contain this cookie value
    cookie_mask      Mask used to restrict the cookie bits that must match
    match            Instance of ``OFPMatch``
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
    def __init__(self, datapath, flags, table_id, out_port, out_group,
                 cookie, cookie_mask, match, type_=None):
        super(OFPAggregateStatsRequest, self).__init__(datapath,
                                                       flags,
                                                       table_id,
                                                       out_port,
                                                       out_group,
                                                       cookie,
                                                       cookie_mask,
                                                       match)


@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_AGGREGATE_STATS, OFPAggregateStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPAggregateStatsReply(OFPMultipartReply):
    """
    Aggregate flow statistics reply message

    The switch responds with this message to an aggregate flow statistics
    request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             Instance of ``OFPAggregateStats``
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
        def aggregate_stats_reply_handler(self, ev):
            body = ev.msg.body

            self.logger.debug('AggregateStats: stats=%s', body.stats)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPAggregateStatsReply, self).__init__(datapath, **kwargs)


class OFPTableStats(ofproto_parser.namedtuple('OFPTableStats', (
        'table_id', 'active_count', 'lookup_count',
        'matched_count'))):
    @classmethod
    def parser(cls, buf, offset):
        tbl = struct.unpack_from(ofproto.OFP_TABLE_STATS_PACK_STR,
                                 buf, offset)
        stats = cls(*tbl)
        stats.length = ofproto.OFP_TABLE_STATS_SIZE
        return stats


@_set_stats_type(ofproto.OFPMP_TABLE_STATS, OFPTableStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPTableStatsRequest(OFPMultipartRequest):
    """
    Table statistics request message

    The controller uses this message to query flow table statictics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    ================ ======================================================

    Example::

        def send_table_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPTableStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags, type_=None):
        super(OFPTableStatsRequest, self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_TABLE_STATS, OFPTableStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPTableStatsReply(OFPMultipartReply):
    """
    Table statistics reply message

    The switch responds with this message to a table statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPTableStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
        def table_stats_reply_handler(self, ev):
            tables = []
            for stat in ev.msg.body:
                tables.append('table_id=%d active_count=%d lookup_count=%d '
                              ' matched_count=%d' %
                              (stat.table_id, stat.active_count,
                               stat.lookup_count, stat.matched_count))
            self.logger.debug('TableStats: %s', tables)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPTableStatsReply, self).__init__(datapath, **kwargs)


class OFPPortStatsProp(OFPPropBase):
    _TYPES = {}


@OFPPortStatsProp.register_type(ofproto.OFPPSPT_ETHERNET)
class OFPPortStatsPropEthernet(OFPPortStatsProp):
    def __init__(self, type_=None, length=None, rx_frame_err=None,
                 rx_over_err=None, rx_crc_err=None, collisions=None):
        self.type = type_
        self.length = length
        self.rx_frame_err = rx_frame_err
        self.rx_over_err = rx_over_err
        self.rx_crc_err = rx_crc_err
        self.collisions = collisions

    @classmethod
    def parser(cls, buf):
        ether = cls()
        (ether.type, ether.length, ether.rx_frame_err, ether.rx_over_err,
         ether.rx_crc_err, ether.collisions) = struct.unpack_from(
            ofproto.OFP_PORT_STATS_PROP_ETHERNET_PACK_STR, buf, 0)
        return ether


@OFPPortStatsProp.register_type(ofproto.OFPPSPT_OPTICAL)
class OFPPortStatsPropOptical(OFPPortStatsProp):
    def __init__(self, type_=None, length=None, flags=None,
                 tx_freq_lmda=None, tx_offset=None, tx_grid_span=None,
                 rx_freq_lmda=None, rx_offset=None, rx_grid_span=None,
                 tx_pwr=None, rx_pwr=None, bias_current=None,
                 temperature=None):
        self.type = type_
        self.length = length
        self.flags = flags
        self.tx_freq_lmda = tx_freq_lmda
        self.tx_offset = tx_offset
        self.tx_grid_span = tx_grid_span
        self.rx_freq_lmda = rx_freq_lmda
        self.rx_offset = rx_offset
        self.rx_grid_span = rx_grid_span
        self.tx_pwr = tx_pwr
        self.rx_pwr = rx_pwr
        self.bias_current = bias_current
        self.temperature = temperature

    @classmethod
    def parser(cls, buf):
        optical = cls()
        (optical.type, optical.length, optical.flags,
         optical.tx_freq_lmda, optical.tx_offset, optical.tx_grid_span,
         optical.rx_freq_lmda, optical.rx_offset, optical.rx_grid_span,
         optical.tx_pwr, optical.rx_pwr, optical.bias_current,
         optical.temperature) = struct.unpack_from(
            ofproto.OFP_PORT_STATS_PROP_OPTICAL_PACK_STR, buf, 0)
        return optical


@OFPPortStatsProp.register_type(ofproto.OFPPSPT_EXPERIMENTER)
class OFPPortStatsPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPPortStats(StringifyMixin):
    def __init__(self, length=None, port_no=None, duration_sec=None,
                 duration_nsec=None, rx_packets=None, tx_packets=None,
                 rx_bytes=None, tx_bytes=None, rx_dropped=None,
                 tx_dropped=None, rx_errors=None, tx_errors=None,
                 properties=None):
        super(OFPPortStats, self).__init__()
        self.length = length
        self.port_no = port_no
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.rx_packets = rx_packets
        self.tx_packets = tx_packets
        self.rx_bytes = rx_bytes
        self.tx_bytes = tx_bytes
        self.rx_dropped = rx_dropped
        self.tx_dropped = tx_dropped
        self.rx_errors = rx_errors
        self.tx_errors = tx_errors
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        (length, port_no, duration_sec, duration_nsec, rx_packets,
         tx_packets, rx_bytes, tx_bytes, rx_dropped, tx_dropped,
         rx_errors, tx_errors) = struct.unpack_from(
            ofproto.OFP_PORT_STATS_PACK_STR, buf, offset)
        props = []
        rest = buf[offset + ofproto.OFP_PORT_STATS_SIZE:offset + length]
        while rest:
            p, rest = OFPPortStatsProp.parse(rest)
            props.append(p)
        stats = cls(length, port_no, duration_sec, duration_nsec, rx_packets,
                    tx_packets, rx_bytes, tx_bytes, rx_dropped, tx_dropped,
                    rx_errors, tx_errors, props)
        return stats


@_set_stats_type(ofproto.OFPMP_PORT_STATS, OFPPortStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPPortStatsRequest(OFPMultipartRequest):
    """
    Port statistics request message

    The controller uses this message to query information about ports
    statistics.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    port_no          Port number to read (OFPP_ANY to all ports)
    ================ ======================================================

    Example::

        def send_port_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags, port_no, type_=None):
        super(OFPPortStatsRequest, self).__init__(datapath, flags)
        self.port_no = port_no

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_PORT_MULTIPART_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.port_no)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_PORT_STATS, OFPPortStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPPortStatsReply(OFPMultipartReply):
    """
    Port statistics reply message

    The switch responds with this message to a port statistics request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPPortStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
        def port_stats_reply_handler(self, ev):
            ports = []
            for stat in ev.msg.body:
                ports.append(stat.length, stat.port_no,
                             stat.duration_sec, stat.duration_nsec,
                             stat.rx_packets, stat.tx_packets,
                             stat.rx_bytes, stat.tx_bytes,
                             stat.rx_dropped, stat.tx_dropped,
                             stat.rx_errors, stat.tx_errors,
                             repr(stat.properties))
            self.logger.debug('PortStats: %s', ports)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPPortStatsReply, self).__init__(datapath, **kwargs)


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
        msg.desc = OFPPort.parser(msg.buf, ofproto.OFP_PORT_STATUS_DESC_OFFSET)
        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_ROLE_STATUS)
class OFPRoleStatus(MsgBase):
    """
    Role status message

    The switch notifies controller of change of role.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    role             One of the following values.

                     | OFPCR_ROLE_NOCHANGE
                     | OFPCR_ROLE_EQUAL
                     | OFPCR_ROLE_MASTER
    reason           One of the following values.

                     | OFPCRR_MASTER_REQUEST
                     | OFPCRR_CONFIG
                     | OFPCRR_EXPERIMENTER
    generation_id    Master Election Generation ID
    properties       List of ``OFPRoleProp`` subclass instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPRoleStatus, MAIN_DISPATCHER)
        def role_status_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.role == ofp.OFPCR_ROLE_NOCHANGE:
                role = 'ROLE NOCHANGE'
            elif msg.role == ofp.OFPCR_ROLE_EQUAL:
                role = 'ROLE EQUAL'
            elif msg.role == ofp.OFPCR_ROLE_MASTER:
                role = 'ROLE MASTER'
            else:
                role = 'unknown'

            if msg.reason == ofp.OFPCRR_MASTER_REQUEST:
                reason = 'MASTER REQUEST'
            elif msg.reason == ofp.OFPCRR_CONFIG:
                reason = 'CONFIG'
            elif msg.reason == ofp.OFPCRR_EXPERIMENTER:
                reason = 'EXPERIMENTER'
            else:
                reason = 'unknown'

            self.logger.debug('OFPRoleStatus received: role=%s reason=%s '
                              'generation_id=%d properties=%s', role, reason,
                              msg.generation_id, repr(msg.properties))
    """
    def __init__(self, datapath, role=None, reason=None,
                 generation_id=None, properties=None):
        super(OFPRoleStatus, self).__init__(datapath)
        self.role = role
        self.reason = reason
        self.generation_id = generation_id
        self.properties = properties

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPRoleStatus, cls).parser(datapath, version, msg_type,
                                               msg_len, xid, buf)
        (msg.role, msg.reason, msg.generation_id) = struct.unpack_from(
            ofproto.OFP_ROLE_STATUS_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)

        msg.properties = []
        rest = msg.buf[ofproto.OFP_ROLE_STATUS_SIZE:]
        while rest:
            p, rest = OFPRoleProp.parse(rest)
            msg.properties.append(p)

        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_TABLE_STATUS)
class OFPTableStatus(MsgBase):
    """
    Table status message

    The switch notifies controller of change of table status.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    reason           One of the following values.

                     | OFPTR_VACANCY_DOWN
                     | OFPTR_VACANCY_UP
    table            ``OFPTableDesc`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPTableStatus, MAIN_DISPATCHER)
        def table(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.OFPTR_VACANCY_DOWN:
                reason = 'VACANCY_DOWN'
            elif msg.reason == ofp.OFPTR_VACANCY_UP:
                reason = 'VACANCY_UP'
            else:
                reason = 'unknown'

            self.logger.debug('OFPTableStatus received: reason=%s '
                              'table_id=%d config=0x%08x properties=%s',
                              reason, msg.table.table_id, msg.table.config,
                              repr(msg.table.properties))
    """
    def __init__(self, datapath, reason=None, table=None):
        super(OFPTableStatus, self).__init__(datapath)
        self.reason = reason
        self.table = table

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPTableStatus, cls).parser(datapath, version, msg_type,
                                                msg_len, xid, buf)
        (msg.reason,) = struct.unpack_from(ofproto.OFP_TABLE_STATUS_0_PACK_STR,
                                           msg.buf, ofproto.OFP_HEADER_SIZE)

        msg.table = OFPTableDesc.parser(msg.buf,
                                        ofproto.OFP_TABLE_STATUS_0_SIZE)

        return msg


@_register_parser
@_set_msg_type(ofproto.OFPT_REQUESTFORWARD)
class OFPRequestForward(MsgInMsgBase):
    """
    Forwarded request message

    The swtich forwards request messages from one controller to other
    controllers.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    request          ``OFPGroupMod`` or ``OFPMeterMod`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPRequestForward, MAIN_DISPATCHER)
        def request_forward_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.request.msg_type == ofp.OFPT_GROUP_MOD:
                self.logger.debug(
                    'OFPRequestForward received: request=OFPGroupMod('
                    'command=%d, type=%d, group_id=%d, command_bucket_id=%d, '
                    'buckets=%s, properties=%s)',
                    msg.request.command, msg.request.type,
                    msg.request.group_id, msg.request.command_bucket_id,
                    msg.request.buckets, repr(msg.request.properties))
            elif msg.request.msg_type == ofp.OFPT_METER_MOD:
                self.logger.debug(
                    'OFPRequestForward received: request=OFPMeterMod('
                    'command=%d, flags=%d, meter_id=%d, bands=%s)',
                    msg.request.command, msg.request.flags,
                    msg.request.meter_id, msg.request.bands)
            else:
                self.logger.debug(
                    'OFPRequestForward received: request=Unknown')
    """
    def __init__(self, datapath, request=None):
        super(OFPRequestForward, self).__init__(datapath)
        self.request = request

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPRequestForward, cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)
        req_buf = buf[ofproto.OFP_HEADER_SIZE:]
        (_ver, _type, _len, _xid) = ofproto_parser.header(req_buf)
        msg.request = ofproto_parser.msg(
            datapath, _ver, _type, _len, _xid, req_buf)
        return msg

    def _serialize_body(self):
        assert isinstance(self.request, (OFPGroupMod, OFPMeterMod))
        self.request.serialize()
        self.buf += self.request.buf


class OFPControllerStatusProp(OFPPropBase):
    _TYPES = {}


@OFPControllerStatusProp.register_type(ofproto.OFPCSPT_URI)
class OFPControllerStatusPropUri(OFPControllerStatusProp):
    _TYPE = {
        'ascii': [
            'uri',
        ]
    }

    def __init__(self, type_=None, length=None, uri=None):
        super(OFPControllerStatusPropUri, self).__init__(type_, length)
        self.uri = uri

    @classmethod
    def parser(cls, buf):
        rest = cls.get_rest(buf)
        pack_str = '!%ds' % len(rest)
        (uri, ) = struct.unpack_from(pack_str, rest, 0)
        return cls(uri=uri)


@OFPControllerStatusProp.register_type(ofproto.OFPCSPT_EXPERIMENTER)
class OFPControllerStatusPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPControllerStatusStats(StringifyMixin):

    """
    Controller status structure

    ============== =========================================================
    Attribute      Description
    ============== =========================================================
    length         Length of this entry.
    short_id       ID number which identifies the controller.
    role           Bitmap of controller's role flags.

                   | OFPCR_ROLE_NOCHANGE
                   | OFPCR_ROLE_EQUAL
                   | OFPCR_ROLE_MASTER
                   | OFPCR_ROLE_SLAVE
    reason         Bitmap of controller status reason flags.

                   | OFPCSR_REQUEST
                   | OFPCSR_CHANNEL_STATUS
                   | OFPCSR_ROLE
                   | OFPCSR_CONTROLLER_ADDED
                   | OFPCSR_CONTROLLER_REMOVED
                   | OFPCSR_SHORT_ID
                   | OFPCSR_EXPERIMENTER
    channel_status Bitmap of control channel status flags.

                   | OFPCT_STATUS_UP
                   | OFPCT_STATUS_DOWN
    properties     List of ``OFPControllerStatusProp`` subclass instance
    ============== =========================================================
    """

    def __init__(self, short_id=None, role=None, reason=None,
                 channel_status=None, properties=None, length=None):
        super(OFPControllerStatusStats, self).__init__()
        self.length = length
        self.short_id = short_id
        self.role = role
        self.reason = reason
        self.channel_status = channel_status
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        status = cls()

        (status.length, status.short_id,
         status.role, status.reason,
         status.channel_status) = struct.unpack_from(
            ofproto.OFP_CONTROLLER_STATUS_PACK_STR, buf, offset)
        offset += ofproto.OFP_CONTROLLER_STATUS_SIZE

        status.properties = []
        rest = buf[offset:offset + status.length]
        while rest:
            p, rest = OFPControllerStatusProp.parse(rest)
            status.properties.append(p)

        return status


@_set_stats_type(ofproto.OFPMP_CONTROLLER_STATUS, OFPControllerStatusStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPControllerStatusStatsRequest(OFPMultipartRequest):
    """
    Controller status multipart request message

    The controller uses this message to request the status, the roles
    and the control channels of other controllers configured on the switch.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    ================ ======================================================

    Example::

        def send_controller_status_multipart_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags=0, type_=None):
        super(OFPControllerStatusStatsRequest,
              self).__init__(datapath, flags)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_CONTROLLER_STATUS, OFPControllerStatusStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPControllerStatusStatsReply(OFPMultipartReply):
    """
     Controller status multipart reply message

    The switch responds with this message to a controller status
    multipart request.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    body             List of ``OFPControllerStatus`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPControllerStatusStatsReply,
                    MAIN_DISPATCHER)
        def controller_status_multipart_reply_handler(self, ev):
            status = []
            for s in ev.msg.body:
                status.append('short_id=%d role=%d reason=%d '
                              'channel_status=%d properties=%s' %
                              (s.short_id, s.role, s.reason,
                               s.channel_status, repr(s.properties)))
            self.logger.debug('OFPControllerStatusStatsReply received: %s',
                              status)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPControllerStatusStatsReply, self).__init__(datapath,
                                                            **kwargs)


@_register_parser
@_set_msg_type(ofproto.OFPT_CONTROLLER_STATUS)
class OFPControllerStatus(MsgBase):
    """
    Controller status message

    The switch informs the controller about the status of the control
    channel it maintains with each controller.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    status           ``OFPControllerStatusStats`` instance
    ================ ======================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPControllerStatus, MAIN_DISPATCHER)
        def table(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto
            status = msg.status

            if status.role == ofp.OFPCR_ROLE_NOCHANGE:
                role = 'NOCHANGE'
            elif status.role == ofp.OFPCR_ROLE_EQUAL:
                role = 'EQUAL'
            elif status.role == ofp.OFPCR_ROLE_MASTER:
                role = 'MASTER'
            elif status.role == ofp.OFPCR_ROLE_SLAVE:
                role = 'SLAVE'
            else:
                role = 'unknown'

            if status.reason == ofp.OFPCSR_REQUEST:
                reason = 'REQUEST'
            elif status.reason == ofp.OFPCSR_CHANNEL_STATUS:
                reason = 'CHANNEL_STATUS'
            elif status.reason == ofp.OFPCSR_ROLE:
                reason = 'ROLE'
            elif status.reason == ofp.OFPCSR_CONTROLLER_ADDED:
                reason = 'CONTROLLER_ADDED'
            elif status.reason == ofp.OFPCSR_CONTROLLER_REMOVED:
                reason = 'CONTROLLER_REMOVED'
            elif status.reason == ofp.OFPCSR_SHORT_ID:
                reason = 'SHORT_ID'
            elif status.reason == ofp.OFPCSR_EXPERIMENTER:
                reason = 'EXPERIMENTER'
            else:
                reason = 'unknown'

            if status.channel_status == OFPCT_STATUS_UP:
                channel_status = 'UP'
            if status.channel_status == OFPCT_STATUS_DOWN:
                channel_status = 'DOWN'
            else:
                channel_status = 'unknown'

            self.logger.debug('OFPControllerStatus received: short_id=%d'
                              'role=%s reason=%s channel_status=%s '
                              'properties=%s',
                              status.short_id, role, reason, channel_status,
                              repr(status.properties))
    """
    def __init__(self, datapath, status=None):
        super(OFPControllerStatus, self).__init__(datapath)
        self.status = status

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPControllerStatus, cls).parser(datapath, version,
                                                     msg_type, msg_len,
                                                     xid, buf)

        msg.status = OFPControllerStatusStats.parser(msg.buf,
                                                     ofproto.OFP_HEADER_SIZE)

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
    match            Instance of ``OFPMatch``
                     (``in_port`` is mandatory in the match field)
    actions          list of OpenFlow action class
    data             Packet data
    ================ ======================================================

    Example::

        def send_packet_out(self, datapath, buffer_id, in_port):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            match = OFPMatch(in_port=in_port)
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
            req = ofp_parser.OFPPacketOut(datapath, buffer_id,
                                          match, actions)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, buffer_id=None, match=None, actions=None,
                 data=None, actions_len=None):
        super(OFPPacketOut, self).__init__(datapath)
        if buffer_id is None:
            self.buffer_id = ofproto.OFP_NO_BUFFER
        else:
            self.buffer_id = buffer_id
        self.actions_len = 0
        assert 'in_port' in match
        self.match = match
        self.actions = actions
        self.data = data

    def _serialize_body(self):
        # adjustment
        offset = ofproto.OFP_PACKET_OUT_0_SIZE
        match_len = self.match.serialize(self.buf, offset)
        offset += match_len

        self.actions_len = 0
        for a in self.actions:
            a.serialize(self.buf, offset)
            offset += a.len
            self.actions_len += a.len

        if self.buffer_id == ofproto.OFP_NO_BUFFER:
            assert self.data is not None
            self.buf += self.data
        else:
            assert self.data is None

        msg_pack_into(ofproto.OFP_PACKET_OUT_0_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.buffer_id, self.actions_len)


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
    flags            Bitmap of the following flags.

                     | OFPFF_SEND_FLOW_REM
                     | OFPFF_CHECK_OVERLAP
                     | OFPFF_RESET_COUNTS
                     | OFPFF_NO_PKT_COUNTS
                     | OFPFF_NO_BYT_COUNTS
    importance       Eviction precedence
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
            importance = 0
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
                                        importance,
                                        match, inst)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, cookie=0, cookie_mask=0, table_id=0,
                 command=ofproto.OFPFC_ADD,
                 idle_timeout=0, hard_timeout=0,
                 priority=ofproto.OFP_DEFAULT_PRIORITY,
                 buffer_id=ofproto.OFP_NO_BUFFER,
                 out_port=0, out_group=0, flags=0, importance=0,
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
        self.importance = importance
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
                      self.out_group, self.flags, self.importance)

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
                a.serialize(buf, action_offset)
                action_offset += a.len

        self.len = action_offset - offset
        pad_len = utils.round_up(self.len, 8) - self.len
        msg_pack_into("%dx" % pad_len, buf, action_offset)
        self.len += pad_len

        msg_pack_into(ofproto.OFP_INSTRUCTION_ACTIONS_PACK_STR,
                      buf, offset, self.type, self.len)


@OFPInstruction.register_instruction_type([ofproto.OFPIT_STAT_TRIGGER])
class OFPInstructionStatTrigger(OFPInstruction):
    """
    Statistics triggers instruction

    This instruction defines a set of statistics thresholds using OXS.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Bitmap of the following flags.

                     | OFPSTF_PERIODIC
                     | OFPSTF_ONLY_FIRST
    thresholds       Instance of ``OFPStats``
    ================ ======================================================
    """
    def __init__(self, flags, thresholds, type_=None, len_=None):
        super(OFPInstructionStatTrigger, self).__init__()
        self.type = ofproto.OFPIT_STAT_TRIGGER
        self.len = len_
        self.flags = flags
        self.thresholds = thresholds

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, flags) = struct.unpack_from(
            ofproto.OFP_INSTRUCTION_STAT_TRIGGER_PACK_STR0, buf, offset)

        # adjustment
        offset += 8
        thresholds = OFPStats.parser(buf, offset)

        inst = cls(flags, thresholds)
        inst.len = len_
        return inst

    def serialize(self, buf, offset):
        stats_len = self.thresholds.serialize(buf, offset + 8)

        self.len = 8 + stats_len
        msg_pack_into(ofproto.OFP_INSTRUCTION_STAT_TRIGGER_PACK_STR0,
                      buf, offset, self.type, self.len, self.flags)


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

    The set of keywords available for this is same as OFPMatch
    which including with/without mask.

    Example::

        set_field = OFPActionSetField(eth_src="00:00:00:00:00:00")
        set_field = OFPActionSetField(ipv4_src=("192.168.100.0",
                                                "255.255.255.0"))
    """
    def __init__(self, field=None, **kwargs):
        super(OFPActionSetField, self).__init__()
        assert len(kwargs) == 1
        key = list(kwargs.keys())[0]
        value = kwargs[key]
        assert isinstance(key, (str, six.text_type))
        self.key = key
        self.value = value

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_ACTION_SET_FIELD_PACK_STR, buf, offset)
        (n, value, mask, _len) = ofproto.oxm_parse(buf, offset + 4)
        k, uv = ofproto.oxm_to_user(n, value, mask)
        action = cls(**{k: uv})
        action.len = len_
        return action

    def serialize(self, buf, offset):
        n, value, mask = ofproto.oxm_from_user(self.key, self.value)
        len_ = ofproto.oxm_serialize(n, value, mask, buf, offset + 4)
        self.len = utils.round_up(4 + len_, 8)
        msg_pack_into('!HH', buf, offset, self.type, self.len)
        pad_len = self.len - (4 + len_)
        msg_pack_into("%dx" % pad_len, buf, offset + 4 + len_)

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
        return OFPActionSetField(**{k: v})

    def stringify_attrs(self):
        yield (self.key, self.value)


@OFPAction.register_action_type(ofproto.OFPAT_PUSH_PBB,
                                ofproto.OFP_ACTION_PUSH_SIZE)
class OFPActionPushPbb(OFPAction):
    """
    Push PBB action

    This action pushes a new PBB header to the packet.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    ethertype        Ether type
    ================ ======================================================
    """
    def __init__(self, ethertype, type_=None, len_=None):
        super(OFPActionPushPbb, self).__init__()
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, ethertype) = struct.unpack_from(
            ofproto.OFP_ACTION_PUSH_PACK_STR, buf, offset)
        return cls(ethertype)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_PUSH_PACK_STR, buf, offset,
                      self.type, self.len, self.ethertype)


@OFPAction.register_action_type(ofproto.OFPAT_POP_PBB,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionPopPbb(OFPAction):
    """
    Pop PBB action

    This action pops the outermost PBB service instance header from
    the packet.
    """
    def __init__(self, type_=None, len_=None):
        super(OFPActionPopPbb, self).__init__()

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_) = struct.unpack_from(
            ofproto.OFP_ACTION_HEADER_PACK_STR, buf, offset)
        return cls()


@OFPAction.register_action_type(ofproto.OFPAT_COPY_FIELD,
                                ofproto.OFP_ACTION_COPY_FIELD_SIZE)
class OFPActionCopyField(OFPAction):
    """
    Copy Field action

    This action copy value between header and register.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    n_bits           Number of bits to copy.
    src_offset       Starting bit offset in source.
    dst_offset       Starting bit offset in destination.
    oxm_ids          List of ``OFPOxmId`` instances.
                     The first element of this list, src_oxm_id,
                     identifies the field where the value is copied from.
                     The second element of this list, dst_oxm_id,
                     identifies the field where the value is copied to.
                     The default is [].
    ================ ======================================================
    """
    def __init__(self, n_bits=0, src_offset=0, dst_offset=0, oxm_ids=None,
                 type_=None, len_=None):
        oxm_ids = oxm_ids if oxm_ids else []
        super(OFPActionCopyField, self).__init__()
        self.n_bits = n_bits
        self.src_offset = src_offset
        self.dst_offset = dst_offset
        self.oxm_ids = oxm_ids

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, n_bits, src_offset, dst_offset) = struct.unpack_from(
            ofproto.OFP_ACTION_COPY_FIELD_PACK_STR, buf, offset)
        offset += ofproto.OFP_ACTION_COPY_FIELD_SIZE

        rest = buf[offset:offset + len_]
        oxm_ids = []
        while rest:
            i, rest = OFPOxmId.parse(rest)
            oxm_ids.append(i)
        return cls(n_bits, src_offset, dst_offset, oxm_ids, type_, len_)

    def serialize(self, buf, offset):
        oxm_ids_buf = bytearray()
        for i in self.oxm_ids:
            oxm_ids_buf += i.serialize()
        self.len += len(oxm_ids_buf)
        msg_pack_into(ofproto.OFP_ACTION_COPY_FIELD_PACK_STR, buf,
                      offset, self.type, self.len,
                      self.n_bits, self.src_offset, self.dst_offset)
        buf += oxm_ids_buf


@OFPAction.register_action_type(ofproto.OFPAT_METER,
                                ofproto.OFP_ACTION_METER_SIZE)
class OFPActionMeter(OFPAction):
    """
    Meter action

    This action applies meter (rate limiter)

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    meter_id         Meter instance
    ================ ======================================================
    """
    def __init__(self, meter_id,
                 type_=None, len_=None):
        super(OFPActionMeter, self).__init__()
        self.meter_id = meter_id

    @classmethod
    def parser(cls, buf, offset):
        type_, len_, meter_id = struct.unpack_from(
            ofproto.OFP_ACTION_METER_PACK_STR, buf, offset)
        return cls(meter_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_METER_PACK_STR, buf,
                      offset, self.type, self.len, self.meter_id)


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

    def __init__(self, experimenter):
        super(OFPActionExperimenter, self).__init__()
        self.type = ofproto.OFPAT_EXPERIMENTER
        self.experimenter = experimenter
        self.len = None

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, experimenter) = struct.unpack_from(
            ofproto.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR, buf, offset)
        data = buf[(offset + ofproto.OFP_ACTION_EXPERIMENTER_HEADER_SIZE
                    ): offset + len_]
        if experimenter == ofproto_common.NX_EXPERIMENTER_ID:
            obj = NXAction.parse(data)
        else:
            obj = OFPActionExperimenterUnknown(experimenter, data)
        obj.len = len_
        return obj

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR,
                      buf, offset, self.type, self.len, self.experimenter)


class OFPActionExperimenterUnknown(OFPActionExperimenter):
    def __init__(self, experimenter, data=None, type_=None, len_=None):
        super(OFPActionExperimenterUnknown,
              self).__init__(experimenter=experimenter)
        self.data = data

    def serialize(self, buf, offset):
        # fixup
        data = self.data
        if data is None:
            data = bytearray()
        self.len = (utils.round_up(len(data), 8) +
                    ofproto.OFP_ACTION_EXPERIMENTER_HEADER_SIZE)
        super(OFPActionExperimenterUnknown, self).serialize(buf, offset)
        msg_pack_into('!%ds' % len(self.data),
                      buf,
                      offset + ofproto.OFP_ACTION_EXPERIMENTER_HEADER_SIZE,
                      self.data)


class OFPGroupProp(OFPPropBase):
    _TYPES = {}


@OFPGroupProp.register_type(ofproto.OFPGPT_EXPERIMENTER)
class OFPGroupPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


@_register_parser
@_set_msg_type(ofproto.OFPT_GROUP_MOD)
class OFPGroupMod(MsgBase):
    """
    Modify group entry message

    The controller sends this message to modify the group table.

    ================== ======================================================
    Attribute          Description
    ================== ======================================================
    command            One of the following values.

                       | OFPGC_ADD
                       | OFPGC_MODIFY
                       | OFPGC_DELETE
                       | OFPGC_INSERT_BUCKET
                       | OFPGC_REMOVE_BUCKET
    type               One of the following values.

                       | OFPGT_ALL
                       | OFPGT_SELECT
                       | OFPGT_INDIRECT
                       | OFPGT_FF
    group_id           Group identifier.
    command_bucket_id  Bucket Id used as part of OFPGC_INSERT_BUCKET and
                       OFPGC_REMOVE_BUCKET commands execution.
    buckets            List of ``OFPBucket`` instance
    properties         List of ``OFPGroupProp`` instance
    ================== ======================================================

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
            command_bucket_id=1
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                         ofp.OFPGT_SELECT, group_id,
                                         command_bucket_id, buckets)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, command=ofproto.OFPGC_ADD,
                 type_=ofproto.OFPGT_ALL, group_id=0, command_bucket_id=0,
                 buckets=None, properties=None, bucket_array_len=None):
        buckets = buckets if buckets else []
        properties = properties if properties else []
        super(OFPGroupMod, self).__init__(datapath)
        self.command = command
        self.type = type_
        self.group_id = group_id
        self.command_bucket_id = command_bucket_id
        self.buckets = buckets
        self.properties = properties

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPGroupMod, cls).parser(
            datapath, version, msg_type, msg_len, xid, buf)
        (msg.command, msg.type, msg.group_id, msg.bucket_array_len,
         msg.command_bucket_id) = struct.unpack_from(
            ofproto.OFP_GROUP_MOD_PACK_STR, buf, ofproto.OFP_HEADER_SIZE)
        offset = ofproto.OFP_GROUP_MOD_SIZE

        bucket_buf = buf[offset:offset + msg.bucket_array_len]
        msg.buckets = []
        while bucket_buf:
            bucket = OFPBucket.parser(bucket_buf, 0)
            msg.buckets.append(bucket)
            bucket_buf = bucket_buf[bucket.len:]
        offset += msg.bucket_array_len

        rest = buf[offset:offset + msg.msg_len]
        while rest:
            p, rest = OFPGroupProp.parse(rest)
            msg.properties.append(p)

        return msg

    def _serialize_body(self):
        offset = ofproto.OFP_GROUP_MOD_SIZE
        self.bucket_array_len = 0
        for b in self.buckets:
            b.serialize(self.buf, offset)
            offset += b.len
            self.bucket_array_len += b.len

        msg_pack_into(ofproto.OFP_GROUP_MOD_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE,
                      self.command, self.type, self.group_id,
                      self.bucket_array_len, self.command_bucket_id)

        bin_props = bytearray()
        for p in self.properties:
            bin_props += p.serialize()
        self.buf += bin_props


class OFPPortModProp(OFPPropBase):
    _TYPES = {}


class OFPPortModPropEthernet(OFPPortModProp):
    def __init__(self, type_=None, length=None, advertise=None):
        self.type = type_
        self.advertise = advertise

    def serialize(self):
        # fixup
        self.length = struct.calcsize(
            ofproto.OFP_PORT_MOD_PROP_ETHERNET_PACK_STR)

        buf = bytearray()
        msg_pack_into(ofproto.OFP_PORT_MOD_PROP_ETHERNET_PACK_STR,
                      buf, 0, self.type, self.length, self.advertise)
        return buf


class OFPPortModPropOptical(OFPPortModProp):
    def __init__(self, type_=None, length=None, configure=None,
                 freq_lmda=None, fl_offset=None, grid_span=None,
                 tx_pwr=None):
        self.type = type_
        self.length = length
        self.configure = configure
        self.freq_lmda = freq_lmda
        self.fl_offset = fl_offset
        self.grid_span = grid_span
        self.tx_pwr = tx_pwr

    def serialize(self):
        # fixup
        self.length = struct.calcsize(
            ofproto.OFP_PORT_MOD_PROP_OPTICAL_PACK_STR)

        buf = bytearray()
        msg_pack_into(ofproto.OFP_PORT_MOD_PROP_OPTICAL_PACK_STR, buf, 0,
                      self.type, self.length, self.configure, self.freq_lmda,
                      self.fl_offset, self.grid_span, self.tx_pwr)
        return buf


class OFPPortModPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


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
    properties       List of ``OFPPortModProp`` subclass instance
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
            properties = [ofp_parser.OFPPortModPropEthernet(advertise)]
            req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config,
                                        mask, properties)
            datapath.send_msg(req)
    """

    _TYPE = {
        'ascii': [
            'hw_addr',
        ]
    }

    def __init__(self, datapath, port_no=0, hw_addr='00:00:00:00:00:00',
                 config=0, mask=0, properties=None):
        super(OFPPortMod, self).__init__(datapath)
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.config = config
        self.mask = mask
        self.properties = properties or []

    def _serialize_body(self):
        bin_props = bytearray()
        for p in self.properties:
            bin_props += p.serialize()

        msg_pack_into(ofproto.OFP_PORT_MOD_PACK_STR, self.buf,
                      ofproto.OFP_HEADER_SIZE,
                      self.port_no, addrconv.mac.text_to_bin(self.hw_addr),
                      self.config,
                      self.mask)
        self.buf += bin_props


class OFPGroupBucketProp(OFPPropBase):
    _TYPES = {}


@OFPGroupBucketProp.register_type(ofproto.OFPGBPT_WEIGHT)
class OFPGroupBucketPropWeight(OFPGroupBucketProp):
    def __init__(self, type_=None, length=None, weight=None):
        super(OFPGroupBucketPropWeight, self).__init__(type_, length)
        self.weight = weight

    @classmethod
    def parser(cls, buf):
        prop = cls()
        (prop.type, prop.length, prop.weight) = struct.unpack_from(
            ofproto.OFP_GROUP_BUCKET_PROP_WEIGHT_PACK_STR, buf, 0)
        return prop

    def serialize(self):
        # fixup
        self.length = ofproto.OFP_GROUP_BUCKET_PROP_WEIGHT_SIZE

        buf = bytearray()
        msg_pack_into(ofproto.OFP_GROUP_BUCKET_PROP_WEIGHT_PACK_STR, buf, 0,
                      self.type, self.length, self.weight)
        return buf


@OFPGroupBucketProp.register_type(ofproto.OFPGBPT_WATCH_PORT)
@OFPGroupBucketProp.register_type(ofproto.OFPGBPT_WATCH_GROUP)
class OFPGroupBucketPropWatch(OFPGroupBucketProp):
    def __init__(self, type_=None, length=None, watch=None):
        super(OFPGroupBucketPropWatch, self).__init__(type_, length)
        self.watch = watch

    @classmethod
    def parser(cls, buf):
        prop = cls()
        (prop.type, prop.length, prop.watch) = struct.unpack_from(
            ofproto.OFP_GROUP_BUCKET_PROP_WATCH_PACK_STR, buf, 0)
        return prop

    def serialize(self):
        # fixup
        self.length = ofproto.OFP_GROUP_BUCKET_PROP_WATCH_SIZE

        buf = bytearray()
        msg_pack_into(ofproto.OFP_GROUP_BUCKET_PROP_WATCH_PACK_STR, buf, 0,
                      self.type, self.length, self.watch)
        return buf


@OFPGroupBucketProp.register_type(ofproto.OFPGBPT_EXPERIMENTER)
class OFPGroupBucketPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


class OFPBucket(StringifyMixin):
    def __init__(self, bucket_id=0, actions=None, properties=None,
                 len_=None, action_array_len=None):
        actions = actions if actions else []
        properties = properties if properties else []
        super(OFPBucket, self).__init__()
        self.bucket_id = bucket_id
        self.actions = actions
        self.properties = properties

    @classmethod
    def parser(cls, buf, offset):
        msg = cls()
        (msg.len, msg.action_array_len,
         msg.bucket_id) = struct.unpack_from(
            ofproto.OFP_BUCKET_PACK_STR, buf, offset)
        offset += ofproto.OFP_BUCKET_SIZE

        action_buf = buf[offset:offset + msg.action_array_len]
        msg.actions = []
        while action_buf:
            action = OFPAction.parser(action_buf, 0)
            msg.actions.append(action)
            action_buf = action_buf[action.len:]
        offset += msg.action_array_len

        rest = buf[offset:offset + msg.len]
        msg.properties = []
        while rest:
            p, rest = OFPGroupBucketProp.parse(rest)
            msg.properties.append(p)

        return msg

    def serialize(self, buf, offset):
        action_offset = offset + ofproto.OFP_BUCKET_SIZE
        self.action_array_len = 0
        for a in self.actions:
            a.serialize(buf, action_offset)
            action_offset += a.len
            self.action_array_len += a.len

        bin_props = bytearray()
        for p in self.properties:
            bin_props += p.serialize()
        props_len = len(bin_props)

        self.len = utils.round_up(ofproto.OFP_BUCKET_SIZE +
                                  self.action_array_len + props_len, 8)
        msg_pack_into(ofproto.OFP_BUCKET_PACK_STR, buf, offset,
                      self.len, self.action_array_len, self.bucket_id)

        buf += bin_props


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
    short_id         ID number for the controller.
                     The default is OFPCID_UNDEFINED.
    generation_id    Master Election Generation ID
    ================ ======================================================

    Example::

        def send_role_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPRoleRequest(datapath, ofp.OFPCR_ROLE_EQUAL,
                                            ofp.OFPCID_UNDEFINED, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, role=None, short_id=None,
                 generation_id=None):
        super(OFPRoleRequest, self).__init__(datapath)
        self.role = role
        self.short_id = short_id
        self.generation_id = generation_id

    def _serialize_body(self):
        assert self.role is not None
        assert self.generation_id is not None
        if self.short_id is None:
            self.short_id = ofproto.OFPCID_UNDEFINED
        msg_pack_into(ofproto.OFP_ROLE_REQUEST_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE,
                      self.role, self.short_id, self.generation_id)


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
    short_id         ID number for the controller.
                     The default is OFPCID_UNDEFINED.
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
                              'role=%s short_id=%d, generation_id=%d',
                              role, msg.short_id, msg.generation_id)
    """
    def __init__(self, datapath, role=None, short_id=None,
                 generation_id=None):
        super(OFPRoleReply, self).__init__(datapath)
        self.role = role
        self.short_id = short_id
        self.generation_id = generation_id

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPRoleReply, cls).parser(datapath, version,
                                              msg_type, msg_len, xid,
                                              buf)
        (msg.role, msg.short_id, msg.generation_id) = struct.unpack_from(
            ofproto.OFP_ROLE_REQUEST_PACK_STR, msg.buf,
            ofproto.OFP_HEADER_SIZE)
        return msg


class OFPAsyncConfigProp(OFPPropBase):
    _TYPES = {}


@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_PACKET_IN_SLAVE)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_PACKET_IN_MASTER)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_PORT_STATUS_SLAVE)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_PORT_STATUS_MASTER)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_FLOW_REMOVED_SLAVE)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_FLOW_REMOVED_MASTER)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_ROLE_STATUS_SLAVE)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_ROLE_STATUS_MASTER)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_TABLE_STATUS_SLAVE)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_TABLE_STATUS_MASTER)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_REQUESTFORWARD_SLAVE)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_REQUESTFORWARD_MASTER)
class OFPAsyncConfigPropReasons(OFPAsyncConfigProp):
    def __init__(self, type_=None, length=None, mask=None):
        self.type = type_
        self.length = length
        self.mask = mask

    @classmethod
    def parser(cls, buf):
        reasons = cls()
        (reasons.type, reasons.length, reasons.mask) = struct.unpack_from(
            ofproto.OFP_ASYNC_CONFIG_PROP_REASONS_PACK_STR, buf, 0)
        return reasons

    def serialize(self):
        # fixup
        self.length = ofproto.OFP_ASYNC_CONFIG_PROP_REASONS_SIZE

        buf = bytearray()
        msg_pack_into(ofproto.OFP_ASYNC_CONFIG_PROP_REASONS_PACK_STR, buf, 0,
                      self.type, self.length, self.mask)
        return buf


@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_EXPERIMENTER_SLAVE)
@OFPAsyncConfigProp.register_type(ofproto.OFPACPT_EXPERIMENTER_MASTER)
class OFPAsyncConfigPropExperimenter(OFPPropCommonExperimenter4ByteData):
    pass


@_set_msg_type(ofproto.OFPT_GET_ASYNC_REQUEST)
class OFPGetAsyncRequest(MsgBase):
    """
    Get asynchronous configuration request message

    The controller uses this message to query the asynchronous message.

    Example::

        def send_get_async_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPGetAsyncRequest(datapath)
            datapath.send_msg(req)
    """
    def __init__(self, datapath):
        super(OFPGetAsyncRequest, self).__init__(datapath)


@_register_parser
@_set_msg_type(ofproto.OFPT_GET_ASYNC_REPLY)
class OFPGetAsyncReply(MsgBase):
    """
    Get asynchronous configuration reply message

    The switch responds with this message to a get asynchronous configuration
    request.

    ================== ====================================================
    Attribute          Description
    ================== ====================================================
    properties         List of ``OFPAsyncConfigProp`` subclass instances
    ================== ====================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPGetAsyncReply, MAIN_DISPATCHER)
        def get_async_reply_handler(self, ev):
            msg = ev.msg

            self.logger.debug('OFPGetAsyncReply received: '
                              'properties=%s', repr(msg.properties))
    """
    def __init__(self, datapath, properties=None):
        super(OFPGetAsyncReply, self).__init__(datapath)
        self.properties = properties

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPGetAsyncReply, cls).parser(datapath, version,
                                                  msg_type, msg_len,
                                                  xid, buf)

        msg.properties = []
        rest = msg.buf[ofproto.OFP_HEADER_SIZE:]
        while rest:
            p, rest = OFPAsyncConfigProp.parse(rest)
            msg.properties.append(p)

        return msg


@_set_msg_type(ofproto.OFPT_SET_ASYNC)
class OFPSetAsync(MsgBase):
    """
    Set asynchronous configuration message

    The controller sends this message to set the asynchronous messages that
    it wants to receive on a given OpneFlow channel.

    ================== ====================================================
    Attribute          Description
    ================== ====================================================
    properties         List of ``OFPAsyncConfigProp`` subclass instances
    ================== ====================================================

    Example::

        def send_set_async(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            properties = [ofp_parser.OFPAsyncConfigPropReasons(
                          8, ofp_parser.OFPACPT_PACKET_IN_SLAVE,
                          (ofp_parser.OFPR_APPLY_ACTION |
                           ofp_parser.OFPR_INVALID_TTL)),
                          ofp_parser.OFPAsyncConfigPropExperimenter(
                          ofp.OFPTFPT_EXPERIMENTER_MASTER,
                          16, 100, 2, bytearray())]
            req = ofp_parser.OFPSetAsync(datapath, properties)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, properties=None):
        super(OFPSetAsync, self).__init__(datapath)
        self.properties = properties

    def _serialize_body(self):
        bin_props = bytearray()
        for p in self.properties:
            bin_props += p.serialize()

        self.buf += bin_props


@_register_parser
@_set_msg_type(ofproto.OFPT_BUNDLE_CONTROL)
class OFPBundleCtrlMsg(MsgBase):
    """
    Bundle control message

    The controller uses this message to create, destroy and commit bundles

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    bundle_id        Id of the bundle
    type             One of the following values.

                     | OFPBCT_OPEN_REQUEST
                     | OFPBCT_OPEN_REPLY
                     | OFPBCT_CLOSE_REQUEST
                     | OFPBCT_CLOSE_REPLY
                     | OFPBCT_COMMIT_REQUEST
                     | OFPBCT_COMMIT_REPLY
                     | OFPBCT_DISCARD_REQUEST
                     | OFPBCT_DISCARD_REPLY
    flags            Bitmap of the following flags.

                     | OFPBF_ATOMIC
                     | OFPBF_ORDERED
    properties       List of ``OFPBundleProp`` subclass instance
    ================ ======================================================

    Example::

        def send_bundle_control(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPBundleCtrlMsg(datapath, 7,
                                              ofp.OFPBCT_OPEN_REQUEST,
                                              [ofp.OFPBF_ATOMIC], [])
            datapath.send_msg(req)
    """
    def __init__(self, datapath, bundle_id=None, type_=None, flags=None,
                 properties=None):
        super(OFPBundleCtrlMsg, self).__init__(datapath)
        self.bundle_id = bundle_id
        self.type = type_
        self.flags = flags
        self.properties = properties

    def _serialize_body(self):
        bin_props = bytearray()
        for p in self.properties:
            bin_props += p.serialize()

        msg_pack_into(ofproto.OFP_BUNDLE_CTRL_MSG_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE, self.bundle_id,
                      self.type, self.flags)
        self.buf += bin_props

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = super(OFPBundleCtrlMsg, cls).parser(datapath, version,
                                                  msg_type, msg_len,
                                                  xid, buf)
        (bundle_id, type_, flags) = struct.unpack_from(
            ofproto.OFP_BUNDLE_CTRL_MSG_PACK_STR, buf,
            ofproto.OFP_HEADER_SIZE)
        msg.bundle_id = bundle_id
        msg.type = type_
        msg.flags = flags
        msg.properties = []
        rest = msg.buf[ofproto.OFP_BUNDLE_CTRL_MSG_SIZE:]
        while rest:
            p, rest = OFPBundleProp.parse(rest)
            msg.properties.append(p)

        return msg


@_set_msg_type(ofproto.OFPT_BUNDLE_ADD_MESSAGE)
class OFPBundleAddMsg(MsgInMsgBase):
    """
    Bundle control message

    The controller uses this message to create, destroy and commit bundles

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    bundle_id        Id of the bundle
    flags            Bitmap of the following flags.

                     | OFPBF_ATOMIC
                     | OFPBF_ORDERED
    message          ``MsgBase`` subclass instance
    properties       List of ``OFPBundleProp`` subclass instance
    ================ ======================================================

    Example::

        def send_bundle_add_message(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            msg = ofp_parser.OFPRoleRequest(datapath, ofp.OFPCR_ROLE_EQUAL, 0)

            req = ofp_parser.OFPBundleAddMsg(datapath, 7, [ofp.OFPBF_ATOMIC],
                                             msg, [])
            datapath.send_msg(req)
    """
    def __init__(self, datapath, bundle_id, flags, message, properties):
        super(OFPBundleAddMsg, self).__init__(datapath)
        self.bundle_id = bundle_id
        self.flags = flags
        self.message = message
        self.properties = properties

    def _serialize_body(self):
        # The xid of the inner message must be the same as
        # that of the outer message (OF1.4.0 7.3.9.2)
        if self.message.xid != self.xid:
            self.message.set_xid(self.xid)

        # Message
        self.message.serialize()
        tail_buf = self.message.buf

        # Pad
        if len(self.properties) > 0:
            message_len = len(tail_buf)
            pad_len = utils.round_up(message_len, 8) - message_len
            msg_pack_into("%dx" % pad_len, tail_buf, message_len)

        # Properties
        for p in self.properties:
            tail_buf += p.serialize()

        # Head
        msg_pack_into(ofproto.OFP_BUNDLE_ADD_MSG_0_PACK_STR,
                      self.buf, ofproto.OFP_HEADER_SIZE, self.bundle_id,
                      self.flags)

        # Finish
        self.buf += tail_buf


nx_actions.generate(
    'ryu.ofproto.ofproto_v1_5',
    'ryu.ofproto.ofproto_v1_5_parser'
)
