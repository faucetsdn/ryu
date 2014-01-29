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

import struct
import itertools

from ryu.lib import addrconv
from ryu.lib import mac
from ryu import utils
from ofproto_parser import StringifyMixin, MsgBase, msg_pack_into, msg_str_attr
from . import ofproto_parser
from . import ofproto_common
from . import ofproto_v1_4 as ofproto

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
    def __init__(self, datapath, elements=[]):
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
    flags         One of the following configuration flags.
                  OFPC_FRAG_NORMAL
                  OFPC_FRAG_DROP
                  OFPC_FRAG_REASM
                  OFPC_FRAG_MASK
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
                  OFPC_FRAG_NORMAL
                  OFPC_FRAG_DROP
                  OFPC_FRAG_REASM
                  OFPC_FRAG_MASK
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
    """

    def __init__(self, type_=None, length=None, **kwargs):
        super(OFPMatch, self).__init__()
        self.type = ofproto.OFPMT_OXM
        self.length = length
        kwargs = dict(ofproto.oxm_normalize_user(k, v) for
                      (k, v) in kwargs.iteritems())
        fields = [ofproto.oxm_from_user(k, v) for (k, v)
                  in kwargs.iteritems()]
        fields.sort()
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
        ofproto_parser.msg_pack_into("%dx" % pad_len, buf, field_offset)

        return length + pad_len

    def __getitem__(self, key):
        return dict(self._fields2)[key]

    def __contains__(self, key):
        return key in dict(self._fields2)

    def iteritems(self):
        return dict(self._fields2).iteritems()

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
        o = OFPMatch()
        # XXX old api compat
        # serialize and parse to fill OFPMatch.fields
        buf = bytearray()
        o.serialize(buf, 0)
        return OFPMatch.parser(str(buf), 0)


class OFPPortDescPropUnknown(StringifyMixin):
    def __init__(self, type_=None, length=None, buf=None):
        self.buf = buf

    @classmethod
    def parser(cls, buf):
        return cls(buf=buf)


class OFPPortProp(StringifyMixin):
    _PACK_STR = '!HH'
    _TYPES = {}

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
        # needs
        rest = buf[utils.round_up(length, 8):]
        try:
            subcls = cls._TYPES[type_]
        except KeyError:
            subcls = OFPPortPropUnknown
        prop = subcls.parser(buf)
        prop.type = type_
        prop.length = length
        return prop, rest


@OFPPortProp.register_type(ofproto.OFPPDPT_ETHERNET)
class OFPPortDescPropEthernet(StringifyMixin):
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
        hasmask = (header >> 8) & 1
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
        ofproto_parser.msg_pack_into('!I', buf, offset, self.header)
        self.length = 4

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

    def serialize(self, buf, offset):
        self.value |= ofproto.OFPVID_PRESENT
        super(MTVlanVid, self).serialize(buf, offset)


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


class MTIPv6(StringifyMixin):
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


@OFPMatchField.register_field_header([ofproto.OXM_OF_MPLS_BOS])
class MTMplsBos(OFPMatchField):
    pack_str = '!B'

    def __init__(self, header, value, mask=None):
        super(MTMplsBos, self).__init__(header)
        self.value = value


@OFPMatchField.register_field_header([ofproto.OXM_OF_PBB_ISID,
                                      ofproto.OXM_OF_PBB_ISID_W])
class MTPbbIsid(OFPMatchField):
    pack_str = '!3B'

    def __init__(self, header, value, mask=None):
        super(MTPbbIsid, self).__init__(header)
        self.value = value
        self.mask = mask

    @classmethod
    def field_parser(cls, header, buf, offset):
        hasmask = (header >> 8) & 1
        mask = None
        if ofproto.oxm_tlv_header_extract_hasmask(header):
            pack_str = '!' + cls.pack_str[1:] * 2
            (v1, v2, v3, m1, m2, m3) = struct.unpack_from(pack_str, buf,
                                                          offset + 4)
            value = v1 << 16 | v2 << 8 | v3
            mask = m1 << 16 | m2 << 8 | m3
        else:
            (v1, v2, v3,) = struct.unpack_from(cls.pack_str, buf, offset + 4)
            value = v1 << 16 | v2 << 8 | v3
        return cls(header, value, mask)

    def _put(self, buf, offset, value):
        ofproto_parser.msg_pack_into(self.pack_str, buf, offset,
                                     (value >> 16) & 0xff,
                                     (value >> 8) & 0xff,
                                     (value >> 0) & 0xff)
        self.length += self.n_bytes


@OFPMatchField.register_field_header([ofproto.OXM_OF_TUNNEL_ID,
                                      ofproto.OXM_OF_TUNNEL_ID_W])
class MTTunnelId(OFPMatchField):
    pack_str = '!Q'

    def __init__(self, header, value, mask=None):
        super(MTTunnelId, self).__init__(header)
        self.value = value
        self.mask = mask


@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV6_EXTHDR,
                                      ofproto.OXM_OF_IPV6_EXTHDR_W])
class MTIPv6ExtHdr(OFPMatchField):
    pack_str = '!H'

    def __init__(self, header, value, mask=None):
        super(MTIPv6ExtHdr, self).__init__(header)
        self.value = value
        self.mask = mask


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
                  OFPR_TABLE_MISS
                  OFPR_APPLY_ACTION
                  OFPR_INVALID_TTL
                  OFPR_ACTION_SET
                  OFPR_GROUP
                  OFPR_PACKET_OUT
    table_id      ID of the table that was looked up
    cookie        Cookie of the flow entry that was looked up
    match         Instance of ``OFPMatch``
    data          Ethernet frame
    ============= =========================================================

    Example::

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            msg = ev.msg
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


class OFPPort(StringifyMixin):
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
        name = name.rstrip('\0')
        props = []
        rest = buf[offset + ofproto.OFP_PORT_SIZE:offset + length]
        while rest:
            p, rest = OFPPortProp.parse(rest)
            props.append(p)
        ofpport = cls(port_no, length, hw_addr, name, config, state, props)
        return ofpport


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
            ofproto.OFP_MULTIPART_REPLY_PACK_STR, buffer(buf),
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
        desc = map(lambda x: x.rstrip('\0'), desc)
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
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPDescStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags, type_=None):
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


@_set_stats_type(ofproto.OFPMP_PORT_DESC, OFPPort)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPPortDescStatsRequest(OFPMultipartRequest):
    """
    Port description request message

    The controller uses this message to query description of all the ports.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flags            Zero or ``OFPMPF_REQ_MORE``
    ================ ======================================================

    Example::

        def send_port_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
            datapath.send_msg(req)
    """
    def __init__(self, datapath, flags, type_=None):
        super(OFPPortDescStatsRequest, self).__init__(datapath, flags)


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
    body             List of ``OFPPortDescStats`` instance
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


@_set_stats_type(ofproto.OFPMP_GROUP, OFPGroupStats)
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
    def __init__(self, datapath, flags, group_id, type_=None):
        super(OFPGroupStatsRequest, self).__init__(datapath, flags)
        self.group_id = group_id

    def _serialize_stats_body(self):
        msg_pack_into(ofproto.OFP_GROUP_STATS_REQUEST_PACK_STR,
                      self.buf,
                      ofproto.OFP_MULTIPART_REQUEST_SIZE,
                      self.group_id)


@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_GROUP, OFPGroupStats)
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


class OFPFlowStats(StringifyMixin):
    def __init__(self, table_id=None, duration_sec=None, duration_nsec=None,
                 priority=None, idle_timeout=None, hard_timeout=None,
                 flags=None, importance=None, cookie=None, packet_count=None,
                 byte_count=None, match=None, instructions=None,
                 length=None):
        super(OFPFlowStats, self).__init__()
        self.length = 0
        self.table_id = table_id
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.priority = priority
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.flags = flags
        self.importance = importance
        self.cookie = cookie
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.match = match
        self.instructions = instructions

    @classmethod
    def parser(cls, buf, offset):
        flow_stats = cls()

        (flow_stats.length, flow_stats.table_id,
         flow_stats.duration_sec, flow_stats.duration_nsec,
         flow_stats.priority, flow_stats.idle_timeout,
         flow_stats.hard_timeout, flow_stats.flags,
         flow_stats.importance, flow_stats.cookie,
         flow_stats.packet_count,
         flow_stats.byte_count) = struct.unpack_from(
            ofproto.OFP_FLOW_STATS_0_PACK_STR, buf, offset)
        offset += ofproto.OFP_FLOW_STATS_0_SIZE

        flow_stats.match = OFPMatch.parser(buf, offset)
        match_length = utils.round_up(flow_stats.match.length, 8)
        inst_length = (flow_stats.length - (ofproto.OFP_FLOW_STATS_SIZE -
                                            ofproto.OFP_MATCH_SIZE +
                                            match_length))
        offset += match_length
        instructions = []
        while inst_length > 0:
            inst = OFPInstruction.parser(buf, offset)
            instructions.append(inst)
            offset += inst.len
            inst_length -= inst.len

        flow_stats.instructions = instructions
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


@_set_stats_type(ofproto.OFPMP_FLOW, OFPFlowStats)
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
@_set_stats_type(ofproto.OFPMP_FLOW, OFPFlowStats)
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
                flows.append('table_id=%s '
                             'duration_sec=%d duration_nsec=%d '
                             'priority=%d '
                             'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                             'importance=%d cookie=%d packet_count=%d '
                             'byte_count=%d match=%s instructions=%s' %
                             (stat.table_id,
                              stat.duration_sec, stat.duration_nsec,
                              stat.priority,
                              stat.idle_timeout, stat.hard_timeout,
                              stat.flags, stat.importance,
                              stat.cookie, stat.packet_count, stat.byte_count,
                              stat.match, stat.instructions))
            self.logger.debug('FlowStats: %s', flows)
    """
    def __init__(self, datapath, type_=None, **kwargs):
        super(OFPFlowStatsReply, self).__init__(datapath, **kwargs)


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
                     OFPFC_ADD
                     OFPFC_MODIFY
                     OFPFC_MODIFY_STRICT
                     OFPFC_DELETE
                     OFPFC_DELETE_STRICT
    idle_timeout     Idle time before discarding (seconds)
    hard_timeout     Max time before discarding (seconds)
    priority         Priority level of flow entry
    buffer_id        Buffered packet to apply to (or OFP_NO_BUFFER)
    out_port         For ``OFPFC_DELETE*`` commands, require matching
                     entries to include this as an output port
    out_group        For ``OFPFC_DELETE*`` commands, require matching
                     entries to include this as an output group
    flags            One of the following values.
                     OFPFF_SEND_FLOW_REM
                     OFPFF_CHECK_OVERLAP
                     OFPFF_RESET_COUNTS
                     OFPFF_NO_PKT_COUNTS
                     OFPFF_NO_BYT_COUNTS
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
                                        imporotance,
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
                 instructions=[]):
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
        self.match = match
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


class OFPInstruction(object):
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
class OFPInstructionGotoTable(StringifyMixin):
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
class OFPInstructionWriteMetadata(StringifyMixin):
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
    def __init__(self, metadata, metadata_mask, len_=None):
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
class OFPInstructionActions(StringifyMixin):
    """
    Actions instruction

    This instruction writes/applies/clears the actions.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    type             One of following values.
                     OFPIT_WRITE_ACTIONS
                     OFPIT_APPLY_ACTIONS
                     OFPIT_CLEAR_ACTIONS
    actions          list of OpenFlow action class
    ================ ======================================================

    ``type`` attribute corresponds to ``type_`` parameter of __init__.
    """
    def __init__(self, type_, actions=None, len_=None):
        super(OFPInstructionActions, self).__init__()
        self.type = type_
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
        ofproto_parser.msg_pack_into("%dx" % pad_len, buf, action_offset)
        self.len += pad_len

        msg_pack_into(ofproto.OFP_INSTRUCTION_ACTIONS_PACK_STR,
                      buf, offset, self.type, self.len)


@OFPInstruction.register_instruction_type([ofproto.OFPIT_METER])
class OFPInstructionMeter(StringifyMixin):
    """
    Meter instruction

    This instruction applies the meter.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    meter_id         Meter instance
    ================ ======================================================
    """
    _base_attributes = ['type', 'len']

    def __init__(self, meter_id):
        super(OFPInstructionMeter, self).__init__()
        self.type = ofproto.OFPIT_METER
        self.len = ofproto.OFP_INSTRUCTION_METER_SIZE
        self.meter_id = meter_id

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, meter_id) = struct.unpack_from(
            ofproto.OFP_INSTRUCTION_METER_PACK_STR,
            buf, offset)
        return cls(meter_id)

    def serialize(self, buf, offset):
        msg_pack_into(ofproto.OFP_INSTRUCTION_METER_PACK_STR,
                      buf, offset, self.type, self.len, self.meter_id)


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
    def __init__(self, group_id, type_=None, len_=None):
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


@OFPAction.register_action_type(ofproto.OFPAT_SET_FIELD,
                                ofproto.OFP_ACTION_SET_FIELD_SIZE)
class OFPActionSetField(OFPAction):
    """
    Set field action

    This action modifies a header field in the packet.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    field            Instance of ``OFPMatchField``
    ================ ======================================================
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
            key = kwargs.keys()[0]
            value = kwargs[key]
            assert isinstance(key, (str, unicode))
            assert not isinstance(value, tuple)  # no mask
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
        ofproto_parser.msg_pack_into("%dx" % pad_len, buf, offset + 4 + len_)

    # XXX old api compat
    def serialize_old(self, buf, offset):
        len_ = ofproto.OFP_ACTION_SET_FIELD_SIZE + self.field.oxm_len()
        self.len = utils.round_up(len_, 8)
        pad_len = self.len - len_

        msg_pack_into('!HH', buf, offset, self.type, self.len)
        self.field.serialize(buf, offset + 4)
        offset += len_
        ofproto_parser.msg_pack_into("%dx" % pad_len, buf, offset)

    # XXX old api compat
    def _composed_with_old_api(self):
        return not hasattr(self, 'value')

    def to_jsondict(self):
        # XXX old api compat
        if self._composed_with_old_api():
            # copy object first because serialize_old is destructive
            o2 = OFPActionSetField(self.field)
            # serialize and parse to fill new fields
            buf = bytearray()
            o2.serialize(buf, 0)
            o = OFPActionSetField.parser(str(buf), 0)
        else:
            o = self
        return {
            self.__class__.__name__: {
                'field': ofproto.oxm_to_jsondict(self.key, self.value)
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
        return OFPActionSetField.parser(str(buf), 0)

    # XXX old api compat
    def __str__(self):
        # XXX old api compat
        if self._composed_with_old_api():
            # copy object first because serialize_old is destructive
            o2 = OFPActionSetField(self.field)
            # serialize and parse to fill new fields
            buf = bytearray()
            o2.serialize(buf, 0)
            o = OFPActionSetField.parser(str(buf), 0)
        else:
            o = self
        return super(OFPActionSetField, o).__str__()

    __repr__ = __str__

    def stringify_attrs(self):
        yield (self.key, self.value)
