# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
# Copyright (C) 2012 Simon Horman <horms ad verge net au>
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

import struct

from ryu import exception
from ryu.lib import mac
from . import ofproto_parser
from . import ofproto_v1_0
from . import ofproto

import logging
LOG = logging.getLogger('ryu.ofproto.nx_match')


UINT64_MAX = (1 << 64) - 1

FWW_IN_PORT = 1 << 0
FWW_DL_SRC = 1 << 2
FWW_DL_DST = 1 << 3
FWW_DL_TYPE = 1 << 4
# No corresponding OFPFW_* bits
FWW_ETH_MCAST = 1 << 1
FWW_NW_DSCP = 1 << 6
FWW_NW_ECN = 1 << 7
FWW_ALL = (1 << 13) - 1

# Ethernet types, for set_dl_type()
ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_IPV6 = 0x86dd
ETH_TYPE_LACP = 0x8809

IP_ECN_MASK = 0x03
IP_DSCP_MASK = 0xfc

MF_PACK_STRING_BE64 = '!Q'
MF_PACK_STRING_BE16 = '!H'
MF_PACK_STRING_8 = '!B'
MF_PACK_STRING_MAC = '!6s'

_MF_FIELDS = {}


class Flow(object):
    def __init__(self):
        self.in_port = 0
        self.dl_src = mac.DONTCARE
        self.dl_dst = mac.DONTCARE
        self.dl_type = 0
        self.nw_tos = 0


class FlowWildcards(object):
    def __init__(self):
        self.tun_id_mask = 0
        self.wildcards = FWW_ALL

    def set_dl_dst_mask(self, mask):
        assert mask[0] in ['\x00', '\x01', '\xfe', '\xff']
        if mask[0] == '\x00':
            self.wildcards |= FWW_DL_DST | FWW_ETH_MCAST
        elif mask[0] == '\x01':
            self.wildcards = (self.wildcards | FWW_DL_DST) & ~FWW_ETH_MCAST
        elif mask[0] == '\xfe':
            self.wildcards = (self.wildcards & ~FWW_DL_DST) | FWW_ETH_MCAST
        elif mask[0] == '\xff':
            self.wildcards &= ~(FWW_DL_DST | FWW_ETH_MCAST)

    def to_dl_dst_mask(self):
        key = self.wildcards & (FWW_DL_DST | FWW_ETH_MCAST)
        if key == 0:
            return mac.BROADCAST
        elif key == FWW_DL_DST:
            return mac.UNICAST
        elif key == FWW_ETH_MCAST:
            return mac.MULTICAST
        else:
            return mac.DONTCARE


def flow_wildcards_is_dl_dst_mask_valid(cls, mask):
    # 00:00:00:00:00:00, 01:00:00:00:00:00, fe:ff:ff:ff:ff:ff or
    # ff:ff:ff:ff:ff:ff
    #
    # The trailing octects should all be the same
    # so the set of those values should only have one element
    # which can be compared with the desired value
    s = set(mask[1:])
    if ((len(s) != 1) or
        (mask[0] in ['\x00', '\x01']) and ('\x00' in s) or
        (mask[0] in ['\xff', '\xfe']) and ('\xff' in s)):
        return True
    else:
        return False


class ClsRule(object):
    def __init__(self):
        self.wc = FlowWildcards()
        self.flow = Flow()

    def set_in_port(self, port):
        self.wc.wildcards &= ~FWW_IN_PORT
        self.flow.in_port = port

    def set_dl_dst(self, dl_dst):
        self.wc.wildcards &= ~(FWW_DL_DST | FWW_ETH_MCAST)
        self.flow.dl_dst = dl_dst

    def set_dl_dst_masked(self, dl_dst, mask):
        self.wc.set_dl_dst_mask(mask)
        # bit-wise and of the corresponding elements of dl_dst and mask
        self.flow.dl_dst = reduce(lambda x, y: x + y,
                                  map(lambda x: chr(ord(x[0]) & ord(x[1])),
                                      zip(dl_dst, mask)))

    def set_dl_src(self, dl_src):
        self.wc.wildcards &= ~FWW_DL_SRC
        self.flow.dl_src = dl_src

    def set_dl_type(self, dl_type):
        self.wc.wildcards &= ~FWW_DL_TYPE
        self.flow.dl_type = dl_type

    def set_nw_dscp(self, nw_dscp):
        self.wc.wildcards &= ~FWW_NW_DSCP
        self.flow.nw_tos &= ~IP_DSCP_MASK
        self.flow.nw_tos |= nw_dscp & IP_DSCP_MASK

    def set_tun_id(self, tun_id):
        self.set_tun_id_masked(tun_id, UINT64_MAX)

    def set_tun_id_masked(self, tun_id, mask):
        self.wc.tun_id_mask = mask
        self.flow.tun_id = tun_id & mask

    def set_nw_ecn(self, nw_ecn):
        self.wc.wildcards &= ~FWW_NW_ECN
        self.flow.nw_tos &= ~IP_ECN_MASK
        self.flow.nw_tos |= nw_ecn & IP_ECN_MASK

    def flow_format(self):
        # Tunnel ID is only supported by NXM
        if self.wc.tun_id_mask != 0:
            return ofproto_v1_0.NXFF_NXM

        # Masking DL_DST is only supported by NXM
        mask = FWW_DL_DST | FWW_ETH_MCAST
        key = self.wc.wildcards & mask
        if key != mask and key != 0:
            return ofproto_v1_0.NXFF_NXM

        # ECN is only supported by NXM
        if not self.wc.wildcards & FWW_NW_ECN:
            return ofproto_v1_0.NXFF_NXM

        return ofproto_v1_0.NXFF_OPENFLOW10

    def match_tuple(self):
        assert self.flow_format() == ofproto_v1_0.NXFF_OPENFLOW10
        wildcards = ofproto.OFPFW_ALL

        if not self.wc.wildcards & FWW_IN_PORT:
            wildcards &= ~ofproto.OFPFW_IN_PORT

        if not self.wc.wildcards & FWW_DL_SRC:
            wildcards &= ~ofproto.OFPFW_DL_SRC

        mask = FWW_DL_DST | FWW_ETH_MCAST
        key = self.wc.wildcards & mask
        if key == 0:
            wildcards &= ~ofproto.OFPFW_DL_DST

        if not self.wc.wildcards & FWW_DL_TYPE:
            wildcards &= ~ofproto.OFPFW_DL_TYPE

        # FIXME: Add support for dl_vlan, fl_vlan_pcp, nw_tos, nw_proto,
        # nw_src, nw_dst, tp_src and dp_dst to self
        return (wildcards, self.flow.in_port, self.flow.dl_src,
                self.flow.dl_dst, 0, 0, self.flow.dl_type,
                self.flow.nw_tos & IP_DSCP_MASK, 0, 0, 0, 0, 0)


def _set_nxm_headers(nxm_headers):
    '''Annotate corresponding NXM header'''
    def _set_nxm_headers(self):
        self.nxm_headers = nxm_headers
        return self
    return _set_nxm_headers


def _register_make(cls):
    '''class decorator to Register mf make'''
    assert cls.nxm_headers is not None
    assert cls.nxm_headers is not []
    for nxm_header in cls.nxm_headers:
        assert nxm_header not in _MF_FIELDS
        _MF_FIELDS[nxm_header] = cls.make
    return cls


def mf_from_nxm_header(nxm_header):
    if nxm_header not in _MF_FIELDS:
        return None
    make = _MF_FIELDS.get(nxm_header)
    assert make is not None
    return make()


class MFField(object):
    def __init__(self, pack_str):
        self.pack_str = pack_str
        self.n_bytes = struct.calcsize(pack_str)
        self.n_bits = self.n_bytes * 8

    def _put(self, buf, offset, value):
        ofproto_parser.msg_pack_into(self.pack_str, buf, offset, value)
        return self.n_bytes

    def putw(self, buf, offset, value, mask):
        len = self._put(buf, offset, value)
        return len + self._put(buf, offset + len, mask)

    def _is_all_ones(self, value):
        return value == (1 << self.n_bits) - 1

    def putm(self, buf, offset, value, mask):
        if mask == 0:
            return 0
        elif self._is_all_ones(mask):
            return self._put(buf, offset, value)
        else:
            return self.putw(buf, offset, value, mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IN_PORT])
class MFInPort(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.in_port)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_DST, ofproto_v1_0.NXM_OF_ETH_DST_W])
class MFEthDst(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        mask = FWW_DL_DST | FWW_ETH_MCAST
        key = rule.wc.wildcards & mask
        if key == mask:
            return 0
        if key == 0:
            return self._put(buf, offset, rule.flow.dl_dst)
        else:
            return self.putw(buf, offset, rule.flow.dl_dst,
                             rule.wc.to_dl_dst_mask())


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_SRC])
class MFEthSrc(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.dl_src)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_TYPE])
class MFEthType(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.dl_type)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_TOS])
class MFIPDSCP(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset,
                         rule.flow.nw_tos & IP_DSCP_MASK)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_TUN_ID, ofproto_v1_0.NXM_NX_TUN_ID_W])
class MFTunId(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE64)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.tun_id, rule.wc.tun_id_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IP_ECN])
class MFIPECN(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset,
                         rule.flow.nw_tos & IP_ECN_MASK)


def serialize_nxm_match(rule, buf, offset):
    old_offset = offset

    if not rule.wc.wildcards & FWW_IN_PORT:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IN_PORT, rule)

    # Ethernet.
    offset += nxm_put_eth_dst(buf, offset, rule)
    if not rule.wc.wildcards & FWW_DL_SRC:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ETH_SRC, rule)
    if not rule.wc.wildcards & FWW_DL_TYPE:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ETH_TYPE, rule)

    # XXX: 802.1Q

    # L3
    if not rule.wc.wildcards & FWW_NW_DSCP:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IP_TOS, rule)
    if not rule.wc.wildcards & FWW_NW_ECN:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_IP_ECN, rule)
    # XXX: IP Source and Destination
    # XXX: IPv6
    # XXX: ARP

    # Tunnel Id
    if rule.wc.tun_id_mask != 0:
        if rule.wc.tun_id_mask == UINT64_MAX:
            header = ofproto_v1_0.NXM_NX_TUN_ID
        else:
            header = ofproto_v1_0.NXM_NX_TUN_ID_W
        offset += nxm_put(buf, offset, header, rule)

    # XXX: Cookie

    # Pad
    pad_len = round_up(offset) - offset
    ofproto_parser.msg_pack_into("%dx" % pad_len, buf, offset)

    # The returned length, the match_len, does not include the pad
    return offset - old_offset


def nxm_put(buf, offset, header, rule):
    nxm = NXMatch(header)
    len = nxm.put_header(buf, offset)
    mf = mf_from_nxm_header(nxm.header)
    return len + mf.put(buf, offset + len, rule)


def nxm_put_eth_dst(buf, offset, rule):
    mask = FWW_DL_DST | FWW_ETH_MCAST
    key = rule.wc.wildcards & mask
    if key == mask:
        return 0
    elif key == 0:
        header = ofproto_v1_0.NXM_OF_ETH_DST
    else:
        header = ofproto_v1_0.NXM_OF_ETH_DST_W
    return nxm_put(buf, offset, header, rule)


def round_up(length):
    return (length + 7) / 8 * 8  # Round up to a multiple of 8


class NXMatch(object):
    def __init__(self, header):
        self.header = header

    @classmethod
    def parse(cls, buf, offset, match_len):
        if match_len < 4:
            raise exception.OFPMalformedMessage
        (header,) = struct.unpack_from(ofproto_v1_0.NXM_HEADER_PACK_STRING,
                                       buf, offset)
        instance = cls(header)
        payload_len = instance.length()
        if payload_len == 0 or match_len < payload_len + 4:
            raise exception.OFPMalformedMessage
        return instance

    def vendor(self):
        return self.header >> 16

    def field(self):
        return (self.header >> 9) % 0x7f

    def type(self):
        return (self.header >> 9) % 0x7fffff

    def hasmask(self):
        return (self.header >> 8) & 1

    def length(self):
        return self.header & 0xff

    def show(self):
        return ('%08x (vendor=%x, field=%x, hasmask=%x len=%x)' %
                (self.header, self.vendor(), self.field(),
                 self.hasmask(), self.length()))

    def put_header(self, buf, offset):
        ofproto_parser.msg_pack_into(ofproto_v1_0.NXM_HEADER_PACK_STRING,
                                     buf, offset, self.header)
        return struct.calcsize(ofproto_v1_0.NXM_HEADER_PACK_STRING)
