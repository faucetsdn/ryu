# Copyright (C) 2011-2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
# Copyright (C) 2012 Simon Horman <horms ad verge net au>
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

from ryu import exception
from ryu.lib import mac
from ryu.lib.pack_utils import msg_pack_into
from ryu.ofproto import ether
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import inet


import logging
LOG = logging.getLogger('ryu.ofproto.nx_match')


UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
UINT16_MAX = (1 << 16) - 1

FWW_IN_PORT = 1 << 0
FWW_DL_TYPE = 1 << 4
FWW_NW_PROTO = 1 << 5
# No corresponding OFPFW_* bits
FWW_NW_DSCP = 1 << 1
FWW_NW_ECN = 1 << 2
FWW_ARP_SHA = 1 << 3
FWW_ARP_THA = 1 << 6
FWW_IPV6_LABEL = 1 << 7
FWW_NW_TTL = 1 << 8
FWW_ALL = (1 << 13) - 1

FLOW_NW_FRAG_ANY = 1 << 0
FLOW_NW_FRAG_LATER = 1 << 1
FLOW_NW_FRAG_MASK = FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER

IP_ECN_MASK = 0x03
IP_DSCP_MASK = 0xfc

MF_PACK_STRING_BE64 = '!Q'
MF_PACK_STRING_BE32 = '!I'
MF_PACK_STRING_BE16 = '!H'
MF_PACK_STRING_8 = '!B'
MF_PACK_STRING_MAC = '!6s'
MF_PACK_STRING_IPV6 = '!8H'

_MF_FIELDS = {}

FLOW_N_REGS = 8  # ovs 1.5


class Flow(ofproto_parser.StringifyMixin):
    def __init__(self):
        self.in_port = 0
        self.dl_vlan = 0
        self.dl_vlan_pcp = 0
        self.dl_src = mac.DONTCARE
        self.dl_dst = mac.DONTCARE
        self.dl_type = 0
        self.tp_dst = 0
        self.tp_src = 0
        self.nw_tos = 0
        self.vlan_tci = 0
        self.nw_ttl = 0
        self.nw_proto = 0
        self.arp_sha = 0
        self.arp_tha = 0
        self.nw_src = 0
        self.nw_dst = 0
        self.tun_id = 0
        self.arp_spa = 0
        self.arp_tpa = 0
        self.ipv6_src = []
        self.ipv6_dst = []
        self.nd_target = []
        self.nw_frag = 0
        self.regs = [0] * FLOW_N_REGS
        self.ipv6_label = 0
        self.pkt_mark = 0
        self.tcp_flags = 0


class FlowWildcards(ofproto_parser.StringifyMixin):
    def __init__(self):
        self.dl_src_mask = 0
        self.dl_dst_mask = 0
        self.tp_src_mask = 0
        self.tp_dst_mask = 0
        self.nw_src_mask = 0
        self.nw_dst_mask = 0
        self.tun_id_mask = 0
        self.arp_spa_mask = 0
        self.arp_tpa_mask = 0
        self.vlan_tci_mask = 0
        self.ipv6_src_mask = []
        self.ipv6_dst_mask = []
        self.nd_target_mask = []
        self.nw_frag_mask = 0
        self.regs_bits = 0
        self.regs_mask = [0] * FLOW_N_REGS
        self.wildcards = ofproto_v1_0.OFPFW_ALL
        self.pkt_mark_mask = 0
        self.tcp_flags_mask = 0


class ClsRule(ofproto_parser.StringifyMixin):
    """describe a matching rule for OF 1.0 OFPMatch (and NX).
    """
    def __init__(self, **kwargs):
        self.wc = FlowWildcards()
        self.flow = Flow()

        for key, value in kwargs.items():
            if key[:3] == 'reg':
                register = int(key[3:] or -1)
                self.set_reg(register, value)
                continue

            setter = getattr(self, 'set_' + key, None)
            if not setter:
                LOG.error('Invalid kwarg specified to ClsRule (%s)', key)
                continue

            if not isinstance(value, (tuple, list)):
                value = (value, )

            setter(*value)

    def set_in_port(self, port):
        self.wc.wildcards &= ~FWW_IN_PORT
        self.flow.in_port = port

    def set_dl_vlan(self, dl_vlan):
        self.wc.wildcards &= ~ofproto_v1_0.OFPFW_DL_VLAN
        self.flow.dl_vlan = dl_vlan

    def set_dl_vlan_pcp(self, dl_vlan_pcp):
        self.wc.wildcards &= ~ofproto_v1_0.OFPFW_DL_VLAN_PCP
        self.flow.dl_vlan_pcp = dl_vlan_pcp

    def set_dl_dst(self, dl_dst):
        self.flow.dl_dst = dl_dst

    def set_dl_dst_masked(self, dl_dst, mask):
        self.wc.dl_dst_mask = mask
        # bit-wise and of the corresponding elements of dl_dst and mask
        self.flow.dl_dst = mac.haddr_bitand(dl_dst, mask)

    def set_dl_src(self, dl_src):
        self.flow.dl_src = dl_src

    def set_dl_src_masked(self, dl_src, mask):
        self.wc.dl_src_mask = mask
        self.flow.dl_src = mac.haddr_bitand(dl_src, mask)

    def set_dl_type(self, dl_type):
        self.wc.wildcards &= ~FWW_DL_TYPE
        self.flow.dl_type = dl_type

    def set_dl_tci(self, tci):
        self.set_dl_tci_masked(tci, UINT16_MAX)

    def set_dl_tci_masked(self, tci, mask):
        self.wc.vlan_tci_mask = mask
        self.flow.vlan_tci = tci

    def set_tp_src(self, tp_src):
        self.set_tp_src_masked(tp_src, UINT16_MAX)

    def set_tp_src_masked(self, tp_src, mask):
        self.wc.tp_src_mask = mask
        self.flow.tp_src = tp_src & mask

    def set_tp_dst(self, tp_dst):
        self.set_tp_dst_masked(tp_dst, UINT16_MAX)

    def set_tp_dst_masked(self, tp_dst, mask):
        self.wc.tp_dst_mask = mask
        self.flow.tp_dst = tp_dst & mask

    def set_nw_proto(self, nw_proto):
        self.wc.wildcards &= ~FWW_NW_PROTO
        self.flow.nw_proto = nw_proto

    def set_nw_src(self, nw_src):
        self.set_nw_src_masked(nw_src, UINT32_MAX)

    def set_nw_src_masked(self, nw_src, mask):
        self.flow.nw_src = nw_src
        self.wc.nw_src_mask = mask

    def set_nw_dst(self, nw_dst):
        self.set_nw_dst_masked(nw_dst, UINT32_MAX)

    def set_nw_dst_masked(self, nw_dst, mask):
        self.flow.nw_dst = nw_dst
        self.wc.nw_dst_mask = mask

    def set_nw_dscp(self, nw_dscp):
        self.wc.wildcards &= ~FWW_NW_DSCP
        self.flow.nw_tos &= ~IP_DSCP_MASK
        self.flow.nw_tos |= nw_dscp & IP_DSCP_MASK

    def set_icmp_type(self, icmp_type):
        self.set_tp_src(icmp_type)

    def set_icmp_code(self, icmp_code):
        self.set_tp_dst(icmp_code)

    def set_tun_id(self, tun_id):
        self.set_tun_id_masked(tun_id, UINT64_MAX)

    def set_tun_id_masked(self, tun_id, mask):
        self.wc.tun_id_mask = mask
        self.flow.tun_id = tun_id & mask

    def set_nw_ecn(self, nw_ecn):
        self.wc.wildcards &= ~FWW_NW_ECN
        self.flow.nw_tos &= ~IP_ECN_MASK
        self.flow.nw_tos |= nw_ecn & IP_ECN_MASK

    def set_nw_ttl(self, nw_ttl):
        self.wc.wildcards &= ~FWW_NW_TTL
        self.flow.nw_ttl = nw_ttl

    def set_nw_frag(self, nw_frag):
        self.wc.nw_frag_mask |= FLOW_NW_FRAG_MASK
        self.flow.nw_frag = nw_frag

    def set_nw_frag_masked(self, nw_frag, mask):
        self.wc.nw_frag_mask = mask
        self.flow.nw_frag = nw_frag & mask

    def set_arp_spa(self, spa):
        self.set_arp_spa_masked(spa, UINT32_MAX)

    def set_arp_spa_masked(self, spa, mask):
        self.flow.arp_spa = spa
        self.wc.arp_spa_mask = mask

    def set_arp_tpa(self, tpa):
        self.set_arp_tpa_masked(tpa, UINT32_MAX)

    def set_arp_tpa_masked(self, tpa, mask):
        self.flow.arp_tpa = tpa
        self.wc.arp_tpa_mask = mask

    def set_arp_sha(self, sha):
        self.wc.wildcards &= ~FWW_ARP_SHA
        self.flow.arp_sha = sha

    def set_arp_tha(self, tha):
        self.wc.wildcards &= ~FWW_ARP_THA
        self.flow.arp_tha = tha

    def set_icmpv6_type(self, icmp_type):
        self.set_tp_src(icmp_type)

    def set_icmpv6_code(self, icmp_code):
        self.set_tp_dst(icmp_code)

    def set_ipv6_label(self, label):
        self.wc.wildcards &= ~FWW_IPV6_LABEL
        self.flow.ipv6_label = label

    def set_ipv6_src_masked(self, src, mask):
        self.wc.ipv6_src_mask = mask
        self.flow.ipv6_src = [x & y for (x, y) in zip(src, mask)]

    def set_ipv6_src(self, src):
        self.flow.ipv6_src = src

    def set_ipv6_dst_masked(self, dst, mask):
        self.wc.ipv6_dst_mask = mask
        self.flow.ipv6_dst = [x & y for (x, y) in zip(dst, mask)]

    def set_ipv6_dst(self, dst):
        self.flow.ipv6_dst = dst

    def set_nd_target_masked(self, target, mask):
        self.wc.nd_target_mask = mask
        self.flow.nd_target = [x & y for (x, y) in
                               zip(target, mask)]

    def set_nd_target(self, target):
        self.flow.nd_target = target

    def set_reg(self, reg_idx, value):
        self.set_reg_masked(reg_idx, value, 0)

    def set_reg_masked(self, reg_idx, value, mask):
        self.wc.regs_mask[reg_idx] = mask
        self.flow.regs[reg_idx] = value
        self.wc.regs_bits |= (1 << reg_idx)

    def set_pkt_mark_masked(self, pkt_mark, mask):
        self.flow.pkt_mark = pkt_mark
        self.wc.pkt_mark_mask = mask

    def set_tcp_flags(self, tcp_flags, mask):
        self.flow.tcp_flags = tcp_flags
        self.wc.tcp_flags_mask = mask

    def flow_format(self):
        # Tunnel ID is only supported by NXM
        if self.wc.tun_id_mask != 0:
            return ofproto_v1_0.NXFF_NXM

        # Masking DL_DST is only supported by NXM
        if self.wc.dl_dst_mask:
            return ofproto_v1_0.NXFF_NXM

        # Masking DL_SRC is only supported by NXM
        if self.wc.dl_src_mask:
            return ofproto_v1_0.NXFF_NXM

        # ECN is only supported by NXM
        if not self.wc.wildcards & FWW_NW_ECN:
            return ofproto_v1_0.NXFF_NXM

        if self.wc.regs_bits > 0:
            return ofproto_v1_0.NXFF_NXM

        if self.flow.tcp_flags > 0:
            return ofproto_v1_0.NXFF_NXM

        return ofproto_v1_0.NXFF_OPENFLOW10

    def match_tuple(self):
        """return a tuple which can be used as *args for
        ofproto_v1_0_parser.OFPMatch.__init__().
        see Datapath.send_flow_mod.
        """
        assert self.flow_format() == ofproto_v1_0.NXFF_OPENFLOW10
        wildcards = ofproto_v1_0.OFPFW_ALL

        if not self.wc.wildcards & FWW_IN_PORT:
            wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT

        if self.flow.dl_src != mac.DONTCARE:
            wildcards &= ~ofproto_v1_0.OFPFW_DL_SRC

        if self.flow.dl_dst != mac.DONTCARE:
            wildcards &= ~ofproto_v1_0.OFPFW_DL_DST

        if not self.wc.wildcards & FWW_DL_TYPE:
            wildcards &= ~ofproto_v1_0.OFPFW_DL_TYPE

        if self.flow.dl_vlan != 0:
            wildcards &= ~ofproto_v1_0.OFPFW_DL_VLAN

        if self.flow.dl_vlan_pcp != 0:
            wildcards &= ~ofproto_v1_0.OFPFW_DL_VLAN_PCP

        if self.flow.nw_tos != 0:
            wildcards &= ~ofproto_v1_0.OFPFW_NW_TOS

        if self.flow.nw_proto != 0:
            wildcards &= ~ofproto_v1_0.OFPFW_NW_PROTO

        if self.wc.nw_src_mask != 0 and "01" not in bin(self.wc.nw_src_mask):
            wildcards &= ~ofproto_v1_0.OFPFW_NW_SRC_MASK
            maskbits = (bin(self.wc.nw_src_mask).count("0") - 1)
            wildcards |= (maskbits << ofproto_v1_0.OFPFW_NW_SRC_SHIFT)

        if self.wc.nw_dst_mask != 0 and "01" not in bin(self.wc.nw_dst_mask):
            wildcards &= ~ofproto_v1_0.OFPFW_NW_DST_MASK
            maskbits = (bin(self.wc.nw_dst_mask).count("0") - 1)
            wildcards |= (maskbits << ofproto_v1_0.OFPFW_NW_DST_SHIFT)

        if self.flow.tp_src != 0:
            wildcards &= ~ofproto_v1_0.OFPFW_TP_SRC

        if self.flow.tp_dst != 0:
            wildcards &= ~ofproto_v1_0.OFPFW_TP_DST

        return (wildcards, self.flow.in_port, self.flow.dl_src,
                self.flow.dl_dst, self.flow.dl_vlan, self.flow.dl_vlan_pcp,
                self.flow.dl_type, self.flow.nw_tos & IP_DSCP_MASK,
                self.flow.nw_proto, self.flow.nw_src, self.flow.nw_dst,
                self.flow.tp_src, self.flow.tp_dst)


def _set_nxm_headers(nxm_headers):
    '''Annotate corresponding NXM header'''
    def _set_nxm_headers_dec(self):
        self.nxm_headers = nxm_headers
        return self
    return _set_nxm_headers_dec


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
    return make(nxm_header)


class MFField(object):
    _FIELDS_HEADERS = {}

    @staticmethod
    def register_field_header(headers):
        def _register_field_header(cls):
            for header in headers:
                MFField._FIELDS_HEADERS[header] = cls
            return cls
        return _register_field_header

    def __init__(self, nxm_header, pack_str):
        self.nxm_header = nxm_header
        self.pack_str = pack_str
        self.n_bytes = struct.calcsize(pack_str)
        self.n_bits = self.n_bytes * 8

    @classmethod
    def parser(cls, buf, offset):
        (header,) = struct.unpack_from('!I', buf, offset)

        cls_ = MFField._FIELDS_HEADERS.get(header)

        if cls_:
            field = cls_.field_parser(header, buf, offset)
        else:
            # print 'unknown field type'
            raise
        field.length = (header & 0xff) + 4

        return field

    @classmethod
    def field_parser(cls, header, buf, offset):
        hasmask = (header >> 8) & 1
        mask = None
        if hasmask:
            pack_str = '!' + cls.pack_str[1:] * 2
            (value, mask) = struct.unpack_from(pack_str, buf,
                                               offset + 4)
        else:
            (value,) = struct.unpack_from(cls.pack_str, buf,
                                          offset + 4)
        return cls(header, value, mask)

    def _put(self, buf, offset, value):
        msg_pack_into(self.pack_str, buf, offset, value)
        return self.n_bytes

    def putw(self, buf, offset, value, mask):
        len_ = self._put(buf, offset, value)
        return len_ + self._put(buf, offset + len_, mask)

    def _is_all_ones(self, value):
        return value == (1 << self.n_bits) - 1

    def putm(self, buf, offset, value, mask):
        if mask == 0:
            return 0
        elif self._is_all_ones(mask):
            return self._put(buf, offset, value)
        else:
            return self.putw(buf, offset, value, mask)

    def _putv6(self, buf, offset, value):
        msg_pack_into(self.pack_str, buf, offset, *value)
        return self.n_bytes

    def putv6(self, buf, offset, value, mask):
        len_ = self._putv6(buf, offset, value)
        if len(mask):
            return len_ + self._putv6(buf, offset + len_, mask)
        return len_


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IN_PORT])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_IN_PORT])
class MFInPort(MFField):
    pack_str = MF_PACK_STRING_BE16

    def __init__(self, header, value, mask=None):
        super(MFInPort, self).__init__(header, MFInPort.pack_str)
        self.value = value

    @classmethod
    def make(cls, header):
        return cls(header, MFInPort.pack_str)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.in_port)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_DST, ofproto_v1_0.NXM_OF_ETH_DST_W])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_ETH_DST,
                                ofproto_v1_0.NXM_OF_ETH_DST_W])
class MFEthDst(MFField):
    pack_str = MF_PACK_STRING_MAC

    def __init__(self, header, value, mask=None):
        super(MFEthDst, self).__init__(header, MFEthDst.pack_str)
        self.value = value

    @classmethod
    def make(cls, header):
        return cls(header, MFEthDst.pack_str)

    def put(self, buf, offset, rule):
        if rule.wc.dl_dst_mask:
            return self.putw(buf, offset, rule.flow.dl_dst,
                             rule.wc.dl_dst_mask)
        else:
            return self._put(buf, offset, rule.flow.dl_dst)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_SRC, ofproto_v1_0.NXM_OF_ETH_SRC_W])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_ETH_SRC,
                                ofproto_v1_0.NXM_OF_ETH_SRC_W])
class MFEthSrc(MFField):
    pack_str = MF_PACK_STRING_MAC

    def __init__(self, header, value, mask=None):
        super(MFEthSrc, self).__init__(header, MFEthSrc.pack_str)
        self.value = value

    @classmethod
    def make(cls, header):
        return cls(header, MFEthSrc.pack_str)

    def put(self, buf, offset, rule):
        if rule.wc.dl_src_mask:
            return self.putw(buf, offset, rule.flow.dl_src,
                             rule.wc.dl_src_mask)
        else:
            return self._put(buf, offset, rule.flow.dl_src)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_TYPE])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_ETH_TYPE])
class MFEthType(MFField):
    pack_str = MF_PACK_STRING_BE16

    def __init__(self, header, value, mask=None):
        super(MFEthType, self).__init__(header, MFEthType.pack_str)
        self.value = value

    @classmethod
    def make(cls, header):
        return cls(header, MFEthType.pack_str)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.dl_type)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_VLAN_TCI,
                   ofproto_v1_0.NXM_OF_VLAN_TCI_W])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_VLAN_TCI,
                                ofproto_v1_0.NXM_OF_VLAN_TCI_W])
class MFVlan(MFField):
    pack_str = MF_PACK_STRING_BE16

    def __init__(self, header, value, mask=None):
        super(MFVlan, self).__init__(header, MFVlan.pack_str)
        self.value = value

    @classmethod
    def make(cls, header):
        return cls(header, MFVlan.pack_str)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.vlan_tci,
                         rule.wc.vlan_tci_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_TOS])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_IP_TOS])
class MFIPDSCP(MFField):
    pack_str = MF_PACK_STRING_8

    def __init__(self, header, value, mask=None):
        super(MFIPDSCP, self).__init__(header, MFIPDSCP.pack_str)
        self.value = value

    @classmethod
    def make(cls, header):
        return cls(header, MFIPDSCP.pack_str)

    def put(self, buf, offset, rule):
        return self._put(buf, offset,
                         rule.flow.nw_tos & IP_DSCP_MASK)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_TUN_ID,
                   ofproto_v1_0.NXM_NX_TUN_ID_W])
@MFField.register_field_header([ofproto_v1_0.NXM_NX_TUN_ID,
                                ofproto_v1_0.NXM_NX_TUN_ID_W])
class MFTunId(MFField):
    pack_str = MF_PACK_STRING_BE64

    def __init__(self, header, value, mask=None):
        super(MFTunId, self).__init__(header, MFTunId.pack_str)
        self.value = value

    @classmethod
    def make(cls, header):
        return cls(header, MFTunId.pack_str)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.tun_id, rule.wc.tun_id_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_SRC, ofproto_v1_0.NXM_OF_IP_SRC_W])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_IP_SRC,
                                ofproto_v1_0.NXM_OF_IP_SRC_W])
class MFIPSrc(MFField):
    pack_str = MF_PACK_STRING_BE32

    def __init__(self, header, value, mask=None):
        super(MFIPSrc, self).__init__(header, MFIPSrc.pack_str)
        self.value = value
        self.mask = mask

    @classmethod
    def make(cls, header):
        return cls(header, MFIPSrc.pack_str)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.nw_src, rule.wc.nw_src_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_DST, ofproto_v1_0.NXM_OF_IP_DST_W])
@MFField.register_field_header([ofproto_v1_0.NXM_OF_IP_DST,
                                ofproto_v1_0.NXM_OF_IP_DST_W])
class MFIPDst(MFField):
    pack_str = MF_PACK_STRING_BE32

    def __init__(self, header, value, mask=None):
        super(MFIPDst, self).__init__(header, MFIPDst.pack_str)
        self.value = value
        self.mask = mask

    @classmethod
    def make(cls, header):
        return cls(header, MFIPDst.pack_str)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.nw_dst, rule.wc.nw_dst_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IP_ECN])
class MFIPECN(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset,
                         rule.flow.nw_tos & IP_ECN_MASK)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IP_TTL])
class MFIPTTL(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.nw_ttl)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_PROTO])
class MFIPProto(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.nw_proto)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_TCP_SRC, ofproto_v1_0.NXM_OF_TCP_SRC_W,
                   ofproto_v1_0.NXM_OF_UDP_SRC, ofproto_v1_0.NXM_OF_UDP_SRC_W])
class MFTPSRC(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.tp_src, rule.wc.tp_src_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_TCP_DST, ofproto_v1_0.NXM_OF_TCP_DST_W,
                   ofproto_v1_0.NXM_OF_UDP_DST, ofproto_v1_0.NXM_OF_UDP_DST_W])
class MFTPDST(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.tp_dst, rule.wc.tp_dst_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ARP_SPA, ofproto_v1_0.NXM_OF_ARP_SPA_W])
class MFArpSpa(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE32)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.arp_spa, rule.wc.arp_spa_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ARP_TPA, ofproto_v1_0.NXM_OF_ARP_TPA_W])
class MFArpTpa(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE32)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.arp_tpa, rule.wc.arp_tpa_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_ARP_SHA])
class MFArpSha(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.arp_sha)


class MFIPV6(object):
    pack_str = MF_PACK_STRING_IPV6

    @classmethod
    def field_parser(cls, header, buf, offset):
        hasmask = (header >> 8) & 1
        if hasmask:
            pack_string = '!' + cls.pack_str[1:] * 2
            value = struct.unpack_from(pack_string, buf, offset + 4)
            return cls(header, list(value[:8]), list(value[8:]))
        else:
            value = struct.unpack_from(cls.pack_str, buf, offset + 4)
            return cls(header, list(value))


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IPV6_SRC,
                   ofproto_v1_0.NXM_NX_IPV6_SRC_W])
@MFField.register_field_header([ofproto_v1_0.NXM_NX_IPV6_SRC,
                                ofproto_v1_0.NXM_NX_IPV6_SRC_W])
class MFIPV6Src(MFIPV6, MFField):
    def __init__(self, header, value, mask=None):
        super(MFIPV6Src, self).__init__(header, MFIPV6Src.pack_str)
        self.value = value
        self.mask = mask

    @classmethod
    def make(cls, header):
        return cls(header, cls.pack_str)

    def put(self, buf, offset, rule):
        return self.putv6(buf, offset,
                          rule.flow.ipv6_src,
                          rule.wc.ipv6_src_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IPV6_DST,
                   ofproto_v1_0.NXM_NX_IPV6_DST_W])
@MFField.register_field_header([ofproto_v1_0.NXM_NX_IPV6_DST,
                                ofproto_v1_0.NXM_NX_IPV6_DST_W])
class MFIPV6Dst(MFIPV6, MFField):
    def __init__(self, header, value, mask=None):
        super(MFIPV6Dst, self).__init__(header, MFIPV6Dst.pack_str)
        self.value = value
        self.mask = mask

    @classmethod
    def make(cls, header):
        return cls(header, cls.pack_str)

    def put(self, buf, offset, rule):
        return self.putv6(buf, offset,
                          rule.flow.ipv6_dst,
                          rule.wc.ipv6_dst_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_ND_TARGET,
                   ofproto_v1_0.NXM_NX_ND_TARGET_W])
class MFNdTarget(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, '!4I')

    def put(self, buf, offset, rule):
        return self.putv6(buf, offset,
                          rule.flow.nd_target,
                          rule.wc.nd_target_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IP_FRAG,
                   ofproto_v1_0.NXM_NX_IP_FRAG_W])
class MFIpFrag(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, '!B')

    def put(self, buf, offset, rule):
        if rule.wc.nw_frag_mask == FLOW_NW_FRAG_MASK:
            return self._put(buf, offset, rule.flow.nw_frag)
        else:
            return self.putw(buf, offset, rule.flow.nw_frag,
                             rule.wc.nw_frag_mask & FLOW_NW_FRAG_MASK)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_ARP_THA])
class MFArpTha(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.arp_tha)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ICMP_TYPE])
class MFICMPType(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.tp_src)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ICMP_CODE])
class MFICMPCode(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.tp_dst)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_ICMPV6_TYPE])
class MFICMPV6Type(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.tp_src)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_ICMPV6_CODE])
class MFICMPV6Code(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.tp_dst)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IPV6_LABEL])
class MFICMPV6Label(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE32)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.ipv6_label)


@_register_make
@_set_nxm_headers([ofproto_v1_0.nxm_nx_reg(i) for i in range(FLOW_N_REGS)]
                  + [ofproto_v1_0.nxm_nx_reg_w(i) for i in range(FLOW_N_REGS)])
class MFRegister(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE32)

    def put(self, buf, offset, rule):
        for i in range(FLOW_N_REGS):
            if (ofproto_v1_0.nxm_nx_reg(i) == self.nxm_header or
                    ofproto_v1_0.nxm_nx_reg_w(i) == self.nxm_header):
                if rule.wc.regs_mask[i]:
                    return self.putm(buf, offset, rule.flow.regs[i],
                                     rule.wc.regs_mask[i])
                else:
                    return self._put(buf, offset, rule.flow.regs[i])


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_PKT_MARK,
                   ofproto_v1_0.NXM_NX_PKT_MARK_W])
class MFPktMark(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE32)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.pkt_mark,
                         rule.wc.pkt_mark_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_TCP_FLAGS,
                   ofproto_v1_0.NXM_NX_TCP_FLAGS_W])
class MFTcpFlags(MFField):
    @classmethod
    def make(cls, header):
        return cls(header, MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.tcp_flags,
                         rule.wc.tcp_flags_mask)


def serialize_nxm_match(rule, buf, offset):
    old_offset = offset

    if not rule.wc.wildcards & FWW_IN_PORT:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IN_PORT, rule)

    # Ethernet.
    if rule.flow.dl_dst != mac.DONTCARE:
        if rule.wc.dl_dst_mask:
            header = ofproto_v1_0.NXM_OF_ETH_DST_W
        else:
            header = ofproto_v1_0.NXM_OF_ETH_DST
        offset += nxm_put(buf, offset, header, rule)

    if rule.flow.dl_src != mac.DONTCARE:
        if rule.wc.dl_src_mask:
            header = ofproto_v1_0.NXM_OF_ETH_SRC_W
        else:
            header = ofproto_v1_0.NXM_OF_ETH_SRC
        offset += nxm_put(buf, offset, header, rule)

    if not rule.wc.wildcards & FWW_DL_TYPE:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ETH_TYPE, rule)

    # 802.1Q
    if rule.wc.vlan_tci_mask != 0:
        if rule.wc.vlan_tci_mask == UINT16_MAX:
            header = ofproto_v1_0.NXM_OF_VLAN_TCI
        else:
            header = ofproto_v1_0.NXM_OF_VLAN_TCI_W
        offset += nxm_put(buf, offset, header, rule)

    # L3
    if not rule.wc.wildcards & FWW_NW_DSCP:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IP_TOS, rule)
    if not rule.wc.wildcards & FWW_NW_ECN:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_IP_ECN, rule)
    if not rule.wc.wildcards & FWW_NW_TTL:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_IP_TTL, rule)
    if not rule.wc.wildcards & FWW_NW_PROTO:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IP_PROTO, rule)

    if not rule.wc.wildcards & FWW_NW_PROTO and (rule.flow.nw_proto
                                                 == inet.IPPROTO_ICMP):
        if rule.wc.tp_src_mask != 0:
            offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ICMP_TYPE, rule)
        if rule.wc.tp_dst_mask != 0:
            offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ICMP_CODE, rule)

    if rule.flow.tp_src != 0:
        if rule.flow.nw_proto == 6:
            if rule.wc.tp_src_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_TCP_SRC
            else:
                header = ofproto_v1_0.NXM_OF_TCP_SRC_W
        elif rule.flow.nw_proto == 17:
            if rule.wc.tp_src_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_UDP_SRC
            else:
                header = ofproto_v1_0.NXM_OF_UDP_SRC_W
        else:
            header = 0
        if header != 0:
            offset += nxm_put(buf, offset, header, rule)

    if rule.flow.tp_dst != 0:
        if rule.flow.nw_proto == 6:
            if rule.wc.tp_dst_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_TCP_DST
            else:
                header = ofproto_v1_0.NXM_OF_TCP_DST_W
        elif rule.flow.nw_proto == 17:
            if rule.wc.tp_dst_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_UDP_DST
            else:
                header = ofproto_v1_0.NXM_OF_UDP_DST_W
        else:
            header = 0
        if header != 0:
            offset += nxm_put(buf, offset, header, rule)

    if rule.flow.tcp_flags != 0:
        # TCP Flags can only be used if the ethernet type is IPv4 or IPv6
        if rule.flow.dl_type in (ether.ETH_TYPE_IP, ether.ETH_TYPE_IPV6):
            # TCP Flags can only be used if the ip protocol is TCP
            if rule.flow.nw_proto == inet.IPPROTO_TCP:
                if rule.wc.tcp_flags_mask == UINT16_MAX:
                    header = ofproto_v1_0.NXM_NX_TCP_FLAGS
                else:
                    header = ofproto_v1_0.NXM_NX_TCP_FLAGS_W
            else:
                header = 0
        else:
            header = 0
        if header != 0:
            offset += nxm_put(buf, offset, header, rule)

    # IP Source and Destination
    if rule.flow.nw_src != 0:
        if rule.wc.nw_src_mask == UINT32_MAX:
            header = ofproto_v1_0.NXM_OF_IP_SRC
        else:
            header = ofproto_v1_0.NXM_OF_IP_SRC_W
        offset += nxm_put(buf, offset, header, rule)

    if rule.flow.nw_dst != 0:
        if rule.wc.nw_dst_mask == UINT32_MAX:
            header = ofproto_v1_0.NXM_OF_IP_DST
        else:
            header = ofproto_v1_0.NXM_OF_IP_DST_W
        offset += nxm_put(buf, offset, header, rule)

    # IPv6
    if not rule.wc.wildcards & FWW_NW_PROTO and (rule.flow.nw_proto
                                                 == inet.IPPROTO_ICMPV6):
        if rule.wc.tp_src_mask != 0:
            offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_ICMPV6_TYPE,
                              rule)
        if rule.wc.tp_dst_mask != 0:
            offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_ICMPV6_CODE,
                              rule)

    if not rule.wc.wildcards & FWW_IPV6_LABEL:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_IPV6_LABEL, rule)

    if len(rule.flow.ipv6_src):
        if len(rule.wc.ipv6_src_mask):
            header = ofproto_v1_0.NXM_NX_IPV6_SRC_W
        else:
            header = ofproto_v1_0.NXM_NX_IPV6_SRC
        offset += nxm_put(buf, offset, header, rule)

    if len(rule.flow.ipv6_dst):
        if len(rule.wc.ipv6_dst_mask):
            header = ofproto_v1_0.NXM_NX_IPV6_DST_W
        else:
            header = ofproto_v1_0.NXM_NX_IPV6_DST
        offset += nxm_put(buf, offset, header, rule)

    if len(rule.flow.nd_target):
        if len(rule.wc.nd_target_mask):
            header = ofproto_v1_0.NXM_NX_ND_TARGET_W
        else:
            header = ofproto_v1_0.NXM_NX_ND_TARGET
        offset += nxm_put(buf, offset, header, rule)

    # ARP
    if rule.flow.arp_spa != 0:
        if rule.wc.arp_spa_mask == UINT32_MAX:
            header = ofproto_v1_0.NXM_OF_ARP_SPA
        else:
            header = ofproto_v1_0.NXM_OF_ARP_SPA_W
        offset += nxm_put(buf, offset, header, rule)

    if rule.flow.arp_tpa != 0:
        if rule.wc.arp_tpa_mask == UINT32_MAX:
            header = ofproto_v1_0.NXM_OF_ARP_TPA
        else:
            header = ofproto_v1_0.NXM_OF_ARP_TPA_W
        offset += nxm_put(buf, offset, header, rule)

    if not rule.wc.wildcards & FWW_ARP_SHA:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_ARP_SHA, rule)
    if not rule.wc.wildcards & FWW_ARP_THA:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_ARP_THA, rule)

    if rule.flow.nw_frag:
        if rule.wc.nw_frag_mask == FLOW_NW_FRAG_MASK:
            header = ofproto_v1_0.NXM_NX_IP_FRAG
        else:
            header = ofproto_v1_0.NXM_NX_IP_FRAG_W
        offset += nxm_put(buf, offset, header, rule)

    if rule.flow.pkt_mark != 0:
        if rule.wc.pkt_mark_mask == UINT32_MAX:
            header = ofproto_v1_0.NXM_NX_PKT_MARK
        else:
            header = ofproto_v1_0.NXM_NX_PKT_MARK_W
        offset += nxm_put(buf, offset, header, rule)

    # Tunnel Id
    if rule.wc.tun_id_mask != 0:
        if rule.wc.tun_id_mask == UINT64_MAX:
            header = ofproto_v1_0.NXM_NX_TUN_ID
        else:
            header = ofproto_v1_0.NXM_NX_TUN_ID_W
        offset += nxm_put(buf, offset, header, rule)

    # XXX: Cookie

    for i in range(FLOW_N_REGS):
        if rule.wc.regs_bits & (1 << i):
            if rule.wc.regs_mask[i]:
                header = ofproto_v1_0.nxm_nx_reg_w(i)
            else:
                header = ofproto_v1_0.nxm_nx_reg(i)
            offset += nxm_put(buf, offset, header, rule)

    # Pad
    pad_len = round_up(offset) - offset
    msg_pack_into("%dx" % pad_len, buf, offset)

    # The returned length, the match_len, does not include the pad
    return offset - old_offset


def nxm_put(buf, offset, header, rule):
    nxm = NXMatch(header)
    len_ = nxm.put_header(buf, offset)
    mf = mf_from_nxm_header(nxm.header)
    return len_ + mf.put(buf, offset + len_, rule)


def round_up(length):
    return (length + 7) // 8 * 8  # Round up to a multiple of 8


class NXMatch(object):
    def __init__(self, header):
        self.header = header

    @classmethod
    def parser(cls, buf, offset, match_len):
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
        msg_pack_into(ofproto_v1_0.NXM_HEADER_PACK_STRING,
                      buf, offset, self.header)
        return struct.calcsize(ofproto_v1_0.NXM_HEADER_PACK_STRING)
