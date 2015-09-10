# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import six
from nose.tools import *
from ryu.ofproto.ofproto_v1_0_parser import *
from ryu.ofproto import ofproto_v1_0_parser
from ryu.lib import addrconv


LOG = logging.getLogger('test_ofproto_v10')


class TestOFPPhyPort(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPhyPort
    """

    # OFP_PHY_PORT_PACK_STR
    # '!H6s16sIIIIII'... port_no, hw_addr, name, config, state
    #                    curr, advertised, supported, peer
    port_no = {'buf': b'\xe7\x6b', 'val': 59243}
    hw_addr = '52:54:54:10:20:99'
    name = b'name'.ljust(16)
    config = {'buf': b'\x84\xb6\x8c\x53', 'val': 2226555987}
    state = {'buf': b'\x64\x07\xfb\xc9', 'val': 1678244809}
    curr = {'buf': b'\xa9\xe8\x0a\x2b', 'val': 2850556459}
    advertised = {'buf': b'\x78\xb9\x7b\x72', 'val': 2025421682}
    supported = {'buf': b'\x7e\x65\x68\xad', 'val': 2120575149}
    peer = {'buf': b'\xa4\x5b\x8b\xed', 'val': 2757463021}

    buf = port_no['buf'] \
        + addrconv.mac.text_to_bin(hw_addr) \
        + name \
        + config['buf'] \
        + state['buf'] \
        + curr['buf'] \
        + advertised['buf'] \
        + supported['buf'] \
        + peer['buf']

    c = OFPPhyPort(port_no['val'],
                   hw_addr,
                   name,
                   config['val'],
                   state['val'],
                   curr['val'],
                   advertised['val'],
                   supported['val'],
                   peer['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no['val'], self.c.port_no)
        eq_(self.hw_addr, self.c.hw_addr)
        eq_(self.name, self.c.name)
        eq_(self.config['val'], self.c.config)
        eq_(self.state['val'], self.c.state)
        eq_(self.curr['val'], self.c.curr)
        eq_(self.advertised['val'], self.c.advertised)
        eq_(self.supported['val'], self.c.supported)
        eq_(self.peer['val'], self.c.peer)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port_no['val'], res.port_no)
        eq_(self.hw_addr, res.hw_addr)
        eq_(self.name, res.name)
        eq_(self.config['val'], res.config)
        eq_(self.state['val'], res.state)
        eq_(self.curr['val'], res.curr)
        eq_(self.advertised['val'], res.advertised)
        eq_(self.supported['val'], res.supported)
        eq_(self.peer['val'], res.peer)


class TestOFPMatch(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPMatch
    """

    # OFP_MATCH_PACK_STR
    # '!IH6s6sHBxHBB2xIIHH'...wildcards, in_port, dl_src, dl_dst, dl_vlan,
    #                         dl_vlan_pcp, dl_type, nw_tos, nw_proto,
    #                         nw_src, nw_dst, tp_src, tp_dst
    wildcards = {'buf': b'\xd2\x71\x25\x23', 'val': 3530630435}
    in_port = {'buf': b'\x37\x8b', 'val': 14219}
    dl_src = b'\x52\x54\x54\x10\x20\x99'
    dl_dst = b'\x61\x31\x50\x6d\xc9\xe5'
    dl_vlan = {'buf': b'\xc1\xf9', 'val': 49657}
    dl_vlan_pcp = {'buf': b'\x79', 'val': 121}
    zfill0 = b'\x00'
    dl_type = {'buf': b'\xa6\x9e', 'val': 42654}
    nw_tos = {'buf': b'\xde', 'val': 222}
    nw_proto = {'buf': b'\xe5', 'val': 229}
    zfil11 = b'\x00' * 2
    nw_src = {'buf': b'\x1b\x6d\x8d\x4b', 'val': 460164427}
    nw_dst = {'buf': b'\xab\x25\xe1\x20', 'val': 2871386400}
    tp_src = {'buf': b'\xd5\xc3', 'val': 54723}
    tp_dst = {'buf': b'\x78\xb9', 'val': 30905}

    buf = wildcards['buf'] \
        + in_port['buf'] \
        + dl_src \
        + dl_dst \
        + dl_vlan['buf'] \
        + dl_vlan_pcp['buf'] \
        + zfill0 \
        + dl_type['buf'] \
        + nw_tos['buf'] \
        + nw_proto['buf'] \
        + zfil11 \
        + nw_src['buf'] \
        + nw_dst['buf'] \
        + tp_src['buf'] \
        + tp_dst['buf']

    def _get_obj(self, dl_src, dl_dst):
        c = OFPMatch(self.wildcards['val'],
                     self.in_port['val'],
                     dl_src,
                     dl_dst,
                     self.dl_vlan['val'],
                     self.dl_vlan_pcp['val'],
                     self.dl_type['val'],
                     self.nw_tos['val'],
                     self.nw_proto['val'],
                     self.nw_src['val'],
                     self.nw_dst['val'],
                     self.tp_src['val'],
                     self.tp_dst['val'])
        return c

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        c = self._get_obj(self.dl_src, self.dl_dst)

        eq_(self.wildcards['val'], c.wildcards)
        eq_(self.in_port['val'], c.in_port)
        eq_(self.dl_src, c.dl_src)
        eq_(self.dl_dst, c.dl_dst)
        eq_(self.dl_vlan['val'], c.dl_vlan)
        eq_(self.dl_vlan_pcp['val'], c.dl_vlan_pcp)
        eq_(self.dl_type['val'], c.dl_type)
        eq_(self.nw_tos['val'], c.nw_tos)
        eq_(self.nw_proto['val'], c.nw_proto)
        eq_(self.nw_src['val'], c.nw_src)
        eq_(self.nw_dst['val'], c.nw_dst)
        eq_(self.tp_src['val'], c.tp_src)
        eq_(self.tp_dst['val'], c.tp_dst)

    def test_init_zero(self):
        c = self._get_obj(0, 0)
        eq_(mac.DONTCARE, c.dl_src)
        eq_(mac.DONTCARE, c.dl_dst)

    def test_parse(self):
        c = self._get_obj(self.dl_src, self.dl_dst)
        res = c.parse(self.buf, 0)

        eq_(self.wildcards['val'], res.wildcards)
        eq_(self.in_port['val'], res.in_port)
        eq_(self.dl_src, res.dl_src)
        eq_(self.dl_dst, res.dl_dst)
        eq_(self.dl_vlan['val'], res.dl_vlan)
        eq_(self.dl_vlan_pcp['val'], res.dl_vlan_pcp)
        eq_(self.dl_type['val'], res.dl_type)
        eq_(self.nw_tos['val'], res.nw_tos)
        eq_(self.nw_proto['val'], res.nw_proto)
        eq_(self.nw_src['val'], res.nw_src)
        eq_(self.nw_dst['val'], res.nw_dst)
        eq_(self.tp_src['val'], res.tp_src)
        eq_(self.tp_dst['val'], res.tp_dst)

    def test_serialize(self):
        buf = bytearray()
        c = self._get_obj(self.dl_src, self.dl_dst)

        c.serialize(buf, 0)

        fmt = ofproto.OFP_MATCH_PACK_STR
        res = struct.unpack_from(fmt, six.binary_type(buf))

        eq_(self.wildcards['val'], res[0])
        eq_(self.in_port['val'], res[1])
        eq_(self.dl_src, res[2])
        eq_(self.dl_dst, res[3])
        eq_(self.dl_vlan['val'], res[4])
        eq_(self.dl_vlan_pcp['val'], res[5])
        eq_(self.dl_type['val'], res[6])
        eq_(self.nw_tos['val'], res[7])
        eq_(self.nw_proto['val'], res[8])
        eq_(self.nw_src['val'], res[9])
        eq_(self.nw_dst['val'], res[10])
        eq_(self.tp_src['val'], res[11])
        eq_(self.tp_dst['val'], res[12])

    def test_getitem(self):
        c = self._get_obj(self.dl_src, self.dl_dst)

        eq_(self.wildcards['val'], c["wildcards"])
        eq_(self.in_port['val'], c["in_port"])
        eq_(self.dl_src, c["dl_src"])
        eq_(self.dl_dst, c["dl_dst"])
        eq_(self.dl_vlan['val'], c["dl_vlan"])
        eq_(self.dl_vlan_pcp['val'], c["dl_vlan_pcp"])
        eq_(self.dl_type['val'], c["dl_type"])
        eq_(self.nw_tos['val'], c["nw_tos"])
        eq_(self.nw_proto['val'], c["nw_proto"])
        eq_(self.nw_src['val'], c["nw_src"])
        eq_(self.nw_dst['val'], c["nw_dst"])
        eq_(self.tp_src['val'], c["tp_src"])
        eq_(self.tp_dst['val'], c["tp_dst"])


class TestOFPActionHeader(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionHeader
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH4x'...type, len, zfill
    type = {'buf': b'\x00\x02', 'val': ofproto.OFPAT_SET_VLAN_PCP}
    len = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_HEADER_SIZE}
    zfill = b'\x00' * 4

    buf = type['buf'] \
        + len['buf'] \
        + zfill

    c = OFPActionHeader(type['val'], len['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type['val'], self.c.type)
        eq_(self.len['val'], self.c.len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type['val'], res[0])
        eq_(self.len['val'], res[1])


class TestOFPActionOutput(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionOutput
    """

    # OFP_ACTION_OUTPUT_PACK_STR
    # '!HHHH'...type, len, port, max_len
    type_ = {'buf': b'\x00\x00', 'val': ofproto.OFPAT_OUTPUT}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_OUTPUT_SIZE}
    port = {'buf': b'\x19\xce', 'val': 6606}
    max_len = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_OUTPUT_SIZE}

    buf = type_['buf'] \
        + len_['buf'] \
        + port['buf'] \
        + max_len['buf']

    c = OFPActionOutput(port['val'], max_len['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port['val'], self.c.port)
        eq_(self.max_len['val'], self.c.max_len)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port['val'], res.port)
        eq_(self.max_len['val'], res.max_len)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x01', 'val': 1}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.port['buf'] \
            + self.max_len['buf']

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.port['buf'] \
            + self.max_len['buf']

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_OUTPUT_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.port['val'], res[2])
        eq_(self.max_len['val'], res[3])


class TestOFPActionVlanVid(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionVlanVid
    """

    # OFP_ACTION_VLAN_VID_PACK_STR
    # '!HHH2x'...type, len, vlan_vid, zfill
    type_ = {'buf': b'\x00\x01', 'val': ofproto.OFPAT_SET_VLAN_VID}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_VLAN_VID_SIZE}
    vlan_vid = {'buf': b'\x3c\x0e', 'val': 15374}
    zfill = b'\x00' * 2

    buf = type_['buf'] \
        + len_['buf'] \
        + vlan_vid['buf'] \
        + zfill

    c = OFPActionVlanVid(vlan_vid['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.vlan_vid['val'], self.c.vlan_vid)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.vlan_vid['val'], res.vlan_vid)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x02', 'val': 2}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.vlan_vid['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.vlan_vid['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_VLAN_VID_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vlan_vid['val'], res[2])


class TestOFPActionVlanPcp(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionVlanPcp
    """

    # OFP_ACTION_VLAN_PCP_PACK_STR
    # '!HHB3x'...type, len, vlan_pcp, zfill
    type_ = {'buf': b'\x00\x02', 'val': ofproto.OFPAT_SET_VLAN_PCP}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_VLAN_PCP_SIZE}
    vlan_pcp = {'buf': b'\x1c', 'val': 28}
    zfill = b'\x00' * 3

    buf = type_['buf'] \
        + len_['buf'] \
        + vlan_pcp['buf'] \
        + zfill

    c = OFPActionVlanPcp(vlan_pcp['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.vlan_pcp['val'], self.c.vlan_pcp)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.vlan_pcp['val'], res.vlan_pcp)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x01', 'val': 1}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.vlan_pcp['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.vlan_pcp['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_VLAN_PCP_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vlan_pcp['val'], res[2])


class TestOFPActionStripVlan(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionStripVlan
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH4x'...type, len, zfill
    type_ = {'buf': b'\x00\x03', 'val': ofproto.OFPAT_STRIP_VLAN}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_HEADER_SIZE}
    zfill = b'\x00' * 4

    buf = type_['buf'] \
        + len_['buf'] \
        + zfill

    c = OFPActionStripVlan()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        ok_(self.c.parser(self.buf, 0))

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x01', 'val': 1}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.zfill

        self.c.parser(buf, 0)


class TestOFPActionSetDlSrc(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionSetDlSrc
    """

    # OFP_ACTION_DL_ADDR_PACK_STR
    # '!HH6s6x'...type, len, dl_addr, zfill
    type_ = {'buf': b'\x00\x04', 'val': ofproto.OFPAT_SET_DL_SRC}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.OFP_ACTION_DL_ADDR_SIZE}
    dl_addr = b'\x0e\xde\x27\xce\xc6\xcf'
    zfill = b'\x00' * 6

    buf = type_['buf'] \
        + len_['buf'] \
        + dl_addr \
        + zfill

    c = OFPActionSetDlSrc(dl_addr)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.dl_addr, self.c.dl_addr)

    def test_parser_type_src(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.dl_addr, res.dl_addr)

    def test_parser_type_dst(self):
        type_ = {'buf': b'\x00\x05', 'val': ofproto.OFPAT_SET_DL_DST}
        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.dl_addr \
            + self.zfill

        res = self.c.parser(buf, 0)

        eq_(self.dl_addr, res.dl_addr)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x06', 'val': 6}
        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.dl_addr \
            + self.zfill

        res = self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}
        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.dl_addr \
            + self.zfill

        res = self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_DL_ADDR_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.dl_addr, res[2])


class TestOFPActionSetDlDst(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionSetDlDst
    """

    # OFP_ACTION_DL_ADDR_PACK_STR
    # '!HH6s6x'...type, len, dl_addr, zfill
    type_ = {'buf': b'\x00\x05', 'val': ofproto.OFPAT_SET_DL_DST}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.OFP_ACTION_DL_ADDR_SIZE}
    dl_addr = b'\x37\x48\x38\x9a\xf4\x28'
    zfill = b'\x00' * 6

    buf = type_['buf'] \
        + len_['buf'] \
        + dl_addr \
        + zfill

    c = OFPActionSetDlDst(dl_addr)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.dl_addr, self.c.dl_addr)

    def test_parser_type_dst(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.dl_addr, res.dl_addr)

    def test_parser_type_src(self):
        type_ = {'buf': b'\x00\x04', 'val': ofproto.OFPAT_SET_DL_SRC}
        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.dl_addr \
            + self.zfill

        res = self.c.parser(buf, 0)

        eq_(self.dl_addr, res.dl_addr)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x06', 'val': 6}
        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.dl_addr \
            + self.zfill

        res = self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}
        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.dl_addr \
            + self.zfill

        res = self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_DL_ADDR_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.dl_addr, res[2])


class TestOFPActionSetNwSrc(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionSetNwSrc
    """

    # OFP_ACTION_NW_ADDR_PACK_STR
    # '!HHI'...type, len, nw_addr
    type_ = {'buf': b'\x00\x06', 'val': ofproto.OFPAT_SET_NW_SRC}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_NW_ADDR_SIZE}
    nw_addr = {'buf': b'\xc0\xa8\x7a\x0a', 'val': 3232266762}

    buf = type_['buf'] \
        + len_['buf'] \
        + nw_addr['buf']

    c = OFPActionSetNwSrc(nw_addr['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.nw_addr['val'], self.c.nw_addr)

    def test_parser_src(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.nw_addr['val'], res.nw_addr)

    def test_parser_dst(self):
        type_ = {'buf': b'\x00\x07', 'val': ofproto.OFPAT_SET_NW_DST}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.nw_addr['buf']

        res = self.c.parser(buf, 0)
        eq_(self.nw_addr['val'], res.nw_addr)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x05', 'val': 5}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.nw_addr['buf']

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x10', 'val': 16}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.nw_addr['buf']

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_NW_ADDR_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.nw_addr['val'], res[2])


class TestOFPActionSetNwDst(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionSetNwDst
    """

    # OFP_ACTION_NW_ADDR_PACK_STR
    # '!HHI'...type, len, nw_addr
    type_ = {'buf': b'\x00\x07', 'val': ofproto.OFPAT_SET_NW_DST}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_NW_ADDR_SIZE}
    nw_addr = {'buf': b'\xc0\xa8\x7a\x0a', 'val': 3232266762}

    buf = type_['buf'] \
        + len_['buf'] \
        + nw_addr['buf']

    c = OFPActionSetNwDst(nw_addr['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.nw_addr['val'], self.c.nw_addr)

    def test_parser_dst(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.nw_addr['val'], res.nw_addr)

    def test_parser_src(self):
        type_ = {'buf': b'\x00\x06', 'val': ofproto.OFPAT_SET_NW_SRC}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.nw_addr['buf']

        res = self.c.parser(buf, 0)
        eq_(self.nw_addr['val'], res.nw_addr)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x05', 'val': 5}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.nw_addr['buf']

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x10', 'val': 16}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.nw_addr['buf']

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_NW_ADDR_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.nw_addr['val'], res[2])


class TestOFPActionSetNwTos(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionSetNwTos
    """

    # OFP_ACTION_NW_TOS_PACK_STR
    # '!HHB3x'...type, len, tos, zfill
    type_ = {'buf': b'\x00\x08', 'val': ofproto.OFPAT_SET_NW_TOS}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_NW_TOS_SIZE}
    tos = {'buf': b'\xb6', 'val': 182}
    zfill = b'\x00' * 3

    buf = type_['buf'] \
        + len_['buf'] \
        + tos['buf'] \
        + zfill

    c = OFPActionSetNwTos(tos['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.tos['val'], self.c.tos)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.tos['val'], res.tos)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x05', 'val': 5}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.tos['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.tos['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_NW_TOS_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.tos['val'], res[2])


class TestOFPActionSetTpSrc(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionSetTpSrc
    """

    # OFP_ACTION_TP_PORT_PACK_STR
    # '!HHH2x'...type, len, tp, zfill
    type_ = {'buf': b'\x00\x09', 'val': ofproto.OFPAT_SET_TP_SRC}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_TP_PORT_SIZE}
    tp = {'buf': b'\x07\xf1', 'val': 2033}
    zfill = b'\x00' * 2

    buf = type_['buf'] \
        + len_['buf'] \
        + tp['buf'] \
        + zfill

    c = OFPActionSetTpSrc(tp['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.tp['val'], self.c.tp)

    def test_parser_src(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.tp['val'], res.tp)

    def test_parser_dst(self):
        type_ = {'buf': b'\x00\x0a', 'val': ofproto.OFPAT_SET_TP_DST}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.tp['buf'] \
            + self.zfill

        res = self.c.parser(self.buf, 0)
        eq_(self.tp['val'], res.tp)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x07', 'val': 7}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.tp['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.tp['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_TP_PORT_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.tp['val'], res[2])


class TestOFPActionSetTpDst(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionSetTpDst
    """

    # OFP_ACTION_TP_PORT_PACK_STR
    # '!HHH2x'...type, len, tp, zfill
    type_ = {'buf': b'\x00\x0a', 'val': ofproto.OFPAT_SET_TP_DST}
    len_ = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_TP_PORT_SIZE}
    tp = {'buf': b'\x06\x6d', 'val': 1645}
    zfill = b'\x00' * 2

    buf = type_['buf'] \
        + len_['buf'] \
        + tp['buf'] \
        + zfill

    c = OFPActionSetTpDst(tp['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.tp['val'], self.c.tp)

    def test_parser_dst(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.tp['val'], res.tp)

    def test_parser_src(self):
        type_ = {'buf': b'\x00\x09', 'val': ofproto.OFPAT_SET_TP_SRC}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.tp['buf'] \
            + self.zfill

        res = self.c.parser(buf, 0)
        eq_(self.tp['val'], res.tp)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x10', 'val': 16}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.tp['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x07', 'val': 7}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.tp['buf'] \
            + self.zfill

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_TP_PORT_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.tp['val'], res[2])


class TestOFPActionEnqueue(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPActionEnqueue
    """

    # OFP_ACTION_ENQUEUE_PACK_STR
    # '!HHH6xI'...type_, len_, port, zfill, queue_id
    type_ = {'buf': b'\x00\x0b', 'val': ofproto.OFPAT_ENQUEUE}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.OFP_ACTION_ENQUEUE_SIZE}
    port = {'buf': b'\x04\x55', 'val': 1109}
    zfill = b'\x00' * 6
    queue_id = {'buf': b'\x0a\x5b\x03\x5e', 'val': 173736798}

    buf = type_['buf'] \
        + len_['buf'] \
        + port['buf'] \
        + zfill \
        + queue_id['buf']

    c = OFPActionEnqueue(port['val'], queue_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port['val'], self.c.port)
        eq_(self.queue_id['val'], self.c.queue_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port['val'], res.port)
        eq_(self.queue_id['val'], res.queue_id)

    @raises(AssertionError)
    def test_parser_check_type(self):
        type_ = {'buf': b'\x00\x0a', 'val': 10}

        buf = type_['buf'] \
            + self.len_['buf'] \
            + self.port['buf'] \
            + self.zfill \
            + self.queue_id['buf']

        self.c.parser(buf, 0)

    @raises(AssertionError)
    def test_parser_check_len(self):
        len_ = {'buf': b'\x00\x05', 'val': 5}

        buf = self.type_['buf'] \
            + len_['buf'] \
            + self.port['buf'] \
            + self.zfill \
            + self.queue_id['buf']

        self.c.parser(buf, 0)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.OFP_ACTION_ENQUEUE_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.port['val'], res[2])
        eq_(self.queue_id['val'], res[3])


class TestNXActionResubmit(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionResubmit
    """

    # NX_ACTION_RESUBMIT_PACK_STR
    # '!HHIHHB3x'...type, len, vendor, subtype, in_port, table, zfill
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.NX_ACTION_RESUBMIT_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20', 'val': 8992}
    subtype = {'buf': b'\x00\x01', 'val': 1}
    in_port = {'buf': b'\x0a\x4c', 'val': 2636}
    table = {'buf': b'\x52', 'val': 82}
    zfill = b'\x00' * 3

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + in_port['buf'] \
        + table['buf'] \
        + zfill

    c = NXActionResubmit(in_port['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.in_port['val'], self.c.in_port)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.in_port['val'], res.in_port)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_RESUBMIT_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.in_port['val'], res[4])


class TestNXActionResubmitTable(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionResubmitTable
    """

    # NX_ACTION_RESUBMIT_PACK_STR
    # '!HHIHHB3x'...type, len, vendor, subtype, in_port, table, zfill
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.NX_ACTION_RESUBMIT_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20', 'val': 8992}
    subtype = {'buf': b'\x00\x0e', 'val': 14}
    in_port = {'buf': b'\x0a\x4c', 'val': 2636}
    table = {'buf': b'\x52', 'val': 82}
    zfill = b'\x00' * 3

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + in_port['buf'] \
        + table['buf'] \
        + zfill

    c = NXActionResubmitTable(in_port['val'], table['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.in_port['val'], self.c.in_port)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.in_port['val'], res.in_port)
        eq_(self.table['val'], res.table)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_RESUBMIT_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.in_port['val'], res[4])


class TestNXActionSetTunnel(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionSetTunnel
    """

    # NX_ACTION_SET_TUNNEL_PACK_STR
    # '!HHIH2xI'...type, len, vendor, subtype, zfill, tun_id
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.NX_ACTION_SET_TUNNEL_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20', 'val': 8992}
    subtype = {'buf': b'\x00\x02', 'val': 2}
    zfill = b'\x00' * 2
    tun_id = {'buf': b'\x01\x6f\x01\xd0', 'val': 24052176}

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + zfill \
        + tun_id['buf']

    c = NXActionSetTunnel(tun_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.tun_id['val'], self.c.tun_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.tun_id['val'], res.tun_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_SET_TUNNEL_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.tun_id['val'], res[4])


class TestNXActionSetQueue(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionSetQueue
    """

    # NX_ACTION_SET_QUEUE_PACK_STR
    # '!HHIH2xI'...type, len, vendor, subtype, zfill, queue_id
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.NX_ACTION_SET_TUNNEL_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x04', 'val': ofproto.NXAST_SET_QUEUE}
    zfill = b'\x00' * 2
    queue_id = {'buf': b'\xde\xbe\xc5\x18', 'val': 3737044248}

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + zfill \
        + queue_id['buf']

    c = NXActionSetQueue(queue_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.queue_id['val'], self.c.queue_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.queue_id['val'], res.queue_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_SET_QUEUE_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.queue_id['val'], res[4])


class TestNXActionPopQueue(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionPopQueue
    """

    # NX_ACTION_POP_QUEUE_PACK_STR
    # '!HHIH6x'...type, len, vendor, subtype, zfill
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.NX_ACTION_SET_TUNNEL_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x05', 'val': ofproto.NXAST_POP_QUEUE}
    zfill = b'\x00' * 6

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + zfill

    c = NXActionPopQueue()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.type_['val'], res.type)
        eq_(self.len_['val'], res.len)
        eq_(self.vendor['val'], res.vendor)
        eq_(self.subtype['val'], res.subtype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_POP_QUEUE_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])


class TestNXActionRegMove(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionRegMove
    """

    # NX_ACTION_REG_MOVE_PACK_STR
    # '!HHIHHHHII'...type_, len_, vendor, subtype, n_bits,
    #                src_ofs, dst_ofs, src, dst
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x18', 'val': ofproto.NX_ACTION_REG_MOVE_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x06', 'val': ofproto.NXAST_REG_MOVE}
    n_bits = {'buf': b'\x3d\x98', 'val': 15768}
    src_ofs = {'buf': b'\xf3\xa3', 'val': 62371}
    dst_ofs = {'buf': b'\xdc\x67', 'val': 56423}
    src = {'buf': b'\x15\x68\x60\xfd', 'val': 359162109}
    dst = {'buf': b'\x9f\x9f\x88\x26', 'val': 2678032422}

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + n_bits['buf'] \
        + src_ofs['buf'] \
        + dst_ofs['buf'] \
        + src['buf'] \
        + dst['buf']

    c = NXActionRegMove(n_bits['val'],
                        src_ofs['val'],
                        dst_ofs['val'],
                        src['val'],
                        dst['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.n_bits['val'], self.c.n_bits)
        eq_(self.src_ofs['val'], self.c.src_ofs)
        eq_(self.dst_ofs['val'], self.c.dst_ofs)
        eq_(self.src['val'], self.c.src)
        eq_(self.dst['val'], self.c.dst)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.n_bits['val'], res.n_bits)
        eq_(self.src_ofs['val'], res.src_ofs)
        eq_(self.dst_ofs['val'], res.dst_ofs)
        eq_(self.src['val'], res.src)
        eq_(self.dst['val'], res.dst)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_REG_MOVE_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.n_bits['val'], res[4])
        eq_(self.src_ofs['val'], res[5])
        eq_(self.dst_ofs['val'], res[6])
        eq_(self.src['val'], res[7])
        eq_(self.dst['val'], res[8])


class TestNXActionRegLoad(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionRegLoad
    """

    # NX_ACTION_REG_LOAD_PACK_STR
    # '!HHIHHIQ'...type_, len_, vendor, subtype,
    #              ofs_nbits, dst, value
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x18', 'val': ofproto.NX_ACTION_REG_MOVE_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x07', 'val': ofproto.NXAST_REG_LOAD}
    ofs_nbits = {'buf': b'\x3d\x98', 'val': 15768}
    dst = {'buf': b'\x9f\x9f\x88\x26', 'val': 2678032422}
    value = {'buf': b'\x33\x51\xcd\x43\x25\x28\x18\x99',
             'val': 3697962457317775513}

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + ofs_nbits['buf'] \
        + dst['buf'] \
        + value['buf']

    c = NXActionRegLoad(ofs_nbits['val'],
                        dst['val'],
                        value['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.ofs_nbits['val'], self.c.ofs_nbits)
        eq_(self.dst['val'], self.c.dst)
        eq_(self.value['val'], self.c.value)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.ofs_nbits['val'], res.ofs_nbits)
        eq_(self.dst['val'], res.dst)
        eq_(self.value['val'], res.value)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_REG_LOAD_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.ofs_nbits['val'], res[4])
        eq_(self.dst['val'], res[5])
        eq_(self.value['val'], res[6])


class TestNXActionSetTunnel64(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionSetTunnel64
    """

    # NX_ACTION_SET_TUNNEL64_PACK_STR
    # '!HHIH6xQ'...type, len, vendor, subtype, zfill, tun_id
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x18', 'val': ofproto.NX_ACTION_SET_TUNNEL64_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x09', 'val': ofproto.NXAST_SET_TUNNEL64}
    zfill = b'\x00' * 6
    tun_id = {'buf': b'\x6e\x01\xa6\xea\x7e\x36\x1d\xd9',
              'val': 7926800345218817497}

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + zfill \
        + tun_id['buf']

    c = NXActionSetTunnel64(tun_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.tun_id['val'], self.c.tun_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.tun_id['val'], self.c.tun_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_SET_TUNNEL64_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.tun_id['val'], res[4])


class TestNXActionMultipath(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionMultipath
    """

    # NX_ACTION_MULTIPATH_PACK_STR
    # '!HHIHHH2xHHI2xHI'...type, len, vendor, subtype, fields, basis, zfill
    #                      algorithm, max_link, arg, zfill, ofs_nbits, dst
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x20', 'val': ofproto.NX_ACTION_MULTIPATH_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x0a', 'val': ofproto.NXAST_MULTIPATH}
    fields = {'buf': b'\x6d\xf5', 'val': 28149}
    basis = {'buf': b'\x7c\x0a', 'val': 31754}
    zfill0 = b'\x00' * 2
    algorithm = {'buf': b'\x82\x1d', 'val': 33309}
    max_link = {'buf': b'\x06\x2b', 'val': 1579}
    arg = {'buf': b'\x18\x79\x41\xc8', 'val': 410599880}
    zfill1 = b'\x00' * 2
    ofs_nbits = {'buf': b'\xa9\x9a', 'val': 43418}
    dst = {'buf': b'\xb9\x2f\x16\x64', 'val': 3106870884}

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + fields['buf'] \
        + basis['buf'] \
        + zfill0 \
        + algorithm['buf'] \
        + max_link['buf'] \
        + arg['buf'] \
        + zfill1 \
        + ofs_nbits['buf'] \
        + dst['buf']

    c = NXActionMultipath(fields['val'],
                          basis['val'],
                          algorithm['val'],
                          max_link['val'],
                          arg['val'],
                          ofs_nbits['val'],
                          dst['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.fields['val'], self.c.fields)
        eq_(self.basis['val'], self.c.basis)
        eq_(self.algorithm['val'], self.c.algorithm)
        eq_(self.max_link['val'], self.c.max_link)
        eq_(self.arg['val'], self.c.arg)
        eq_(self.ofs_nbits['val'], self.c.ofs_nbits)
        eq_(self.dst['val'], self.c.dst)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.fields['val'], res.fields)
        eq_(self.basis['val'], res.basis)
        eq_(self.algorithm['val'], res.algorithm)
        eq_(self.max_link['val'], res.max_link)
        eq_(self.arg['val'], res.arg)
        eq_(self.ofs_nbits['val'], res.ofs_nbits)
        eq_(self.dst['val'], res.dst)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_MULTIPATH_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.fields['val'], res[4])
        eq_(self.basis['val'], res[5])
        eq_(self.algorithm['val'], res[6])
        eq_(self.max_link['val'], res[7])
        eq_(self.arg['val'], res[8])
        eq_(self.ofs_nbits['val'], res[9])
        eq_(self.dst['val'], res[10])


class TestNXActionBundle(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionBundle
    """

    # NX_ACTION_BUNDLE_PACK_STR
    # '!HHIHHHHIHHI4x'...type, len, vendor, subtype, algorithm,
    #                    fields, basis, slave_type, n_slaves,
    #                    ofs_nbits, dst, zfill
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x20', 'val': ofproto.NX_ACTION_BUNDLE_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x0c', 'val': ofproto.NXAST_BUNDLE}
    algorithm = {'buf': b'\x51\xa7', 'val': 20903}
    fields = {'buf': b'\xf8\xef', 'val': 63727}
    basis = {'buf': b'\xfd\x6f', 'val': 64879}
    slave_type = {'buf': b'\x7c\x51\x0f\xe0', 'val': 2085687264}
    n_slaves = {'buf': b'\x00\x02', 'val': 2}
    ofs_nbits = {'buf': b'\xec\xf7', 'val': 60663}
    dst = {'buf': b'\x50\x7c\x75\xfe', 'val': 1350333950}
    zfill = b'\x00' * 4

    slaves_buf = (b'\x00\x01', b'\x00\x02')
    slaves_val = (1, 2)

    _len = len_['val'] + len(slaves_val) * 2
    _len += (_len % 8)

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + algorithm['buf'] \
        + fields['buf'] \
        + basis['buf'] \
        + slave_type['buf'] \
        + n_slaves['buf'] \
        + ofs_nbits['buf'] \
        + dst['buf'] \
        + zfill \
        + slaves_buf[0] \
        + slaves_buf[1]

    c = NXActionBundle(algorithm['val'],
                       fields['val'],
                       basis['val'],
                       slave_type['val'],
                       n_slaves['val'],
                       ofs_nbits['val'],
                       dst['val'],
                       slaves_val)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self._len, self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.algorithm['val'], self.c.algorithm)
        eq_(self.fields['val'], self.c.fields)
        eq_(self.basis['val'], self.c.basis)
        eq_(self.slave_type['val'], self.c.slave_type)
        eq_(self.n_slaves['val'], self.c.n_slaves)
        eq_(self.ofs_nbits['val'], self.c.ofs_nbits)
        eq_(self.dst['val'], self.c.dst)

        # slaves
        slaves = self.c.slaves
        eq_(self.slaves_val[0], slaves[0])
        eq_(self.slaves_val[1], slaves[1])

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.type_['val'], res.type)
        eq_(self._len, res.len)
        eq_(self.vendor['val'], res.vendor)
        eq_(self.subtype['val'], res.subtype)
        eq_(self.algorithm['val'], res.algorithm)
        eq_(self.fields['val'], res.fields)
        eq_(self.basis['val'], res.basis)
        eq_(self.slave_type['val'], res.slave_type)
        eq_(self.n_slaves['val'], res.n_slaves)
        eq_(self.ofs_nbits['val'], res.ofs_nbits)
        eq_(self.dst['val'], res.dst)

        # slaves
        slaves = res.slaves
        eq_(self.slaves_val[0], slaves[0])
        eq_(self.slaves_val[1], slaves[1])

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = '!' \
            + ofproto.NX_ACTION_BUNDLE_PACK_STR.replace('!', '') \
            + 'HH4x'

        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self._len, res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.algorithm['val'], res[4])
        eq_(self.fields['val'], res[5])
        eq_(self.basis['val'], res[6])
        eq_(self.slave_type['val'], res[7])
        eq_(self.n_slaves['val'], res[8])
        eq_(self.ofs_nbits['val'], res[9])
        eq_(self.dst['val'], res[10])


class TestNXActionBundleLoad(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionBundleLoad
    """

    # NX_ACTION_BUNDLE_PACK_STR
    # '!HHIHHHHIHHI4x'...type, len, vendor, subtype, algorithm,
    #                    fields, basis, slave_type, n_slaves,
    #                    ofs_nbits, dst, zfill
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x20', 'val': ofproto.NX_ACTION_BUNDLE_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x0d', 'val': ofproto.NXAST_BUNDLE_LOAD}
    algorithm = {'buf': b'\x83\x15', 'val': 33557}
    fields = {'buf': b'\xc2\x7a', 'val': 49786}
    basis = {'buf': b'\x86\x18', 'val': 34328}
    slave_type = {'buf': b'\x18\x42\x0b\x55', 'val': 406981461}
    n_slaves = {'buf': b'\x00\x02', 'val': 2}
    ofs_nbits = {'buf': b'\xd2\x9d', 'val': 53917}
    dst = {'buf': b'\x37\xfe\xb3\x60', 'val': 939438944}
    zfill = b'\x00' * 4

    slaves_buf = (b'\x00\x01', b'\x00\x02')
    slaves_val = (1, 2)

    _len = len_['val'] + len(slaves_val) * 2
    _len += (_len % 8)

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + algorithm['buf'] \
        + fields['buf'] \
        + basis['buf'] \
        + slave_type['buf'] \
        + n_slaves['buf'] \
        + ofs_nbits['buf'] \
        + dst['buf'] \
        + zfill \
        + slaves_buf[0] \
        + slaves_buf[1]

    c = NXActionBundleLoad(algorithm['val'],
                           fields['val'],
                           basis['val'],
                           slave_type['val'],
                           n_slaves['val'],
                           ofs_nbits['val'],
                           dst['val'],
                           slaves_val)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self._len, self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.algorithm['val'], self.c.algorithm)
        eq_(self.fields['val'], self.c.fields)
        eq_(self.basis['val'], self.c.basis)
        eq_(self.slave_type['val'], self.c.slave_type)
        eq_(self.n_slaves['val'], self.c.n_slaves)
        eq_(self.ofs_nbits['val'], self.c.ofs_nbits)
        eq_(self.dst['val'], self.c.dst)

        # slaves
        slaves = self.c.slaves
        eq_(self.slaves_val[0], slaves[0])
        eq_(self.slaves_val[1], slaves[1])

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.type_['val'], res.type)
        eq_(self._len, res.len)
        eq_(self.vendor['val'], res.vendor)
        eq_(self.subtype['val'], res.subtype)
        eq_(self.algorithm['val'], res.algorithm)
        eq_(self.fields['val'], res.fields)
        eq_(self.basis['val'], res.basis)
        eq_(self.slave_type['val'], res.slave_type)
        eq_(self.n_slaves['val'], res.n_slaves)
        eq_(self.ofs_nbits['val'], res.ofs_nbits)
        eq_(self.dst['val'], res.dst)

        # slaves
        slaves = res.slaves
        eq_(self.slaves_val[0], slaves[0])
        eq_(self.slaves_val[1], slaves[1])

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = '!' \
            + ofproto.NX_ACTION_BUNDLE_PACK_STR.replace('!', '') \
            + 'HH4x'

        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self._len, res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.algorithm['val'], res[4])
        eq_(self.fields['val'], res[5])
        eq_(self.basis['val'], res[6])
        eq_(self.slave_type['val'], res[7])
        eq_(self.n_slaves['val'], res[8])
        eq_(self.ofs_nbits['val'], res[9])
        eq_(self.dst['val'], res[10])


class TestNXActionAutopath(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionAutopath
    """

    # NX_ACTION_AUTOPATH_PACK_STR
    # '!HHIHHII4x'...type, len, vendor, subtype, ofs_nbits,
    #                dst, id_, zfill
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x20', 'val': ofproto.NX_ACTION_OUTPUT_REG_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x0b', 'val': ofproto.NXAST_AUTOPATH}
    ofs_nbits = {'buf': b'\xfe\x78', 'val': 65144}
    dst = {'buf': b'\xf8\x55\x74\x95', 'val': 4166349973}
    id_ = {'buf': b'\x02\x2d\x37\xed', 'val': 36517869}
    zfill = b'\x00' * 4

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + ofs_nbits['buf'] \
        + dst['buf'] \
        + id_['buf'] \
        + zfill

    c = NXActionAutopath(ofs_nbits['val'],
                         dst['val'],
                         id_['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.ofs_nbits['val'], self.c.ofs_nbits)
        eq_(self.dst['val'], self.c.dst)
        eq_(self.id_['val'], self.c.id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.type_['val'], res.type)
        eq_(self.len_['val'], res.len)
        eq_(self.vendor['val'], res.vendor)
        eq_(self.subtype['val'], res.subtype)
        eq_(self.ofs_nbits['val'], res.ofs_nbits)
        eq_(self.dst['val'], res.dst)
        eq_(self.id_['val'], res.id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_AUTOPATH_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.ofs_nbits['val'], res[4])
        eq_(self.dst['val'], res[5])
        eq_(self.id_['val'], res[6])


class TestNXActionOutputReg(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionOutputReg
    """

    # NX_ACTION_OUTPUT_REG_PACK_STR
    # '!HHIHHIH6x'...type, len, vendor, subtype, ofs_nbits,
    #                    src, max_len, zfill
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x20', 'val': ofproto.NX_ACTION_OUTPUT_REG_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x0f', 'val': ofproto.NXAST_OUTPUT_REG}
    ofs_nbits = {'buf': b'\xfe\x78', 'val': 65144}
    src = {'buf': b'\x5e\x3a\x04\x26', 'val': 1580860454}
    max_len = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_OUTPUT_SIZE}
    zfill = b'\x00' * 6

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + ofs_nbits['buf'] \
        + src['buf'] \
        + max_len['buf'] \
        + zfill

    c = NXActionOutputReg(ofs_nbits['val'],
                          src['val'],
                          max_len['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)
        eq_(self.ofs_nbits['val'], self.c.ofs_nbits)
        eq_(self.src['val'], self.c.src)
        eq_(self.max_len['val'], self.c.max_len)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.type_['val'], res.type)
        eq_(self.len_['val'], res.len)
        eq_(self.vendor['val'], res.vendor)
        eq_(self.subtype['val'], res.subtype)
        eq_(self.ofs_nbits['val'], res.ofs_nbits)
        eq_(self.src['val'], res.src)
        eq_(self.max_len['val'], res.max_len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_OUTPUT_REG_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])
        eq_(self.ofs_nbits['val'], res[4])
        eq_(self.src['val'], res[5])
        eq_(self.max_len['val'], res[6])


class TestNXActionExit(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXActionExit
    """

    # NX_ACTION_HEADER_PACK_STR
    # '!HHIH'...type, len, vendor, subtype
    type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPAT_VENDOR}
    len_ = {'buf': b'\x00\x10', 'val': ofproto.NX_ACTION_HEADER_SIZE}
    vendor = {'buf': b'\x00\x00\x23\x20',
              'val': ofproto_common.NX_EXPERIMENTER_ID}
    subtype = {'buf': b'\x00\x11', 'val': ofproto.NXAST_EXIT}
    zfill = b'\x00' * 6

    buf = type_['buf'] \
        + len_['buf'] \
        + vendor['buf'] \
        + subtype['buf'] \
        + zfill

    c = NXActionExit()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_['val'], self.c.type)
        eq_(self.len_['val'], self.c.len)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.subtype['val'], self.c.subtype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.type_['val'], res.type)
        eq_(self.len_['val'], res.len)
        eq_(self.vendor['val'], res.vendor)
        eq_(self.subtype['val'], res.subtype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto.NX_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, six.binary_type(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.vendor['val'], res[2])
        eq_(self.subtype['val'], res[3])


class TestOFPDescStats(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPDescStats
    """

    # OFP_DESC_STATS_PACK_STR
    # '!256s256s256s32s256s'...mfr_desc, hw_desc, sw_desc, serial_num, dp_desc
    mfr_desc = b'mfr_desc'.ljust(256)
    hw_desc = b'hw_desc'.ljust(256)
    sw_desc = b'sw_desc'.ljust(256)
    serial_num = b'serial_num'.ljust(32)
    dp_desc = b'dp_desc'.ljust(256)

    buf = mfr_desc \
        + hw_desc \
        + sw_desc \
        + serial_num \
        + dp_desc

    c = OFPDescStats(mfr_desc, hw_desc, sw_desc, serial_num, dp_desc)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.mfr_desc, self.c.mfr_desc)
        eq_(self.hw_desc, self.c.hw_desc)
        eq_(self.sw_desc, self.c.sw_desc)
        eq_(self.serial_num, self.c.serial_num)
        eq_(self.dp_desc, self.c.dp_desc)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.mfr_desc, self.mfr_desc)
        eq_(self.hw_desc, self.hw_desc)
        eq_(self.sw_desc, self.sw_desc)
        eq_(self.serial_num, self.serial_num)
        eq_(self.dp_desc, self.dp_desc)


class TestOFPFlowStats(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPFlowStats
    """

    # OFP_FLOW_STATS_0_PACK_STR
    # '!HBx'...length, table_id, zfill
    length = {'buf': b'\x00\x58', 'val': 88}
    length_append_action = {'buf': b'\x00\x60', 'val': 96}
    table_id = {'buf': b'\x51', 'val': 81}
    zfill_0 = b'\x00'

    # OFP_MATCH_PACK_STR
    # '!IH6s6sHBxHBB2xIIHH'...
    match = b'\x97\x7c\xa6\x1e' \
        + b'\x5e\xa0' \
        + b'\x7a\x3e\xed\x30\x4a\x90' \
        + b'\x96\x8e\x67\xbe\x2f\xe2' \
        + b'\xb1\x81' \
        + b'\xbe' \
        + b'\x00' \
        + b'\x01\xab' \
        + b'\x42' \
        + b'\xfe' \
        + b'\x00\x00' \
        + b'\xa4\x5d\x5c\x42' \
        + b'\xa2\x5c\x2e\x05' \
        + b'\x5a\x94' \
        + b'\x64\xd4'

    # OFP_FLOW_STATS_1_PACK_STR
    # '!IIHHH6xQQQ'...duration_sec, duration_nsec, priority,
    #                 idle_timeout, hard_timeout, zfill,
    #                 cookie, packet_count, byte_count
    duration_sec = {'buf': b'\x94\x19\xb3\xd2', 'val': 2484712402}
    duration_nsec = {'buf': b'\xee\x66\xcf\x7c', 'val': 3999715196}
    priority = {'buf': b'\xe1\xc0', 'val': 57792}
    idle_timeout = {'buf': b'\x8e\x10', 'val': 36368}
    hard_timeout = {'buf': b'\xd4\x99', 'val': 54425}
    zfill_1 = b'\x00\x00\x00\x00\x00\x00'
    cookie = {'buf': b'\x0b\x01\xe8\xe5\xf0\x84\x8a\xe0',
              'val': 793171083674290912}
    packet_count = {'buf': b'\x47\x5c\xc6\x05\x28\xff\x7c\xdb',
                    'val': 5142202600015232219}
    byte_count = {'buf': b'\x24\xe9\x4b\xee\xcb\x57\xd9\xc3',
                  'val': 2659740543924820419}

    # <action>_PACK_STR...type_, len_ [others...]
    type = {'buf': b'\x00\x00', 'val': ofproto.OFPAT_OUTPUT}
    len = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_OUTPUT_SIZE}
    port = {'buf': b'\x59\x2a', 'val': 22826}
    max_len = {'buf': b'\x00\x08', 'val': ofproto.OFP_ACTION_OUTPUT_SIZE}
    action = (type, len, port, max_len)

    ACTION_TYPE = 0
    ACTION_LEN = 1
    ACTION_PORT = 2
    ACTION_MAX_LEN = 3

    c = OFPFlowStats()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def _parser(self, action=None):
        buf = self.table_id['buf'] \
            + self.zfill_0 \
            + self.match \
            + self.duration_sec['buf'] \
            + self.duration_nsec['buf'] \
            + self.priority['buf'] \
            + self.idle_timeout['buf'] \
            + self.hard_timeout['buf'] \
            + self.zfill_1 \
            + self.cookie['buf'] \
            + self.packet_count['buf'] \
            + self.byte_count['buf']

        if not action:
            buf = self.length['buf'] + buf
        else:
            buf = self.length_append_action['buf'] + buf

            for a in self.action:
                buf = buf + a['buf']

        return self.c.parser(buf, 0)

    def test_parser(self):
        res = self._parser()

        eq_(self.length['val'], res.length)
        eq_(self.table_id['val'], res.table_id)
        eq_(self.duration_sec['val'], res.duration_sec)
        eq_(self.duration_nsec['val'], res.duration_nsec)
        eq_(self.priority['val'], res.priority)
        eq_(self.idle_timeout['val'], res.idle_timeout)
        eq_(self.hard_timeout['val'], res.hard_timeout)
        eq_(self.cookie['val'], res.cookie)
        eq_(self.packet_count['val'], res.packet_count)
        eq_(self.byte_count['val'], res.byte_count)

    def test_parser_append_actions(self):
        res = self._parser(True).actions[0]

        eq_(self.action[self.ACTION_TYPE]['val'], res.type)
        eq_(self.action[self.ACTION_LEN]['val'], res.len)
        eq_(self.action[self.ACTION_PORT]['val'], res.port)
        eq_(self.action[self.ACTION_MAX_LEN]['val'], res.max_len)


class TestOFPAggregateStats(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPAggregateStats
    """

    # OFP_AGGREGATE_STATS_REPLY_PACK_STR
    # '!QQI4x'...packet_count, byte_count, flow_count, zfill
    packet_count = {'buf': b'\x43\x95\x1b\xfb\x0f\xf6\xa7\xdd',
                    'val': 4869829337189623773}
    byte_count = {'buf': b'\x36\xda\x2d\x80\x2a\x95\x35\xdd',
                  'val': 3952521651464517085}
    flow_count = {'buf': b'\xc3\x0d\xc3\xed', 'val': 3272459245}
    zfill = b'\x00' * 4

    buf = packet_count['buf'] \
        + byte_count['buf'] \
        + flow_count['buf'] \
        + zfill

    c = OFPAggregateStats(packet_count['val'],
                          byte_count['val'],
                          flow_count['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.packet_count['val'], self.c.packet_count)
        eq_(self.byte_count['val'], self.c.byte_count)
        eq_(self.flow_count['val'], self.c.flow_count)

    def test_parser(self):

        res = self.c.parser(self.buf, 0)

        eq_(self.packet_count['val'], res.packet_count)
        eq_(self.byte_count['val'], res.byte_count)
        eq_(self.flow_count['val'], res.flow_count)


class TestOFPTableStats(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPTableStats
    """

    # OFP_TABLE_STATS_PACK_STR
    # '!B3x32sIIIQQ'...table_id, zfill, name, wildcards, max_entries,
    #                  active_count, lookup_count, matched_count
    table_id = {'buf': b'\x5b', 'val': 91}
    zfill = b'\x00' * 3
    name = b'name'.ljust(32)
    wildcards = {'buf': b'\xc5\xaf\x6e\x12', 'val': 3316608530}
    max_entries = {'buf': b'\x95\x6c\x78\x4d', 'val': 2506913869}
    active_count = {'buf': b'\x78\xac\xa8\x1e', 'val': 2024581150}
    lookup_count = {'buf': b'\x40\x1d\x9c\x39\x19\xec\xd4\x1c',
                    'val': 4620020561814017052}
    matched_count = {'buf': b'\x27\x35\x02\xb6\xc5\x5e\x17\x65',
                     'val': 2825167325263435621}

    buf = table_id['buf'] \
        + zfill \
        + name \
        + wildcards['buf'] \
        + max_entries['buf'] \
        + active_count['buf'] \
        + lookup_count['buf'] \
        + matched_count['buf']

    c = OFPTableStats(table_id['val'],
                      name,
                      wildcards['val'],
                      max_entries['val'],
                      active_count['val'],
                      lookup_count['val'],
                      matched_count['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.table_id['val'], self.c.table_id)
        eq_(self.name, self.c.name)
        eq_(self.wildcards['val'], self.c.wildcards)
        eq_(self.max_entries['val'], self.c.max_entries)
        eq_(self.active_count['val'], self.c.active_count)
        eq_(self.lookup_count['val'], self.c.lookup_count)
        eq_(self.matched_count['val'], self.c.matched_count)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.table_id['val'], res.table_id)
        eq_(self.name, res.name)
        eq_(self.wildcards['val'], res.wildcards)
        eq_(self.max_entries['val'], res.max_entries)
        eq_(self.active_count['val'], res.active_count)
        eq_(self.lookup_count['val'], res.lookup_count)
        eq_(self.matched_count['val'], res.matched_count)


class TestOFPPortStats(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPortStats
    """

    # OFP_PORT_STATS_PACK_STR
    # '!H6xQQQQQQQQQQQQ'... port_no, zfill, rx_packets, tx_packets,
    #                       rx_bytes, tx_bytes, rx_dropped, tx_dropped,
    #                       rx_errors, tx_errors, rx_frame_err,
    #                       rx_over_err, rx_crc_err, collisions
    port_no = {'buf': b'\xe7\x6b', 'val': 59243}
    zfill = b'\x00' * 6
    rx_packets = {'buf': b'\x53\x44\x36\x61\xc4\x86\xc0\x37',
                  'val': 5999980397101236279}
    tx_packets = {'buf': b'\x27\xa4\x41\xd7\xd4\x53\x9e\x42',
                  'val': 2856480458895760962}
    rx_bytes = {'buf': b'\x55\xa1\x38\x60\x43\x97\x0d\x89',
                'val': 6170274950576278921}
    tx_bytes = {'buf': b'\x77\xe1\xd5\x63\x18\xae\x63\xaa',
                'val': 8638420181865882538}
    rx_dropped = {'buf': b'\x60\xe6\x20\x01\x24\xda\x4e\x5a',
                  'val': 6982303461569875546}
    tx_dropped = {'buf': b'\x09\x2d\x5d\x71\x71\xb6\x8e\xc7',
                  'val': 661287462113808071}
    rx_errors = {'buf': b'\x2f\x7e\x35\xb3\x66\x3c\x19\x0d',
                 'val': 3422231811478788365}
    tx_errors = {'buf': b'\x57\x32\x08\x2f\x88\x32\x40\x6b',
                 'val': 6283093430376743019}
    rx_frame_err = {'buf': b'\x0c\x28\x6f\xad\xce\x66\x6e\x8b',
                    'val': 876072919806406283}
    rx_over_err = {'buf': b'\x5a\x90\x8f\x9b\xfc\x82\x2e\xa0',
                   'val': 6525873760178941600}
    rx_crc_err = {'buf': b'\x73\x3a\x71\x17\xd6\x74\x69\x47',
                  'val': 8303073210207070535}
    collisions = {'buf': b'\x2f\x52\x0c\x79\x96\x03\x6e\x79',
                  'val': 3409801584220270201}

    buf = port_no['buf'] \
        + zfill \
        + rx_packets['buf'] \
        + tx_packets['buf'] \
        + rx_bytes['buf'] \
        + tx_bytes['buf'] \
        + rx_dropped['buf'] \
        + tx_dropped['buf'] \
        + rx_errors['buf'] \
        + tx_errors['buf'] \
        + rx_frame_err['buf'] \
        + rx_over_err['buf'] \
        + rx_crc_err['buf'] \
        + collisions['buf']

    c = OFPPortStats(port_no['val'],
                     rx_packets['val'],
                     tx_packets['val'],
                     rx_bytes['val'],
                     tx_bytes['val'],
                     rx_dropped['val'],
                     tx_dropped['val'],
                     rx_errors['val'],
                     tx_errors['val'],
                     rx_frame_err['val'],
                     rx_over_err['val'],
                     rx_crc_err['val'],
                     collisions['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no['val'], self.c.port_no)
        eq_(self.rx_packets['val'], self.c.rx_packets)
        eq_(self.tx_packets['val'], self.c.tx_packets)
        eq_(self.rx_bytes['val'], self.c.rx_bytes)
        eq_(self.tx_bytes['val'], self.c.tx_bytes)
        eq_(self.rx_dropped['val'], self.c.rx_dropped)
        eq_(self.tx_dropped['val'], self.c.tx_dropped)
        eq_(self.rx_errors['val'], self.c.rx_errors)
        eq_(self.tx_errors['val'], self.c.tx_errors)
        eq_(self.rx_frame_err['val'], self.c.rx_frame_err)
        eq_(self.rx_over_err['val'], self.c.rx_over_err)
        eq_(self.rx_crc_err['val'], self.c.rx_crc_err)
        eq_(self.collisions['val'], self.c.collisions)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port_no['val'], res.port_no)
        eq_(self.rx_packets['val'], res.rx_packets)
        eq_(self.tx_packets['val'], res.tx_packets)
        eq_(self.rx_bytes['val'], res.rx_bytes)
        eq_(self.tx_bytes['val'], res.tx_bytes)
        eq_(self.rx_dropped['val'], res.rx_dropped)
        eq_(self.tx_dropped['val'], res.tx_dropped)
        eq_(self.rx_errors['val'], res.rx_errors)
        eq_(self.tx_errors['val'], res.tx_errors)
        eq_(self.rx_frame_err['val'], res.rx_frame_err)
        eq_(self.rx_over_err['val'], res.rx_over_err)
        eq_(self.rx_crc_err['val'], res.rx_crc_err)
        eq_(self.collisions['val'], res.collisions)


class TestOFPQueueStats(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPQueueStats
    """

    # OFP_QUEUE_STATS_PACK_STR
    # '!H2xIQQQ...port_no, queue_id, tx_bytes, tx_packets, tx_errors
    port_no = {'buf': b'\xe7\x6b', 'val': 59243}
    zfill = b'\x00' * 2
    queue_id = {'buf': b'\x2a\xa8\x7f\x32', 'val': 715685682}
    tx_bytes = {'buf': b'\x77\xe1\xd5\x63\x18\xae\x63\xaa',
                'val': 8638420181865882538}
    tx_packets = {'buf': b'\x27\xa4\x41\xd7\xd4\x53\x9e\x42',
                  'val': 2856480458895760962}
    tx_errors = {'buf': b'\x57\x32\x08\x2f\x88\x32\x40\x6b',
                 'val': 6283093430376743019}

    c = OFPQueueStats(port_no['val'],
                      queue_id['val'],
                      tx_bytes['val'],
                      tx_packets['val'],
                      tx_errors['val'])

    buf = port_no['buf'] \
        + zfill \
        + queue_id['buf'] \
        + tx_bytes['buf'] \
        + tx_packets['buf'] \
        + tx_errors['buf']

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no['val'], self.c.port_no)
        eq_(self.queue_id['val'], self.c.queue_id)
        eq_(self.tx_bytes['val'], self.c.tx_bytes)
        eq_(self.tx_packets['val'], self.c.tx_packets)
        eq_(self.tx_errors['val'], self.c.tx_errors)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port_no['val'], res.port_no)
        eq_(self.queue_id['val'], res.queue_id)
        eq_(self.tx_bytes['val'], res.tx_bytes)
        eq_(self.tx_packets['val'], res.tx_packets)
        eq_(self.tx_errors['val'], res.tx_errors)


class TestOFPVendorStats(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPVendorStats
    """

    specific_data = 'specific_data'
    specific_data_after = 'data'
    offset = specific_data.find(specific_data_after)

    c = OFPVendorStats(specific_data)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.specific_data, self.c.specific_data)

    def test_parser(self):
        res = self.c.parser(self.specific_data, self.offset)
        eq_(self.specific_data_after, res.specific_data)


class TestOFPQueuePropNone(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPQueuePropNone
    """

    # OFP_QUEUE_PROP_HEADER_PACK_STR
    # '!HH4x'...property_, len_
    property = {'buf': b'\x00\x00', 'val': ofproto.OFPQT_NONE}
    len = {'buf': b'\x00\x08', 'val': ofproto.OFP_QUEUE_PROP_HEADER_SIZE}
    zfill = b'\x00' * 4

    c = OFPQueuePropNone()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        cls = OFPQueuePropHeader._QUEUE_PROPERTIES[self.c.cls_prop_type]

        eq_(self.property['val'], self.c.cls_prop_type)
        eq_(self.property['val'], self.c.property)
        eq_(self.property['val'], cls.cls_prop_type)

        eq_(self.len['val'], self.c.cls_prop_len)
        eq_(self.len['val'], self.c.len)
        eq_(self.len['val'], cls.cls_prop_len)

    def test_parser(self):
        buf = self.property['buf'] \
            + self.len['buf'] \
            + self.zfill

        ok_(self.c.parser(buf, 0))


class TestOFPQueuePropMinRate(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPQueuePropMinRate
    """

    # OFP_QUEUE_PROP_MIN_RATE_PACK_STR
    # '!H6x'...rate
    rate = {'buf': b'\x00\x01', 'val': ofproto.OFPQT_MIN_RATE}
    len = {'buf': b'\x00\x10', 'val': ofproto.OFP_QUEUE_PROP_MIN_RATE_SIZE}
    zfill = b'\x00' * 6

    buf = rate['buf'] \
        + zfill

    c = OFPQueuePropMinRate(rate['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        cls = OFPQueuePropHeader._QUEUE_PROPERTIES[self.c.cls_prop_type]

        eq_(self.rate['val'], self.c.cls_prop_type)
        eq_(self.rate['val'], self.c.rate)
        eq_(self.rate['val'], cls.cls_prop_type)

        eq_(self.len['val'], self.c.cls_prop_len)
        eq_(self.len['val'], cls.cls_prop_len)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.rate['val'], res.rate)


class TestOFPPacketQueue(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPacketQueue
    """

    # OFP_PACKET_QUEUE_PQCK_STR
    # '!IH2x'...queue_id, len_, zfill
    queue_id = {'buf': b'\x4d\x4b\x3a\xd1', 'val': 1296775889}
    len_ = {'buf': b'\x00\x08',
            'val': ofproto.OFP_QUEUE_PROP_HEADER_SIZE}
    zfill = b'\x00' * 2

    buf = queue_id['buf'] \
        + len_['buf'] \
        + zfill

    c = OFPPacketQueue(queue_id['val'],
                       len_['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.queue_id['val'], self.c.queue_id)
        eq_(self.len_['val'], self.c.len)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.queue_id['val'], res.queue_id)
        eq_(self.len_['val'], res.len)

    def test_parser_append_prop(self):
        # OFP_QUEUE_PROP_HEADER_PACK_STR + OFP_QUEUE_PROP_MIN_RATE_PACK_STR
        # '!HH4xH6x'...type, len, zfill, rate, zfill
        len_ = {'buf': b'\x00\x10',
                'val': ofproto.OFP_QUEUE_PROP_MIN_RATE_SIZE}
        a_type = {'buf': b'\x00\x01', 'val': ofproto.OFPQT_MIN_RATE}
        a_len = {'buf': b'\x00\x10',
                 'val': ofproto.OFP_QUEUE_PROP_MIN_RATE_SIZE}
        a_zfill0 = b'\x00' * 4
        a_rate = {'buf': b'\x00\x01', 'val': ofproto.OFPQT_MIN_RATE}
        a_zfill1 = b'\x00' * 6

        buf = self.queue_id['buf'] \
            + len_['buf'] \
            + self.zfill \
            + a_type['buf'] \
            + a_len['buf'] \
            + a_zfill0 \
            + a_rate['buf'] \
            + a_zfill1

        res = self.c.parser(buf, 0)

        eq_(self.queue_id['val'], res.queue_id)
        eq_(len_['val'], res.len)

        append_cls = res.properties[0]

        eq_(a_type['val'], append_cls.property)
        eq_(a_len['val'], append_cls.len)
        eq_(a_rate['val'], append_cls.rate)


class TestOFPHello(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPHello
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = ofproto.OFP_VERSION
        msg_type = ofproto.OFPT_HELLO
        msg_len = ofproto.OFP_HEADER_SIZE
        xid = 2183948390
        data = b'\x00\x01\x02\x03'

        fmt = ofproto.OFP_HEADER_PACK_STR
        buf = struct.pack(fmt, version, msg_type, msg_len, xid) \
            + data

        res = OFPHello.parser(object, version, msg_type, msg_len, xid,
                              bytearray(buf))

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(six.binary_type(buf), six.binary_type(res.buf))

    def test_serialize(self):

        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        c = OFPHello(Datapath)
        c.serialize()
        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_HELLO, c.msg_type)
        eq_(0, c.xid)


class TestOFPErrorMsg(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPErrorMsg
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x01', 'val': ofproto.OFPT_ERROR}
        msg_len = {'buf': b'\x00\x0c',
                   'val': ofproto.OFP_ERROR_MSG_SIZE}
        xid = {'buf': b'\x87\x8b\x26\x7c', 'val': 2274043516}
        type = {'buf': b'\xab\x3e', 'val': 43838}
        code = {'buf': b'\x5d\x3c', 'val': 23868}
        data = b'Error Message.'

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + type['buf'] \
            + code['buf'] \
            + data

        res = OFPErrorMsg.parser(object,
                                 version['val'],
                                 msg_type['val'],
                                 msg_len['val'],
                                 xid['val'],
                                 buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type['val'], res.type)
        eq_(code['val'], res.code)
        eq_(data, res.data)

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        type = 1306
        code = 13774
        data = b'Error Message.'

        c = OFPErrorMsg(Datapath)
        c.type = type
        c.code = code
        c.data = data

        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_ERROR, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_ERROR_MSG_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_ERROR, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(type, res[4])
        eq_(code, res[5])
        eq_(data, res[6])


class TestOFPEchoRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPEchoRequest
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x02', 'val': ofproto.OFPT_ECHO_REQUEST}
        msg_len = {'buf': b'\x00\x08',
                   'val': ofproto.OFP_HEADER_SIZE}
        xid = {'buf': b'\x84\x47\xef\x3f', 'val': 2219306815}
        data = b'Request Message.'

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + data

        res = OFPEchoRequest.parser(object,
                                    version['val'],
                                    msg_type['val'],
                                    msg_len['val'],
                                    xid['val'],
                                    buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(data, res.data)

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        data = b'Request Message.'

        c = OFPEchoRequest(Datapath)
        c.data = data

        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_ECHO_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_ECHO_REQUEST, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(data, res[4])


class TestOFPEchoReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPEchoReply
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x03', 'val': ofproto.OFPT_ECHO_REPLY}
        msg_len = {'buf': b'\x00\x08',
                   'val': ofproto.OFP_HEADER_SIZE}
        xid = {'buf': b'\x6e\x21\x3e\x62', 'val': 1847672418}
        data = b'Reply Message.'

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + data

        res = OFPEchoReply.parser(object,
                                  version['val'],
                                  msg_type['val'],
                                  msg_len['val'],
                                  xid['val'],
                                  buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(data, res.data)

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        data = b'Reply Message.'

        c = OFPEchoReply(Datapath)
        c.data = data

        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_ECHO_REPLY, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_ECHO_REPLY, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(data, res[4])


class TestOFPVendor(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPVendor
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x04', 'val': ofproto.OFPT_VENDOR}
        msg_len = {'buf': b'\x00\x0c',
                   'val': ofproto.OFP_VENDOR_HEADER_SIZE}
        xid = {'buf': b'\x05\x45\xdf\x18', 'val': 88465176}
        vendor = {'buf': b'\x53\xea\x25\x3e', 'val': 1407853886}
        data = b'Vendor Message.'

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + vendor['buf'] \
            + data

        res = OFPVendor.parser(object,
                               version['val'],
                               msg_type['val'],
                               msg_len['val'],
                               xid['val'],
                               buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(vendor['val'], res.vendor)
        eq_(data, res.data)

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        vendor = {'buf': b'\x38\x4b\xf9\x6c', 'val': 944503148}
        data = b'Reply Message.'

        c = OFPVendor(Datapath)
        c.vendor = vendor['val']
        c.data = data

        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_VENDOR, c.msg_type)
        eq_(0, c.xid)
        eq_(vendor['val'], c.vendor)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_VENDOR_HEADER_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_VENDOR, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(vendor['val'], res[4])
        eq_(data, res[5])


# class TestNXTRequest(unittest.TestCase):
class TestNiciraHeader(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NiciraHeader
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        subtype = ofproto.NXT_FLOW_MOD_TABLE_ID

        c = NiciraHeader(object, subtype)
        eq_(subtype, c.subtype)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        data = b'Reply Message.'
        subtype = ofproto.NXT_FLOW_MOD_TABLE_ID

        c = NiciraHeader(Datapath, subtype)
        c.data = data

        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_VENDOR, c.msg_type)
        eq_(0, c.xid)
        eq_(ofproto_common.NX_EXPERIMENTER_ID, c.vendor)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NICIRA_HEADER_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_VENDOR, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(ofproto_common.NX_EXPERIMENTER_ID, res[4])
        eq_(subtype, res[5])
        eq_(data, res[6])


class TestNXTSetFlowFormat(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXTSetFlowFormat
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        flow_format = {'buf': b'\xdc\x6b\xf5\x24', 'val': 3698062628}

        c = NXTSetFlowFormat(object, flow_format['val'])
        eq_(flow_format['val'], c.format)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        flow_format = {'buf': b'\x5a\x4e\x59\xad', 'val': 1515084205}

        c = NXTSetFlowFormat(Datapath, flow_format['val'])
        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_VENDOR, c.msg_type)
        eq_(0, c.xid)
        eq_(ofproto_common.NX_EXPERIMENTER_ID, c.vendor)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NICIRA_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NX_SET_FLOW_FORMAT_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_VENDOR, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(ofproto_common.NX_EXPERIMENTER_ID, res[4])
        eq_(ofproto.NXT_SET_FLOW_FORMAT, res[5])
        eq_(flow_format['val'], res[6])


class TestNXTFlowMod(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXTFlowMod
    """

    # NX_FLOW_MOD_PACK_STR
    # '!Q4HI3H6x'...cokkie, command, idle_timeout, head_timeout,
    #               priority, buffer_id, out_port, flags, rule, zfill
    cookie = {'buf': b'\x04\x56\x27\xad\xbd\x43\xd6\x83',
              'val': 312480851306993283}
    command = {'buf': b'\x61\xaa', 'val': 25002}
    idle_timeout = {'buf': b'\x4e\xff', 'val': 20223}
    hard_timeout = {'buf': b'\x80\x16', 'val': 32790}
    priority = {'buf': b'\x70\x5f', 'val': 28767}
    buffer_id = {'buf': b'\x7b\x97\x3a\x09', 'val': 2073508361}
    out_port = {'buf': b'\x11\x7d', 'val': 4477}
    flags = {'buf': b'\x5c\xb9', 'val': 23737}
    rule = nx_match.ClsRule()
    zfill = b'\x00' * 6

    port = {'buf': b'\x2a\xe0', 'val': 10976}
    actions = [OFPActionOutput(port['val'])]

    def _get_obj(self, append_action=False):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        actions = None
        if append_action:
            actions = self.actions

        c = NXTFlowMod(Datapath,
                       self.cookie['val'],
                       self.command['val'],
                       self.idle_timeout['val'],
                       self.hard_timeout['val'],
                       self.priority['val'],
                       self.buffer_id['val'],
                       self.out_port['val'],
                       self.flags['val'],
                       self.rule,
                       actions)

        return c

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        c = self._get_obj()

        eq_(self.cookie['val'], c.cookie)
        eq_(self.command['val'], c.command)
        eq_(self.idle_timeout['val'], c.idle_timeout)
        eq_(self.hard_timeout['val'], c.hard_timeout)
        eq_(self.priority['val'], c.priority)
        eq_(self.buffer_id['val'], c.buffer_id)
        eq_(self.out_port['val'], c.out_port)
        eq_(self.flags['val'], c.flags)
        eq_(self.rule.__hash__(), c.rule.__hash__())

    def test_init_append_actions(self):
        c = self._get_obj(True)

        action = c.actions[0]
        eq_(ofproto.OFPAT_OUTPUT, action.type)
        eq_(ofproto.OFP_ACTION_OUTPUT_SIZE, action.len)
        eq_(self.port['val'], action.port)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        c = self._get_obj()
        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_VENDOR, c.msg_type)
        eq_(0, c.xid)
        eq_(ofproto_common.NX_EXPERIMENTER_ID, c.vendor)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NICIRA_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NX_FLOW_MOD_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_VENDOR, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(ofproto_common.NX_EXPERIMENTER_ID, res[4])
        eq_(ofproto.NXT_FLOW_MOD, res[5])
        eq_(self.cookie['val'], res[6])
        eq_(self.command['val'], res[7])
        eq_(self.idle_timeout['val'], res[8])
        eq_(self.hard_timeout['val'], res[9])
        eq_(self.priority['val'], res[10])
        eq_(self.buffer_id['val'], res[11])
        eq_(self.out_port['val'], res[12])
        eq_(self.flags['val'], res[13])

    def test_serialize_append_actions(self):
        c = self._get_obj(True)
        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_VENDOR, c.msg_type)
        eq_(0, c.xid)
        eq_(ofproto_common.NX_EXPERIMENTER_ID, c.vendor)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NICIRA_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NX_FLOW_MOD_PACK_STR.replace('!', '') \
            + ofproto.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_VENDOR, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(ofproto_common.NX_EXPERIMENTER_ID, res[4])
        eq_(ofproto.NXT_FLOW_MOD, res[5])
        eq_(self.cookie['val'], res[6])
        eq_(self.command['val'], res[7])
        eq_(self.idle_timeout['val'], res[8])
        eq_(self.hard_timeout['val'], res[9])
        eq_(self.priority['val'], res[10])
        eq_(self.buffer_id['val'], res[11])
        eq_(self.out_port['val'], res[12])
        eq_(self.flags['val'], res[13])

        # action
        eq_(0, res[14])
        eq_(ofproto.OFPAT_OUTPUT, res[15])
        eq_(ofproto.OFP_ACTION_OUTPUT_SIZE, res[16])
        eq_(self.port['val'], res[17])
        eq_(0xffe5, res[18])


class TestNXTRoleRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXTRoleRequest
    """

    # NX_ROLE_PACK_STR
    # '!I'...role
    role = {'buf': b'\x62\x81\x27\x61', 'val': 1652631393}

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = NXTRoleRequest(Datapath, role['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.role['val'], self.c.role)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_VENDOR, self.c.msg_type)
        eq_(0, self.c.xid)
        eq_(ofproto_common.NX_EXPERIMENTER_ID, self.c.vendor)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NICIRA_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NX_ROLE_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_VENDOR, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(ofproto_common.NX_EXPERIMENTER_ID, res[4])
        eq_(ofproto.NXT_ROLE_REQUEST, res[5])
        eq_(self.role['val'], res[6])


class TestNXTFlowModTableId(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.NXTFlowModTableId
    """

    # NX_FLOW_MOD_TABLE_ID_PACK_STR
    # '!B7x'...set_, zfill
    set_ = {'buf': b'\x71', 'val': 113}
    zfill = b'\x00' * 7

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = NXTFlowModTableId(Datapath, set_['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.set_['val'], self.c.set)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_VENDOR, self.c.msg_type)
        eq_(0, self.c.xid)
        eq_(ofproto_common.NX_EXPERIMENTER_ID, self.c.vendor)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NICIRA_HEADER_PACK_STR.replace('!', '') \
            + ofproto.NX_FLOW_MOD_TABLE_ID_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_VENDOR, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(ofproto_common.NX_EXPERIMENTER_ID, res[4])
        eq_(ofproto.NXT_FLOW_MOD_TABLE_ID, res[5])
        eq_(self.set_['val'], res[6])


class TestOFPSwitchFeatures(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPSwitchFeatures
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPSwitchFeatures(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x06', 'val': ofproto.OFPT_FEATURES_REPLY}
        msg_len_val = ofproto.OFP_SWITCH_FEATURES_SIZE \
            + ofproto.OFP_PHY_PORT_SIZE
        msg_len = {'buf': b'\x00\x4c', 'val': msg_len_val}
        xid = {'buf': b'\xcc\x0a\x41\xd4', 'val': 3423224276}

        # OFP_SWITCH_FEATURES_PACK_STR
        # '!QIB3xII'...datapath_id, n_buffers, n_tables,
        #              zfill, capabilities, actions
        datapath_id = {'buf': b'\x11\xa3\x72\x63\x61\xde\x39\x81',
                       'val': 1270985291017894273}
        n_buffers = {'buf': b'\x80\x14\xd7\xf6', 'val': 2148849654}
        n_tables = {'buf': b'\xe4', 'val': 228}
        zfill = b'\x00' * 3
        capabilities = {'buf': b'\x69\x4f\xe4\xc2', 'val': 1766843586}
        actions = {'buf': b'\x78\x06\xd9\x0c', 'val': 2013714700}

        # OFP_PHY_PORT_PACK_STR
        # '!H6s16sIIIIII'... port_no, hw_addr, name, config, state
        #                    curr, advertised, supported, peer
        port_no = {'buf': b'\xe7\x6b', 'val': 59243}
        hw_addr = '3c:d1:2b:8d:3f:d6'
        name = b'name'.ljust(16)
        config = {'buf': b'\x84\xb6\x8c\x53', 'val': 2226555987}
        state = {'buf': b'\x64\x07\xfb\xc9', 'val': 1678244809}
        curr = {'buf': b'\xa9\xe8\x0a\x2b', 'val': 2850556459}
        advertised = {'buf': b'\x78\xb9\x7b\x72', 'val': 2025421682}
        supported = {'buf': b'\x7e\x65\x68\xad', 'val': 2120575149}
        peer = {'buf': b'\xa4\x5b\x8b\xed', 'val': 2757463021}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + datapath_id['buf'] \
            + n_buffers['buf'] \
            + n_tables['buf'] \
            + zfill \
            + capabilities['buf'] \
            + actions['buf'] \
            + port_no['buf'] \
            + addrconv.mac.text_to_bin(hw_addr) \
            + name \
            + config['buf'] \
            + state['buf'] \
            + curr['buf'] \
            + advertised['buf'] \
            + supported['buf'] \
            + peer['buf']

        res = OFPSwitchFeatures.parser(object,
                                       version['val'],
                                       msg_type['val'],
                                       msg_len['val'],
                                       xid['val'],
                                       buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(datapath_id['val'], res.datapath_id)
        eq_(n_buffers['val'], res.n_buffers)
        eq_(n_tables['val'], res.n_tables)
        eq_(capabilities['val'], res.capabilities)
        eq_(actions['val'], res.actions)

        # port
        port = res.ports[port_no['val']]
        eq_(port_no['val'], port.port_no)
        eq_(hw_addr, hw_addr)
        eq_(name, port.name)
        eq_(config['val'], port.config)
        eq_(state['val'], port.state)
        eq_(curr['val'], port.curr)
        eq_(advertised['val'], port.advertised)
        eq_(supported['val'], port.supported)
        eq_(peer['val'], port.peer)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPPortStatus(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPortStatus
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPPortStatus(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x0c', 'val': ofproto.OFPT_PORT_STATUS}
        msg_len = {'buf': b'\x00\x40',
                   'val': ofproto.OFP_PORT_STATUS_SIZE}
        xid = {'buf': b'\x06\x27\x8b\x7b', 'val': 103254907}

        # OFP_PORT_STATUS_PACK_STR
        # '!B7xH6s16sIIIIII'...reason, zfill, port_no, hw_addr,
        #                      name, config, state, curr,
        #                      advertised, supported, peer
        reason = {'buf': b'\x71', 'val': 113}
        zfill = b'\x00' * 7
        port_no = {'buf': b'\x48\xd8', 'val': 18648}
        hw_addr = '41:f7:a3:52:8f:6b'
        name = b'name'.ljust(16)
        config = {'buf': b'\xae\x73\x90\xec', 'val': 2926809324}
        state = {'buf': b'\x41\x37\x32\x1d', 'val': 1094136349}
        curr = {'buf': b'\xa9\x47\x13\x2c', 'val': 2840007468}
        advertised = {'buf': b'\xce\x6b\x4a\x87', 'val': 3463137927}
        supported = {'buf': b'\xb8\x06\x65\xa1', 'val': 3087426977}
        peer = {'buf': b'\x6a\x11\x52\x39', 'val': 1779520057}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + reason['buf'] \
            + zfill \
            + port_no['buf'] \
            + addrconv.mac.text_to_bin(hw_addr) \
            + name \
            + config['buf'] \
            + state['buf'] \
            + curr['buf'] \
            + advertised['buf'] \
            + supported['buf'] \
            + peer['buf']

        res = OFPPortStatus.parser(object,
                                   version['val'],
                                   msg_type['val'],
                                   msg_len['val'],
                                   xid['val'],
                                   buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(reason['val'], res.reason)

        # desc
        desc = res.desc
        eq_(port_no['val'], desc.port_no)
        eq_(hw_addr, desc.hw_addr)
        eq_(name, desc.name)
        eq_(config['val'], desc.config)
        eq_(state['val'], desc.state)
        eq_(curr['val'], desc.curr)
        eq_(advertised['val'], desc.advertised)
        eq_(supported['val'], desc.supported)
        eq_(peer['val'], desc.peer)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPPacketIn(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPacketIn
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPPacketIn(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def _test_parser(self, padding=False):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x0a', 'val': ofproto.OFPT_PACKET_IN}
        msg_len = {'buf': b'\x00\x14',
                   'val': ofproto.OFP_PACKET_IN_SIZE}
        xid = {'buf': b'\xd0\x23\x8c\x34', 'val': 3491990580}

        # OFP_PACKET_IN_PACK_STR
        # '!IHHBx2x'...buffer_id, total_len,
        #              in_port, reason, zfill, data
        buffer_id = {'buf': b'\xae\x73\x90\xec', 'val': 2926809324}
        total_len = {'buf': b'\x00\x10', 'val': 16}
        in_port = {'buf': b'\x08\x42', 'val': 2114}
        reason = {'buf': b'\x43', 'val': 67}
        zfill = b'\x00' * 1
        if padding:
            data = b'PACKET IN'.ljust(20)
        else:
            data = b'PACKET IN'.ljust(16)

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + buffer_id['buf'] \
            + total_len['buf'] \
            + in_port['buf'] \
            + reason['buf'] \
            + zfill \
            + data

        res = OFPPacketIn.parser(object,
                                 version['val'],
                                 msg_type['val'],
                                 msg_len['val'],
                                 xid['val'],
                                 buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(buffer_id['val'], res.buffer_id)
        eq_(total_len['val'], res.total_len)
        eq_(in_port['val'], res.in_port)
        eq_(reason['val'], res.reason)
        eq_(data[0:16], res.data)

        return True

    def test_parser(self):
        ok_(self._test_parser())

    def test_parser_padding(self):
        ok_(self._test_parser(True))

    def test_serialize(self):
        # Not used.
        pass


class TestOFPGetConfigReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPGetConfigReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPGetConfigReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x0a', 'val': ofproto.OFPT_GET_CONFIG_REPLY}
        msg_len = {'buf': b'\x00\x14',
                   'val': ofproto.OFP_SWITCH_CONFIG_SIZE}
        xid = {'buf': b'\x94\xc4\xd2\xcd', 'val': 2495926989}

        # OFP_SWITCH_CONFIG_PACK_STR
        # '!HH'...flags, miss_send_len
        flags = {'buf': b'\xa0\xe2', 'val': 41186}
        miss_send_len = {'buf': b'\x36\x0e', 'val': 13838}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf'] \
            + flags['buf'] \
            + miss_send_len['buf']

        res = OFPGetConfigReply.parser(object,
                                       version['val'],
                                       msg_type['val'],
                                       msg_len['val'],
                                       xid['val'],
                                       buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(flags['val'], res.flags)
        eq_(miss_send_len['val'], res.miss_send_len)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPBarrierReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPBarrierReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPBarrierReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x13', 'val': ofproto.OFPT_BARRIER_REPLY}
        msg_len = {'buf': b'\x00\x08',
                   'val': ofproto.OFP_HEADER_SIZE}
        xid = {'buf': b'\x66\xc4\xc3\xac', 'val': 1724171180}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        res = OFPBarrierReply.parser(object,
                                     version['val'],
                                     msg_type['val'],
                                     msg_len['val'],
                                     xid['val'],
                                     buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPFlowRemoved(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPFlowRemoved
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPFlowRemoved(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x0a', 'val': ofproto.OFPT_FLOW_REMOVED}
        msg_len = {'buf': b'\x00\x14',
                   'val': ofproto.OFP_FLOW_REMOVED_SIZE}
        xid = {'buf': b'\x94\xc4\xd2\xcd', 'val': 2495926989}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_MATCH_PACK_STR
        # '!IH6s6sHBxHBB2xIIHH'...wildcards, in_port, dl_src, dl_dst, dl_vlan,
        #                         dl_vlan_pcp, dl_type, nw_tos, nw_proto,
        #                         nw_src, nw_dst, tp_src, tp_dst
        wildcards = {'buf': b'\xd2\x71\x25\x23', 'val': 3530630435}
        in_port = {'buf': b'\x37\x8b', 'val': 14219}
        dl_src = b'\x7f\x85\xc4\x70\x12\xda'
        dl_dst = b'\x0a\x51\x17\x58\xb0\xbb'
        dl_vlan = {'buf': b'\xc1\xf9', 'val': 49657}
        dl_vlan_pcp = {'buf': b'\x79', 'val': 121}
        zfill0 = b'\x00'
        dl_type = {'buf': b'\xa6\x9e', 'val': 42654}
        nw_tos = {'buf': b'\xde', 'val': 222}
        nw_proto = {'buf': b'\xe5', 'val': 229}
        zfil11 = b'\x00' * 2
        nw_src = {'buf': b'\x1b\x6d\x8d\x4b', 'val': 460164427}
        nw_dst = {'buf': b'\xab\x25\xe1\x20', 'val': 2871386400}
        tp_src = {'buf': b'\xd5\xc3', 'val': 54723}
        tp_dst = {'buf': b'\x78\xb9', 'val': 30905}

        buf += wildcards['buf'] \
            + in_port['buf'] \
            + dl_src \
            + dl_dst \
            + dl_vlan['buf'] \
            + dl_vlan_pcp['buf'] \
            + zfill0 \
            + dl_type['buf'] \
            + nw_tos['buf'] \
            + nw_proto['buf'] \
            + zfil11 \
            + nw_src['buf'] \
            + nw_dst['buf'] \
            + tp_src['buf'] \
            + tp_dst['buf']

        # OFP_FLOW_REMOVED_PACK_STR0
        # '!QHBxIIH2xQQ'...cookie, priority, reason, zfill,
        #                  duration_sec, duration_nsec, idle_timeout,
        #                  zfill, packet_count, byte_count
        cookie = {'buf': b'\x02\x79\xba\x00\xef\xab\xee\x44',
                  'val': 178378173441633860}
        priority = {'buf': b'\x02\xce', 'val': 718}
        reason = {'buf': b'\xa9', 'val': 169}
        zfill0 = b'\x00' * 1
        duration_sec = {'buf': b'\x86\x24\xa3\xba', 'val': 2250548154}
        duration_nsec = {'buf': b'\x94\x94\xc2\x23', 'val': 2492776995}
        idle_timeout = {'buf': b'\xeb\x7c', 'val': 60284}
        zfill1 = b'\x00' * 2
        packet_count = {'buf': b'\x5a\x0d\xf2\x03\x8e\x0a\xbb\x8d',
                        'val': 6489108735192644493}
        byte_count = {'buf': b'\x65\xc8\xd3\x72\x51\xb5\xbb\x7c',
                      'val': 7334344481123449724}

        buf += cookie['buf'] \
            + priority['buf'] \
            + reason['buf'] \
            + zfill0 \
            + duration_sec['buf'] \
            + duration_nsec['buf'] \
            + idle_timeout['buf'] \
            + zfill1 \
            + packet_count['buf'] \
            + byte_count['buf']

        res = OFPFlowRemoved.parser(object,
                                    version['val'],
                                    msg_type['val'],
                                    msg_len['val'],
                                    xid['val'],
                                    buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(cookie['val'], res.cookie)
        eq_(priority['val'], res.priority)
        eq_(reason['val'], res.reason)
        eq_(duration_sec['val'], res.duration_sec)
        eq_(duration_nsec['val'], res.duration_nsec)
        eq_(idle_timeout['val'], res.idle_timeout)
        eq_(packet_count['val'], res.packet_count)
        eq_(byte_count['val'], res.byte_count)

        # match
        match = res.match
        eq_(wildcards['val'], match.wildcards)
        eq_(in_port['val'], match.in_port)
        eq_(dl_src, match.dl_src)
        eq_(dl_dst, match.dl_dst)
        eq_(dl_vlan['val'], match.dl_vlan)
        eq_(dl_vlan_pcp['val'], match.dl_vlan_pcp)
        eq_(dl_type['val'], match.dl_type)
        eq_(nw_tos['val'], match.nw_tos)
        eq_(nw_proto['val'], match.nw_proto)
        eq_(nw_src['val'], match.nw_src)
        eq_(nw_dst['val'], match.nw_dst)
        eq_(tp_src['val'], match.tp_src)
        eq_(tp_dst['val'], match.tp_dst)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPQueueGetConfigReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPQueueGetConfigReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPQueueGetConfigReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x0a',
                    'val': ofproto.OFPT_QUEUE_GET_CONFIG_REPLY}
        msg_len_val = ofproto.OFP_QUEUE_GET_CONFIG_REPLY_SIZE \
            + ofproto.OFP_PACKET_QUEUE_SIZE
        msg_len = {'buf': b'\x00\x14', 'val': msg_len_val}
        xid = {'buf': b'\x94\xc4\xd2\xcd', 'val': 2495926989}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR
        # '!H6x'...port, zfill
        port = {'buf': b'\xfe\x66', 'val': 65126}
        zfill = b'\x00' * 6

        buf += port['buf'] \
            + zfill

        # OFP_PACKET_QUEUE_PQCK_STR
        # '!IH2x'...queue_id, len_, zfill
        queue_id = {'buf': b'\x4d\x4b\x3a\xd1', 'val': 1296775889}
        len_ = {'buf': b'\x00\x08',
                'val': ofproto.OFP_QUEUE_PROP_HEADER_SIZE}
        zfill = b'\x00' * 2

        buf += queue_id['buf'] \
            + len_['buf'] \
            + zfill

        res = OFPQueueGetConfigReply.parser(object,
                                            version['val'],
                                            msg_type['val'],
                                            msg_len['val'],
                                            xid['val'],
                                            buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(port['val'], res.port)

        # queue
        queue = res.queues[0]
        eq_(queue_id['val'], queue.queue_id)
        eq_(len_['val'], queue.len)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPDescStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPDescStatsReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPDescStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x11', 'val': ofproto.OFPT_STATS_REPLY}
        msg_len_val = ofproto.OFP_STATS_MSG_SIZE \
            + ofproto.OFP_DESC_STATS_SIZE
        msg_len = {'buf': b'\x04\x38', 'val': msg_len_val}
        xid = {'buf': b'\x94\xc4\xd2\xcd', 'val': 2495926989}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_STATS_MSG_PACK_STR
        # '!HH'...type_, flags
        type_ = {'buf': b'\x00\x00', 'val': ofproto.OFPST_DESC}
        flags = {'buf': b'\x30\xd9', 'val': 12505}

        buf += type_['buf'] \
            + flags['buf']

        # stats_type_cls = OFPDescStats
        # OFP_DESC_STATS_PACK_STR
        # '!256s256s256s32s256s'...mfr_desc, hw_desc, sw_desc,
        #                          serial_num, dp_desc
        mfr_desc = b'mfr_desc'.ljust(256)
        hw_desc = b'hw_desc'.ljust(256)
        sw_desc = b'sw_desc'.ljust(256)
        serial_num = b'serial_num'.ljust(32)
        dp_desc = b'dp_desc'.ljust(256)

        buf += mfr_desc \
            + hw_desc \
            + sw_desc \
            + serial_num \
            + dp_desc

        res = OFPDescStatsReply.parser(object,
                                       version['val'],
                                       msg_type['val'],
                                       msg_len['val'],
                                       xid['val'],
                                       buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type_['val'], res.type)
        eq_(flags['val'], res.flags)

        # body
        body = res.body
        eq_(mfr_desc, body.mfr_desc)
        eq_(hw_desc, body.hw_desc)
        eq_(sw_desc, body.sw_desc)
        eq_(serial_num, body.serial_num)
        eq_(dp_desc, body.dp_desc)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPFlowStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPFlowStatsReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPFlowStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x11', 'val': ofproto.OFPT_STATS_REPLY}
        msg_len_val = ofproto.OFP_STATS_MSG_SIZE \
            + ofproto.OFP_FLOW_STATS_SIZE
        msg_len = {'buf': b'\x00\x64', 'val': msg_len_val}
        xid = {'buf': b'\x94\xc4\xd2\xcd', 'val': 2495926989}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_STATS_MSG_PACK_STR
        # '!HH'...type_, flags
        type_ = {'buf': b'\x00\x01', 'val': ofproto.OFPST_FLOW}
        flags = {'buf': b'\x95\xf4', 'val': 38388}

        buf += type_['buf'] \
            + flags['buf']

        # stats_type_cls = OFPFlowStats
        # OFP_FLOW_STATS_0_PACK_STR
        # '!HBx'...length, table_id, zfill
        length = {'buf': b'\x00\x60', 'val': 96}
        table_id = {'buf': b'\x51', 'val': 81}
        zfill = b'\x00'

        buf += length['buf'] \
            + table_id['buf'] \
            + zfill

        # OFP_MATCH_PACK_STR
        # '!IH6s6sHBxHBB2xIIHH'...
        match = b'\x97\x7c\xa6\x1e' \
            + b'\x5e\xa0' \
            + b'\x70\x17\xdc\x80\x59\x9e' \
            + b'\x79\xc6\x56\x87\x92\x28' \
            + b'\xb1\x81' \
            + b'\xbe' \
            + b'\x00' \
            + b'\x01\xab' \
            + b'\x42' \
            + b'\xfe' \
            + b'\x00\x00' \
            + b'\xa4\x5d\x5c\x42' \
            + b'\xa2\x5c\x2e\x05' \
            + b'\x5a\x94' \
            + b'\x64\xd4'

        buf += match

        # OFP_FLOW_STATS_1_PACK_STR
        # '!IIHHH6xQQQ'...duration_sec, duration_nsec, priority,
        #                 idle_timeout, hard_timeout, zfill,
        #                 cookie, packet_count, byte_count
        duration_sec = {'buf': b'\x94\x19\xb3\xd2', 'val': 2484712402}
        duration_nsec = {'buf': b'\xee\x66\xcf\x7c', 'val': 3999715196}
        priority = {'buf': b'\xe1\xc0', 'val': 57792}
        idle_timeout = {'buf': b'\x8e\x10', 'val': 36368}
        hard_timeout = {'buf': b'\xd4\x99', 'val': 54425}
        zfill = b'\x00' * 6
        cookie = {'buf': b'\x0b\x01\xe8\xe5\xf0\x84\x8a\xe0',
                  'val': 793171083674290912}
        packet_count = {'buf': b'\x47\x5c\xc6\x05\x28\xff\x7c\xdb',
                        'val': 5142202600015232219}
        byte_count = {'buf': b'\x24\xe9\x4b\xee\xcb\x57\xd9\xc3',
                      'val': 2659740543924820419}

        buf += duration_sec['buf']
        buf += duration_nsec['buf']
        buf += priority['buf']
        buf += idle_timeout['buf']
        buf += hard_timeout['buf']
        buf += zfill
        buf += cookie['buf']
        buf += packet_count['buf']
        buf += byte_count['buf']

        # <action>_PACK_STR...type_, len_ [others...]
        type = {'buf': b'\x00\x00', 'val': ofproto.OFPAT_OUTPUT}
        len = {'buf': b'\x00\x08',
               'val': ofproto.OFP_ACTION_OUTPUT_SIZE}
        port = {'buf': b'\x59\x2a', 'val': 22826}
        max_len = {'buf': b'\x00\x08',
                   'val': ofproto.OFP_ACTION_OUTPUT_SIZE}

        buf += type['buf'] \
            + len['buf'] \
            + port['buf'] \
            + max_len['buf']

        res = OFPFlowStatsReply.parser(object,
                                       version['val'],
                                       msg_type['val'],
                                       msg_len['val'],
                                       xid['val'],
                                       buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type_['val'], res.type)
        eq_(flags['val'], res.flags)

        # body
        body = res.body[0]
        eq_(length['val'], body.length)
        eq_(table_id['val'], body.table_id)
        eq_(duration_sec['val'], body.duration_sec)
        eq_(duration_nsec['val'], body.duration_nsec)
        eq_(priority['val'], body.priority)
        eq_(idle_timeout['val'], body.idle_timeout)
        eq_(hard_timeout['val'], body.hard_timeout)
        eq_(cookie['val'], body.cookie)
        eq_(packet_count['val'], body.packet_count)
        eq_(byte_count['val'], body.byte_count)

        # action
        action = body.actions[0]
        eq_(type['val'], action.type)
        eq_(len['val'], action.len)
        eq_(port['val'], action.port)
        eq_(max_len['val'], action.max_len)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPAggregateStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPAggregateStatsReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPAggregateStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x11', 'val': ofproto.OFPT_STATS_REPLY}
        msg_len_val = ofproto.OFP_STATS_MSG_SIZE \
            + ofproto.OFP_AGGREGATE_STATS_REPLY_SIZE
        msg_len = {'buf': b'\x00\x4c', 'val': msg_len_val}
        xid = {'buf': b'\xc6\xd6\xce\x38', 'val': 3335966264}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_STATS_MSG_PACK_STR
        # '!HH'...type_, flags
        type_ = {'buf': b'\x00\x02', 'val': ofproto.OFPST_AGGREGATE}
        flags = {'buf': b'\x65\x66', 'val': 25958}

        buf += type_['buf'] \
            + flags['buf']

        # stats_type_cls = OFPAggregateStats
        # OFP_AGGREGATE_STATS_REPLY_PACK_STR
        # '!QQI4x'...packet_count, byte_count, flow_count, zfill
        packet_count = {'buf': b'\x43\x95\x1b\xfb\x0f\xf6\xa7\xdd',
                        'val': 4869829337189623773}
        byte_count = {'buf': b'\x36\xda\x2d\x80\x2a\x95\x35\xdd',
                      'val': 3952521651464517085}
        flow_count = {'buf': b'\xc3\x0d\xc3\xed', 'val': 3272459245}
        zfill = b'\x00' * 4

        buf += packet_count['buf'] \
            + byte_count['buf'] \
            + flow_count['buf'] \
            + zfill

        res = OFPAggregateStatsReply.parser(object,
                                            version['val'],
                                            msg_type['val'],
                                            msg_len['val'],
                                            xid['val'],
                                            buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type_['val'], res.type)
        eq_(flags['val'], res.flags)

        # body
        body = res.body[0]
        eq_(packet_count['val'], body.packet_count)
        eq_(byte_count['val'], body.byte_count)
        eq_(flow_count['val'], body.flow_count)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPTableStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPTableStatsReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPTableStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x11', 'val': ofproto.OFPT_STATS_REPLY}
        msg_len_val = ofproto.OFP_STATS_MSG_SIZE \
            + ofproto.OFP_TABLE_STATS_SIZE
        msg_len = {'buf': b'\x00\x4c', 'val': msg_len_val}
        xid = {'buf': b'\xd6\xb4\x8d\xe6', 'val': 3602157030}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_STATS_MSG_PACK_STR
        # '!HH'...type_, flags
        type_ = {'buf': b'\x00\x03', 'val': ofproto.OFPST_TABLE}
        flags = {'buf': b'\xb3\xf0', 'val': 46064}

        buf += type_['buf'] \
            + flags['buf']

        # stats_type_cls = OFPTableStats
        # OFP_TABLE_STATS_PACK_STR
        # '!B3x32sIIIQQ'...table_id, zfill, name, wildcards, max_entries,
        #                  active_count, lookup_count, matched_count
        table_id = {'buf': b'\x5b', 'val': 91}
        zfill = b'\x00' * 3
        name = b'name'.ljust(32)
        wildcards = {'buf': b'\xc5\xaf\x6e\x12', 'val': 3316608530}
        max_entries = {'buf': b'\x95\x6c\x78\x4d', 'val': 2506913869}
        active_count = {'buf': b'\x78\xac\xa8\x1e', 'val': 2024581150}
        lookup_count = {'buf': b'\x40\x1d\x9c\x39\x19\xec\xd4\x1c',
                        'val': 4620020561814017052}
        matched_count = {'buf': b'\x27\x35\x02\xb6\xc5\x5e\x17\x65',
                         'val': 2825167325263435621}

        buf += table_id['buf'] \
            + zfill \
            + name \
            + wildcards['buf'] \
            + max_entries['buf'] \
            + active_count['buf'] \
            + lookup_count['buf'] \
            + matched_count['buf']

        res = OFPTableStatsReply.parser(object,
                                        version['val'],
                                        msg_type['val'],
                                        msg_len['val'],
                                        xid['val'],
                                        buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type_['val'], res.type)
        eq_(flags['val'], res.flags)

        # body
        body = res.body[0]
        eq_(table_id['val'], body.table_id)
        eq_(name, body.name)
        eq_(wildcards['val'], body.wildcards)
        eq_(max_entries['val'], body.max_entries)
        eq_(active_count['val'], body.active_count)
        eq_(lookup_count['val'], body.lookup_count)
        eq_(matched_count['val'], body.matched_count)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPPortStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPortStatsReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPPortStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x11', 'val': ofproto.OFPT_STATS_REPLY}
        msg_len_val = ofproto.OFP_STATS_MSG_SIZE \
            + ofproto.OFP_PORT_STATS_SIZE
        msg_len = {'buf': b'\x00\x74', 'val': msg_len_val}
        xid = {'buf': b'\xc2\xaf\x3d\xff', 'val': 3266264575}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_STATS_MSG_PACK_STR
        # '!HH'...type_, flags
        type_ = {'buf': b'\x00\x04', 'val': ofproto.OFPST_PORT}
        flags = {'buf': b'\xda\xde', 'val': 56030}

        buf += type_['buf'] \
            + flags['buf']

        # stats_type_cls = OFPPortStats
        # OFP_PORT_STATS_PACK_STR
        # '!H6xQQQQQQQQQQQQ'... port_no, zfill, rx_packets, tx_packets,
        #                       rx_bytes, tx_bytes, rx_dropped, tx_dropped,
        #                       rx_errors, tx_errors, rx_frame_err,
        #                       rx_over_err, rx_crc_err, collisions
        port_no = {'buf': b'\xe7\x6b', 'val': 59243}
        zfill = b'\x00' * 6
        rx_packets = {'buf': b'\x53\x44\x36\x61\xc4\x86\xc0\x37',
                      'val': 5999980397101236279}
        tx_packets = {'buf': b'\x27\xa4\x41\xd7\xd4\x53\x9e\x42',
                      'val': 2856480458895760962}
        rx_bytes = {'buf': b'\x55\xa1\x38\x60\x43\x97\x0d\x89',
                    'val': 6170274950576278921}
        tx_bytes = {'buf': b'\x77\xe1\xd5\x63\x18\xae\x63\xaa',
                    'val': 8638420181865882538}
        rx_dropped = {'buf': b'\x60\xe6\x20\x01\x24\xda\x4e\x5a',
                      'val': 6982303461569875546}
        tx_dropped = {'buf': b'\x09\x2d\x5d\x71\x71\xb6\x8e\xc7',
                      'val': 661287462113808071}
        rx_errors = {'buf': b'\x2f\x7e\x35\xb3\x66\x3c\x19\x0d',
                     'val': 3422231811478788365}
        tx_errors = {'buf': b'\x57\x32\x08\x2f\x88\x32\x40\x6b',
                     'val': 6283093430376743019}
        rx_frame_err = {'buf': b'\x0c\x28\x6f\xad\xce\x66\x6e\x8b',
                        'val': 876072919806406283}
        rx_over_err = {'buf': b'\x5a\x90\x8f\x9b\xfc\x82\x2e\xa0',
                       'val': 6525873760178941600}
        rx_crc_err = {'buf': b'\x73\x3a\x71\x17\xd6\x74\x69\x47',
                      'val': 8303073210207070535}
        collisions = {'buf': b'\x2f\x52\x0c\x79\x96\x03\x6e\x79',
                      'val': 3409801584220270201}

        buf += port_no['buf'] \
            + zfill \
            + rx_packets['buf'] \
            + tx_packets['buf'] \
            + rx_bytes['buf'] \
            + tx_bytes['buf'] \
            + rx_dropped['buf'] \
            + tx_dropped['buf'] \
            + rx_errors['buf'] \
            + tx_errors['buf'] \
            + rx_frame_err['buf'] \
            + rx_over_err['buf'] \
            + rx_crc_err['buf'] \
            + collisions['buf']

        res = OFPPortStatsReply.parser(object,
                                       version['val'],
                                       msg_type['val'],
                                       msg_len['val'],
                                       xid['val'],
                                       buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type_['val'], res.type)
        eq_(flags['val'], res.flags)

        # body
        body = res.body[0]
        eq_(port_no['val'], body.port_no)
        eq_(rx_packets['val'], body.rx_packets)
        eq_(tx_packets['val'], body.tx_packets)
        eq_(rx_bytes['val'], body.rx_bytes)
        eq_(tx_bytes['val'], body.tx_bytes)
        eq_(rx_dropped['val'], body.rx_dropped)
        eq_(tx_dropped['val'], body.tx_dropped)
        eq_(rx_errors['val'], body.rx_errors)
        eq_(tx_errors['val'], body.tx_errors)
        eq_(rx_frame_err['val'], body.rx_frame_err)
        eq_(rx_over_err['val'], body.rx_over_err)
        eq_(rx_crc_err['val'], body.rx_crc_err)
        eq_(collisions['val'], body.collisions)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPQueueStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPQueueStatsReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPQueueStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x11', 'val': ofproto.OFPT_STATS_REPLY}
        msg_len_val = ofproto.OFP_STATS_MSG_SIZE \
            + ofproto.OFP_QUEUE_STATS_SIZE
        msg_len = {'buf': b'\x00\x2c', 'val': msg_len_val}
        xid = {'buf': b'\x19\xfc\x28\x6c', 'val': 435955820}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_STATS_MSG_PACK_STR
        # '!HH'...type_, flags
        type_ = {'buf': b'\x00\x05', 'val': ofproto.OFPST_QUEUE}
        flags = {'buf': b'\x3b\x2b', 'val': 15147}

        buf += type_['buf'] \
            + flags['buf']

        # stats_type_cls = OFPQueueStats
        # OFP_QUEUE_STATS_PACK_STR
        # '!H2xIQQQ...port_no, queue_id, tx_bytes, tx_packets, tx_errors
        port_no = {'buf': b'\xe7\x6b', 'val': 59243}
        zfill = b'\x00' * 2
        queue_id = {'buf': b'\x2a\xa8\x7f\x32', 'val': 715685682}
        tx_bytes = {'buf': b'\x77\xe1\xd5\x63\x18\xae\x63\xaa',
                    'val': 8638420181865882538}
        tx_packets = {'buf': b'\x27\xa4\x41\xd7\xd4\x53\x9e\x42',
                      'val': 2856480458895760962}
        tx_errors = {'buf': b'\x57\x32\x08\x2f\x88\x32\x40\x6b',
                     'val': 6283093430376743019}

        buf += port_no['buf'] \
            + zfill \
            + queue_id['buf'] \
            + tx_bytes['buf'] \
            + tx_packets['buf'] \
            + tx_errors['buf']

        res = OFPQueueStatsReply.parser(object,
                                        version['val'],
                                        msg_type['val'],
                                        msg_len['val'],
                                        xid['val'],
                                        buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type_['val'], res.type)
        eq_(flags['val'], res.flags)

        # body
        body = res.body[0]
        eq_(port_no['val'], body.port_no)
        eq_(queue_id['val'], body.queue_id)
        eq_(tx_bytes['val'], body.tx_bytes)
        eq_(tx_packets['val'], body.tx_packets)
        eq_(tx_errors['val'], body.tx_errors)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPVendorStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPVendorStatsReply
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPVendorStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        version = {'buf': b'\x01', 'val': ofproto.OFP_VERSION}
        msg_type = {'buf': b'\x11', 'val': ofproto.OFPT_STATS_REPLY}
        # ofproto.OFP_STATS_MSG_SIZE + len(specific_data)
        msg_len = {'buf': b'\x00\x18',
                   'val': ofproto.OFP_STATS_MSG_SIZE + 12}
        xid = {'buf': b'\x94\xc4\xd2\xcd', 'val': 2495926989}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_STATS_MSG_PACK_STR
        # '!HH'...type_, flags
        type_ = {'buf': b'\xff\xff', 'val': ofproto.OFPST_VENDOR}
        flags = {'buf': b'\x30\xd9', 'val': 12505}

        buf += type_['buf'] \
            + flags['buf']

        # stats_type_cls = OFPVendorStats
        specific_data = b'specific_data'

        buf += specific_data

        res = OFPVendorStatsReply.parser(object,
                                         version['val'],
                                         msg_type['val'],
                                         msg_len['val'],
                                         xid['val'],
                                         buf)

        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)
        eq_(type_['val'], res.type)
        eq_(flags['val'], res.flags)

        # body
        body = res.body[0]
        eq_(specific_data, body)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPFeaturesRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPFeaturesRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPFeaturesRequest(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_FEATURES_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = ofproto.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, six.binary_type(self.c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_FEATURES_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])


class TestOFPGetConfigRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPGetConfigRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPGetConfigRequest(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_GET_CONFIG_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = ofproto.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, six.binary_type(self.c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_GET_CONFIG_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])


class TestOFPSetConfig(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPSetConfig
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    # OFP_SWITCH_CONFIG_PACK_STR
    # '!HH'...flags, miss_send_len
    flags = {'buf': b'\xa0\xe2', 'val': 41186}
    miss_send_len = {'buf': b'\x36\x0e', 'val': 13838}

    c = OFPSetConfig(Datapath,
                     flags['val'],
                     miss_send_len['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.flags['val'], self.c.flags)
        eq_(self.miss_send_len['val'], self.c.miss_send_len)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_SET_CONFIG, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_SWITCH_CONFIG_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_SET_CONFIG, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(self.flags['val'], res[4])
        eq_(self.miss_send_len['val'], res[5])


class TestOFPPacketOut(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPacketOut
    """

    port = 0x2ae0
    actions = [OFPActionOutput(port, max_len=0)]

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _get_obj(self, buffer_id, in_port, data=None):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        c = OFPPacketOut(Datapath,
                         buffer_id,
                         in_port,
                         self.actions,
                         data)
        return c

    def test_init(self):
        buffer_id = 0xffffffff
        in_port = 0x40455
        data = 'Message'

        c = self._get_obj(buffer_id, in_port, data)

        eq_(buffer_id, c.buffer_id)
        eq_(in_port, c.in_port)
        eq_(data, c.data)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        buffer_id = 0xffffffff
        in_port = 0x9e07
        data = b'Message'

        c = self._get_obj(buffer_id, in_port, data)
        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_PACKET_OUT, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_PACKET_OUT_PACK_STR.replace('!', '') \
            + ofproto.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, six.binary_type(c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_PACKET_OUT, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])

        # OFP_PACKET_OUT_PACK_STR
        eq_(buffer_id, res[4])
        eq_(in_port, res[5])
        eq_(ofproto.OFP_ACTION_OUTPUT_SIZE, res[6])

        # OFP_ACTION_OUTPUT_PACK_STR
        eq_(ofproto.OFPAT_OUTPUT, res[7])
        eq_(ofproto.OFP_ACTION_OUTPUT_SIZE, res[8])
        eq_(self.port, res[9])
        eq_(0, res[10])

        # data
        eq_(data, res[11])

    @raises(AssertionError)
    def test_serialize_check_buffer_id(self):
        buffer_id = 0xffffff00
        in_port = 0xaa92
        data = 'Message'

        c = self._get_obj(buffer_id, in_port, data)
        c.serialize()


class TestOFPFlowMod(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPFlowMod
    """

    # OFP_FLOW_MOD_PACK_STR0
    # '!QHHHHIHH'...cookie, command, idle_timeout, hard_timeout,
    #               priority, buffer_id, out_port, flags
    cookie = {'buf': b'\x1d\x86\xce\x6e\x8d\xc0\xbe\xa8',
              'val': 2127614848199081640}
    command = {'buf': b'\xe1\x55', 'val': 57685}
    idle_timeout = {'buf': b'\xf3\x6d', 'val': 62317}
    hard_timeout = {'buf': b'\x1c\xc5', 'val': 7365}
    priority = {'buf': b'\x9c\xe3', 'val': 40163}
    buffer_id = {'buf': b'\xf0\xa1\x80\x33', 'val': 4037115955}
    out_port = {'buf': b'\xfe\x0d', 'val': 65037}
    flags = {'buf': b'\x00\x87', 'val': 135}

    # OFP_MATCH_PACK_STR
    # '!IH6s6sHBxHBB2xIIHH'...wildcards, in_port, dl_src, dl_dst, dl_vlan,
    #                         dl_vlan_pcp, dl_type, nw_tos, nw_proto,
    #                         nw_src, nw_dst, tp_src, tp_dst
    wildcards = {'buf': b'\xd2\x71\x25\x23', 'val': 3530630435}
    in_port = {'buf': b'\x37\x8b', 'val': 14219}
    dl_src = b'\xdf\xcf\xe1\x5d\xcf\xc0'
    dl_dst = b'\x76\xb3\xfb\xc6\x21\x2f'
    dl_vlan = {'buf': b'\xc1\xf9', 'val': 49657}
    dl_vlan_pcp = {'buf': b'\x79', 'val': 121}
    zfill0 = b'\x00'
    dl_type = {'buf': b'\xa6\x9e', 'val': 42654}
    nw_tos = {'buf': b'\xde', 'val': 222}
    nw_proto = {'buf': b'\xe5', 'val': 229}
    zfil11 = b'\x00' * 2
    nw_src = {'buf': b'\x1b\x6d\x8d\x4b', 'val': 460164427}
    nw_dst = {'buf': b'\xab\x25\xe1\x20', 'val': 2871386400}
    tp_src = {'buf': b'\xd5\xc3', 'val': 54723}
    tp_dst = {'buf': b'\x78\xb9', 'val': 30905}

    match = OFPMatch(wildcards['val'],
                     in_port['val'],
                     dl_src,
                     dl_dst,
                     dl_vlan['val'],
                     dl_vlan_pcp['val'],
                     dl_type['val'],
                     nw_tos['val'],
                     nw_proto['val'],
                     nw_src['val'],
                     nw_dst['val'],
                     tp_src['val'],
                     tp_dst['val'])

    port = 0x2ae0
    actions = [OFPActionOutput(port, max_len=1000)]

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _get_obj(self, actions=None):
        class Datapath(object):
            ofproto = ofproto  # copy to class attribute
            ofproto_parser = ofproto_v1_0_parser

        c = OFPFlowMod(Datapath,
                       self.match,
                       self.cookie['val'],
                       self.command['val'],
                       self.idle_timeout['val'],
                       self.hard_timeout['val'],
                       self.priority['val'],
                       self.buffer_id['val'],
                       self.out_port['val'],
                       self.flags['val'],
                       actions)

        return c

    def test_init(self):
        c = self._get_obj()

        eq_(self.cookie['val'], c.cookie)
        eq_(self.command['val'], c.command)
        eq_(self.idle_timeout['val'], c.idle_timeout)
        eq_(self.hard_timeout['val'], c.hard_timeout)
        eq_(self.priority['val'], c.priority)
        eq_(self.buffer_id['val'], c.buffer_id)
        eq_(self.out_port['val'], c.out_port)
        eq_(self.flags['val'], c.flags)

    def test_init_actions(self):
        c = self._get_obj(self.actions)
        action = c.actions[0]

        eq_(self.port, action.port)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        c = self._get_obj(self.actions)
        c.serialize()

        eq_(ofproto.OFP_VERSION, c.version)
        eq_(ofproto.OFPT_FLOW_MOD, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_MATCH_PACK_STR.replace('!', '') \
            + ofproto.OFP_FLOW_MOD_PACK_STR0.replace('!', '') \
            + ofproto.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_FLOW_MOD, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])

        # OFP_MATCH_PACK_STR
        eq_(self.wildcards['val'], res[4])
        eq_(self.in_port['val'], res[5])
        eq_(self.dl_src, res[6])
        eq_(self.dl_dst, res[7])
        eq_(self.dl_vlan['val'], res[8])
        eq_(self.dl_vlan_pcp['val'], res[9])
        eq_(self.dl_type['val'], res[10])
        eq_(self.nw_tos['val'], res[11])
        eq_(self.nw_proto['val'], res[12])
        eq_(self.nw_src['val'], res[13])
        eq_(self.nw_dst['val'], res[14])
        eq_(self.tp_src['val'], res[15])
        eq_(self.tp_dst['val'], res[16])

        # OFP_FLOW_MOD_PACK_STR0
        eq_(self.cookie['val'], res[17])
        eq_(self.command['val'], res[18])
        eq_(self.idle_timeout['val'], res[19])
        eq_(self.hard_timeout['val'], res[20])
        eq_(self.priority['val'], res[21])
        eq_(self.buffer_id['val'], res[22])
        eq_(self.out_port['val'], res[23])
        eq_(self.flags['val'], res[24])

        # OFP_ACTION_OUTPUT_PACK_STR
        eq_(ofproto.OFPAT_OUTPUT, res[25])
        eq_(ofproto.OFP_ACTION_OUTPUT_SIZE, res[26])
        eq_(self.port, res[27])
        eq_(1000, res[28])


class TestOFPBarrierRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPBarrierRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    c = OFPBarrierRequest(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_BARRIER_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = ofproto.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, six.binary_type(self.c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_BARRIER_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])


class TestOFPQueueGetConfigRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPQueueGetConfigRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    # OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR
    # '!H2x'...port, zfill
    port = {'buf': b'\xa0\xe2', 'val': 41186}
    zfill = b'\x00' * 2

    c = OFPQueueGetConfigRequest(Datapath,
                                 port['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port['val'], self.c.port)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_QUEUE_GET_CONFIG_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        a = ofproto.OFP_HEADER_PACK_STR.replace('!', '')
        b = ofproto.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR.replace('!', '')
        fmt = '!' + a + b

        res = struct.unpack(fmt, six.binary_type(self.c.buf))
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_QUEUE_GET_CONFIG_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(self.port['val'], res[4])


class TestOFPDescStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPDescStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    flags = {'buf': b'\x00\x00', 'val': 0}

    c = OFPDescStatsRequest(Datapath, flags['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(ofproto.OFPST_DESC, self.c.type)
        eq_(self.flags['val'], self.c.flags)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_STATS_MSG_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_STATS_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])

        # OFP_STATS_MSG_PACK_STR
        eq_(ofproto.OFPST_DESC, res[4])
        eq_(self.flags['val'], res[5])


class TestOFPFlowStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPFlowStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    flags = {'buf': b'\x00\x00', 'val': 0}

    # OFP_MATCH_PACK_STR
    # '!IH6s6sHBxHBB2xIIHH'...wildcards, in_port, dl_src, dl_dst, dl_vlan,
    #                         dl_vlan_pcp, dl_type, nw_tos, nw_proto,
    #                         nw_src, nw_dst, tp_src, tp_dst
    wildcards = {'buf': b'\xd2\x71\x25\x23', 'val': 3530630435}
    in_port = {'buf': b'\x37\x8b', 'val': 14219}
    dl_src = b'\x58\xd0\x8a\x69\xa4\xfc'
    dl_dst = b'\xb6\xe2\xef\xb1\xa6\x2d'
    dl_vlan = {'buf': b'\xc1\xf9', 'val': 49657}
    dl_vlan_pcp = {'buf': b'\x79', 'val': 121}
    zfill0 = b'\x00'
    dl_type = {'buf': b'\xa6\x9e', 'val': 42654}
    nw_tos = {'buf': b'\xde', 'val': 222}
    nw_proto = {'buf': b'\xe5', 'val': 229}
    zfil11 = b'\x00' * 2
    nw_src = {'buf': b'\x1b\x6d\x8d\x4b', 'val': 460164427}
    nw_dst = {'buf': b'\xab\x25\xe1\x20', 'val': 2871386400}
    tp_src = {'buf': b'\xd5\xc3', 'val': 54723}
    tp_dst = {'buf': b'\x78\xb9', 'val': 30905}

    match = OFPMatch(wildcards['val'],
                     in_port['val'],
                     dl_src,
                     dl_dst,
                     dl_vlan['val'],
                     dl_vlan_pcp['val'],
                     dl_type['val'],
                     nw_tos['val'],
                     nw_proto['val'],
                     nw_src['val'],
                     nw_dst['val'],
                     tp_src['val'],
                     tp_dst['val'])

    # OFP_FLOW_STATS_REQUEST_ID_PORT_STR
    # '!BxH'...table_id, zfill, out_port
    table_id = {'buf': b'\xd1', 'val': 209}
    zfill = b'\x00' * 1
    out_port = {'buf': b'\xe4\x9a', 'val': 58522}

    c = OFPFlowStatsRequest(Datapath,
                            flags['val'],
                            match,
                            table_id['val'],
                            out_port['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(ofproto.OFPST_FLOW, self.c.type)
        eq_(self.flags['val'], self.c.flags)
        eq_(self.table_id['val'], self.c.table_id)
        eq_(self.out_port['val'], self.c.out_port)

        # match
        match = self.c.match
        eq_(self.match.__hash__(), match.__hash__())

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_STATS_MSG_PACK_STR.replace('!', '') \
            + ofproto.OFP_MATCH_PACK_STR.replace('!', '') \
            + ofproto.OFP_FLOW_STATS_REQUEST_ID_PORT_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_STATS_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])

        # OFP_STATS_MSG_PACK_STR
        eq_(ofproto.OFPST_FLOW, res[4])
        eq_(self.flags['val'], res[5])

        # OFP_MATCH_PACK_STR
        eq_(self.wildcards['val'], res[6])
        eq_(self.in_port['val'], res[7])
        eq_(self.dl_src, res[8])
        eq_(self.dl_dst, res[9])
        eq_(self.dl_vlan['val'], res[10])
        eq_(self.dl_vlan_pcp['val'], res[11])
        eq_(self.dl_type['val'], res[12])
        eq_(self.nw_tos['val'], res[13])
        eq_(self.nw_proto['val'], res[14])
        eq_(self.nw_src['val'], res[15])
        eq_(self.nw_dst['val'], res[16])
        eq_(self.tp_src['val'], res[17])
        eq_(self.tp_dst['val'], res[18])

        # OFP_FLOW_STATS_REQUEST_ID_PORT_STR
        eq_(self.table_id['val'], res[19])
        eq_(self.out_port['val'], res[20])


class TestOFPAggregateStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPAggregateStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    flags = {'buf': b'\x00\x00', 'val': 0}

    # OFP_MATCH_PACK_STR
    # '!IH6s6sHBxHBB2xIIHH'...wildcards, in_port, dl_src, dl_dst, dl_vlan,
    #                         dl_vlan_pcp, dl_type, nw_tos, nw_proto,
    #                         nw_src, nw_dst, tp_src, tp_dst
    wildcards = {'buf': b'\xea\x66\x4a\xd4', 'val': 3932572372}
    in_port = {'buf': b'\x64\xac', 'val': 25772}
    dl_src = b'\x90\x13\x60\x5e\x20\x4d'
    dl_dst = b'\xb5\x5d\x14\x5e\xb9\x22'
    dl_vlan = {'buf': b'\x8b\xeb', 'val': 35819}
    dl_vlan_pcp = {'buf': b'\xe8', 'val': 232}
    zfill0 = b'\x00'
    dl_type = {'buf': b'\62\xc9', 'val': 25289}
    nw_tos = {'buf': b'\xb5', 'val': 181}
    nw_proto = {'buf': b'\xc4', 'val': 196}
    zfil11 = b'\x00' * 2
    nw_src = {'buf': b'\xb7\xd1\xb7\xef', 'val': 3083974639}
    nw_dst = {'buf': b'\x7c\xc6\x18\x15', 'val': 2093357077}
    tp_src = {'buf': b'\x26\x9a', 'val': 9882}
    tp_dst = {'buf': b'\x7a\x89', 'val': 31369}

    match = OFPMatch(wildcards['val'],
                     in_port['val'],
                     dl_src,
                     dl_dst,
                     dl_vlan['val'],
                     dl_vlan_pcp['val'],
                     dl_type['val'],
                     nw_tos['val'],
                     nw_proto['val'],
                     nw_src['val'],
                     nw_dst['val'],
                     tp_src['val'],
                     tp_dst['val'])

    # OFP_FLOW_STATS_REQUEST_ID_PORT_STR
    # '!BxH'...table_id, zfill, out_port
    table_id = {'buf': b'\xd1', 'val': 209}
    zfill = b'\x00' * 1
    out_port = {'buf': b'\xb5\xe8', 'val': 46568}

    c = OFPAggregateStatsRequest(Datapath,
                                 flags['val'],
                                 match,
                                 table_id['val'],
                                 out_port['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(ofproto.OFPST_AGGREGATE, self.c.type)
        eq_(self.flags['val'], self.c.flags)
        eq_(self.table_id['val'], self.c.table_id)
        eq_(self.out_port['val'], self.c.out_port)

        # match
        match = self.c.match
        eq_(self.match.__hash__(), match.__hash__())

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_STATS_MSG_PACK_STR.replace('!', '') \
            + ofproto.OFP_MATCH_PACK_STR.replace('!', '') \
            + ofproto.OFP_FLOW_STATS_REQUEST_ID_PORT_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_STATS_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])

        # OFP_STATS_MSG_PACK_STR
        eq_(ofproto.OFPST_AGGREGATE, res[4])
        eq_(self.flags['val'], res[5])

        # OFP_MATCH_PACK_STR
        eq_(self.wildcards['val'], res[6])
        eq_(self.in_port['val'], res[7])
        eq_(self.dl_src, res[8])
        eq_(self.dl_dst, res[9])
        eq_(self.dl_vlan['val'], res[10])
        eq_(self.dl_vlan_pcp['val'], res[11])
        eq_(self.dl_type['val'], res[12])
        eq_(self.nw_tos['val'], res[13])
        eq_(self.nw_proto['val'], res[14])
        eq_(self.nw_src['val'], res[15])
        eq_(self.nw_dst['val'], res[16])
        eq_(self.tp_src['val'], res[17])
        eq_(self.tp_dst['val'], res[18])

        # OFP_FLOW_STATS_REQUEST_ID_PORT_STR
        eq_(self.table_id['val'], res[19])
        eq_(self.out_port['val'], res[20])


class TestOFPTableStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPTableStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    flags = {'buf': b'\x00\x00', 'val': 0}

    c = OFPTableStatsRequest(Datapath, flags['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(ofproto.OFPST_TABLE, self.c.type)
        eq_(self.flags['val'], self.c.flags)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_STATS_MSG_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_STATS_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])

        # OFP_STATS_MSG_PACK_STR
        eq_(ofproto.OFPST_TABLE, res[4])
        eq_(self.flags['val'], res[5])


class TestOFPPortStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPPortStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    flags = {'buf': b'\x00\x00', 'val': 0}

    # OFP_PORT_STATS_REQUEST_PACK_STR
    # '!H6x'...port_no, zfill
    port_no = {'buf': b'\x6d\x27', 'val': 27943}

    c = OFPPortStatsRequest(Datapath,
                            flags['val'],
                            port_no['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(ofproto.OFPST_PORT, self.c.type)
        eq_(self.flags['val'], self.c.flags)
        eq_(self.port_no['val'], self.c.port_no)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_STATS_MSG_PACK_STR.replace('!', '') \
            + ofproto.OFP_PORT_STATS_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_STATS_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])

        # OFP_STATS_MSG_PACK_STR
        eq_(ofproto.OFPST_PORT, res[4])
        eq_(self.flags['val'], res[5])

        # OFP_PORT_STATS_REQUEST_PACK_STR
        eq_(self.port_no['val'], res[6])


class TestOFPQueueStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPQueueStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    flags = {'buf': b'\x00\x00', 'val': 0}

    # OFP_QUEUE_STATS_REQUEST_PACK_STR
    # '!HxxI'...port_no, zfill, zfill, queue_id
    port_no = {'buf': b'\x0c\x2d', 'val': 3117}
    queue_id = {'buf': b'\x1b\xe6\xba\x36', 'val': 468105782}

    c = OFPQueueStatsRequest(Datapath,
                             flags['val'],
                             port_no['val'],
                             queue_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(ofproto.OFPST_QUEUE, self.c.type)
        eq_(self.flags['val'], self.c.flags)
        eq_(self.port_no['val'], self.c.port_no)
        eq_(self.queue_id['val'], self.c.queue_id)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_STATS_MSG_PACK_STR.replace('!', '') \
            + ofproto.OFP_QUEUE_STATS_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_STATS_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])

        # OFP_STATS_MSG_PACK_STR
        eq_(ofproto.OFPST_QUEUE, res[4])
        eq_(self.flags['val'], res[5])

        # OFP_QUEUE_STATS_REQUEST_PACK_STR
        eq_(self.port_no['val'], res[6])
        eq_(self.queue_id['val'], res[7])


class TestOFPVendorStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_0_parser.OFPVendorStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto  # copy to class attribute
        ofproto_parser = ofproto_v1_0_parser

    flags = {'buf': b'\x00\x00', 'val': 0}

    # OFP_VENDOR_STATS_MSG_PACK_STR
    # '!I'...vendor
    vendor = {'buf': b'\xff\xff\xff\xff', 'val': ofproto.OFPAT_VENDOR}

    specific_data = b'specific_data'

    c = OFPVendorStatsRequest(Datapath,
                              flags['val'],
                              vendor['val'],
                              specific_data)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(ofproto.OFPST_VENDOR, self.c.type)
        eq_(self.flags['val'], self.c.flags)
        eq_(self.vendor['val'], self.c.vendor)
        eq_(self.specific_data, self.c.specific_data)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto.OFP_VERSION, self.c.version)
        eq_(ofproto.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto.OFP_STATS_MSG_PACK_STR.replace('!', '') \
            + ofproto.OFP_VENDOR_STATS_MSG_PACK_STR.replace('!', '') \
            + str(len(self.specific_data)) + 's'

        res = struct.unpack(fmt, six.binary_type(self.c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto.OFP_VERSION, res[0])
        eq_(ofproto.OFPT_STATS_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])

        # OFP_STATS_MSG_PACK_STR
        eq_(ofproto.OFPST_VENDOR, res[4])
        eq_(self.flags['val'], res[5])

        # OFP_VENDOR_STATS_MSG_PACK_STR
        eq_(self.vendor['val'], res[6])

        # specific_data
        eq_(self.specific_data, res[7])
