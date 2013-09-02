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
import socket
from struct import *
from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto.ofproto_v1_2_parser import *
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ether
from ryu.ofproto.ofproto_parser import MsgBase
from ryu import utils
from ryu.lib import addrconv

LOG = logging.getLogger('test_ofproto_v12')


class _Datapath(object):
    ofproto = ofproto_v1_2
    ofproto_parser = ofproto_v1_2_parser


class TestRegisterParser(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser._register_parser
    """

    class _OFPDummy(MsgBase):
        def __init__(self, datapath):
            self.dummy = 'dummy'

        def parser(self):
            return self.dummy

    def test_cls_msg_type(self):
        msg_type = 0xff
        cls = self._OFPDummy(_Datapath)
        cls.cls_msg_type = msg_type

        res = ofproto_v1_2_parser._register_parser(cls)
        res_parser = ofproto_v1_2_parser._MSG_PARSERS[msg_type]
        del ofproto_v1_2_parser._MSG_PARSERS[msg_type]

        eq_(res.cls_msg_type, msg_type)
        ok_(res.dummy)
        eq_(res_parser(), 'dummy')

    @raises(AssertionError)
    def test_cls_msg_type_none(self):
        cls = OFPHello(_Datapath)
        cls.cls_msg_type = None
        ofproto_v1_2_parser._register_parser(cls)

    @raises(AssertionError)
    def test_cls_msg_type_already_registed(self):
        cls = OFPHello(_Datapath)
        ofproto_v1_2_parser._register_parser(cls)


class TestMsgParser(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.msg_parser
    """

    def _test_msg_parser(self, xid, msg_len):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_HELLO

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version,  msg_type, msg_len, xid)

        c = msg_parser(_Datapath, version, msg_type, msg_len, xid, buf)

        eq_(version, c.version)
        eq_(msg_type, c.msg_type)
        eq_(msg_len, c.msg_len)
        eq_(xid, c.xid)

        # buf
        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        res = struct.unpack(fmt, c.buf)

        eq_(version, res[0])
        eq_(msg_type, res[1])
        eq_(msg_len, res[2])
        eq_(xid, res[3])

    def test_parser_mid(self):
        xid = 2147483648
        msg_len = 8
        self._test_msg_parser(xid, msg_len)

    def test_parser_max(self):
        xid = 4294967295
        msg_len = 65535
        self._test_msg_parser(xid, msg_len)

    def test_parser_min(self):
        xid = 0
        msg_len = 0
        self._test_msg_parser(xid, msg_len)


class TestOFPHello(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPHello
    """

    def _test_parser(self, xid):
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_HELLO
        msg_len = ofproto_v1_2.OFP_HEADER_SIZE

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        res = OFPHello.parser(object, version, msg_type, msg_len, xid,
                              bytearray(buf))

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(buffer(buf), res.buf)

    def test_parser_xid_min(self):
        xid = 0
        self._test_parser(xid)

    def test_parser_xid_mid(self):
        xid = 2183948390
        self._test_parser(xid)

    def test_parser_xid_max(self):
        xid = 4294967295
        self._test_parser(xid)

    def test_serialize(self):
        c = OFPHello(_Datapath)
        c.serialize()
        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_HELLO, c.msg_type)
        eq_(0, c.xid)


class TestOFPErrorMsg(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPErrorMsg
    """

    # OFP_HEADER_PACK_STR
    # '!BBHI'...version, msg_type, msg_len, xid
    version = ofproto_v1_2.OFP_VERSION
    msg_type = ofproto_v1_2.OFPT_ERROR
    msg_len = ofproto_v1_2.OFP_ERROR_MSG_SIZE
    xid = 2495926989

    fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
    buf = pack(fmt, version, msg_type, msg_len, xid)

    def test_init(self):
        c = OFPErrorMsg(_Datapath)
        eq_(c.code, None)
        eq_(c.type, None)
        eq_(c.data, None)

    def _test_parser(self, type_, code, data=None):

        # OFP_ERROR_MSG_PACK_STR = '!HH'
        fmt = ofproto_v1_2.OFP_ERROR_MSG_PACK_STR
        buf = self.buf + pack(fmt, type_, code)

        if data is not None:
            buf += data

        res = OFPErrorMsg.parser(object, self.version, self.msg_type,
                                 self.msg_len, self.xid, buf)

        eq_(res.version, self.version)
        eq_(res.msg_type, self.msg_type)
        eq_(res.msg_len, self.msg_len)
        eq_(res.xid, self.xid)
        eq_(res.type, type_)
        eq_(res.code, code)

        if data is not None:
            eq_(res.data, data)

    def test_parser_mid(self):
        type_ = 32768
        code = 32768
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_max(self):
        type_ = 65534
        code = 65535
        data = 'Error Message.'.ljust(65523)
        self._test_parser(type_, code, data)

    def test_parser_min(self):
        type_ = 0
        code = 0
        data = None
        self._test_parser(type_, code, data)

    def test_parser_p0_1(self):
        type_ = ofproto_v1_2.OFPET_HELLO_FAILED
        code = ofproto_v1_2.OFPHFC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_0(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_VERSION
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_1(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_2(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_STAT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_3(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_EXPERIMENTER
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_4(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_EXP_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_5(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_6(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_LEN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_7(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BUFFER_EMPTY
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_8(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BUFFER_UNKNOWN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_9(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_TABLE_ID
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_10(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_IS_SLAVE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_11(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_PORT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p1_12(self):
        type_ = ofproto_v1_2.OFPET_BAD_REQUEST
        code = ofproto_v1_2.OFPBRC_BAD_PACKET
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_0(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_1(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_LEN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_2(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_EXPERIMENTER
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_3(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_EXP_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_4(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_OUT_PORT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_5(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_ARGUMENT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_6(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_7(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_TOO_MANY
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_8(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_QUEUE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_9(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_OUT_GROUP
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_10(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_MATCH_INCONSISTENT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_11(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_UNSUPPORTED_ORDER
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_12(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_TAG
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_13(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_SET_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_14(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_SET_LEN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p2_15(self):
        type_ = ofproto_v1_2.OFPET_BAD_ACTION
        code = ofproto_v1_2.OFPBAC_BAD_SET_ARGUMENT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_0(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_UNKNOWN_INST
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_1(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_UNSUP_INST
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_2(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_BAD_TABLE_ID
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_3(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_UNSUP_METADATA
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_4(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_UNSUP_METADATA_MASK
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_5(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_BAD_EXPERIMENTER
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_6(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_BAD_EXP_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_7(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_BAD_LEN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p3_8(self):
        type_ = ofproto_v1_2.OFPET_BAD_INSTRUCTION
        code = ofproto_v1_2.OFPBIC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_0(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_1(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_LEN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_2(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_TAG
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_3(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_DL_ADDR_MASK
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_4(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_NW_ADDR_MASK
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_5(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_WILDCARDS
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_6(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_FIELD
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_7(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_VALUE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_8(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_MASK
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_9(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_BAD_PREREQ
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_10(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_DUP_FIELD
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p4_11(self):
        type_ = ofproto_v1_2.OFPET_BAD_MATCH
        code = ofproto_v1_2.OFPBMC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_0(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_UNKNOWN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_1(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_TABLE_FULL
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_2(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_BAD_TABLE_ID
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_3(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_OVERLAP
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_4(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_5(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_BAD_TIMEOUT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_6(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_BAD_COMMAND
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p5_7(self):
        type_ = ofproto_v1_2.OFPET_FLOW_MOD_FAILED
        code = ofproto_v1_2.OFPFMFC_BAD_FLAGS
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_0(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_GROUP_EXISTS
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_1(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_INVALID_GROUP
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_2(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_WEIGHT_UNSUPPORTED
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_3(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_OUT_OF_GROUPS
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_4(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_OUT_OF_BUCKETS
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_5(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_CHAINING_UNSUPPORTED
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_6(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_WATCH_UNSUPPORTED
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_7(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_LOOP
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_8(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_UNKNOWN_GROUP
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_9(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_CHAINED_GROUP
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_10(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_BAD_TYPE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_11(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_BAD_COMMAND
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_12(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_BAD_BUCKET
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_13(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_BAD_WATCH
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p6_14(self):
        type_ = ofproto_v1_2.OFPET_GROUP_MOD_FAILED
        code = ofproto_v1_2.OFPGMFC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p7_0(self):
        type_ = ofproto_v1_2.OFPET_PORT_MOD_FAILED
        code = ofproto_v1_2.OFPPMFC_BAD_PORT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p7_1(self):
        type_ = ofproto_v1_2.OFPET_PORT_MOD_FAILED
        code = ofproto_v1_2.OFPPMFC_BAD_HW_ADDR
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p7_2(self):
        type_ = ofproto_v1_2.OFPET_PORT_MOD_FAILED
        code = ofproto_v1_2.OFPPMFC_BAD_CONFIG
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p7_3(self):
        type_ = ofproto_v1_2.OFPET_PORT_MOD_FAILED
        code = ofproto_v1_2.OFPPMFC_BAD_ADVERTISE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p7_4(self):
        type_ = ofproto_v1_2.OFPET_PORT_MOD_FAILED
        code = ofproto_v1_2.OFPPMFC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p8_0(self):
        type_ = ofproto_v1_2.OFPET_TABLE_MOD_FAILED
        code = ofproto_v1_2.OFPTMFC_BAD_TABLE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p8_1(self):
        type_ = ofproto_v1_2.OFPET_TABLE_MOD_FAILED
        code = ofproto_v1_2.OFPTMFC_BAD_CONFIG
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p8_2(self):
        type_ = ofproto_v1_2.OFPET_TABLE_MOD_FAILED
        code = ofproto_v1_2.OFPTMFC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p9_0(self):
        type_ = ofproto_v1_2.OFPET_QUEUE_OP_FAILED
        code = ofproto_v1_2.OFPQOFC_BAD_PORT
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p9_1(self):
        type_ = ofproto_v1_2.OFPET_QUEUE_OP_FAILED
        code = ofproto_v1_2.OFPQOFC_BAD_QUEUE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p9_2(self):
        type_ = ofproto_v1_2.OFPET_QUEUE_OP_FAILED
        code = ofproto_v1_2.OFPQOFC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p10_0(self):
        type_ = ofproto_v1_2.OFPET_SWITCH_CONFIG_FAILED
        code = ofproto_v1_2.OFPSCFC_BAD_FLAGS
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p10_1(self):
        type_ = ofproto_v1_2.OFPET_SWITCH_CONFIG_FAILED
        code = ofproto_v1_2.OFPSCFC_BAD_LEN
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p10_2(self):
        type_ = ofproto_v1_2.OFPET_SWITCH_CONFIG_FAILED
        code = ofproto_v1_2.OFPQCFC_EPERM
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p11_0(self):
        type_ = ofproto_v1_2.OFPET_ROLE_REQUEST_FAILED
        code = ofproto_v1_2.OFPRRFC_STALE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p11_1(self):
        type_ = ofproto_v1_2.OFPET_ROLE_REQUEST_FAILED
        code = ofproto_v1_2.OFPRRFC_UNSUP
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_p11_2(self):
        type_ = ofproto_v1_2.OFPET_ROLE_REQUEST_FAILED
        code = ofproto_v1_2.OFPRRFC_BAD_ROLE
        data = 'Error Message.'
        self._test_parser(type_, code, data)

    def test_parser_experimenter(self):
        type_ = 0xffff
        exp_type = 1
        experimenter = 1
        data = 'Error Experimenter Message.'

        # OFP_ERROR_EXPERIMENTER_MSG_PACK_STR = '!HHI'
        fmt = ofproto_v1_2.OFP_ERROR_EXPERIMENTER_MSG_PACK_STR
        buf = self.buf + pack(fmt, type_, exp_type, experimenter) \
            + data

        res = OFPErrorMsg.parser(object, self.version, self.msg_type,
                                 self.msg_len, self.xid, buf)

        eq_(res.version, self.version)
        eq_(res.msg_type, self.msg_type)
        eq_(res.msg_len, self.msg_len)
        eq_(res.xid, self.xid)
        eq_(res.type, type_)
        eq_(res.exp_type, exp_type)
        eq_(res.experimenter, experimenter)
        eq_(res.data, data)

    def _test_serialize(self, type_, code, data):
        # OFP_ERROR_MSG_PACK_STR = '!HH'
        fmt = ofproto_v1_2.OFP_ERROR_MSG_PACK_STR
        buf = self.buf + pack(fmt, type_, code) + data

        # initialization
        c = OFPErrorMsg(_Datapath)
        c.type = type_
        c.code = code
        c.data = data

        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_ERROR, c.msg_type)
        eq_(0, c.xid)
        eq_(len(buf), c.msg_len)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ERROR_MSG_PACK_STR.replace('!', '') \
            + str(len(c.data)) + 's'

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_ERROR)
        eq_(res[2], len(buf))
        eq_(res[3], 0)
        eq_(res[4], type_)
        eq_(res[5], code)
        eq_(res[6], data)

    def test_serialize_mid(self):
        type_ = 32768
        code = 32768
        data = 'Error Message.'
        self._test_serialize(type_, code, data)

    def test_serialize_max(self):
        type_ = 65535
        code = 65535
        data = 'Error Message.'.ljust(65523)
        self._test_serialize(type_, code, data)

    def test_serialize_min_except_data(self):
        type_ = ofproto_v1_2.OFPET_HELLO_FAILED
        code = ofproto_v1_2.OFPHFC_INCOMPATIBLE
        data = 'Error Message.'
        self._test_serialize(type_, code, data)

    @raises(AssertionError)
    def test_serialize_check_data(self):
        c = OFPErrorMsg(_Datapath)
        c.serialize()

    def _test_serialize_p(self, type_, code):
        self._test_serialize(type_, code, 'Error Message.')

    def test_serialize_p0_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_HELLO_FAILED,
                               ofproto_v1_2.OFPHFC_EPERM)

    def test_serialize_p1_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_VERSION)

    def test_serialize_p1_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_TYPE)

    def test_serialize_p1_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_STAT)

    def test_serialize_p1_3(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_EXPERIMENTER)

    def test_serialize_p1_4(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_EXP_TYPE)

    def test_serialize_p1_5(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_EPERM)

    def test_serialize_p1_6(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_LEN)

    def test_serialize_p1_7(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BUFFER_EMPTY)

    def test_serialize_p1_8(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BUFFER_UNKNOWN)

    def test_serialize_p1_9(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_TABLE_ID)

    def test_serialize_p1_10(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_IS_SLAVE)

    def test_serialize_p1_11(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_PORT)

    def test_serialize_p1_12(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_REQUEST,
                               ofproto_v1_2.OFPBRC_BAD_PACKET)

    def test_serialize_p2_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_TYPE)

    def test_serialize_p2_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_LEN)

    def test_serialize_p2_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_EXPERIMENTER)

    def test_serialize_p2_3(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_EXP_TYPE)

    def test_serialize_p2_4(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_OUT_PORT)

    def test_serialize_p2_5(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_ARGUMENT)

    def test_serialize_p2_6(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_EPERM)

    def test_serialize_p2_7(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_TOO_MANY)

    def test_serialize_p2_8(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_QUEUE)

    def test_serialize_p2_9(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_OUT_GROUP)

    def test_serialize_p2_10(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_MATCH_INCONSISTENT)

    def test_serialize_p2_11(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_UNSUPPORTED_ORDER)

    def test_serialize_p2_12(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_TAG)

    def test_serialize_p2_13(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_SET_TYPE)

    def test_serialize_p2_14(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_SET_LEN)

    def test_serialize_p2_15(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_ACTION,
                               ofproto_v1_2.OFPBAC_BAD_SET_ARGUMENT)

    def test_serialize_p3_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_UNKNOWN_INST)

    def test_serialize_p3_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_UNSUP_INST)

    def test_serialize_p3_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_BAD_TABLE_ID)

    def test_serialize_p3_3(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_UNSUP_METADATA)

    def test_serialize_p3_4(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_UNSUP_METADATA_MASK)

    def test_serialize_p3_5(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_BAD_EXPERIMENTER)

    def test_serialize_p3_6(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_BAD_EXP_TYPE)

    def test_serialize_p3_7(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_BAD_LEN)

    def test_serialize_p3_8(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_INSTRUCTION,
                               ofproto_v1_2.OFPBIC_EPERM)

    def test_serialize_p4_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_TYPE)

    def test_serialize_p4_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_LEN)

    def test_serialize_p4_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_TAG)

    def test_serialize_p4_3(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_DL_ADDR_MASK)

    def test_serialize_p4_4(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_NW_ADDR_MASK)

    def test_serialize_p4_5(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_WILDCARDS)

    def test_serialize_p4_6(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_FIELD)

    def test_serialize_p4_7(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_VALUE)

    def test_serialize_p4_8(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_MASK)

    def test_serialize_p4_9(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_BAD_PREREQ)

    def test_serialize_p4_10(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_DUP_FIELD)

    def test_serialize_p4_11(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_BAD_MATCH,
                               ofproto_v1_2.OFPBMC_EPERM)

    def test_serialize_p5_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_UNKNOWN)

    def test_serialize_p5_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_TABLE_FULL)

    def test_serialize_p5_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_BAD_TABLE_ID)

    def test_serialize_p5_3(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_OVERLAP)

    def test_serialize_p5_4(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_EPERM)

    def test_serialize_p5_5(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_BAD_TIMEOUT)

    def test_serialize_p5_6(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_BAD_COMMAND)

    def test_serialize_p5_7(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_FLOW_MOD_FAILED,
                               ofproto_v1_2.OFPFMFC_BAD_FLAGS)

    def test_serialize_p6_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_GROUP_EXISTS)

    def test_serialize_p6_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_INVALID_GROUP)

    def test_serialize_p6_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_WEIGHT_UNSUPPORTED)

    def test_serialize_p6_3(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_OUT_OF_GROUPS)

    def test_serialize_p6_4(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_OUT_OF_BUCKETS)

    def test_serialize_p6_5(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_CHAINING_UNSUPPORTED)

    def test_serialize_p6_6(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_WATCH_UNSUPPORTED)

    def test_serialize_p6_7(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_LOOP)

    def test_serialize_p6_8(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_UNKNOWN_GROUP)

    def test_serialize_p6_9(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_CHAINED_GROUP)

    def test_serialize_p6_10(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_BAD_TYPE)

    def test_serialize_p6_11(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_BAD_COMMAND)

    def test_serialize_p6_12(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_BAD_BUCKET)

    def test_serialize_p6_13(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_BAD_WATCH)

    def test_serialize_p6_14(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_GROUP_MOD_FAILED,
                               ofproto_v1_2.OFPGMFC_EPERM)

    def test_serialize_p7_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_PORT_MOD_FAILED,
                               ofproto_v1_2.OFPPMFC_BAD_PORT)

    def test_serialize_p7_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_PORT_MOD_FAILED,
                               ofproto_v1_2.OFPPMFC_BAD_HW_ADDR)

    def test_serialize_p7_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_PORT_MOD_FAILED,
                               ofproto_v1_2.OFPPMFC_BAD_CONFIG)

    def test_serialize_p7_3(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_PORT_MOD_FAILED,
                               ofproto_v1_2.OFPPMFC_BAD_ADVERTISE)

    def test_serialize_p7_4(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_PORT_MOD_FAILED,
                               ofproto_v1_2.OFPPMFC_EPERM)

    def test_serialize_p8_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_TABLE_MOD_FAILED,
                               ofproto_v1_2.OFPTMFC_BAD_TABLE)

    def test_serialize_p8_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_TABLE_MOD_FAILED,
                               ofproto_v1_2.OFPTMFC_BAD_CONFIG)

    def test_serialize_p8_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_TABLE_MOD_FAILED,
                               ofproto_v1_2.OFPTMFC_EPERM)

    def test_serialize_p9_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_QUEUE_OP_FAILED,
                               ofproto_v1_2.OFPQOFC_BAD_PORT)

    def test_serialize_p9_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_QUEUE_OP_FAILED,
                               ofproto_v1_2.OFPQOFC_BAD_QUEUE)

    def test_serialize_p9_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_QUEUE_OP_FAILED,
                               ofproto_v1_2.OFPQOFC_EPERM)

    def test_serialize_p10_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_SWITCH_CONFIG_FAILED,
                               ofproto_v1_2.OFPSCFC_BAD_FLAGS)

    def test_serialize_p10_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_SWITCH_CONFIG_FAILED,
                               ofproto_v1_2.OFPSCFC_BAD_LEN)

    def test_serialize_p10_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_SWITCH_CONFIG_FAILED,
                               ofproto_v1_2.OFPQCFC_EPERM)

    def test_serialize_p11_0(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_ROLE_REQUEST_FAILED,
                               ofproto_v1_2.OFPRRFC_STALE)

    def test_serialize_p11_1(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_ROLE_REQUEST_FAILED,
                               ofproto_v1_2.OFPRRFC_UNSUP)

    def test_serialize_p11_2(self):
        self._test_serialize_p(ofproto_v1_2.OFPET_ROLE_REQUEST_FAILED,
                               ofproto_v1_2.OFPRRFC_BAD_ROLE)


class TestOFPErrorExperimenterMsg(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPErrorExperimenterMsg
    """

    def test_init(self):
        c = OFPErrorExperimenterMsg(_Datapath)
        eq_(c.type, 65535)
        eq_(c.exp_type, None)
        eq_(c.experimenter, None)
        eq_(c.data, None)

    def _test_parser(self, exp_type, experimenter, data=None):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_ERROR
        msg_len = ofproto_v1_2.OFP_ERROR_MSG_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_ERROR_EXPERIMENTER_MSG_PACK_STR = '!HHI'
        type_ = 0xffff
        fmt = ofproto_v1_2.OFP_ERROR_EXPERIMENTER_MSG_PACK_STR
        buf += pack(fmt, type_, exp_type, experimenter)

        if data is not None:
            buf += data

        res = OFPErrorExperimenterMsg.parser(
            object, version, msg_type, msg_len, xid, buf)

        eq_(res.version, version)
        eq_(res.msg_type, msg_type)
        eq_(res.msg_len, msg_len)
        eq_(res.xid, xid)
        eq_(res.type, type_)
        eq_(res.exp_type, exp_type)
        eq_(res.experimenter, experimenter)

        if data is not None:
            eq_(res.data, data)

    def test_parser_mid(self):
        exp_type = 32768
        experimenter = 2147483648
        data = 'Error Experimenter Message.'
        self._test_parser(exp_type, experimenter, data)

    def test_parser_max(self):
        exp_type = 65535
        experimenter = 4294967295
        data = 'Error Experimenter Message.'.ljust(65519)
        self._test_parser(exp_type, experimenter, data)

    def test_parser_min(self):
        exp_type = 0
        experimenter = 0
        self._test_parser(exp_type, experimenter)


class TestOFPEchoRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPEchoRequest
    """
    # OFP_HEADER_PACK_STR
    # '!BBHI'...version, msg_type, msg_len, xid
    version = ofproto_v1_2.OFP_VERSION
    msg_type = ofproto_v1_2.OFPT_ECHO_REQUEST
    msg_len = ofproto_v1_2.OFP_HEADER_SIZE
    xid = 2495926989

    def test_init(self):
        c = OFPEchoRequest(_Datapath)
        eq_(c.data, None)

    def _test_parser(self, data=None):
        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, self.version, self.msg_type,
                   self.msg_len, self.xid)

        if data is not None:
            buf += data

        res = OFPEchoRequest.parser(object, self.version, self.msg_type,
                                    self.msg_len, self.xid, buf)

        eq_(res.version, self.version)
        eq_(res.msg_type, self.msg_type)
        eq_(res.msg_len, self.msg_len)
        eq_(res.xid, self.xid)

        if data is not None:
            eq_(res.data, data)

    def test_parser_mid(self):
        data = 'Request Message.'
        self._test_parser(data)

    def test_parser_max(self):
        data = 'Request Message.'.ljust(65527)
        self._test_parser(data)

    def test_parser_min(self):
        data = None
        self._test_parser(data)

    def _test_serialize(self, data):
        c = OFPEchoRequest(_Datapath)
        c.data = data
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_ECHO_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR

        if data is not None:
            fmt += str(len(c.data)) + 's'

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_ECHO_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)

        if data is not None:
            eq_(res[4], data)

    def test_serialize_mid(self):
        data = 'Request Message.'
        self._test_serialize(data)

    def test_serialize_max(self):
        data = 'Request Message.'.ljust(65527)
        self._test_serialize(data)

    def test_serialize_min(self):
        data = None
        self._test_serialize(data)


class TestOFPEchoReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPEchoReply
    """

    # OFP_HEADER_PACK_STR
    # '!BBHI'...version, msg_type, msg_len, xid
    version = ofproto_v1_2.OFP_VERSION
    msg_type = ofproto_v1_2.OFPT_ECHO_REPLY
    msg_len = ofproto_v1_2.OFP_HEADER_SIZE
    xid = 2495926989

    def test_init(self):
        c = OFPEchoReply(_Datapath)
        eq_(c.data, None)

    def _test_parser(self, data):
        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, self.version, self.msg_type,
                   self.msg_len, self.xid)

        if data is not None:
            buf += data

        res = OFPEchoReply.parser(object, self.version, self.msg_type,
                                  self.msg_len, self.xid, buf)

        eq_(res.version, self.version)
        eq_(res.msg_type, self.msg_type)
        eq_(res.msg_len, self.msg_len)
        eq_(res.xid, self.xid)

        if data is not None:
            eq_(res.data, data)

    def test_parser_mid(self):
        data = 'Reply Message.'
        self._test_parser(data)

    def test_parser_max(self):
        data = 'Reply Message.'.ljust(65527)
        self._test_parser(data)

    def test_parser_min(self):
        data = None
        self._test_parser(data)

    def _test_serialize(self, data):
        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, self.version, self.msg_type,
                   self.msg_len, self.xid) + data

        c = OFPEchoReply(_Datapath)
        c.data = data
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_ECHO_REPLY, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + str(len(c.data)) + 's'

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_ECHO_REPLY)
        eq_(res[2], len(buf))
        eq_(res[3], 0)
        eq_(res[4], data)

    def test_serialize_mid(self):
        data = 'Reply Message.'
        self._test_serialize(data)

    def test_serialize_max(self):
        data = 'Reply Message.'.ljust(65527)
        self._test_serialize(data)

    @raises(AssertionError)
    def test_serialize_check_data(self):
        c = OFPEchoReply(_Datapath)
        c.serialize()


class TestOFPExperimenter(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPExperimenter
    """

    c = OFPExperimenter(_Datapath)

    def _test_parser(self, xid, experimenter, exp_type):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_EXPERIMENTER
        msg_len = ofproto_v1_2.OFP_EXPERIMENTER_HEADER_SIZE

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version,  msg_type, msg_len, xid)

        # OFP_EXPERIMENTER_HEADER_PACK_STR
        # '!II'...experimenter, exp_type
        fmt = ofproto_v1_2.OFP_EXPERIMENTER_HEADER_PACK_STR
        buf += pack(fmt, experimenter, exp_type)

        res = OFPExperimenter.parser(object, version, msg_type,
                                     msg_len, xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(experimenter, res.experimenter)
        eq_(exp_type, res.exp_type)

    def test_parser_mid(self):
        xid = 2495926989
        experimenter = 2147483648
        exp_type = 1
        self._test_parser(xid, experimenter, exp_type)

    def test_parser_max(self):
        xid = 4294967295
        experimenter = 4294967295
        exp_type = 65535
        self._test_parser(xid, experimenter, exp_type)

    def test_parser_min(self):
        xid = 0
        experimenter = 0
        exp_type = 0
        self._test_parser(xid, experimenter, exp_type)


class TestOFPPort(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPort
    """

    def test_init(self):
        # OFP_PORT_PACK_STR
        # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
        #                          name, config, state, curr, advertised,
        #                          peer, curr_speed, max_speed
        port_no = 1119692796
        hw_addr = 'c0:26:53:c4:29:e2'
        name = 'name'.ljust(16)
        config = 2226555987
        state = 1678244809
        curr = 2850556459
        advertised = 2025421682
        supported = 2120575149
        peer = 2757463021
        curr_speed = 2641353507
        max_speed = 1797291672

        fmt = ofproto_v1_2.OFP_PORT_PACK_STR
        buf = pack(fmt, port_no, hw_addr, name, config, state, curr,
                   advertised, supported, peer, curr_speed, max_speed)

        c = OFPPort(port_no, hw_addr, name, config, state, curr,
                    advertised, supported, peer, curr_speed, max_speed)

        eq_(port_no, c.port_no)
        eq_(hw_addr, c.hw_addr)
        eq_(name, c.name)
        eq_(config, c.config)
        eq_(state, c.state)
        eq_(curr, c.curr)
        eq_(advertised, c.advertised)
        eq_(supported, c.supported)
        eq_(peer, c.peer)
        eq_(curr_speed, c.curr_speed)
        eq_(max_speed, c.max_speed)

    def _test_parser(self, port_no, hw_addr, config, state, curr, advertised,
                     supported, peer, curr_speed, max_speed):
        name = 'name'.ljust(16)
        fmt = ofproto_v1_2.OFP_PORT_PACK_STR
        buf = pack(fmt, port_no, addrconv.mac.text_to_bin(hw_addr), name,
                   config, state, curr,
                   advertised, supported, peer, curr_speed, max_speed)

        res = OFPPort.parser(buf, 0)

        eq_(port_no, res.port_no)
        eq_(hw_addr, res.hw_addr)
        eq_(name, res.name)
        eq_(config, res.config)
        eq_(state, res.state)
        eq_(curr, res.curr)
        eq_(advertised, res.advertised)
        eq_(supported, res.supported)
        eq_(peer, res.peer)
        eq_(curr_speed, res.curr_speed)
        eq_(max_speed, res.max_speed)

    def test_parser_mid(self):
        port_no = 1119692796
        hw_addr = 'c0:26:53:c4:29:e2'
        config = 2226555987
        state = 1678244809
        curr = 2850556459
        advertised = 2025421682
        supported = 2120575149
        peer = 2757463021
        curr_speed = 2641353507
        max_speed = 1797291672
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_max(self):
        port_no = ofproto_v1_2.OFPP_ANY
        hw_addr = 'ff:ff:ff:ff:ff:ff'
        config = 4294967295
        state = 4294967295
        curr = 4294967295
        advertised = 4294967295
        supported = 4294967295
        peer = 4294967295
        curr_speed = 4294967295
        max_speed = 4294967295
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_min(self):
        port_no = 0
        hw_addr = '00:00:00:00:00:00'
        config = 0
        state = 0
        curr = 0
        advertised = 0
        supported = 0
        peer = 0
        curr_speed = 0
        max_speed = 0
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p1(self):
        port_no = ofproto_v1_2.OFPP_MAX
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_PORT_DOWN
        state = ofproto_v1_2.OFPPS_LINK_DOWN
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_10MB_HD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p2(self):
        port_no = ofproto_v1_2.OFPP_IN_PORT
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_RECV
        state = ofproto_v1_2.OFPPS_BLOCKED
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_10MB_FD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p3(self):
        port_no = ofproto_v1_2.OFPP_TABLE
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_FWD
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_100MB_HD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p4(self):
        port_no = ofproto_v1_2.OFPP_NORMAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_100MB_FD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p5(self):
        port_no = ofproto_v1_2.OFPP_FLOOD
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_1GB_HD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p6(self):
        port_no = ofproto_v1_2.OFPP_ALL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_1GB_FD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p7(self):
        port_no = ofproto_v1_2.OFPP_CONTROLLER
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_10GB_FD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p8(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_40GB_FD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p9(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_100GB_FD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p10(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_1TB_FD
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p11(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_OTHER
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p12(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_COPPER
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p13(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_FIBER
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p14(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_AUTONEG
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p15(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_PAUSE
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p16(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = 'c0:26:53:c4:29:e2'
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        state = ofproto_v1_2.OFPPS_LIVE
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_PAUSE_ASYM
        self._test_parser(port_no, hw_addr, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)


class TestOFPFeaturesRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFeaturesRequest
    """

    def test_serialize(self):
        c = OFPFeaturesRequest(_Datapath)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_FEATURES_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_FEATURES_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)


class TestOFPSwitchFeatures(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPSwitchFeatures
    """

    def _test_parser(self, xid, datapath_id, n_buffers,
                     n_tables, capabilities, reserved, port_cnt=0):

        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_FEATURES_REPLY
        msg_len = ofproto_v1_2.OFP_SWITCH_FEATURES_SIZE \
            + ofproto_v1_2.OFP_PORT_SIZE * port_cnt

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_SWITCH_FEATURES_PACK_STR
        # '!QIB3xII'...datapath_id, n_buffers, n_tables,
        #              pad(3), capabilities, reserved

        fmt = ofproto_v1_2.OFP_SWITCH_FEATURES_PACK_STR
        buf += pack(fmt, datapath_id, n_buffers, n_tables,
                    capabilities, reserved)

        for i in range(port_cnt):
            # OFP_PORT_PACK_STR
            # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
            #                          name, config, state, curr, advertised,
            #                          peer, curr_speed, max_speed
            port_no = i

            fmt = ofproto_v1_2.OFP_PORT_PACK_STR
            buf += pack(fmt, port_no, '\x00' * 6, '\x00' * 16, 0, 0, 0,
                        0, 0, 0, 0, 0)

        res = OFPSwitchFeatures.parser(object, version, msg_type,
                                       msg_len, xid, buf)

        eq_(res.version, version)
        eq_(res.msg_type, msg_type)
        eq_(res.msg_len, msg_len)
        eq_(res.xid, xid)

        eq_(res.datapath_id, datapath_id)
        eq_(res.n_buffers, n_buffers)
        eq_(res.n_tables, n_tables)
        eq_(res.capabilities, capabilities)
        eq_(res._reserved, reserved)

        for i in range(port_cnt):
            eq_(res.ports[i].port_no, i)

    def test_parser_mid(self):
        xid = 2495926989
        datapath_id = 1270985291017894273
        n_buffers = 2148849654
        n_tables = 228
        capabilities = 1766843586
        reserved = 2013714700
        port_cnt = 1

        self._test_parser(xid, datapath_id, n_buffers, n_tables,
                          capabilities, reserved, port_cnt)

    def test_parser_max(self):
        xid = 4294967295
        datapath_id = 18446744073709551615
        n_buffers = 4294967295
        n_tables = 255
        capabilities = 4294967295
        reserved = 4294967295
        port_cnt = 1023

        self._test_parser(xid, datapath_id, n_buffers, n_tables,
                          capabilities, reserved, port_cnt)

    def test_parser_min(self):
        xid = 0
        datapath_id = 0
        n_buffers = 0
        n_tables = 0
        capabilities = 0
        reserved = 0
        port_cnt = 0

        self._test_parser(xid, datapath_id, n_buffers, n_tables,
                          capabilities, reserved, port_cnt)


class TestOFPGetConfigRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGetConfigRequest
    """

    def test_serialize(self):
        c = OFPGetConfigRequest(_Datapath)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_GET_CONFIG_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, str(c.buf))
        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_GET_CONFIG_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)


class TestOFPGetConfigReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGetConfigReply
    """

    def _test_parser(self, xid, flags, miss_send_len):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_GET_CONFIG_REPLY
        msg_len = ofproto_v1_2.OFP_SWITCH_CONFIG_SIZE

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_SWITCH_CONFIG_PACK_STR
        # '!HH'...flags, miss_send_len
        fmt = ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR
        buf += pack(fmt, flags, miss_send_len)

        res = OFPGetConfigReply.parser(object, version, msg_type,
                                       msg_len, xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(flags, res.flags)
        eq_(miss_send_len, res.miss_send_len)

    def test_parser_mid(self):
        xid = 3423224276
        flags = 41186
        miss_send_len = 13838
        self._test_parser(xid, flags, miss_send_len)

    def test_parser_max(self):
        xid = 4294967295
        flags = 65535
        miss_send_len = 65535
        self._test_parser(xid, flags, miss_send_len)

    def test_parser_min(self):
        xid = 0
        flags = ofproto_v1_2.OFPC_FRAG_NORMAL
        miss_send_len = 0
        self._test_parser(xid, flags, miss_send_len)

    def test_parser_p1(self):
        xid = 3423224276
        flags = ofproto_v1_2.OFPC_FRAG_DROP
        miss_send_len = 13838
        self._test_parser(xid, flags, miss_send_len)

    def test_parser_p2(self):
        xid = 3423224276
        flags = ofproto_v1_2.OFPC_FRAG_REASM
        miss_send_len = 13838
        self._test_parser(xid, flags, miss_send_len)

    def test_parser_p3(self):
        xid = 3423224276
        flags = ofproto_v1_2.OFPC_FRAG_MASK
        miss_send_len = 13838
        self._test_parser(xid, flags, miss_send_len)

    def test_parser_p4(self):
        xid = 3423224276
        flags = ofproto_v1_2.OFPC_INVALID_TTL_TO_CONTROLLER
        miss_send_len = 13838
        self._test_parser(xid, flags, miss_send_len)


class TestOFPSetConfig(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPSetConfig
    """

    def test_init(self):
        # OFP_SWITCH_CONFIG_PACK_STR
        # '!HH'...flags, miss_send_len
        flags = 41186
        miss_send_len = 13838

        c = OFPSetConfig(_Datapath, flags, miss_send_len)

        eq_(flags, c.flags)
        eq_(miss_send_len, c.miss_send_len)

    def _test_serialize(self, flags, miss_send_len):
        c = OFPSetConfig(_Datapath, flags, miss_send_len)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_SET_CONFIG, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_SET_CONFIG)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], flags)
        eq_(res[5], miss_send_len)

    def test_serialize_mid(self):
        flags = 41186
        miss_send_len = 13838
        self._test_serialize(flags, miss_send_len)

    def test_serialize_max(self):
        flags = 65535
        miss_send_len = 65535
        self._test_serialize(flags, miss_send_len)

    def test_serialize_min(self):
        flags = ofproto_v1_2.OFPC_FRAG_NORMAL
        miss_send_len = 0
        self._test_serialize(flags, miss_send_len)

    def test_serialize_p1(self):
        flags = ofproto_v1_2.OFPC_FRAG_DROP
        miss_send_len = 13838
        self._test_serialize(flags, miss_send_len)

    def test_serialize_p2(self):
        flags = ofproto_v1_2.OFPC_FRAG_REASM
        miss_send_len = 13838
        self._test_serialize(flags, miss_send_len)

    def test_serialize_p3(self):
        flags = ofproto_v1_2.OFPC_FRAG_MASK
        miss_send_len = 13838
        self._test_serialize(flags, miss_send_len)

    def test_serialize_p4(self):
        flags = ofproto_v1_2.OFPC_INVALID_TTL_TO_CONTROLLER
        miss_send_len = 13838
        self._test_serialize(flags, miss_send_len)

    @raises(AssertionError)
    def test_serialize_check_flags(self):
        flags = None
        miss_send_len = 13838
        c = OFPSetConfig(_Datapath, flags, miss_send_len)
        c.serialize()

    @raises(AssertionError)
    def test_serialize_check_miss_send_len(self):
        flags = 41186
        miss_send_len = None
        c = OFPSetConfig(_Datapath, flags, miss_send_len)
        c.serialize()


class TestOFPPacketIn(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPacketIn
    """

    def _test_parser(self, xid, buffer_id, total_len=0,
                     reason=0, table_id=0, data=None):
        if data is None:
            data = ''

        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_PACKET_IN
        msg_len = ofproto_v1_2.OFP_PACKET_IN_SIZE + len(data)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_PACKET_IN_PACK_STR
        fmt = ofproto_v1_2.OFP_PACKET_IN_PACK_STR
        buf += pack(fmt, buffer_id, total_len, reason, table_id)

        # match
        buf_match = bytearray()
        match = OFPMatch()
        match.serialize(buf_match, 0)
        buf += str(buf_match)

        # data
        buf += '\x00' * 2
        buf += data

        res = OFPPacketIn.parser(object, version, msg_type, msg_len,
                                 xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(buffer_id, res.buffer_id)
        eq_(total_len, res.total_len)
        eq_(reason, res.reason)
        eq_(table_id, res.table_id)
        ok_(hasattr(res, 'match'))
        eq_(ofproto_v1_2.OFPMT_OXM, res.match.type)

        if data:
            eq_(data[:total_len], res.data)

    def test_data_is_total_len(self):
        xid = 3423224276
        buffer_id = 2926809324
        reason = 128
        table_id = 3
        data = 'PacketIn'
        total_len = len(data)
        self._test_parser(xid, buffer_id, total_len, reason, table_id, data)

    def test_data_is_not_total_len(self):
        xid = 3423224276
        buffer_id = 2926809324
        reason = 128
        table_id = 3
        data = 'PacketIn'
        total_len = len(data) - 1
        self._test_parser(xid, buffer_id, total_len, reason, table_id, data)

    def test_parser_max(self):
        # 65535(!H max) - 24(without data) = 65511
        xid = 4294967295
        buffer_id = 4294967295
        reason = 255
        table_id = 255
        data = 'data'.ljust(65511)
        total_len = len(data)
        self._test_parser(xid, buffer_id, total_len, reason, table_id, data)

    def test_parser_min(self):
        xid = 0
        buffer_id = 0
        reason = ofproto_v1_2.OFPR_NO_MATCH
        table_id = 0
        total_len = 0
        self._test_parser(xid, buffer_id, total_len, reason, table_id)

    def test_parser_p1(self):
        data = 'data'.ljust(8)
        xid = 3423224276
        buffer_id = 2926809324
        total_len = len(data)
        reason = ofproto_v1_2.OFPR_ACTION
        table_id = 3
        self._test_parser(xid, buffer_id, total_len, reason, table_id, data)

    def test_parser_p2(self):
        data = 'data'.ljust(8)
        xid = 3423224276
        buffer_id = 2926809324
        total_len = len(data)
        reason = ofproto_v1_2.OFPR_INVALID_TTL
        table_id = 3
        self._test_parser(xid, buffer_id, total_len, reason, table_id, data)


class TestOFPFlowRemoved(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowRemoved
    """

    def _test_parser(self, xid, cookie, priority,
                     reason, table_id, duration_sec,
                     duration_nsec, idle_timeout, hard_timeout,
                     packet_count, byte_count):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_FLOW_REMOVED
        msg_len = ofproto_v1_2.OFP_FLOW_REMOVED_SIZE

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_FLOW_REMOVED_PACK_STR0
        # '!QHBBIIHHQQ' ...cookie, priority, reason, table_id,
        #                  duration_sec, duration_nsec, idle_timeout,
        #                  hard_timeout, packet_count, byte_count

        fmt = ofproto_v1_2.OFP_FLOW_REMOVED_PACK_STR0
        buf += pack(fmt, cookie, priority, reason, table_id,
                    duration_sec, duration_nsec, idle_timeout,
                    hard_timeout, packet_count, byte_count)

        # OFP_MATCH_PACK_STR
        match = OFPMatch()
        buf_match = bytearray()
        match.serialize(buf_match, 0)

        buf += str(buf_match)

        res = OFPFlowRemoved.parser(object, version, msg_type,
                                    msg_len, xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(cookie, res.cookie)
        eq_(priority, res.priority)
        eq_(reason, res.reason)
        eq_(table_id, res.table_id)
        eq_(duration_sec, res.duration_sec)
        eq_(duration_nsec, res.duration_nsec)
        eq_(idle_timeout, res.idle_timeout)
        eq_(hard_timeout, res.hard_timeout)
        eq_(packet_count, res.packet_count)
        eq_(byte_count, res.byte_count)
        ok_(hasattr(res, 'match'))
        eq_(ofproto_v1_2.OFPMT_OXM, res.match.type)

    def test_parser_mid(self):
        xid = 3423224276
        cookie = 178378173441633860
        priority = 718
        reason = 128
        table_id = 169
        duration_sec = 2250548154
        duration_nsec = 2492776995
        idle_timeout = 60284
        hard_timeout = 60285
        packet_count = 6489108735192644493
        byte_count = 7334344481123449724
        self._test_parser(xid, cookie, priority,
                          reason, table_id, duration_sec,
                          duration_nsec, idle_timeout, hard_timeout,
                          packet_count, byte_count)

    def test_parser_max(self):
        xid = 4294967295
        cookie = 18446744073709551615
        priority = 65535
        reason = 255
        table_id = 255
        duration_sec = 4294967295
        duration_nsec = 4294967295
        idle_timeout = 65535
        hard_timeout = 65535
        packet_count = 18446744073709551615
        byte_count = 18446744073709551615
        self._test_parser(xid, cookie, priority,
                          reason, table_id, duration_sec,
                          duration_nsec, idle_timeout, hard_timeout,
                          packet_count, byte_count)

    def test_parser_min(self):
        xid = 0
        cookie = 0
        priority = 0
        reason = ofproto_v1_2.OFPRR_IDLE_TIMEOUT
        table_id = 0
        duration_sec = 0
        duration_nsec = 0
        idle_timeout = 0
        hard_timeout = 0
        packet_count = 0
        byte_count = 0
        self._test_parser(xid, cookie, priority,
                          reason, table_id, duration_sec,
                          duration_nsec, idle_timeout, hard_timeout,
                          packet_count, byte_count)

    def test_parser_p1(self):
        xid = 3423224276
        cookie = 178378173441633860
        priority = 718
        reason = ofproto_v1_2.OFPRR_HARD_TIMEOUT
        table_id = 169
        duration_sec = 2250548154
        duration_nsec = 2492776995
        idle_timeout = 60284
        hard_timeout = 60285
        packet_count = 6489108735192644493
        byte_count = 7334344481123449724
        self._test_parser(xid, cookie, priority,
                          reason, table_id, duration_sec,
                          duration_nsec, idle_timeout, hard_timeout,
                          packet_count, byte_count)

    def test_parser_p2(self):
        xid = 3423224276
        cookie = 178378173441633860
        priority = 718
        reason = ofproto_v1_2.OFPRR_DELETE
        table_id = 169
        duration_sec = 2250548154
        duration_nsec = 2492776995
        idle_timeout = 60284
        hard_timeout = 60285
        packet_count = 6489108735192644493
        byte_count = 7334344481123449724
        self._test_parser(xid, cookie, priority,
                          reason, table_id, duration_sec,
                          duration_nsec, idle_timeout, hard_timeout,
                          packet_count, byte_count)

    def test_parser_p3(self):
        xid = 3423224276
        cookie = 178378173441633860
        priority = 718
        reason = ofproto_v1_2.OFPRR_GROUP_DELETE
        table_id = 169
        duration_sec = 2250548154
        duration_nsec = 2492776995
        idle_timeout = 60284
        hard_timeout = 60285
        packet_count = 6489108735192644493
        byte_count = 7334344481123449724
        self._test_parser(xid, cookie, priority,
                          reason, table_id, duration_sec,
                          duration_nsec, idle_timeout, hard_timeout,
                          packet_count, byte_count)


class TestOFPPortStatus(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortStatus
    """

    def _test_parser(self, xid, reason,
                     port_no, config, state, curr, advertised,
                     supported, peer, curr_speed, max_speed):

        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_PORT_STATUS
        msg_len = ofproto_v1_2.OFP_PORT_STATUS_SIZE

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_PORT_STATUS_PACK_STR = '!B7x' + _OFP_PORT_PACK_STR
        # '!B7x'...reason, pad(7)
        # OFP_PORT_PACK_STR
        # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
        #                          name, config, state, curr, advertised,
        #                          peer, curr_speed, max_speed
        hw_addr = '80:ff:9a:e3:72:85'
        name = 'name'.ljust(16)

        fmt = ofproto_v1_2.OFP_PORT_STATUS_PACK_STR
        buf += pack(fmt, reason, port_no, addrconv.mac.text_to_bin(hw_addr),
                    name, config, state, curr, advertised,
                    supported, peer, curr_speed, max_speed)

        res = OFPPortStatus.parser(object, version, msg_type, msg_len,
                                   xid, buf)

        eq_(reason, res.reason)
        eq_(port_no, res.desc.port_no)
        eq_(hw_addr, res.desc.hw_addr)
        eq_(name, res.desc.name)
        eq_(config, res.desc.config)
        eq_(state, res.desc.state)
        eq_(curr, res.desc.curr)
        eq_(advertised, res.desc.advertised)
        eq_(supported, res.desc.supported)
        eq_(peer, res.desc.peer)
        eq_(curr_speed, res.desc.curr_speed)
        eq_(max_speed, res.desc.max_speed)

    def test_parser_mid(self):
        xid = 3423224276
        reason = 128
        port_no = 1119692796
        config = 2226555987
        state = 1678244809
        curr = 2850556459
        advertised = 2025421682
        supported = 2120575149
        peer = 2757463021
        curr_speed = 2641353507
        max_speed = 1797291672
        self._test_parser(xid, reason,
                          port_no, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_max(self):
        xid = 4294967295
        reason = 255
        port_no = ofproto_v1_2.OFPP_ANY
        config = 4294967295
        state = 4294967295
        curr = 4294967295
        advertised = 4294967295
        supported = 4294967295
        peer = 4294967295
        curr_speed = 4294967295
        max_speed = 4294967295
        self._test_parser(xid, reason,
                          port_no, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_min(self):
        xid = 0
        reason = 0
        port_no = 0
        config = 0
        state = 0
        curr = 0
        advertised = 0
        supported = 0
        peer = 0
        curr_speed = 0
        max_speed = 0
        self._test_parser(xid, reason,
                          port_no, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p1(self):
        xid = 3423224276
        reason = ofproto_v1_2.OFPPR_DELETE
        port_no = ofproto_v1_2.OFPP_MAX
        config = ofproto_v1_2.OFPPC_PORT_DOWN
        state = ofproto_v1_2.OFPPS_LINK_DOWN
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_10MB_HD
        self._test_parser(xid, reason,
                          port_no, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)

    def test_parser_p2(self):
        xid = 3423224276
        reason = ofproto_v1_2.OFPPR_MODIFY
        port_no = ofproto_v1_2.OFPP_MAX
        config = ofproto_v1_2.OFPPC_PORT_DOWN
        state = ofproto_v1_2.OFPPS_LINK_DOWN
        curr = advertised = supported \
             = peer = curr_speed = max_speed \
             = ofproto_v1_2.OFPPF_10MB_HD
        self._test_parser(xid, reason,
                          port_no, config, state, curr, advertised,
                          supported, peer, curr_speed, max_speed)


class TestOFPPacketOut(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPacketOut
    """

    def _test_init(self, in_port):
        buffer_id = 0xffffffff
        data = 'Message'
        out_port = 0x00002ae0
        actions = [OFPActionOutput(out_port, 0)]

        c = OFPPacketOut(_Datapath, buffer_id, in_port, actions, data)

        eq_(buffer_id, c.buffer_id)
        eq_(in_port, c.in_port)
        eq_(0, c.actions_len)
        eq_(data, c.data)
        eq_(actions, c.actions)

    def test_init(self):
        in_port = 0x00040455
        self._test_init(in_port)

    @raises(AssertionError)
    def test_init_check_in_port(self):
        in_port = None
        self._test_init(in_port)

    def _test_serialize(self, buffer_id, in_port, action_cnt=0, data=None):
        actions = []
        for i in range(action_cnt):
            actions.append(ofproto_v1_2_parser.OFPActionOutput(i, 0))

        c = OFPPacketOut(_Datapath, buffer_id, in_port, actions, data)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_PACKET_OUT, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR \
            + ofproto_v1_2.OFP_PACKET_OUT_PACK_STR[1:] \
            + ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR[1:] * action_cnt

        if data is not None:
            fmt += str(len(data)) + 's'

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_PACKET_OUT)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], buffer_id)
        eq_(res[5], in_port)
        eq_(res[6], ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE * action_cnt)

        for i in range(action_cnt):
            index = 7 + i * 4
            eq_(res[index], ofproto_v1_2.OFPAT_OUTPUT)
            eq_(res[index + 1], ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE)
            eq_(res[index + 2], i)
            eq_(res[index + 3], 0)

        if data:
            eq_(res[-1], data)

    def test_serialize_true(self):
        buffer_id = 0xffffffff
        in_port = 0x00040455
        action_cnt = 2
        data = 'Message'
        self._test_serialize(buffer_id, in_port, action_cnt, data)

    def test_serialize_none(self):
        buffer_id = 0xffffffff
        in_port = 0x00040455
        self._test_serialize(buffer_id, in_port)

    def test_serialize_max(self):
        buffer_id = 0xffffffff
        in_port = 4294967295
        action_cnt = 1
        data = "Message".ljust(65495)
        self._test_serialize(buffer_id, in_port, action_cnt, data)

    def test_serialize_min(self):
        buffer_id = 0
        in_port = 0
        self._test_serialize(buffer_id, in_port)

    def test_serialize_p1(self):
        buffer_id = 2147483648
        in_port = ofproto_v1_2.OFPP_CONTROLLER
        self._test_serialize(buffer_id, in_port)

    @raises(AssertionError)
    def test_serialize_check_buffer_id(self):
        buffer_id = 2147483648
        in_port = 1
        action_cnt = 0
        data = 'DATA'
        self._test_serialize(buffer_id, in_port, action_cnt, data)


class TestOFPFlowMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowMod
    """

    def test_init(self):
        # OFP_FLOW_MOD_PACK_STR0
        # '!QQBBHHHIIIH2x'...cookie, cookie_mask, table_id, command,
        #                    idle_timeout, hard_timeout, priority, buffer_id,
        #                    out_port, out_group, flags
        cookie = 2127614848199081640
        cookie_mask = 2127614848199081641
        table_id = 3
        command = 0
        idle_timeout = 62317
        hard_timeout = 7365
        priority = 40163
        buffer_id = 4037115955
        out_port = 65037
        out_group = 6606
        flags = 135
        instructions = [OFPInstructionGotoTable(table_id)]

        in_port = 1
        match = OFPMatch()
        match.set_in_port(in_port)

        c = OFPFlowMod(_Datapath, cookie, cookie_mask, table_id, command,
                       idle_timeout, hard_timeout, priority, buffer_id,
                       out_port, out_group, flags, match, instructions)

        eq_(cookie, c.cookie)
        eq_(cookie_mask, c.cookie_mask)
        eq_(table_id, c.table_id)
        eq_(command, c.command)
        eq_(idle_timeout, c.idle_timeout)
        eq_(hard_timeout, c.hard_timeout)
        eq_(priority, c.priority)
        eq_(buffer_id, c.buffer_id)
        eq_(out_port, c.out_port)
        eq_(out_group, c.out_group)
        eq_(flags, c.flags)
        eq_(in_port, c.match._flow.in_port)
        eq_(instructions[0], c.instructions[0])

    def _test_serialize(self, cookie, cookie_mask, table_id,
                        command, idle_timeout, hard_timeout,
                        priority, buffer_id, out_port,
                        out_group, flags, inst_cnt=0):
        dl_type = 0x0800
        match = OFPMatch()
        match.set_dl_type(dl_type)

        insts = []
        for i in range(inst_cnt):
            insts.append(OFPInstructionGotoTable(i))

        c = OFPFlowMod(_Datapath, cookie, cookie_mask, table_id, command,
                       idle_timeout, hard_timeout, priority, buffer_id,
                       out_port, out_group, flags, match, insts)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_FLOW_MOD, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR \
            + ofproto_v1_2.OFP_FLOW_MOD_PACK_STR0[1:] \
            + 'HHHBB' \
            + MTEthType.pack_str[1:] + '6x' \
            + ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR[1:] * inst_cnt

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_FLOW_MOD)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], cookie)
        eq_(res[5], cookie_mask)
        eq_(res[6], table_id)
        eq_(res[7], command)
        eq_(res[8], idle_timeout)
        eq_(res[9], hard_timeout)
        eq_(res[10], priority)
        eq_(res[11], buffer_id)
        eq_(res[12], out_port)
        eq_(res[13], out_group)
        eq_(res[14], flags)

        # OFP_MATCH (type, length, class, [field, hashmask], n_byte, ip_proto)
        eq_(res[15], ofproto_v1_2.OFPMT_OXM)
        eq_(res[16], 10)  # OFP_MATCH_STR + MTEthType.pack_str
        eq_(res[17], ofproto_v1_2.OFPXMC_OPENFLOW_BASIC)
        eq_(res[18] >> 1, ofproto_v1_2.OFPXMT_OFB_ETH_TYPE)
        eq_(res[18] & 0b0001, 0)
        eq_(res[19], calcsize(MTEthType.pack_str))
        eq_(res[20], dl_type)

        # insts (type, length, table_id)
        for i in range(inst_cnt):
            index = 21 + 3 * i
            eq_(res[index], ofproto_v1_2.OFPIT_GOTO_TABLE)
            eq_(res[index + 1], ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_SIZE)
            eq_(res[index + 2], i)

    def test_serialize_mid(self):
        cookie = 2127614848199081640
        cookie_mask = 2127614848199081641
        table_id = 3
        command = 128
        idle_timeout = 62317
        hard_timeout = 7365
        priority = 40163
        buffer_id = 4037115955
        out_port = 65037
        out_group = 6606
        flags = 135
        inst_cnt = 1
        self._test_serialize(cookie, cookie_mask, table_id,
                             command, idle_timeout, hard_timeout,
                             priority, buffer_id, out_port,
                             out_group, flags, inst_cnt)

    def test_serialize_max(self):
        cookie = 18446744073709551615
        cookie_mask = 18446744073709551615
        table_id = 255
        command = 255
        idle_timeout = 65535
        hard_timeout = 65535
        priority = 65535
        buffer_id = 0xffffffff
        out_port = 0xffffffff
        out_group = 0xffffffff
        flags = 65535
        inst_cnt = 0xff
        self._test_serialize(cookie, cookie_mask, table_id,
                             command, idle_timeout, hard_timeout,
                             priority, buffer_id, out_port,
                             out_group, flags, inst_cnt)

    def test_serialize_min(self):
        cookie = 0
        cookie_mask = 0
        table_id = 0
        command = ofproto_v1_2.OFPFC_ADD
        idle_timeout = 0
        hard_timeout = 0
        priority = 0
        buffer_id = 0
        out_port = 0
        out_group = 0
        flags = 0
        self._test_serialize(cookie, cookie_mask, table_id,
                             command, idle_timeout, hard_timeout,
                             priority, buffer_id, out_port,
                             out_group, flags)

    def test_serialize_p1(self):
        cookie = 2127614848199081640
        cookie_mask = 2127614848199081641
        table_id = 3
        command = 1
        idle_timeout = 62317
        hard_timeout = 7365
        priority = 40163
        buffer_id = 4037115955
        out_port = 65037
        out_group = 6606
        flags = 1 << 0
        self._test_serialize(cookie, cookie_mask, table_id,
                             command, idle_timeout, hard_timeout,
                             priority, buffer_id, out_port,
                             out_group, flags)

    def test_serialize_p2(self):
        cookie = 2127614848199081640
        cookie_mask = 2127614848199081641
        table_id = 3
        command = 2
        idle_timeout = 62317
        hard_timeout = 7365
        priority = 40163
        buffer_id = 4037115955
        out_port = 65037
        out_group = 6606
        flags = 1 << 0
        self._test_serialize(cookie, cookie_mask, table_id,
                             command, idle_timeout, hard_timeout,
                             priority, buffer_id, out_port,
                             out_group, flags)

    def test_serialize_p3(self):
        cookie = 2127614848199081640
        cookie_mask = 2127614848199081641
        table_id = 3
        command = 3
        idle_timeout = 62317
        hard_timeout = 7365
        priority = 40163
        buffer_id = 4037115955
        out_port = 65037
        out_group = 6606
        flags = 1 << 1
        self._test_serialize(cookie, cookie_mask, table_id,
                             command, idle_timeout, hard_timeout,
                             priority, buffer_id, out_port,
                             out_group, flags)

    def test_serialize_p4(self):
        cookie = 2127614848199081640
        cookie_mask = 2127614848199081641
        table_id = 3
        command = 4
        idle_timeout = 62317
        hard_timeout = 7365
        priority = 40163
        buffer_id = 4037115955
        out_port = 65037
        out_group = 6606
        flags = 1 << 2
        self._test_serialize(cookie, cookie_mask, table_id,
                             command, idle_timeout, hard_timeout,
                             priority, buffer_id, out_port,
                             out_group, flags)


class TestOFPInstructionGotoTable(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPInstructionGotoTable
    """

    # OFP_INSTRUCTION_GOTO_TABLE_PACK_STR
    # '!HHB3x'...type, len, table_id, pad(3)
    type_ = ofproto_v1_2.OFPIT_GOTO_TABLE
    len_ = ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_SIZE

    fmt = ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR

    def test_init(self):
        table_id = 3
        c = OFPInstructionGotoTable(table_id)

        eq_(self.type_, c.type)
        eq_(self.len_, c.len)
        eq_(table_id, c.table_id)

    def _test_parser(self, table_id):
        buf = pack(self.fmt, self.type_, self.len_, table_id)
        res = OFPInstructionGotoTable.parser(buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.table_id, table_id)

    def test_parser_mid(self):
        self._test_parser(3)

    def test_parser_max(self):
        self._test_parser(255)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, table_id):
        c = OFPInstructionGotoTable(table_id)

        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], table_id)

    def test_serialize_mid(self):
        self._test_serialize(3)

    def test_serialize_max(self):
        self._test_serialize(255)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPInstructionWriteMetadata(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPInstructionWriteMetadata
    """

    # OFP_INSTRUCTION_WRITE_METADATA_PACK_STR
    # '!HH4xQQ'...type, len, pad(4), metadata, metadata_mask
    type_ = ofproto_v1_2.OFPIT_WRITE_METADATA
    len_ = ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_SIZE
    metadata = 0x1212121212121212
    metadata_mask = 0xff00ff00ff00ff00

    fmt = ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_PACK_STR

    def test_init(self):
        c = OFPInstructionWriteMetadata(self.metadata,
                                        self.metadata_mask)

        eq_(self.type_, c.type)
        eq_(self.len_, c.len)
        eq_(self.metadata, c.metadata)
        eq_(self.metadata_mask, c.metadata_mask)

    def _test_parser(self, metadata, metadata_mask):
        buf = pack(self.fmt, self.type_, self.len_,
                   metadata, metadata_mask)

        res = OFPInstructionWriteMetadata.parser(buf, 0)
        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.metadata, metadata)
        eq_(res.metadata_mask, metadata_mask)

    def test_parser_metadata_mid(self):
        self._test_parser(self.metadata, self.metadata_mask)

    def test_parser_metadata_max(self):
        metadata = 0xffffffffffffffff
        self._test_parser(metadata, self.metadata_mask)

    def test_parser_metadata_min(self):
        metadata = 0
        self._test_parser(metadata, self.metadata_mask)

    def test_parser_metadata_mask_max(self):
        metadata_mask = 0xffffffffffffffff
        self._test_parser(self.metadata, metadata_mask)

    def test_parser_metadata_mask_min(self):
        metadata_mask = 0
        self._test_parser(self.metadata, metadata_mask)

    def _test_serialize(self, metadata, metadata_mask):
        c = OFPInstructionWriteMetadata(metadata,
                                        metadata_mask)

        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], metadata)
        eq_(res[3], metadata_mask)

    def test_serialize_metadata_mid(self):
        self._test_serialize(self.metadata, self.metadata_mask)

    def test_serialize_metadata_max(self):
        metadata = 0xffffffffffffffff
        self._test_serialize(metadata, self.metadata_mask)

    def test_serialize_metadata_min(self):
        metadata = 0
        self._test_serialize(metadata, self.metadata_mask)

    def test_serialize_metadata_mask_max(self):
        metadata_mask = 0xffffffffffffffff
        self._test_serialize(self.metadata, metadata_mask)

    def test_serialize_metadata_mask_min(self):
        metadata_mask = 0
        self._test_serialize(self.metadata, metadata_mask)


class TestOFPInstructionActions(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPInstructionActions
    """
    # OFP_INSTRUCTION_ACTIONS_PACK_STR
    # '!HH4x'...type, len, pad(4)
    type_ = ofproto_v1_2.OFPIT_WRITE_ACTIONS
    len_ = ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_SIZE \
        + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE

    fmt = ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_PACK_STR
    buf = pack(fmt, type_, len_)

    # OFP_ACTION (OFP_ACTION_OUTPUT)
    port = 0x00002ae0
    max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    actions = [OFPActionOutput(port, max_len)]
    buf_actions = bytearray()
    actions[0].serialize(buf_actions, 0)

    buf += str(buf_actions)

    def test_init(self):
        c = OFPInstructionActions(self.type_, self.actions)

        eq_(self.type_, c.type)
        eq_(self.actions, c.actions)

    def _test_parser(self, action_cnt):
        # OFP_INSTRUCTION_ACTIONS_PACK_STR
        # '!HH4x'...type, len, pad(4)
        len_ = ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_SIZE \
            + (ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE * action_cnt)

        fmt = ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_PACK_STR
        buf = pack(fmt, self.type_, len_)

        actions = []
        for a in range(action_cnt):
            # OFP_ACTION (OFP_ACTION_OUTPUT)
            port = a
            action = OFPActionOutput(port, self.max_len)
            actions.append(action)
            buf_actions = bytearray()
            actions[a].serialize(buf_actions, 0)
            buf += str(buf_actions)

        res = OFPInstructionActions.parser(buf, 0)

        # 8
        eq_(res.len, len_)
        eq_(res.type, self.type_)

        # 8 + 16 * action_cnt < 65535 byte
        # action_cnt <= 4095
        for a in range(action_cnt):
            eq_(res.actions[a].type, actions[a].type)
            eq_(res.actions[a].len, actions[a].len)
            eq_(res.actions[a].port, actions[a].port)
            eq_(res.actions[a].max_len, actions[a].max_len)

    def test_parser_mid(self):
        self._test_parser(2047)

    def test_parser_max(self):
        self._test_parser(4095)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, action_cnt):
        # OFP_INSTRUCTION_ACTIONS_PACK_STR
        # '!HH4x'...type, len, pad(4)
        len_ = ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_SIZE \
            + (ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE * action_cnt)

        actions = []
        for a in range(action_cnt):
            # OFP_ACTION (OFP_ACTION_OUTPUT)
            port = a
            action = OFPActionOutput(port, self.max_len)
            actions.append(action)

        c = OFPInstructionActions(self.type_, actions)

        buf = bytearray()
        c.serialize(buf, 0)

        fmt = '!' \
            + ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_PACK_STR.replace('!', '')

        for a in range(action_cnt):
            fmt += ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], len_)

        for a in range(action_cnt):
            d = 2 + a * 4
            eq_(res[d], actions[a].type)
            eq_(res[d + 1], actions[a].len)
            eq_(res[d + 2], actions[a].port)
            eq_(res[d + 3], actions[a].max_len)

    def test_serialize_mid(self):
        self._test_serialize(2047)

    def test_serialize_max(self):
        self._test_serialize(4095)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionHeader(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionHeader
    """

    def test_init(self):
        # OFP_ACTION_HEADER_PACK_STR
        # '!HH4x'...type, len, pad(4)
        type_ = ofproto_v1_2.OFPAT_OUTPUT
        len_ = ofproto_v1_2.OFP_ACTION_HEADER_SIZE

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        buf = pack(fmt, type_, len_)

        c = OFPActionHeader(type_, len_)

        eq_(type_, c.type)
        eq_(len_, c.len)

    def _test_serialize(self, type_, len_):
        # OFP_ACTION_HEADER_PACK_STR
        # '!HH4x'...type, len, pad(4)

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        buf = pack(fmt, type_, len_)

        c = OFPActionHeader(type_, len_)

        buf = bytearray()
        c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], type_)
        eq_(res[1], len_)

    def test_serialize_mid(self):
        type_ = 11
        len_ = 8
        self._test_serialize(type_, len_)

    def test_serialize_max(self):
        type_ = 0xffff
        len_ = 0xffff
        self._test_serialize(type_, len_)

    def test_serialize_min(self):
        type_ = 0
        len_ = 0
        self._test_serialize(type_, len_)


class TestOFPActionOutput(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionOutput
    """

    # OFP_ACTION_OUTPUT_PACK_STR
    # '!HHIH6x'...type, len, port, max_len, pad(6)
    type_ = ofproto_v1_2.OFPAT_OUTPUT
    len_ = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE

    def test_init(self):
        port = 6606
        max_len = 1500
        fmt = ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR
        c = OFPActionOutput(port, max_len)
        eq_(port, c.port)
        eq_(max_len, c.max_len)

    def _test_parser(self, port, max_len):
        fmt = ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR
        buf = pack(fmt, self.type_, self.len_, port, max_len)

        c = OFPActionOutput(port, max_len)

        res = c.parser(buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.port, port)
        eq_(res.max_len, max_len)

    def test_parser_mid(self):
        port = 6606
        max_len = 16
        self._test_parser(port, max_len)

    def test_parser_max(self):
        port = 4294967295
        max_len = 0xffff
        self._test_parser(port, max_len)

    def test_parser_min(self):
        port = 0
        max_len = 0
        self._test_parser(port, max_len)

    def test_parser_p1(self):
        port = 6606
        max_len = 0xffe5
        self._test_parser(port, max_len)

    def _test_serialize(self, port, max_len):
        c = OFPActionOutput(port, max_len)

        buf = bytearray()
        c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR
        res = struct.unpack(fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], port)
        eq_(res[3], max_len)

    def test_serialize_mid(self):
        port = 6606
        max_len = 16
        self._test_serialize(port, max_len)

    def test_serialize_max(self):
        port = 4294967295
        max_len = 0xffff
        self._test_serialize(port, max_len)

    def test_serialize_min(self):
        port = 0
        max_len = 0
        self._test_serialize(port, max_len)

    def test_serialize_p1(self):
        port = 6606
        max_len = 0xffe5
        self._test_serialize(port, max_len)


class TestOFPActionGroup(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionGroup
    """

    # OFP_ACTION_GROUP_PACK_STR
    # '!HHI'...type, len, group_id
    type_ = ofproto_v1_2.OFPAT_GROUP
    len_ = ofproto_v1_2.OFP_ACTION_GROUP_SIZE
    group_id = 6606

    fmt = ofproto_v1_2.OFP_ACTION_GROUP_PACK_STR

    def test_init(self):
        c = OFPActionGroup(self.group_id)
        eq_(self.group_id, c.group_id)

    def _test_parser(self, group_id):
        buf = pack(self.fmt, self.type_, self.len_, group_id)

        res = OFPActionGroup.parser(buf, 0)
        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.group_id, group_id)

    def test_parser_mid(self):
        self._test_parser(self.group_id)

    def test_parser_max(self):
        self._test_parser(4294967295)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, group_id):
        c = OFPActionGroup(group_id)

        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], group_id)

    def test_serialize_mid(self):
        self._test_serialize(self.group_id)

    def test_serialize_max(self):
        self._test_serialize(4294967295)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionSetQueue(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionSetQueue
    """

    # OFP_ACTION_SET_QUEUE_PACK_STR
    # '!HHI'...type, len, queue_id
    type_ = ofproto_v1_2.OFPAT_SET_QUEUE
    len_ = ofproto_v1_2.OFP_ACTION_SET_QUEUE_SIZE
    queue_id = 6606

    fmt = ofproto_v1_2.OFP_ACTION_SET_QUEUE_PACK_STR

    def test_init(self):
        c = OFPActionSetQueue(self.queue_id)
        eq_(self.queue_id, c.queue_id)

    def _test_parser(self, queue_id):
        buf = pack(self.fmt, self.type_, self.len_, queue_id)

        res = OFPActionSetQueue.parser(buf, 0)
        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.queue_id, queue_id)

    def test_parser_mid(self):
        self._test_parser(self.queue_id)

    def test_parser_max(self):
        self._test_parser(4294967295)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, queue_id):
        c = OFPActionSetQueue(queue_id)

        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], queue_id)

    def test_serialize_mid(self):
        self._test_serialize(self.queue_id)

    def test_serialize_max(self):
        self._test_serialize(4294967295)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionSetMplsTtl(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionSetMplsTtl
    """

    # OFP_ACTION_MPLS_TTL_PACK_STR
    # '!HHB3x'...type, len, mpls_ttl, pad(3)
    type_ = ofproto_v1_2.OFPAT_SET_MPLS_TTL
    len_ = ofproto_v1_2.OFP_ACTION_MPLS_TTL_SIZE
    mpls_ttl = 254

    fmt = ofproto_v1_2.OFP_ACTION_MPLS_TTL_PACK_STR

    def test_init(self):
        c = OFPActionSetMplsTtl(self.mpls_ttl)
        eq_(self.mpls_ttl, c.mpls_ttl)

    def _test_parser(self, mpls_ttl):
        buf = pack(self.fmt, self.type_, self.len_, mpls_ttl)

        res = OFPActionSetMplsTtl.parser(buf, 0)
        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.mpls_ttl, mpls_ttl)

    def test_parser_mid(self):
        self._test_parser(self.mpls_ttl)

    def test_parser_max(self):
        self._test_parser(255)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, mpls_ttl):
        c = OFPActionSetMplsTtl(mpls_ttl)

        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], mpls_ttl)

    def test_serialize_mid(self):
        self._test_serialize(self.mpls_ttl)

    def test_serialize_max(self):
        self._test_serialize(255)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionDecMplsTtl(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionDecMplsTtl
    """

    type_ = ofproto_v1_2.OFPAT_DEC_MPLS_TTL
    len_ = ofproto_v1_2.OFP_ACTION_MPLS_TTL_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
    buf = pack(fmt, type_, len_)
    c = OFPActionDecMplsTtl()

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)


class TestOFPActionSetNwTtl(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionSetNwTtl
    """

    # OFP_ACTION_NW_TTL_PACK_STR
    # '!HHB3x'...type, len, nw_ttl, pad(3)
    type_ = ofproto_v1_2.OFPAT_SET_NW_TTL
    len_ = ofproto_v1_2.OFP_ACTION_NW_TTL_SIZE
    nw_ttl = 240

    fmt = ofproto_v1_2.OFP_ACTION_NW_TTL_PACK_STR

    def test_init(self):
        c = OFPActionSetNwTtl(self.nw_ttl)
        eq_(self.nw_ttl, c.nw_ttl)

    def _test_parser(self, nw_ttl):
        buf = pack(self.fmt, self.type_, self.len_, nw_ttl)

        res = OFPActionSetNwTtl.parser(buf, 0)
        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.nw_ttl, nw_ttl)

    def test_parser_mid(self):
        self._test_parser(self.nw_ttl)

    def test_parser_max(self):
        self._test_parser(255)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, nw_ttl):
        c = OFPActionSetNwTtl(nw_ttl)

        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], nw_ttl)

    def test_serialize_mid(self):
        self._test_serialize(self.nw_ttl)

    def test_serialize_max(self):
        self._test_serialize(255)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionDecNwTtl(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionDecNwTtl
    """

    type_ = ofproto_v1_2.OFPAT_DEC_NW_TTL
    len_ = ofproto_v1_2.OFP_ACTION_NW_TTL_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
    buf = pack(fmt, type_, len_)
    c = OFPActionDecNwTtl()

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)


class TestOFPActionCopyTtlOut(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionCopyTtlOut
    """

    type_ = ofproto_v1_2.OFPAT_COPY_TTL_OUT
    len_ = ofproto_v1_2.OFP_ACTION_HEADER_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
    buf = pack(fmt, type_, len_)
    c = OFPActionCopyTtlOut()

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(res.len, self.len_)
        eq_(res.type, self.type_)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)


class TestOFPActionCopyTtlIn(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionCopyTtlIn
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH'...type, len
    type_ = ofproto_v1_2.OFPAT_COPY_TTL_IN
    len_ = ofproto_v1_2.OFP_ACTION_HEADER_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
    buf = pack(fmt, type_, len_)
    c = OFPActionCopyTtlIn()

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)


class TestOFPActionPushVlan(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionPushVlan
    """

    # OFP_ACTION_PUSH_PACK_STR
    # '!HHH2x'...type, len, ethertype, pad(2)
    type_ = ofproto_v1_2.OFPAT_PUSH_VLAN
    len_ = ofproto_v1_2.OFP_ACTION_PUSH_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR

    def test_init(self):
        ethertype = 0x8100
        c = OFPActionPushVlan(ethertype)
        eq_(ethertype, c.ethertype)

    def _test_parser(self, ethertype):
        buf = pack(self.fmt, self.type_, self.len_, ethertype)

        res = OFPActionPushVlan.parser(buf, 0)
        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.ethertype, ethertype)

    def test_parser_mid(self):
        self._test_parser(0x8100)

    def test_parser_max(self):
        self._test_parser(0xffff)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, ethertype):
        c = OFPActionPushVlan(ethertype)
        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], ethertype)

    def test_serialize_mid(self):
        self._test_serialize(0x8100)

    def test_serialize_max(self):
        self._test_serialize(0xffff)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionPushMpls(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionPushMpls
    """

    # OFP_ACTION_PUSH_PACK_STR
    # '!HHH2x'...type, len, ethertype, pad(2)
    type_ = ofproto_v1_2.OFPAT_PUSH_MPLS
    len_ = ofproto_v1_2.OFP_ACTION_PUSH_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR

    def test_init(self):
        ethertype = 0x8100
        c = OFPActionPushMpls(ethertype)
        eq_(ethertype, c.ethertype)

    def _test_parser(self, ethertype):
        buf = pack(self.fmt, self.type_, self.len_, ethertype)

        res = OFPActionPushMpls.parser(buf, 0)
        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.ethertype, ethertype)

    def test_parser_mid(self):
        self._test_parser(0x8100)

    def test_parser_max(self):
        self._test_parser(0xffff)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, ethertype):
        c = OFPActionPushMpls(ethertype)
        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], ethertype)

    def test_serialize_mid(self):
        self._test_serialize(0x8100)

    def test_serialize_max(self):
        self._test_serialize(0xffff)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionPopVlan(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionPopVlan
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH'...type, len
    type_ = ofproto_v1_2.OFPAT_POP_VLAN
    len_ = ofproto_v1_2.OFP_ACTION_HEADER_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
    buf = pack(fmt, type_, len_)
    c = OFPActionPopVlan()

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.type_, res.type)
        eq_(self.len_, res.len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)


class TestOFPActionPopMpls(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionPopMpls
    """

    # OFP_ACTION_POP_MPLS_PACK_STR
    # '!HHH2x'...type, len, ethertype, pad(2)
    type_ = ofproto_v1_2.OFPAT_POP_MPLS
    len_ = ofproto_v1_2.OFP_ACTION_POP_MPLS_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_POP_MPLS_PACK_STR

    def test_init(self):
        ethertype = 0x8100
        c = OFPActionPopMpls(ethertype)
        eq_(ethertype, c.ethertype)

    def _test_parser(self, ethertype):
        buf = pack(self.fmt, self.type_, self.len_, ethertype)

        res = OFPActionPopMpls.parser(buf, 0)
        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.ethertype, ethertype)

    def test_parser_mid(self):
        self._test_parser(0x8100)

    def test_parser_max(self):
        self._test_parser(0xffff)

    def test_parser_min(self):
        self._test_parser(0)

    def _test_serialize(self, ethertype):
        c = OFPActionPopMpls(ethertype)
        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], ethertype)

    def test_serialize_mid(self):
        self._test_serialize(0x8100)

    def test_serialize_max(self):
        self._test_serialize(0xffff)

    def test_serialize_min(self):
        self._test_serialize(0)


class TestOFPActionSetField(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionSetField
    """

    type_ = ofproto_v1_2.OFPAT_SET_FIELD
    header = ofproto_v1_2.OXM_OF_IN_PORT
    in_port = 6606

    field = MTInPort(header, in_port)
    length = ofproto_v1_2.OFP_ACTION_SET_FIELD_SIZE + field.oxm_len()
    len_ = utils.round_up(length, 8)

    fmt = '!HHII4x'
    buf = pack(fmt, type_, len_, header, in_port)

    c = OFPActionSetField(field)

    def test_init(self):
        eq_(self.field, self.c.field)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.field.header, self.header)
        eq_(res.field.value, self.in_port)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.header)
        eq_(res[3], self.in_port)


class TestOFPActionExperimenter(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionExperimenter
    """

    # OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR v1.2
    # '!HHI'...type, len, experimenter
    type_ = ofproto_v1_2.OFPAT_EXPERIMENTER
    len_ = ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_SIZE
    fmt = ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR

    def test_init(self):
        experimenter = 4294967295
        c = OFPActionExperimenter(experimenter)
        eq_(experimenter, c.experimenter)

    def _test_parser(self, experimenter):
        buf = pack(self.fmt, self.type_, self.len_, experimenter)

        res = OFPActionExperimenter.parser(buf, 0)
        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.experimenter, experimenter)

    def test_parser_mid(self):
        experimenter = 2147483648
        self._test_parser(experimenter)

    def test_parser_max(self):
        experimenter = 4294967295
        self._test_parser(experimenter)

    def test_parser_min(self):
        experimenter = 0
        self._test_parser(experimenter)

    def _test_serialize(self, experimenter):
        c = OFPActionExperimenter(experimenter)

        buf = bytearray()
        c.serialize(buf, 0)

        res = struct.unpack(self.fmt, buffer(buf))
        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], experimenter)

    def test_serialize_mid(self):
        experimenter = 2147483648
        self._test_serialize(experimenter)

    def test_serialize_max(self):
        experimenter = 4294967295
        self._test_serialize(experimenter)

    def test_serialize_min(self):
        experimenter = 0
        self._test_serialize(experimenter)


class TestOFPBucket(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBucket
    """

    def test_init(self):
        # OFP_BUCKET_PACK_STR
        # '!HHII4x'...len, weight, watch_port, watch_group, pad(4)
        weight = 4386
        watch_port = 6606
        watch_group = 3

        # OFP_ACTION (OFP_ACTION_OUTPUT)
        port = 3
        max_len = 1500
        actions = [OFPActionOutput(port, max_len)]

        c = OFPBucket(weight, watch_port, watch_group, actions)
        eq_(weight, c.weight)
        eq_(watch_port, c.watch_port)
        eq_(watch_group, c.watch_group)
        eq_(1, len(c.actions))
        eq_(port, c.actions[0].port)
        eq_(max_len, c.actions[0].max_len)

    def _test_parser(self, weight, watch_port, watch_group, action_cnt):
        # OFP_BUCKET_PACK_STR
        # '!HHII4x'...len, weight, watch_port, watch_group, pad(4)
        len_ = ofproto_v1_2.OFP_BUCKET_SIZE \
            + (ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE * action_cnt)

        fmt = ofproto_v1_2.OFP_BUCKET_PACK_STR
        buf = pack(fmt, len_, weight, watch_port, watch_group)

        actions = []
        for a in range(action_cnt):
            # OFP_ACTION (OFP_ACTION_OUTPUT)
            port = a
            max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
            action = OFPActionOutput(port, max_len)
            actions.append(action)
            buf_actions = bytearray()
            actions[a].serialize(buf_actions, 0)
            buf += str(buf_actions)

        res = OFPBucket.parser(buf, 0)

        # 16
        eq_(weight, res.weight)
        eq_(watch_port, res.watch_port)
        eq_(watch_group, res.watch_group)

        # 16 + 16 * action_cnt < 65535 byte
        # action_cnt <= 4094
        for a in range(action_cnt):
            eq_(actions[a].type, res.actions[a].type)
            eq_(actions[a].len, res.actions[a].len)
            eq_(actions[a].port, res.actions[a].port)
            eq_(actions[a].max_len, res.actions[a].max_len)

    def test_parser_mid(self):
        weight = 4386
        watch_port = 6606
        watch_group = 3
        action_cnt = 2047
        self._test_parser(weight, watch_port,
                          watch_group, action_cnt)

    def test_parser_max(self):
        weight = 65535
        watch_port = 4294967295
        watch_group = 4294967295
        action_cnt = 4094
        self._test_parser(weight, watch_port,
                          watch_group, action_cnt)

    def test_parser_min(self):
        weight = 0
        watch_port = 0
        watch_group = 0
        action_cnt = 0
        self._test_parser(weight, watch_port,
                          watch_group, action_cnt)

    def _test_serialize(self, weight, watch_port, watch_group,
                        action_cnt):
        # OFP_BUCKET_PACK_STR
        # '!HHII4x'...len, weight, watch_port, watch_group, pad(4)
        len_ = ofproto_v1_2.OFP_BUCKET_SIZE \
            + (ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE * action_cnt)

        actions = []
        for a in range(action_cnt):
            # OFP_ACTION (OFP_ACTION_OUTPUT)
            port = a
            max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
            action = OFPActionOutput(port, max_len)
            actions.append(action)

        c = OFPBucket(weight, watch_port, watch_group, actions)

        buf = bytearray()
        c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_BUCKET_PACK_STR
        for a in range(action_cnt):
            fmt += ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR[1:]
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], len_)
        eq_(res[1], weight)
        eq_(res[2], watch_port)
        eq_(res[3], watch_group)

        for a in range(action_cnt):
            d = 4 + a * 4
            eq_(res[d], actions[a].type)
            eq_(res[d + 1], actions[a].len)
            eq_(res[d + 2], actions[a].port)
            eq_(res[d + 3], actions[a].max_len)

    def test_serialize_mid(self):
        weight = 4386
        watch_port = 6606
        watch_group = 3
        action_cnt = 2047
        self._test_serialize(weight, watch_port,
                             watch_group, action_cnt)

    def test_serialize_max(self):
        weight = 65535
        watch_port = 4294967295
        watch_group = 4294967295
        action_cnt = 4094
        self._test_serialize(weight, watch_port,
                             watch_group, action_cnt)

    def test_serialize_min(self):
        weight = 0
        watch_port = 0
        watch_group = 0
        action_cnt = 0
        self._test_serialize(weight, watch_port,
                             watch_group, action_cnt)


class TestOFPGroupMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupMod
    """

    def test_init(self):
        # OFP_GROUP_MOD_PACK_STR
        # '!HBBI'...command, type, pad, group_id
        command = ofproto_v1_2.OFPFC_ADD
        type_ = ofproto_v1_2.OFPGT_SELECT
        group_id = 6606

        # OFP_BUCKET
        weight = 4386
        watch_port = 8006
        watch_group = 3

        # OFP_ACTION (OFP_ACTION_OUTPUT)
        port = 10
        max_len = 2000
        actions = [OFPActionOutput(port, max_len)]

        buckets = [OFPBucket(weight, watch_port, watch_group, actions)]

        c = OFPGroupMod(_Datapath, command, type_, group_id, buckets)
        eq_(command, c.command)
        eq_(type_, c.type)
        eq_(group_id, c.group_id)
        eq_(1, len(c.buckets))
        eq_(1, len(c.buckets[0].actions))
        eq_(port, c.buckets[0].actions[0].port)
        eq_(max_len, c.buckets[0].actions[0].max_len)

    def _test_serialize(self, command, type_, group_id, bucket_cnt):
        len_ = ofproto_v1_2.OFP_BUCKET_SIZE \
            + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE

        buckets = []
        for b in range(bucket_cnt):
            # OFP_BUCKET
            weight = watch_port = watch_group = port = b
            actions = [OFPActionOutput(port, 0)]
            bucket = OFPBucket(weight, watch_port, watch_group, actions)
            buckets.append(bucket)

        c = OFPGroupMod(_Datapath, command, type_, group_id, buckets)

        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_GROUP_MOD, c.msg_type)
        eq_(0, c.xid)
        eq_(len(c.buf), c.msg_len)

        # 16 byte
        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR \
            + ofproto_v1_2.OFP_GROUP_MOD_PACK_STR[1:]

        # 16 + (16 + 16) * bucket_cnt < 65535 byte
        # bucket_cnt <= 2047
        for b in range(bucket_cnt):
            fmt += ofproto_v1_2.OFP_BUCKET_PACK_STR[1:] \
                + ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR[1:]

        res = struct.unpack(fmt, str(c.buf))

        msg_len = ofproto_v1_2.OFP_GROUP_MOD_SIZE \
            + (len_ * bucket_cnt)

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_GROUP_MOD)
        eq_(res[2], msg_len)
        eq_(res[3], 0)
        eq_(res[4], command)
        eq_(res[5], type_)
        eq_(res[6], group_id)

        for d in range(bucket_cnt):
            e = 7 + d * 8
            eq_(res[e + 1], buckets[d].weight)
            eq_(res[e + 2], buckets[d].watch_port)
            eq_(res[e + 3], buckets[d].watch_group)
            eq_(res[e + 4], buckets[d].actions[0].type)
            eq_(res[e + 5], buckets[d].actions[0].len)
            eq_(res[e + 6], buckets[d].actions[0].port)
            eq_(res[e + 7], buckets[d].actions[0].max_len)

    def test_serialize_mid(self):
        command = 32768
        type_ = 128
        group_id = 6606
        bucket_cnt = 1023
        self._test_serialize(command, type_, group_id, bucket_cnt)

    def test_serialize_max(self):
        command = 65535
        type_ = 255
        group_id = 4294967295
        bucket_cnt = 2047
        self._test_serialize(command, type_, group_id, bucket_cnt)

    def test_serialize_min(self):
        command = 0
        type_ = 0
        group_id = 0
        bucket_cnt = 0
        self._test_serialize(command, type_, group_id, bucket_cnt)

    def test_serialize_p1(self):
        command = 1
        type_ = 1
        group_id = 6606
        bucket_cnt = 1023
        self._test_serialize(command, type_, group_id, bucket_cnt)

    def test_serialize_p2(self):
        command = 1
        type_ = 2
        group_id = 6606
        bucket_cnt = 1023
        self._test_serialize(command, type_, group_id, bucket_cnt)

    def test_serialize_p3(self):
        command = 2
        type_ = 3
        group_id = 6606
        bucket_cnt = 1023
        self._test_serialize(command, type_, group_id, bucket_cnt)


class TestOFPPortMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortMod
    """

    # OFP_PORT_MOD_PACK_STR v1.2
    # '!I4xs2xIII4x'...port_no, pad(4), hw_addr, pad(2),
    #                  config, mask, advertise, pad(4)
    port_no = 1119692796
    hw_addr = 'e8:fe:5e:a9:68:6c'
    config = 2226555987
    mask = 1678244809
    advertise = 2025421682

    def test_init(self):
        c = OFPPortMod(_Datapath, self.port_no, self.hw_addr,
                       self.config, self.mask, self.advertise)
        eq_(self.port_no, c.port_no)
        eq_(self.hw_addr, c.hw_addr)
        eq_(self.config, c.config)
        eq_(self.mask, c.mask)
        eq_(self.advertise, c.advertise)

    def _test_serialize(self, port_no, hw_addr, config, mask, advertise):
        c = OFPPortMod(_Datapath, port_no, hw_addr, config,
                       mask, advertise)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_PORT_MOD, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_PORT_MOD_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_PORT_MOD)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], port_no)
        eq_(res[5], addrconv.mac.text_to_bin(hw_addr))
        eq_(res[6], config)
        eq_(res[7], mask)
        eq_(res[8], advertise)

    def test_serialize_mid(self):
        self._test_serialize(self.port_no, self.hw_addr,
                             self.config, self.mask, self.advertise)

    def test_serialize_max(self):
        port_no = ofproto_v1_2.OFPP_ANY
        hw_addr = 'ff:ff:ff:ff:ff:ff'
        config = 0xffffffff
        mask = 0xffffffff
        advertise = 0xffffffff
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_min(self):
        port_no = 0
        hw_addr = '00:00:00:00:00:00'
        config = 0
        mask = 0
        advertise = 0
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p1(self):
        port_no = ofproto_v1_2.OFPP_MAX
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_PORT_DOWN
        mask = ofproto_v1_2.OFPPC_PORT_DOWN
        advertise = ofproto_v1_2.OFPPF_10MB_HD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p2(self):
        port_no = ofproto_v1_2.OFPP_IN_PORT
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_RECV
        mask = ofproto_v1_2.OFPPC_NO_RECV
        advertise = ofproto_v1_2.OFPPF_10MB_FD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p3(self):
        port_no = ofproto_v1_2.OFPP_TABLE
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_FWD
        mask = ofproto_v1_2.OFPPC_NO_FWD
        advertise = ofproto_v1_2.OFPPF_100MB_HD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p4(self):
        port_no = ofproto_v1_2.OFPP_NORMAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_100MB_FD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p5(self):
        port_no = ofproto_v1_2.OFPP_FLOOD
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_1GB_HD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p6(self):
        port_no = ofproto_v1_2.OFPP_ALL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_1GB_FD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p7(self):
        port_no = ofproto_v1_2.OFPP_CONTROLLER
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_10GB_FD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p8(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_40GB_FD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p9(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_100GB_FD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p10(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_1TB_FD
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p11(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_OTHER
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p12(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_COPPER
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p13(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_FIBER
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p14(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_AUTONEG
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p15(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_PAUSE
        self._test_serialize(port_no, hw_addr, config, mask, advertise)

    def test_serialize_p16(self):
        port_no = ofproto_v1_2.OFPP_LOCAL
        hw_addr = self.hw_addr
        config = ofproto_v1_2.OFPPC_NO_PACKET_IN
        mask = ofproto_v1_2.OFPPC_NO_PACKET_IN
        advertise = ofproto_v1_2.OFPPF_PAUSE_ASYM
        self._test_serialize(port_no, hw_addr, config, mask, advertise)


class TestOFPTableMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPTableMod
    """

    # OFP_PORT_TABLE_PACK_STR v1.2
    # '!B3xI'...table_id, pad(3), config
    table_id = 3
    config = 2226555987

    def test_init(self):
        c = OFPTableMod(_Datapath, self.table_id, self.config)
        eq_(self.table_id, c.table_id)
        eq_(self.config, c.config)

    def _test_serialize(self, table_id, config):
        c = OFPTableMod(_Datapath, table_id, config)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_TABLE_MOD, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_TABLE_MOD_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_TABLE_MOD)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], table_id)
        eq_(res[5], config)

    def test_serialize_mid(self):
        self._test_serialize(self.table_id, self.config)

    def test_serialize_max(self):
        table_id = ofproto_v1_2.OFPTT_ALL
        config = 0xffffffff
        self._test_serialize(table_id, config)

    def test_serialize_min(self):
        table_id = 0
        config = 0
        self._test_serialize(table_id, config)

    def test_serialize_p1(self):
        table_id = ofproto_v1_2.OFPTT_MAX
        config = ofproto_v1_2.OFPTC_TABLE_MISS_CONTINUE
        self._test_serialize(table_id, config)

    def test_serialize_p2(self):
        table_id = ofproto_v1_2.OFPTT_MAX
        config = ofproto_v1_2.OFPTC_TABLE_MISS_DROP
        self._test_serialize(table_id, config)

    def test_serialize_p3(self):
        table_id = ofproto_v1_2.OFPTT_MAX
        config = ofproto_v1_2.OFPTC_TABLE_MISS_MASK
        self._test_serialize(table_id, config)


class TestOFPStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPStatsRequest
    """

    type_ = ofproto_v1_2.OFPST_DESC
    c = OFPStatsRequest(_Datapath, type_)

    def test_init(self):
        eq_(self.type_, self.c.type)
        eq_(0, self.c.flags)

    def test_serialize_body(self):
        len_ = ofproto_v1_2.OFP_HEADER_SIZE \
            + ofproto_v1_2.OFP_STATS_REQUEST_SIZE
        self.c.buf = bytearray(len_)
        self.c._serialize_body()

        fmt = ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR
        res = struct.unpack_from(fmt, str(self.c.buf),
                                 ofproto_v1_2.OFP_HEADER_SIZE)

        eq_(res[0], self.type_)
        eq_(res[1], 0)


class TestOFPStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPStatsReply
    """

    c = OFPStatsReply(_Datapath)

    def test_parser_single_struct_true(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_STATS_REPLY
        msg_len = ofproto_v1_2.OFP_STATS_REPLY_SIZE \
            + ofproto_v1_2.OFP_AGGREGATE_STATS_REPLY_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_STATS_REPLY_PACK_STR
        # '!HH4x'...type, flags, pad(4)
        type_ = ofproto_v1_2.OFPST_AGGREGATE
        flags = 41802

        fmt = ofproto_v1_2.OFP_STATS_REPLY_PACK_STR
        buf += pack(fmt, type_, flags)

        # OFP_AGGREGATE_STATS_REPLY_PACK_STR
        packet_count = 5142202600015232219
        byte_count = 2659740543924820419
        flow_count = 1344694860
        body = OFPAggregateStatsReply(packet_count, byte_count, flow_count)

        fmt = ofproto_v1_2.OFP_AGGREGATE_STATS_REPLY_PACK_STR
        buf += pack(fmt, packet_count, byte_count, flow_count)

        res = self.c.parser(object, version, msg_type, msg_len, xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(type_, res.type)
        eq_(flags, res.flags)
        eq_(packet_count, res.body.packet_count)
        eq_(byte_count, res.body.byte_count)
        eq_(flow_count, res.body.flow_count)

    def test_parser_single_struct_flase(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_STATS_REPLY
        msg_len = ofproto_v1_2.OFP_STATS_REPLY_SIZE \
            + ofproto_v1_2.OFP_QUEUE_STATS_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_STATS_REPLY_PACK_STR
        # '!HH4x'...type, flags, pad(4)
        type_ = ofproto_v1_2.OFPST_QUEUE
        flags = 11884

        fmt = ofproto_v1_2.OFP_STATS_REPLY_PACK_STR
        buf += pack(fmt, type_, flags)

        # OFP_QUEUE_STATS_PACK_STR
        port_no = 41186
        queue_id = 6606
        tx_bytes = 8638420181865882538
        tx_packets = 2856480458895760962
        tx_errors = 6283093430376743019
        body = [OFPQueueStats(port_no, queue_id, tx_bytes, tx_packets,
                              tx_errors)]

        fmt = ofproto_v1_2.OFP_QUEUE_STATS_PACK_STR
        buf += pack(fmt, port_no, queue_id, tx_bytes, tx_packets, tx_errors)

        res = self.c.parser(object, version, msg_type, msg_len, xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(type_, res.type)
        eq_(flags, res.flags)
        eq_(port_no, res.body[0].port_no)
        eq_(queue_id, res.body[0].queue_id)
        eq_(tx_bytes, res.body[0].tx_bytes)
        eq_(tx_packets, res.body[0].tx_packets)
        eq_(tx_errors, res.body[0].tx_errors)

    def test_parser_max(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_STATS_REPLY
        msg_len = ofproto_v1_2.OFP_STATS_REPLY_SIZE
        xid = 0xffffffff

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_STATS_REPLY_PACK_STR
        # '!HH4x'...type, flags, pad(4)
        type_ = ofproto_v1_2.OFPST_QUEUE
        flags = 0xffff

        fmt = ofproto_v1_2.OFP_STATS_REPLY_PACK_STR
        buf += pack(fmt, type_, flags)
        res = self.c.parser(object, version, msg_type, msg_len, xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(type_, res.type)
        eq_(flags, res.flags)

    def test_parser_min(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_STATS_REPLY
        msg_len = ofproto_v1_2.OFP_STATS_REPLY_SIZE
        xid = 0

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_STATS_REPLY_PACK_STR
        # '!HH4x'...type, flags, pad(4)
        type_ = ofproto_v1_2.OFPST_QUEUE
        flags = 0

        fmt = ofproto_v1_2.OFP_STATS_REPLY_PACK_STR
        buf += pack(fmt, type_, flags)
        res = self.c.parser(object, version, msg_type, msg_len, xid, buf)

        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(type_, res.type)
        eq_(flags, res.flags)


class TestOFPDescStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPDescStatsRequest
    """

    def test_serialize(self):
        c = OFPDescStatsRequest(_Datapath)
        c.serialize()

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_DESC)
        eq_(res[5], 0)


class TestOFPDescStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPDescStats
    """

    # OFP_DESC_STATS_PACK_STR
    # '!256s256s256s32s256s'...mfr_desc, hw_desc, sw_desc, serial_num, dp_desc
    mfr_desc = 'mfr_desc'.ljust(256)
    hw_desc = 'hw_desc'.ljust(256)
    sw_desc = 'sw_desc'.ljust(256)
    serial_num = 'serial_num'.ljust(32)
    dp_desc = 'dp_desc'.ljust(256)

    buf = mfr_desc \
        + hw_desc \
        + sw_desc \
        + serial_num \
        + dp_desc

    c = OFPDescStats(mfr_desc, hw_desc, sw_desc, serial_num, dp_desc)

    def test_init(self):
        eq_(self.mfr_desc, self.c.mfr_desc)
        eq_(self.hw_desc, self.c.hw_desc)
        eq_(self.sw_desc, self.c.sw_desc)
        eq_(self.serial_num, self.c.serial_num)
        eq_(self.dp_desc, self.c.dp_desc)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.mfr_desc, res.mfr_desc)
        eq_(self.hw_desc, res.hw_desc)
        eq_(self.sw_desc, res.sw_desc)
        eq_(self.serial_num, res.serial_num)
        eq_(self.dp_desc, res.dp_desc)


class TestOFPFlowStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowStatsRequest
    """

    # OFP_FLOW_STATS_REQUEST_PACK_STR
    # '!B3xII4xQQ'...table_id, pad(3), out_port, out_group, pad(4),
    #                cookie, cookie_mask
    table_id = 3
    out_port = 65037
    out_group = 6606
    cookie = 2127614848199081640
    cookie_mask = 2127614848199081641

    def test_init(self):
        match = OFPMatch()
        in_port = 3
        match.set_in_port(in_port)

        c = OFPFlowStatsRequest(_Datapath, self.table_id, self.out_port,
                                self.out_group, self.cookie, self.cookie_mask,
                                match)

        eq_(self.table_id, c.table_id)
        eq_(self.out_port, c.out_port)
        eq_(self.out_group, c.out_group)
        eq_(self.cookie, c.cookie)
        eq_(self.cookie_mask, c.cookie_mask)
        eq_(in_port, c.match._flow.in_port)

    def _test_serialize(self, table_id, out_port, out_group,
                        cookie, cookie_mask):
        match = OFPMatch()
        dl_type = 0x800
        match.set_dl_type(dl_type)

        c = OFPFlowStatsRequest(_Datapath, table_id, out_port,
                                out_group, cookie, cookie_mask, match)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR[1:] \
            + ofproto_v1_2.OFP_FLOW_STATS_REQUEST_PACK_STR[1:] \
            + 'HHHBB' \
            + MTEthType.pack_str[1:] + '6x'

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        size = ofproto_v1_2.OFP_STATS_REPLY_SIZE \
            + ofproto_v1_2.OFP_FLOW_STATS_REQUEST_SIZE \
            + calcsize(MTEthType.pack_str + '6x')
        eq_(res[2], size)
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_FLOW)
        eq_(res[5], 0)
        eq_(res[6], table_id)
        eq_(res[7], out_port)
        eq_(res[8], out_group)
        eq_(res[9], cookie)
        eq_(res[10], cookie_mask)
        # match
        eq_(res[11], ofproto_v1_2.OFPMT_OXM)
        eq_(res[12], 10)
        eq_(res[13], ofproto_v1_2.OFPXMC_OPENFLOW_BASIC)
        eq_(res[14] >> 1, ofproto_v1_2.OFPXMT_OFB_ETH_TYPE)
        eq_(res[14] & 0b0001, 0)
        eq_(res[15], calcsize(MTEthType.pack_str))
        eq_(res[16], dl_type)

    def test_serialize_mid(self):
        self._test_serialize(self.table_id, self.out_port, self.out_group,
                             self.cookie, self.cookie_mask)

    def test_serialize_max(self):
        table_id = 0xff
        out_port = 0xffff
        out_group = 0xffff
        cookie = 0xffffffff
        cookie_mask = 0xffffffff
        self._test_serialize(table_id, out_port, out_group,
                             cookie, cookie_mask)

    def test_serialize_min(self):
        table_id = 0
        out_port = 0
        out_group = 0
        cookie = 0
        cookie_mask = 0
        self._test_serialize(table_id, out_port, out_group,
                             cookie, cookie_mask)

    def test_serialize_p1(self):
        table_id = ofproto_v1_2.OFPTT_MAX
        self._test_serialize(table_id, self.out_port, self.out_group,
                             self.cookie, self.cookie_mask)


class TestOFPFlowStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowStats
    """

    def test_init(self):
        length = ofproto_v1_2.OFP_FLOW_STATS_SIZE
        table_id = 81
        duration_sec = 2484712402
        duration_nsec = 3999715196
        priority = 57792
        idle_timeout = 36368
        hard_timeout = 54425
        cookie = 793171083674290912
        packet_count = 5142202600015232219
        byte_count = 2659740543924820419

        match = OFPMatch()
        in_port = 2
        match.set_in_port(in_port)

        goto_table = 3
        instructions = [OFPInstructionGotoTable(goto_table)]
        c = OFPFlowStats(table_id, duration_sec, duration_nsec,
                         priority, idle_timeout, hard_timeout, cookie,
                         packet_count, byte_count, match, instructions)

        eq_(table_id, c.table_id)
        eq_(duration_sec, c.duration_sec)
        eq_(duration_nsec, c.duration_nsec)
        eq_(priority, c.priority)
        eq_(idle_timeout, c.idle_timeout)
        eq_(hard_timeout, c.hard_timeout)
        eq_(cookie, c.cookie)
        eq_(packet_count, c.packet_count)
        eq_(byte_count, c.byte_count)
        eq_(in_port, c.match._flow.in_port)
        eq_(goto_table, c.instructions[0].table_id)

    def _test_parser(self, table_id, duration_sec, duration_nsec,
                     priority, idle_timeout, hard_timeout, cookie,
                     packet_count, byte_count, inst_cnt=0):

        length = ofproto_v1_2.OFP_FLOW_STATS_SIZE \
            + calcsize(MTEthType.pack_str[1:] + '6x') \
            + ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_SIZE * inst_cnt

        # OFP_FLOW_STATS_PACK_STR
        buf = pack(ofproto_v1_2.OFP_FLOW_STATS_PACK_STR,
                   length, table_id, duration_sec, duration_nsec,
                   priority, idle_timeout, hard_timeout, cookie,
                   packet_count, byte_count)

        # match
        match = OFPMatch()
        dl_type = 0x0800
        match.set_dl_type(dl_type)
        match_buf = bytearray()
        match.serialize(match_buf, 0)
        buf += str(match_buf)

        # instructions
        # 56 + 8 + 8 * inst_cnt <= 65535
        # inst_cnt <= 8183
        for i in range(inst_cnt):
            inst = OFPInstructionGotoTable(1)
            inst_buf = bytearray()
            inst.serialize(inst_buf, 0)
            buf += str(inst_buf)

        # parse
        res = OFPFlowStats.parser(buf, 0)
        eq_(length, res.length)
        eq_(table_id, res.table_id)
        eq_(duration_sec, res.duration_sec)
        eq_(duration_nsec, res.duration_nsec)
        eq_(priority, res.priority)
        eq_(idle_timeout, res.idle_timeout)
        eq_(hard_timeout, res.hard_timeout)
        eq_(cookie, res.cookie)
        eq_(packet_count, res.packet_count)
        eq_(byte_count, res.byte_count)
        eq_(dl_type, res.match.fields[0].value)
        for i in range(inst_cnt):
            eq_(1, res.instructions[i].table_id)

    def test_parser_mid(self):
        table_id = 81
        duration_sec = 2484712402
        duration_nsec = 3999715196
        priority = 57792
        idle_timeout = 36368
        hard_timeout = 54425
        cookie = 793171083674290912
        packet_count = 5142202600015232219
        byte_count = 2659740543924820419
        inst_cnt = 2

        self._test_parser(table_id, duration_sec, duration_nsec,
                          priority, idle_timeout, hard_timeout, cookie,
                          packet_count, byte_count, inst_cnt)

    def test_parser_max(self):
        table_id = 0xff
        duration_sec = 0xffff
        duration_nsec = 0xffff
        priority = 0xffff
        idle_timeout = 0xff
        hard_timeout = 0xff
        cookie = 0xffffffffffffffff
        packet_count = 0xffffffffffffffff
        byte_count = 0xffffffffffffffff
        inst_cnt = 8183

        self._test_parser(table_id, duration_sec, duration_nsec,
                          priority, idle_timeout, hard_timeout, cookie,
                          packet_count, byte_count, inst_cnt)

    def test_parser_min(self):
        self._test_parser(0, 0, 0, 0, 0, 0, 0, 0, 0)


class TestOFPAggregateStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPAggregateStatsRequest
    """

    # OFP_AGGREGATE_STATS_REQUEST_PACK_STR
    # '!B3xII4xQQ'...table_id, pad(3), out_port, out_group, pad(4),
    #                cookie, cookie_mask
    table_id = 3
    out_port = 65037
    out_group = 6606
    cookie = 2127614848199081640
    cookie_mask = 2127614848199081641

    def test_init(self):
        match = OFPMatch()
        dl_type = 0x800
        match.set_dl_type(dl_type)
        c = OFPAggregateStatsRequest(_Datapath, self.table_id,
                                     self.out_port, self.out_group,
                                     self.cookie, self.cookie_mask,
                                     match)

        eq_(self.table_id, c.table_id)
        eq_(self.out_port, c.out_port)
        eq_(self.out_group, c.out_group)
        eq_(self.cookie, c.cookie)
        eq_(self.cookie_mask, c.cookie_mask)
        eq_(dl_type, c.match._flow.dl_type)

    def _test_serialize(self, table_id, out_port, out_group,
                        cookie, cookie_mask):
        match = OFPMatch()
        dl_type = 0x800
        match.set_dl_type(dl_type)
        c = OFPAggregateStatsRequest(_Datapath, table_id,
                                     out_port, out_group, cookie,
                                     cookie_mask, match)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR[1:] \
            + ofproto_v1_2.OFP_AGGREGATE_STATS_REQUEST_PACK_STR[1:] \
            + 'HHHBB' \
            + MTEthType.pack_str[1:] + '6x'

        res = struct.unpack(fmt, str(c.buf))
        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_AGGREGATE)
        eq_(res[5], 0)
        eq_(res[6], table_id)
        eq_(res[7], out_port)
        eq_(res[8], out_group)
        eq_(res[9], cookie)
        eq_(res[10], cookie_mask)
        # match
        eq_(res[11], ofproto_v1_2.OFPMT_OXM)
        eq_(res[12], 10)
        eq_(res[13], ofproto_v1_2.OFPXMC_OPENFLOW_BASIC)
        eq_(res[14] >> 1, ofproto_v1_2.OFPXMT_OFB_ETH_TYPE)
        eq_(res[14] & 0b0001, 0)
        eq_(res[15], calcsize(MTEthType.pack_str))
        eq_(res[16], dl_type)

    def test_serialize_mid(self):
        self._test_serialize(self.table_id, self.out_port, self.out_group,
                             self.cookie, self.cookie_mask)

    def test_serialize_max(self):
        table_id = 0xff
        out_port = 0xffffffff
        out_group = 0xffffffff
        cookie = 0xffffffff
        cookie_mask = 0xffffffff
        self._test_serialize(table_id, out_port, out_group,
                             cookie, cookie_mask)

    def test_serialize_min(self):
        table_id = 0
        out_port = 0
        out_group = 0
        cookie = 0
        cookie_mask = 0
        self._test_serialize(table_id, out_port, out_group,
                             cookie, cookie_mask)

    def test_serialize_p1(self):
        table_id = ofproto_v1_2.OFPTT_MAX
        self._test_serialize(table_id, self.out_port, self.out_group,
                             self.cookie, self.cookie_mask)


class TestOFPAggregateStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPAggregateStatsReply
    """

    # OFP_AGGREGATE_STATS_REPLY_PACK_STR
    # '!QQI4x'...packet_count, byte_count, flow_count, pad(4)
    packet_count = 5142202600015232219
    byte_count = 2659740543924820419
    flow_count = 1344694860

    def test_init(self):
        c = OFPAggregateStatsReply(self.packet_count, self.byte_count,
                                   self.flow_count)

        eq_(c.packet_count, self.packet_count)
        eq_(c.byte_count, self.byte_count)
        eq_(c.flow_count, self.flow_count)

    def _test_parser(self, packet_count, byte_count, flow_count):
        fmt = ofproto_v1_2.OFP_AGGREGATE_STATS_REPLY_PACK_STR
        buf = pack(fmt, packet_count, byte_count, flow_count)

        res = OFPAggregateStatsReply.parser(buf, 0)
        eq_(packet_count, res.packet_count)
        eq_(byte_count, res.byte_count)
        eq_(flow_count, res.flow_count)

    def test_parser_mid(self):
        self._test_parser(self.packet_count, self.byte_count,
                          self.flow_count)

    def test_parser_max(self):
        packet_count = 18446744073709551615
        byte_count = 18446744073709551615
        flow_count = 4294967295
        self._test_parser(packet_count, byte_count,
                          flow_count)

    def test_parser_min(self):
        packet_count = 0
        byte_count = 0
        flow_count = 0
        self._test_parser(packet_count, byte_count,
                          flow_count)


class TestOFPTableStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPTableStatsRequest
    """

    def test_serialize(self):
        c = OFPTableStatsRequest(_Datapath)
        c.serialize()

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_TABLE)
        eq_(res[5], 0)


class TestOFPTableStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPTableStats
    """

    def test_init(self):
        table_id = 91
        name = 'name'
        match = 1270985291017894273
        wildcards = 3316608530
        write_actions = 2484712402
        apply_actions = 3999715196
        write_setfields = 5142202600015232219
        apply_setfields = 2659740543924820419
        metadata_match = 2127614848199081640
        metadata_write = 2127614848199081641
        instructions = 1119692796
        config = 2226555987
        max_entries = 2506913869
        active_count = 2024581150
        lookup_count = 4620020561814017052
        matched_count = 2825167325263435621

        res = OFPTableStats(table_id, name, match, wildcards, write_actions,
                            apply_actions, write_setfields, apply_setfields,
                            metadata_match, metadata_write, instructions,
                            config, max_entries, active_count, lookup_count,
                            matched_count)

        eq_(table_id, res.table_id)
        eq_(name, res.name)
        eq_(match, res.match)
        eq_(wildcards, res.wildcards)
        eq_(write_actions, res.write_actions)
        eq_(apply_actions, res.apply_actions)
        eq_(write_setfields, res.write_setfields)
        eq_(apply_setfields, res.apply_setfields)
        eq_(metadata_match, res.metadata_match)
        eq_(metadata_write, res.metadata_write)
        eq_(instructions, res.instructions)
        eq_(config, res.config)
        eq_(max_entries, res.max_entries)
        eq_(active_count, res.active_count)
        eq_(lookup_count, res.lookup_count)
        eq_(matched_count, res.matched_count)

    def _test_parser(self, table_id, name, match, wildcards, write_actions,
                     apply_actions, write_setfields, apply_setfields,
                     metadata_match, metadata_write, instructions, config,
                     max_entries, active_count, lookup_count, matched_count):
        # OFP_TABLE_STATS_PACK_STR
        # '!B7x32sQQIIQQQQIIIIQQ'
        # ...table_id, name, match, wildcards, write_actions, apply_actions,
        #    write_setfields, apply_setfields', metadata_match, metadata_write,
        #    instructions, config, max_entries,
        #    active_count, lookup_count, matched_count
        fmt = ofproto_v1_2.OFP_TABLE_STATS_PACK_STR
        buf = pack(fmt, table_id, name, match, wildcards, write_actions,
                   apply_actions, write_setfields, apply_setfields,
                   metadata_match, metadata_write, instructions, config,
                   max_entries, active_count, lookup_count, matched_count)

        res = OFPTableStats.parser(buf, 0)

        eq_(table_id, res.table_id)
        eq_(name, res.name.replace('\x00', ''))
        eq_(match, res.match)
        eq_(wildcards, res.wildcards)
        eq_(write_actions, res.write_actions)
        eq_(apply_actions, res.apply_actions)
        eq_(write_setfields, res.write_setfields)
        eq_(apply_setfields, res.apply_setfields)
        eq_(metadata_match, res.metadata_match)
        eq_(metadata_write, res.metadata_write)
        eq_(instructions, res.instructions)
        eq_(config, res.config)
        eq_(max_entries, res.max_entries)
        eq_(active_count, res.active_count)
        eq_(lookup_count, res.lookup_count)
        eq_(matched_count, res.matched_count)

    def test_parser_mid(self):
        table_id = 91
        name = 'name'
        match = 1270985291017894273
        wildcards = 3316608530
        write_actions = 2484712402
        apply_actions = 3999715196
        write_setfields = 5142202600015232219
        apply_setfields = 2659740543924820419
        metadata_match = 2127614848199081640
        metadata_write = 2127614848199081641
        instructions = 1119692796
        config = 2226555987
        max_entries = 2506913869
        active_count = 2024581150
        lookup_count = 4620020561814017052
        matched_count = 2825167325263435621

        self._test_parser(table_id, name, match, wildcards, write_actions,
                          apply_actions, write_setfields, apply_setfields,
                          metadata_match, metadata_write, instructions, config,
                          max_entries, active_count, lookup_count,
                          matched_count)

    def test_parser_max(self):
        # '!B7x32sQQIIQQQQIIIIQQ'
        table_id = 0xff
        name = 'a' * 32
        match = 0xffffffffffffffff
        wildcards = 0xffffffffffffffff
        write_actions = 0xffffffff
        apply_actions = 0xffffffff
        write_setfields = 0xffffffffffffffff
        apply_setfields = 0xffffffffffffffff
        metadata_match = 0xffffffffffffffff
        metadata_write = 0xffffffffffffffff
        instructions = 0xffffffff
        config = 0xffffffff
        max_entries = 0xffffffff
        active_count = 0xffffffff
        lookup_count = 0xffffffffffffffff
        matched_count = 0xffffffffffffffff

        self._test_parser(table_id, name, match, wildcards, write_actions,
                          apply_actions, write_setfields, apply_setfields,
                          metadata_match, metadata_write, instructions, config,
                          max_entries, active_count, lookup_count,
                          matched_count)

    def test_parser_min(self):
        table_id = 0
        name = ''
        match = 0
        wildcards = 0
        write_actions = 0
        apply_actions = 0
        write_setfields = 0
        apply_setfields = 0
        metadata_match = 0
        metadata_write = 0
        instructions = 0
        config = 0
        max_entries = 0
        active_count = 0
        lookup_count = 0
        matched_count = 0

        self._test_parser(table_id, name, match, wildcards, write_actions,
                          apply_actions, write_setfields, apply_setfields,
                          metadata_match, metadata_write, instructions, config,
                          max_entries, active_count, lookup_count,
                          matched_count)

    def _test_parser_p(self, ofpxmt, ofpit, ofptc):
        table_id = 91
        name = 'name'
        match = ofpxmt
        wildcards = ofpxmt
        write_actions = 2484712402
        apply_actions = 3999715196
        write_setfields = ofpxmt
        apply_setfields = ofpxmt
        metadata_match = 2127614848199081640
        metadata_write = 2127614848199081641
        instructions = ofpit
        config = ofptc
        max_entries = 2506913869
        active_count = 2024581150
        lookup_count = 4620020561814017052
        matched_count = 2825167325263435621

        self._test_parser(table_id, name, match, wildcards, write_actions,
                          apply_actions, write_setfields, apply_setfields,
                          metadata_match, metadata_write, instructions, config,
                          max_entries, active_count, lookup_count,
                          matched_count)

    def test_parser_p1(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IN_PORT,
                            ofproto_v1_2.OFPIT_GOTO_TABLE,
                            ofproto_v1_2.OFPTC_TABLE_MISS_CONTINUE)

    def test_parser_p2(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IN_PHY_PORT,
                            ofproto_v1_2.OFPIT_WRITE_METADATA,
                            ofproto_v1_2.OFPTC_TABLE_MISS_DROP)

    def test_parser_p3(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_METADATA,
                            ofproto_v1_2.OFPIT_WRITE_ACTIONS,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p4(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ETH_DST,
                            ofproto_v1_2.OFPIT_APPLY_ACTIONS,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p5(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ETH_SRC,
                            ofproto_v1_2.OFPIT_CLEAR_ACTIONS,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p6(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ETH_TYPE,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p7(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_VLAN_VID,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p8(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_VLAN_PCP,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p9(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IP_DSCP,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p10(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IP_ECN,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p11(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IP_PROTO,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p12(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV4_SRC,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p13(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV4_DST,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p14(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_TCP_SRC,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p15(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_TCP_DST,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p16(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_UDP_SRC,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p17(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_UDP_DST,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p18(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_SCTP_SRC,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p19(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_SCTP_DST,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p20(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ICMPV4_TYPE,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p21(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ICMPV4_CODE,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p22(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ARP_OP,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p23(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ARP_SPA,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p24(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ARP_TPA,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p25(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ARP_SHA,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p26(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ARP_THA,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p27(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV6_SRC,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p28(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV6_DST,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p29(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV6_FLABEL,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p30(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ICMPV6_TYPE,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p31(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_ICMPV6_CODE,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p32(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_TARGET,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p33(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_SLL,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p34(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_IPV6_ND_TLL,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p35(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_MPLS_LABEL,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)

    def test_parser_p36(self):
        self._test_parser_p(ofproto_v1_2.OFPXMT_OFB_MPLS_TC,
                            ofproto_v1_2.OFPIT_EXPERIMENTER,
                            ofproto_v1_2.OFPTC_TABLE_MISS_MASK)


class TestOFPPortStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortStatsRequest
    """

    # OFP_PORT_STATS_REQUEST_PACK_STR
    # '!I4x'...port_no, pad(4)
    port_no = 41186

    def test_init(self):
        c = OFPPortStatsRequest(_Datapath, self.port_no)
        eq_(self.port_no, c.port_no)

    def _test_serialize(self, port_no):
        c = OFPPortStatsRequest(_Datapath, port_no)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_PORT_STATS_REQUEST_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_PORT)
        eq_(res[5], 0)
        eq_(res[6], port_no)

    def test_serialize_mid(self):
        self._test_serialize(self.port_no)

    def test_serialize_max(self):
        self._test_serialize(ofproto_v1_2.OFPP_ANY)

    def test_serialize_min(self):
        self._test_serialize(0)

    def test_serialize_p1(self):
        self._test_serialize(ofproto_v1_2.OFPP_MAX)

    def test_serialize_p2(self):
        self._test_serialize(ofproto_v1_2.OFPP_IN_PORT)

    def test_serialize_p3(self):
        self._test_serialize(ofproto_v1_2.OFPP_TABLE)

    def test_serialize_p4(self):
        self._test_serialize(ofproto_v1_2.OFPP_NORMAL)

    def test_serialize_p5(self):
        self._test_serialize(ofproto_v1_2.OFPP_FLOOD)

    def test_serialize_p6(self):
        self._test_serialize(ofproto_v1_2.OFPP_ALL)

    def test_serialize_p7(self):
        self._test_serialize(ofproto_v1_2.OFPP_CONTROLLER)

    def test_serialize_p8(self):
        self._test_serialize(ofproto_v1_2.OFPP_LOCAL)


class TestOFPPortStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortStats
    """

    def test_init(self):
        port_no = 6606
        rx_packets = 5999980397101236279
        tx_packets = 2856480458895760962
        rx_bytes = 6170274950576278921
        tx_bytes = 8638420181865882538
        rx_dropped = 6982303461569875546
        tx_dropped = 661287462113808071
        rx_errors = 3422231811478788365
        tx_errors = 6283093430376743019
        rx_frame_err = 876072919806406283
        rx_over_err = 6525873760178941600
        rx_crc_err = 8303073210207070535
        collisions = 3409801584220270201

        res = OFPPortStats(port_no, rx_packets, tx_packets,
                           rx_bytes, tx_bytes, rx_dropped, tx_dropped,
                           rx_errors, tx_errors, rx_frame_err,
                           rx_over_err, rx_crc_err, collisions)

        eq_(port_no, res.port_no)
        eq_(rx_packets, res.rx_packets)
        eq_(tx_packets, res.tx_packets)
        eq_(rx_bytes, res.rx_bytes)
        eq_(tx_bytes, res.tx_bytes)
        eq_(rx_dropped, res.rx_dropped)
        eq_(tx_dropped, res.tx_dropped)
        eq_(rx_errors, res.rx_errors)
        eq_(tx_errors, res.tx_errors)
        eq_(rx_frame_err, res.rx_frame_err)
        eq_(rx_over_err, res.rx_over_err)
        eq_(rx_crc_err, res.rx_crc_err)
        eq_(collisions, res.collisions)

    def _test_parser(self, port_no, rx_packets, tx_packets,
                     rx_bytes, tx_bytes, rx_dropped, tx_dropped,
                     rx_errors, tx_errors, rx_frame_err,
                     rx_over_err, rx_crc_err, collisions):

        # OFP_PORT_STATS_PACK_STR = '!H6xQQQQQQQQQQQQ'
        fmt = ofproto_v1_2.OFP_PORT_STATS_PACK_STR
        buf = pack(fmt, port_no, rx_packets, tx_packets, rx_bytes, tx_bytes,
                   rx_dropped, tx_dropped, rx_errors, tx_errors, rx_frame_err,
                   rx_over_err, rx_crc_err, collisions)

        res = OFPPortStats.parser(buf, 0)

        eq_(port_no, res.port_no)
        eq_(rx_packets, res.rx_packets)
        eq_(tx_packets, res.tx_packets)
        eq_(rx_bytes, res.rx_bytes)
        eq_(tx_bytes, res.tx_bytes)
        eq_(rx_dropped, res.rx_dropped)
        eq_(tx_dropped, res.tx_dropped)
        eq_(rx_errors, res.rx_errors)
        eq_(tx_errors, res.tx_errors)
        eq_(rx_frame_err, res.rx_frame_err)
        eq_(rx_over_err, res.rx_over_err)
        eq_(rx_crc_err, res.rx_crc_err)
        eq_(collisions, res.collisions)

    def test_parser_mid(self):
        port_no = 6606
        rx_packets = 5999980397101236279
        tx_packets = 2856480458895760962
        rx_bytes = 6170274950576278921
        tx_bytes = 8638420181865882538
        rx_dropped = 6982303461569875546
        tx_dropped = 661287462113808071
        rx_errors = 3422231811478788365
        tx_errors = 6283093430376743019
        rx_frame_err = 876072919806406283
        rx_over_err = 6525873760178941600
        rx_crc_err = 8303073210207070535
        collisions = 3409801584220270201

        self._test_parser(port_no, rx_packets, tx_packets, rx_bytes, tx_bytes,
                          rx_dropped, tx_dropped, rx_errors, tx_errors,
                          rx_frame_err, rx_over_err, rx_crc_err, collisions)

    def test_parser_max(self):
        port_no = 0xffffffff
        rx_packets = 0xffffffffffffffff
        tx_packets = 0xffffffffffffffff
        rx_bytes = 0xffffffffffffffff
        tx_bytes = 0xffffffffffffffff
        rx_dropped = 0xffffffffffffffff
        tx_dropped = 0xffffffffffffffff
        rx_errors = 0xffffffffffffffff
        tx_errors = 0xffffffffffffffff
        rx_frame_err = 0xffffffffffffffff
        rx_over_err = 0xffffffffffffffff
        rx_crc_err = 0xffffffffffffffff
        collisions = 0xffffffffffffffff

        self._test_parser(port_no, rx_packets, tx_packets, rx_bytes, tx_bytes,
                          rx_dropped, tx_dropped, rx_errors, tx_errors,
                          rx_frame_err, rx_over_err, rx_crc_err, collisions)

    def test_parser_min(self):
        port_no = 0
        rx_packets = 0
        tx_packets = 0
        rx_bytes = 0
        tx_bytes = 0
        rx_dropped = 0
        tx_dropped = 0
        rx_errors = 0
        tx_errors = 0
        rx_frame_err = 0
        rx_over_err = 0
        rx_crc_err = 0
        collisions = 0

        self._test_parser(port_no, rx_packets, tx_packets, rx_bytes, tx_bytes,
                          rx_dropped, tx_dropped, rx_errors, tx_errors,
                          rx_frame_err, rx_over_err, rx_crc_err, collisions)

    def _test_parser_p(self, port_no):
        port_no = port_no
        rx_packets = 5999980397101236279
        tx_packets = 2856480458895760962
        rx_bytes = 6170274950576278921
        tx_bytes = 8638420181865882538
        rx_dropped = 6982303461569875546
        tx_dropped = 661287462113808071
        rx_errors = 3422231811478788365
        tx_errors = 6283093430376743019
        rx_frame_err = 876072919806406283
        rx_over_err = 6525873760178941600
        rx_crc_err = 8303073210207070535
        collisions = 3409801584220270201

        self._test_parser(port_no, rx_packets, tx_packets, rx_bytes, tx_bytes,
                          rx_dropped, tx_dropped, rx_errors, tx_errors,
                          rx_frame_err, rx_over_err, rx_crc_err, collisions)

    def test_parser_p1(self):
        self._test_parser_p(ofproto_v1_2.OFPP_MAX)

    def test_parser_p2(self):
        self._test_parser_p(ofproto_v1_2.OFPP_IN_PORT)

    def test_parser_p3(self):
        self._test_parser_p(ofproto_v1_2.OFPP_TABLE)

    def test_parser_p4(self):
        self._test_parser_p(ofproto_v1_2.OFPP_NORMAL)

    def test_parser_p5(self):
        self._test_parser_p(ofproto_v1_2.OFPP_FLOOD)

    def test_parser_p6(self):
        self._test_parser_p(ofproto_v1_2.OFPP_ALL)

    def test_parser_p7(self):
        self._test_parser_p(ofproto_v1_2.OFPP_CONTROLLER)

    def test_parser_p8(self):
        self._test_parser_p(ofproto_v1_2.OFPP_LOCAL)


class TestOFPQueueStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueStatsRequest
    """

    # OFP_QUEUE_STATS_REQUEST_PACK_STR
    # '!II'...port_no, queue_id
    port_no = 41186
    queue_id = 6606

    def test_init(self):
        c = OFPQueueStatsRequest(_Datapath, self.port_no, self.queue_id)

        eq_(self.port_no, c.port_no)
        eq_(self.queue_id, c.queue_id)

    def _test_serialize(self, port_no, queue_id):
        c = OFPQueueStatsRequest(_Datapath, port_no, queue_id)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_QUEUE_STATS_REQUEST_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_QUEUE)
        eq_(res[5], 0)
        eq_(res[6], port_no)
        eq_(res[7], queue_id)

    def test_serialize_mid(self):
        self._test_serialize(self.port_no, self.queue_id)

    def test_serialize_max(self):
        self._test_serialize(0xffffffff, 0xffffffff)

    def test_serialize_min(self):
        self._test_serialize(0, 0)

    def test_serialize_p1(self):
        self._test_serialize(ofproto_v1_2.OFPP_MAX, self.queue_id)

    def test_serialize_p2(self):
        self._test_serialize(ofproto_v1_2.OFPP_IN_PORT, self.queue_id)

    def test_serialize_p3(self):
        self._test_serialize(ofproto_v1_2.OFPP_NORMAL, self.queue_id)

    def test_serialize_p4(self):
        self._test_serialize(ofproto_v1_2.OFPP_TABLE, self.queue_id)

    def test_serialize_p5(self):
        self._test_serialize(ofproto_v1_2.OFPP_FLOOD, self.queue_id)

    def test_serialize_p6(self):
        self._test_serialize(ofproto_v1_2.OFPP_ALL, self.queue_id)

    def test_serialize_p7(self):
        self._test_serialize(ofproto_v1_2.OFPP_CONTROLLER, self.queue_id)

    def test_serialize_p8(self):
        self._test_serialize(ofproto_v1_2.OFPP_LOCAL, self.queue_id)


class TestOFPQueueStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueStats
    """

    def test_init(self):
        port_no = 41186
        queue_id = 6606
        tx_bytes = 8638420181865882538
        tx_packets = 2856480458895760962
        tx_errors = 6283093430376743019

        res = OFPQueueStats(port_no, queue_id, tx_bytes,
                            tx_packets, tx_errors)

        eq_(port_no, res.port_no)
        eq_(queue_id, res.queue_id)
        eq_(tx_bytes, res.tx_bytes)
        eq_(tx_packets, res.tx_packets)
        eq_(tx_errors, res.tx_errors)

    def _test_parser(self, port_no, queue_id, tx_bytes,
                     tx_packets, tx_errors):

        # OFP_QUEUE_STATS_PACK_STR = '!IIQQQ'
        fmt = ofproto_v1_2.OFP_QUEUE_STATS_PACK_STR
        buf = pack(fmt, port_no, queue_id, tx_bytes, tx_packets, tx_errors)
        res = OFPQueueStats.parser(buf, 0)

        eq_(port_no, res.port_no)
        eq_(queue_id, res.queue_id)
        eq_(tx_bytes, res.tx_bytes)
        eq_(tx_packets, res.tx_packets)
        eq_(tx_errors, res.tx_errors)

    def test_parser_mid(self):
        port_no = 41186
        queue_id = 6606
        tx_bytes = 8638420181865882538
        tx_packets = 2856480458895760962
        tx_errors = 6283093430376743019

        self._test_parser(port_no, queue_id, tx_bytes,
                          tx_packets, tx_errors)

    def test_parser_max(self):
        port_no = 0xffffffff
        queue_id = 0xffffffff
        tx_bytes = 0xffffffffffffffff
        tx_packets = 0xffffffffffffffff
        tx_errors = 0xffffffffffffffff

        self._test_parser(port_no, queue_id, tx_bytes,
                          tx_packets, tx_errors)

    def test_parser_min(self):
        port_no = 0
        queue_id = 0
        tx_bytes = 0
        tx_packets = 0
        tx_errors = 0

        self._test_parser(port_no, queue_id, tx_bytes,
                          tx_packets, tx_errors)

    def _test_parser_p(self, port_no):
        queue_id = 6606
        tx_bytes = 8638420181865882538
        tx_packets = 2856480458895760962
        tx_errors = 6283093430376743019

        self._test_parser(port_no, queue_id, tx_bytes,
                          tx_packets, tx_errors)

    def test_parser_p1(self):
        self._test_parser_p(ofproto_v1_2.OFPP_MAX)

    def test_parser_p2(self):
        self._test_parser_p(ofproto_v1_2.OFPP_IN_PORT)

    def test_parser_p3(self):
        self._test_parser_p(ofproto_v1_2.OFPP_TABLE)

    def test_parser_p4(self):
        self._test_parser_p(ofproto_v1_2.OFPP_NORMAL)

    def test_parser_p5(self):
        self._test_parser_p(ofproto_v1_2.OFPP_FLOOD)

    def test_parser_p6(self):
        self._test_parser_p(ofproto_v1_2.OFPP_ALL)

    def test_parser_p7(self):
        self._test_parser_p(ofproto_v1_2.OFPP_CONTROLLER)

    def test_parser_p8(self):
        self._test_parser_p(ofproto_v1_2.OFPP_LOCAL)


class TestOFPBucketCounter(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBucketCounter
    """

    # OFP_BUCKET_COUNTER_PACK_STR = '!QQ'
    packet_count = 6489108735192644493
    byte_count = 7334344481123449724

    def test_init(self):
        c = OFPBucketCounter(self.packet_count, self.byte_count)

        eq_(self.packet_count, c.packet_count)
        eq_(self.byte_count, c.byte_count)

    def _test_parser(self, packet_count, byte_count):
        fmt = ofproto_v1_2.OFP_BUCKET_COUNTER_PACK_STR
        buf = pack(fmt, packet_count, byte_count)

        res = OFPBucketCounter.parser(buf, 0)
        eq_(packet_count, res.packet_count)
        eq_(byte_count, res.byte_count)

    def test_parser_mid(self):
        self._test_parser(self.packet_count, self.byte_count)

    def test_parser_max(self):
        packet_count = 18446744073709551615
        byte_count = 18446744073709551615
        self._test_parser(packet_count, byte_count)

    def test_parser_min(self):
        packet_count = 0
        byte_count = 0
        self._test_parser(packet_count, byte_count)


class TestOFPGroupStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupStatsRequest
    """

    # OFP_GROUP_STATS_REQUEST_PACK_STR
    # '!I4x'...group_id, pad(4)
    group_id = 6606

    def test_init(self):
        c = OFPGroupStatsRequest(_Datapath, self.group_id)
        eq_(self.group_id, c.group_id)

    def _test_serialize(self, group_id):
        c = OFPGroupStatsRequest(_Datapath, group_id)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_GROUP_STATS_REQUEST_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_GROUP)
        eq_(res[5], 0)
        eq_(res[6], group_id)

    def test_serialize_mid(self):
        self._test_serialize(self.group_id)

    def test_serialize_max(self):
        self._test_serialize(0xffffffff)

    def test_serialize_min(self):
        self._test_serialize(0)

    def test_serialize_p1(self):
        self._test_serialize(ofproto_v1_2.OFPG_MAX)

    def test_serialize_p2(self):
        self._test_serialize(ofproto_v1_2.OFPG_ALL)


class TestOFPGroupStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupStats
    """

    # OFP_GROUP_STATS_PACK_STR = '!H2xII4xQQ'
    length = ofproto_v1_2.OFP_GROUP_STATS_SIZE \
        + ofproto_v1_2.OFP_BUCKET_COUNTER_SIZE
    group_id = 6606
    ref_count = 2102
    packet_count = 6489108735192644493
    byte_count = 7334344481123449724

    # OFP_BUCKET_COUNTER_PACK_STR = '!QQ'
    buck_packet_count = 3519264449364891087
    buck_byte_count = 3123449724733434448
    bucket_counters = [OFPBucketCounter(buck_packet_count, buck_byte_count)]
    buf_bucket_counters = pack(ofproto_v1_2.OFP_BUCKET_COUNTER_PACK_STR,
                               buck_packet_count, buck_byte_count)

    fmt = ofproto_v1_2.OFP_GROUP_STATS_PACK_STR
    buf = pack(fmt, length, group_id, ref_count, packet_count, byte_count) \
        + buf_bucket_counters

    def test_init(self):
        c = OFPGroupStats(self.group_id, self.ref_count,
                          self.packet_count, self.byte_count,
                          self.bucket_counters)

        eq_(self.group_id, c.group_id)
        eq_(self.ref_count, c.ref_count)
        eq_(self.packet_count, c.packet_count)
        eq_(self.byte_count, c.byte_count)
        eq_(self.bucket_counters, c.bucket_counters)

    def _test_parser(self, group_id, ref_count, packet_count,
                     byte_count, bucket_counter_cnt):
        # OFP_GROUP_STATS_PACK_STR = '!H2xII4xQQ'
        length = ofproto_v1_2.OFP_GROUP_STATS_SIZE \
            + (ofproto_v1_2.OFP_BUCKET_COUNTER_SIZE * bucket_counter_cnt)
        fmt = ofproto_v1_2.OFP_GROUP_STATS_PACK_STR
        buf = pack(fmt, length, group_id, ref_count,
                   packet_count, byte_count)

        bucket_counters = []
        for b in range(bucket_counter_cnt):
            # OFP_BUCKET_COUNTER_PACK_STR = '!QQ'
            buck_packet_count = b
            buck_byte_count = b
            bucket_counter = OFPBucketCounter(buck_packet_count,
                                              buck_byte_count)
            bucket_counters.append(bucket_counter)
            buf_bucket_counters = \
                pack(ofproto_v1_2.OFP_BUCKET_COUNTER_PACK_STR,
                     buck_packet_count, buck_byte_count)
            buf += buf_bucket_counters

        res = OFPGroupStats.parser(buf, 0)

        # 32
        eq_(length, res.length)
        eq_(group_id, res.group_id)
        eq_(ref_count, res.ref_count)
        eq_(packet_count, res.packet_count)
        eq_(byte_count, res.byte_count)

        # 32 + 16 * bucket_counter_cnt < 65535 byte
        # bucket_counter_cnt <= 4093
        for b in range(bucket_counter_cnt):
            eq_(bucket_counters[b].packet_count,
                res.bucket_counters[b].packet_count)
            eq_(bucket_counters[b].byte_count,
                res.bucket_counters[b].byte_count)

    def test_parser_mid(self):
        bucket_counter_cnt = 2046
        self._test_parser(self.group_id, self.ref_count,
                          self.packet_count, self.byte_count,
                          bucket_counter_cnt)

    def test_parser_max(self):
        group_id = 4294967295
        ref_count = 4294967295
        packet_count = 18446744073709551615
        byte_count = 18446744073709551615
        bucket_counter_cnt = 4093
        self._test_parser(group_id, ref_count,
                          packet_count, byte_count,
                          bucket_counter_cnt)

    def test_parser_min(self):
        group_id = 0
        ref_count = 0
        packet_count = 0
        byte_count = 0
        bucket_counter_cnt = 0
        self._test_parser(group_id, ref_count,
                          packet_count, byte_count,
                          bucket_counter_cnt)


class TestOFPGroupDescStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupDescStatsRequest
    """

    def test_serialize(self):
        c = OFPGroupDescStatsRequest(_Datapath)
        c.serialize()

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_GROUP_DESC)
        eq_(res[5], 0)


class TestOFPGroupDescStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupDescStats
    """

    # OFP_GROUP_DESC_STATS_PACK_STR = '!HBxI'
    length = ofproto_v1_2.OFP_GROUP_DESC_STATS_SIZE \
        + ofproto_v1_2.OFP_BUCKET_SIZE \
        + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    type_ = 128
    group_id = 6606

    # OFP_ACTION (OFP_ACTION_OUTPUT)
    port = 0x00002ae0
    max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    actions = [OFPActionOutput(port, max_len)]
    buf_actions = bytearray()
    actions[0].serialize(buf_actions, 0)

    # OFP_BUCKET
    weight = 4386
    watch_port = 8006
    watch_group = 3
    buckets = [OFPBucket(weight, watch_port, watch_group, actions)]

    bucket_cnt = 1024

    def test_init(self):
        c = OFPGroupDescStats(self.type_, self.group_id, self.buckets)

        eq_(self.type_, c.type)
        eq_(self.group_id, c.group_id)
        eq_(self.buckets, c.buckets)

    def _test_parser(self, type_, group_id, bucket_cnt):
        # OFP_GROUP_DESC_STATS_PACK_STR = '!HBxI'
        length = ofproto_v1_2.OFP_GROUP_DESC_STATS_SIZE \
            + (ofproto_v1_2.OFP_BUCKET_SIZE
               + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE) * bucket_cnt

        fmt = ofproto_v1_2.OFP_GROUP_DESC_STATS_PACK_STR
        buf = pack(fmt, length, type_, group_id)

        buckets = []
        for b in range(bucket_cnt):
            # OFP_BUCKET
            weight = watch_port = watch_group = b
            bucket = OFPBucket(weight,
                               watch_port, watch_group,
                               self.actions)
            buckets.append(bucket)
            buf_buckets = bytearray()
            buckets[b].serialize(buf_buckets, 0)
            buf += str(buf_buckets)

        res = OFPGroupDescStats.parser(buf, 0)

        # 8 byte
        eq_(type_, res.type)
        eq_(group_id, res.group_id)

        # 8 + ( 16 + 16 ) * b < 65535 byte
        # b <= 2047 byte
        for b in range(bucket_cnt):
            eq_(buckets[b].weight, res.buckets[b].weight)
            eq_(buckets[b].watch_port, res.buckets[b].watch_port)
            eq_(buckets[b].watch_group, res.buckets[b].watch_group)
            eq_(buckets[b].actions[0].port,
                res.buckets[b].actions[0].port)
            eq_(buckets[b].actions[0].max_len,
                res.buckets[b].actions[0].max_len)

    def test_parser_mid(self):
        self._test_parser(self.type_, self.group_id, self.bucket_cnt)

    def test_parser_max(self):
        group_id = 4294967295
        type_ = 255
        bucket_cnt = 2047
        self._test_parser(type_, group_id, bucket_cnt)

    def test_parser_min(self):
        group_id = 0
        type_ = ofproto_v1_2.OFPGT_ALL
        bucket_cnt = 0
        self._test_parser(type_, group_id, bucket_cnt)

    def test_parser_p1(self):
        type_ = ofproto_v1_2.OFPGT_SELECT
        self._test_parser(type_, self.group_id, self.bucket_cnt)

    def test_parser_p2(self):
        type_ = ofproto_v1_2.OFPGT_INDIRECT
        self._test_parser(type_, self.group_id, self.bucket_cnt)

    def test_parser_p3(self):
        type_ = ofproto_v1_2.OFPGT_FF
        self._test_parser(type_, self.group_id, self.bucket_cnt)


class TestOFPGroupFeaturesStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupFeaturesStatsRequest
    """

    def test_serialize(self):
        c = OFPGroupFeaturesStatsRequest(_Datapath)
        c.serialize()

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_GROUP_FEATURES)
        eq_(res[5], 0)


class TestOFPGroupFeaturesStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupFeaturesStats
    """

    # OFP_GROUP_FEATURES_STATS_PACK_STR = '!II4I4I'
    types = ofproto_v1_2.OFPGT_ALL
    capabilities = ofproto_v1_2.OFPGFC_SELECT_WEIGHT
    max_groups = [1, 2, 3, 4]
    actions = [1 << ofproto_v1_2.OFPAT_OUTPUT,
               1 << ofproto_v1_2.OFPAT_COPY_TTL_OUT,
               1 << ofproto_v1_2.OFPAT_SET_MPLS_TTL,
               1 << ofproto_v1_2.OFPAT_PUSH_VLAN]

    def test_init(self):
        c = OFPGroupFeaturesStats(self.types, self.capabilities,
                                  self.max_groups, self.actions)
        eq_(self.types, c.types)
        eq_(self.capabilities, c.capabilities)
        eq_(self.max_groups, c.max_groups)
        eq_(self.actions, c.actions)

    def _test_parser(self, types, capabilities, max_groups, actions):

        buf = pack('!I', types) \
            + pack('!I', capabilities) \
            + pack('!I', max_groups[0]) \
            + pack('!I', max_groups[1]) \
            + pack('!I', max_groups[2]) \
            + pack('!I', max_groups[3]) \
            + pack('!I', actions[0]) \
            + pack('!I', actions[1]) \
            + pack('!I', actions[2]) \
            + pack('!I', actions[3])

        res = OFPGroupFeaturesStats.parser(buf, 0)

        # max_groups and actions after the parser is tuple
        eq_(types, res.types)
        eq_(capabilities, res.capabilities)
        eq_(max_groups, res.max_groups)
        eq_(actions, res.actions)

    def test_parser_mid(self):
        self._test_parser(self.types, self.capabilities,
                          self.max_groups, self.actions)

    def test_parser_max(self):
        types = 0b11111111111111111111111111111111
        capabilities = 0b11111111111111111111111111111111
        max_groups = [4294967295] * 4
        actions = [0b11111111111111111111111111111111] * 4
        self._test_parser(types, capabilities,
                          max_groups, actions)

    def test_parser_min(self):
        types = 0b00000000000000000000000000000000
        capabilities = 0b00000000000000000000000000000000
        max_groups = [0] * 4
        actions = [0b00000000000000000000000000000000] * 4
        self._test_parser(types, capabilities,
                          max_groups, actions)

    def _test_parser_p(self, types, capabilities, actions):
        self._test_parser(types, capabilities,
                          self.max_groups, actions)

    def test_parser_p1(self):
        actions = [1 << ofproto_v1_2.OFPAT_COPY_TTL_IN,
                   1 << ofproto_v1_2.OFPAT_DEC_MPLS_TTL,
                   1 << ofproto_v1_2.OFPAT_POP_VLAN,
                   1 << ofproto_v1_2.OFPAT_PUSH_MPLS]
        self._test_parser_p(1 << ofproto_v1_2.OFPGT_ALL,
                            ofproto_v1_2.OFPGFC_CHAINING,
                            actions)

    def test_parser_p2(self):
        actions = [1 << ofproto_v1_2.OFPAT_POP_MPLS,
                   1 << ofproto_v1_2.OFPAT_SET_QUEUE,
                   1 << ofproto_v1_2.OFPAT_GROUP,
                   1 << ofproto_v1_2.OFPAT_SET_NW_TTL]
        self._test_parser_p(1 << ofproto_v1_2.OFPGT_SELECT,
                            ofproto_v1_2.OFPGFC_SELECT_WEIGHT,
                            actions)

    def test_parser_p3(self):
        actions = [1 << ofproto_v1_2.OFPAT_DEC_NW_TTL,
                   1 << ofproto_v1_2.OFPAT_SET_FIELD,
                   1 << ofproto_v1_2.OFPAT_GROUP,
                   1 << ofproto_v1_2.OFPAT_SET_NW_TTL]
        self._test_parser_p(1 << ofproto_v1_2.OFPGT_SELECT,
                            ofproto_v1_2.OFPGFC_SELECT_LIVENESS,
                            actions)

    def test_parser_p4(self):
        self._test_parser_p(1 << ofproto_v1_2.OFPGT_INDIRECT,
                            ofproto_v1_2.OFPGFC_CHAINING,
                            self.actions)

    def test_parser_p5(self):
        self._test_parser_p(1 << ofproto_v1_2.OFPGT_FF,
                            ofproto_v1_2.OFPGFC_CHAINING_CHECKS,
                            self.actions)


class TestOFPQueueGetConfigRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueGetConfigRequest
    """

    # OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR v1.2
    # '!I4x'...port, pad(4)
    port = 41186

    def test_init(self):
        c = OFPQueueGetConfigRequest(_Datapath, self.port)
        eq_(self.port, c.port)

    def _test_serialize(self, port):
        c = OFPQueueGetConfigRequest(_Datapath, port)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR \
            + ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR[1:]

        res = struct.unpack(fmt, str(c.buf))
        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST)
        eq_(res[2], len(c.buf))
        eq_(res[3], 0)
        eq_(res[4], port)

    def test_serialize_mid(self):
        self._test_serialize(self.port)

    def test_serialize_max(self):
        self._test_serialize(0xffffffff)

    def test_serialize_min(self):
        self._test_serialize(0)

    def test_serialize_p1(self):
        self._test_serialize(ofproto_v1_2.OFPP_MAX)


class TestOFPQueuePropHeader(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueuePropHeader
    """

    # OFP_QUEUE_PROP_HEADER_PACK_STR = '!HH4x'
    property_ = 1
    len_ = 10

    def test_init(self):
        c = OFPQueuePropHeader(self.property_, self.len_)
        eq_(self.property_, c.property)
        eq_(self.len_, c.len)

    def _test_serialize(self, property_, len_):
        c = OFPQueuePropHeader(property_, len_)
        buf = bytearray()
        c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], property_)
        eq_(res[1], len_)

    def test_serialize_mid(self):
        self._test_serialize(self.property_, self.len_)

    def test_serialize_max(self):
        self._test_serialize(0xffff, 0xffff)

    def test_serialize_min(self):
        self._test_serialize(0, 0)


class TestOFPPacketQueue(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPacketQueue
    """

    def test_init(self):
        queue_id = 1
        port = 2
        len_ = 3
        properties = [4, 5, 6]
        c = OFPPacketQueue(queue_id, port, properties)

        eq_(queue_id, c.queue_id)
        eq_(port, c.port)
        eq_(properties, c.properties)

    def _test_parser(self, queue_id, port, prop_cnt):
        # OFP_PACKET_QUEUE_PACK_STR = '!IIH6x'
        fmt = ofproto_v1_2.OFP_PACKET_QUEUE_PACK_STR
        queue_len = ofproto_v1_2.OFP_PACKET_QUEUE_SIZE \
            + ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_SIZE * prop_cnt

        buf = pack(fmt, queue_id, port, queue_len)

        for rate in range(prop_cnt):
            # OFP_QUEUE_PROP_HEADER_PACK_STR = '!HH4x'
            fmt = ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR
            prop_type = ofproto_v1_2.OFPQT_MIN_RATE
            prop_len = ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_SIZE
            buf += pack(fmt, prop_type, prop_len)

            # OFP_QUEUE_PROP_MIN_RATE_PACK_STR = '!H6x'
            fmt = ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_PACK_STR
            prop_rate = rate
            buf += pack(fmt, prop_rate)

        res = OFPPacketQueue.parser(buf, 0)

        eq_(queue_id, res.queue_id)
        eq_(port, res.port)
        eq_(queue_len, res.len)
        eq_(prop_cnt, len(res.properties))

        for rate, p in enumerate(res.properties):
            eq_(prop_type, p.property)
            eq_(prop_len, p.len)
            eq_(rate, p.rate)

    def test_parser_mid(self):
        queue_id = 1
        port = 2
        prop_cnt = 2
        self._test_parser(queue_id, port, prop_cnt)

    def test_parser_max(self):
        # queue_len format is 'H' < number 65535
        #
        # queue_len = OFP_PACKET_QUEUE_SIZE(16)
        #     + OFP_QUEUE_PROP_MIN_RATE_SIZE(16) * N
        # max_prop_cnt = (65535 - 16) / 16 = 4094
        queue_id = 0xffffffff
        port = 0xffffffff
        prop_cnt = 4094
        self._test_parser(queue_id, port, prop_cnt)

    def test_parser_min(self):
        queue_id = 0
        port = 0
        prop_cnt = 0
        self._test_parser(queue_id, port, prop_cnt)


class TestOFPQueuePropMinRate(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueuePropMinRate
    """

    def _test_parser(self, rate):
        # OFP_QUEUE_PROP_MIN_RATE_PACK_STR...H6x
        buf = pack(ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_PACK_STR, rate)
        res = OFPQueuePropMinRate.parser(buf, 0)
        eq_(rate, res.rate)

    def test_parser_mid(self):
        self._test_parser(32768)

    def test_parser_max(self):
        self._test_parser(0xffff)

    def test_parser_min(self):
        self._test_parser(0)


class TestOFPQueuePropMaxRate(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueuePropMaxRate
    """

    rate = 100
    buf = pack(ofproto_v1_2.OFP_QUEUE_PROP_MAX_RATE_PACK_STR, rate)
    c = OFPQueuePropMaxRate(rate)

    def _test_parser(self, rate):
        # OFP_QUEUE_PROP_MAX_RATE_PACK_STR...H6x
        buf = pack(ofproto_v1_2.OFP_QUEUE_PROP_MAX_RATE_PACK_STR, rate)
        res = OFPQueuePropMaxRate.parser(buf, 0)
        eq_(rate, res.rate)

    def test_parser_mid(self):
        self._test_parser(100)

    def test_parser_max(self):
        self._test_parser(0xffff)

    def test_parser_min(self):
        self._test_parser(0)


class TestOFPQueueGetConfigReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueGetConfigReply
    """

    def _test_parser(self, xid, port, queue_cnt):
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REPLY

        queues_len = 0
        for q in range(queue_cnt):
            queues_len += ofproto_v1_2.OFP_PACKET_QUEUE_SIZE
            queues_len += ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_SIZE

        msg_len = ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REPLY_SIZE \
            + queues_len

        # OFP_HEADER_PACK_STR = '!BBHI'
        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR = '!I4x'
        fmt = ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR
        buf += pack(fmt, port)

        queues = []
        for q in range(1, queue_cnt + 1):
            # OFP_PACKET_QUEUE_PACK_STR = '!IIH6x'
            fmt = ofproto_v1_2.OFP_PACKET_QUEUE_PACK_STR
            queue_id = q * 100
            queue_port = q
            queue_len = ofproto_v1_2.OFP_PACKET_QUEUE_SIZE \
                + ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_SIZE
            buf += pack(fmt, queue_id, queue_port, queue_len)

            # OFP_QUEUE_PROP_HEADER_PACK_STR = '!HH4x'
            fmt = ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR
            prop_type = ofproto_v1_2.OFPQT_MIN_RATE
            prop_len = ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_SIZE
            buf += pack(fmt, prop_type, prop_len)

            # OFP_QUEUE_PROP_MIN_RATE_PACK_STR = '!H6x'
            fmt = ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_PACK_STR
            prop_rate = q * 10
            buf += pack(fmt, prop_rate)

            queue = {'queue_id': queue_id, 'queue_port': queue_port,
                     'queue_len': queue_len, 'prop_type': prop_type,
                     'prop_len': prop_len, 'prop_rate': prop_rate}
            queues.append(queue)

        res = OFPQueueGetConfigReply.parser(object, version, msg_type,
                                            msg_len, xid, buf)
        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)
        eq_(port, res.port)
        eq_(queue_cnt, len(res.queues))

        for i, val in enumerate(res.queues):
            c = queues[i]
            eq_(c['queue_id'], val.queue_id)
            eq_(c['queue_port'], val.port)
            eq_(c['queue_len'], val.len)
            eq_(1, len(val.properties))

            prop = val.properties[0]
            eq_(c['prop_type'], prop.property)
            eq_(c['prop_len'], prop.len)
            eq_(c['prop_rate'], prop.rate)

    def test_parser_mid(self):
        self._test_parser(2495926989, 65037, 2)

    def test_parser_max(self):
        # total msg_len = 65520
        self._test_parser(0xffffffff, 0xffffffff, 2047)

    def test_parser_min(self):
        self._test_parser(0, 0, 0)


class TestOFPBarrierRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBarrierRequest
    """
    def test_serialize(self):
        c = OFPBarrierRequest(_Datapath)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_BARRIER_REQUEST, c.msg_type)
        eq_(ofproto_v1_2.OFP_HEADER_SIZE, c.msg_len)
        eq_(0, c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        res = unpack(fmt, str(c.buf))
        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_BARRIER_REQUEST, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, c.xid)


class TestOFPBarrierReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBarrierReply
    """

    def _test_parser(self, xid):
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_BARRIER_REPLY
        msg_len = ofproto_v1_2.OFP_HEADER_SIZE

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        res = OFPBarrierReply.parser(object, version, msg_type,
                                     msg_len, xid, buf)
        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)

    def test_parser_mid(self):
        self._test_parser(2147483648)

    def test_parser_max(self):
        self._test_parser(0xffffffff)

    def test_parser_min(self):
        self._test_parser(0)


class TestOFPRoleRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPRoleRequest
    """

    # OFP_ROLE_REQUEST_PACK_STR
    # '!I4xQ'...role, pad(4), generation_id
    role = 2147483648
    generation_id = 1270985291017894273

    def test_init(self):
        c = OFPRoleRequest(_Datapath, self.role, self.generation_id)
        eq_(self.role, c.role)
        eq_(self.generation_id, c.generation_id)

    def _test_serialize(self, role, generation_id):
        c = OFPRoleRequest(_Datapath, role, generation_id)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_ROLE_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ROLE_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_ROLE_REQUEST, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(role, res[4])
        eq_(generation_id, res[5])

    def test_serialize_mid(self):
        self._test_serialize(self.role, self.generation_id)

    def test_serialize_max(self):
        role = 0xffffffff
        generation_id = 0xffffffffffffffff
        self._test_serialize(role, generation_id)

    def test_serialize_min(self):
        role = 0
        generation_id = 0
        self._test_serialize(role, generation_id)

    def test_serialize_p1(self):
        role = ofproto_v1_2.OFPCR_ROLE_EQUAL
        self._test_serialize(role, self.generation_id)

    def test_serialize_p2(self):
        role = ofproto_v1_2.OFPCR_ROLE_MASTER
        self._test_serialize(role, self.generation_id)

    def test_serialize_p3(self):
        role = ofproto_v1_2.OFPCR_ROLE_SLAVE
        self._test_serialize(role, self.generation_id)


class TestOFPRoleReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPRoleReply
    """

    # OFP_ROLE_REQUEST_PACK_STR
    # '!I4xQ'...role, pad(4), generation_id
    #role = ofproto_v1_2.OFPCR_ROLE_NOCHANGE
    role = 2147483648
    generation_id = 1270985291017894273

    def _test_parser(self, role, generation_id):
        # OFP_HEADER_PACK_STR
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_ROLE_REPLY
        msg_len = ofproto_v1_2.OFP_ROLE_REQUEST_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        fmt = ofproto_v1_2.OFP_ROLE_REQUEST_PACK_STR
        buf += pack(fmt, role, generation_id)

        res = OFPRoleReply.parser(object, version, msg_type, msg_len, xid, buf)

        # OFP_HEADER_PACK_STR
        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)

        # OFP_ROLE_REQUEST_PACK_STR
        eq_(role, res.role)
        eq_(generation_id, res.generation_id)

    def test_parser_mid(self):
        self._test_parser(self.role, self.generation_id)

    def test_parser_max(self):
        role = 0xffffffff
        generation_id = 0xffffffffffffffff
        self._test_parser(role, generation_id)

    def test_parser_min(self):
        role = ofproto_v1_2.OFPCR_ROLE_NOCHANGE
        generation_id = 0
        self._test_parser(role, generation_id)

    def test_parser_p1(self):
        role = ofproto_v1_2.OFPCR_ROLE_EQUAL
        self._test_parser(role, self.generation_id)

    def test_parser_p2(self):
        role = ofproto_v1_2.OFPCR_ROLE_MASTER
        self._test_parser(role, self.generation_id)

    def test_parser_p3(self):
        role = ofproto_v1_2.OFPCR_ROLE_SLAVE
        self._test_parser(role, self.generation_id)


class TestOFPMatch(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPMatch
    """

    def test_init(self):
        res = OFPMatch()

        # wc check
        eq_(res._wc.metadata_mask, 0)
        eq_(res._wc.dl_dst_mask, 0)
        eq_(res._wc.dl_src_mask, 0)
        eq_(res._wc.vlan_vid_mask, 0)
        eq_(res._wc.ipv4_src_mask, 0)
        eq_(res._wc.ipv4_dst_mask, 0)
        eq_(res._wc.arp_spa_mask, 0)
        eq_(res._wc.arp_tpa_mask, 0)
        eq_(res._wc.arp_sha_mask, 0)
        eq_(res._wc.arp_tha_mask, 0)
        eq_(res._wc.ipv6_src_mask, [])
        eq_(res._wc.ipv6_dst_mask, [])
        eq_(res._wc.ipv6_flabel_mask, 0)
        eq_(res._wc.wildcards, (1 << 64) - 1)

        # flow check
        eq_(res._flow.in_port, 0)
        eq_(res._flow.in_phy_port, 0)
        eq_(res._flow.metadata, 0)
        eq_(res._flow.dl_dst, mac.DONTCARE)
        eq_(res._flow.dl_src, mac.DONTCARE)
        eq_(res._flow.dl_type, 0)
        eq_(res._flow.vlan_vid, 0)
        eq_(res._flow.vlan_pcp, 0)
        eq_(res._flow.ip_dscp, 0)
        eq_(res._flow.ip_ecn, 0)
        eq_(res._flow.ip_proto, 0)
        eq_(res._flow.ipv4_src, 0)
        eq_(res._flow.ipv4_dst, 0)
        eq_(res._flow.tcp_src, 0)
        eq_(res._flow.tcp_dst, 0)
        eq_(res._flow.udp_src, 0)
        eq_(res._flow.udp_dst, 0)
        eq_(res._flow.sctp_src, 0)
        eq_(res._flow.sctp_dst, 0)
        eq_(res._flow.icmpv4_type, 0)
        eq_(res._flow.icmpv4_code, 0)
        eq_(res._flow.arp_op, 0)
        eq_(res._flow.arp_spa, 0)
        eq_(res._flow.arp_tpa, 0)
        eq_(res._flow.arp_sha, 0)
        eq_(res._flow.arp_tha, 0)
        eq_(res._flow.ipv6_src, [])
        eq_(res._flow.ipv6_dst, [])
        eq_(res._flow.ipv6_flabel, 0)
        eq_(res._flow.icmpv6_type, 0)
        eq_(res._flow.icmpv6_code, 0)
        eq_(res._flow.ipv6_nd_target, [])
        eq_(res._flow.ipv6_nd_sll, 0)
        eq_(res._flow.ipv6_nd_tll, 0)
        eq_(res._flow.mpls_label, 0)
        eq_(res._flow.mpls_tc, 0)

        # flow check
        eq_(res.fields, [])

    def _test_serialize_and_parser(self, match, header, value, mask=None):
        cls_ = OFPMatchField._FIELDS_HEADERS.get(header)
        pack_str = cls_.pack_str.replace('!', '')
        fmt = '!HHI' + pack_str

        # serialize
        buf = bytearray()
        length = match.serialize(buf, 0)
        eq_(length, len(buf))
        if mask and len(buf) > calcsize(fmt):
            fmt += pack_str

        res = list(unpack_from(fmt, str(buf), 0)[3:])
        if type(value) is list:
            res_value = res[:calcsize(pack_str) / 2]
            eq_(res_value, value)
            if mask:
                res_mask = res[calcsize(pack_str) / 2:]
                eq_(res_mask, mask)
        else:
            res_value = res.pop(0)
            if cls_.__name__ == 'MTVlanVid':
                eq_(res_value, value | ofproto_v1_2.OFPVID_PRESENT)
            else:
                eq_(res_value, value)
            if mask and res and res[0]:
                res_mask = res[0]
                eq_(res_mask, mask)

        # parser
        res = match.parser(str(buf), 0)
        eq_(res.type, ofproto_v1_2.OFPMT_OXM)
        eq_(res.fields[0].header, header)
        eq_(res.fields[0].value, value)
        if mask and res.fields[0].mask is not None:
            eq_(res.fields[0].mask, mask)

        # to_jsondict
        jsondict = match.to_jsondict()

        # from_jsondict
        match2 = match.from_jsondict(jsondict["OFPMatch"])
        buf2 = bytearray()
        match2.serialize(buf2, 0)
        eq_(str(match), str(match2))
        eq_(buf, buf2)

    def test_parse_unknown_field(self):
        buf = bytearray()
        ofproto_parser.msg_pack_into('!HH', buf, 0, ofproto_v1_2.OFPMT_OXM,
                                     4 + 6)
        header = ofproto_v1_2.oxm_tlv_header(36, 2)
        ofproto_parser.msg_pack_into('!IH', buf, 4, header, 1)
        header = ofproto_v1_2.OXM_OF_ETH_TYPE
        ofproto_v1_2_parser.msg_pack_into('!IH', buf, 10, header, 1)

        match = OFPMatch()
        res = match.parser(str(buf), 0)

    # set_in_port
    def _test_set_in_port(self, in_port):
        header = ofproto_v1_2.OXM_OF_IN_PORT
        match = OFPMatch()
        match.set_in_port(in_port)
        self._test_serialize_and_parser(match, header, in_port)

    def test_set_in_port_mid(self):
        self._test_set_in_port(0xff8)

    def test_set_in_port_max(self):
        self._test_set_in_port(0xffffffff)

    def test_set_in_port_min(self):
        self._test_set_in_port(0)

    # set_in_phy_port
    def _test_set_in_phy_port(self, phy_port):
        header = ofproto_v1_2.OXM_OF_IN_PHY_PORT
        match = OFPMatch()
        match.set_in_phy_port(phy_port)
        self._test_serialize_and_parser(match, header, phy_port)

    def test_set_in_phy_port_mid(self):
        self._test_set_in_phy_port(1)

    def test_set_in_phy_port_max(self):
        self._test_set_in_phy_port(0xffffffff)

    def test_set_in_phy_port_min(self):
        self._test_set_in_phy_port(0)

    # set_metadata
    def _test_set_metadata(self, metadata, mask=None):
        header = ofproto_v1_2.OXM_OF_METADATA
        match = OFPMatch()
        if mask is None:
            match.set_metadata(metadata)
        else:
            if (mask + 1) >> 64 != 1:
                header = ofproto_v1_2.OXM_OF_METADATA_W
            match.set_metadata_masked(metadata, mask)
            metadata &= mask
        self._test_serialize_and_parser(match, header, metadata, mask)

    def test_set_metadata_mid(self):
        self._test_set_metadata(0x1212121212121212)

    def test_set_metadata_max(self):
        self._test_set_metadata(0xffffffffffffffff)

    def test_set_metadata_min(self):
        self._test_set_metadata(0)

    def test_set_metadata_masked_mid(self):
        self._test_set_metadata(0x1212121212121212, 0xff00ff00ff00ff00)

    def test_set_metadata_masked_max(self):
        self._test_set_metadata(0x1212121212121212, 0xffffffffffffffff)

    def test_set_metadata_masked_min(self):
        self._test_set_metadata(0x1212121212121212, 0)

    # set_dl_dst
    def _test_set_dl_dst(self, dl_dst, mask=None):
        header = ofproto_v1_2.OXM_OF_ETH_DST
        match = OFPMatch()
        dl_dst = mac.haddr_to_bin(dl_dst)
        if mask is None:
            match.set_dl_dst(dl_dst)
        else:
            header = ofproto_v1_2.OXM_OF_ETH_DST_W
            mask = mac.haddr_to_bin(mask)
            match.set_dl_dst_masked(dl_dst, mask)
            dl_dst = mac.haddr_bitand(dl_dst, mask)
        self._test_serialize_and_parser(match, header, dl_dst, mask)

    def test_set_dl_dst_mid(self):
        self._test_set_dl_dst('e2:7a:09:79:0b:0f')

    def test_set_dl_dst_max(self):
        self._test_set_dl_dst('ff:ff:ff:ff:ff:ff')

    def test_set_dl_dst_min(self):
        self._test_set_dl_dst('00:00:00:00:00:00')

    def test_set_dl_dst_masked_mid(self):
        self._test_set_dl_dst('e2:7a:09:79:0b:0f', 'ff:00:ff:00:ff:00')

    def test_set_dl_dst_masked_max(self):
        self._test_set_dl_dst('e2:7a:09:79:0b:0f', 'ff:ff:ff:ff:ff:ff')

    def test_set_dl_dst_masked_min(self):
        self._test_set_dl_dst('e2:7a:09:79:0b:0f', '00:00:00:00:00:00')

    # set_dl_src
    def _test_set_dl_src(self, dl_src, mask=None):
        header = ofproto_v1_2.OXM_OF_ETH_SRC
        match = OFPMatch()
        dl_src = mac.haddr_to_bin(dl_src)
        if mask is None:
            match.set_dl_src(dl_src)
        else:
            header = ofproto_v1_2.OXM_OF_ETH_SRC_W
            mask = mac.haddr_to_bin(mask)
            match.set_dl_src_masked(dl_src, mask)
            dl_src = mac.haddr_bitand(dl_src, mask)
        self._test_serialize_and_parser(match, header, dl_src, mask)

    def test_set_dl_src_mid(self):
        self._test_set_dl_src('d0:98:79:b4:75:b5')

    def test_set_dl_src_max(self):
        self._test_set_dl_src('ff:ff:ff:ff:ff:ff')

    def test_set_dl_src_min(self):
        self._test_set_dl_src('00:00:00:00:00:00')

    def test_set_dl_src_masked_mid(self):
        self._test_set_dl_src('d0:98:79:b4:75:b5', 'f0:f0:f0:f0:f0:f0')

    def test_set_dl_src_masked_max(self):
        self._test_set_dl_src('d0:98:79:b4:75:b5', 'ff:ff:ff:ff:ff:ff')

    def test_set_dl_src_masked_min(self):
        self._test_set_dl_src('d0:98:79:b4:75:b5', '00:00:00:00:00:00')

    # set_dl_type
    def _test_set_dl_type(self, value):
        header = ofproto_v1_2.OXM_OF_ETH_TYPE
        match = OFPMatch()
        match.set_dl_type(value)
        self._test_serialize_and_parser(match, header, value)

    def test_set_dl_type_mid(self):
        self._test_set_dl_type(0x7fb6)

    def test_set_dl_type_max(self):
        self._test_set_dl_type(0xffff)

    def test_set_dl_type_min(self):
        self._test_set_dl_type(0)

    def test_set_dl_type_ip(self):
        value = ether.ETH_TYPE_IP
        self._test_set_dl_type(value)

    def test_set_dl_type_arp(self):
        value = ether.ETH_TYPE_ARP
        self._test_set_dl_type(value)

    def test_set_dl_type_ipv6(self):
        value = ether.ETH_TYPE_IPV6
        self._test_set_dl_type(value)

    def test_set_dl_type_slow(self):
        value = ether.ETH_TYPE_SLOW
        self._test_set_dl_type(value)

    # set_vlan_vid
    def _test_set_vlan_vid(self, vid, mask=None):
        header = ofproto_v1_2.OXM_OF_VLAN_VID
        match = OFPMatch()
        if mask is None:
            match.set_vlan_vid(vid)
        else:
            header = ofproto_v1_2.OXM_OF_VLAN_VID_W
            match.set_vlan_vid_masked(vid, mask)
        self._test_serialize_and_parser(match, header, vid, mask)

    def test_set_vlan_vid_mid(self):
        self._test_set_vlan_vid(2047)

    def test_set_vlan_vid_max(self):
        self._test_set_vlan_vid(0xfff)

    def test_set_vlan_vid_min(self):
        self._test_set_vlan_vid(0)

    def test_set_vlan_vid_masked_mid(self):
        self._test_set_vlan_vid(2047, 0xf0f)

    def test_set_vlan_vid_masked_max(self):
        self._test_set_vlan_vid(2047, 0xfff)

    def test_set_vlan_vid_masked_min(self):
        self._test_set_vlan_vid(2047, 0)

    # set_vlan_pcp
    def _test_set_vlan_pcp(self, pcp):
        header = ofproto_v1_2.OXM_OF_VLAN_PCP
        match = OFPMatch()
        match.set_vlan_pcp(pcp)
        self._test_serialize_and_parser(match, header, pcp)

    def test_set_vlan_pcp_mid(self):
        self._test_set_vlan_pcp(5)

    def test_set_vlan_pcp_max(self):
        self._test_set_vlan_pcp(7)

    def test_set_vlan_pcp_min(self):
        self._test_set_vlan_pcp(0)

    # set_ip_dscp
    def _test_set_ip_dscp(self, ip_dscp):
        header = ofproto_v1_2.OXM_OF_IP_DSCP
        match = OFPMatch()
        match.set_ip_dscp(ip_dscp)
        self._test_serialize_and_parser(match, header, ip_dscp)

    def test_set_ip_dscp_mid(self):
        self._test_set_ip_dscp(36)

    def test_set_ip_dscp_max(self):
        self._test_set_ip_dscp(63)

    def test_set_ip_dscp_min(self):
        self._test_set_ip_dscp(0)

    # set_ip_ecn
    def _test_set_ip_ecn(self, ip_ecn):
        header = ofproto_v1_2.OXM_OF_IP_ECN
        match = OFPMatch()
        match.set_ip_ecn(ip_ecn)
        self._test_serialize_and_parser(match, header, ip_ecn)

    def test_set_ip_ecn_mid(self):
        self._test_set_ip_ecn(1)

    def test_set_ip_ecn_max(self):
        self._test_set_ip_ecn(3)

    def test_set_ip_ecn_min(self):
        self._test_set_ip_ecn(0)

    # set_ip_proto
    def _test_set_ip_proto(self, ip_proto):
        header = ofproto_v1_2.OXM_OF_IP_PROTO
        match = OFPMatch()
        match.set_ip_proto(ip_proto)
        self._test_serialize_and_parser(match, header, ip_proto)

    def test_set_ip_proto_mid(self):
        self._test_set_ip_proto(6)

    def test_set_ip_proto_max(self):
        self._test_set_ip_proto(0xff)

    def test_set_ip_proto_min(self):
        self._test_set_ip_proto(0)

    # set_ipv4_src
    def _test_set_ipv4_src(self, ip, mask=None):
        header = ofproto_v1_2.OXM_OF_IPV4_SRC
        match = OFPMatch()
        ip = unpack('!I', socket.inet_aton(ip))[0]
        if mask is None:
            match.set_ipv4_src(ip)
        else:
            mask = unpack('!I', socket.inet_aton(mask))[0]
            if (mask + 1) >> 32 != 1:
                header = ofproto_v1_2.OXM_OF_IPV4_SRC_W
            match.set_ipv4_src_masked(ip, mask)
        self._test_serialize_and_parser(match, header, ip, mask)

    def test_set_ipv4_src_mid(self):
        self._test_set_ipv4_src('192.168.196.250')

    def test_set_ipv4_src_max(self):
        self._test_set_ipv4_src('255.255.255.255')

    def test_set_ipv4_src_min(self):
        self._test_set_ipv4_src('0.0.0.0')

    def test_set_ipv4_src_masked_mid(self):
        self._test_set_ipv4_src('192.168.196.250', '255.255.0.0')

    def test_set_ipv4_src_masked_max(self):
        self._test_set_ipv4_src('192.168.196.250', '255.255.255.255')

    def test_set_ipv4_src_masked_min(self):
        self._test_set_ipv4_src('192.168.196.250', '0.0.0.0')

    # set_ipv4_dst
    def _test_set_ipv4_dst(self, ip, mask=None):
        header = ofproto_v1_2.OXM_OF_IPV4_DST
        match = OFPMatch()
        ip = unpack('!I', socket.inet_aton(ip))[0]
        if mask is None:
            match.set_ipv4_dst(ip)
        else:
            mask = unpack('!I', socket.inet_aton(mask))[0]
            if (mask + 1) >> 32 != 1:
                header = ofproto_v1_2.OXM_OF_IPV4_DST_W
            match.set_ipv4_dst_masked(ip, mask)
        self._test_serialize_and_parser(match, header, ip, mask)

    def test_set_ipv4_dst_mid(self):
        self._test_set_ipv4_dst('192.168.196.250')

    def test_set_ipv4_dst_max(self):
        self._test_set_ipv4_dst('255.255.255.255')

    def test_set_ipv4_dst_min(self):
        self._test_set_ipv4_dst('0.0.0.0')

    def test_set_ipv4_dst_masked_mid(self):
        self._test_set_ipv4_dst('192.168.196.250', '255.255.0.0')

    def test_set_ipv4_dst_masked_max(self):
        self._test_set_ipv4_dst('192.168.196.250', '255.255.255.255')

    def test_set_ipv4_dst_masked_min(self):
        self._test_set_ipv4_dst('192.168.196.250', '0.0.0.0')

    # set_tcp_src
    def _test_set_tcp_src(self, tcp_src):
        header = ofproto_v1_2.OXM_OF_TCP_SRC
        match = OFPMatch()
        match.set_tcp_src(tcp_src)
        self._test_serialize_and_parser(match, header, tcp_src)

    def test_set_tcp_src_mid(self):
        self._test_set_tcp_src(1103)

    def test_set_tcp_src_max(self):
        self._test_set_tcp_src(0xffff)

    def test_set_tcp_src_min(self):
        self._test_set_tcp_src(0)

    # set_tcp_dst
    def _test_set_tcp_dst(self, tcp_dst):
        header = ofproto_v1_2.OXM_OF_TCP_DST
        match = OFPMatch()
        match.set_tcp_dst(tcp_dst)
        self._test_serialize_and_parser(match, header, tcp_dst)

    def test_set_tcp_dst_mid(self):
        self._test_set_tcp_dst(236)

    def test_set_tcp_dst_max(self):
        self._test_set_tcp_dst(0xffff)

    def test_set_tcp_dst_min(self):
        self._test_set_tcp_dst(0)

    # set_udp_src
    def _test_set_udp_src(self, udp_src):
        header = ofproto_v1_2.OXM_OF_UDP_SRC
        match = OFPMatch()
        match.set_udp_src(udp_src)
        self._test_serialize_and_parser(match, header, udp_src)

    def test_set_udp_src_mid(self):
        self._test_set_udp_src(56617)

    def test_set_udp_src_max(self):
        self._test_set_udp_src(0xffff)

    def test_set_udp_src_min(self):
        self._test_set_udp_src(0)

    # set_udp_dst
    def _test_set_udp_dst(self, udp_dst):
        header = ofproto_v1_2.OXM_OF_UDP_DST
        match = OFPMatch()
        match.set_udp_dst(udp_dst)
        self._test_serialize_and_parser(match, header, udp_dst)

    def test_set_udp_dst_mid(self):
        self._test_set_udp_dst(61278)

    def test_set_udp_dst_max(self):
        self._test_set_udp_dst(0xffff)

    def test_set_udp_dst_min(self):
        self._test_set_udp_dst(0)

    # set_sctp_src
    def _test_set_sctp_src(self, sctp_src):
        header = ofproto_v1_2.OXM_OF_SCTP_SRC
        match = OFPMatch()
        match.set_sctp_src(sctp_src)
        self._test_serialize_and_parser(match, header, sctp_src)

    def test_set_sctp_src_mid(self):
        self._test_set_sctp_src(9999)

    def test_set_sctp_src_max(self):
        self._test_set_sctp_src(0xffff)

    def test_set_sctp_src_min(self):
        self._test_set_sctp_src(0)

    # set_sctp_dst
    def _test_set_sctp_dst(self, sctp_dst):
        header = ofproto_v1_2.OXM_OF_SCTP_DST
        match = OFPMatch()
        match.set_sctp_dst(sctp_dst)
        self._test_serialize_and_parser(match, header, sctp_dst)

    def test_set_sctp_dst_mid(self):
        self._test_set_sctp_dst(1234)

    def test_set_sctp_dst_max(self):
        self._test_set_sctp_dst(0xffff)

    def test_set_sctp_dst_min(self):
        self._test_set_sctp_dst(0)

    # set_icmpv4_type
    def _test_set_icmpv4_type(self, icmpv4_type):
        header = ofproto_v1_2.OXM_OF_ICMPV4_TYPE
        match = OFPMatch()
        match.set_icmpv4_type(icmpv4_type)
        self._test_serialize_and_parser(match, header, icmpv4_type)

    def test_set_icmpv4_type_mid(self):
        self._test_set_icmpv4_type(8)

    def test_set_icmpv4_type_max(self):
        self._test_set_icmpv4_type(0xff)

    def test_set_icmpv4_type_min(self):
        self._test_set_icmpv4_type(0)

    # set_icmpv4_code
    def _test_set_icmpv4_code(self, icmpv4_code):
        header = ofproto_v1_2.OXM_OF_ICMPV4_CODE
        match = OFPMatch()
        match.set_icmpv4_code(icmpv4_code)
        self._test_serialize_and_parser(match, header, icmpv4_code)

    def test_set_icmpv4_code_mid(self):
        self._test_set_icmpv4_code(1)

    def test_set_icmpv4_code_max(self):
        self._test_set_icmpv4_code(0xff)

    def test_set_icmpv4_code_min(self):
        self._test_set_icmpv4_code(0)

    # set_arp_opcode
    def _test_set_arp_opcode(self, arp_op):
        header = ofproto_v1_2.OXM_OF_ARP_OP
        match = OFPMatch()
        match.set_arp_opcode(arp_op)
        self._test_serialize_and_parser(match, header, arp_op)

    def test_set_arp_opcode_mid(self):
        self._test_set_arp_opcode(1)

    def test_set_arp_opcode_max(self):
        self._test_set_arp_opcode(0xffff)

    def test_set_arp_opcode_min(self):
        self._test_set_arp_opcode(0)

    # set_arp_spa
    def _test_set_arp_spa(self, ip, mask=None):
        header = ofproto_v1_2.OXM_OF_ARP_SPA
        match = OFPMatch()
        ip = unpack('!I', socket.inet_aton(ip))[0]
        if mask is None:
            match.set_arp_spa(ip)
        else:
            mask = unpack('!I', socket.inet_aton(mask))[0]
            if (mask + 1) >> 32 != 1:
                header = ofproto_v1_2.OXM_OF_ARP_SPA_W
            match.set_arp_spa_masked(ip, mask)
        self._test_serialize_and_parser(match, header, ip, mask)

    def test_set_arp_spa_mid(self):
        self._test_set_arp_spa('192.168.227.57')

    def test_set_arp_spa_max(self):
        self._test_set_arp_spa('255.255.255.255')

    def test_set_arp_spa_min(self):
        self._test_set_arp_spa('0.0.0.0')

    def test_set_arp_spa_masked_mid(self):
        self._test_set_arp_spa('192.168.227.57', '255.255.0.0')

    def test_set_arp_spa_masked_max(self):
        self._test_set_arp_spa('192.168.227.57', '255.255.255.255')

    def test_set_arp_spa_masked_min(self):
        self._test_set_arp_spa('192.168.227.57', '0.0.0.0')

    # set_arp_tpa
    def _test_set_arp_tpa(self, ip, mask=None):
        header = ofproto_v1_2.OXM_OF_ARP_TPA
        match = OFPMatch()
        ip = unpack('!I', socket.inet_aton(ip))[0]
        if mask is None:
            match.set_arp_tpa(ip)
        else:
            mask = unpack('!I', socket.inet_aton(mask))[0]
            if (mask + 1) >> 32 != 1:
                header = ofproto_v1_2.OXM_OF_ARP_TPA_W
            match.set_arp_tpa_masked(ip, mask)
        self._test_serialize_and_parser(match, header, ip, mask)

    def test_set_arp_tpa_mid(self):
        self._test_set_arp_tpa('192.168.227.57')

    def test_set_arp_tpa_max(self):
        self._test_set_arp_tpa('255.255.255.255')

    def test_set_arp_tpa_min(self):
        self._test_set_arp_tpa('0.0.0.0')

    def test_set_arp_tpa_masked_mid(self):
        self._test_set_arp_tpa('192.168.227.57', '255.255.0.0')

    def test_set_arp_tpa_masked_max(self):
        self._test_set_arp_tpa('192.168.227.57', '255.255.255.255')

    def test_set_arp_tpa_masked_min(self):
        self._test_set_arp_tpa('192.168.227.57', '0.0.0.0')

    # set_arp_sha
    def _test_set_arp_sha(self, arp_sha, mask=None):
        header = ofproto_v1_2.OXM_OF_ARP_SHA
        match = OFPMatch()
        arp_sha = mac.haddr_to_bin(arp_sha)
        if mask is None:
            match.set_arp_sha(arp_sha)
        else:
            header = ofproto_v1_2.OXM_OF_ARP_SHA_W
            mask = mac.haddr_to_bin(mask)
            match.set_arp_sha_masked(arp_sha, mask)
            arp_sha = mac.haddr_bitand(arp_sha, mask)
        self._test_serialize_and_parser(match, header, arp_sha, mask)

    def test_set_arp_sha_mid(self):
        self._test_set_arp_sha('3e:ec:13:9b:f3:0b')

    def test_set_arp_sha_max(self):
        self._test_set_arp_sha('ff:ff:ff:ff:ff:ff')

    def test_set_arp_sha_min(self):
        self._test_set_arp_sha('00:00:00:00:00:00')

    def test_set_arp_sha_masked_mid(self):
        self._test_set_arp_sha('3e:ec:13:9b:f3:0b', 'ff:ff:ff:00:00:00')

    def test_set_arp_sha_masked_max(self):
        self._test_set_arp_sha('3e:ec:13:9b:f3:0b', 'ff:ff:ff:ff:ff:ff')

    def test_set_arp_sha_masked_min(self):
        self._test_set_arp_sha('3e:ec:13:9b:f3:0b', '00:00:00:00:00:00')

    # set_arp_tha
    def _test_set_arp_tha(self, arp_tha, mask=None):
        header = ofproto_v1_2.OXM_OF_ARP_THA
        match = OFPMatch()
        arp_tha = mac.haddr_to_bin(arp_tha)
        if mask is None:
            match.set_arp_tha(arp_tha)
        else:
            header = ofproto_v1_2.OXM_OF_ARP_THA_W
            mask = mac.haddr_to_bin(mask)
            match.set_arp_tha_masked(arp_tha, mask)
            arp_tha = mac.haddr_bitand(arp_tha, mask)
        self._test_serialize_and_parser(match, header, arp_tha, mask)

    def test_set_arp_tha_mid(self):
        self._test_set_arp_tha('83:6c:21:52:49:68')

    def test_set_arp_tha_max(self):
        self._test_set_arp_tha('ff:ff:ff:ff:ff:ff')

    def test_set_arp_tha_min(self):
        self._test_set_arp_tha('00:00:00:00:00:00')

    def test_set_arp_tha_masked_mid(self):
        self._test_set_arp_tha('83:6c:21:52:49:68', 'ff:ff:ff:00:00:00')

    def test_set_arp_tha_masked_max(self):
        self._test_set_arp_tha('83:6c:21:52:49:68', 'ff:ff:ff:ff:ff:ff')

    def test_set_arp_tha_masked_min(self):
        self._test_set_arp_tha('83:6c:21:52:49:68', '00:00:00:00:00:00')

    # set_ipv6_src
    def _test_set_ipv6_src(self, ipv6, mask=None):
        header = ofproto_v1_2.OXM_OF_IPV6_SRC
        match = OFPMatch()
        ipv6 = [int(x, 16) for x in ipv6.split(":")]
        if mask is None:
            match.set_ipv6_src(ipv6)
        else:
            header = ofproto_v1_2.OXM_OF_IPV6_SRC_W
            mask = [int(x, 16) for x in mask.split(":")]
            match.set_ipv6_src_masked(ipv6, mask)
            ipv6 = [x & y for (x, y) in itertools.izip(ipv6, mask)]
        self._test_serialize_and_parser(match, header, ipv6, mask)

    def test_set_ipv6_src_mid(self):
        ipv6 = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        self._test_set_ipv6_src(ipv6)

    def test_set_ipv6_src_max(self):
        ipv6 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        self._test_set_ipv6_src(ipv6)

    def test_set_ipv6_src_min(self):
        ipv6 = '0:0:0:0:0:0:0:0'
        self._test_set_ipv6_src(ipv6)

    def test_set_ipv6_src_masked_mid(self):
        ipv6 = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        mask = 'ffff:ffff:ffff:ffff:0:0:0:0'
        self._test_set_ipv6_src(ipv6, mask)

    def test_set_ipv6_src_masked_max(self):
        ipv6 = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        self._test_set_ipv6_src(ipv6, mask)

    def test_set_ipv6_src_masked_min(self):
        ipv6 = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        mask = '0:0:0:0:0:0:0:0'
        self._test_set_ipv6_src(ipv6, mask)

    # set_ipv6_dst
    def _test_set_ipv6_dst(self, ipv6, mask=None):
        header = ofproto_v1_2.OXM_OF_IPV6_DST
        match = OFPMatch()
        ipv6 = [int(x, 16) for x in ipv6.split(":")]
        if mask is None:
            match.set_ipv6_dst(ipv6)
        else:
            header = ofproto_v1_2.OXM_OF_IPV6_DST_W
            mask = [int(x, 16) for x in mask.split(":")]
            match.set_ipv6_dst_masked(ipv6, mask)
            ipv6 = [x & y for (x, y) in itertools.izip(ipv6, mask)]
        self._test_serialize_and_parser(match, header, ipv6, mask)

    def test_set_ipv6_dst_mid(self):
        ipv6 = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        self._test_set_ipv6_dst(ipv6)

    def test_set_ipv6_dst_max(self):
        ipv6 = ':'.join(['ffff'] * 8)
        self._test_set_ipv6_dst(ipv6)

    def test_set_ipv6_dst_min(self):
        ipv6 = ':'.join(['0'] * 8)
        self._test_set_ipv6_dst(ipv6)

    def test_set_ipv6_dst_mask_mid(self):
        ipv6 = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        mask = ':'.join(['ffff'] * 4 + ['0'] * 4)
        self._test_set_ipv6_dst(ipv6, mask)

    def test_set_ipv6_dst_mask_max(self):
        ipv6 = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        mask = ':'.join(['ffff'] * 8)
        self._test_set_ipv6_dst(ipv6, mask)

    def test_set_ipv6_dst_mask_min(self):
        ipv6 = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        mask = ':'.join(['0'] * 8)
        self._test_set_ipv6_dst(ipv6, mask)

    # set_ipv6_flabel
    def _test_set_ipv6_flabel(self, flabel, mask=None):
        header = ofproto_v1_2.OXM_OF_IPV6_FLABEL
        match = OFPMatch()
        if mask is None:
            match.set_ipv6_flabel(flabel)
        else:
            header = ofproto_v1_2.OXM_OF_IPV6_FLABEL_W
            match.set_ipv6_flabel_masked(flabel, mask)
        self._test_serialize_and_parser(match, header, flabel, mask)

    def test_set_ipv6_flabel_mid(self):
        self._test_set_ipv6_flabel(0xc5384)

    def test_set_ipv6_flabel_max(self):
        self._test_set_ipv6_flabel(0xfffff)

    def test_set_ipv6_flabel_min(self):
        self._test_set_ipv6_flabel(0)

    def test_set_ipv6_flabel_masked_mid(self):
        self._test_set_ipv6_flabel(0xc5384, 0xfff00)

    def test_set_ipv6_flabel_masked_max(self):
        self._test_set_ipv6_flabel(0xc5384, 0xfffff)

    def test_set_ipv6_flabel_masked_min(self):
        self._test_set_ipv6_flabel(0xc5384, 0)

    # set_icmpv6_type
    def _test_set_icmpv6_type(self, icmpv6_type):
        header = ofproto_v1_2.OXM_OF_ICMPV6_TYPE
        match = OFPMatch()
        match.set_icmpv6_type(icmpv6_type)
        self._test_serialize_and_parser(match, header, icmpv6_type)

    def test_set_icmpv6_type_mid(self):
        self._test_set_icmpv6_type(129)

    def test_set_icmpv6_type_max(self):
        self._test_set_icmpv6_type(0xff)

    def test_set_icmpv6_type_min(self):
        self._test_set_icmpv6_type(0)

    # set_icmpv6_code
    def _test_set_icmpv6_code(self, icmpv6_code):
        header = ofproto_v1_2.OXM_OF_ICMPV6_CODE
        match = OFPMatch()
        match.set_icmpv6_code(icmpv6_code)
        self._test_serialize_and_parser(match, header, icmpv6_code)

    def test_set_icmpv6_code_mid(self):
        self._test_set_icmpv6_code(1)

    def test_set_icmpv6_code_max(self):
        self._test_set_icmpv6_code(0xff)

    def test_set_icmpv6_code_min(self):
        self._test_set_icmpv6_code(0)

    # set_ipv6_nd_target
    def _test_set_ipv6_nd_target(self, ipv6):
        header = ofproto_v1_2.OXM_OF_IPV6_ND_TARGET
        match = OFPMatch()
        ipv6 = [int(x, 16) for x in ipv6.split(":")]
        match.set_ipv6_nd_target(ipv6)
        self._test_serialize_and_parser(match, header, ipv6)

    def test_set_ipv6_nd_target_mid(self):
        ip = '5420:db3f:921b:3e33:2791:98f:dd7f:2e19'
        self._test_set_ipv6_nd_target(ip)

    def test_set_ipv6_nd_target_max(self):
        ip = ':'.join(['ffff'] * 8)
        self._test_set_ipv6_nd_target(ip)

    def test_set_ipv6_nd_target_min(self):
        ip = ':'.join(['0'] * 8)
        self._test_set_ipv6_nd_target(ip)

    # set_ipv6_nd_sll
    def _test_set_ipv6_nd_sll(self, nd_sll):
        header = ofproto_v1_2.OXM_OF_IPV6_ND_SLL
        match = OFPMatch()
        nd_sll = mac.haddr_to_bin(nd_sll)
        match.set_ipv6_nd_sll(nd_sll)
        self._test_serialize_and_parser(match, header, nd_sll)

    def test_set_ipv6_nd_sll_mid(self):
        self._test_set_ipv6_nd_sll('93:6d:d0:d4:e8:36')

    def test_set_ipv6_nd_sll_max(self):
        self._test_set_ipv6_nd_sll('ff:ff:ff:ff:ff:ff')

    def test_set_ipv6_nd_sll_min(self):
        self._test_set_ipv6_nd_sll('00:00:00:00:00:00')

    # set_ipv6_nd_tll
    def _test_set_ipv6_nd_tll(self, nd_tll):
        header = ofproto_v1_2.OXM_OF_IPV6_ND_TLL
        match = OFPMatch()
        nd_tll = mac.haddr_to_bin(nd_tll)
        match.set_ipv6_nd_tll(nd_tll)
        self._test_serialize_and_parser(match, header, nd_tll)

    def test_set_ipv6_nd_tll_mid(self):
        self._test_set_ipv6_nd_tll('18:f6:66:b6:f1:b3')

    def test_set_ipv6_nd_tll_max(self):
        self._test_set_ipv6_nd_tll('ff:ff:ff:ff:ff:ff')

    def test_set_ipv6_nd_tll_min(self):
        self._test_set_ipv6_nd_tll('00:00:00:00:00:00')

    # set_mpls_label
    def _test_set_mpls_label(self, mpls_label):
        header = ofproto_v1_2.OXM_OF_MPLS_LABEL
        match = OFPMatch()
        match.set_mpls_label(mpls_label)
        self._test_serialize_and_parser(match, header, mpls_label)

    def test_set_mpls_label_mid(self):
        self._test_set_mpls_label(2144)

    def test_set_mpls_label_max(self):
        self._test_set_mpls_label(0xfffff)

    def test_set_mpls_label_min(self):
        self._test_set_mpls_label(0)

    # set_mpls_tc
    def _test_set_mpls_tc(self, mpls_tc):
        header = ofproto_v1_2.OXM_OF_MPLS_TC
        match = OFPMatch()
        match.set_mpls_tc(mpls_tc)
        self._test_serialize_and_parser(match, header, mpls_tc)

    def test_set_mpls_tc_mid(self):
        self._test_set_mpls_tc(3)

    def test_set_mpls_tc_max(self):
        self._test_set_mpls_tc(7)

    def test_set_mpls_tc_min(self):
        self._test_set_mpls_tc(0)


class TestOFPMatchField(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPMatchField
    """

    def test_init_hasmask_true(self):
        header = 0x0100

        res = OFPMatchField(header)

        eq_(res.header, header)
        eq_(res.n_bytes, (header & 0xff) / 2)
        eq_(res.length, 0)

    def test_init_hasmask_false(self):
        header = 0x0000

        res = OFPMatchField(header)

        eq_(res.header, header)
        eq_(res.n_bytes, header & 0xff)
        eq_(res.length, 0)
