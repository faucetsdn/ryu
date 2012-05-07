# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
from nose.tools import *
#from ryu.ofproto.ofproto_v1_0 import *
from ryu.ofproto.ofproto_v1_0_parser import *

LOG = logging.getLogger('test_ofproto_v10')


class TestOFPActionOutput(unittest.TestCase):
    """ Test case for ofprotp_v1_0_parser.OFPActionOutput
    """

    def setup(self):
        pass

    def tearndown(self):
        pass

    def test_init(self):
        c = OFPActionOutput(ofproto_v1_0.OFPAT_OUTPUT,
                            ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)
        eq_(ofproto_v1_0.OFPAT_OUTPUT, c.port)
        eq_(ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE, c.max_len)


    def test_parser(self):
        type_   = '\x00\x00'
        len_    = '\x00\x08'
        port    = '\x00\x00'
        max_len = '\x00\x08'

        buf = type_ + len_ + port + max_len
        c = OFPActionOutput(ofproto_v1_0.OFPAT_OUTPUT,
                            ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)

        c.parser(buf, 0)
        eq_(c.port, ofproto_v1_0.OFPAT_OUTPUT)
        eq_(c.max_len, ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)


    @raises(AssertionError)
    def test_parser_check_type(self):
        type_   = '\x00\x01'
        len_    = '\x00\x08'
        port    = '\x00\x00'
        max_len = '\x00\x08'

        buf = type_ + len_ + port + max_len
        c = OFPActionOutput(ofproto_v1_0.OFPAT_OUTPUT,
                            ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)

        c.parser(buf, 0)


    @raises(AssertionError)
    def test_parser_check_len(self):
        type_   = '\x00\x00'
        len_    = '\x00\x0a'
        port    = '\x00\x00'
        max_len = '\x00\x08'

        buf = type_ + len_ + port + max_len
        c = OFPActionOutput(ofproto_v1_0.OFPAT_OUTPUT,
                            ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)

        c.parser(buf, 0)


    def test_serialize_short(self):
        c = OFPActionOutput(ofproto_v1_0.OFPAT_OUTPUT,
                            ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)

        len_ = c.max_len - 1
        buf  = bytearray().zfill(len_)
        #LOG.debug("buf: %s", buf)

        c.serialize(buf, c.max_len)


    def test_serialize_max(self):
        c = OFPActionOutput(ofproto_v1_0.OFPAT_OUTPUT,
                            ofproto_v1_0.OFP_ACTION_OUTPUT_SIZE)

        len_ = c.max_len + struct.calcsize(ofproto_v1_0.OFP_ACTION_OUTPUT_PACK_STR) - 1
        buf  = str().zfill(len_)
        #LOG.debug("buf: %s", buf)

        c.serialize(buf, c.max_len)

