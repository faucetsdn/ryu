# vim: tabstop=4 shiftwidth=4 softtabstop=4

import binascii
import unittest
from nose.tools import ok_, eq_

from ryu.ofproto import ofproto, ofproto_parser, ofproto_v1_0_parser

import logging
LOG = logging.getLogger(__name__)


class TestOfproto_Parser(unittest.TestCase):
    def setUp(self):
        LOG.debug('setUp')
        self.bufHello = binascii.unhexlify('0100000800000001')
        self.bufFeaturesReply = binascii.unhexlify(
                '010600b0000000020000000000000abc' \
                + '00000100010000000000008700000fff' \
                + '0002aefa39d2b9177472656d61302d30' \
                + '00000000000000000000000000000000' \
                + '000000c0000000000000000000000000' \
                + 'fffe723f9a764cc87673775f30786162' \
                + '63000000000000000000000100000001' \
                + '00000082000000000000000000000000' \
                + '00012200d6c5a1947472656d61312d30' \
                + '00000000000000000000000000000000' \
                + '000000c0000000000000000000000000')
        self.bufPacketIn = binascii.unhexlify(
                '010a005200000000000001010040' \
                + '00020000000000000002000000000001' \
                + '080045000032000000004011f967c0a8' \
                + '0001c0a8000200010001001e00000000' \
                + '00000000000000000000000000000000' \
                + '00000000')

    def tearDown(self):
        LOG.debug('tearDown')
        pass

    def testHello(self):
        (version, msg_type, msg_len, xid) = ofproto_parser.header(self.bufHello)
        eq_(version, 1)
        eq_(msg_type, 0)
        eq_(msg_len, 8)
        eq_(xid, 1)

    def testFeaturesReply(self):
        (version, msg_type, msg_len, xid) = ofproto_parser.header(self.bufFeaturesReply)
        msg = ofproto_parser.msg(self, version, msg_type, msg_len, xid, self.bufFeaturesReply)
        LOG.debug(msg)
        ok_(isinstance(msg, ofproto_v1_0_parser.OFPSwitchFeatures))
        LOG.debug(msg.ports[65534])
        ok_(isinstance(msg.ports[1], ofproto_v1_0_parser.OFPPhyPort))
        ok_(isinstance(msg.ports[2], ofproto_v1_0_parser.OFPPhyPort))
        ok_(isinstance(msg.ports[65534], ofproto_v1_0_parser.OFPPhyPort))

    def testPacketIn(self):
        (version, msg_type, msg_len, xid) = ofproto_parser.header(self.bufPacketIn)
        msg = ofproto_parser.msg(self, version, msg_type, msg_len, xid, self.bufPacketIn)
        LOG.debug(msg)
        ok_(isinstance(msg, ofproto_v1_0_parser.OFPPacketIn))
