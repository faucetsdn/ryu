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
from struct import *
from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto.ofproto_v1_2_parser import *
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ether


LOG = logging.getLogger('test_ofproto_v12')


class TestMsgParser(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.msg_parser
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_msg_parser(self):

        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_HELLO
        msg_len = ofproto_v1_2.OFP_HEADER_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version,  msg_type, msg_len, xid)

        c = msg_parser(Datapath, version, msg_type, msg_len, xid, buf)

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


class TestOFPHello(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPHello
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        xid = 2183948390
        res = OFPHello.parser(object,
                              ofproto_v1_2.OFP_VERSION,
                              ofproto_v1_2.OFPT_HELLO,
                              ofproto_v1_2.OFP_HEADER_SIZE,
                              xid,
                              str().zfill(ofproto_v1_2.OFP_HEADER_SIZE))

        eq_(ofproto_v1_2.OFP_VERSION, res.version)
        eq_(ofproto_v1_2.OFPT_HELLO, res.msg_type)
        eq_(ofproto_v1_2.OFP_HEADER_SIZE, res.msg_len)
        eq_(xid, res.xid)

    def test_serialize(self):

        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        c = OFPHello(Datapath)
        c.serialize()
        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_HELLO, c.msg_type)
        eq_(0, c.xid)


class TestOFPErrorMsg(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPErrorMsg
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_HEADER_PACK_STR
    # '!BBHI'...version, msg_type, msg_len, xid
    version = ofproto_v1_2.OFP_VERSION
    msg_type = ofproto_v1_2.OFPT_ERROR
    msg_len = ofproto_v1_2.OFP_ERROR_MSG_SIZE
    xid = 2495926989

    fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
    buf = pack(fmt, version, msg_type, msg_len, xid)

    # OFP_ERROR_MSG_PACK_STR = '!HH'
    type_ = ofproto_v1_2.OFPET_HELLO_FAILED
    code = ofproto_v1_2.OFPHFC_EPERM
    data = 'Error Message.'

    fmt = ofproto_v1_2.OFP_ERROR_MSG_PACK_STR
    buf += pack(fmt, type_, code) + data

    c = OFPErrorMsg(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        self.c.code = self.code
        self.c.type = self.type_
        self.c.data = self.data

    def test_parser(self):
        res = self.c.parser(object, self.version, self.msg_type,
                            self.msg_len, self.xid, self.buf)

        eq_(res.version, self.version)
        eq_(res.msg_type, self.msg_type)
        eq_(res.msg_len, self.msg_len)
        eq_(res.xid, self.xid)
        eq_(res.type, self.type_)
        eq_(res.code, self.code)
        eq_(res.data, self.data)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_ERROR, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ERROR_MSG_PACK_STR.replace('!', '') \
            + str(len(self.data)) + 's'

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_ERROR)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.type_)
        eq_(res[5], self.code)
        eq_(res[6], self.data)


class TestOFPEchoRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPEchoRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_HEADER_PACK_STR
    # '!BBHI'...version, msg_type, msg_len, xid
    version = ofproto_v1_2.OFP_VERSION
    msg_type = ofproto_v1_2.OFPT_ECHO_REQUEST
    msg_len = ofproto_v1_2.OFP_HEADER_SIZE
    xid = 2495926989

    data = 'Request Message.'

    fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
    buf = pack(fmt, version, msg_type, msg_len, xid) + data

    c = OFPEchoRequest(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        self.c.data = self.data

    def test_parser(self):
        res = self.c.parser(object, self.version, self.msg_type,
                            self.msg_len, self.xid, self.buf)

        eq_(res.version, self.version)
        eq_(res.msg_type, self.msg_type)
        eq_(res.msg_len, self.msg_len)
        eq_(res.xid, self.xid)
        eq_(res.data, self.data)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_ECHO_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + str(len(self.data)) + 's'

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_ECHO_REQUEST)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.data)


class TestOFPEchoReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPEchoReply
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_HEADER_PACK_STR
    # '!BBHI'...version, msg_type, msg_len, xid
    version = ofproto_v1_2.OFP_VERSION
    msg_type = ofproto_v1_2.OFPT_ECHO_REPLY
    msg_len = ofproto_v1_2.OFP_HEADER_SIZE
    xid = 2495926989

    data = 'Reply Message.'

    fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
    buf = pack(fmt, version, msg_type, msg_len, xid) + data

    c = OFPEchoReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        self.c.data = self.data

    def test_parser(self):
        res = self.c.parser(object, self.version, self.msg_type,
                            self.msg_len, self.xid, self.buf)

        eq_(res.version, self.version)
        eq_(res.msg_type, self.msg_type)
        eq_(res.msg_len, self.msg_len)
        eq_(res.xid, self.xid)
        eq_(res.data, self.data)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_ECHO_REPLY, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + str(len(self.data)) + 's'

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_ECHO_REPLY)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.data)


class TestOFPExperimenter(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPExperimenter
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPExperimenter(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_EXPERIMENTER
        msg_len = ofproto_v1_2.OFP_EXPERIMENTER_HEADER_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version,  msg_type, msg_len, xid)

        # OFP_EXPERIMENTER_HEADER_PACK_STR
        # '!II'...experimenter, exp_type
        experimenter = 0
        exp_type = 1

        fmt = ofproto_v1_2.OFP_EXPERIMENTER_HEADER_PACK_STR
        buf += pack(fmt, experimenter, exp_type)

        res = self.c.parser(object, version, msg_type, msg_len, xid, buf)

        # OFP_HEADER_PACK_STR
        eq_(version, res.version)
        eq_(msg_type, res.msg_type)
        eq_(msg_len, res.msg_len)
        eq_(xid, res.xid)

        # OFP_EXPERIMENTER_HEADER_PACK_STR
        eq_(experimenter, res.experimenter)
        eq_(exp_type, res.exp_type)


class TestOFPPort(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPort
    """

    # OFP_PORT_PACK_STR
    # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
    #                          name, config, state, curr, advertised,
    #                          peer, curr_speed, max_speed
    port_no = 1119692796
    hw_addr = 'hw'.ljust(6)
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

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no, self.c.port_no)
        eq_(self.hw_addr, self.c.hw_addr)
        eq_(self.name, self.c.name)
        eq_(self.config, self.c.config)
        eq_(self.state, self.c.state)
        eq_(self.curr, self.c.curr)
        eq_(self.advertised, self.c.advertised)
        eq_(self.supported, self.c.supported)
        eq_(self.peer, self.c.peer)
        eq_(self.curr_speed, self.c.curr_speed)
        eq_(self.max_speed, self.c.max_speed)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port_no, res.port_no)
        eq_(self.hw_addr, res.hw_addr)
        eq_(self.name, res.name)
        eq_(self.config, res.config)
        eq_(self.state, res.state)
        eq_(self.curr, res.curr)
        eq_(self.advertised, res.advertised)
        eq_(self.supported, res.supported)
        eq_(self.peer, res.peer)
        eq_(self.curr_speed, res.curr_speed)
        eq_(self.max_speed, res.max_speed)


class TestOFPFeaturesRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFeaturesRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPFeaturesRequest(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_FEATURES_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_FEATURES_REQUEST)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)


class TestOFPSwitchFeatures(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPSwitchFeatures
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPSwitchFeatures(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):

        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_FEATURES_REPLY
        msg_len = ofproto_v1_2.OFP_SWITCH_FEATURES_SIZE \
            + ofproto_v1_2.OFP_PORT_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_SWITCH_FEATURES_PACK_STR
        # '!QIB3xII'...datapath_id, n_buffers, n_tables,
        #              pad(3), capabilities, reserved
        datapath_id = 1270985291017894273
        n_buffers = 2148849654
        n_tables = 228
        capabilities = 1766843586
        reserved = 2013714700

        fmt = ofproto_v1_2.OFP_SWITCH_FEATURES_PACK_STR
        buf += pack(fmt, datapath_id, n_buffers, n_tables,
                    capabilities, reserved)

        # OFP_PORT_PACK_STR
        # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
        #                          name, config, state, curr, advertised,
        #                          peer, curr_speed, max_speed
        port_no = 1119692796
        hw_addr = 'hw'.ljust(6)
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
        buf += pack(fmt, port_no, hw_addr, name, config, state, curr,
                    advertised, supported, peer, curr_speed, max_speed)

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
        eq_(res.reserved, reserved)

        port = res.ports[port_no]
        eq_(port.port_no, port_no)
        eq_(port.hw_addr, hw_addr)
        eq_(port.name, name)
        eq_(port.config, config)
        eq_(port.state, state)
        eq_(port.curr, curr)
        eq_(port.advertised, advertised)
        eq_(port.supported, supported)
        eq_(port.peer, peer)
        eq_(port.curr_speed, curr_speed)
        eq_(port.max_speed, max_speed)


class TestOFPGetConfigRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGetConfigRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPGetConfigRequest(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_GET_CONFIG_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_GET_CONFIG_REQUEST)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)


class TestOFPGetConfigReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGetConfigReply
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPGetConfigReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):

        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_GET_CONFIG_REPLY
        msg_len = ofproto_v1_2.OFP_SWITCH_CONFIG_SIZE
        xid = 3423224276

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_SWITCH_CONFIG_PACK_STR
        # '!HH'...flags, miss_send_len
        flags = 41186
        miss_send_len = 13838

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


class TestOFPSetConfig(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPSetConfig
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_SWITCH_CONFIG_PACK_STR
    # '!HH'...flags, miss_send_len
    flags = 41186
    miss_send_len = 13838

    c = OFPSetConfig(Datapath, flags, miss_send_len)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.flags, self.c.flags)
        eq_(self.miss_send_len, self.c.miss_send_len)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_SET_CONFIG, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_SET_CONFIG)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.flags)
        eq_(res[5], self.miss_send_len)


class TestOFPPacketIn(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPacketIn
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPPacketIn(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_PACKET_IN
        msg_len = ofproto_v1_2.OFP_PACKET_IN_SIZE
        xid = 3423224276

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_PACKET_IN_PACK_STR
        # '!IHHBB'...buffer_id, total_len, reason, table_id
        buffer_id = 2926809324
        total_len = ofproto_v1_2.OFP_MATCH_SIZE
        reason = 1
        table_id = 3

        fmt = ofproto_v1_2.OFP_PACKET_IN_PACK_STR
        buf += pack(fmt, buffer_id, total_len, reason, table_id)

        # OFP_MATCH_PACK_STR
        match = OFPMatch()
        buf_match = bytearray()
        match.serialize(buf_match, 0)

        buf += str(buf_match)

        # the last 2x is for ofp_packet_in::data
        data = 'data'.ljust(16)

        buf += pack('2x16s', data)

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
        eq_(data[:8], res.data)


class TestOFPFlowRemoved(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowRemoved
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPFlowRemoved(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_FLOW_REMOVED
        msg_len = ofproto_v1_2.OFP_FLOW_REMOVED_SIZE
        xid = 3423224276

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_FLOW_REMOVED_PACK_STR0
        # '!QHBBIIHHQQ' ...cookie, priority, reason, table_id,
        #                  duration_sec, duration_nsec, idle_timeout,
        #                  hard_timeout, packet_count, byte_count
        cookie = 178378173441633860
        priority = 718
        reason = 1
        table_id = 169
        duration_sec = 2250548154
        duration_nsec = 2492776995
        idle_timeout = 60284
        hard_timeout = 60285
        packet_count = 6489108735192644493
        byte_count = 7334344481123449724

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


class TestOFPPortStatus(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortStatus
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # OFP_HEADER_PACK_STR
        # '!BBHI'...version, msg_type, msg_len, xid
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_PORT_STATUS
        msg_len = ofproto_v1_2.OFP_PORT_STATUS_SIZE
        xid = 3423224276

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_PORT_STATUS_PACK_STR = '!B7x' + _OFP_PORT_PACK_STR
        # '!B7x'...reason, pad(7)
        reason = 0

        # OFP_PORT_PACK_STR
        # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
        #                          name, config, state, curr, advertised,
        #                          peer, curr_speed, max_speed
        port_no = 1119692796
        hw_addr = 'hw'.ljust(6)
        name = 'name'.ljust(16)
        config = 2226555987
        state = 1678244809
        curr = 2850556459
        advertised = 2025421682
        supported = 2120575149
        peer = 2757463021
        curr_speed = 2641353507
        max_speed = 1797291672

        fmt = ofproto_v1_2.OFP_PORT_STATUS_PACK_STR
        buf += pack(fmt, reason,
                    port_no, hw_addr, name, config, state, curr,
                    advertised, supported, peer, curr_speed, max_speed)

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


class TestOFPPacketOut(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPacketOut
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_PACKET_OUT_PACK_STR = '!IIH6x'
    buffer_id = 0xffffffff
    in_port = 0x00040455
    data = 'Message'

    # OFP_ACTION (OFP_ACTION_OUTPUT)
    port = 0x00002ae0
    actions = [OFPActionOutput(port, 0)]

    c = OFPPacketOut(Datapath, buffer_id, in_port, actions, data)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.buffer_id, self.c.buffer_id)
        eq_(self.in_port, self.c.in_port)
        eq_(self.data, self.c.data)
        eq_(self.actions, self.c.actions)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_PACKET_OUT, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_PACKET_OUT_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '') \
            + str(len(self.data)) + 's'

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_PACKET_OUT)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.buffer_id)
        eq_(res[5], self.in_port)
        eq_(res[6], ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE)
        eq_(res[7], ofproto_v1_2.OFPAT_OUTPUT)
        eq_(res[8], ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE)
        eq_(res[9], self.port)
        eq_(res[10], 0)
        eq_(res[11], self.data)


class TestOFPFlowMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowMod
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

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

    match = OFPMatch()

    instructions = [OFPInstructionGotoTable(table_id)]

    c = OFPFlowMod(Datapath, cookie, cookie_mask, table_id, command,
                   idle_timeout, hard_timeout, priority, buffer_id,
                   out_port, out_group, flags, match, instructions)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.cookie, self.c.cookie)
        eq_(self.cookie_mask, self.c.cookie_mask)
        eq_(self.table_id, self.c.table_id)
        eq_(self.command, self.c.command)
        eq_(self.idle_timeout, self.c.idle_timeout)
        eq_(self.hard_timeout, self.c.hard_timeout)
        eq_(self.priority, self.c.priority)
        eq_(self.buffer_id, self.c.buffer_id)
        eq_(self.out_port, self.c.out_port)
        eq_(self.out_group, self.c.out_group)
        eq_(self.flags, self.c.flags)
        eq_(self.match, self.c.match)
        eq_(self.instructions[0], self.c.instructions[0])

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_FLOW_MOD, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_FLOW_MOD_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_FLOW_MOD)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.cookie)
        eq_(res[5], self.cookie_mask)
        eq_(res[6], self.table_id)
        eq_(res[7], self.command)
        eq_(res[8], self.idle_timeout)
        eq_(res[9], self.hard_timeout)
        eq_(res[10], self.priority)
        eq_(res[11], self.buffer_id)
        eq_(res[12], self.out_port)
        eq_(res[13], self.out_group)
        eq_(res[14], self.flags)


class TestOFPInstructionGotoTable(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPInstructionGotoTable
    """

    # OFP_INSTRUCTION_GOTO_TABLE_PACK_STR
    # '!HHB3x'...type, len, table_id, pad(3)
    type_ = ofproto_v1_2.OFPIT_GOTO_TABLE
    len_ = ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_SIZE
    table_id = 3

    fmt = ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR
    buf = pack(fmt, type_, len_, table_id)

    c = OFPInstructionGotoTable(table_id)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.table_id, self.c.table_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.table_id, self.table_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.table_id)


class TestOFPInstructionWriteMetadata(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPInstructionWriteMetadata
    """

    # OFP_INSTRUCTION_WRITE_METADATA_PACK_STR
    # '!HH4xQQ'...type, len, pad(4), metadata, metadata_mask
    type_ = ofproto_v1_2.OFPIT_WRITE_METADATA
    len_ = ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_SIZE
    metadata = 2127614848199081640
    metadata_mask = 2127614848199081641

    fmt = ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_PACK_STR
    buf = pack(fmt, type_, len_, metadata, metadata_mask)

    c = OFPInstructionWriteMetadata(metadata, metadata_mask)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.metadata, self.c.metadata)
        eq_(self.metadata_mask, self.c.metadata_mask)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.metadata, self.metadata)
        eq_(res.metadata_mask, self.metadata_mask)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_INSTRUCTION_WRITE_METADATA_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.metadata)
        eq_(res[3], self.metadata_mask)


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

    c = OFPInstructionActions(type_, actions)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.actions, self.c.actions)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)

        eq_(res.actions[0].type, self.actions[0].type)
        eq_(res.actions[0].len, self.actions[0].len)
        eq_(res.actions[0].port, self.actions[0].port)
        eq_(res.actions[0].max_len, self.actions[0].max_len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = '!' \
            + ofproto_v1_2.OFP_INSTRUCTION_ACTIONS_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.actions[0].type)
        eq_(res[3], self.actions[0].len)
        eq_(res[4], self.actions[0].port)
        eq_(res[5], self.actions[0].max_len)


class TestOFPActionHeader(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionHeader
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH4x'...type, len, pad(4)
    type_ = ofproto_v1_2.OFPAT_OUTPUT
    len_ = ofproto_v1_2.OFP_ACTION_HEADER_SIZE

    fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
    buf = pack(fmt, type_, len_)

    c = OFPActionHeader(type_, len_)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_, self.c.type)
        eq_(self.len_, self.c.len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)


class TestOFPActionOutput(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionOutput
    """

    # OFP_ACTION_OUTPUT_PACK_STR
    # '!HHIH6x'...type, len, port, max_len, pad(6)
    type_ = ofproto_v1_2.OFPAT_OUTPUT
    len_ = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    port = 6606
    max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE

    fmt = ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR
    buf = pack(fmt, type_, len_, port, max_len)

    c = OFPActionOutput(port, max_len)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port, self.c.port)
        eq_(self.max_len, self.c.max_len)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.port, self.port)
        eq_(res.max_len, self.max_len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.port)
        eq_(res[3], self.max_len)


class TestOFPActionGroup(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionGroup
    """

    # OFP_ACTION_GROUP_PACK_STR
    # '!HHI'...type, len, group_id
    type_ = ofproto_v1_2.OFPAT_GROUP
    len_ = ofproto_v1_2.OFP_ACTION_GROUP_SIZE
    group_id = 6606

    fmt = ofproto_v1_2.OFP_ACTION_GROUP_PACK_STR
    buf = pack(fmt, type_, len_, group_id)

    c = OFPActionGroup(group_id)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.group_id, self.c.group_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.group_id, self.group_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_GROUP_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.group_id)


class TestOFPActionSetQueue(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionSetQueue
    """

    # OFP_ACTION_SET_QUEUE_PACK_STR
    # '!HHI'...type, len, queue_id
    type_ = ofproto_v1_2.OFPAT_SET_QUEUE
    len_ = ofproto_v1_2.OFP_ACTION_SET_QUEUE_SIZE
    queue_id = 6606

    fmt = ofproto_v1_2.OFP_ACTION_SET_QUEUE_PACK_STR
    buf = pack(fmt, type_, len_, queue_id)

    c = OFPActionSetQueue(queue_id)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.queue_id, self.c.queue_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.queue_id, self.queue_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_SET_QUEUE_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.queue_id)


class TestOFPActionSetMplsTtl(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionSetMplsTtl
    """

    # OFP_ACTION_MPLS_TTL_PACK_STR
    # '!HHB3x'...type, len, mpls_ttl, pad(3)
    type_ = ofproto_v1_2.OFPAT_SET_MPLS_TTL
    len_ = ofproto_v1_2.OFP_ACTION_MPLS_TTL_SIZE
    mpls_ttl = 254

    fmt = ofproto_v1_2.OFP_ACTION_MPLS_TTL_PACK_STR
    buf = pack(fmt, type_, len_, mpls_ttl)

    c = OFPActionSetMplsTtl(mpls_ttl)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.mpls_ttl, self.c.mpls_ttl)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)
        eq_(res.mpls_ttl, self.mpls_ttl)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_MPLS_TTL_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.mpls_ttl)


class TestOFPActionDecMplsTtl(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionDecMplsTtl
    """

    # OFP_ACTION_MPLS_TTL_PACK_STR
    # '!HHB3x'...type, len, mpls_ttl, pad(3)
    type_ = ofproto_v1_2.OFPAT_DEC_MPLS_TTL
    len_ = ofproto_v1_2.OFP_ACTION_MPLS_TTL_SIZE
    mpls_ttl = 254

    fmt = ofproto_v1_2.OFP_ACTION_MPLS_TTL_PACK_STR
    buf = pack(fmt, type_, len_, mpls_ttl)

    c = OFPActionDecMplsTtl()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

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
    buf = pack(fmt, type_, len_, nw_ttl)

    c = OFPActionSetNwTtl(nw_ttl)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.nw_ttl, self.c.nw_ttl)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.nw_ttl, self.nw_ttl)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_NW_TTL_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.nw_ttl)


class TestOFPActionDecNwTtl(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionDecNwTtl
    """

    # OFP_ACTION_NW_TTL_PACK_STR
    # '!HHB3x'...type, len, nw_ttl, pad(3)
    type_ = ofproto_v1_2.OFPAT_DEC_NW_TTL
    len_ = ofproto_v1_2.OFP_ACTION_NW_TTL_SIZE
    nw_ttl = 240

    fmt = ofproto_v1_2.OFP_ACTION_NW_TTL_PACK_STR
    buf = pack(fmt, type_, len_, nw_ttl)

    c = OFPActionDecNwTtl()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)


class TestOFPActionCopyTtlOut(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionCopyTtlOut
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH'...type, len
    type_ = ofproto_v1_2.OFPAT_COPY_TTL_OUT
    len_ = ofproto_v1_2.OFP_ACTION_HEADER_SIZE

    fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
    buf = pack(fmt, type_, len_)

    c = OFPActionCopyTtlOut()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)


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

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.len, self.len_)
        eq_(res.type, self.type_)


class TestOFPActionPushVlan(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionPushVlan
    """

    # OFP_ACTION_PUSH_PACK_STR
    # '!HHB3x'...type, len, ethertype, pad(2)
    type_ = ofproto_v1_2.OFPAT_PUSH_VLAN
    len_ = ofproto_v1_2.OFP_ACTION_PUSH_SIZE
    ethertype = 0x8100

    fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR
    buf = pack(fmt, type_, len_, ethertype)

    c = OFPActionPushVlan(ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.ethertype, self.c.ethertype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.ethertype, self.ethertype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.ethertype)


class TestOFPActionPushMpls(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionPushMpls
    """

    # OFP_ACTION_PUSH_PACK_STR
    # '!HHH2x'...type, len, ethertype, pad(2)
    type_ = ofproto_v1_2.OFPAT_PUSH_MPLS
    len_ = ofproto_v1_2.OFP_ACTION_PUSH_SIZE
    ethertype = 0x8847

    fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR
    buf = pack(fmt, type_, len_, ethertype)

    c = OFPActionPushMpls(ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.ethertype, self.c.ethertype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.ethertype, self.ethertype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.ethertype)


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

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.type_, res.type)
        eq_(self.len_, res.len)


class TestOFPActionPopMpls(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPActionPopMpls
    """

    # OFP_ACTION_POP_MPLS_PACK_STR
    # '!HHH2x'...type, len, ethertype, pad(2)
    type_ = ofproto_v1_2.OFPAT_POP_MPLS
    len_ = ofproto_v1_2.OFP_ACTION_POP_MPLS_SIZE
    ethertype = 0x8100

    fmt = ofproto_v1_2.OFP_ACTION_POP_MPLS_PACK_STR
    buf = pack(fmt, type_, len_, ethertype)

    c = OFPActionPopMpls(ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.ethertype, self.c.ethertype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.ethertype, self.ethertype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_POP_MPLS_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.ethertype)


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

    def setUp(self):
        pass

    def tearDown(self):
        pass

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
    experimenter = 4294967295

    fmt = ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR
    buf = pack(fmt, type_, len_, experimenter)

    c = OFPActionExperimenter(experimenter)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.experimenter, self.c.experimenter)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(res.type, self.type_)
        eq_(res.len, self.len_)
        eq_(res.experimenter, self.experimenter)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.type_)
        eq_(res[1], self.len_)
        eq_(res[2], self.experimenter)


class TestOFPBucket(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBucket
    """

    # OFP_BUCKET_PACK_STR
    # '!HHII4x'...len, weight, watch_port, watch_group, pad(4)
    len_ = ofproto_v1_2.OFP_BUCKET_SIZE \
        + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    weight = 4386
    watch_port = 6606
    watch_group = 3

    fmt = ofproto_v1_2.OFP_BUCKET_PACK_STR
    buf = pack(fmt, len_, weight, watch_port, watch_group)

    # OFP_ACTION (OFP_ACTION_OUTPUT)
    port = 0x00002ae0
    max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    actions = [OFPActionOutput(port, max_len)]
    buf_actions = bytearray()
    actions[0].serialize(buf_actions, 0)

    buf += str(buf_actions)

    c = OFPBucket(len_, weight, watch_port, watch_group, actions)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.len_, self.c.len)
        eq_(self.weight, self.c.weight)
        eq_(self.watch_port, self.c.watch_port)
        eq_(self.watch_group, self.c.watch_group)
        eq_(self.actions, self.c.actions)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.len_, res.len)
        eq_(self.weight, res.weight)
        eq_(self.watch_port, res.watch_port)
        eq_(self.watch_group, res.watch_group)

        eq_(self.actions[0].type, res.actions[0].type)
        eq_(self.actions[0].len, res.actions[0].len)
        eq_(self.actions[0].port, res.actions[0].port)
        eq_(self.actions[0].max_len, res.actions[0].max_len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = '!' \
            + ofproto_v1_2.OFP_BUCKET_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.len_)
        eq_(res[1], self.weight)
        eq_(res[2], self.watch_port)
        eq_(res[3], self.watch_group)
        eq_(res[4], self.actions[0].type)
        eq_(res[5], self.actions[0].len)
        eq_(res[6], self.actions[0].port)
        eq_(res[7], self.actions[0].max_len)


class TestOFPGroupMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupMod
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_GROUP_MOD_PACK_STR
    # '!HBBI'...command, type, pad, group_id
    command = ofproto_v1_2.OFPFC_ADD
    type_ = ofproto_v1_2.OFPGT_SELECT
    group_id = 6606

    # OFP_ACTION (OFP_ACTION_OUTPUT)
    port = 0x00002ae0
    max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    actions = [OFPActionOutput(port, max_len)]

    # OFP_BUCKET
    len_ = ofproto_v1_2.OFP_BUCKET_SIZE + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    weight = 4386
    watch_port = 8006
    watch_group = 3
    buckets = [OFPBucket(len_, weight, watch_port, watch_group, actions)]

    c = OFPGroupMod(Datapath, command, type_, group_id, buckets)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.command, self.c.command)
        eq_(self.type_, self.c.type)
        eq_(self.group_id, self.c.group_id)
        eq_(self.buckets, self.c.buckets)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_GROUP_MOD, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_GROUP_MOD_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_BUCKET_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_GROUP_MOD)
        eq_(res[2], ofproto_v1_2.OFP_GROUP_MOD_SIZE + self.len_)
        eq_(res[3], 0)
        eq_(res[4], self.command)
        eq_(res[5], self.type_)
        eq_(res[6], self.group_id)
        eq_(res[7], self.len_)
        eq_(res[8], self.weight)
        eq_(res[9], self.watch_port)
        eq_(res[10], self.watch_group)
        eq_(res[11], self.actions[0].type)
        eq_(res[12], self.actions[0].len)
        eq_(res[13], self.port)
        eq_(res[14], self.max_len)


class TestOFPPortMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortMod
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_PORT_MOD_PACK_STR v1.2
    # '!I4xs2xIII4x'...port_no, pad(4), hw_addr, pad(2),
    #                  config, mask, advertise, pad(4)
    port_no = 1119692796
    hw_addr = 'hw'.ljust(ofproto_v1_2.OFP_ETH_ALEN)
    config = 2226555987
    mask = 1678244809
    advertise = 2025421682

    c = OFPPortMod(Datapath, port_no, hw_addr, config, mask, advertise)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no, self.c.port_no)
        eq_(self.hw_addr, self.c.hw_addr)
        eq_(self.config, self.c.config)
        eq_(self.mask, self.c.mask)
        eq_(self.advertise, self.c.advertise)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_PORT_MOD, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_PORT_MOD_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_PORT_MOD)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.port_no)
        eq_(res[5], self.hw_addr)
        eq_(res[6], self.config)
        eq_(res[7], self.mask)
        eq_(res[8], self.advertise)


class TestOFPTableMod(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPTableMod
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_PORT_TABLE_PACK_STR v1.2
    # '!B3xI'...table_id, pad(3), config
    table_id = 3
    config = 2226555987

    c = OFPTableMod(Datapath, table_id, config)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.table_id, self.c.table_id)
        eq_(self.config, self.c.config)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_TABLE_MOD, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_TABLE_MOD_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_TABLE_MOD)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.table_id)
        eq_(res[5], self.config)


class TestOFPStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    type_ = ofproto_v1_2.OFPST_DESC

    c = OFPStatsRequest(Datapath, type_)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_, self.c.type)
        eq_(0, self.c.type)

    def test_serialize_stats_body(self):
        self.c._serialize_stats_body()


class TestOFPStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPStatsReply
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPStatsReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

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
        flags = 0

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
        eq_(body, res.body)
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
        flags = 0

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
        eq_(body, res.body)
        eq_(port_no, res.body[0].port_no)
        eq_(queue_id, res.body[0].queue_id)
        eq_(tx_bytes, res.body[0].tx_bytes)
        eq_(tx_packets, res.body[0].tx_packets)
        eq_(tx_errors, res.body[0].tx_errors)


class TestOFPDescStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPDescStatsRequest
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        OFPDescStatsRequest(Datapath)


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

        eq_(self.mfr_desc, res.mfr_desc)
        eq_(self.hw_desc, res.hw_desc)
        eq_(self.sw_desc, res.sw_desc)
        eq_(self.serial_num, res.serial_num)
        eq_(self.dp_desc, res.dp_desc)


class TestOFPFlowStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_FLOW_STATS_REQUEST_PACK_STR
    # '!B3xII4xQQ'...table_id, pad(3), out_port, out_group, pad(4),
    #                cookie, cookie_mask
    table_id = 3
    out_port = 65037
    out_group = 6606
    cookie = 2127614848199081640
    cookie_mask = 2127614848199081641

    match = OFPMatch()

    c = OFPFlowStatsRequest(Datapath, table_id, out_port, out_group,
                            cookie, cookie_mask, match)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.table_id, self.c.table_id)
        eq_(self.out_port, self.c.out_port)
        eq_(self.out_group, self.c.out_group)
        eq_(self.cookie, self.c.cookie)
        eq_(self.cookie_mask, self.c.cookie_mask)
        eq_(self.match, self.c.match)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_FLOW_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_MATCH_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        size = ofproto_v1_2.OFP_STATS_REPLY_SIZE \
            + ofproto_v1_2.OFP_FLOW_STATS_REQUEST_SIZE
        eq_(res[2], size)
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_FLOW)
        eq_(res[5], 0)
        eq_(res[6], self.table_id)
        eq_(res[7], self.out_port)
        eq_(res[8], self.out_group)
        eq_(res[9], self.cookie)
        eq_(res[10], self.cookie_mask)


class TestOFPFlowStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPFlowStats
    """

    # OFP_FLOW_STATS_PACK_STR
    # '!HBxIIHHH6xQQQ'...length, table_id, pad, duration_sec, duration_nsec,
    #                    priority, idle_timeoutl, hard_timeout, pad(6),
    #                    cookie, packet_count, byte_count
    length = ofproto_v1_2.OFP_FLOW_STATS_SIZE \
        + ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_SIZE
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
    buf_match = bytearray()
    match.serialize(buf_match, 0)

    instructions = [OFPInstructionGotoTable(table_id)]
    buf_instructions = bytearray()
    instructions[0].serialize(buf_instructions, 0)

    fmt = ofproto_v1_2.OFP_FLOW_STATS_PACK_STR
    buf = pack(fmt, length, table_id, duration_sec, duration_nsec,
               priority, idle_timeout, hard_timeout, cookie,
               packet_count, byte_count) \
        + str(buf_match) \
        + str(buf_instructions)

    c = OFPFlowStats(length, table_id, duration_sec, duration_nsec,
                     priority, idle_timeout, hard_timeout, cookie,
                     packet_count, byte_count, match, instructions)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.c.length)
        eq_(self.table_id, self.c.table_id)
        eq_(self.duration_sec, self.c.duration_sec)
        eq_(self.duration_nsec, self.c.duration_nsec)
        eq_(self.priority, self.c.priority)
        eq_(self.idle_timeout, self.c.idle_timeout)
        eq_(self.hard_timeout, self.c.hard_timeout)
        eq_(self.cookie, self.c.cookie)
        eq_(self.packet_count, self.c.packet_count)
        eq_(self.byte_count, self.c.byte_count)
        eq_(self.match, self.c.match)
        eq_(self.instructions, self.c.instructions)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.length, res.length)
        eq_(self.table_id, res.table_id)
        eq_(self.duration_sec, res.duration_sec)
        eq_(self.duration_nsec, res.duration_nsec)
        eq_(self.priority, res.priority)
        eq_(self.idle_timeout, res.idle_timeout)
        eq_(self.hard_timeout, res.hard_timeout)
        eq_(self.cookie, res.cookie)
        eq_(self.packet_count, res.packet_count)
        eq_(self.byte_count, res.byte_count)
        eq_(self.instructions[0].type, res.instructions[0].type)
        eq_(self.instructions[0].len, res.instructions[0].len)
        eq_(self.instructions[0].table_id, res.instructions[0].table_id)


class TestOFPAggregateStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPAggregateStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_AGGREGATE_STATS_REQUEST_PACK_STR
    # '!B3xII4xQQ'...table_id, pad(3), out_port, out_group, pad(4),
    #                cookie, cookie_mask
    table_id = 3
    out_port = 65037
    out_group = 6606
    cookie = 2127614848199081640
    cookie_mask = 2127614848199081641

    match = OFPMatch()

    c = OFPAggregateStatsRequest(Datapath, table_id, out_port, out_group,
                                 cookie, cookie_mask, match)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.table_id, self.c.table_id)
        eq_(self.out_port, self.c.out_port)
        eq_(self.out_group, self.c.out_group)
        eq_(self.cookie, self.c.cookie)
        eq_(self.cookie_mask, self.c.cookie_mask)
        eq_(self.match, self.c.match)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_AGGREGATE_STATS_REQUEST_PACK_STR.replace('!',
                                                                        '') \
            + ofproto_v1_2.OFP_MATCH_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        size = ofproto_v1_2.OFP_STATS_REPLY_SIZE \
            + ofproto_v1_2.OFP_AGGREGATE_STATS_REQUEST_SIZE
        eq_(res[2], size)
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_AGGREGATE)
        eq_(res[5], 0)
        eq_(res[6], self.table_id)
        eq_(res[7], self.out_port)
        eq_(res[8], self.out_group)
        eq_(res[9], self.cookie)
        eq_(res[10], self.cookie_mask)


class TestOFPAggregateStatsReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPAggregateStatsReply
    """

    # OFP_AGGREGATE_STATS_REPLY_PACK_STR
    # '!QQI4x'...packet_count, byte_count, flow_count, pad(4)
    packet_count = 5142202600015232219
    byte_count = 2659740543924820419
    flow_count = 1344694860

    fmt = ofproto_v1_2.OFP_AGGREGATE_STATS_REPLY_PACK_STR
    buf = pack(fmt, packet_count, byte_count, flow_count)

    c = OFPAggregateStatsReply(packet_count, byte_count, flow_count)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.packet_count, res.packet_count)
        eq_(self.byte_count, res.byte_count)
        eq_(self.flow_count, res.flow_count)


class TestOFPTableStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPTableStatsRequest
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        OFPTableStatsRequest(Datapath)


class TestOFPTableStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPTableStats
    """

    # OFP_TABLE_STATS_PACK_STR
    # '!B7x32sQQIIQQQQIIIIQQ'
    # ...table_id, name, match, wildcards, write_actions, apply_actions,
    #    write_setfields, apply_setfields', metadata_match, metadata_write,
    #    instructions, config, max_entries,
    #    active_count, lookup_count, matched_count
    table_id = 91
    name = 'name'.ljust(ofproto_v1_2.OFP_MAX_TABLE_NAME_LEN)
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

    fmt = ofproto_v1_2.OFP_TABLE_STATS_PACK_STR
    buf = pack(fmt, table_id, name, match, wildcards, write_actions,
               apply_actions, write_setfields, apply_setfields,
               metadata_match, metadata_write, instructions, config,
               max_entries, active_count, lookup_count, matched_count)

    c = OFPTableStats(table_id, name, match, wildcards, write_actions,
                      apply_actions, write_setfields, apply_setfields,
                      metadata_match, metadata_write, instructions, config,
                      max_entries, active_count, lookup_count, matched_count)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.table_id, res.table_id)
        eq_(self.name, res.name)
        eq_(self.match, res.match)
        eq_(self.wildcards, res.wildcards)
        eq_(self.write_actions, res.write_actions)
        eq_(self.apply_actions, res.apply_actions)
        eq_(self.write_setfields, res.write_setfields)
        eq_(self.apply_setfields, res.apply_setfields)
        eq_(self.metadata_match, res.metadata_match)
        eq_(self.metadata_write, res.metadata_write)
        eq_(self.instructions, res.instructions)
        eq_(self.config, res.config)
        eq_(self.max_entries, res.max_entries)
        eq_(self.active_count, res.active_count)
        eq_(self.lookup_count, res.lookup_count)
        eq_(self.matched_count, res.matched_count)


class TestOFPPortStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_PORT_STATS_REQUEST_PACK_STR
    # '!I4x'...port_no, pad(4)
    port_no = 41186

    c = OFPPortStatsRequest(Datapath, port_no)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no, self.c.port_no)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_PORT_STATS_REQUEST_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        size = ofproto_v1_2.OFP_STATS_REQUEST_SIZE \
            + ofproto_v1_2.OFP_PORT_STATS_REQUEST_SIZE
        eq_(res[2], size)
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_PORT)
        eq_(res[5], 0)
        eq_(res[6], self.port_no)


class TestOFPPortStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPPortStats
    """

    # OFP_PORT_STATS_PACK_STR = '!H6xQQQQQQQQQQQQ'
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

    fmt = ofproto_v1_2.OFP_PORT_STATS_PACK_STR
    buf = pack(fmt, port_no, rx_packets, tx_packets, rx_bytes, tx_bytes,
               rx_dropped, tx_dropped, rx_errors, tx_errors, rx_frame_err,
               rx_over_err, rx_crc_err, collisions)

    c = OFPPortStats(port_no, rx_packets, tx_packets, rx_bytes, tx_bytes,
                     rx_dropped, tx_dropped, rx_errors, tx_errors,
                     rx_frame_err, rx_over_err, rx_crc_err, collisions)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port_no, res.port_no)
        eq_(self.rx_packets, res.rx_packets)
        eq_(self.tx_packets, res.tx_packets)
        eq_(self.rx_bytes, res.rx_bytes)
        eq_(self.tx_bytes, res.tx_bytes)
        eq_(self.rx_dropped, res.rx_dropped)
        eq_(self.tx_dropped, res.tx_dropped)
        eq_(self.rx_errors, res.rx_errors)
        eq_(self.tx_errors, res.tx_errors)
        eq_(self.rx_frame_err, res.rx_frame_err)
        eq_(self.rx_over_err, res.rx_over_err)
        eq_(self.rx_crc_err, res.rx_crc_err)
        eq_(self.collisions, res.collisions)


class TestOFPQueueStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_QUEUE_STATS_REQUEST_PACK_STR
    # '!II'...port_no, queue_id
    port_no = {'buf': '\x00\x00\xa0\xe2', 'val': 41186}
    queue_id = {'buf': '\x00\x00\x19\xce', 'val': 6606}

    c = OFPQueueStatsRequest(Datapath, port_no['val'], queue_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no['val'], self.c.port_no)
        eq_(self.queue_id['val'], self.c.queue_id)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_QUEUE_STATS_REQUEST_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        size = ofproto_v1_2.OFP_STATS_REQUEST_SIZE \
            + ofproto_v1_2.OFP_QUEUE_STATS_REQUEST_SIZE
        eq_(res[2], size)
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_QUEUE)
        eq_(res[5], 0)
        eq_(res[6], self.port_no['val'])
        eq_(res[7], self.queue_id['val'])


class TestOFPQueueStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueStats
    """

    # OFP_QUEUE_STATS_PACK_STR = '!IIQQQ'
    port_no = 41186
    queue_id = 6606
    tx_bytes = 8638420181865882538
    tx_packets = 2856480458895760962
    tx_errors = 6283093430376743019

    fmt = ofproto_v1_2.OFP_QUEUE_STATS_PACK_STR
    buf = pack(fmt, port_no, queue_id, tx_bytes, tx_packets, tx_errors)

    c = OFPQueueStats(port_no, queue_id, tx_bytes, tx_packets, tx_errors)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.port_no, res.port_no)
        eq_(self.queue_id, res.queue_id)
        eq_(self.tx_bytes, res.tx_bytes)
        eq_(self.tx_packets, res.tx_packets)
        eq_(self.tx_errors, res.tx_errors)


class TestOFPBucketCounter(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBucketCounter
    """

    # OFP_BUCKET_COUNTER_PACK_STR = '!QQ'
    packet_count = 6489108735192644493
    byte_count = 7334344481123449724

    fmt = ofproto_v1_2.OFP_BUCKET_COUNTER_PACK_STR
    buf = pack(fmt, packet_count, byte_count)

    c = OFPBucketCounter(packet_count, byte_count)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.packet_count, self.c.packet_count)
        eq_(self.byte_count, self.c.byte_count)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.packet_count, res.packet_count)
        eq_(self.byte_count, res.byte_count)


class TestOFPGroupStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupStatsRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_GROUP_STATS_REQUEST_PACK_STR
    # '!I4x'...group_id, pad(4)
    group_id = 6606

    c = OFPGroupStatsRequest(Datapath, group_id)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.group_id, self.c.group_id)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_STATS_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_STATS_REQUEST_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_GROUP_STATS_REQUEST_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_STATS_REQUEST)
        size = ofproto_v1_2.OFP_STATS_REQUEST_SIZE \
            + ofproto_v1_2.OFP_GROUP_STATS_REQUEST_SIZE
        eq_(res[2], size)
        eq_(res[3], 0)
        eq_(res[4], ofproto_v1_2.OFPST_GROUP)
        eq_(res[5], 0)
        eq_(res[6], self.group_id)


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

    c = OFPGroupStats(length, group_id, ref_count, packet_count,
                      byte_count, bucket_counters)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.c.length)
        eq_(self.group_id, self.c.group_id)
        eq_(self.ref_count, self.c.ref_count)
        eq_(self.packet_count, self.c.packet_count)
        eq_(self.byte_count, self.c.byte_count)
        eq_(self.bucket_counters, self.c.bucket_counters)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.length, res.length)
        eq_(self.group_id, res.group_id)
        eq_(self.ref_count, res.ref_count)
        eq_(self.packet_count, res.packet_count)
        eq_(self.byte_count, res.byte_count)
        eq_(self.buck_packet_count, res.bucket_counters[0].packet_count)
        eq_(self.buck_byte_count, res.bucket_counters[0].byte_count)


class TestOFPGroupDescStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupDescStatsRequest
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        OFPGroupDescStatsRequest(Datapath)


class TestOFPGroupDescStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupDescStats
    """

    # OFP_GROUP_DESC_STATS_PACK_STR = '!HBxI'
    length = ofproto_v1_2.OFP_GROUP_DESC_STATS_SIZE \
        + ofproto_v1_2.OFP_BUCKET_SIZE \
        + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    type_ = ofproto_v1_2.OFPGT_ALL
    group_id = 6606

    # OFP_ACTION (OFP_ACTION_OUTPUT)
    port = 0x00002ae0
    max_len = ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    actions = [OFPActionOutput(port, max_len)]
    buf_actions = bytearray()
    actions[0].serialize(buf_actions, 0)

    # OFP_BUCKET
    len_ = ofproto_v1_2.OFP_BUCKET_SIZE + ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE
    weight = 4386
    watch_port = 8006
    watch_group = 3
    buckets = [OFPBucket(len_, weight, watch_port, watch_group, actions)]
    buf_buckets = bytearray()
    buckets[0].serialize(buf_buckets, 0)

    fmt = ofproto_v1_2.OFP_GROUP_DESC_STATS_PACK_STR
    buf = pack(fmt, length, type_, group_id) + str(buf_buckets)

    c = OFPGroupDescStats(length, type_, group_id, buckets)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.c.length)
        eq_(self.type_, self.c.type)
        eq_(self.group_id, self.c.group_id)
        eq_(self.buckets, self.c.buckets)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.type_, res.type)
        eq_(self.length, res.length)
        eq_(self.group_id, res.group_id)
        eq_(self.len_, res.buckets[0].len)
        eq_(self.weight, res.buckets[0].weight)
        eq_(self.watch_port, res.buckets[0].watch_port)
        eq_(self.watch_group, res.buckets[0].watch_group)
        eq_(self.port, res.buckets[0].actions[0].port)
        eq_(self.max_len, res.buckets[0].actions[0].max_len)


class TestOFPGroupFeaturesStatsRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupFeaturesStatsRequest
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        OFPGroupFeaturesStatsRequest(Datapath)


class TestOFPGroupFeaturesStats(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPGroupFeaturesStats
    """

    # OFP_GROUP_FEATURES_STATS_PACK_STR = '!II4I4I'
    types = ofproto_v1_2.OFPGT_ALL
    capabilities = ofproto_v1_2.OFPGFC_SELECT_WEIGHT
    max_groups = (1, 2, 3, 4)
    actions = (ofproto_v1_2.OFPAT_OUTPUT,
               ofproto_v1_2.OFPAT_COPY_TTL_OUT,
               ofproto_v1_2.OFPAT_SET_MPLS_TTL,
               ofproto_v1_2.OFPAT_PUSH_VLAN)

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

    c = OFPGroupFeaturesStats(types, capabilities, max_groups, actions)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.types, self.c.types)
        eq_(self.capabilities, self.c.capabilities)
        eq_(self.max_groups, self.c.max_groups)
        eq_(self.actions, self.c.actions)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.types, res.types)
        eq_(self.capabilities, res.capabilities)
        eq_(self.max_groups, res.max_groups)
        eq_(self.actions, res.actions)


class TestOFPQueuePropMinRate(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueuePropMinRate
    """

    rate = 0
    buf = pack(ofproto_v1_2.OFP_QUEUE_PROP_MIN_RATE_PACK_STR, rate)
    c = OFPQueuePropMinRate(rate)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.rate, self.c.rate)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.rate, res.rate)


class TestOFPQueuePropMaxRate(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueuePropMaxRate
    """

    rate = 100
    buf = pack(ofproto_v1_2.OFP_QUEUE_PROP_MAX_RATE_PACK_STR, rate)
    c = OFPQueuePropMaxRate(rate)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.rate, self.c.rate)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)
        eq_(self.rate, res.rate)


class TestOFPQueueGetConfigRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueGetConfigRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR v1.2
    # '!I4x'...port, pad(4)
    port = 41186

    c = OFPQueueGetConfigRequest(Datapath, port)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port, self.c.port)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        a = ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '')
        b = ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR.replace('!', '')
        fmt = '!' + a + b

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(res[0], ofproto_v1_2.OFP_VERSION)
        eq_(res[1], ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST)
        eq_(res[2], len(self.c.buf))
        eq_(res[3], 0)
        eq_(res[4], self.port)


class TestOFPQueuePropHeader(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueuePropHeader
    """

    # OFP_QUEUE_PROP_HEADER_PACK_STR = '!HH4x'
    property_ = 1
    len_ = ofproto_v1_2.OFP_QUEUE_PROP_HEADER_SIZE

    c = OFPQueuePropHeader(property_, len_)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.property_, self.c.property)
        eq_(self.len_, self.c.len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(res[0], self.property_)
        eq_(res[1], self.len_)


class TestOFPQueueGetConfigReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPQueueGetConfigReply
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_HEADER_PACK_STR
    version = ofproto_v1_2.OFP_VERSION
    msg_type = ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REPLY
    msg_len = ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REPLY_SIZE \
        + ofproto_v1_2.OFP_PACKET_QUEUE_SIZE \
        + ofproto_v1_2.OFP_QUEUE_PROP_HEADER_SIZE
    xid = 2495926989

    fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
    buf = pack(fmt, version, msg_type, msg_len, xid)

    # OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR = '!I4x'
    # OFP_QUEUE_GET_CONFIG_REPLY_SIZE = 16
    port = 65037

    fmt = ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR
    buf += pack(fmt, port)

    # OFP_QUEUE_PROP_HEADER_PACK_STR = '!HH4x'
    # OFP_QUEUE_PROP_HEADER_SIZE = 8
    property_ = ofproto_v1_2.OFPQT_MIN_RATE
    properties_len = ofproto_v1_2.OFP_QUEUE_PROP_HEADER_SIZE
    properties = [OFPQueuePropHeader(property_, properties_len)]

    buf_properties = bytearray()
    properties[0].serialize(buf_properties, 0)

    # OFP_PACKET_QUEUE_PACK_STR = '!IIH6x'
    # OFP_PACKET_QUEUE_SIZE = 16
    queue_id = 6606
    queue_port = 41186
    queue_len = ofproto_v1_2.OFP_PACKET_QUEUE_SIZE \
        + ofproto_v1_2.OFP_QUEUE_PROP_HEADER_SIZE
    queues = [OFPPacketQueue(queue_id, queue_port, queue_len, properties)]

    fmt = ofproto_v1_2.OFP_PACKET_QUEUE_PACK_STR
    buf += pack(fmt, queue_id, queue_port, queue_len) + buf_properties

    c = OFPQueueGetConfigReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        res = self.c.parser(object, self.version, self.msg_type, self.msg_len,
                            self.xid, self.buf)

        eq_(self.version, res.version)
        eq_(self.msg_type, res.msg_type)
        eq_(self.msg_len, res.msg_len)
        eq_(self.xid, res.xid)

        eq_(self.queue_id, res.queues[0].queue_id)
        eq_(self.queue_port, res.queues[0].port)
        eq_(self.queue_len, res.queues[0].len)
        eq_(self.property_, res.queues[0].properties[0].property)


class TestOFPBarrierRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBarrierRequest
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        OFPBarrierRequest(Datapath)


class TestOFPBarrierReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPBarrierReply
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        OFPBarrierReply(Datapath)


class TestOFPRoleRequest(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPRoleRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_ROLE_REQUEST_PACK_STR
    # '!I4xQ'...role, pad(4), generation_id
    role = ofproto_v1_2.OFPCR_ROLE_NOCHANGE
    generation_id = 1270985291017894273

    c = OFPRoleRequest(Datapath, role, generation_id)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.role, self.c.role)
        eq_(self.generation_id, self.c.generation_id)

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_ROLE_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ROLE_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_ROLE_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(self.role, res[4])
        eq_(self.generation_id, res[5])


class TestOFPRoleReply(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPRoleReply
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    c = OFPRoleReply(Datapath)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        # OFP_HEADER_PACK_STR
        version = ofproto_v1_2.OFP_VERSION
        msg_type = ofproto_v1_2.OFPT_ROLE_REPLY
        msg_len = ofproto_v1_2.OFP_ROLE_REQUEST_SIZE
        xid = 2495926989

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        buf = pack(fmt, version, msg_type, msg_len, xid)

        # OFP_ROLE_REQUEST_PACK_STR
        # '!I4xQ'...role, pad(4), generation_id
        role = ofproto_v1_2.OFPCR_ROLE_NOCHANGE
        generation_id = 1270985291017894273

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


class TestOFPMatch(unittest.TestCase):
    """ Test case for ofproto_v1_2_parser.OFPMatch
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def _test_serialize_and_parser(self, header, value, match):
        # match_serialize
        buf = bytearray()
        length = match.serialize(buf, 0)

        cls_ = OFPMatchField._FIELDS_HEADERS.get(header)
        fmt = '!HHI' + cls_.pack_str.replace('!', '')
        res = unpack_from(fmt, buffer(buf), 0)

        if type(value) is list:
            eq_(list(res)[3:], value)
        else:
            eq_(res[3], value)

        # match_parser
        res = match.parser(str(buf), 0)

        eq_(res.type, ofproto_v1_2.OFPMT_OXM)
        eq_(res.fields[0].header, header)
        eq_(res.fields[0].value, value)

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

    def test_set_in_port(self):
        header = ofproto_v1_2.OXM_OF_IN_PORT
        value = in_port = 0xfff8

        match = OFPMatch()
        match.set_in_port(in_port)

        self._test_serialize_and_parser(header, value, match)

    def test_set_in_phy_port(self):
        header = ofproto_v1_2.OXM_OF_IN_PHY_PORT
        value = phy_port = 1

        match = OFPMatch()
        match.set_in_phy_port(phy_port)

        self._test_serialize_and_parser(header, value, match)

    def test_set_metadata(self):
        header = ofproto_v1_2.OXM_OF_METADATA
        value = metadata = 0x1fffffffffffff80

        match = OFPMatch()
        match.set_metadata(metadata)

        self._test_serialize_and_parser(header, value, match)

    def test_set_metadata_masked(self):
        header = ofproto_v1_2.OXM_OF_METADATA_W
        value = metadata = 0x1fffffffffffff80
        mask = 0xfffffffffffffff0

        match = OFPMatch()
        match.set_metadata_masked(metadata, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_dl_dst(self):
        header = ofproto_v1_2.OXM_OF_ETH_DST
        value = dl_dst = mac.haddr_to_bin('e2:7a:09:79:0b:0f')

        match = OFPMatch()
        match.set_dl_dst(dl_dst)

        self._test_serialize_and_parser(header, value, match)

    def test_set_dl_dst_masked(self):
        header = ofproto_v1_2.OXM_OF_ETH_DST_W
        value = dl_dst = mac.haddr_to_bin('e2:7a:09:79:0b:0f')
        mask = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')

        match = OFPMatch()
        match.set_dl_dst_masked(dl_dst, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_dl_src(self):
        header = ofproto_v1_2.OXM_OF_ETH_SRC
        value = dl_src = mac.haddr_to_bin('d0:98:79:b4:75:b5')

        match = OFPMatch()
        match.set_dl_src(dl_src)

        self._test_serialize_and_parser(header, value, match)

    def test_set_dl_src_masked(self):
        header = ofproto_v1_2.OXM_OF_ETH_SRC_W
        value = dl_src = mac.haddr_to_bin('d0:98:79:b4:75:b5')
        mask = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')

        match = OFPMatch()
        match.set_dl_src_masked(dl_src, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_dl_type(self):
        header = ofproto_v1_2.OXM_OF_ETH_TYPE
        value = dl_type = ether.ETH_TYPE_IP

        match = OFPMatch()
        match.set_dl_type(dl_type)

        self._test_serialize_and_parser(header, value, match)

    def test_set_vlan_vid(self):
        header = ofproto_v1_2.OXM_OF_VLAN_VID
        value = vid = 0b101010101010

        match = OFPMatch()
        match.set_vlan_vid(vid)

        self._test_serialize_and_parser(header, value, match)

    def test_set_vlan_vid_masked(self):
        header = ofproto_v1_2.OXM_OF_VLAN_VID_W
        value = vid = 0b101010101010
        mask = 0xfff

        match = OFPMatch()
        match.set_vlan_vid_masked(vid, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_vlan_pcp(self):
        header = ofproto_v1_2.OXM_OF_VLAN_PCP
        value = pcp = 5

        match = OFPMatch()
        match.set_vlan_pcp(pcp)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ip_dscp(self):
        header = ofproto_v1_2.OXM_OF_IP_DSCP
        value = ip_dscp = 36

        match = OFPMatch()
        match.set_ip_dscp(ip_dscp)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ip_ecn(self):
        header = ofproto_v1_2.OXM_OF_IP_ECN
        value = ip_ecn = 3

        match = OFPMatch()
        match.set_ip_ecn(ip_ecn)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ip_proto(self):
        header = ofproto_v1_2.OXM_OF_IP_PROTO
        value = ip_proto = 6

        match = OFPMatch()
        match.set_ip_proto(ip_proto)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv4_src(self):
        header = ofproto_v1_2.OXM_OF_IPV4_SRC
        ip = '192.168.196.250'
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = ipv4_src = ipv4

        match = OFPMatch()
        match.set_ipv4_src(ipv4_src)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv4_src_masked(self):
        header = ofproto_v1_2.OXM_OF_IPV4_SRC_W
        ip = '192.168.196.250'
        mask = 0xffffff00
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = ipv4_src = ipv4

        match = OFPMatch()
        match.set_ipv4_src_masked(ipv4_src, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv4_dst(self):
        header = ofproto_v1_2.OXM_OF_IPV4_DST
        ip = '192.168.196.250'
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = ipv4_dst = ipv4

        match = OFPMatch()
        match.set_ipv4_dst(ipv4_dst)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv4_dst_masked(self):
        header = ofproto_v1_2.OXM_OF_IPV4_DST_W
        ip = '192.168.196.250'
        mask = 0xffffff00
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = ipv4_dst = ipv4

        match = OFPMatch()
        match.set_ipv4_dst_masked(ipv4_dst, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_tcp_src(self):
        header = ofproto_v1_2.OXM_OF_TCP_SRC
        value = tcp_src = 1103

        match = OFPMatch()
        match.set_tcp_src(tcp_src)

        self._test_serialize_and_parser(header, value, match)

    def test_set_tcp_dst(self):
        header = ofproto_v1_2.OXM_OF_TCP_DST
        value = tcp_dst = 236

        match = OFPMatch()
        match.set_tcp_dst(tcp_dst)

        self._test_serialize_and_parser(header, value, match)

    def test_set_udp_src(self):
        header = ofproto_v1_2.OXM_OF_UDP_SRC
        value = udp_src = 56617

        match = OFPMatch()
        match.set_udp_src(udp_src)

        self._test_serialize_and_parser(header, value, match)

    def test_set_udp_dst(self):
        header = ofproto_v1_2.OXM_OF_UDP_DST
        value = udp_dst = 61278

        match = OFPMatch()
        match.set_udp_dst(udp_dst)

        self._test_serialize_and_parser(header, value, match)

    def test_set_sctp_src(self):
        header = ofproto_v1_2.OXM_OF_SCTP_SRC
        value = sctp_src = 9999

        match = OFPMatch()
        match.set_sctp_src(sctp_src)

        self._test_serialize_and_parser(header, value, match)

    def test_set_sctp_dst(self):
        header = ofproto_v1_2.OXM_OF_SCTP_DST
        value = sctp_dst = 1234

        match = OFPMatch()
        match.set_sctp_dst(sctp_dst)

        self._test_serialize_and_parser(header, value, match)

    def test_set_icmpv4_type(self):
        header = ofproto_v1_2.OXM_OF_ICMPV4_TYPE
        value = icmpv4_type = 8

        match = OFPMatch()
        match.set_icmpv4_type(icmpv4_type)

        self._test_serialize_and_parser(header, value, match)

    def test_set_icmpv4_code(self):
        header = ofproto_v1_2.OXM_OF_ICMPV4_CODE
        value = icmpv4_code = 1

        match = OFPMatch()
        match.set_icmpv4_code(icmpv4_code)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_opcode(self):
        header = ofproto_v1_2.OXM_OF_ARP_OP
        value = arp_op = 1

        match = OFPMatch()
        match.set_arp_opcode(arp_op)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_spa(self):
        header = ofproto_v1_2.OXM_OF_ARP_SPA
        ip = '192.168.227.57'
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = arp_spa = ipv4

        match = OFPMatch()
        match.set_arp_spa(arp_spa)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_spa_masked(self):
        header = ofproto_v1_2.OXM_OF_ARP_SPA_W
        ip = '192.168.227.57'
        mask = 0xffffff00
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = arp_spa = ipv4

        match = OFPMatch()
        match.set_arp_spa_masked(arp_spa, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_tpa(self):
        header = ofproto_v1_2.OXM_OF_ARP_TPA
        ip = '192.168.198.233'
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = arp_tpa = ipv4

        match = OFPMatch()
        match.set_arp_tpa(arp_tpa)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_tpa_masked(self):
        header = ofproto_v1_2.OXM_OF_ARP_TPA_W
        ip = '192.168.198.233'
        mask = 0xffffff00
        ipv4 = 0
        for b in ip.split("."):
            ipv4 = (ipv4 << 8) | int(b)
        value = arp_tpa = ipv4

        match = OFPMatch()
        match.set_arp_tpa_masked(arp_tpa, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_sha(self):
        header = ofproto_v1_2.OXM_OF_ARP_SHA
        value = arp_sha = mac.haddr_to_bin('3e:ec:13:9b:f3:0b')

        match = OFPMatch()
        match.set_arp_sha(arp_sha)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_sha_masked(self):
        header = ofproto_v1_2.OXM_OF_ARP_SHA_W
        value = arp_sha = mac.haddr_to_bin('3e:ec:13:9b:f3:0b')
        mask = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')

        match = OFPMatch()
        match.set_arp_sha_masked(arp_sha, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_tha(self):
        header = ofproto_v1_2.OXM_OF_ARP_THA
        value = arp_tha = mac.haddr_to_bin('83:6c:21:52:49:68')

        match = OFPMatch()
        match.set_arp_tha(arp_tha)

        self._test_serialize_and_parser(header, value, match)

    def test_set_arp_tha_masked(self):
        header = ofproto_v1_2.OXM_OF_ARP_THA_W
        value = arp_tha = mac.haddr_to_bin('83:6c:21:52:49:68')
        mask = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')

        match = OFPMatch()
        match.set_arp_tha_masked(arp_tha, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_src(self):
        header = ofproto_v1_2.OXM_OF_IPV6_SRC
        ip = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        value = ipv6_src = [int(x, 16) for x in ip.split(":")]

        match = OFPMatch()
        match.set_ipv6_src(ipv6_src)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_src_masked(self):
        header = ofproto_v1_2.OXM_OF_IPV6_SRC_W
        ip = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        value = ipv6_src = [int(x, 16) for x in ip.split(":")]
        mask = [0xffff for x in range(8)]

        match = OFPMatch()
        match.set_ipv6_src_masked(ipv6_src, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_dst(self):
        header = ofproto_v1_2.OXM_OF_IPV6_DST
        ip = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        value = ipv6_dst = [int(x, 16) for x in ip.split(":")]

        match = OFPMatch()
        match.set_ipv6_dst(ipv6_dst)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_dst_masked(self):
        header = ofproto_v1_2.OXM_OF_IPV6_DST_W
        ip = 'e9e8:9ea5:7d67:82cc:ca54:1fc0:2d24:f038'
        value = ipv6_dst = [int(x, 16) for x in ip.split(":")]
        mask = [0xffff for x in range(8)]

        match = OFPMatch()
        match.set_ipv6_dst_masked(ipv6_dst, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_flabel(self):
        header = ofproto_v1_2.OXM_OF_IPV6_FLABEL
        value = flabel = 0xc5384

        match = OFPMatch()
        match.set_ipv6_flabel(flabel)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_flabel_masked(self):
        header = ofproto_v1_2.OXM_OF_IPV6_FLABEL_W
        value = flabel = 0xc5384
        mask = 0xfffff

        match = OFPMatch()
        match.set_ipv6_flabel_masked(flabel, mask)

        self._test_serialize_and_parser(header, value, match)

    def test_set_icmpv6_type(self):
        header = ofproto_v1_2.OXM_OF_ICMPV6_TYPE
        value = icmpv6_type = 129

        match = OFPMatch()
        match.set_icmpv6_type(icmpv6_type)

        self._test_serialize_and_parser(header, value, match)

    def test_set_icmpv6_code(self):
        header = ofproto_v1_2.OXM_OF_ICMPV6_CODE
        value = icmpv6_code = 1

        match = OFPMatch()
        match.set_icmpv6_code(icmpv6_code)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_nd_target(self):
        header = ofproto_v1_2.OXM_OF_IPV6_ND_TARGET
        ip = '5420:db3f:921b:3e33:2791:98f:dd7f:2e19'
        value = target = [int(x, 16) for x in ip.split(":")]
        cls_ = OFPMatchField._FIELDS_HEADERS.get(header)

        match = OFPMatch()
        match.set_ipv6_nd_target(target)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_nd_sll(self):
        header = ofproto_v1_2.OXM_OF_IPV6_ND_SLL
        value = nd_sll = mac.haddr_to_bin('93:6d:d0:d4:e8:36')

        match = OFPMatch()
        match.set_ipv6_nd_sll(nd_sll)

        self._test_serialize_and_parser(header, value, match)

    def test_set_ipv6_nd_tll(self):
        header = ofproto_v1_2.OXM_OF_IPV6_ND_TLL
        value = nd_tll = mac.haddr_to_bin('18:f6:66:b6:f1:b3')

        match = OFPMatch()
        match.set_ipv6_nd_tll(nd_tll)

        self._test_serialize_and_parser(header, value, match)

    def test_set_mpls_label(self):
        header = ofproto_v1_2.OXM_OF_MPLS_LABEL
        value = mpls_label = 2144

        match = OFPMatch()
        match.set_mpls_label(mpls_label)

        self._test_serialize_and_parser(header, value, match)

    def test_set_mpls_(self):
        header = ofproto_v1_2.OXM_OF_MPLS_TC
        value = mpls_tc = 3

        match = OFPMatch()
        match.set_mpls_tc(mpls_tc)

        self._test_serialize_and_parser(header, value, match)
