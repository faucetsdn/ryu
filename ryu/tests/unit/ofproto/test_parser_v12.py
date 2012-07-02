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


LOG = logging.getLogger('test_ofproto_v12')


class TestMsgParser(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.msg_parser
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
        version = {'buf': '\x03', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x00', 'val': ofproto_v1_2.OFPT_HELLO}
        msg_len = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_HEADER_SIZE}
        xid = {'buf': '\x50\x26\x6a\x4c', 'val': 1344694860}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        c = msg_parser(Datapath,
                       version['val'],
                       msg_type['val'],
                       msg_len['val'],
                       xid['val'],
                       buf)

        eq_(version['val'], c.version)
        eq_(msg_type['val'], c.msg_type)
        eq_(msg_len['val'], c.msg_len)
        eq_(xid['val'], c.xid)

        # buf
        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR
        res = struct.unpack(fmt, c.buf)

        eq_(version['val'], res[0])
        eq_(msg_type['val'], res[1])
        eq_(msg_len['val'], res[2])
        eq_(xid['val'], res[3])


class TestOFPPort(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPPort
    """

    # OFP_PORT_PACK_STR
    # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
    #                          name, config, state, curr, advertised,
    #                          peer, curr_speed, max_speed
    port_no = {'buf': '\x42\xbd\x27\xfc', 'val': 1119692796}
    hw_addr = 'hw'.ljust(6)
    name = 'name'.ljust(16)
    config = {'buf': '\x84\xb6\x8c\x53', 'val': 2226555987}
    state = {'buf': '\x64\x07\xfb\xc9', 'val': 1678244809}
    curr = {'buf': '\xa9\xe8\x0a\x2b', 'val': 2850556459}
    advertised = {'buf': '\x78\xb9\x7b\x72', 'val': 2025421682}
    supported = {'buf': '\x7e\x65\x68\xad', 'val': 2120575149}
    peer = {'buf': '\xa4\x5b\x8b\xed', 'val': 2757463021}
    curr_speed = {'buf': '\x9d\x6f\xdb\x23', 'val': 2641353507}
    max_speed = {'buf': '\x6b\x20\x7e\x98', 'val': 1797291672}

    buf = port_no['buf'] \
        + pack('4x') \
        + hw_addr \
        + pack('2x') \
        + name \
        + config['buf'] \
        + state['buf'] \
        + curr['buf'] \
        + advertised['buf'] \
        + supported['buf'] \
        + peer['buf'] \
        + curr_speed['buf'] \
        + max_speed['buf']

    c = OFPPort(port_no['val'],
                hw_addr,
                name,
                config['val'],
                state['val'],
                curr['val'],
                advertised['val'],
                supported['val'],
                peer['val'],
                curr_speed['val'],
                max_speed['val'])

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
        eq_(self.curr_speed['val'], self.c.curr_speed)
        eq_(self.max_speed['val'], self.c.max_speed)

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
        eq_(self.curr_speed['val'], res.curr_speed)
        eq_(self.max_speed['val'], res.max_speed)


class TestOFPHello(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPHello
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_parser(self):
        xid = 2183948390
        res = OFPHello.parser(object, \
                              ofproto_v1_2.OFP_VERSION, \
                              ofproto_v1_2.OFPT_HELLO, \
                              ofproto_v1_2.OFP_HEADER_SIZE, \
                              xid, \
                              str().zfill(ofproto_v1_2.OFP_HEADER_SIZE))

        eq_(ofproto_v1_2.OFP_VERSION, res.version)
        eq_(ofproto_v1_2.OFPT_HELLO, res.msg_type)
        eq_(ofproto_v1_2.OFP_HEADER_SIZE, res.msg_len)
        eq_(xid, res.xid)

        # test __str__()
        list_ = ('version:', 'msg_type', 'xid')
        check = {}
        str_ = str(res)
        str_ = str_.rsplit()

        i = 0
        for s in str_:
            if s in list_:
                check[str_[i]] = str_[i + 1]
            i += 1

        # comparison fails in some environment
        #   such as hex() returns string with suffix 'L'
        eq_(hex(ofproto_v1_2.OFP_VERSION).find(check['version:']), 0)
        eq_(hex(ofproto_v1_2.OFPT_HELLO).find(check['msg_type']), 0)
        eq_(hex(xid).find(check['xid']), 0)

    def test_serialize(self):

        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        c = OFPHello(Datapath)
        c.serialize()
        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_HELLO, c.msg_type)
        eq_(0, c.xid)


class TestOFPFeaturesRequest(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPFeaturesRequest
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

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_FEATURES_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_FEATURES_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])


class TestOFPSwitchFeatures(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPSwitchFeatures
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
        version = {'buf': '\x03', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x06', 'val': ofproto_v1_2.OFPT_FEATURES_REPLY}
        msg_len = {'buf': '\x00\x4c',
                   'val': ofproto_v1_2.OFP_SWITCH_FEATURES_SIZE \
                        + ofproto_v1_2.OFP_PORT_SIZE}
        xid = {'buf': '\xcc\x0a\x41\xd4', 'val': 3423224276}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_SWITCH_FEATURES_PACK_STR
        # '!QIB3xII'...datapath_id, n_buffers, n_tables,
        #              pad(3), capabilities, reserved
        datapath_id = {'buf': '\x11\xa3\x72\x63\x61\xde\x39\x81',
                       'val': 1270985291017894273}
        n_buffers = {'buf': '\x80\x14\xd7\xf6', 'val': 2148849654}
        n_tables = {'buf': '\xe4', 'val': 228}
        capabilities = {'buf': '\x69\x4f\xe4\xc2', 'val': 1766843586}
        reserved = {'buf': '\x78\x06\xd9\x0c', 'val': 2013714700}

        buf += datapath_id['buf'] \
            + n_buffers['buf'] \
            + n_tables['buf'] \
            + pack('3x') \
            + capabilities['buf'] \
            + reserved['buf']

        # OFP_PORT_PACK_STR
        # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
        #                          name, config, state, curr, advertised,
        #                          peer, curr_speed, max_speed
        port_no = {'buf': '\x42\xbd\x27\xfc', 'val': 1119692796}
        hw_addr = 'hw'.ljust(6)
        name = 'name'.ljust(16)
        config = {'buf': '\x84\xb6\x8c\x53', 'val': 2226555987}
        state = {'buf': '\x64\x07\xfb\xc9', 'val': 1678244809}
        curr = {'buf': '\xa9\xe8\x0a\x2b', 'val': 2850556459}
        advertised = {'buf': '\x78\xb9\x7b\x72', 'val': 2025421682}
        supported = {'buf': '\x7e\x65\x68\xad', 'val': 2120575149}
        peer = {'buf': '\xa4\x5b\x8b\xed', 'val': 2757463021}
        curr_speed = {'buf': '\x9d\x6f\xdb\x23', 'val': 2641353507}
        max_speed = {'buf': '\x6b\x20\x7e\x98', 'val': 1797291672}

        buf += port_no['buf'] \
            + pack('4x') \
            + hw_addr \
            + pack('2x') \
            + name \
            + config['buf'] \
            + state['buf'] \
            + curr['buf'] \
            + advertised['buf'] \
            + supported['buf'] \
            + peer['buf'] \
            + curr_speed['buf'] \
            + max_speed['buf']

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
        eq_(reserved['val'], res.reserved)

        # port
        port = res.ports[port_no['val']]
        eq_(port_no['val'], port.port_no)
        eq_(hw_addr, port.hw_addr)
        eq_(name, port.name)
        eq_(config['val'], port.config)
        eq_(state['val'], port.state)
        eq_(curr['val'], port.curr)
        eq_(advertised['val'], port.advertised)
        eq_(supported['val'], port.supported)
        eq_(peer['val'], port.peer)
        eq_(curr_speed['val'], port.curr_speed)
        eq_(max_speed['val'], port.max_speed)

        # test __str__()
        list_ = ('version:', 'msg_type', 'xid',)
        check = {}
        str_ = str(res)
        str_ = str_.rsplit()

        i = 0
        for s in str_:
            if s in list_:
                check[str_[i]] = str_[i + 1]
            i += 1

        eq_(hex(version['val']).find(check['version:']), 0)
        eq_(hex(msg_type['val']).find(check['msg_type']), 0)
        eq_(hex(xid['val']).find(check['xid']), 0)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPSetConfig(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPSetConfig
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_SWITCH_CONFIG_PACK_STR
    # '!HH'...flags, miss_send_len
    flags = {'buf': '\xa0\xe2', 'val': 41186}
    miss_send_len = {'buf': '\x36\x0e', 'val': 13838}

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

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_SET_CONFIG, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_SWITCH_CONFIG_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_SET_CONFIG, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(self.flags['val'], res[4])
        eq_(self.miss_send_len['val'], res[5])


class TestOFPEchoRequest(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPEchoRequest
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
        version = {'buf': '\x01', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x02', 'val': ofproto_v1_2.OFPT_ECHO_REQUEST}
        msg_len = {'buf': '\x00\x08',
                   'val': ofproto_v1_2.OFP_HEADER_SIZE}
        xid = {'buf': '\x84\x47\xef\x3f', 'val': 2219306815}

        data = 'Request Message.'

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

        # test __str__()
        list_ = ('version:', 'msg_type', 'xid')
        check = {}
        str_ = str(res)
        str_ = str_.rsplit()

        i = 0
        for s in str_:
            if s in list_:
                check[str_[i]] = str_[i + 1]
            i += 1

        # comparison fails in some environment
        #   such as hex() returns string with suffix 'L'
        eq_(hex(version['val']).find(check['version:']), 0)
        eq_(hex(msg_type['val']).find(check['msg_type']), 0)
        eq_(hex(xid['val']).find(check['xid']), 0)

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        data = 'Request Message.'

        c = OFPEchoRequest(Datapath)
        c.data = data

        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_ECHO_REQUEST, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, str(c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_ECHO_REQUEST, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(data, res[4])


class TestOFPEchoReply(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPEchoReply
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
        version = {'buf': '\x01', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x03', 'val': ofproto_v1_2.OFPT_ECHO_REPLY}
        msg_len = {'buf': '\x00\x08',
                   'val': ofproto_v1_2.OFP_HEADER_SIZE}
        xid = {'buf': '\x6e\x21\x3e\x62', 'val': 1847672418}

        data = 'Reply Message.'

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

        # test __str__()
        list_ = ('version:', 'msg_type', 'xid')
        check = {}
        str_ = str(res)
        str_ = str_.rsplit()

        i = 0
        for s in str_:
            if s in list_:
                check[str_[i]] = str_[i + 1]
            i += 1

        # comparison fails in some environment
        #   such as hex() returns string with suffix 'L'
        eq_(hex(version['val']).find(check['version:']), 0)
        eq_(hex(msg_type['val']).find(check['msg_type']), 0)
        eq_(hex(xid['val']).find(check['xid']), 0)

    def test_serialize(self):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        data = 'Reply Message.'

        c = OFPEchoReply(Datapath)
        c.data = data

        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_ECHO_REPLY, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, str(c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_ECHO_REPLY, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])
        eq_(data, res[4])


class TestOFPGetConfigRequest(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPGetConfigRequest
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

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_GET_CONFIG_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = ofproto_v1_2.OFP_HEADER_PACK_STR

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_GET_CONFIG_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])


class TestOFPGetConfigReply(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPGetConfigReply
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
        version = {'buf': '\x01', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x0a', 'val': ofproto_v1_2.OFPT_GET_CONFIG_REPLY}
        msg_len = {'buf': '\x00\x14',
                   'val': ofproto_v1_2.OFP_SWITCH_CONFIG_SIZE}
        xid = {'buf': '\x94\xc4\xd2\xcd', 'val': 2495926989}

        # OFP_SWITCH_CONFIG_PACK_STR
        # '!HH'...flags, miss_send_len
        flags = {'buf': '\xa0\xe2', 'val': 41186}
        miss_send_len = {'buf': '\x36\x0e', 'val': 13838}

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

        # test __str__()
        list_ = ('version:', 'msg_type', 'xid',)
        check = {}
        str_ = str(res)
        str_ = str_.rsplit()

        i = 0
        for s in str_:
            if s in list_:
                check[str_[i]] = str_[i + 1]
            i += 1

        eq_(hex(version['val']).find(check['version:']), 0)
        eq_(hex(msg_type['val']).find(check['msg_type']), 0)
        eq_(hex(xid['val']).find(check['xid']), 0)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPPacketIn(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPPacketIn
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
        version = {'buf': '\x01', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x0a', 'val': ofproto_v1_2.OFPT_PACKET_IN}
        msg_len = {'buf': '\x00\x14', 'val': ofproto_v1_2.OFP_PACKET_IN_SIZE}
        xid = {'buf': '\xd0\x23\x8c\x34', 'val': 3491990580}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_PACKET_IN_PACK_STR v1.2
        # '!IHHBB'...buffer_id, total_len, reason, table_id
        buffer_id = {'buf': '\xae\x73\x90\xec', 'val': 2926809324}
        total_len = {'buf': '\x00\x10', 'val': 16}
        reason = {'buf': '\x43', 'val': 67}
        table_id = {'buf': '\x03', 'val': 3}

        buf += buffer_id['buf'] \
            + total_len['buf'] \
            + reason['buf'] \
            + table_id['buf']

        # OFP_MATCH_PACK_STR v1.2
        # '!HHBBBB'...type, length, oxm_fields[4]
        type = {'buf': '\x00\x01', 'val': 1}
        length = {'buf': '\x00\x04', 'val': 4}
        oxm_fields = []
        oxm_fields.append({'buf': '\x79', 'val': 121})
        oxm_fields.append({'buf': '\x7a', 'val': 122})
        oxm_fields.append({'buf': '\x7b', 'val': 123})
        oxm_fields.append({'buf': '\x7c', 'val': 124})

        buf += type['buf'] \
            + length['buf'] \
            + oxm_fields[0]['buf'] \
            + oxm_fields[1]['buf'] \
            + oxm_fields[2]['buf'] \
            + oxm_fields[3]['buf']

        res = OFPPacketIn.parser(object,
                                 version['val'],
                                 msg_type['val'],
                                 msg_len['val'],
                                 xid['val'],
                                 buf)

        # OFP_HEADER_PACK_STR
        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)

        # OFP_PACKET_IN_PACK_STR
        eq_(buffer_id['val'], res.buffer_id)
        eq_(total_len['val'], res.total_len)
        eq_(reason['val'], res.reason)
        eq_(table_id['val'], res.table_id)

        # OFP_MATCH_PACK_STR
        eq_(type['val'], res.match.type)
        eq_(length['val'], res.match.length)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPFlowRemoved(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPFlowRemoved
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
        version = {'buf': '\x01', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x0a', 'val': ofproto_v1_2.OFPT_FLOW_REMOVED}
        msg_len = {'buf': '\x00\x14',
                   'val': ofproto_v1_2.OFP_FLOW_REMOVED_SIZE}
        xid = {'buf': '\x94\xc4\xd2\xcd', 'val': 2495926989}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_FLOW_REMOVED_PACK_STR0 v1.2
        # '!QHBBIIHHQQ' ...cookie, priority, reason, table_id,
        #                  duration_sec, duration_nsec, idle_timeout,
        #                  hard_timeout, packet_count, byte_count
        cookie = {'buf': '\x02\x79\xba\x00\xef\xab\xee\x44',
                  'val': 178378173441633860}
        priority = {'buf': '\x02\xce', 'val': 718}
        reason = {'buf': '\x01', 'val': 1}
        table_id = {'buf': '\xa9', 'val': 169}
        duration_sec = {'buf': '\x86\x24\xa3\xba', 'val': 2250548154}
        duration_nsec = {'buf': '\x94\x94\xc2\x23', 'val': 2492776995}
        idle_timeout = {'buf': '\xeb\x7c', 'val': 60284}
        hard_timeout = {'buf': '\xeb\x7d', 'val': 60285}
        packet_count = {'buf': '\x5a\x0d\xf2\x03\x8e\x0a\xbb\x8d',
                        'val': 6489108735192644493}
        byte_count = {'buf': '\x65\xc8\xd3\x72\x51\xb5\xbb\x7c',
                      'val': 7334344481123449724}

        buf += cookie['buf'] \
            + priority['buf'] \
            + reason['buf'] \
            + table_id['buf'] \
            + duration_sec['buf'] \
            + duration_nsec['buf'] \
            + idle_timeout['buf'] \
            + hard_timeout['buf'] \
            + packet_count['buf'] \
            + byte_count['buf']

        # OFP_MATCH_PACK_STR v1.2
        # '!HHBBBB'...type, length, oxm_fields[4]
        type = {'buf': '\x00\x01', 'val': 1}
        length = {'buf': '\x00\x04', 'val': 4}
        oxm_fields = []
        oxm_fields.append({'buf': '\x79', 'val': 121})
        oxm_fields.append({'buf': '\x7a', 'val': 122})
        oxm_fields.append({'buf': '\x7b', 'val': 123})
        oxm_fields.append({'buf': '\x7c', 'val': 124})

        buf += type['buf'] \
            + length['buf'] \
            + oxm_fields[0]['buf'] \
            + oxm_fields[1]['buf'] \
            + oxm_fields[2]['buf'] \
            + oxm_fields[2]['buf'] \
            + oxm_fields[3]['buf']

        res = OFPFlowRemoved.parser(object,
                                    version['val'],
                                    msg_type['val'],
                                    msg_len['val'],
                                    xid['val'],
                                    buf)

        # OFP_HEADER_PACK_STR
        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)

        # OFP_FLOW_REMOVED_PACK_STR0
        eq_(cookie['val'], res.cookie)
        eq_(priority['val'], res.priority)
        eq_(reason['val'], res.reason)
        eq_(table_id['val'], res.table_id)
        eq_(duration_sec['val'], res.duration_sec)
        eq_(duration_nsec['val'], res.duration_nsec)
        eq_(idle_timeout['val'], res.idle_timeout)
        eq_(hard_timeout['val'], res.hard_timeout)
        eq_(packet_count['val'], res.packet_count)
        eq_(byte_count['val'], res.byte_count)

        # OFP_MATCH_PACK_STR
        eq_(type['val'], res.match.type)
        eq_(length['val'], res.match.length)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPPortStatus(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPPortStatus
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
        version = {'buf': '\x03', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x0c', 'val': ofproto_v1_2.OFPT_PORT_STATUS}
        msg_len = {'buf': '\x00\x50', 'val': 80}
        xid = {'buf': '\xcc\x0a\x41\xd4', 'val': 3423224276}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_PORT_STATUS_PACK_STR
        # '!B7x'...reason, pad(7)
        reason = {'buf': '\x00', 'val': 0}

        buf += reason['buf'] \
            + pack('7x')

        # OFP_PORT_PACK_STR
        # '!I4x6s2x16sIIIIIIII'... port_no, pad(4), hw_addr, pad(2),
        #                          name, config, state, curr, advertised,
        #                          peer, curr_speed, max_speed
        port_no = {'buf': '\x42\xbd\x27\xfc', 'val': 1119692796}
        hw_addr = 'hw'.ljust(6)
        name = 'name'.ljust(16)
        config = {'buf': '\x84\xb6\x8c\x53', 'val': 2226555987}
        state = {'buf': '\x64\x07\xfb\xc9', 'val': 1678244809}
        curr = {'buf': '\xa9\xe8\x0a\x2b', 'val': 2850556459}
        advertised = {'buf': '\x78\xb9\x7b\x72', 'val': 2025421682}
        supported = {'buf': '\x7e\x65\x68\xad', 'val': 2120575149}
        peer = {'buf': '\xa4\x5b\x8b\xed', 'val': 2757463021}
        curr_speed = {'buf': '\x9d\x6f\xdb\x23', 'val': 2641353507}
        max_speed = {'buf': '\x6b\x20\x7e\x98', 'val': 1797291672}

        buf += port_no['buf'] \
            + pack('4x') \
            + hw_addr \
            + pack('2x') \
            + name \
            + config['buf'] \
            + state['buf'] \
            + curr['buf'] \
            + advertised['buf'] \
            + supported['buf'] \
            + peer['buf'] \
            + curr_speed['buf'] \
            + max_speed['buf']

        res = OFPPortStatus.parser(object,
                                   version['val'],
                                   msg_type['val'],
                                   msg_len['val'],
                                   xid['val'],
                                   buf)

        # OFP_PORT_STATUS_PACK_STR
        eq_(reason['val'], res.reason)

        # OFP_PORT_PACK_STR
        eq_(port_no['val'], res.desc.port_no)
        eq_(hw_addr, res.desc.hw_addr)
        eq_(name, res.desc.name)
        eq_(config['val'], res.desc.config)
        eq_(state['val'], res.desc.state)
        eq_(curr['val'], res.desc.curr)
        eq_(advertised['val'], res.desc.advertised)
        eq_(supported['val'], res.desc.supported)
        eq_(peer['val'], res.desc.peer)
        eq_(curr_speed['val'], res.desc.curr_speed)
        eq_(max_speed['val'], res.desc.max_speed)

    def test_serialize(self):
        # Not used.
        pass


class TestOFPPacketOut(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPPacketOut
    """

    port = 0x00002ae0
    actions = [OFPActionOutput(port, 0)]

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _get_obj(self, buffer_id, in_port, data=None):
        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        c = OFPPacketOut(Datapath,
                         buffer_id,
                         in_port,
                         self.actions,
                         data)
        return c

    def test_init(self):
        buffer_id = 0xffffffff
        in_port = 0x00040455
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
        in_port = 0x10009e07
        data = 'Message'

        c = self._get_obj(buffer_id, in_port, data)
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_PACKET_OUT, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_PACKET_OUT_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR.replace('!', '') \
            + str(len(data)) + 's'

        res = struct.unpack(fmt, str(c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_PACKET_OUT, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])

        # OFP_PACKET_OUT_PACK_STR
        eq_(buffer_id, res[4])
        eq_(in_port, res[5])
        eq_(ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE, res[6])

        # OFP_ACTION_OUTPUT_PACK_STR
        eq_(ofproto_v1_2.OFPAT_OUTPUT, res[7])
        eq_(ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE, res[8])
        eq_(self.port, res[9])
        eq_(0, res[10])

        # data
        eq_(data, res[11])


class TestOFPFlowMod(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPFlowMod
    """

    # OFP_FLOW_MOD_PACK_STR0 v1.2
    # '!QQBBHHHIIIH2x'...cookie, cookie_mask, table_id, command,
    #                    idle_timeout, hard_timeout, priority, buffer_id,
    #                    out_port, out_group, flags
    cookie = {'buf': '\x1d\x86\xce\x6e\x8d\xc0\xbe\xa8',
              'val': 2127614848199081640}
    cookie_mask = {'buf': '\x1d\x86\xce\x6e\x8d\xc0\xbe\xa9',
                   'val': 2127614848199081641}
    table_id = {'buf': '\x03', 'val': 3}
    command = {'buf': '\x00', 'val': 0}
    idle_timeout = {'buf': '\xf3\x6d', 'val': 62317}
    hard_timeout = {'buf': '\x1c\xc5', 'val': 7365}
    priority = {'buf': '\x9c\xe3', 'val': 40163}
    buffer_id = {'buf': '\xf0\xa1\x80\x33', 'val': 4037115955}
    out_port = {'buf': '\x00\x00\xfe\x0d', 'val': 65037}
    out_group = {'buf': '\x00\x00\x19\xce', 'val': 6606}
    flags = {'buf': '\x00\x87', 'val': 135}

    match = OFPMatch()

    instructions = [OFPInstructionGotoTable(table_id['val'])]

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _get_obj(self):

        class Datapath(object):
            ofproto = ofproto_v1_2
            ofproto_parser = ofproto_v1_2_parser

        c = OFPFlowMod(Datapath,
                       self.cookie['val'],
                       self.cookie_mask['val'],
                       self.table_id['val'],
                       self.command['val'],
                       self.idle_timeout['val'],
                       self.hard_timeout['val'],
                       self.priority['val'],
                       self.buffer_id['val'],
                       self.out_port['val'],
                       self.out_group['val'],
                       self.flags['val'],
                       self.match,
                       self.instructions)

        return c

    def test_init(self):
        c = self._get_obj()

        eq_(self.cookie['val'], c.cookie)
        eq_(self.cookie_mask['val'], c.cookie_mask)
        eq_(self.table_id['val'], c.table_id)
        eq_(self.command['val'], c.command)
        eq_(self.idle_timeout['val'], c.idle_timeout)
        eq_(self.hard_timeout['val'], c.hard_timeout)
        eq_(self.priority['val'], c.priority)
        eq_(self.buffer_id['val'], c.buffer_id)
        eq_(self.out_port['val'], c.out_port)
        eq_(self.out_group['val'], c.out_group)
        eq_(self.flags['val'], c.flags)
        eq_(self.match, c.match)
        eq_(self.instructions[0], c.instructions[0])

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        c = self._get_obj()
        c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, c.version)
        eq_(ofproto_v1_2.OFPT_FLOW_MOD, c.msg_type)
        eq_(0, c.xid)

        fmt = '!' \
            + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_FLOW_MOD_PACK_STR.replace('!', '') \
            + ofproto_v1_2.OFP_INSTRUCTION_GOTO_TABLE_PACK_STR.replace('!', '')
        res = struct.unpack(fmt, str(c.buf))

        # OFP_HEADER_PACK_STR
        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_FLOW_MOD, res[1])
        eq_(len(c.buf), res[2])
        eq_(0, res[3])

        # OFP_FLOW_MOD_PACK_STR0
        eq_(self.cookie['val'], res[4])
        eq_(self.cookie_mask['val'], res[5])
        eq_(self.table_id['val'], res[6])
        eq_(self.command['val'], res[7])
        eq_(self.idle_timeout['val'], res[8])
        eq_(self.hard_timeout['val'], res[9])
        eq_(self.priority['val'], res[10])
        eq_(self.buffer_id['val'], res[11])
        eq_(self.out_port['val'], res[12])
        eq_(self.out_group['val'], res[13])
        eq_(self.flags['val'], res[14])


class TestOFPActionHeader(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionHeader
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH4x'...type, len, pad(4)
    type = {'buf': '\x00\x02', 'val': 2}
    len = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_HEADER_SIZE}

    buf = type['buf'] \
        + len['buf'] \
        + pack('4x')

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

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type['val'], res[0])
        eq_(self.len['val'], res[1])


class TestOFPActionOutput(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionOutput
    """

    # OFP_ACTION_OUTPUT_PACK_STR v1.2
    # '!HHIH6x'...type, len, port, max_len, pad(6)
    type_ = {'buf': '\x00\x00', 'val': ofproto_v1_2.OFPAT_OUTPUT}
    len_ = {'buf': '\x00\x10', 'val': ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE}
    port = {'buf': '\x00\x00\x19\xce', 'val': 6606}
    max_len = {'buf': '\x00\x10', 'val': ofproto_v1_2.OFP_ACTION_OUTPUT_SIZE}

    buf = type_['buf'] \
        + len_['buf'] \
        + port['buf'] \
        + max_len['buf'] \
        + pack('6x')

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

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_OUTPUT_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.port['val'], res[2])
        eq_(self.max_len['val'], res[3])


class TestOFPActionGroup(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionGroup
    """

    # OFP_ACTION_GROUP_PACK_STR v1.2
    # '!HHI'...type, len, group_id
    type_ = {'buf': '\x00\x16', 'val': ofproto_v1_2.OFPAT_GROUP}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_GROUP_SIZE}
    group_id = {'buf': '\x00\x00\x19\xce', 'val': 6606}

    buf = type_['buf'] \
        + len_['buf'] \
        + group_id['buf']

    c = OFPActionGroup(group_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.group_id['val'], self.c.group_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.group_id['val'], res.group_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_GROUP_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.group_id['val'], res[2])


class TestOFPActionSetQueue(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionSetQueue
    """

    # OFP_ACTION_SET_QUEUE_PACK_STR v1.2
    # '!HHI'...type, len, queue_id
    type_ = {'buf': '\x00\x15', 'val': ofproto_v1_2.OFPAT_SET_QUEUE}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_SET_QUEUE_SIZE}
    queue_id = {'buf': '\x00\x00\x19\xce', 'val': 6606}

    buf = type_['buf'] \
        + len_['buf'] \
        + queue_id['buf']

    c = OFPActionSetQueue(queue_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.queue_id['val'], self.c.queue_id)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.queue_id['val'], res.queue_id)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_SET_QUEUE_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.queue_id['val'], res[2])


class TestOFPActionSetMplsTtl(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionSetMplsTtl
    """

    # OFP_ACTION_MPLS_TTL_PACK_STR v1.2
    # '!HHB3x'...type, len, mpls_ttl, pad(3)
    type_ = {'buf': '\x00\x0f', 'val': ofproto_v1_2.OFPAT_SET_MPLS_TTL}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_MPLS_TTL_SIZE}
    mpls_ttl = {'buf': '\xfe', 'val': 254}

    buf = type_['buf'] \
        + len_['buf'] \
        + mpls_ttl['buf'] \
        + pack('3x')

    c = OFPActionSetMplsTtl(mpls_ttl['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.mpls_ttl['val'], self.c.mpls_ttl)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.mpls_ttl['val'], res.mpls_ttl)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_MPLS_TTL_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.mpls_ttl['val'], res[2])


class TestOFPActionDecMplsTtl(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionDecMplsTtl
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH'...type, len
    type_ = {'buf': '\x00\x10', 'val': ofproto_v1_2.OFPAT_DEC_MPLS_TTL}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_HEADER_SIZE}

    c = OFPActionDecMplsTtl()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])


class TestOFPActionSetNwTtl(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionSetNwTtl
    """

    # OFP_ACTION_NW_TTL_PACK_STR v1.2
    # '!HHB3x'...type, len, nw_ttl, pad(3)
    type_ = {'buf': '\x00\x17', 'val': ofproto_v1_2.OFPAT_SET_NW_TTL}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_NW_TTL_SIZE}
    nw_ttl = {'buf': '\xf0', 'val': 240}

    buf = type_['buf'] \
        + len_['buf'] \
        + nw_ttl['buf'] \
        + pack('3x')

    c = OFPActionSetNwTtl(nw_ttl['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.nw_ttl['val'], self.c.nw_ttl)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.nw_ttl['val'], res.nw_ttl)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_NW_TTL_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.nw_ttl['val'], res[2])


class TestOFPActionDecNwTtl(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionDecNwTtl
    """

    # OFP_ACTION_HEADER_PACK_STR
    # '!HH'...type, len
    type_ = {'buf': '\x00\x18', 'val': ofproto_v1_2.OFPAT_DEC_NW_TTL}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_HEADER_SIZE}

    c = OFPActionDecNwTtl()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])


class TestOFPActionPushVlan(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionPushVlan
    """

    # OFP_ACTION_PUSH_PACK_STR v1.2
    # '!HHB3x'...type, len, ethertype, pad(2)
    type_ = {'buf': '\x00\x11', 'val': ofproto_v1_2.OFPAT_PUSH_VLAN}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_PUSH_SIZE}
    ethertype = {'buf': '\x1f\xa4', 'val': 8100}

    buf = type_['buf'] \
        + len_['buf'] \
        + ethertype['buf'] \
        + pack('2x')

    c = OFPActionPushVlan(ethertype['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.ethertype['val'], self.c.ethertype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.ethertype['val'], res.ethertype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.ethertype['val'], res[2])


class TestOFPActionPushMpls(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionPushMpls
    """

    # OFP_ACTION_PUSH_PACK_STR v1.2
    # '!HHH2x'...type, len, ethertype, pad(2)
    type_ = {'buf': '\x00\x13', 'val': ofproto_v1_2.OFPAT_PUSH_MPLS}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_PUSH_SIZE}
    ethertype = {'buf': '\x22\x8f', 'val': 8847}

    buf = type_['buf'] \
        + len_['buf'] \
        + ethertype['buf'] \
        + pack('2x')

    c = OFPActionPushMpls(ethertype['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.ethertype['val'], self.c.ethertype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.ethertype['val'], res.ethertype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_PUSH_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.ethertype['val'], res[2])


class OFPActionPopMpls(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionPopMpls
    """

    # OFP_ACTION_POP_MPLS_PACK_STR
    # '!HHH2x'...type, len, ethertype, pad(2)
    type_ = {'buf': '\x00\x14', 'val': ofproto_v1_2.OFPAT_POP_MPLS}
    len_ = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_ACTION_POP_MPLS_SIZE}
    ethertype = {'buf': '\x1f\xa4', 'val': 8100}

    buf = type_['buf'] \
        + len_['buf'] \
        + ethertype['buf'] \
        + pack('2x')

    c = OFPActionPopMpls(ethertype['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.ethertype['val'], self.c.ethertype)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.ethertype['val'], res.ethertype)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_POP_MPLS_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.ethertype['val'], res[2])


class TestOFPActionExperimenter(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPActionExperimenter
    """

    # OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR v1.2
    # '!HHI'...type, len, experimenter
    type_ = {'buf': '\xff\xff', 'val': ofproto_v1_2.OFPAT_EXPERIMENTER}
    len_ = {'buf': '\x00\x08',
            'val': ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_SIZE}
    experimenter = {'buf': '\xff\xff\xff\xff', 'val': 4294967295}

    buf = type_['buf'] \
        + len_['buf'] \
        + experimenter['buf']

    c = OFPActionExperimenter(experimenter['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.experimenter['val'], self.c.experimenter)

    def test_parser(self):
        res = self.c.parser(self.buf, 0)

        eq_(self.experimenter['val'], res.experimenter)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.type_['val'], res[0])
        eq_(self.len_['val'], res[1])
        eq_(self.experimenter['val'], res[2])


class TestOFPPortMod(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPPortMod
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_PORT_MOD_PACK_STR v1.2
    # '!I4xs2xIII4x'...port_no, pad(4), hw_addr, pad(2),
    #                  config, mask, advertise, pad(4)
    port_no = {'buf': '\x42\xbd\x27\xfc', 'val': 1119692796}
    hw_addr = 'hw'.ljust(ofproto_v1_2.OFP_ETH_ALEN)
    config = {'buf': '\x84\xb6\x8c\x53', 'val': 2226555987}
    mask = {'buf': '\x64\x07\xfb\xc9', 'val': 1678244809}
    advertise = {'buf': '\x78\xb9\x7b\x72', 'val': 2025421682}

    c = OFPPortMod(Datapath, port_no['val'], hw_addr, config['val'],
                             mask['val'], advertise['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.port_no['val'], self.c.port_no)
        eq_(self.hw_addr, self.c.hw_addr)
        eq_(self.config['val'], self.c.config)
        eq_(self.mask['val'], self.c.mask)
        eq_(self.advertise['val'], self.c.advertise)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_PORT_MOD, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
          + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
          + ofproto_v1_2.OFP_PORT_MOD_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_PORT_MOD, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(self.port_no['val'], res[4])
        eq_(self.hw_addr, res[5])
        eq_(self.config['val'], res[6])
        eq_(self.mask['val'], res[7])
        eq_(self.advertise['val'], res[8])


class TestOFPTableMod(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPTableMod
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_PORT_TABLE_PACK_STR v1.2
    # '!B3xI'...table_id, pad(3), config
    table_id = {'buf': '\x03', 'val': 3}
    config = {'buf': '\x84\xb6\x8c\x53', 'val': 2226555987}

    c = OFPTableMod(Datapath, table_id['val'], config['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.table_id['val'], self.c.table_id)
        eq_(self.config['val'], self.c.config)

    def test_parser(self):
        # Not used.
        pass

    def test_serialize(self):
        self.c.serialize()

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_TABLE_MOD, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
          + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
          + ofproto_v1_2.OFP_TABLE_MOD_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_TABLE_MOD, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(self.table_id['val'], res[4])
        eq_(self.config['val'], res[5])


class TestOFPQueueGetConfigRequest(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPQueueGetConfigRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR v1.2
    # '!I4x'...port, pad(4)
    port = {'buf': '\x00\x00\xa0\xe2', 'val': 41186}

    c = OFPQueueGetConfigRequest(Datapath, port['val'])

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

        eq_(ofproto_v1_2.OFP_VERSION, self.c.version)
        eq_(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST, self.c.msg_type)
        eq_(0, self.c.xid)

        fmt = '!' \
          + ofproto_v1_2.OFP_HEADER_PACK_STR.replace('!', '') \
          + ofproto_v1_2.OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR.replace('!', '')

        res = struct.unpack(fmt, str(self.c.buf))

        eq_(ofproto_v1_2.OFP_VERSION, res[0])
        eq_(ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST, res[1])
        eq_(len(self.c.buf), res[2])
        eq_(0, res[3])
        eq_(self.port['val'], res[4])


class OFPQueuePropHeader(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPQueuePropHeader
    """

    # OFP_QUEUE_PROP_HEADER_PACK_STR
    # '!HH4x'...property, len, pad(4)
    property = {'buf': '\x00\x01', 'val': 1}
    len = {'buf': '\x00\x08', 'val': ofproto_v1_2.OFP_QUEUE_PROP_HEADER_SIZE}

    buf = property['buf'] \
        + len['buf'] \
        + pack('4x')

    c = OFPQueuePropHeader(property['val'], len['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.property['val'], self.c.property)
        eq_(self.len['val'], self.c.len)

    def test_serialize(self):
        buf = bytearray()
        self.c.serialize(buf, 0)

        fmt = ofproto_v1_2.OFP_QUEUE_PROP_HEADER_PACK_STR
        res = struct.unpack(fmt, buffer(buf))

        eq_(self.property['val'], res[0])
        eq_(self.len['val'], res[1])


class OFPRoleRequest(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPRoleRequest
    """

    class Datapath(object):
        ofproto = ofproto_v1_2
        ofproto_parser = ofproto_v1_2_parser

    # OFP_ROLE_REQUEST_PACK_STR
    # '!I4xQ'...role, pad(4), generation_id
    role = {'buf': '\x00\x00\x00\x0a', 'val': 10}
    generation_id = {'buf': '\x11\xa3\x72\x63\x61\xde\x39\x81',
                     'val': 1270985291017894273}

    c = OFPRoleRequest(Datapath,
                       role['val'],
                       generation_id['val'])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.role['val'], self.c.role)
        eq_(self.generation_id['val'], self.c.generation_id)

    def test_parser(self):
        # Not used.
        pass

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
        eq_(self.role['val'], res[4])
        eq_(self.generation_id['val'], res[5])


class TestOFPRoleReply(unittest.TestCase):
    """ Test case for ofprotp_v1_2_parser.OFPRoleReply
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
        # '!BBHI'...version, msg_type, msg_len, xid
        version = {'buf': '\x01', 'val': ofproto_v1_2.OFP_VERSION}
        msg_type = {'buf': '\x19', 'val': ofproto_v1_2.OFPT_ROLE_REPLY}
        msg_len = {'buf': '\x00\x18',
                   'val': ofproto_v1_2.OFP_ROLE_REQUEST_SIZE}
        xid = {'buf': '\x94\xc4\xd2\xcd', 'val': 2495926989}

        buf = version['buf'] \
            + msg_type['buf'] \
            + msg_len['buf'] \
            + xid['buf']

        # OFP_ROLE_REQUEST_PACK_STR
        # '!I4xQ'...role, pad(4), generation_id
        role = {'buf': '\x00\x00\x00\x0a', 'val': 10}
        generation_id = {'buf': '\x11\xa3\x72\x63\x61\xde\x39\x81',
                         'val': 1270985291017894273}

        buf += role['buf'] \
            + pack('4x') \
            + generation_id['buf']

        res = OFPRoleReply.parser(object,
                                  version['val'],
                                  msg_type['val'],
                                  msg_len['val'],
                                  xid['val'],
                                  buf)

        # OFP_HEADER_PACK_STR
        eq_(version['val'], res.version)
        eq_(msg_type['val'], res.msg_type)
        eq_(msg_len['val'], res.msg_len)
        eq_(xid['val'], res.xid)

        # OFP_ROLE_REQUEST_PACK_STR
        eq_(role['val'], res.role)
        eq_(generation_id['val'], res.generation_id)

    def test_serialize(self):
        # Not used.
        pass
