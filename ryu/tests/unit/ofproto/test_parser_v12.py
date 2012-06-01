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
from nose.tools import *
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
    # '!I4x6s2x16sIIIIIIII'... port_no, zfill, hw_addr, zfill,
    #                          name, config, state, curr, advertised,
    #                          peer, curr_speed, max_speed
    port_no = {'buf': '\x42\xbd\x27\xfc', 'val': 1119692796}
    zfill0 = '\x00' * 4
    hw_addr = 'hw'.ljust(6)
    zfill1 = '\x00' * 2
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
        + zfill0 \
        + hw_addr \
        + zfill1 \
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
        #              zfill, capabilities, reserved
        datapath_id = {'buf': '\x11\xa3\x72\x63\x61\xde\x39\x81',
                       'val': 1270985291017894273}
        n_buffers = {'buf': '\x80\x14\xd7\xf6', 'val': 2148849654}
        n_tables = {'buf': '\xe4', 'val': 228}
        zfill = '\x00' * 3
        capabilities = {'buf': '\x69\x4f\xe4\xc2', 'val': 1766843586}
        reserved = {'buf': '\x78\x06\xd9\x0c', 'val': 2013714700}

        buf += datapath_id['buf'] \
            + n_buffers['buf'] \
            + n_tables['buf'] \
            + zfill \
            + capabilities['buf'] \
            + reserved['buf']

        # OFP_PORT_PACK_STR
        # '!I4x6s2x16sIIIIIIII'... port_no, zfill, hw_addr, zfill,
        #                          name, config, state, curr, advertised,
        #                          peer, curr_speed, max_speed
        port_no = {'buf': '\x42\xbd\x27\xfc', 'val': 1119692796}
        zfill0 = '\x00' * 4
        hw_addr = 'hw'.ljust(6)
        zfill1 = '\x00' * 2
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
            + zfill0 \
            + hw_addr \
            + zfill1 \
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
