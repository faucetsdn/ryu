#!/usr/bin/env python
#
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import sys
import unittest
from nose.tools import eq_

from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_0_parser
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3_parser
import json


# XXX dummy dp for testing
class DummyDatapath(object):
    def __init__(self, ofp, ofpp):
        self.ofproto = ofp
        self.ofproto_parser = ofpp


class Test_Parser(unittest.TestCase):
    """ Test case for ryu.ofproto, especially json representation
    """

    _ofp_versions = {
        ofproto_v1_0.OFP_VERSION: (ofproto_v1_0,
                                   ofproto_v1_0_parser),
        ofproto_v1_2.OFP_VERSION: (ofproto_v1_2,
                                   ofproto_v1_2_parser),
        ofproto_v1_3.OFP_VERSION: (ofproto_v1_3,
                                   ofproto_v1_3_parser),
    }

    def __init__(self, methodName):
        print 'init', methodName
        super(Test_Parser, self).__init__(methodName)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @staticmethod
    def _msg_to_jsondict(msg):
        return msg.to_jsondict()

    @staticmethod
    def _jsondict_to_msg(dp, jsondict):
        return ofproto_parser.ofp_msg_from_jsondict(dp, jsondict)

    def _test_msg(self, name, wire_msg, json_str):
        json_dict = json.loads(json_str)
        # on-wire -> OFPxxx -> json
        has_parser = False
        (version, msg_type, msg_len, xid) = ofproto_parser.header(wire_msg)
        try:
            dp = DummyDatapath(*self._ofp_versions[version])
            msg = ofproto_parser.msg(dp, version, msg_type, msg_len, xid,
                                     wire_msg)
            json_dict2 = self._msg_to_jsondict(msg)
            # XXXdebug code
            open(('/tmp/%s.json' % name), 'wb').write(json.dumps(json_dict2))
            eq_(json_dict, json_dict2)
            has_parser = True
        except TypeError:
            # not all msg_type has a proper parser
            pass

        # XXX either of parser or serializer should work at least
        has_serializer = not has_parser

        # json -> OFPxxx -> json
        msg2 = self._jsondict_to_msg(dp, json_dict)
        msg2.serialize()
        eq_(self._msg_to_jsondict(msg2), json_dict)

        if has_serializer:
            eq_(wire_msg, msg2.buf)


def _add_tests():
    import os
    import fnmatch
    import new
    import functools

    packet_data_dir = '../packet_data'
    json_dir = './ofproto/json'
    ofvers = [
        'of10',
        'of12',
        'of13',
    ]
    for ver in ofvers:
        pdir = packet_data_dir + '/' + ver
        jdir = json_dir + '/' + ver
        for file in os.listdir(pdir):
            if not fnmatch.fnmatch(file, '*.packet'):
                continue
            wire_msg = open(pdir + '/' + file, 'rb').read()
            json_str = open(jdir + '/' + file + '.json', 'rb').read()
            method_name = ('test_' + file).replace('-', '_').replace('.', '_')

            def _run(self, name, wire_msg, json_str):
                print ('processing %s ...' % name)
                self._test_msg(name, wire_msg, json_str)
            print ('adding %s ...' % method_name)
            f = functools.partial(_run, name=method_name, wire_msg=wire_msg,
                                  json_str=json_str)
            f.func_name = method_name
            f.__name__ = method_name
            im = new.instancemethod(f, None, Test_Parser)
            setattr(Test_Parser, method_name, im)

_add_tests()
