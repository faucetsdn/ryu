# Copyright (C) 2013,2014,2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from __future__ import print_function

import six
import sys
import unittest
from nose.tools import eq_

from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.tests import test_lib
from ryu import exception
import json


# (has_parser, has_serializer)
implemented = {
    1: {
        ofproto_v1_0.OFPT_PACKET_OUT: (False, True),
        ofproto_v1_0.OFPT_FEATURES_REQUEST: (False, True),
        ofproto_v1_0.OFPT_FEATURES_REPLY: (True, False),
        ofproto_v1_0.OFPT_PACKET_IN: (True, False),
        ofproto_v1_0.OFPT_FLOW_MOD: (True, True),
    },
    3: {
        ofproto_v1_2.OFPT_FEATURES_REQUEST: (False, True),
        ofproto_v1_2.OFPT_FEATURES_REPLY: (True, False),
        ofproto_v1_2.OFPT_GET_CONFIG_REQUEST: (False, True),
        ofproto_v1_2.OFPT_GET_CONFIG_REPLY: (True, False),
        ofproto_v1_2.OFPT_SET_CONFIG: (False, True),
        ofproto_v1_2.OFPT_PACKET_IN: (True, False),
        ofproto_v1_2.OFPT_FLOW_REMOVED: (True, False),
        ofproto_v1_2.OFPT_PORT_STATUS: (True, False),
        ofproto_v1_2.OFPT_PACKET_OUT: (False, True),
        ofproto_v1_2.OFPT_FLOW_MOD: (True, True),
        ofproto_v1_2.OFPT_GROUP_MOD: (False, True),
        ofproto_v1_2.OFPT_PORT_MOD: (False, True),
        ofproto_v1_2.OFPT_TABLE_MOD: (False, True),
        ofproto_v1_2.OFPT_STATS_REQUEST: (False, True),
        ofproto_v1_2.OFPT_STATS_REPLY: (True, False),
        ofproto_v1_2.OFPT_BARRIER_REQUEST: (False, True),
        ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REQUEST: (False, True),
        ofproto_v1_2.OFPT_QUEUE_GET_CONFIG_REPLY: (True, False),
        ofproto_v1_2.OFPT_ROLE_REQUEST: (False, True),
        ofproto_v1_2.OFPT_ROLE_REPLY: (True, False),
    },
    4: {
        ofproto_v1_3.OFPT_HELLO: (True, False),
        ofproto_v1_3.OFPT_FEATURES_REQUEST: (False, True),
        ofproto_v1_3.OFPT_FEATURES_REPLY: (True, False),
        ofproto_v1_3.OFPT_GET_CONFIG_REQUEST: (False, True),
        ofproto_v1_3.OFPT_GET_CONFIG_REPLY: (True, False),
        ofproto_v1_3.OFPT_SET_CONFIG: (False, True),
        ofproto_v1_3.OFPT_PACKET_IN: (True, False),
        ofproto_v1_3.OFPT_FLOW_REMOVED: (True, False),
        ofproto_v1_3.OFPT_PORT_STATUS: (True, False),
        ofproto_v1_3.OFPT_PACKET_OUT: (False, True),
        ofproto_v1_3.OFPT_FLOW_MOD: (True, True),
        ofproto_v1_3.OFPT_GROUP_MOD: (False, True),
        ofproto_v1_3.OFPT_PORT_MOD: (False, True),
        ofproto_v1_3.OFPT_METER_MOD: (False, True),
        ofproto_v1_3.OFPT_TABLE_MOD: (False, True),
        ofproto_v1_3.OFPT_MULTIPART_REQUEST: (False, True),
        ofproto_v1_3.OFPT_MULTIPART_REPLY: (True, False),
        ofproto_v1_3.OFPT_BARRIER_REQUEST: (False, True),
        ofproto_v1_3.OFPT_QUEUE_GET_CONFIG_REQUEST: (False, True),
        ofproto_v1_3.OFPT_QUEUE_GET_CONFIG_REPLY: (True, False),
        ofproto_v1_3.OFPT_ROLE_REQUEST: (False, True),
        ofproto_v1_3.OFPT_ROLE_REPLY: (True, False),
        ofproto_v1_3.OFPT_GET_ASYNC_REQUEST: (False, True),
        ofproto_v1_3.OFPT_GET_ASYNC_REPLY: (True, False),
        ofproto_v1_3.OFPT_SET_ASYNC: (False, True),
    },
    5: {
        ofproto_v1_4.OFPT_HELLO: (True, False),
        ofproto_v1_4.OFPT_FEATURES_REQUEST: (False, True),
        ofproto_v1_4.OFPT_FEATURES_REPLY: (True, False),
        ofproto_v1_4.OFPT_GET_CONFIG_REQUEST: (False, True),
        ofproto_v1_4.OFPT_GET_CONFIG_REPLY: (True, False),
        ofproto_v1_4.OFPT_SET_CONFIG: (False, True),
        ofproto_v1_4.OFPT_PACKET_IN: (True, False),
        ofproto_v1_4.OFPT_FLOW_REMOVED: (True, False),
        ofproto_v1_4.OFPT_PORT_STATUS: (True, False),
        ofproto_v1_4.OFPT_PACKET_OUT: (False, True),
        ofproto_v1_4.OFPT_FLOW_MOD: (True, True),
        ofproto_v1_4.OFPT_GROUP_MOD: (True, True),
        ofproto_v1_4.OFPT_PORT_MOD: (False, True),
        ofproto_v1_4.OFPT_METER_MOD: (True, True),
        ofproto_v1_4.OFPT_TABLE_MOD: (False, True),
        ofproto_v1_4.OFPT_MULTIPART_REQUEST: (False, True),
        ofproto_v1_4.OFPT_MULTIPART_REPLY: (True, False),
        ofproto_v1_4.OFPT_BARRIER_REQUEST: (False, True),
        ofproto_v1_4.OFPT_ROLE_REQUEST: (False, True),
        ofproto_v1_4.OFPT_ROLE_REPLY: (True, False),
        ofproto_v1_4.OFPT_GET_ASYNC_REQUEST: (False, True),
        ofproto_v1_4.OFPT_GET_ASYNC_REPLY: (True, False),
        ofproto_v1_4.OFPT_SET_ASYNC: (False, True),
        ofproto_v1_4.OFPT_ROLE_STATUS: (True, False),
        ofproto_v1_4.OFPT_TABLE_STATUS: (True, False),
        ofproto_v1_4.OFPT_REQUESTFORWARD: (True, True),
        ofproto_v1_4.OFPT_BUNDLE_CONTROL: (True, True),
        ofproto_v1_4.OFPT_BUNDLE_ADD_MESSAGE: (False, True),
    },
    6: {
        ofproto_v1_5.OFPT_HELLO: (True, False),
        ofproto_v1_5.OFPT_FEATURES_REQUEST: (False, True),
        ofproto_v1_5.OFPT_FEATURES_REPLY: (True, False),
        ofproto_v1_5.OFPT_GET_CONFIG_REQUEST: (False, True),
        ofproto_v1_5.OFPT_GET_CONFIG_REPLY: (True, False),
        ofproto_v1_5.OFPT_SET_CONFIG: (False, True),
        ofproto_v1_5.OFPT_PACKET_IN: (True, False),
        ofproto_v1_5.OFPT_FLOW_REMOVED: (True, False),
        ofproto_v1_5.OFPT_PORT_STATUS: (True, False),
        ofproto_v1_5.OFPT_PACKET_OUT: (False, True),
        ofproto_v1_5.OFPT_FLOW_MOD: (True, True),
        ofproto_v1_5.OFPT_GROUP_MOD: (True, True),
        ofproto_v1_5.OFPT_PORT_MOD: (False, True),
        ofproto_v1_5.OFPT_METER_MOD: (True, True),
        ofproto_v1_5.OFPT_TABLE_MOD: (False, True),
        ofproto_v1_5.OFPT_MULTIPART_REQUEST: (False, True),
        ofproto_v1_5.OFPT_MULTIPART_REPLY: (True, False),
        ofproto_v1_5.OFPT_BARRIER_REQUEST: (False, True),
        ofproto_v1_5.OFPT_ROLE_REQUEST: (False, True),
        ofproto_v1_5.OFPT_ROLE_REPLY: (True, False),
        ofproto_v1_5.OFPT_GET_ASYNC_REQUEST: (False, True),
        ofproto_v1_5.OFPT_GET_ASYNC_REPLY: (True, False),
        ofproto_v1_5.OFPT_SET_ASYNC: (False, True),
        ofproto_v1_5.OFPT_ROLE_STATUS: (True, False),
        ofproto_v1_5.OFPT_TABLE_STATUS: (True, False),
        ofproto_v1_5.OFPT_REQUESTFORWARD: (True, True),
        ofproto_v1_5.OFPT_BUNDLE_CONTROL: (True, True),
        ofproto_v1_5.OFPT_BUNDLE_ADD_MESSAGE: (False, True),
        ofproto_v1_5.OFPT_CONTROLLER_STATUS: (True, False),
    },
}


class Test_Parser(unittest.TestCase):
    """ Test case for ryu.ofproto, especially json representation
    """

    def __init__(self, methodName):
        print('init %s' % methodName)
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
        def bytes_eq(buf1, buf2):
            if buf1 != buf2:
                msg = 'EOF in either data'
                for i in range(0, min(len(buf1), len(buf2))):
                    c1 = six.indexbytes(six.binary_type(buf1), i)
                    c2 = six.indexbytes(six.binary_type(buf2), i)
                    if c1 != c2:
                        msg = 'differs at chr %d, %d != %d' % (i, c1, c2)
                        break
                assert buf1 == buf2, "%r != %r, %s" % (buf1, buf2, msg)

        json_dict = json.loads(json_str)
        # on-wire -> OFPxxx -> json
        (version, msg_type, msg_len, xid) = ofproto_parser.header(wire_msg)
        try:
            has_parser, has_serializer = implemented[version][msg_type]
        except KeyError:
            has_parser = True
            has_serializer = True

        dp = ofproto_protocol.ProtocolDesc(version=version)
        if has_parser:
            try:
                msg = ofproto_parser.msg(dp, version, msg_type, msg_len, xid,
                                         wire_msg)
                json_dict2 = self._msg_to_jsondict(msg)
            except exception.OFPTruncatedMessage as e:
                json_dict2 = {'OFPTruncatedMessage':
                              self._msg_to_jsondict(e.ofpmsg)}
            # XXXdebug code
            open(('/tmp/%s.json' % name), 'w').write(json.dumps(json_dict2))
            eq_(json_dict, json_dict2)
            if 'OFPTruncatedMessage' in json_dict2:
                return

        # json -> OFPxxx -> json
        xid = json_dict[list(json_dict.keys())[0]].pop('xid', None)
        msg2 = self._jsondict_to_msg(dp, json_dict)
        msg2.set_xid(xid)
        if has_serializer:
            msg2.serialize()
            eq_(self._msg_to_jsondict(msg2), json_dict)
            bytes_eq(wire_msg, msg2.buf)

            # check if "len" "length" fields can be omitted

            def _remove(d, names):
                f = lambda x: _remove(x, names)
                if isinstance(d, list):
                    return list(map(f, d))
                if isinstance(d, dict):
                    d2 = {}
                    for k, v in d.items():
                        if k in names:
                            continue
                        d2[k] = f(v)
                    return d2
                return d

            json_dict3 = _remove(json_dict, ['len', 'length'])
            msg3 = self._jsondict_to_msg(dp, json_dict3)
            msg3.set_xid(xid)
            msg3.serialize()
            bytes_eq(wire_msg, msg3.buf)

            msg2.serialize()
            bytes_eq(wire_msg, msg2.buf)


def _add_tests():
    import os
    import os.path
    import functools

    this_dir = os.path.dirname(sys.modules[__name__].__file__)
    packet_data_dir = os.path.join(this_dir, '../../packet_data')
    json_dir = os.path.join(this_dir, 'json')
    ofvers = [
        'of10',
        'of12',
        'of13',
        'of14',
        'of15',
    ]
    cases = set()
    for ver in ofvers:
        pdir = packet_data_dir + '/' + ver
        jdir = json_dir + '/' + ver
        n_added = 0
        for file in os.listdir(pdir):
            if file.endswith('.packet'):
                truncated = None
            elif '.truncated' in file:
                # contents of .truncated files aren't relevant
                s1, s2 = file.split('.truncated')
                try:
                    truncated = int(s2)
                except ValueError:
                    continue
                file = s1 + '.packet'
            else:
                continue
            wire_msg = open(pdir + '/' + file, 'rb').read()
            if not truncated:
                json_str = open(jdir + '/' + file + '.json', 'r').read()
            else:
                json_str = open(jdir + '/' + file +
                                '.truncated%d.json' % truncated, 'r').read()
                wire_msg = wire_msg[:truncated]
            method_name = ('test_' + file).replace('-', '_').replace('.', '_')
            if truncated:
                method_name += '_truncated%d' % truncated

            def _run(self, name, wire_msg, json_str):
                print('processing %s ...' % name)
                if six.PY3:
                    self._test_msg(self, name, wire_msg, json_str)
                else:
                    self._test_msg(name, wire_msg, json_str)
            print('adding %s ...' % method_name)
            f = functools.partial(_run, name=method_name, wire_msg=wire_msg,
                                  json_str=json_str)
            test_lib.add_method(Test_Parser, method_name, f)
            cases.add(method_name)
            n_added += 1
        assert n_added > 0
    assert (cases ==
            set(unittest.defaultTestLoader.getTestCaseNames(Test_Parser)))


_add_tests()
