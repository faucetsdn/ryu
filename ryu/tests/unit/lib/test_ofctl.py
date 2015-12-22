# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

import functools
import json
import logging
from nose.tools import eq_
import os
import sys
import unittest

from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_parser
from ryu.ofproto.ofproto_protocol import ProtocolDesc
from ryu.tests import test_lib

LOG = logging.getLogger(__name__)


class DummyDatapath(ProtocolDesc):
    def __init__(self, version):
        super(DummyDatapath, self).__init__(version)
        self.id = 1  # XXX
        self.request_msg = None
        self.reply_msg = None
        self.waiters = None

    @staticmethod
    def set_xid(msg):
        msg.set_xid(0)
        return 0

    def send_msg(self, msg):
        msg.serialize()
        self.request_msg = msg

        if self.reply_msg:
            lock, msgs = self.waiters[self.id][msg.xid]
            msgs.append(self.reply_msg)
            del self.waiters[self.id][msg.xid]
            lock.set()

    def set_reply(self, msg, waiters):
        self.reply_msg = msg
        self.waiters = waiters


class Test_ofctl(unittest.TestCase):

    def _test(self, name, dp, method, args, request, reply, expected):
        print('processing %s ...' % name)
        waiters = {}
        dp.set_reply(reply, waiters)
        if reply:
            output = method(dp=dp, waiters=waiters, **args)
        else:
            output = method(dp=dp, **args)

        # expected message <--> sent message
        request.serialize()
        try:
            eq_(request.buf, dp.request_msg.buf)
        except AssertionError as e:
            # For debugging
            json.dump(dp.request_msg.to_jsondict(),
                      open('/tmp/' + name, 'w'), indent=3, sort_keys=True)
            raise e

        # expected output <--> return of ofctl
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

        try:
            eq_(_remove(expected, ['len', 'length']),
                _remove(output, ['len', 'length']))
        except AssertionError as e:
            # For debugging
            json.dump(output, open('/tmp/' + name, 'w'), indent=4)
            raise e


def _add_tests():
    _ofp_vers = {
        'of10': 0x01,
        'of12': 0x03,
        'of13': 0x04
    }

    _test_cases = {
        'of13': [
            {
                'method': ofctl_v1_3.get_desc_stats,
                'request': '4-24-ofp_desc_request.packet.json',
                'reply': '4-0-ofp_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_queue_stats,
                'request': '4-37-ofp_queue_stats_request.packet.json',
                'reply': '4-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_queue_config,
                'request': '4-35-ofp_queue_get_config_request.packet.json',
                'reply': '4-36-ofp_queue_get_config_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_flow_stats,
                'request': '4-11-ofp_flow_stats_request.packet.json',
                'reply': '4-12-ofp_flow_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_aggregate_flow_stats,
                'request': '4-25-ofp_aggregate_stats_request.packet.json',
                'reply': '4-26-ofp_aggregate_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_table_stats,
                'request': '4-27-ofp_table_stats_request.packet.json',
                'reply': '4-28-ofp_table_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_table_features,
                'request': 'lib-ofctl-ofp_table_features_request.packet.json',
                'reply': '4-56-ofp_table_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_port_stats,
                'request': '4-29-ofp_port_stats_request.packet.json',
                'reply': '4-30-ofp_port_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_meter_stats,
                'request': '4-49-ofp_meter_stats_request.packet.json',
                'reply': '4-50-ofp_meter_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_meter_features,
                'request': '4-51-ofp_meter_features_request.packet.json',
                'reply': '4-52-ofp_meter_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_meter_config,
                'request': '4-47-ofp_meter_config_request.packet.json',
                'reply': '4-48-ofp_meter_config_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_group_stats,
                'request': '4-57-ofp_group_stats_request.packet.json',
                'reply': '4-58-ofp_group_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_group_features,
                'request': '4-31-ofp_group_features_request.packet.json',
                'reply': '4-32-ofp_group_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_group_desc,
                'request': '4-33-ofp_group_desc_request.packet.json',
                'reply': '4-34-ofp_group_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_port_desc,
                'request': '4-53-ofp_port_desc_request.packet.json',
                'reply': '4-54-ofp_port_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.mod_flow_entry,
                'request': '4-2-ofp_flow_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_3.mod_meter_entry,
                'request': '4-45-ofp_meter_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_3.mod_group_entry,
                'request': '4-21-ofp_group_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_3.mod_port_behavior,
                'request': '4-22-ofp_port_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_3.send_experimenter,
                'request': '4-16-ofp_experimenter.packet.json',
                'reply': None
            },
        ]
    }

    def _jsonfile_to_msg(datapath, jsonfile):
        return ofproto_parser.ofp_msg_from_jsondict(
            datapath, json.load(open(jsonfile)))

    this_dir = os.path.dirname(sys.modules[__name__].__file__)
    parser_json_root = os.path.join(this_dir, '../ofproto/json/')
    ofctl_json_root = os.path.join(this_dir, 'ofctl_json/')

    for ofp_ver, tests in _test_cases.items():
        dp = DummyDatapath(_ofp_vers[ofp_ver])
        parser_json_dir = os.path.join(parser_json_root, ofp_ver)
        ofctl_json_dir = os.path.join(ofctl_json_root, ofp_ver)
        for test in tests:
            name = 'test_ofctl_' + test['request']
            print('adding %s ...' % name)
            args = {}
            args_json_path = os.path.join(ofctl_json_dir, test['request'])
            if os.path.exists(args_json_path):
                args = json.load(open(args_json_path))
            request = _jsonfile_to_msg(
                dp, os.path.join(parser_json_dir, test['request']))
            reply = None
            expected = None
            if test['reply']:
                reply = _jsonfile_to_msg(
                    dp, os.path.join(parser_json_dir, test['reply']))
                expected = json.load(
                    open(os.path.join(ofctl_json_dir, test['reply'])))
            f = functools.partial(
                Test_ofctl._test, name=name, dp=dp, method=test['method'],
                args=args, request=request, reply=reply, expected=expected)
            test_lib.add_method(Test_ofctl, name, f)


_add_tests()

if __name__ == "__main__":
    unittest.main()
