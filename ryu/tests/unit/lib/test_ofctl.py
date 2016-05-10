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
from ryu.lib import ofctl_v1_4
from ryu.lib import ofctl_v1_5
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
            eq_(json.dumps(request.to_jsondict(), sort_keys=True),
                json.dumps(dp.request_msg.to_jsondict(), sort_keys=True))
        except AssertionError as e:
            # For debugging
            json.dump(dp.request_msg.to_jsondict(),
                      open('/tmp/' + name + '_request.json', 'w'),
                      indent=3, sort_keys=True)
            raise e

        # expected output <--> return of ofctl
        def _remove(d, names):
            def f(x):
                return _remove(x, names)

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

        expected = _remove(expected, ['len', 'length'])
        output = _remove(output, ['len', 'length'])
        try:
            eq_(json.dumps(expected, sort_keys=True),
                json.dumps(output, sort_keys=True))
        except AssertionError as e:
            # For debugging
            json.dump(output, open('/tmp/' + name + '_reply.json', 'w'),
                      indent=4)
            raise e


def _add_tests():
    _ofp_vers = {
        'of10': 0x01,
        'of12': 0x03,
        'of13': 0x04,
        'of14': 0x05,
        'of15': 0x06,
    }

    _test_cases = {
        'of10': [
            {
                'method': ofctl_v1_0.mod_flow_entry,
                'request': '1-2-ofp_flow_mod.packet.json',
                'reply': None
            },
        ],
        'of12': [
            {
                'method': ofctl_v1_2.get_desc_stats,
                'request': '3-24-ofp_desc_stats_request.packet.json',
                'reply': '3-0-ofp_desc_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_queue_stats,
                'request': '3-37-ofp_queue_stats_request.packet.json',
                'reply': '3-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_queue_stats,
                'request': 'lib-ofctl-ofp_queue_stats_request.packet1.json',
                'reply': '3-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_queue_stats,
                'request': 'lib-ofctl-ofp_queue_stats_request.packet2.json',
                'reply': '3-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_queue_stats,
                'request': 'lib-ofctl-ofp_queue_stats_request.packet3.json',
                'reply': '3-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_queue_config,
                'request': '3-35-ofp_queue_get_config_request.packet.json',
                'reply': '3-36-ofp_queue_get_config_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_queue_config,
                'request': 'lib-ofctl-ofp_queue_get_config_request.packet.json',
                'reply': '3-36-ofp_queue_get_config_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_flow_stats,
                'request': '3-11-ofp_flow_stats_request.packet.json',
                'reply': '3-12-ofp_flow_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_aggregate_flow_stats,
                'request': '3-25-ofp_aggregate_stats_request.packet.json',
                'reply': '3-26-ofp_aggregate_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_table_stats,
                'request': '3-27-ofp_table_stats_request.packet.json',
                'reply': '3-28-ofp_table_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_port_stats,
                'request': '3-29-ofp_port_stats_request.packet.json',
                'reply': '3-30-ofp_port_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_port_stats,
                'request': 'lib-ofctl-ofp_port_stats_request.packet.json',
                'reply': '3-30-ofp_port_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_group_stats,
                'request': '3-61-ofp_group_stats_request.packet.json',
                'reply': '3-62-ofp_group_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_group_stats,
                'request': 'lib-ofctl-ofp_group_stats_request.packet.json',
                'reply': '3-62-ofp_group_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_group_features,
                'request': '3-31-ofp_group_features_stats_request.packet.json',
                'reply': '3-32-ofp_group_features_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.get_group_desc,
                'request': '3-33-ofp_group_desc_stats_request.packet.json',
                'reply': '3-34-ofp_group_desc_stats_reply.packet.json'
            },
            # In OpenFlow 1.2, ofp_port_desc is not defined.
            # We use ofp_features_request to get ports description instead.
            {
                'method': ofctl_v1_2.get_port_desc,
                'request': '3-5-ofp_features_request.packet.json',
                'reply': '3-6-ofp_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_2.mod_flow_entry,
                'request': '3-2-ofp_flow_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_2.mod_group_entry,
                'request': '3-21-ofp_group_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_2.mod_port_behavior,
                'request': '3-22-ofp_port_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_2.send_experimenter,
                'request': '3-16-ofp_experimenter.packet.json',
                'reply': None
            },
        ],
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
                'method': ofctl_v1_3.get_queue_stats,
                'request': 'lib-ofctl-ofp_queue_stats_request.packet1.json',
                'reply': '4-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_queue_stats,
                'request': 'lib-ofctl-ofp_queue_stats_request.packet2.json',
                'reply': '4-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_queue_stats,
                'request': 'lib-ofctl-ofp_queue_stats_request.packet3.json',
                'reply': '4-38-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_queue_config,
                'request': '4-35-ofp_queue_get_config_request.packet.json',
                'reply': '4-36-ofp_queue_get_config_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_queue_config,
                'request': 'lib-ofctl-ofp_queue_get_config_request.packet.json',
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
                'method': ofctl_v1_3.get_port_stats,
                'request': 'lib-ofctl-ofp_port_stats_request.packet.json',
                'reply': '4-30-ofp_port_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_meter_stats,
                'request': '4-49-ofp_meter_stats_request.packet.json',
                'reply': '4-50-ofp_meter_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_meter_stats,
                'request': 'lib-ofctl-ofp_meter_stats_request.packet.json',
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
                'method': ofctl_v1_3.get_meter_config,
                'request': 'lib-ofctl-ofp_meter_config_request.packet.json',
                'reply': '4-48-ofp_meter_config_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_group_stats,
                'request': '4-57-ofp_group_stats_request.packet.json',
                'reply': '4-58-ofp_group_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_3.get_group_stats,
                'request': 'lib-ofctl-ofp_group_stats_request.packet.json',
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
        ],
        'of14': [
            {
                'method': ofctl_v1_4.get_desc_stats,
                'request': '5-24-ofp_desc_request.packet.json',
                'reply': '5-0-ofp_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_queue_stats,
                'request': '5-35-ofp_queue_stats_request.packet.json',
                'reply': '5-36-ofp_queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_queue_desc,
                'request': '5-63-ofp_queue_desc_request.packet.json',
                'reply': '5-64-ofp_queue_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_flow_stats,
                'request': '5-11-ofp_flow_stats_request.packet.json',
                'reply': '5-12-ofp_flow_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_aggregate_flow_stats,
                'request': '5-25-ofp_aggregate_stats_request.packet.json',
                'reply': '5-26-ofp_aggregate_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_table_stats,
                'request': '5-27-ofp_table_stats_request.packet.json',
                'reply': '5-28-ofp_table_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_table_features,
                'request': 'lib-ofctl-ofp_table_features_request.packet.json',
                'reply': '5-54-ofp_table_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_port_stats,
                'request': '5-29-ofp_port_stats_request.packet.json',
                'reply': '5-30-ofp_port_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_meter_stats,
                'request': '5-47-ofp_meter_stats_request.packet.json',
                'reply': '5-48-ofp_meter_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_meter_features,
                'request': '5-49-ofp_meter_features_request.packet.json',
                'reply': '5-50-ofp_meter_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_meter_config,
                'request': '5-45-ofp_meter_config_request.packet.json',
                'reply': '5-46-ofp_meter_config_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_group_stats,
                'request': '5-55-ofp_group_stats_request.packet.json',
                'reply': '5-56-ofp_group_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_group_features,
                'request': '5-31-ofp_group_features_request.packet.json',
                'reply': '5-32-ofp_group_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_group_desc,
                'request': '5-33-ofp_group_desc_request.packet.json',
                'reply': '5-34-ofp_group_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.get_port_desc,
                'request': '5-51-ofp_port_desc_request.packet.json',
                'reply': '5-52-ofp_port_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_4.mod_flow_entry,
                'request': '5-2-ofp_flow_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_4.mod_meter_entry,
                'request': '5-43-ofp_meter_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_4.mod_group_entry,
                'request': '5-21-ofp_group_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_4.mod_port_behavior,
                'request': '5-22-ofp_port_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_4.send_experimenter,
                'request': '5-16-ofp_experimenter.packet.json',
                'reply': None
            },
        ],
        'of15': [
            {
                'method': ofctl_v1_5.get_desc_stats,
                'request': 'libofproto-OFP15-desc_request.packet.json',
                'reply': 'libofproto-OFP15-desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_queue_stats,
                'request': 'lib-ofctl-ofp_queue_stats_request.packet.json',
                'reply': 'libofproto-OFP15-queue_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_queue_desc,
                'request': 'libofproto-OFP15-queue_desc_request.packet.json',
                'reply': 'libofproto-OFP15-queue_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_flow_stats,
                'request': 'libofproto-OFP15-flow_stats_request.packet.json',
                'reply': 'libofproto-OFP15-flow_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_flow_desc_stats,
                'request': 'libofproto-OFP15-flow_desc_request.packet.json',
                'reply': 'libofproto-OFP15-flow_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_flow_desc_stats,
                'request': 'lib-ofctl-OFP15-flow_desc_request.packet.json',
                'reply': 'lib-ofctl-OFP15-flow_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_aggregate_flow_stats,
                'request': 'libofproto-OFP15-aggregate_stats_request.packet.json',
                'reply': 'libofproto-OFP15-aggregate_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_table_stats,
                'request': 'libofproto-OFP15-table_stats_request.packet.json',
                'reply': 'libofproto-OFP15-table_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_table_features,
                'request': 'lib-ofctl-ofp_table_features_request.packet.json',
                'reply': 'libofproto-OFP15-table_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_port_stats,
                'request': 'libofproto-OFP15-port_stats_request.packet.json',
                'reply': 'libofproto-OFP15-port_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_meter_stats,
                'request': 'libofproto-OFP15-meter_stats_request.packet.json',
                'reply': 'libofproto-OFP15-meter_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_meter_features,
                'request': 'libofproto-OFP15-meter_features_request.packet.json',
                'reply': 'libofproto-OFP15-meter_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_meter_desc,
                'request': 'libofproto-OFP15-meter_desc_request.packet.json',
                'reply': 'libofproto-OFP15-meter_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_group_stats,
                'request': 'libofproto-OFP15-group_stats_request.packet.json',
                'reply': 'libofproto-OFP15-group_stats_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_group_features,
                'request': 'libofproto-OFP15-group_features_request.packet.json',
                'reply': 'libofproto-OFP15-group_features_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_group_desc,
                'request': 'libofproto-OFP15-group_desc_request.packet.json',
                'reply': 'libofproto-OFP15-group_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.get_port_desc,
                'request': 'libofproto-OFP15-port_desc_request.packet.json',
                'reply': 'libofproto-OFP15-port_desc_reply.packet.json'
            },
            {
                'method': ofctl_v1_5.mod_flow_entry,
                'request': 'libofproto-OFP15-flow_mod_no_nx.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_5.mod_flow_entry,
                'request': 'lib-ofctl-OFP15-flow_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_5.mod_meter_entry,
                'request': 'libofproto-OFP15-meter_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_5.mod_group_entry,
                'request': 'libofproto-OFP15-group_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_5.mod_port_behavior,
                'request': 'libofproto-OFP15-port_mod.packet.json',
                'reply': None
            },
            {
                'method': ofctl_v1_5.send_experimenter,
                'request': 'libofproto-OFP15-experimenter.packet.json',
                'reply': None
            }
        ],
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
            name = 'test_ofctl_' + ofp_ver + '_' + test['request']
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
