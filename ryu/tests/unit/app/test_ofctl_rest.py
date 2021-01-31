# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

import functools
import json
import logging
import os
import sys
import unittest
try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3
from nose.tools import eq_

from ryu.app import ofctl_rest
from ryu.app.wsgi import Request
from ryu.app.wsgi import WSGIApplication
from ryu.controller.dpset import DPSet
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.tests import test_lib


LOG = logging.getLogger(__name__)


class DummyDatapath(ofproto_protocol.ProtocolDesc):

    def __init__(self, version):
        super(DummyDatapath, self).__init__(version)
        self.id = 1
        _kw = {'port_no': 1, 'hw_addr': 'aa:bb:cc:dd:ee:ff',
               'name': 's1-eth1', 'config': 1, 'state': 1}
        # for OpenFlow 1.0
        if version in [ofproto_v1_0.OFP_VERSION]:
            _kw.update(
                {'curr': 2112, 'advertised': 0, 'supported': 0, 'peer': 0})
            port_info = self.ofproto_parser.OFPPhyPort(**_kw)
        # for OpenFlow 1.2 or 1.3
        elif version in [ofproto_v1_2.OFP_VERSION, ofproto_v1_3.OFP_VERSION]:
            _kw.update(
                {'curr': 2112, 'advertised': 0, 'supported': 0, 'peer': 0,
                 'curr_speed': 10000000, 'max_speed': 0})
            port_info = self.ofproto_parser.OFPPort(**_kw)
        # for OpenFlow 1.4+
        else:
            _kw.update({'properties': []})
            port_info = self.ofproto_parser.OFPPort(**_kw)
        self.ports = {1: port_info}


class Test_ofctl_rest(unittest.TestCase):

    def _test(self, name, dp, method, path, body):
        # print('processing %s ...' % name)

        dpset = DPSet()
        dpset._register(dp)
        wsgi = WSGIApplication()
        contexts = {
            'dpset': dpset,
            'wsgi': wsgi,
        }
        ofctl_rest.RestStatsApi(**contexts)

        req = Request.blank(path)
        req.body = json.dumps(body).encode('utf-8')
        req.method = method

        with mock.patch('ryu.lib.ofctl_utils.send_stats_request'),\
                mock.patch('ryu.lib.ofctl_utils.send_msg'):
            res = req.get_response(wsgi)
        eq_(res.status, '200 OK')


def _add_tests():
    _ofp_vers = {
        'of10': ofproto_v1_0.OFP_VERSION,
        'of12': ofproto_v1_2.OFP_VERSION,
        'of13': ofproto_v1_3.OFP_VERSION,
        'of14': ofproto_v1_4.OFP_VERSION,
        'of15': ofproto_v1_5.OFP_VERSION,
    }

    this_dir = os.path.dirname(sys.modules[__name__].__file__)
    ofctl_rest_json_dir = os.path.join(this_dir, 'ofctl_rest_json/')

    for ofp_ver in _ofp_vers:
        # read a json file
        json_path = os.path.join(ofctl_rest_json_dir, ofp_ver + '.json')
        if os.path.exists(json_path):
            _test_cases = json.load(open(json_path))
        else:
            # print("Skip to load test cases for %s" % ofp_ver)
            continue

        # add test
        for test in _test_cases:
            method = test['method']
            path = test['path']
            body = test.get('body', {})

            name = 'test_ofctl_rest_' + method + '_' + ofp_ver + '_' + path
            # print('adding %s ...' % name)
            f = functools.partial(
                Test_ofctl_rest._test,
                name=name,
                dp=DummyDatapath(_ofp_vers[ofp_ver]),
                method=test['method'],
                path=test['path'],
                body=body
            )
            test_lib.add_method(Test_ofctl_rest, name, f)


_add_tests()

if __name__ == "__main__":
    unittest.main()
