# Copyright (C) 2015 Stratosphere Inc.
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

try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3

import warnings
import unittest
import logging

import nose
from nose.tools import assert_equal
from nose.tools import assert_true

from ryu.base import app_manager  # To suppress cyclic import
from ryu.controller import controller
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_0_parser


LOG = logging.getLogger('test_controller')


class Test_Datapath(unittest.TestCase):

    """ Test case for Datapath
    """

    def _test_ports_accessibility(self, ofproto_parser, msgs_len):
        with mock.patch('ryu.controller.controller.Datapath.set_state'):

            # Ignore warnings
            with warnings.catch_warnings(record=True) as msgs:
                warnings.simplefilter('always')

                # Test target
                sock_mock = mock.Mock()
                addr_mock = mock.Mock()
                dp = controller.Datapath(sock_mock, addr_mock)
                dp.ofproto_parser = ofproto_parser

                # Create
                dp.ports = {}

                # Update
                port_mock = mock.Mock()
                dp.ports[0] = port_mock

                # Read & Delete
                del dp.ports[0]

                assert_equal(len(msgs), msgs_len)
                for msg in msgs:
                    assert_true(issubclass(msg.category, UserWarning))

    def test_ports_accessibility_v13(self):
        self._test_ports_accessibility(ofproto_v1_3_parser, 2)

    def test_ports_accessibility_v12(self):
        self._test_ports_accessibility(ofproto_v1_2_parser, 0)

    def test_ports_accessibility_v10(self):
        self._test_ports_accessibility(ofproto_v1_0_parser, 0)


if __name__ == '__main__':
    nose.main(argv=['nosetests', '-s', '-v'], defaultTest=__file__)
