# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import unittest

from ryu.lib import ofctl_utils
from ryu.ofproto import ofproto_v1_3


LOG = logging.getLogger(__name__)


class Test_ofctl_utils(unittest.TestCase):
    # prepare test target
    util = ofctl_utils.OFCtlUtil(ofproto_v1_3)

    def _test_str_to_int(self, input_value, expected_value):
        output_value = ofctl_utils.str_to_int(input_value)
        self.assertEqual(expected_value, output_value)

    def test_str_to_int(self):
        self._test_str_to_int(1, 1)        # int
        self._test_str_to_int('0b10', 2)   # binary digit
        self._test_str_to_int('0o10', 8)   # octal digit
        self._test_str_to_int('0x10', 16)  # hexadecimal digit

    def test_ofp_port_from_user(self):
        self.assertEqual(
            ofproto_v1_3.OFPP_CONTROLLER,
            self.util.ofp_port_from_user(ofproto_v1_3.OFPP_CONTROLLER)  # int
        )
        self.assertEqual(
            ofproto_v1_3.OFPP_CONTROLLER,
            self.util.ofp_port_from_user('CONTROLLER')       # str without prefix
        )
        self.assertEqual(
            ofproto_v1_3.OFPP_CONTROLLER,
            self.util.ofp_port_from_user('OFPP_CONTROLLER')  # str with prefix
        )

    def test_ofp_port_to_user(self):
        self.assertEqual(
            'CONTROLLER',
            self.util.ofp_port_to_user(ofproto_v1_3.OFPP_CONTROLLER)
        )
        self.assertEqual(
            1,
            self.util.ofp_port_to_user(1)  # not matched
        )

    def test_ofp_table_from_user(self):
        self.assertEqual(
            ofproto_v1_3.OFPTT_ALL,
            self.util.ofp_table_from_user('ALL')
        )

    def test_ofp_table_to_user(self):
        self.assertEqual(
            'ALL',
            self.util.ofp_table_to_user(ofproto_v1_3.OFPTT_ALL)
        )

    def test_ofp_cml_from_user(self):
        self.assertEqual(
            ofproto_v1_3.OFPCML_NO_BUFFER,
            self.util.ofp_cml_from_user('NO_BUFFER')
        )

    def test_ofp_cml_to_user(self):
        self.assertEqual(
            'NO_BUFFER',
            self.util.ofp_cml_to_user(ofproto_v1_3.OFPCML_NO_BUFFER)
        )

    def test_ofp_group_from_user(self):
        self.assertEqual(
            ofproto_v1_3.OFPG_ANY,
            self.util.ofp_group_from_user('ANY')
        )

    def test_ofp_group_to_user(self):
        self.assertEqual(
            'ANY',
            self.util.ofp_group_to_user(ofproto_v1_3.OFPG_ANY)
        )

    def test_ofp_buffer_from_user(self):
        self.assertEqual(
            ofproto_v1_3.OFP_NO_BUFFER,
            self.util.ofp_buffer_from_user('NO_BUFFER')
        )
        self.assertEqual(
            1,
            self.util.ofp_buffer_from_user(1)  # not matched
        )

    def test_ofp_buffer_to_user(self):
        self.assertEqual(
            'NO_BUFFER',
            self.util.ofp_buffer_to_user(ofproto_v1_3.OFP_NO_BUFFER)
        )
        self.assertEqual(
            1,
            self.util.ofp_buffer_to_user(1)  # not matched
        )

    def test_ofp_meter_from_user(self):
        self.assertEqual(
            ofproto_v1_3.OFPM_ALL,
            self.util.ofp_meter_from_user('ALL')
        )

    def test_ofp_meter_to_user(self):
        self.assertEqual(
            'ALL',
            self.util.ofp_meter_to_user(ofproto_v1_3.OFPM_ALL)
        )

    def test_ofp_queue_from_user(self):
        self.assertEqual(
            ofproto_v1_3.OFPQ_ALL,
            self.util.ofp_queue_from_user('ALL')
        )

    def test_ofp_queue_to_user(self):
        self.assertEqual(
            'ALL',
            self.util.ofp_queue_to_user(ofproto_v1_3.OFPQ_ALL)
        )
