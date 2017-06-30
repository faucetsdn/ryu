# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

import unittest
import logging
import six
from nose.tools import eq_

from ryu import utils

LOG = logging.getLogger(__name__)


class Test_utils(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_hex_array_string(self):
        """
        Test hex_array() with str type.
        """
        expected_result = '0x01 0x02 0x03 0x04'
        data = b'\x01\x02\x03\x04'
        eq_(expected_result, utils.hex_array(data))

    def test_hex_array_bytearray(self):
        """
        Test hex_array() with bytearray type.
        """
        expected_result = '0x01 0x02 0x03 0x04'
        data = bytearray(b'\x01\x02\x03\x04')
        eq_(expected_result, utils.hex_array(data))

    def test_hex_array_bytes(self):
        """
        Test hex_array() with bytes type. (Python3 only)
        """
        if six.PY2:
            return
        expected_result = '0x01 0x02 0x03 0x04'
        data = bytes(b'\x01\x02\x03\x04')
        eq_(expected_result, utils.hex_array(data))

    def test_binary_str_string(self):
        """
        Test binary_str() with str type.
        """
        expected_result = '\\x01\\x02\\x03\\x04'
        data = b'\x01\x02\x03\x04'
        eq_(expected_result, utils.binary_str(data))

    def test_binary_str_bytearray(self):
        """
        Test binary_str() with bytearray type.
        """
        expected_result = '\\x01\\x02\\x03\\x04'
        data = bytearray(b'\x01\x02\x03\x04')
        eq_(expected_result, utils.binary_str(data))

    def test_binary_str_bytes(self):
        """
        Test binary_str() with bytes type. (Python3 only)
        """
        if six.PY2:
            return
        expected_result = '\\x01\\x02\\x03\\x04'
        data = bytes(b'\x01\x02\x03\x04')
        eq_(expected_result, utils.binary_str(data))
