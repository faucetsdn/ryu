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
from nose.tools import eq_

from ryu import utils

LOG = logging.getLogger(__name__)


class Test_utils(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_hex_array_string(self):
        ''' Test string conversion into array of hexes '''
        expected_result = '0x1 0x2 0x3 0x4'
        data = '\01\02\03\04'
        eq_(expected_result, utils.hex_array(data))

    def test_hex_array_bytearray(self):
        ''' Test bytearray conversion into array of hexes '''
        expected_result = '0x1 0x2 0x3 0x4'
        data = bytearray('\01\02\03\04')
        eq_(expected_result, utils.hex_array(data))

    def test_hex_array_invalid(self):
        ''' Test conversion into array of hexes with invalid data type '''
        expected_result = None
        data = 1234
        eq_(expected_result, utils.hex_array(data))
