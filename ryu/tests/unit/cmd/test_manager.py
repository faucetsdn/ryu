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
import mock
from nose.tools import eq_, raises

from ryu.cmd.manager import main


class Test_Manager(unittest.TestCase):
    """Test ryu-manager command
    """

    def __init__(self, methodName):
        super(Test_Manager, self).__init__(methodName)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @raises(SystemExit)
    @mock.patch('sys.argv', new=['ryu-manager', '--version'])
    def test_version(self):
        main()

    @raises(SystemExit)
    @mock.patch('sys.argv', new=['ryu-manager', '--help'])
    def test_help(self):
        main()

    @mock.patch('sys.argv', new=['ryu-manager', '--verbose',
                                 'ryu.tests.unit.cmd.dummy_app'])
    def test_no_services(self):
        main()
