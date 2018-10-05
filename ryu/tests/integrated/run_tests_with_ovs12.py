#!/usr/bin/env python
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import unittest
from nose.tools import ok_, eq_, timed, nottest

from subprocess import Popen, PIPE, STDOUT
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch

TIMEOUT = 60
RYU_HOST = '127.0.0.1'
RYU_PORT = 6633
PYTHON_BIN = '.venv/bin/python'
RYU_MGR = './bin/ryu-manager'


class OVS12KernelSwitch(OVSKernelSwitch):
    """Set protocols parameter for OVS version 1.10"""

    def start(self, controllers):
        super(OVS12KernelSwitch, self).start(controllers)
        self.cmd('ovs-vsctl set Bridge', self,
                 "protocols='[OpenFlow10, OpenFlow12]'")


class TestWithOVS12(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mn = Mininet()
        c = cls.mn.addController(controller=RemoteController,
                                 ip=RYU_HOST, port=RYU_PORT)
        c.start()

        s1 = cls.mn.addSwitch('s1', cls=OVS12KernelSwitch)
        s1.start(cls.mn.controllers)

        h1 = cls.mn.addHost('h1', ip='0.0.0.0/0')

        link = cls.mn.addLink(h1, s1)
        s1.attach(link.intf2)

    @classmethod
    def tearDownClass(cls):
        cls.mn.stop()

    @timed(TIMEOUT)
    def test_add_flow_v10(self):
        app = 'ryu/tests/integrated/test_add_flow_v10.py'
        self._run_ryu_manager_and_check_output(app)

    @timed(TIMEOUT)
    def test_request_reply_v12(self):
        app = 'ryu/tests/integrated/test_request_reply_v12.py'
        self._run_ryu_manager_and_check_output(app)

    @timed(TIMEOUT)
    def test_add_flow_v12_actions(self):
        app = 'ryu/tests/integrated/test_add_flow_v12_actions.py'
        self._run_ryu_manager_and_check_output(app)

    @timed(TIMEOUT)
    def test_add_flow_v12_matches(self):
        app = 'ryu/tests/integrated/test_add_flow_v12_matches.py'
        self._run_ryu_manager_and_check_output(app)

    @nottest
    def test_of_config(self):
        # OVS 1.10 does not support of_config
        pass

    def _run_ryu_manager_and_check_output(self, app):
        cmd = [PYTHON_BIN, RYU_MGR, app]
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT)

        while True:
            if p.poll() is not None:
                raise Exception('Another ryu-manager already running?')

            line = p.stdout.readline().strip()
            if line == '':
                time.sleep(1)
                continue

            print("ryu-manager: %s" % line)
            if line.find('TEST_FINISHED') != -1:
                ok_(line.find('Completed=[True]') != -1)
                p.terminate()
                p.communicate()  # wait for subprocess is terminated
                break


if __name__ == '__main__':
    unittest.main()
