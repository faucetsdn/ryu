# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
from nose.tools import ok_, eq_

from ryu.app.simple_switch import SimpleSwitch

import logging
LOG = logging.getLogger(__name__)


class TestSimpleSwitch(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testInit(self):
        ss = SimpleSwitch()
        ok_(True)
