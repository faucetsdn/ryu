# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
from nose.tools import ok_, eq_
# from ryu.app.simple_switch import SimpleSwitch

import logging


LOG = logging.getLogger('ryu.tests.test_sample1')


class TestSample1(unittest.TestCase):

    def testS1Func1(self):
        LOG.debug('testS1Func1 - START')
        ok_(True)

    def testS1Func2(self):
        ok_(True)
