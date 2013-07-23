import unittest
import logging
import struct
import netaddr
from struct import *
from nose.tools import *
from nose.plugins.skip import Skip, SkipTest

from ryu.lib import ip

LOG = logging.getLogger('test_ip')


class Test_ip(unittest.TestCase):
    '''
        test case for ip address module
    '''

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_ipv4_to_bin(self):
        ipv4_str = '10.28.197.1'
        val = 0x0a1cc501

        (res,) = struct.unpack('!I', ip.ipv4_to_bin(ipv4_str))
        eq_(val, res)

    def test_ipv4_to_str(self):
        ipv4_bin = struct.pack('!I', 0x0a1cc501)
        val = '10.28.197.1'

        res = ip.ipv4_to_str(ipv4_bin)
        eq_(val, res)

    def test_ipv6_to_bin(self):
        ipv6_str = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'
        val = struct.pack('!8H', 0x2013, 0xda8, 0x215, 0x8f2, 0xaa20, 0x66ff,
                          0xfe4c, 0x9c3c)
        res = ip.ipv6_to_bin(ipv6_str)
        eq_(val, res)

    def test_ipv6_to_bin_with_shortcut(self):
        ipv6_str = '3f:10::1:2'
        val = struct.pack('!8H', 0x3f, 0x10, 0, 0, 0, 0, 0x1, 0x2)

        res = ip.ipv6_to_bin(ipv6_str)
        eq_(val, res)

    def test_ipv6_to_str(self):
        ipv6_bin = struct.pack('!8H', 0x2013, 0xda8, 0x215, 0x8f2, 0xaa20,
                               0x66ff, 0xfe4c, 0x9c3c)
        val = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'

        res = ip.ipv6_to_str(ipv6_bin)
        print val, res
        eq_(val, res)
