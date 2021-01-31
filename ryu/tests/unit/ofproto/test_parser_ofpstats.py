# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

try:
    # Python 3
    from functools import reduce
except ImportError:
    # Python 2
    pass

import six
import sys
import unittest
from nose.tools import eq_
from nose.tools import ok_

from ryu.ofproto import ofproto_v1_5
from ryu.ofproto import ofproto_v1_5_parser
from ryu.tests import test_lib


class Test_Parser_OFPStats(unittest.TestCase):
    _ofp = {ofproto_v1_5_parser: ofproto_v1_5}

    def __init__(self, methodName):
        print('init %s' % methodName)
        super(Test_Parser_OFPStats, self).__init__(methodName)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _test(self, name, ofpp, d):
        stats = ofpp.OFPStats(**d)
        b = bytearray()
        stats.serialize(b, 0)
        stats2 = stats.parser(six.binary_type(b), 0)
        for k, v in d.items():
            ok_(k in stats)
            ok_(k in stats2)
            eq_(stats[k], v)
            eq_(stats2[k], v)
        for k, v in stats.iteritems():
            ok_(k in d)
            eq_(d[k], v)
        for k, v in stats2.iteritems():
            ok_(k in d)
            eq_(d[k], v)


def _add_tests():
    import functools
    import itertools

    class Field(object):
        pass

    class Int1(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0xff

    class Int2(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x1234
            yield 0xffff

    class Int3(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x123456
            yield 0xffffff

    class Int4(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x12345678
            yield 0xffffffff

    class Int4double(Field):
        @staticmethod
        def generate():
            # Note: If yield value as a tuple, flatten_one() will reduce it
            # into a single value. So the followings avoid this problem by
            # using a list value.
            yield [0, 1]
            yield [0x12345678, 0x23456789]
            yield [0xffffffff, 0xfffffffe]

    class Int8(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x123456789abcdef0
            yield 0xffffffffffffffff

    class Mac(Field):
        @staticmethod
        def generate():
            yield '00:00:00:00:00:00'
            yield 'f2:0b:a4:7d:f8:ea'
            yield 'ff:ff:ff:ff:ff:ff'

    class IPv4(Field):
        @staticmethod
        def generate():
            yield '0.0.0.0'
            yield '192.0.2.1'
            yield '255.255.255.255'

    class IPv6(Field):
        @staticmethod
        def generate():
            yield '::'
            yield 'fe80::f00b:a4ff:fed0:3f70'
            yield 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'

    class B64(Field):
        @staticmethod
        def generate():
            yield 'aG9nZWhvZ2U='
            yield 'ZnVnYWZ1Z2E='

    ofpps = [ofproto_v1_5_parser]
    common = [
        ('duration', Int4double),
        ('idle_time', Int4double),
        ('flow_count', Int4),
        ('packet_count', Int8),
        ('byte_count', Int8),
        ('field_100', B64),
    ]
    L = {}
    L[ofproto_v1_5_parser] = common

    def flatten_one(l, i):
        if isinstance(i, tuple):
            return l + flatten(i)
        else:
            return l + [i]
    flatten = lambda l: reduce(flatten_one, l, [])

    for ofpp in ofpps:
        for n in range(1, 3):
            for C in itertools.combinations(L[ofpp], n):
                l = [1]
                keys = []
                clss = []
                for (k, cls) in C:
                    l = itertools.product(l, cls.generate())
                    keys.append(k)
                    clss.append(cls)
                l = [flatten(x)[1:] for x in l]
                for values in l:
                    d = dict(zip(keys, values))
                    for n, uv in d.items():
                        if isinstance(uv, list):
                            # XXX
                            # OFPStats returns value as tuple when field is
                            # 'duration' or 'idle_time'. Then convert list
                            # value into tuple here.
                            d[n] = tuple(uv)
                    mod = ofpp.__name__.split('.')[-1]
                    method_name = 'test_' + mod
                    for k in sorted(dict(d).keys()):
                        method_name += '_' + str(k)
                        method_name += '_' + str(d[k])
                    method_name = method_name.replace(':', '_')
                    method_name = method_name.replace('.', '_')
                    method_name = method_name.replace('(', '_')
                    method_name = method_name.replace(')', '_')
                    method_name = method_name.replace(',', '_')
                    method_name = method_name.replace("'", '_')
                    method_name = method_name.replace(' ', '_')

                    def _run(self, name, ofpp, d):
                        print('processing %s ...' % name)
                        if six.PY3:
                            self._test(self, name, ofpp, d)
                        else:
                            self._test(name, ofpp, d)
                    print('adding %s ...' % method_name)
                    f = functools.partial(_run, name=method_name,
                                          ofpp=ofpp, d=d)
                    test_lib.add_method(Test_Parser_OFPStats,
                                        method_name, f)


_add_tests()
