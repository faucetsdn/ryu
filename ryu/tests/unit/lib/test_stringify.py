# Copyright (C) 2013-2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013-2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import base64
import six
import unittest
from nose.tools import eq_

from ryu.lib import stringify


class C1(stringify.StringifyMixin):
    def __init__(self, a, c):
        print("init %s %s" % (a, c))
        self.a = a
        self._b = 'B'
        self.c = c


class Test_stringify(unittest.TestCase):
    """ Test case for ryu.lib.stringify
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_jsondict(self):
        if six.PY3:
            def b64encode(s):
                return base64.b64encode(s).decode('ascii')
        else:
            b64encode = base64.b64encode
        j = {'C1': {'a': 'QUFB', 'c': 'Q0ND'}}
        eq_(j['C1']['a'], b64encode(b'AAA'))
        eq_(j['C1']['c'], b64encode(b'CCC'))
        c = C1(a=b'AAA', c=b'CCC')
        c2 = C1.from_jsondict(j['C1'])
        eq_(c.__class__, c2.__class__)
        eq_(c.__dict__, c2.__dict__)
        eq_(j, c.to_jsondict())

    def test_jsondict2(self):

        def my_encode(x):
            return x.lower()

        def my_decode(x):
            return x.upper()

        j = {'C1': {'a': 'aaa', 'c': 'ccc'}}
        eq_(j['C1']['a'], my_encode('AAA'))
        eq_(j['C1']['c'], my_encode('CCC'))
        c = C1(a='AAA', c='CCC')
        c2 = C1.from_jsondict(j['C1'], decode_string=my_decode)
        eq_(c.__class__, c2.__class__)
        eq_(c.__dict__, c2.__dict__)
        eq_(j, c.to_jsondict(encode_string=my_encode))
