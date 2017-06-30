# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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
import six
import struct

from nose.tools import ok_, eq_

from ryu.lib import pack_utils


class TestMsgPackInto(unittest.TestCase):
    """ Test case for msg_pack_into
    """

    def _test_msg_pack_into(self, offset_type='e'):
        fmt = '!HH'
        len_ = struct.calcsize(fmt)
        buf = bytearray(len_)
        offset = len_
        arg1 = 1
        arg2 = 2

        if offset_type == 'l':
            offset += 1
        elif offset_type == 'g':
            offset -= 1

        pack_utils.msg_pack_into(fmt, buf, offset, arg1, arg2)

        check_offset = len(buf) - len_
        res = struct.unpack_from(fmt, six.binary_type(buf), check_offset)

        eq_(arg1, res[0])
        eq_(arg2, res[1])

        return True

    def test_msg_pack_into(self):
        ok_(self._test_msg_pack_into())

    def test_msg_pack_into_less(self):
        ok_(self._test_msg_pack_into('l'))

    def test_msg_pack_into_greater(self):
        ok_(self._test_msg_pack_into('g'))
