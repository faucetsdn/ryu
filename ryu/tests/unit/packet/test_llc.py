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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging

from nose.tools import eq_
from ryu.lib.packet import llc


LOG = logging.getLogger(__name__)


class Test_ControlFormatI(unittest.TestCase):
    msg = llc.llc(llc.SAP_BPDU, llc.SAP_BPDU, llc.ControlFormatI())

    def test_json(self):
        jsondict = self.msg.to_jsondict()
        msg = llc.llc.from_jsondict(jsondict['llc'])
        eq_(str(self.msg), str(msg))


class Test_ControlFormatS(Test_ControlFormatI):
    msg = llc.llc(llc.SAP_BPDU, llc.SAP_BPDU, llc.ControlFormatS())


class Test_ControlFormatU(Test_ControlFormatI):
    msg = llc.llc(llc.SAP_BPDU, llc.SAP_BPDU, llc.ControlFormatU())
