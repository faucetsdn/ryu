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

import unittest
from nose.tools import eq_

from ryu.utils import import_module


class Test_import_module(unittest.TestCase):
    """
    Test case for ryu.utils.import_module
    """

    @staticmethod
    def _my_import(name):
        mod = __import__(name)
        components = name.split('.')
        for c in components[1:]:
            mod = getattr(mod, c)
        return mod

    def test_import_module_with_same_basename(self):
        aaa = import_module('ryu.tests.unit.lib.test_mod.aaa.mod')
        eq_("this is aaa", aaa.name)
        bbb = import_module('ryu.tests.unit.lib.test_mod.bbb.mod')
        eq_("this is bbb", bbb.name)

    def test_import_module_by_filename(self):
        ccc = import_module('./lib/test_mod/ccc/mod.py')
        eq_("this is ccc", ccc.name)
        ddd = import_module('./lib/test_mod/ddd/mod.py')
        # Note: When importing a module by filename, if module file name
        # is duplicated, import_module reload (override) a module instance.
        eq_("this is ddd", ddd.name)

    def test_import_same_module1(self):
        from ryu.tests.unit.lib.test_mod import eee as eee1
        eq_("this is eee", eee1.name)
        eee2 = import_module('./lib/test_mod/eee.py')
        eq_("this is eee", eee2.name)

    def test_import_same_module2(self):
        fff1 = import_module('./lib/test_mod/fff.py')
        eq_("this is fff", fff1.name)
        fff2 = import_module('ryu.tests.unit.lib.test_mod.fff')
        eq_("this is fff", fff2.name)

    def test_import_same_module3(self):
        ggg1 = import_module('./lib/test_mod/ggg.py')
        eq_("this is ggg", ggg1.name)
        ggg2 = self._my_import('ryu.tests.unit.lib.test_mod.ggg')
        eq_("this is ggg", ggg2.name)
