# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2016 Fumihiko Kakuma <kakuma at valinux co jp>
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

from __future__ import absolute_import

import logging
import os
import sys
import unittest

from ryu import log


def load_tests(loader, tests, pattern):
    dirname = os.path.dirname(os.path.abspath(__file__))
    base_path = os.path.abspath(dirname + '/../../..')
    suite = unittest.TestSuite()
    for test_dir in ['ryu/tests/integrated/bgp']:
        if not pattern:
            suite.addTests(loader.discover(test_dir,
                                           top_level_dir=base_path))
        else:
            suite.addTests(loader.discover(test_dir, pattern=pattern,
                                           top_level_dir=base_path))
    return suite


if __name__ == '__main__':
    log.early_init_log(logging.DEBUG)
    log.init_log()
    LOG = logging.getLogger(__name__)
    pattern = None
    if len(sys.argv) == 2:
        pattern = sys.argv[1]
    loader = unittest.defaultTestLoader
    suite = load_tests(loader, None, pattern)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    ret = 0
    if res.errors or res.failures:
        ret = 1
    sys.exit(ret)
