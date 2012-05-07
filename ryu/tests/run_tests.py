#!/usr/bin/env python


import os
import sys

from nose import config
from nose import core

sys.path.append(os.getcwd())
sys.path.append(os.path.dirname(__file__))


import ryu.tests.unit
from ryu.tests.test_lib import run_tests


if __name__ == '__main__':
    exit_status = False

    # if a single test case was specified,
    # we should only invoked the tests once
    invoke_once = len(sys.argv) > 1

    cwd = os.getcwd()
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      includeExe=True,
                      traverseNamespace=True,
                      plugins=core.DefaultPluginManager())
    c.configureWhere(ryu.tests.unit.__path__)

    exit_status = run_tests(c)
    sys.exit(exit_status)
