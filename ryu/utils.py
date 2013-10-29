# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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

# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import inspect
import logging
import os
import sys
import re

LOG = logging.getLogger('ryu.utils')


def chop_py_suffix(p):
    for suf in ['.py', '.pyc', '.pyo']:
        if p.endswith(suf):
            return p[:-len(suf)]
    return p


def _likely_same(a, b):
    try:
        if os.path.samefile(a, b):
            return True
    except OSError:
        # m.__file__ is not always accessible.  eg. egg
        return False
    if chop_py_suffix(a) == chop_py_suffix(b):
        return True
    return False


def _find_loaded_module(modpath):
    # copy() to avoid RuntimeError: dictionary changed size during iteration
    for k, m in sys.modules.copy().iteritems():
        if k == '__main__':
            continue
        if not hasattr(m, '__file__'):
            continue
        if _likely_same(m.__file__, modpath):
            return m
    return None


def import_module(modname):
    try:
        __import__(modname)
    except:
        abspath = os.path.abspath(modname)
        mod = _find_loaded_module(abspath)
        if mod:
            return mod
        opath = sys.path
        sys.path.append(os.path.dirname(abspath))
        name = os.path.basename(modname)
        if name.endswith('.py'):
            name = name[:-3]
        __import__(name)
        sys.path = opath
        return sys.modules[name]
    return sys.modules[modname]


def round_up(x, y):
    return ((x + y - 1) / y) * y


def hex_array(data):
    """Convert string into array of hexes to be printed."""
    return ' '.join(hex(ord(char)) for char in data)


def bytearray_to_hex(data):
    """Convert bytearray into array of hexes to be printed."""
    return ' '.join(hex(byte) for byte in data)


# the following functions are taken from OpenStack
#
# Get requirements from the first file that exists
def get_reqs_from_files(requirements_files):
    for requirements_file in requirements_files:
        if os.path.exists(requirements_file):
            with open(requirements_file, 'r') as fil:
                return fil.read().split('\n')
    return []


def parse_requirements(requirements_files=['requirements.txt',
                                           'tools/pip-requires']):
    requirements = []
    for line in get_reqs_from_files(requirements_files):
        # For the requirements list, we need to inject only the portion
        # after egg= so that distutils knows the package it's looking for
        # such as:
        # -e git://github.com/openstack/nova/master#egg=nova
        if re.match(r'\s*-e\s+', line):
            requirements.append(re.sub(r'\s*-e\s+.*#egg=(.*)$', r'\1',
                                line))
        # such as:
        # http://github.com/openstack/nova/zipball/master#egg=nova
        elif re.match(r'\s*https?:', line):
            requirements.append(re.sub(r'\s*https?:.*#egg=(.*)$', r'\1',
                                line))
        # -f lines are for index locations, and don't get used here
        elif re.match(r'\s*-f\s+', line):
            pass
        else:
            requirements.append(line)

    return requirements
