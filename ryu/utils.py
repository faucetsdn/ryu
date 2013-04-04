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


import inspect
import logging
import os
import sys
import re

LOG = logging.getLogger('ryu.utils')


def _abspath(path):
    if path == '':
        path = '.'
    return os.path.abspath(path)


def _split_modname(modpath):
    sys_path = [_abspath(path) for path in sys.path]
    modname = os.path.basename(modpath)
    dirname = os.path.dirname(modpath)
    while True:
        if dirname in sys_path:
            break
        if not os.path.exists(os.path.join(dirname, '__init__.py')):
            break

        basename = os.path.basename(dirname)
        if basename:
            old_dirname = dirname
            dirname = os.path.dirname(dirname)
            if old_dirname == dirname:
                break
            if modname:
                modname = basename + '.' + modname
            else:
                modname = basename
        else:
            break

    return dirname, modname


def _import(modname):
    __import__(modname)
    return sys.modules[modname]


def import_module(modname):
    try:
        return _import(modname)
    except ImportError:
        pass

    if modname.endswith('.py'):
        modname = modname[:-3]
        try:
            return _import(modname)
        except ImportError:
            pass

    modname = os.path.abspath(modname)
    dirname, name = _split_modname(modname)
    if dirname not in [_abspath(path) for path in sys.path]:
        sys.path.append(dirname)
    return _import(name)


def round_up(x, y):
    return ((x + y - 1) / y) * y


def hex_array(data):
    return ' '.join(hex(ord(chr)) for chr in data)


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
        # argparse is part of the standard library starting with 2.7
        # adding it to the requirements list screws distro installs
        elif line == 'argparse' and sys.version_info >= (2, 7):
            pass
        else:
            requirements.append(line)

    return requirements
