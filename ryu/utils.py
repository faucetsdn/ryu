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

import importlib
import logging
import os
import sys

import six
from pip import req as pip_req
from pip.download import PipSession


LOG = logging.getLogger('ryu.utils')


def load_source(name, pathname):
    """
    This function provides the backward compatibility for 'imp.load_source'
    in Python 2.

    :param name: Name used to create or access a module object.
    :param pathname: Path pointing to the source file.
    :return: Loaded and initialized module.
    """
    if six.PY2:
        import imp
        return imp.load_source(name, pathname)
    else:
        loader = importlib.machinery.SourceFileLoader(name, pathname)
        return loader.load_module(name)


def chop_py_suffix(p):
    for suf in ['.py', '.pyc', '.pyo']:
        if p.endswith(suf):
            return p[:-len(suf)]
    return p


def _likely_same(a, b):
    try:
        # Samefile not availible on windows
        if sys.platform == 'win32':
            if os.stat(a) == os.stat(b):
                return True
        else:
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
    for k, m in sys.modules.copy().items():
        if k == '__main__':
            continue
        if not hasattr(m, '__file__'):
            continue
        if _likely_same(m.__file__, modpath):
            return m
    return None


def import_module(modname):
    try:
        # Import module with python module path
        # e.g.) modname = 'module.path.module_name'
        return importlib.import_module(modname)
    except (ImportError, TypeError):
        # In this block, we retry to import module when modname is filename
        # e.g.) modname = 'module/path/module_name.py'
        abspath = os.path.abspath(modname)
        # Check if specified modname is already imported
        mod = _find_loaded_module(abspath)
        if mod:
            return mod
        # Backup original sys.path before appending path to file
        original_path = list(sys.path)
        sys.path.append(os.path.dirname(abspath))
        # Remove python suffix
        name = chop_py_suffix(os.path.basename(modname))
        # Retry to import
        mod = importlib.import_module(name)
        # Restore sys.path
        sys.path = original_path
        return mod


def round_up(x, y):
    return ((x + y - 1) // y) * y


def hex_array(data):
    """
    Convert six.binary_type or bytearray into array of hexes to be printed.
    """
    # convert data into bytearray explicitly
    return ' '.join('0x%02x' % byte for byte in bytearray(data))


def binary_str(data):
    """
    Convert six.binary_type or bytearray into str to be printed.
    """
    # convert data into bytearray explicitly
    return ''.join('\\x%02x' % byte for byte in bytearray(data))


def parse_requirements(requirements_files=None):
    """
    Parses requirements files and returns a list of requirements.

    Returned list would be like::

        ['foo', 'bar>=X.X', ...]

    :param requirements_files: List of requirements files. The default
     is ['requirements.txt', 'tools/pip-requires'].
    :return: List of requirements.
    """
    requirements_files = requirements_files or [
        'requirements.txt',
        'tools/pip-requires',
    ]

    requirements = []
    for f in requirements_files:
        if not os.path.isfile(f):
            continue

        for r in pip_req.parse_requirements(f, session=PipSession()):
            requirements.append(str(r.req))

    return requirements
