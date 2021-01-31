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


def _import_module_file(path):
    abspath = os.path.abspath(path)
    # Backup original sys.path before appending path to file
    original_path = list(sys.path)
    sys.path.append(os.path.dirname(abspath))
    modname = chop_py_suffix(os.path.basename(abspath))
    try:
        return load_source(modname, abspath)
    finally:
        # Restore original sys.path
        sys.path = original_path


def import_module(modname):
    if os.path.exists(modname):
        try:
            # Try to import module since 'modname' is a valid path to a file
            # e.g.) modname = './path/to/module/name.py'
            return _import_module_file(modname)
        except SyntaxError:
            # The file didn't parse as valid Python code, try
            # importing module assuming 'modname' is a Python module name
            # e.g.) modname = 'path.to.module.name'
            return importlib.import_module(modname)
    else:
        # Import module assuming 'modname' is a Python module name
        # e.g.) modname = 'path.to.module.name'
        return importlib.import_module(modname)


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
