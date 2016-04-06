# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import sys
from setuptools.command import easy_install
from ryu import version


# Global variables in this module doesn't work as we expect
# because, during the setup procedure, this module seems to be
# copied (as a file) and can be loaded multiple times.
# We save them into __main__ module instead.
def _main_module():
    return sys.modules['__main__']


def save_orig():
    """Save original easy_install.get_script_args.
    This is necessary because pbr's setup_hook is sometimes called
    before ours."""
    _main_module()._orig_get_script_args = easy_install.get_script_args


def setup_hook(config):
    """Filter config parsed from a setup.cfg to inject our defaults."""
    metadata = config['metadata']
    if sys.platform == 'win32':
        requires = metadata.get('requires_dist', '').split('\n')
        metadata['requires_dist'] = "\n".join(requires)
    config['metadata'] = metadata

    metadata['version'] = str(version)

    # pbr's setup_hook replaces easy_install.get_script_args with
    # their own version, override_get_script_args, prefering simpler
    # scripts which are not aware of multi-version.
    # prevent that by doing the opposite.  it's a horrible hack
    # but we are in patching wars already...
    from pbr import packaging

    def my_get_script_args(*args, **kwargs):
        return _main_module()._orig_get_script_args(*args, **kwargs)

    packaging.override_get_script_args = my_get_script_args
    easy_install.get_script_args = my_get_script_args

    # another hack to allow setup from tarball.
    orig_get_version = packaging.get_version

    def my_get_version(package_name, pre_version=None):
        if package_name == 'ryu':
            return str(version)
        return orig_get_version(package_name, pre_version)

    packaging.get_version = my_get_version
