# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

import logging
import os
import sys
import unittest

import pkg_resources
from pip.req import parse_requirements
from pip.download import PipSession
from six.moves import urllib

from nose.tools import ok_


LOG = logging.getLogger(__name__)

MOD_DIR = os.path.dirname(sys.modules[__name__].__file__)
_RYU_REQUIREMENTS_FILES = [
    '../../../tools/pip-requires',
    '../../../tools/optional-requires',
]
RYU_REQUIREMENTS_FILES = [
    os.path.join(MOD_DIR, f) for f in _RYU_REQUIREMENTS_FILES]

OPENSTACK_REQUIREMENTS_REPO = 'https://github.com/openstack/requirements'
OPENSTACK_REQUIREMENTS_URL = (
    'https://github.com/openstack/requirements/raw/master/')
_OPENSTACK_REQUIREMENTS_FILES = [
    'requirements.txt',
    'global-requirements.txt',
]
OPENSTACK_REQUIREMENTS_FILES = [
    urllib.parse.urljoin(OPENSTACK_REQUIREMENTS_URL, f)
    for f in _OPENSTACK_REQUIREMENTS_FILES]


def _get_requirements(files):
    requirements = {}
    for f in files:
        req = parse_requirements(f, session=PipSession())
        for r in req:
            requirements[r.name] = str(r.req)

    return requirements

OPENSTACK_REQUIREMENTS = _get_requirements(OPENSTACK_REQUIREMENTS_FILES)
RYU_REQUIREMENTS = _get_requirements(RYU_REQUIREMENTS_FILES)


class TestRequirements(unittest.TestCase):
    """
    Test whether the requirements of Ryu has no conflict with that
    of other projects.
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_with_openstack_requirements(self):
        try:
            for name, req in OPENSTACK_REQUIREMENTS.items():
                if name in RYU_REQUIREMENTS:
                    ok_(pkg_resources.require(req))
        except pkg_resources.VersionConflict as e:
            LOG.exception(
                'Some requirements of Ryu are conflicting with that of '
                'OpenStack project: %s' % OPENSTACK_REQUIREMENTS_REPO)
            raise e
