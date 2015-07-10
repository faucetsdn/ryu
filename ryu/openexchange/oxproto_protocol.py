# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from . import oxproto_v1_0
from . import oxproto_v1_0_parser

_versions = {
    oxproto_v1_0.OXP_VERSION: (oxproto_v1_0, oxproto_v1_0_parser),
}


# OF versions supported by every apps in this process (intersection)
_supported_versions = set(_versions.keys())


def set_app_supported_versions(vers):
    global _supported_versions

    _supported_versions &= set(vers)
    assert _supported_versions, 'No OpenExchange version is available'


class ProtocolDesc(object):
    """
    OpenExchange protocol version flavor descriptor
    """

    def __init__(self, version=None):
        if version is None:
            version = max(_supported_versions)
        self.set_version(version)

    def set_version(self, version):
        assert version in _supported_versions
        (self.oxproto, self.oxproto_parser) = _versions[version]

    @property
    def supported_ofp_version(self):
        return _supported_versions
