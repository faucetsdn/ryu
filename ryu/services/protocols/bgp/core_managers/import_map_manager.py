# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

from ryu.services.protocols.bgp.info_base.vrf import VrfRtImportMap
from ryu.services.protocols.bgp.info_base.vrf4 import Vrf4NlriImportMap
from ryu.services.protocols.bgp.info_base.vrf6 import Vrf6NlriImportMap


class ImportMapManager(object):

    def __init__(self):
        self._import_maps_by_name = {}

    def create_vpnv4_nlri_import_map(self, name, value):
        self._create_import_map_factory(name, value, Vrf4NlriImportMap)

    def create_vpnv6_nlri_import_map(self, name, value):
        self._create_import_map_factory(name, value, Vrf6NlriImportMap)

    def create_rt_import_map(self, name, value):
        self._create_import_map_factory(name, value, VrfRtImportMap)

    def _create_import_map_factory(self, name, value, cls):
        if self._import_maps_by_name.get(name) is not None:
            raise ImportMapAlreadyExistsError()
        self._import_maps_by_name[name] = cls(value)

    def get_import_map_by_name(self, name):
        return self._import_maps_by_name.get(name)


class ImportMapAlreadyExistsError(Exception):
    pass
