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

"""
 Import-map configuration.
"""
import logging

from ryu.services.protocols.bgp.api.base import register
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.core_managers.import_map_manager\
    import ImportMapAlreadyExistsError
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError

LOG = logging.getLogger('bgpspeaker.api.import_map')


@register(name='importmap.create')
def create_importmap(type, action, name, value, route_family=None):
    if action != 'drop':
        raise RuntimeConfigError(
            'Unknown action. For now we only support "drop" action.'
        )

    if type not in ('prefix_match', 'rt_match'):
        raise RuntimeConfigError(
            'Unknown type. We support only "prefix_match" and "rt_match".'
        )

    if type == 'prefix_match':
        return _create_prefix_match_importmap(name, value, route_family)
    elif type == 'rt_match':
        return _create_rt_match_importmap(name, value)


def _create_prefix_match_importmap(name, value, route_family):
    core_service = CORE_MANAGER.get_core_service()
    importmap_manager = core_service.importmap_manager
    try:
        if route_family == 'ipv4':
            importmap_manager.create_vpnv4_nlri_import_map(name, value)
        elif route_family == 'ipv6':
            importmap_manager.create_vpnv6_nlri_import_map(name, value)
        else:
            raise RuntimeConfigError(
                'Unknown address family %s. it should be ipv4 or ipv6'
                % route_family
            )
    except ImportMapAlreadyExistsError:
        raise RuntimeConfigError(
            'Map with this name already exists'
        )

    return True


def _create_rt_match_importmap(name, value):
    core_service = CORE_MANAGER.get_core_service()
    importmap_manager = core_service.importmap_manager
    try:
        importmap_manager.create_rt_import_map(name, value)
    except ImportMapAlreadyExistsError:
        raise RuntimeConfigError(
            'Map with this name already exists'
        )

    return True
