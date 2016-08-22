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

"""
 Defines data types and models required specifically for EVPN support.
"""

import logging

from ryu.lib.packet.bgp import EvpnNLRI
from ryu.lib.packet.bgp import RF_L2_EVPN

from ryu.services.protocols.bgp.info_base.base import Path
from ryu.services.protocols.bgp.info_base.base import Table
from ryu.services.protocols.bgp.info_base.base import Destination
from ryu.services.protocols.bgp.info_base.base import NonVrfPathProcessingMixin

LOG = logging.getLogger('bgpspeaker.info_base.evpn')


class EvpnDest(Destination, NonVrfPathProcessingMixin):
    """EVPN Destination

    Store EVPN paths.
    """
    ROUTE_FAMILY = RF_L2_EVPN

    def _best_path_lost(self):
        old_best_path = self._best_path
        NonVrfPathProcessingMixin._best_path_lost(self)
        self._core_service._signal_bus.best_path_changed(old_best_path, True)

    def _new_best_path(self, best_path):
        NonVrfPathProcessingMixin._new_best_path(self, best_path)
        self._core_service._signal_bus.best_path_changed(best_path, False)


class EvpnTable(Table):
    """Global table to store EVPN routing information.

    Uses `EvpnDest` to store destination information for each known EVPN
    paths.
    """
    ROUTE_FAMILY = RF_L2_EVPN
    VPN_DEST_CLASS = EvpnDest

    def __init__(self, core_service, signal_bus):
        super(EvpnTable, self).__init__(None, core_service, signal_bus)

    def _table_key(self, nlri):
        """Return a key that will uniquely identify this NLRI inside
        this table.
        """
        return nlri.formatted_nlri_str

    def _create_dest(self, nlri):
        return self.VPN_DEST_CLASS(self, nlri)

    def __str__(self):
        return '%s(scope_id: %s, rf: %s)' % (
            self.__class__.__name__, self.scope_id, self.route_family
        )


class EvpnPath(Path):
    """Represents a way of reaching an EVPN destination."""
    ROUTE_FAMILY = RF_L2_EVPN
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = EvpnNLRI

    def __init__(self, *args, **kwargs):
        super(EvpnPath, self).__init__(*args, **kwargs)
        # TODO:
        # To support the VRF table for BGP EVPN routes.
