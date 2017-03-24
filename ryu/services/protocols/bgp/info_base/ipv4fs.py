# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
 Defines data types and models required specifically
 for Ipv4 Flow Specification support.
"""

import logging

from ryu.lib.packet.bgp import FlowSpecIPv4NLRI
from ryu.lib.packet.bgp import RF_IPv4_FLOWSPEC

from ryu.services.protocols.bgp.info_base.base import Path
from ryu.services.protocols.bgp.info_base.base import Table
from ryu.services.protocols.bgp.info_base.base import Destination
from ryu.services.protocols.bgp.info_base.base import NonVrfPathProcessingMixin

LOG = logging.getLogger('bgpspeaker.info_base.ipv4fs')


class IPv4FlowSpecDest(Destination, NonVrfPathProcessingMixin):
    """IPv4 Flow Specification Destination

    Store Flow Specification Paths.
    """
    ROUTE_FAMILY = RF_IPv4_FLOWSPEC

    def _best_path_lost(self):
        old_best_path = self._best_path
        NonVrfPathProcessingMixin._best_path_lost(self)
        self._core_service._signal_bus.best_path_changed(old_best_path, True)

    def _new_best_path(self, best_path):
        NonVrfPathProcessingMixin._new_best_path(self, best_path)
        self._core_service._signal_bus.best_path_changed(best_path, False)


class IPv4FlowSpecTable(Table):
    """Global table to store IPv4 Flow Specification routing information.

    Uses `FlowSpecIpv4Dest` to store destination information for each known
    Flow Specification paths.
    """
    ROUTE_FAMILY = RF_IPv4_FLOWSPEC
    VPN_DEST_CLASS = IPv4FlowSpecDest

    def __init__(self, core_service, signal_bus):
        super(IPv4FlowSpecTable, self).__init__(None, core_service, signal_bus)

    def _table_key(self, nlri):
        """Return a key that will uniquely identify this NLRI inside
        this table.
        """
        return nlri.prefix

    def _create_dest(self, nlri):
        return self.VPN_DEST_CLASS(self, nlri)

    def __str__(self):
        return '%s(scope_id: %s, rf: %s)' % (
            self.__class__.__name__, self.scope_id, self.route_family
        )


class IPv4FlowSpecPath(Path):
    """Represents a way of reaching an IPv4 Flow Specification destination."""
    ROUTE_FAMILY = RF_IPv4_FLOWSPEC
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = FlowSpecIPv4NLRI

    def __init__(self, *args, **kwargs):
        # Set dummy IP address.
        kwargs['nexthop'] = '0.0.0.0'
        super(IPv4FlowSpecPath, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrf4fs import (
            Vrf4FlowSpecPath)
        self.VRF_PATH_CLASS = Vrf4FlowSpecPath
        # Because the IPv4 Flow Specification does not require nexthop,
        # initialize with None.
        self._nexthop = None
