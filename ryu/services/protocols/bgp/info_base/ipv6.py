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
 Defines data types and models required specifically for IPv4 support.
"""

import logging

from ryu.lib.packet.bgp import IPAddrPrefix
from ryu.lib.packet.bgp import RF_IPv6_UC

from ryu.services.protocols.bgp.info_base.base import Path
from ryu.services.protocols.bgp.info_base.base import Table
from ryu.services.protocols.bgp.info_base.base import Destination
from ryu.services.protocols.bgp.info_base.base import NonVrfPathProcessingMixin
from ryu.services.protocols.bgp.info_base.base import PrefixFilter

LOG = logging.getLogger('bgpspeaker.info_base.ipv6')


class IPv6Dest(Destination, NonVrfPathProcessingMixin):
    """v6 Destination

    Store IPv6 Paths.
    """
    ROUTE_FAMILY = RF_IPv6_UC

    def _best_path_lost(self):
        old_best_path = self._best_path
        NonVrfPathProcessingMixin._best_path_lost(self)
        self._core_service._signal_bus.best_path_changed(old_best_path, True)

    def _new_best_path(self, best_path):
        NonVrfPathProcessingMixin._new_best_path(self, best_path)
        self._core_service._signal_bus.best_path_changed(best_path, False)


class Ipv6Table(Table):
    """Global table to store IPv4 routing information.

    Uses `IPv6Dest` to store destination information for each known vpnv6
    paths.
    """
    ROUTE_FAMILY = RF_IPv6_UC
    VPN_DEST_CLASS = IPv6Dest

    def __init__(self, core_service, signal_bus):
        super(Ipv6Table, self).__init__(None, core_service, signal_bus)

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


class Ipv6Path(Path):
    """Represents a way of reaching an v6 destination."""
    ROUTE_FAMILY = RF_IPv6_UC
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = IPAddrPrefix

    def __init__(self, *args, **kwargs):
        super(Ipv6Path, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrf6 import Vrf6Path
        self.VRF_PATH_CLASS = Vrf6Path


class Ipv6PrefixFilter(PrefixFilter):
    """IPv6 Prefix Filter class"""
    ROUTE_FAMILY = RF_IPv6_UC
