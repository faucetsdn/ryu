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
 Defines base data types and models required specifically for VPN support.
"""

import abc
import logging
import six

from ryu.lib.packet.bgp import RF_L2_EVPN
from ryu.services.protocols.bgp.info_base.base import Destination
from ryu.services.protocols.bgp.info_base.base import NonVrfPathProcessingMixin
from ryu.services.protocols.bgp.info_base.base import Path
from ryu.services.protocols.bgp.info_base.base import Table

LOG = logging.getLogger('bgpspeaker.info_base.vpn')


class VpnTable(Table):
    """Global table to store VPNv4 routing information.

    Uses `VpnvXDest` to store destination information for each known vpnvX
    paths.
    """
    ROUTE_FAMILY = None
    VPN_DEST_CLASS = None

    def __init__(self, core_service, signal_bus):
        super(VpnTable, self).__init__(None, core_service, signal_bus)

    def _table_key(self, vpn_nlri):
        """Return a key that will uniquely identify this vpnvX NLRI inside
        this table.
        """
        return vpn_nlri.route_dist + ':' + vpn_nlri.prefix

    def _create_dest(self, nlri):
        return self.VPN_DEST_CLASS(self, nlri)

    def __str__(self):
        return '%s(scope_id: %s, rf: %s)' % (
            self.__class__.__name__, self.scope_id, self.route_family
        )


@six.add_metaclass(abc.ABCMeta)
class VpnPath(Path):
    ROUTE_FAMILY = None
    VRF_PATH_CLASS = None
    NLRI_CLASS = None

    def clone_to_vrf(self, is_withdraw=False):
        if self.ROUTE_FAMILY == RF_L2_EVPN:
            # Because NLRI class is the same if the route family is EVPN,
            # we re-use the NLRI instance.
            vrf_nlri = self._nlri
        else:  # self.ROUTE_FAMILY in [RF_IPv4_VPN, RF_IPv46_VPN]
            vrf_nlri = self.NLRI_CLASS(self._nlri.prefix)

        pathattrs = None
        if not is_withdraw:
            pathattrs = self.pathattr_map

        vrf_path = self.VRF_PATH_CLASS(
            puid=self.VRF_PATH_CLASS.create_puid(
                self._nlri.route_dist,
                self._nlri.prefix),
            source=self.source,
            nlri=vrf_nlri,
            src_ver_num=self.source_version_num,
            pattrs=pathattrs,
            nexthop=self.nexthop,
            is_withdraw=is_withdraw,
            label_list=self._nlri.label_list)

        return vrf_path


@six.add_metaclass(abc.ABCMeta)
class VpnDest(Destination, NonVrfPathProcessingMixin):
    """Base class for VPN destinations."""

    def _best_path_lost(self):
        old_best_path = self._best_path
        NonVrfPathProcessingMixin._best_path_lost(self)
        self._core_service._signal_bus.best_path_changed(old_best_path, True)

        # Best-path might have been imported into VRF tables, we have to
        # withdraw from them, if the source is a peer.
        if old_best_path:
            withdraw_clone = old_best_path.clone(for_withdrawal=True)
            tm = self._core_service.table_manager
            tm.import_single_vpn_path_to_all_vrfs(
                withdraw_clone, path_rts=old_best_path.get_rts()
            )

    def _new_best_path(self, best_path):
        NonVrfPathProcessingMixin._new_best_path(self, best_path)
        self._core_service._signal_bus.best_path_changed(best_path, False)

        # Extranet feature requires that we import new best path into VRFs.
        tm = self._core_service.table_manager
        tm.import_single_vpn_path_to_all_vrfs(
            self._best_path, self._best_path.get_rts())
