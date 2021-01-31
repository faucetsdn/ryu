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
 Defines data types and models required specifically for
 L2VPN Flow Specification support.
"""

import logging

from ryu.lib.packet.bgp import FlowSpecL2VPNNLRI
from ryu.lib.packet.bgp import RF_L2VPN_FLOWSPEC

from ryu.services.protocols.bgp.info_base.vpn import VpnDest
from ryu.services.protocols.bgp.info_base.vpn import VpnPath
from ryu.services.protocols.bgp.info_base.vpn import VpnTable

LOG = logging.getLogger('bgpspeaker.info_base.l2vpnfs')


class L2VPNFlowSpecDest(VpnDest):
    """L2VPN Flow Specification Destination

    Store Flow Specification Paths.
    """
    ROUTE_FAMILY = RF_L2VPN_FLOWSPEC


class L2VPNFlowSpecTable(VpnTable):
    """Global table to store L2VPN Flow Specification routing information.

    Uses `L2VPNFlowSpecDest` to store destination information for each known
    Flow Specification paths.
    """
    ROUTE_FAMILY = RF_L2VPN_FLOWSPEC
    VPN_DEST_CLASS = L2VPNFlowSpecDest


class L2VPNFlowSpecPath(VpnPath):
    """Represents a way of reaching an L2VPN Flow Specification destination."""
    ROUTE_FAMILY = RF_L2VPN_FLOWSPEC
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = FlowSpecL2VPNNLRI

    def __init__(self, *args, **kwargs):
        # Set dummy IP address.
        kwargs['nexthop'] = '0.0.0.0'
        super(L2VPNFlowSpecPath, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrfl2vpnfs import (
            L2vpnFlowSpecPath)
        self.VRF_PATH_CLASS = L2vpnFlowSpecPath
        # Because the L2VPN Flow Specification does not require nexthop,
        # initialize with None.
        self._nexthop = None
