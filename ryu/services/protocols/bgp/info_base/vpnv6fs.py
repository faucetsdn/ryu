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
 VPNv6 Flow Specification support.
"""

import logging

from ryu.lib.packet.bgp import FlowSpecVPNv6NLRI
from ryu.lib.packet.bgp import RF_VPNv6_FLOWSPEC

from ryu.services.protocols.bgp.info_base.vpn import VpnDest
from ryu.services.protocols.bgp.info_base.vpn import VpnPath
from ryu.services.protocols.bgp.info_base.vpn import VpnTable

LOG = logging.getLogger('bgpspeaker.info_base.vpnv6fs')


class VPNv6FlowSpecDest(VpnDest):
    """VPNv6 Flow Specification Destination

    Store Flow Specification Paths.
    """
    ROUTE_FAMILY = RF_VPNv6_FLOWSPEC


class VPNv6FlowSpecTable(VpnTable):
    """Global table to store VPNv6 Flow Specification routing information.

    Uses `VPNv6FlowSpecDest` to store destination information for each known
    Flow Specification paths.
    """
    ROUTE_FAMILY = RF_VPNv6_FLOWSPEC
    VPN_DEST_CLASS = VPNv6FlowSpecDest


class VPNv6FlowSpecPath(VpnPath):
    """Represents a way of reaching an VPNv6 Flow Specification destination."""
    ROUTE_FAMILY = RF_VPNv6_FLOWSPEC
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = FlowSpecVPNv6NLRI

    def __init__(self, *args, **kwargs):
        # Set dummy IP address.
        kwargs['nexthop'] = '::'
        super(VPNv6FlowSpecPath, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrf6fs import (
            Vrf6FlowSpecPath)
        self.VRF_PATH_CLASS = Vrf6FlowSpecPath
        # Because the IPv6 Flow Specification does not require nexthop,
        # initialize with None.
        self._nexthop = None
