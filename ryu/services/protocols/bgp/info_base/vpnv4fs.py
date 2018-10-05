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
 VPNv4 Flow Specification support.
"""

import logging

from ryu.lib.packet.bgp import FlowSpecVPNv4NLRI
from ryu.lib.packet.bgp import RF_VPNv4_FLOWSPEC

from ryu.services.protocols.bgp.info_base.vpn import VpnDest
from ryu.services.protocols.bgp.info_base.vpn import VpnPath
from ryu.services.protocols.bgp.info_base.vpn import VpnTable

LOG = logging.getLogger('bgpspeaker.info_base.vpnv4fs')


class VPNv4FlowSpecDest(VpnDest):
    """VPNv4 Flow Specification Destination

    Store Flow Specification Paths.
    """
    ROUTE_FAMILY = RF_VPNv4_FLOWSPEC


class VPNv4FlowSpecTable(VpnTable):
    """Global table to store VPNv4 Flow Specification routing information.

    Uses `VPNv4FlowSpecDest` to store destination information for each known
    Flow Specification paths.
    """
    ROUTE_FAMILY = RF_VPNv4_FLOWSPEC
    VPN_DEST_CLASS = VPNv4FlowSpecDest


class VPNv4FlowSpecPath(VpnPath):
    """Represents a way of reaching an VPNv4 Flow Specification destination."""
    ROUTE_FAMILY = RF_VPNv4_FLOWSPEC
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = FlowSpecVPNv4NLRI

    def __init__(self, *args, **kwargs):
        # Set dummy IP address.
        kwargs['nexthop'] = '0.0.0.0'
        super(VPNv4FlowSpecPath, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrf4fs import (
            Vrf4FlowSpecPath)
        self.VRF_PATH_CLASS = Vrf4FlowSpecPath
        # Because the IPv4 Flow Specification does not require nexthop,
        # initialize with None.
        self._nexthop = None
