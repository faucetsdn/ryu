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
 for VRF (for IPv6 Flow Specification) support.
 Represents data structures for VRF not VPN/global.
 (Inside VRF you have IPv6 Flow Specification prefixes
 and inside VPN you have VPNV6 Flow Specification prefixes)
"""

import logging

from ryu.lib.packet.bgp import RF_IPv6_FLOWSPEC
from ryu.lib.packet.bgp import RF_VPNv6_FLOWSPEC
from ryu.lib.packet.bgp import FlowSpecIPv6NLRI
from ryu.lib.packet.bgp import FlowSpecVPNv6NLRI

from ryu.services.protocols.bgp.info_base.vpnv6fs import VPNv6FlowSpecPath
from ryu.services.protocols.bgp.info_base.vrffs import VRFFlowSpecDest
from ryu.services.protocols.bgp.info_base.vrffs import VRFFlowSpecPath
from ryu.services.protocols.bgp.info_base.vrffs import VRFFlowSpecTable

LOG = logging.getLogger('bgpspeaker.info_base.vrf6fs')


class Vrf6FlowSpecPath(VRFFlowSpecPath):
    """Represents a way of reaching an IP destination with
    a VPN Flow Specification.
    """
    ROUTE_FAMILY = RF_IPv6_FLOWSPEC
    VPN_PATH_CLASS = VPNv6FlowSpecPath
    VPN_NLRI_CLASS = FlowSpecVPNv6NLRI


class Vrf6FlowSpecDest(VRFFlowSpecDest):
    ROUTE_FAMILY = RF_IPv6_FLOWSPEC


class Vrf6FlowSpecTable(VRFFlowSpecTable):
    """Virtual Routing and Forwarding information base
    for IPv6 Flow Specification.
    """
    ROUTE_FAMILY = RF_IPv6_FLOWSPEC
    VPN_ROUTE_FAMILY = RF_VPNv6_FLOWSPEC
    NLRI_CLASS = FlowSpecIPv6NLRI
    VRF_PATH_CLASS = Vrf6FlowSpecPath
    VRF_DEST_CLASS = Vrf6FlowSpecDest
