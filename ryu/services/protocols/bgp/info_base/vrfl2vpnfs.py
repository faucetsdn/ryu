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
 for L2VPN support.
 Represents data structures for VRF not VPN/global.
 (Inside VRF you have L2VPN Flow Specification prefixes
 and inside VPN you have L2VPN Flow Specification prefixes)
"""

import logging

from ryu.lib.packet.bgp import RF_L2VPN_FLOWSPEC
from ryu.lib.packet.bgp import FlowSpecL2VPNNLRI

from ryu.services.protocols.bgp.info_base.l2vpnfs import L2VPNFlowSpecPath
from ryu.services.protocols.bgp.info_base.vrffs import VRFFlowSpecDest
from ryu.services.protocols.bgp.info_base.vrffs import VRFFlowSpecPath
from ryu.services.protocols.bgp.info_base.vrffs import VRFFlowSpecTable

LOG = logging.getLogger('bgpspeaker.info_base.vrfl2vpnfs')


class L2vpnFlowSpecPath(VRFFlowSpecPath):
    """Represents a way of reaching an IP destination with
    a L2VPN Flow Specification.
    """
    ROUTE_FAMILY = RF_L2VPN_FLOWSPEC
    VPN_PATH_CLASS = L2VPNFlowSpecPath
    VPN_NLRI_CLASS = FlowSpecL2VPNNLRI


class L2vpnFlowSpecDest(VRFFlowSpecDest):
    ROUTE_FAMILY = RF_L2VPN_FLOWSPEC


class L2vpnFlowSpecTable(VRFFlowSpecTable):
    """Virtual Routing and Forwarding information base
    for L2VPN Flow Specification.
    """
    ROUTE_FAMILY = RF_L2VPN_FLOWSPEC
    VPN_ROUTE_FAMILY = RF_L2VPN_FLOWSPEC
    NLRI_CLASS = FlowSpecL2VPNNLRI
    VRF_PATH_CLASS = L2vpnFlowSpecPath
    VRF_DEST_CLASS = L2vpnFlowSpecDest
