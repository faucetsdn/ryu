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
 Defines data types and models required specifically for VRF (for IPv4)
 support. Represents data structures for VRF not VPN/global.
 (Inside VRF you have IPv4 prefixes and inside VPN you have VPNv4 prefixes)
"""

import logging

from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import IPAddrPrefix
from ryu.lib.packet.bgp import LabelledVPNIPAddrPrefix

from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Path
from ryu.services.protocols.bgp.info_base.vrf import VrfDest
from ryu.services.protocols.bgp.info_base.vrf import VrfNlriImportMap
from ryu.services.protocols.bgp.info_base.vrf import VrfPath
from ryu.services.protocols.bgp.info_base.vrf import VrfTable

LOG = logging.getLogger('bgpspeaker.info_base.vrf4')


class Vrf4Path(VrfPath):
    """Represents a way of reaching an IP destination with a VPN."""
    ROUTE_FAMILY = RF_IPv4_UC
    VPN_PATH_CLASS = Vpnv4Path
    VPN_NLRI_CLASS = LabelledVPNIPAddrPrefix


class Vrf4Dest(VrfDest):
    ROUTE_FAMILY = RF_IPv4_UC


class Vrf4Table(VrfTable):
    """Virtual Routing and Forwarding information base for IPv4."""
    ROUTE_FAMILY = RF_IPv4_UC
    VPN_ROUTE_FAMILY = RF_IPv4_VPN
    NLRI_CLASS = IPAddrPrefix
    VRF_PATH_CLASS = Vrf4Path
    VRF_DEST_CLASS = Vrf4Dest


class Vrf4NlriImportMap(VrfNlriImportMap):
    VRF_PATH_CLASS = Vrf4Path
    NLRI_CLASS = IPAddrPrefix
