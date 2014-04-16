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
 Defines data types and models required specifically for VRF (for IPv6)
 support. Represents data structures for VRF not VPN/global.
 (Inside VRF you have IPv4 prefixes and inside VPN you have VPNv6 prefixes)
"""

import logging

from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import IP6AddrPrefix
from ryu.lib.packet.bgp import LabelledVPNIP6AddrPrefix

from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Path
from ryu.services.protocols.bgp.info_base.vrf import VrfDest
from ryu.services.protocols.bgp.info_base.vrf import VrfNlriImportMap
from ryu.services.protocols.bgp.info_base.vrf import VrfPath
from ryu.services.protocols.bgp.info_base.vrf import VrfTable

LOG = logging.getLogger('bgpspeaker.info_base.vrf6')


class Vrf6Path(VrfPath):
    """Represents a way of reaching an IP destination with a VPN."""
    ROUTE_FAMILY = RF_IPv6_UC
    VPN_PATH_CLASS = Vpnv6Path
    VPN_NLRI_CLASS = LabelledVPNIP6AddrPrefix


class Vrf6Dest(VrfDest):
    """Destination for IPv6 VRFs."""
    ROUTE_FAMILY = RF_IPv6_UC


class Vrf6Table(VrfTable):
    """Virtual Routing and Forwarding information base for IPv6."""
    ROUTE_FAMILY = RF_IPv6_UC
    VPN_ROUTE_FAMILY = RF_IPv6_VPN
    NLRI_CLASS = IP6AddrPrefix
    VRF_PATH_CLASS = Vrf6Path
    VRF_DEST_CLASS = Vrf6Dest


class Vrf6NlriImportMap(VrfNlriImportMap):
    VRF_PATH_CLASS = Vrf6Path
    NLRI_CLASS = IP6AddrPrefix
