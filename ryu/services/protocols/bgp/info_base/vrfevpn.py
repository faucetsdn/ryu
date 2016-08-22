# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
 Defines data types and models required specifically for VRF (for EVPN)
 support. Represents data structures for VRF not VPN/global.
"""

import logging

from ryu.lib.packet.bgp import RF_L2_EVPN
from ryu.lib.packet.bgp import EvpnNLRI

from ryu.services.protocols.bgp.info_base.evpn import EvpnPath
from ryu.services.protocols.bgp.info_base.vrf import VrfDest
from ryu.services.protocols.bgp.info_base.vrf import VrfNlriImportMap
from ryu.services.protocols.bgp.info_base.vrf import VrfPath
from ryu.services.protocols.bgp.info_base.vrf import VrfTable

LOG = logging.getLogger('bgpspeaker.info_base.vrfevpn')


class VrfEvpnPath(VrfPath):
    """Represents a way of reaching an EVPN destination with a VPN."""
    ROUTE_FAMILY = RF_L2_EVPN
    VPN_PATH_CLASS = EvpnPath
    VPN_NLRI_CLASS = EvpnNLRI


class VrfEvpnDest(VrfDest):
    """Destination for EVPN VRFs."""
    ROUTE_FAMILY = RF_L2_EVPN


class VrfEvpnTable(VrfTable):
    """Virtual Routing and Forwarding information base for EVPN."""
    ROUTE_FAMILY = RF_L2_EVPN
    VPN_ROUTE_FAMILY = RF_L2_EVPN
    NLRI_CLASS = EvpnNLRI
    VRF_PATH_CLASS = VrfEvpnPath
    VRF_DEST_CLASS = VrfEvpnDest


class VrfEvpnNlriImportMap(VrfNlriImportMap):
    VRF_PATH_CLASS = VrfEvpnPath
    NLRI_CLASS = EvpnNLRI
