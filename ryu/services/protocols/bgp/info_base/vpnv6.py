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
 Defines data types and models required specifically for VPNv6 support.
"""

import logging

from ryu.lib.packet.bgp import IP6AddrPrefix
from ryu.lib.packet.bgp import RF_IPv6_VPN

from ryu.services.protocols.bgp.info_base.vpn import VpnDest
from ryu.services.protocols.bgp.info_base.vpn import VpnPath
from ryu.services.protocols.bgp.info_base.vpn import VpnTable

LOG = logging.getLogger('bgpspeaker.info_base.vpnv6')


class Vpnv6Dest(VpnDest):
    """VPNv6 destination

    Stores IPv6 paths.
    """
    ROUTE_FAMILY = RF_IPv6_VPN


class Vpnv6Table(VpnTable):
    """Global table to store VPNv6 routing information

    Uses `Vpnv6Dest` to store destination information for each known vpnv6
    paths.
    """
    ROUTE_FAMILY = RF_IPv6_VPN
    VPN_DEST_CLASS = Vpnv6Dest


class Vpnv6Path(VpnPath):
    """Represents a way of reaching an VPNv4 destination."""
    ROUTE_FAMILY = RF_IPv6_VPN
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = IP6AddrPrefix

    def __init__(self, *args, **kwargs):
        super(Vpnv6Path, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrf6 import Vrf6Path
        self.VRF_PATH_CLASS = Vrf6Path
