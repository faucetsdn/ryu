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
 Defines data types and models required specifically for VPNv4 support.
"""

import logging

from ryu.lib.packet.bgp import IPAddrPrefix
from ryu.lib.packet.bgp import RF_IPv4_VPN

from ryu.services.protocols.bgp.info_base.vpn import VpnDest
from ryu.services.protocols.bgp.info_base.vpn import VpnPath
from ryu.services.protocols.bgp.info_base.vpn import VpnTable

LOG = logging.getLogger('bgpspeaker.info_base.vpnv4')


class Vpnv4Dest(VpnDest):
    """VPNv4 Destination

    Store IPv4 Paths.
    """
    ROUTE_FAMILY = RF_IPv4_VPN


class Vpnv4Table(VpnTable):
    """Global table to store VPNv4 routing information.

    Uses `Vpnv4Dest` to store destination information for each known vpnv4
    paths.
    """
    ROUTE_FAMILY = RF_IPv4_VPN
    VPN_DEST_CLASS = Vpnv4Dest


class Vpnv4Path(VpnPath):
    """Represents a way of reaching an VPNv4 destination."""
    ROUTE_FAMILY = RF_IPv4_VPN
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = IPAddrPrefix

    def __init__(self, *args, **kwargs):
        super(Vpnv4Path, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrf4 import Vrf4Path
        self.VRF_PATH_CLASS = Vrf4Path
