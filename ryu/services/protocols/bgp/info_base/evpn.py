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
 Defines data types and models required specifically for EVPN support.
"""

import logging

from ryu.lib.packet.bgp import EvpnNLRI
from ryu.lib.packet.bgp import RF_L2_EVPN

from ryu.services.protocols.bgp.info_base.vpn import VpnDest
from ryu.services.protocols.bgp.info_base.vpn import VpnPath
from ryu.services.protocols.bgp.info_base.vpn import VpnTable

LOG = logging.getLogger('bgpspeaker.info_base.evpn')


class EvpnDest(VpnDest):
    """EVPN Destination

    Store EVPN Paths.
    """
    ROUTE_FAMILY = RF_L2_EVPN


class EvpnTable(VpnTable):
    """Global table to store EVPN routing information.

    Uses `EvpnDest` to store destination information for each known EVPN
    paths.
    """
    ROUTE_FAMILY = RF_L2_EVPN
    VPN_DEST_CLASS = EvpnDest


class EvpnPath(VpnPath):
    """Represents a way of reaching an EVPN destination."""
    ROUTE_FAMILY = RF_L2_EVPN
    VRF_PATH_CLASS = None  # defined in init - anti cyclic import hack
    NLRI_CLASS = EvpnNLRI

    def __init__(self, *args, **kwargs):
        super(EvpnPath, self).__init__(*args, **kwargs)
        from ryu.services.protocols.bgp.info_base.vrfevpn import VrfEvpnPath
        self.VRF_PATH_CLASS = VrfEvpnPath
