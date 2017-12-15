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
 Defines base data types and models required specifically
 for VRF Flow Specification support.
"""

import abc
import logging
import six

from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
from ryu.lib.packet.bgp import BGPPathAttributeOrigin
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGPPathAttributeExtendedCommunities

from ryu.services.protocols.bgp.base import OrderedDict
from ryu.services.protocols.bgp.info_base.vrf import VrfTable
from ryu.services.protocols.bgp.info_base.vrf import VrfDest
from ryu.services.protocols.bgp.info_base.vrf import VrfPath

from ryu.services.protocols.bgp.utils.bgp import create_rt_extended_community

LOG = logging.getLogger('bgpspeaker.info_base.vrffs')


@six.add_metaclass(abc.ABCMeta)
class VRFFlowSpecTable(VrfTable):
    """Virtual Routing and Forwarding information base.
    Keeps destination imported to given VRF Flow Specification
    in represents.
    """

    def insert_vrffs_path(self, nlri, communities, is_withdraw=False):
        assert nlri
        assert isinstance(communities, list)
        vrf_conf = self.vrf_conf

        from ryu.services.protocols.bgp.core import EXPECTED_ORIGIN
        pattrs = OrderedDict()
        pattrs[BGP_ATTR_TYPE_ORIGIN] = BGPPathAttributeOrigin(
            EXPECTED_ORIGIN)
        pattrs[BGP_ATTR_TYPE_AS_PATH] = BGPPathAttributeAsPath([])

        for rt in vrf_conf.export_rts:
            communities.append(create_rt_extended_community(rt, 2))
        for soo in vrf_conf.soo_list:
            communities.append(create_rt_extended_community(soo, 3))

        pattrs[BGP_ATTR_TYPE_EXTENDED_COMMUNITIES] = (
            BGPPathAttributeExtendedCommunities(communities=communities))

        puid = self.VRF_PATH_CLASS.create_puid(
            vrf_conf.route_dist, nlri.prefix)

        path = self.VRF_PATH_CLASS(
            puid, None, nlri, 0,
            pattrs=pattrs, is_withdraw=is_withdraw
        )

        # Insert the path into VRF table, get affected destination so that we
        # can process it further.
        eff_dest = self.insert(path)
        # Enqueue the eff_dest for further processing.
        self._signal_bus.dest_changed(eff_dest)


@six.add_metaclass(abc.ABCMeta)
class VRFFlowSpecDest(VrfDest):
    """Base class for VRF Flow Specification."""


@six.add_metaclass(abc.ABCMeta)
class VRFFlowSpecPath(VrfPath):
    """Represents a way of reaching an IP destination with
    a VPN Flow Specification.
    """
