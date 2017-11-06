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
 Utilities related to bgp data types and models.
"""
import logging

import netaddr

from ryu.lib import ip
from ryu.lib.packet.bgp import (
    BGPUpdate,
    RF_IPv4_UC,
    RF_IPv6_UC,
    RF_IPv4_VPN,
    RF_IPv6_VPN,
    RF_L2_EVPN,
    RF_IPv4_FLOWSPEC,
    RF_IPv6_FLOWSPEC,
    RF_VPNv4_FLOWSPEC,
    RF_VPNv6_FLOWSPEC,
    RF_L2VPN_FLOWSPEC,
    RF_RTC_UC,
    RouteTargetMembershipNLRI,
    BGP_ATTR_TYPE_MULTI_EXIT_DISC,
    BGPPathAttributeMultiExitDisc,
    BGPPathAttributeMpUnreachNLRI,
    BGPPathAttributeAs4Path,
    BGPPathAttributeAs4Aggregator,
    BGPPathAttributeUnknown,
    BGP_ATTR_FLAG_OPTIONAL,
    BGP_ATTR_FLAG_TRANSITIVE,
    BGPTwoOctetAsSpecificExtendedCommunity,
    BGPIPv4AddressSpecificExtendedCommunity,
    BGPFourOctetAsSpecificExtendedCommunity,
    BGPFlowSpecTrafficRateCommunity,
    BGPFlowSpecTrafficActionCommunity,
    BGPFlowSpecRedirectCommunity,
    BGPFlowSpecTrafficMarkingCommunity,
    BGPFlowSpecVlanActionCommunity,
    BGPFlowSpecTPIDActionCommunity,
)
from ryu.services.protocols.bgp.info_base.rtc import RtcPath
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Path
from ryu.services.protocols.bgp.info_base.ipv6 import Ipv6Path
from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Path
from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Path
from ryu.services.protocols.bgp.info_base.evpn import EvpnPath
from ryu.services.protocols.bgp.info_base.ipv4fs import IPv4FlowSpecPath
from ryu.services.protocols.bgp.info_base.ipv6fs import IPv6FlowSpecPath
from ryu.services.protocols.bgp.info_base.vpnv4fs import VPNv4FlowSpecPath
from ryu.services.protocols.bgp.info_base.vpnv6fs import VPNv6FlowSpecPath
from ryu.services.protocols.bgp.info_base.l2vpnfs import L2VPNFlowSpecPath


LOG = logging.getLogger('utils.bgp')

# RouteFamily to path sub-class mapping.
_ROUTE_FAMILY_TO_PATH_MAP = {RF_IPv4_UC: Ipv4Path,
                             RF_IPv6_UC: Ipv6Path,
                             RF_IPv4_VPN: Vpnv4Path,
                             RF_IPv6_VPN: Vpnv6Path,
                             RF_L2_EVPN: EvpnPath,
                             RF_IPv4_FLOWSPEC: IPv4FlowSpecPath,
                             RF_IPv6_FLOWSPEC: IPv6FlowSpecPath,
                             RF_VPNv4_FLOWSPEC: VPNv4FlowSpecPath,
                             RF_VPNv6_FLOWSPEC: VPNv6FlowSpecPath,
                             RF_L2VPN_FLOWSPEC: L2VPNFlowSpecPath,
                             RF_RTC_UC: RtcPath}


def create_path(src_peer, nlri, **kwargs):
    route_family = nlri.ROUTE_FAMILY
    assert route_family in _ROUTE_FAMILY_TO_PATH_MAP.keys()
    path_cls = _ROUTE_FAMILY_TO_PATH_MAP.get(route_family)
    return path_cls(src_peer, nlri, src_peer.version_num, **kwargs)


def clone_path_and_update_med_for_target_neighbor(path, med):
    assert path and med
    route_family = path.route_family
    if route_family not in _ROUTE_FAMILY_TO_PATH_MAP.keys():
        raise ValueError('Clone is not supported for address-family %s' %
                         route_family)
    path_cls = _ROUTE_FAMILY_TO_PATH_MAP.get(route_family)
    pattrs = path.pathattr_map
    pattrs[BGP_ATTR_TYPE_MULTI_EXIT_DISC] = BGPPathAttributeMultiExitDisc(med)
    return path_cls(
        path.source, path.nlri, path.source_version_num,
        pattrs=pattrs, nexthop=path.nexthop,
        is_withdraw=path.is_withdraw,
        med_set_by_target_neighbor=True
    )


def clone_rtcpath_update_rt_as(path, new_rt_as):
    """Clones given RT NLRI `path`, and updates it with new RT_NLRI AS.

        Parameters:
            - `path`: (Path) RT_NLRI path
            - `new_rt_as`: AS value of cloned paths' RT_NLRI
    """
    assert path and new_rt_as
    if not path or path.route_family != RF_RTC_UC:
        raise ValueError('Expected RT_NLRI path')
    old_nlri = path.nlri
    new_rt_nlri = RouteTargetMembershipNLRI(new_rt_as, old_nlri.route_target)
    return RtcPath(path.source, new_rt_nlri, path.source_version_num,
                   pattrs=path.pathattr_map, nexthop=path.nexthop,
                   is_withdraw=path.is_withdraw)


def from_inet_ptoi(bgp_id):
    """Convert an IPv4 address string format to a four byte long.
    """
    four_byte_id = None
    try:
        four_byte_id = ip.ipv4_to_int(bgp_id)
    except ValueError:
        LOG.debug('Invalid bgp id given for conversion to integer value %s',
                  bgp_id)

    return four_byte_id


def get_unknown_opttrans_attr(path):
    """Utility method that gives a `dict` of unknown and unsupported optional
    transitive path attributes of `path`.

    Returns dict: <key> - attribute type code, <value> - unknown path-attr.
    """
    path_attrs = path.pathattr_map
    unknown_opt_tran_attrs = {}
    for _, attr in path_attrs.items():
        if (isinstance(attr, BGPPathAttributeUnknown) and
                attr.flags & (BGP_ATTR_FLAG_OPTIONAL |
                              BGP_ATTR_FLAG_TRANSITIVE)) or \
                isinstance(attr, BGPPathAttributeAs4Path) or \
                isinstance(attr, BGPPathAttributeAs4Aggregator):
            unknown_opt_tran_attrs[attr.type] = attr

    return unknown_opt_tran_attrs


def create_end_of_rib_update():
    """Construct end-of-rib (EOR) Update instance."""
    mpunreach_attr = BGPPathAttributeMpUnreachNLRI(RF_IPv4_VPN.afi,
                                                   RF_IPv4_VPN.safi,
                                                   [])
    eor = BGPUpdate(path_attributes=[mpunreach_attr])
    return eor


# Bgp update message instance that can used as End of RIB marker.
UPDATE_EOR = create_end_of_rib_update()


def create_rt_extended_community(value, subtype=2):
    """
    Creates an instance of the BGP Route Target Community (if "subtype=2")
    or Route Origin Community ("subtype=3").

    :param value: String of Route Target or Route Origin value.
    :param subtype: Subtype of Extended Community.
    :return: An instance of Route Target or Route Origin Community.
    """
    global_admin, local_admin = value.split(':')
    local_admin = int(local_admin)
    if global_admin.isdigit() and 0 <= int(global_admin) <= 0xffff:
        ext_com = BGPTwoOctetAsSpecificExtendedCommunity(
            subtype=subtype,
            as_number=int(global_admin),
            local_administrator=local_admin)
    elif global_admin.isdigit() and 0xffff < int(global_admin) <= 0xffffffff:
        ext_com = BGPFourOctetAsSpecificExtendedCommunity(
            subtype=subtype,
            as_number=int(global_admin),
            local_administrator=local_admin)
    elif ip.valid_ipv4(global_admin):
        ext_com = BGPIPv4AddressSpecificExtendedCommunity(
            subtype=subtype,
            ipv4_address=global_admin,
            local_administrator=local_admin)
    else:
        raise ValueError(
            'Invalid Route Target or Route Origin value: %s' % value)

    return ext_com


def create_v4flowspec_actions(actions=None):
    """
    Create list of traffic filtering actions
    for Ipv4 Flow Specification and VPNv4 Flow Specification.

    `` actions`` specifies Traffic Filtering Actions of
    Flow Specification as a dictionary type value.

    Returns a list of extended community values.
    """
    from ryu.services.protocols.bgp.api.prefix import (
        FLOWSPEC_ACTION_TRAFFIC_RATE,
        FLOWSPEC_ACTION_TRAFFIC_ACTION,
        FLOWSPEC_ACTION_REDIRECT,
        FLOWSPEC_ACTION_TRAFFIC_MARKING,
    )

    # Supported action type for IPv4 and VPNv4.
    action_types = {
        FLOWSPEC_ACTION_TRAFFIC_RATE: BGPFlowSpecTrafficRateCommunity,
        FLOWSPEC_ACTION_TRAFFIC_ACTION: BGPFlowSpecTrafficActionCommunity,
        FLOWSPEC_ACTION_REDIRECT: BGPFlowSpecRedirectCommunity,
        FLOWSPEC_ACTION_TRAFFIC_MARKING: BGPFlowSpecTrafficMarkingCommunity,
    }

    return _create_actions(actions, action_types)


def create_v6flowspec_actions(actions=None):
    """
    Create list of traffic filtering actions
    for Ipv6 Flow Specification and VPNv6 Flow Specification.

    "FLOWSPEC_ACTION_REDIRECT_IPV6" is not implemented yet.
    """
    from ryu.services.protocols.bgp.api.prefix import (
        FLOWSPEC_ACTION_TRAFFIC_RATE,
        FLOWSPEC_ACTION_TRAFFIC_ACTION,
        FLOWSPEC_ACTION_REDIRECT,
        FLOWSPEC_ACTION_TRAFFIC_MARKING,
    )

    # Supported action type for IPv6 and VPNv6.
    action_types = {
        FLOWSPEC_ACTION_TRAFFIC_RATE: BGPFlowSpecTrafficRateCommunity,
        FLOWSPEC_ACTION_TRAFFIC_ACTION: BGPFlowSpecTrafficActionCommunity,
        FLOWSPEC_ACTION_REDIRECT: BGPFlowSpecRedirectCommunity,
        FLOWSPEC_ACTION_TRAFFIC_MARKING: BGPFlowSpecTrafficMarkingCommunity,
    }

    return _create_actions(actions, action_types)


def create_l2vpnflowspec_actions(actions=None):
    """
    Create list of traffic filtering actions for L2VPN Flow Specification.
    """
    from ryu.services.protocols.bgp.api.prefix import (
        FLOWSPEC_ACTION_TRAFFIC_RATE,
        FLOWSPEC_ACTION_TRAFFIC_ACTION,
        FLOWSPEC_ACTION_REDIRECT,
        FLOWSPEC_ACTION_TRAFFIC_MARKING,
        FLOWSPEC_ACTION_VLAN,
        FLOWSPEC_ACTION_TPID,
    )

    # Supported action type for L2VPN.
    action_types = {
        FLOWSPEC_ACTION_TRAFFIC_RATE: BGPFlowSpecTrafficRateCommunity,
        FLOWSPEC_ACTION_TRAFFIC_ACTION: BGPFlowSpecTrafficActionCommunity,
        FLOWSPEC_ACTION_REDIRECT: BGPFlowSpecRedirectCommunity,
        FLOWSPEC_ACTION_TRAFFIC_MARKING: BGPFlowSpecTrafficMarkingCommunity,
        FLOWSPEC_ACTION_VLAN: BGPFlowSpecVlanActionCommunity,
        FLOWSPEC_ACTION_TPID: BGPFlowSpecTPIDActionCommunity,
    }

    return _create_actions(actions, action_types)


def _create_actions(actions, action_types):
    communities = []

    if actions is None:
        return communities

    for name, action in actions.items():
        cls_ = action_types.get(name, None)
        if cls_:
            communities.append(cls_(**action))
        else:
            raise ValueError(
                'Unsupported flowspec action %s' % name)

    return communities
