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
 Prefix related APIs.
"""
import logging

from ryu.lib.packet.bgp import EvpnEsi
from ryu.lib.packet.bgp import EvpnNLRI
from ryu.lib.packet.bgp import EvpnEthernetAutoDiscoveryNLRI
from ryu.lib.packet.bgp import EvpnMacIPAdvertisementNLRI
from ryu.lib.packet.bgp import EvpnInclusiveMulticastEthernetTagNLRI
from ryu.lib.packet.bgp import EvpnEthernetSegmentNLRI
from ryu.lib.packet.bgp import EvpnIpPrefixNLRI
from ryu.lib.packet.bgp import BGPPathAttributePmsiTunnel
from ryu.lib.packet.bgp import FlowSpecIPv4NLRI
from ryu.lib.packet.bgp import FlowSpecIPv6NLRI
from ryu.lib.packet.bgp import FlowSpecVPNv4NLRI
from ryu.lib.packet.bgp import FlowSpecVPNv6NLRI
from ryu.lib.packet.bgp import FlowSpecL2VPNNLRI
from ryu.lib.packet.bgp import BGPFlowSpecTrafficRateCommunity
from ryu.lib.packet.bgp import BGPFlowSpecTrafficActionCommunity
from ryu.lib.packet.bgp import BGPFlowSpecRedirectCommunity
from ryu.lib.packet.bgp import BGPFlowSpecTrafficMarkingCommunity
from ryu.lib.packet.bgp import BGPFlowSpecVlanActionCommunity
from ryu.lib.packet.bgp import BGPFlowSpecTPIDActionCommunity

from ryu.services.protocols.bgp.api.base import EVPN_ROUTE_TYPE
from ryu.services.protocols.bgp.api.base import EVPN_ESI
from ryu.services.protocols.bgp.api.base import EVPN_ETHERNET_TAG_ID
from ryu.services.protocols.bgp.api.base import REDUNDANCY_MODE
from ryu.services.protocols.bgp.api.base import MAC_ADDR
from ryu.services.protocols.bgp.api.base import IP_ADDR
from ryu.services.protocols.bgp.api.base import IP_PREFIX
from ryu.services.protocols.bgp.api.base import GW_IP_ADDR
from ryu.services.protocols.bgp.api.base import MPLS_LABELS
from ryu.services.protocols.bgp.api.base import NEXT_HOP
from ryu.services.protocols.bgp.api.base import PREFIX
from ryu.services.protocols.bgp.api.base import RegisterWithArgChecks
from ryu.services.protocols.bgp.api.base import ROUTE_DISTINGUISHER
from ryu.services.protocols.bgp.api.base import VPN_LABEL
from ryu.services.protocols.bgp.api.base import EVPN_VNI
from ryu.services.protocols.bgp.api.base import TUNNEL_TYPE
from ryu.services.protocols.bgp.api.base import PMSI_TUNNEL_TYPE
from ryu.services.protocols.bgp.api.base import MAC_MOBILITY
from ryu.services.protocols.bgp.api.base import TUNNEL_ENDPOINT_IP
from ryu.services.protocols.bgp.api.base import FLOWSPEC_FAMILY
from ryu.services.protocols.bgp.api.base import FLOWSPEC_RULES
from ryu.services.protocols.bgp.api.base import FLOWSPEC_ACTIONS
from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import PREFIX_ERROR_CODE
from ryu.services.protocols.bgp.base import validate
from ryu.services.protocols.bgp.core import BgpCoreError
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.rtconf.base import ConfigValueError
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_L2_EVPN
from ryu.services.protocols.bgp.utils import validation

LOG = logging.getLogger('bgpspeaker.api.prefix')

# Maximum value of the Ethernet Tag ID
EVPN_MAX_ET = EvpnNLRI.MAX_ET

# ESI Types
ESI_TYPE_ARBITRARY = EvpnEsi.ARBITRARY
ESI_TYPE_LACP = EvpnEsi.LACP
ESI_TYPE_L2_BRIDGE = EvpnEsi.L2_BRIDGE
ESI_TYPE_MAC_BASED = EvpnEsi.MAC_BASED
ESI_TYPE_ROUTER_ID = EvpnEsi.ROUTER_ID
ESI_TYPE_AS_BASED = EvpnEsi.AS_BASED
SUPPORTED_ESI_TYPES = [
    ESI_TYPE_ARBITRARY,
    ESI_TYPE_LACP,
    ESI_TYPE_L2_BRIDGE,
    ESI_TYPE_MAC_BASED,
    ESI_TYPE_ROUTER_ID,
    ESI_TYPE_AS_BASED,
]

# Constants used in API calls for EVPN
EVPN_ETH_AUTO_DISCOVERY = EvpnEthernetAutoDiscoveryNLRI.ROUTE_TYPE_NAME
EVPN_MAC_IP_ADV_ROUTE = EvpnMacIPAdvertisementNLRI.ROUTE_TYPE_NAME
EVPN_MULTICAST_ETAG_ROUTE = (
    EvpnInclusiveMulticastEthernetTagNLRI.ROUTE_TYPE_NAME)
EVPN_ETH_SEGMENT = EvpnEthernetSegmentNLRI.ROUTE_TYPE_NAME
EVPN_IP_PREFIX_ROUTE = EvpnIpPrefixNLRI.ROUTE_TYPE_NAME
SUPPORTED_EVPN_ROUTE_TYPES = [
    EVPN_ETH_AUTO_DISCOVERY,
    EVPN_MAC_IP_ADV_ROUTE,
    EVPN_MULTICAST_ETAG_ROUTE,
    EVPN_ETH_SEGMENT,
    EVPN_IP_PREFIX_ROUTE,
]

# Constants used in API calls for Flow Specification
FLOWSPEC_FAMILY_IPV4 = FlowSpecIPv4NLRI.FLOWSPEC_FAMILY
FLOWSPEC_FAMILY_IPV6 = FlowSpecIPv6NLRI.FLOWSPEC_FAMILY
FLOWSPEC_FAMILY_VPNV4 = FlowSpecVPNv4NLRI.FLOWSPEC_FAMILY
FLOWSPEC_FAMILY_VPNV6 = FlowSpecVPNv6NLRI.FLOWSPEC_FAMILY
FLOWSPEC_FAMILY_L2VPN = FlowSpecL2VPNNLRI.FLOWSPEC_FAMILY
SUPPORTED_FLOWSPEC_FAMILIES = (
    FLOWSPEC_FAMILY_IPV4,
    FLOWSPEC_FAMILY_IPV6,
    FLOWSPEC_FAMILY_VPNV4,
    FLOWSPEC_FAMILY_VPNV6,
    FLOWSPEC_FAMILY_L2VPN,
)

# Constants for the Traffic Filtering Actions of Flow Specification
# Constants for the Traffic Filtering Actions of Flow Specification.
FLOWSPEC_ACTION_TRAFFIC_RATE = BGPFlowSpecTrafficRateCommunity.ACTION_NAME
FLOWSPEC_ACTION_TRAFFIC_ACTION = BGPFlowSpecTrafficActionCommunity.ACTION_NAME
FLOWSPEC_ACTION_REDIRECT = BGPFlowSpecRedirectCommunity.ACTION_NAME
FLOWSPEC_ACTION_TRAFFIC_MARKING = BGPFlowSpecTrafficMarkingCommunity.ACTION_NAME
FLOWSPEC_ACTION_VLAN = BGPFlowSpecVlanActionCommunity.ACTION_NAME
FLOWSPEC_ACTION_TPID = BGPFlowSpecTPIDActionCommunity.ACTION_NAME

SUPPORTTED_FLOWSPEC_ACTIONS = (
    FLOWSPEC_ACTION_TRAFFIC_RATE,
    FLOWSPEC_ACTION_TRAFFIC_ACTION,
    FLOWSPEC_ACTION_REDIRECT,
    FLOWSPEC_ACTION_TRAFFIC_MARKING,
    FLOWSPEC_ACTION_VLAN,
    FLOWSPEC_ACTION_TPID,
)


# Constants for ESI Label extended community
REDUNDANCY_MODE_ALL_ACTIVE = 'all_active'
REDUNDANCY_MODE_SINGLE_ACTIVE = 'single_active'
SUPPORTED_REDUNDANCY_MODES = [
    REDUNDANCY_MODE_ALL_ACTIVE,
    REDUNDANCY_MODE_SINGLE_ACTIVE,
]

# Constants for BGP Tunnel Encapsulation Attribute
TUNNEL_TYPE_VXLAN = 'vxlan'
TUNNEL_TYPE_NVGRE = 'nvgre'
TUNNEL_TYPE_MPLS = 'mpls'
TUNNEL_TYPE_MPLS_IN_GRE = 'mpls_in_gre'
TUNNEL_TYPE_VXLAN_GRE = 'vxlan_gre'
SUPPORTED_TUNNEL_TYPES = [
    TUNNEL_TYPE_VXLAN,
    TUNNEL_TYPE_NVGRE,
    TUNNEL_TYPE_MPLS,
    TUNNEL_TYPE_MPLS_IN_GRE,
    TUNNEL_TYPE_VXLAN_GRE,
]
# Constants for PMSI Tunnel Attribute
PMSI_TYPE_NO_TUNNEL_INFO = (
    BGPPathAttributePmsiTunnel.TYPE_NO_TUNNEL_INFORMATION_PRESENT
)
PMSI_TYPE_INGRESS_REP = (
    BGPPathAttributePmsiTunnel.TYPE_INGRESS_REPLICATION
)
SUPPORTED_PMSI_TUNNEL_TYPES = [
    PMSI_TYPE_NO_TUNNEL_INFO,
    PMSI_TYPE_INGRESS_REP,
]


@add_bgp_error_metadata(code=PREFIX_ERROR_CODE,
                        sub_code=1,
                        def_desc='Unknown error related to operation on '
                        'prefixes')
class PrefixError(RuntimeConfigError):
    pass


@validate(name=PREFIX)
def is_valid_prefix(prefix):
    if not (validation.is_valid_ipv4_prefix(prefix)
            or validation.is_valid_ipv6_prefix(prefix)):
        raise ConfigValueError(conf_name=PREFIX,
                               conf_value=prefix)


@validate(name=NEXT_HOP)
def is_valid_next_hop(next_hop):
    if not (validation.is_valid_ipv4(next_hop)
            or validation.is_valid_ipv6(next_hop)):
        raise ConfigValueError(conf_name=NEXT_HOP,
                               conf_value=next_hop)


@validate(name=EVPN_ROUTE_TYPE)
def is_valid_evpn_route_type(route_type):
    if route_type not in SUPPORTED_EVPN_ROUTE_TYPES:
        raise ConfigValueError(conf_name=EVPN_ROUTE_TYPE,
                               conf_value=route_type)


@validate(name=EVPN_ESI)
def is_valid_esi(esi):
    if not validation.is_valid_esi(esi):
        raise ConfigValueError(conf_name=EVPN_ESI,
                               conf_value=esi)


@validate(name=EVPN_ETHERNET_TAG_ID)
def is_valid_ethernet_tag_id(ethernet_tag_id):
    if not validation.is_valid_ethernet_tag_id(ethernet_tag_id):
        raise ConfigValueError(conf_name=EVPN_ETHERNET_TAG_ID,
                               conf_value=ethernet_tag_id)


@validate(name=REDUNDANCY_MODE)
def is_valid_redundancy_mode(redundancy_mode):
    if redundancy_mode not in SUPPORTED_REDUNDANCY_MODES:
        raise ConfigValueError(conf_name=REDUNDANCY_MODE,
                               conf_value=redundancy_mode)


@validate(name=MAC_ADDR)
def is_valid_mac_addr(addr):
    if not validation.is_valid_mac(addr):
        raise ConfigValueError(conf_name=MAC_ADDR,
                               conf_value=addr)


@validate(name=IP_ADDR)
def is_valid_ip_addr(addr):
    # Note: Allows empty IP Address (means length=0).
    # e.g.) L2VPN MAC advertisement of Cisco NX-OS
    if not (addr is None
            or validation.is_valid_ipv4(addr)
            or validation.is_valid_ipv6(addr)):
        raise ConfigValueError(conf_name=IP_ADDR,
                               conf_value=addr)


@validate(name=IP_PREFIX)
def is_valid_ip_prefix(prefix):
    if not (validation.is_valid_ipv4_prefix(prefix)
            or validation.is_valid_ipv6_prefix(prefix)):
        raise ConfigValueError(conf_name=IP_PREFIX,
                               conf_value=prefix)


@validate(name=GW_IP_ADDR)
def is_valid_gw_ip_addr(addr):
    if not (validation.is_valid_ipv4(addr)
            or validation.is_valid_ipv6(addr)):
        raise ConfigValueError(conf_name=GW_IP_ADDR,
                               conf_value=addr)


@validate(name=MPLS_LABELS)
def is_valid_mpls_labels(labels):
    if not validation.is_valid_mpls_labels(labels):
        raise ConfigValueError(conf_name=MPLS_LABELS,
                               conf_value=labels)


@validate(name=EVPN_VNI)
def is_valid_vni(vni):
    if not validation.is_valid_vni(vni):
        raise ConfigValueError(conf_name=EVPN_VNI,
                               conf_value=vni)


@validate(name=TUNNEL_TYPE)
def is_valid_tunnel_type(tunnel_type):
    if tunnel_type not in SUPPORTED_TUNNEL_TYPES:
        raise ConfigValueError(conf_name=TUNNEL_TYPE,
                               conf_value=tunnel_type)


@validate(name=PMSI_TUNNEL_TYPE)
def is_valid_pmsi_tunnel_type(pmsi_tunnel_type):
    if pmsi_tunnel_type not in SUPPORTED_PMSI_TUNNEL_TYPES:
        raise ConfigValueError(conf_name=PMSI_TUNNEL_TYPE,
                               conf_value=pmsi_tunnel_type)


@validate(name=FLOWSPEC_FAMILY)
def is_valid_flowspec_family(flowspec_family):
    if flowspec_family not in SUPPORTED_FLOWSPEC_FAMILIES:
        raise ConfigValueError(conf_name=FLOWSPEC_FAMILY,
                               conf_value=flowspec_family)


@validate(name=FLOWSPEC_RULES)
def is_valid_flowspec_rules(rules):
    if not isinstance(rules, dict):
        raise ConfigValueError(conf_name=FLOWSPEC_RULES,
                               conf_value=rules)


@validate(name=FLOWSPEC_ACTIONS)
def is_valid_flowspec_actions(actions):
    for k in actions:
        if k not in SUPPORTTED_FLOWSPEC_ACTIONS:
            raise ConfigValueError(conf_name=FLOWSPEC_ACTIONS,
                                   conf_value=actions)


@RegisterWithArgChecks(name='prefix.add_local',
                       req_args=[ROUTE_DISTINGUISHER, PREFIX, NEXT_HOP],
                       opt_args=[VRF_RF])
def add_local(route_dist, prefix, next_hop, route_family=VRF_RF_IPV4):
    """Adds *prefix* from VRF identified by *route_dist* and sets the source as
    network controller.
    """
    try:
        # Create new path and insert into appropriate VRF table.
        tm = CORE_MANAGER.get_core_service().table_manager
        label = tm.update_vrf_table(route_dist, prefix, next_hop, route_family)
        # Currently we only allocate one label per local_prefix,
        # so we share first label from the list.
        if label:
            label = label[0]

        # Send success response with new label.
        return [{ROUTE_DISTINGUISHER: route_dist, PREFIX: prefix,
                 VRF_RF: route_family, VPN_LABEL: label}]
    except BgpCoreError as e:
        raise PrefixError(desc=e)


@RegisterWithArgChecks(name='prefix.delete_local',
                       req_args=[ROUTE_DISTINGUISHER, PREFIX],
                       opt_args=[VRF_RF])
def delete_local(route_dist, prefix, route_family=VRF_RF_IPV4):
    """Deletes/withdraws *prefix* from VRF identified by *route_dist* and
    source as network controller.
    """
    try:
        tm = CORE_MANAGER.get_core_service().table_manager
        tm.update_vrf_table(route_dist, prefix,
                            route_family=route_family, is_withdraw=True)
        # Send success response.
        return [{ROUTE_DISTINGUISHER: route_dist, PREFIX: prefix,
                 VRF_RF: route_family}]
    except BgpCoreError as e:
        raise PrefixError(desc=e)


# =============================================================================
# BGP EVPN Routes related APIs
# =============================================================================

@RegisterWithArgChecks(name='evpn_prefix.add_local',
                       req_args=[EVPN_ROUTE_TYPE, ROUTE_DISTINGUISHER,
                                 NEXT_HOP],
                       opt_args=[EVPN_ESI, EVPN_ETHERNET_TAG_ID,
                                 REDUNDANCY_MODE, MAC_ADDR, IP_ADDR, IP_PREFIX,
                                 GW_IP_ADDR, EVPN_VNI, TUNNEL_TYPE,
                                 PMSI_TUNNEL_TYPE, TUNNEL_ENDPOINT_IP,
                                 MAC_MOBILITY])
def add_evpn_local(route_type, route_dist, next_hop, **kwargs):
    """Adds EVPN route from VRF identified by *route_dist*.
    """

    if(route_type in [EVPN_ETH_AUTO_DISCOVERY, EVPN_ETH_SEGMENT]
       and kwargs['esi'] == 0):
        raise ConfigValueError(conf_name=EVPN_ESI,
                               conf_value=kwargs['esi'])

    try:
        # Create new path and insert into appropriate VRF table.
        tm = CORE_MANAGER.get_core_service().table_manager
        label = tm.update_vrf_table(route_dist, next_hop=next_hop,
                                    route_family=VRF_RF_L2_EVPN,
                                    route_type=route_type, **kwargs)
        # Currently we only allocate one label per local route,
        # so we share first label from the list.
        if label:
            label = label[0]

        # Send success response with new label.
        return [{EVPN_ROUTE_TYPE: route_type,
                 ROUTE_DISTINGUISHER: route_dist,
                 VRF_RF: VRF_RF_L2_EVPN,
                 VPN_LABEL: label}.update(kwargs)]
    except BgpCoreError as e:
        raise PrefixError(desc=e)


@RegisterWithArgChecks(name='evpn_prefix.delete_local',
                       req_args=[EVPN_ROUTE_TYPE, ROUTE_DISTINGUISHER],
                       opt_args=[EVPN_ESI, EVPN_ETHERNET_TAG_ID, MAC_ADDR,
                                 IP_ADDR, IP_PREFIX, EVPN_VNI])
def delete_evpn_local(route_type, route_dist, **kwargs):
    """Deletes/withdraws EVPN route from VRF identified by *route_dist*.
    """
    try:
        tm = CORE_MANAGER.get_core_service().table_manager
        tm.update_vrf_table(route_dist,
                            route_family=VRF_RF_L2_EVPN,
                            route_type=route_type, is_withdraw=True, **kwargs)
        # Send success response.
        return [{EVPN_ROUTE_TYPE: route_type,
                 ROUTE_DISTINGUISHER: route_dist,
                 VRF_RF: VRF_RF_L2_EVPN}.update(kwargs)]
    except BgpCoreError as e:
        raise PrefixError(desc=e)


# =============================================================================
# BGP Flow Specification Routes related APIs
# =============================================================================

@RegisterWithArgChecks(
    name='flowspec.add_local',
    req_args=[FLOWSPEC_FAMILY, ROUTE_DISTINGUISHER, FLOWSPEC_RULES],
    opt_args=[FLOWSPEC_ACTIONS])
def add_flowspec_local(flowspec_family, route_dist, rules, **kwargs):
    """Adds Flow Specification route from VRF identified by *route_dist*.
    """
    try:
        # Create new path and insert into appropriate VRF table.
        tm = CORE_MANAGER.get_core_service().table_manager
        tm.update_flowspec_vrf_table(
            flowspec_family=flowspec_family, route_dist=route_dist,
            rules=rules, **kwargs)

        # Send success response.
        return [{FLOWSPEC_FAMILY: flowspec_family,
                 ROUTE_DISTINGUISHER: route_dist,
                 FLOWSPEC_RULES: rules}.update(kwargs)]

    except BgpCoreError as e:
        raise PrefixError(desc=e)


@RegisterWithArgChecks(
    name='flowspec.del_local',
    req_args=[FLOWSPEC_FAMILY, ROUTE_DISTINGUISHER, FLOWSPEC_RULES])
def del_flowspec_local(flowspec_family, route_dist, rules):
    """Deletes/withdraws Flow Specification route from VRF identified
    by *route_dist*.
    """
    try:
        tm = CORE_MANAGER.get_core_service().table_manager
        tm.update_flowspec_vrf_table(
            flowspec_family=flowspec_family, route_dist=route_dist,
            rules=rules, is_withdraw=True)

        # Send success response.
        return [{FLOWSPEC_FAMILY: flowspec_family,
                 ROUTE_DISTINGUISHER: route_dist,
                 FLOWSPEC_RULES: rules}]

    except BgpCoreError as e:
        raise PrefixError(desc=e)
