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
 Runtime configuration manager.
"""
import logging

from ryu.services.protocols.bgp.api.base import register
from ryu.services.protocols.bgp.api.base import RegisterWithArgChecks
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.rtconf.base import ConfWithId
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf import neighbors
from ryu.services.protocols.bgp.rtconf.neighbors import NeighborConf
from ryu.services.protocols.bgp.rtconf.vrfs import ROUTE_DISTINGUISHER
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4
from ryu.services.protocols.bgp.rtconf.vrfs import VrfConf
from ryu.services.protocols.bgp import constants as const

LOG = logging.getLogger('bgpspeaker.api.rtconf')


# =============================================================================
# Neighbor configuration related APIs
# =============================================================================


def _get_neighbor_conf(neigh_ip_address):
    """Returns neighbor configuration for given neighbor ip address.

    Raises exception if no neighbor with `neigh_ip_address` exists.
    """
    neigh_conf = \
        CORE_MANAGER.neighbors_conf.get_neighbor_conf(neigh_ip_address)
    if not neigh_conf:
        raise RuntimeConfigError(desc='No Neighbor configuration with IP'
                                 ' address %s' % neigh_ip_address)
    assert isinstance(neigh_conf, NeighborConf)
    return neigh_conf


@register(name='neighbor.create')
def create_neighbor(**kwargs):
    neigh_conf = NeighborConf(**kwargs)
    CORE_MANAGER.neighbors_conf.add_neighbor_conf(neigh_conf)
    return True


@RegisterWithArgChecks(name='neighbor.update_enabled',
                       req_args=[neighbors.IP_ADDRESS, neighbors.ENABLED])
def update_neighbor_enabled(neigh_ip_address, enabled):
    neigh_conf = _get_neighbor_conf(neigh_ip_address)
    neigh_conf.enabled = enabled
    return True


@RegisterWithArgChecks(name='neighbor.update',
                       req_args=[neighbors.IP_ADDRESS, neighbors.CHANGES])
def update_neighbor(neigh_ip_address, changes):
    rets = []
    for k, v in changes.items():
        if k == neighbors.MULTI_EXIT_DISC:
            rets.append(_update_med(neigh_ip_address, v))

        if k == neighbors.ENABLED:
            rets.append(update_neighbor_enabled(neigh_ip_address, v))

        if k == neighbors.CONNECT_MODE:
            rets.append(_update_connect_mode(neigh_ip_address, v))

    return all(rets)


def _update_med(neigh_ip_address, value):
    neigh_conf = _get_neighbor_conf(neigh_ip_address)
    neigh_conf.multi_exit_disc = value
    LOG.info('MED value for neigh: %s updated to %s', neigh_conf, value)
    return True


def _update_connect_mode(neigh_ip_address, value):
    neigh_conf = _get_neighbor_conf(neigh_ip_address)
    neigh_conf.connect_mode = value
    return True


@RegisterWithArgChecks(name='neighbor.delete',
                       req_args=[neighbors.IP_ADDRESS])
def delete_neighbor(neigh_ip_address):
    neigh_conf = _get_neighbor_conf(neigh_ip_address)
    if neigh_conf:
        neigh_conf.enabled = False
        CORE_MANAGER.neighbors_conf.remove_neighbor_conf(neigh_ip_address)
        return True
    return False


@RegisterWithArgChecks(name='neighbor.get',
                       req_args=[neighbors.IP_ADDRESS])
def get_neighbor_conf(neigh_ip_address):
    """Returns a neighbor configuration for given ip address if exists."""
    neigh_conf = _get_neighbor_conf(neigh_ip_address)
    return neigh_conf.settings


@register(name='neighbors.get')
def get_neighbors_conf():
    return CORE_MANAGER.neighbors_conf.settings


@RegisterWithArgChecks(name='neighbor.in_filter.get',
                       req_args=[neighbors.IP_ADDRESS])
def get_neighbor_in_filter(neigh_ip_address):
    """Returns a neighbor in_filter for given ip address if exists."""
    core = CORE_MANAGER.get_core_service()
    peer = core.peer_manager.get_by_addr(neigh_ip_address)
    return peer.in_filters


@RegisterWithArgChecks(name='neighbor.in_filter.set',
                       req_args=[neighbors.IP_ADDRESS, neighbors.IN_FILTER])
def set_neighbor_in_filter(neigh_ip_address, filters):
    """Returns a neighbor in_filter for given ip address if exists."""
    core = CORE_MANAGER.get_core_service()
    peer = core.peer_manager.get_by_addr(neigh_ip_address)
    peer.in_filters = filters
    return True


@RegisterWithArgChecks(name='neighbor.out_filter.get',
                       req_args=[neighbors.IP_ADDRESS])
def get_neighbor_out_filter(neigh_ip_address):
    """Returns a neighbor out_filter for given ip address if exists."""
    core = CORE_MANAGER.get_core_service()
    ret = core.peer_manager.get_by_addr(neigh_ip_address).out_filters
    return ret


@RegisterWithArgChecks(name='neighbor.out_filter.set',
                       req_args=[neighbors.IP_ADDRESS, neighbors.OUT_FILTER])
def set_neighbor_out_filter(neigh_ip_address, filters):
    """Sets the out_filter of a neighbor."""
    core = CORE_MANAGER.get_core_service()
    peer = core.peer_manager.get_by_addr(neigh_ip_address)
    peer.out_filters = filters
    return True


@RegisterWithArgChecks(name='neighbor.attribute_map.set',
                       req_args=[neighbors.IP_ADDRESS,
                                 neighbors.ATTRIBUTE_MAP],
                       opt_args=[ROUTE_DISTINGUISHER, VRF_RF])
def set_neighbor_attribute_map(neigh_ip_address, at_maps,
                               route_dist=None, route_family=VRF_RF_IPV4):
    """set attribute_maps to the neighbor."""
    core = CORE_MANAGER.get_core_service()
    peer = core.peer_manager.get_by_addr(neigh_ip_address)

    at_maps_key = const.ATTR_MAPS_LABEL_DEFAULT
    at_maps_dict = {}

    if route_dist is not None:
        vrf_conf =\
            CORE_MANAGER.vrfs_conf.get_vrf_conf(route_dist, route_family)
        if vrf_conf:
            at_maps_key = ':'.join([route_dist, route_family])
        else:
            raise RuntimeConfigError(desc='No VrfConf with rd %s' %
                                          route_dist)

    at_maps_dict[const.ATTR_MAPS_LABEL_KEY] = at_maps_key
    at_maps_dict[const.ATTR_MAPS_VALUE] = at_maps
    peer.attribute_maps = at_maps_dict

    return True


@RegisterWithArgChecks(name='neighbor.attribute_map.get',
                       req_args=[neighbors.IP_ADDRESS],
                       opt_args=[ROUTE_DISTINGUISHER, VRF_RF])
def get_neighbor_attribute_map(neigh_ip_address, route_dist=None,
                               route_family=VRF_RF_IPV4):
    """Returns a neighbor attribute_map for given ip address if exists."""
    core = CORE_MANAGER.get_core_service()
    peer = core.peer_manager.get_by_addr(neigh_ip_address)
    at_maps_key = const.ATTR_MAPS_LABEL_DEFAULT

    if route_dist is not None:
        at_maps_key = ':'.join([route_dist, route_family])
    at_maps = peer.attribute_maps.get(at_maps_key)
    if at_maps:
        return at_maps.get(const.ATTR_MAPS_ORG_KEY)
    else:
        return []

# =============================================================================
# VRF configuration related APIs
# =============================================================================


@register(name='vrf.create')
def create_vrf(**kwargs):
    vrf_conf = VrfConf(**kwargs)
    CORE_MANAGER.vrfs_conf.add_vrf_conf(vrf_conf)
    return True


@register(name='vrf.update')
def update_vrf(**kwargs):
    route_dist = kwargs.get(ROUTE_DISTINGUISHER)
    vrf_id = kwargs.get(ConfWithId.ID)
    vrf_rf = kwargs.get(VRF_RF)
    vrf_conf = CORE_MANAGER.vrfs_conf.get_vrf_conf(
        route_dist, vrf_rf, vrf_id=vrf_id
    )

    # If we do not have a VrfConf with given id, we create one.
    if not vrf_conf:
        create_vrf(**kwargs)
    else:
        vrf_conf.update(**kwargs)
    return True


@RegisterWithArgChecks(name='vrf.delete', req_args=[ROUTE_DISTINGUISHER])
def delete_vrf(route_dist):
    vrf_conf = CORE_MANAGER.vrfs_conf.remove_vrf_conf(route_dist)
    if vrf_conf:
        return True

    return False


@RegisterWithArgChecks(
    name='vrf.get',
    req_args=[ROUTE_DISTINGUISHER],
    opt_args=[VRF_RF])
def get_vrf(route_dist, route_family=VRF_RF_IPV4):
    vrf_conf = CORE_MANAGER.vrfs_conf.get_vrf_conf(
        route_dist, vrf_rf=route_family
    )
    if not vrf_conf:
        raise RuntimeConfigError(desc='No VrfConf with vpn id %s' %
                                 route_dist)
    return vrf_conf.settings


@register(name='vrfs.get')
def get_vrfs_conf():
    vrfs_conf = CORE_MANAGER.vrfs_conf
    return vrfs_conf.settings

# =============================================================================
# network configuration related APIs
# =============================================================================


@register(name='network.add')
def add_network(prefix, next_hop=None):
    tm = CORE_MANAGER.get_core_service().table_manager
    tm.add_to_global_table(prefix, next_hop)
    return True


@register(name='network.del')
def del_network(prefix):
    tm = CORE_MANAGER.get_core_service().table_manager
    tm.add_to_global_table(prefix, is_withdraw=True)
    return True

# =============================================================================
# BMP configuration related APIs
# =============================================================================


@register(name='bmp.start')
def bmp_start(host, port):
    core = CORE_MANAGER.get_core_service()
    return core.start_bmp(host, port)


@register(name='bmp.stop')
def bmp_stop(host, port):
    core = CORE_MANAGER.get_core_service()
    return core.stop_bmp(host, port)
