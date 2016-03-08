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
 Running or runtime configuration related to bgp peers/neighbors.
"""
from abc import abstractmethod
import logging
import netaddr
import numbers

from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import BGPOptParamCapabilityEnhancedRouteRefresh
from ryu.lib.packet.bgp import BGPOptParamCapabilityMultiprotocol
from ryu.lib.packet.bgp import BGPOptParamCapabilityRouteRefresh
from ryu.lib.packet.bgp import BGP_CAP_ENHANCED_ROUTE_REFRESH
from ryu.lib.packet.bgp import BGP_CAP_MULTIPROTOCOL
from ryu.lib.packet.bgp import BGP_CAP_ROUTE_REFRESH

from ryu.services.protocols.bgp.base import OrderedDict
from ryu.services.protocols.bgp.rtconf.base import ADVERTISE_PEER_AS
from ryu.services.protocols.bgp.rtconf.base import BaseConf
from ryu.services.protocols.bgp.rtconf.base import BaseConfListener
from ryu.services.protocols.bgp.rtconf.base import CAP_ENHANCED_REFRESH
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV6
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.rtconf.base import CAP_REFRESH
from ryu.services.protocols.bgp.rtconf.base import CAP_RTC
from ryu.services.protocols.bgp.rtconf.base import compute_optional_conf
from ryu.services.protocols.bgp.rtconf.base import ConfigTypeError
from ryu.services.protocols.bgp.rtconf.base import ConfigValueError
from ryu.services.protocols.bgp.rtconf.base import ConfWithId
from ryu.services.protocols.bgp.rtconf.base import ConfWithIdListener
from ryu.services.protocols.bgp.rtconf.base import ConfWithStats
from ryu.services.protocols.bgp.rtconf.base import ConfWithStatsListener
from ryu.services.protocols.bgp.rtconf.base import HOLD_TIME
from ryu.services.protocols.bgp.rtconf.base import MAX_PREFIXES
from ryu.services.protocols.bgp.rtconf.base import MULTI_EXIT_DISC
from ryu.services.protocols.bgp.rtconf.base import RTC_AS
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.base import SITE_OF_ORIGINS
from ryu.services.protocols.bgp.rtconf.base import validate
from ryu.services.protocols.bgp.rtconf.base import validate_med
from ryu.services.protocols.bgp.rtconf.base import validate_soo_list
from ryu.services.protocols.bgp.utils.validation import is_valid_old_asn
from ryu.services.protocols.bgp.info_base.base import Filter
from ryu.services.protocols.bgp.info_base.base import PrefixFilter
from ryu.services.protocols.bgp.info_base.base import AttributeMap

LOG = logging.getLogger('bgpspeaker.rtconf.neighbor')

# Various neighbor settings.
REMOTE_AS = 'remote_as'
IP_ADDRESS = 'ip_address'
ENABLED = 'enabled'
CHANGES = 'changes'
LOCAL_ADDRESS = 'local_address'
LOCAL_PORT = 'local_port'
PEER_NEXT_HOP = 'peer_next_hop'
PASSWORD = 'password'
IN_FILTER = 'in_filter'
OUT_FILTER = 'out_filter'
IS_ROUTE_SERVER_CLIENT = 'is_route_server_client'
CHECK_FIRST_AS = 'check_first_as'
ATTRIBUTE_MAP = 'attribute_map'
IS_NEXT_HOP_SELF = 'is_next_hop_self'
CONNECT_MODE = 'connect_mode'
CONNECT_MODE_ACTIVE = 'active'
CONNECT_MODE_PASSIVE = 'passive'
CONNECT_MODE_BOTH = 'both'

# Default value constants.
DEFAULT_CAP_GR_NULL = True
DEFAULT_CAP_REFRESH = True
DEFAULT_CAP_ENHANCED_REFRESH = False
DEFAULT_CAP_MBGP_IPV4 = True
DEFAULT_CAP_MBGP_IPV6 = False
DEFAULT_CAP_MBGP_VPNV4 = False
DEFAULT_CAP_MBGP_VPNV6 = False
DEFAULT_HOLD_TIME = 40
DEFAULT_ENABLED = True
DEFAULT_CAP_RTC = False
DEFAULT_IN_FILTER = []
DEFAULT_OUT_FILTER = []
DEFAULT_IS_ROUTE_SERVER_CLIENT = False
DEFAULT_CHECK_FIRST_AS = False
DEFAULT_IS_NEXT_HOP_SELF = False
DEFAULT_CONNECT_MODE = CONNECT_MODE_BOTH

# Default value for *MAX_PREFIXES* setting is set to 0.
DEFAULT_MAX_PREFIXES = 0
DEFAULT_ADVERTISE_PEER_AS = False


@validate(name=ENABLED)
def validate_enabled(enabled):
    if not isinstance(enabled, bool):
        raise ConfigValueError(desc='Enable property is not an instance of '
                               'boolean')
    return enabled


@validate(name=CHANGES)
def validate_changes(changes):
    for k, v in changes.items():
        if k not in (MULTI_EXIT_DISC, ENABLED, CONNECT_MODE):
            raise ConfigValueError(desc="Unknown field to change: %s" % k)

        if k == MULTI_EXIT_DISC:
            validate_med(v)
        elif k == ENABLED:
            validate_enabled(v)
        elif k == CONNECT_MODE:
            validate_connect_mode(v)
    return changes


def valid_ip_address(addr):
    if not netaddr.valid_ipv4(addr) and not netaddr.valid_ipv6(addr):
        return False
    return True


@validate(name=IP_ADDRESS)
def validate_ip_address(ip_address):
    if not valid_ip_address(ip_address):
        raise ConfigValueError(desc='Invalid neighbor ip_address: %s' %
                               ip_address)
    return str(netaddr.IPAddress(ip_address))


@validate(name=LOCAL_ADDRESS)
def validate_local_address(ip_address):
    if not valid_ip_address(ip_address):
        raise ConfigValueError(desc='Invalid local ip_address: %s' %
                               ip_address)
    return str(netaddr.IPAddress(ip_address))


@validate(name=PEER_NEXT_HOP)
def validate_next_hop(ip_address):
    if not valid_ip_address(ip_address):
        raise ConfigValueError(desc='Invalid next_hop ip_address: %s' %
                               ip_address)
    return str(netaddr.IPAddress(ip_address))


@validate(name=PASSWORD)
def validate_password(password):
    return password


@validate(name=LOCAL_PORT)
def validate_local_port(port):
    if not isinstance(port, numbers.Integral):
        raise ConfigTypeError(desc='Invalid local port: %s' % port)
    if port < 1025 or port > 65535:
        raise ConfigValueError(desc='Invalid local port value: %s, has to be'
                               ' between 1025 and 65535' % port)
    return port


@validate(name=REMOTE_AS)
def validate_remote_as(asn):
    if not is_valid_old_asn(asn):
        raise ConfigValueError(desc='Invalid remote as value %s' % asn)
    return asn


def valid_prefix_filter(filter_):
    policy = filter_.get('policy', None)
    if policy == 'permit':
        policy = PrefixFilter.POLICY_PERMIT
    else:
        policy = PrefixFilter.POLICY_DENY
    prefix = filter_['prefix']
    ge = filter_.get('ge', None)
    le = filter_.get('le', None)
    return PrefixFilter(prefix, policy, ge=ge, le=le)

PREFIX_FILTER = 'prefix_filter'

SUPPORTED_FILTER_VALIDATORS = {
    PREFIX_FILTER: valid_prefix_filter
}


def valid_filter(filter_):
    if isinstance(filter_, Filter):
        return filter_

    if not isinstance(filter_, dict):
        raise ConfigTypeError(desc='Invalid filter: %s' % filter_)

    if 'type' not in filter_:
        raise ConfigTypeError(desc='Invalid filter: %s, needs \'type\' field'
                              % filter_)

    if not filter_['type'] in SUPPORTED_FILTER_VALIDATORS:
        raise ConfigTypeError(desc='Invalid filter type: %s, supported filter'
                              ' types are %s'
                              % (filter_['type'],
                                 list(SUPPORTED_FILTER_VALIDATORS.keys())))

    return SUPPORTED_FILTER_VALIDATORS[filter_['type']](filter_)


def valid_attribute_map(attribute_map):
    if not isinstance(attribute_map, AttributeMap):
        raise ConfigTypeError(desc='Invalid AttributeMap: %s' % attribute_map)
    else:
        return attribute_map


@validate(name=IN_FILTER)
def validate_in_filters(filters):
    return [valid_filter(filter_) for filter_ in filters]


@validate(name=OUT_FILTER)
def validate_out_filters(filters):
    return [valid_filter(filter_) for filter_ in filters]


@validate(name=ATTRIBUTE_MAP)
def validate_attribute_maps(attribute_maps):
    return [valid_attribute_map(attribute_map)
            for attribute_map in attribute_maps]


@validate(name=IS_ROUTE_SERVER_CLIENT)
def validate_is_route_server_client(is_route_server_client):
    if is_route_server_client not in (True, False):
        raise ConfigValueError(desc='Invalid is_route_server_client(%s)' %
                               is_route_server_client)

    return is_route_server_client


@validate(name=CHECK_FIRST_AS)
def validate_check_first_as(check_first_as):
    if check_first_as not in (True, False):
        raise ConfigValueError(desc='Invalid check_first_as(%s)' %
                               check_first_as)

    return check_first_as


@validate(name=IS_NEXT_HOP_SELF)
def validate_is_next_hop_self(is_next_hop_self):
    if is_next_hop_self not in (True, False):
        raise ConfigValueError(desc='Invalid is_next_hop_self(%s)' %
                               is_next_hop_self)

    return is_next_hop_self


@validate(name=CONNECT_MODE)
def validate_connect_mode(mode):
    if mode not in (CONNECT_MODE_ACTIVE,
                    CONNECT_MODE_PASSIVE,
                    CONNECT_MODE_BOTH):
        raise ConfigValueError(desc='Invalid connect_mode(%s)' % mode)
    return mode


class NeighborConf(ConfWithId, ConfWithStats):
    """Class that encapsulates one neighbors' configuration."""

    UPDATE_ENABLED_EVT = 'update_enabled_evt'
    UPDATE_MED_EVT = 'update_med_evt'
    UPDATE_CONNECT_MODE_EVT = 'update_connect_mode_evt'

    VALID_EVT = frozenset([UPDATE_ENABLED_EVT, UPDATE_MED_EVT,
                           UPDATE_CONNECT_MODE_EVT])
    REQUIRED_SETTINGS = frozenset([REMOTE_AS, IP_ADDRESS])
    OPTIONAL_SETTINGS = frozenset([CAP_REFRESH,
                                   CAP_ENHANCED_REFRESH,
                                   CAP_MBGP_IPV4, CAP_MBGP_IPV6,
                                   CAP_MBGP_VPNV4, CAP_MBGP_VPNV6,
                                   CAP_RTC, RTC_AS, HOLD_TIME,
                                   ENABLED, MULTI_EXIT_DISC, MAX_PREFIXES,
                                   ADVERTISE_PEER_AS, SITE_OF_ORIGINS,
                                   LOCAL_ADDRESS, LOCAL_PORT,
                                   PEER_NEXT_HOP, PASSWORD,
                                   IN_FILTER, OUT_FILTER,
                                   IS_ROUTE_SERVER_CLIENT, CHECK_FIRST_AS,
                                   IS_NEXT_HOP_SELF, CONNECT_MODE])

    def __init__(self, **kwargs):
        super(NeighborConf, self).__init__(**kwargs)

    def _init_opt_settings(self, **kwargs):
        self._settings[CAP_REFRESH] = compute_optional_conf(
            CAP_REFRESH, DEFAULT_CAP_REFRESH, **kwargs)
        self._settings[CAP_ENHANCED_REFRESH] = compute_optional_conf(
            CAP_ENHANCED_REFRESH, DEFAULT_CAP_ENHANCED_REFRESH, **kwargs)
        self._settings[CAP_MBGP_IPV4] = compute_optional_conf(
            CAP_MBGP_IPV4, DEFAULT_CAP_MBGP_IPV4, **kwargs)
        self._settings[CAP_MBGP_IPV6] = compute_optional_conf(
            CAP_MBGP_IPV6, DEFAULT_CAP_MBGP_IPV6, **kwargs)
        self._settings[CAP_MBGP_VPNV4] = compute_optional_conf(
            CAP_MBGP_VPNV4, DEFAULT_CAP_MBGP_VPNV4, **kwargs)
        self._settings[CAP_MBGP_VPNV6] = compute_optional_conf(
            CAP_MBGP_VPNV6, DEFAULT_CAP_MBGP_VPNV6, **kwargs)
        self._settings[HOLD_TIME] = compute_optional_conf(
            HOLD_TIME, DEFAULT_HOLD_TIME, **kwargs)
        self._settings[ENABLED] = compute_optional_conf(
            ENABLED, DEFAULT_ENABLED, **kwargs)
        self._settings[MAX_PREFIXES] = compute_optional_conf(
            MAX_PREFIXES, DEFAULT_MAX_PREFIXES, **kwargs)
        self._settings[ADVERTISE_PEER_AS] = compute_optional_conf(
            ADVERTISE_PEER_AS, DEFAULT_ADVERTISE_PEER_AS, **kwargs)
        self._settings[IN_FILTER] = compute_optional_conf(
            IN_FILTER, DEFAULT_IN_FILTER, **kwargs)
        self._settings[OUT_FILTER] = compute_optional_conf(
            OUT_FILTER, DEFAULT_OUT_FILTER, **kwargs)
        self._settings[IS_ROUTE_SERVER_CLIENT] = compute_optional_conf(
            IS_ROUTE_SERVER_CLIENT,
            DEFAULT_IS_ROUTE_SERVER_CLIENT, **kwargs)
        self._settings[CHECK_FIRST_AS] = compute_optional_conf(
            CHECK_FIRST_AS, DEFAULT_CHECK_FIRST_AS, **kwargs)
        self._settings[IS_NEXT_HOP_SELF] = compute_optional_conf(
            IS_NEXT_HOP_SELF,
            DEFAULT_IS_NEXT_HOP_SELF, **kwargs)
        self._settings[CONNECT_MODE] = compute_optional_conf(
            CONNECT_MODE, DEFAULT_CONNECT_MODE, **kwargs)

        # We do not have valid default MED value.
        # If no MED attribute is provided then we do not have to use MED.
        # If MED attribute is provided we have to validate it and use it.
        med = kwargs.pop(MULTI_EXIT_DISC, None)
        if med and validate_med(med):
            self._settings[MULTI_EXIT_DISC] = med

        # We do not have valid default SOO value.
        # If no SOO attribute is provided then we do not have to use SOO.
        # If SOO attribute is provided we have to validate it and use it.
        soos = kwargs.pop(SITE_OF_ORIGINS, None)
        if soos and validate_soo_list(soos):
            self._settings[SITE_OF_ORIGINS] = soos

        # We do not have valid default LOCAL_ADDRESS and LOCAL_PORT value.
        # If no LOCAL_ADDRESS/PORT is provided then we will bind to system
        # default.
        self._settings[LOCAL_ADDRESS] = compute_optional_conf(
            LOCAL_ADDRESS, None, **kwargs)
        self._settings[LOCAL_PORT] = compute_optional_conf(
            LOCAL_PORT, None, **kwargs)

        self._settings[PEER_NEXT_HOP] = compute_optional_conf(
            PEER_NEXT_HOP, None, **kwargs)

        self._settings[PASSWORD] = compute_optional_conf(
            PASSWORD, None, **kwargs)

        # RTC configurations.
        self._settings[CAP_RTC] = \
            compute_optional_conf(CAP_RTC, DEFAULT_CAP_RTC, **kwargs)
        # Default RTC_AS is local (router) AS.
        from ryu.services.protocols.bgp.core_manager import \
            CORE_MANAGER
        default_rt_as = CORE_MANAGER.common_conf.local_as
        self._settings[RTC_AS] = \
            compute_optional_conf(RTC_AS, default_rt_as, **kwargs)

        # Since ConfWithId' default values use str(self) and repr(self), we
        # call super method after we have initialized other settings.
        super(NeighborConf, self)._init_opt_settings(**kwargs)

    @classmethod
    def get_opt_settings(cls):
        self_confs = super(NeighborConf, cls).get_opt_settings()
        self_confs.update(NeighborConf.OPTIONAL_SETTINGS)
        return self_confs

    @classmethod
    def get_req_settings(cls):
        self_confs = super(NeighborConf, cls).get_req_settings()
        self_confs.update(NeighborConf.REQUIRED_SETTINGS)
        return self_confs

    @classmethod
    def get_valid_evts(cls):
        self_valid_evts = super(NeighborConf, cls).get_valid_evts()
        self_valid_evts.update(NeighborConf.VALID_EVT)
        return self_valid_evts

    # =========================================================================
    # Required attributes
    # =========================================================================

    @property
    def remote_as(self):
        return self._settings[REMOTE_AS]

    @property
    def ip_address(self):
        return self._settings[IP_ADDRESS]

    @property
    def host_bind_ip(self):
        return self._settings[LOCAL_ADDRESS]

    @property
    def host_bind_port(self):
        return self._settings[LOCAL_PORT]

    @property
    def next_hop(self):
        return self._settings[PEER_NEXT_HOP]

    @property
    def password(self):
        return self._settings[PASSWORD]

    # =========================================================================
    # Optional attributes with valid defaults.
    # =========================================================================

    @property
    def hold_time(self):
        return self._settings[HOLD_TIME]

    @property
    def cap_refresh(self):
        return self._settings[CAP_REFRESH]

    @property
    def cap_enhanced_refresh(self):
        return self._settings[CAP_ENHANCED_REFRESH]

    @property
    def cap_mbgp_ipv4(self):
        return self._settings[CAP_MBGP_IPV4]

    @property
    def cap_mbgp_ipv6(self):
        return self._settings[CAP_MBGP_IPV6]

    @property
    def cap_mbgp_vpnv4(self):
        return self._settings[CAP_MBGP_VPNV4]

    @property
    def cap_mbgp_vpnv6(self):
        return self._settings[CAP_MBGP_VPNV6]

    @property
    def cap_rtc(self):
        return self._settings[CAP_RTC]

    @property
    def enabled(self):
        return self._settings[ENABLED]

    @enabled.setter
    def enabled(self, enable):
        # Update enabled flag and notify listeners.
        if self._settings[ENABLED] != enable:
            self._settings[ENABLED] = enable
            self._notify_listeners(NeighborConf.UPDATE_ENABLED_EVT,
                                   enable)

    # =========================================================================
    # Optional attributes with no valid defaults.
    # =========================================================================

    @property
    def multi_exit_disc(self):
        # This property does not have any valid default. Hence if not set we
        # return None.
        return self._settings.get(MULTI_EXIT_DISC)

    @multi_exit_disc.setter
    def multi_exit_disc(self, value):
        if self._settings.get(MULTI_EXIT_DISC) != value:
            self._settings[MULTI_EXIT_DISC] = value
            self._notify_listeners(NeighborConf.UPDATE_MED_EVT, value)

    @property
    def soo_list(self):
        soos = self._settings.get(SITE_OF_ORIGINS)
        if soos:
            soos = list(soos)
        else:
            soos = []
        return soos

    @property
    def rtc_as(self):
        return self._settings[RTC_AS]

    @property
    def in_filter(self):
        return self._settings[IN_FILTER]

    @property
    def out_filter(self):
        return self._settings[OUT_FILTER]

    @property
    def is_route_server_client(self):
        return self._settings[IS_ROUTE_SERVER_CLIENT]

    @property
    def check_first_as(self):
        return self._settings[CHECK_FIRST_AS]

    @property
    def is_next_hop_self(self):
        return self._settings[IS_NEXT_HOP_SELF]

    @property
    def connect_mode(self):
        return self._settings[CONNECT_MODE]

    @connect_mode.setter
    def connect_mode(self, mode):
        self._settings[CONNECT_MODE] = mode
        self._notify_listeners(NeighborConf.UPDATE_CONNECT_MODE_EVT, mode)

    def exceeds_max_prefix_allowed(self, prefix_count):
        allowed_max = self._settings[MAX_PREFIXES]
        does_exceed = False
        # Check if allowed max. is unlimited.
        if allowed_max != 0:
            # If max. prefix is limited, check if given exceeds this limit.
            if prefix_count > allowed_max:
                does_exceed = True

        return does_exceed

    def get_configured_capabilites(self):
        """Returns configured capabilities."""

        capabilities = OrderedDict()
        mbgp_caps = []
        if self.cap_mbgp_ipv4:
            mbgp_caps.append(
                BGPOptParamCapabilityMultiprotocol(
                    RF_IPv4_UC.afi, RF_IPv4_UC.safi))

        if self.cap_mbgp_ipv6:
            mbgp_caps.append(
                BGPOptParamCapabilityMultiprotocol(
                    RF_IPv6_UC.afi, RF_IPv6_UC.safi))

        if self.cap_mbgp_vpnv4:
            mbgp_caps.append(
                BGPOptParamCapabilityMultiprotocol(
                    RF_IPv4_VPN.afi, RF_IPv4_VPN.safi))

        if self.cap_mbgp_vpnv6:
            mbgp_caps.append(
                BGPOptParamCapabilityMultiprotocol(
                    RF_IPv6_VPN.afi, RF_IPv6_VPN.safi))

        if self.cap_rtc:
            mbgp_caps.append(
                BGPOptParamCapabilityMultiprotocol(
                    RF_RTC_UC.afi, RF_RTC_UC.safi))

        if mbgp_caps:
            capabilities[BGP_CAP_MULTIPROTOCOL] = mbgp_caps

        if self.cap_refresh:
            capabilities[BGP_CAP_ROUTE_REFRESH] = [
                BGPOptParamCapabilityRouteRefresh()]

        if self.cap_enhanced_refresh:
            capabilities[BGP_CAP_ENHANCED_ROUTE_REFRESH] = [
                BGPOptParamCapabilityEnhancedRouteRefresh()]

        return capabilities

    def __repr__(self):
        return '<%s(%r, %r, %r)>' % (self.__class__.__name__,
                                     self.remote_as,
                                     self.ip_address,
                                     self.enabled)

    def __str__(self):
        return 'Neighbor: %s' % (self.ip_address)


class NeighborsConf(BaseConf):
    """Container of all neighbor configurations."""

    ADD_NEIGH_CONF_EVT = 'add_neigh_conf_evt'
    REMOVE_NEIGH_CONF_EVT = 'remove_neigh_conf_evt'

    VALID_EVT = frozenset([ADD_NEIGH_CONF_EVT, REMOVE_NEIGH_CONF_EVT])

    def __init__(self):
        super(NeighborsConf, self).__init__()
        self._neighbors = {}

    def _init_opt_settings(self, **kwargs):
        pass

    def update(self, **kwargs):
        raise NotImplementedError('Use either add/remove_neighbor_conf'
                                  ' methods instead.')

    @property
    def rtc_as_set(self):
        """Returns current RTC AS configured for current neighbors.
        """
        rtc_as_set = set()
        for neigh in self._neighbors.values():
            rtc_as_set.add(neigh.rtc_as)
        return rtc_as_set

    @classmethod
    def get_valid_evts(cls):
        self_valid_evts = super(NeighborsConf, cls).get_valid_evts()
        self_valid_evts.update(NeighborsConf.VALID_EVT)
        return self_valid_evts

    def add_neighbor_conf(self, neigh_conf):
        # Check if we already know this neighbor
        if neigh_conf.ip_address in self._neighbors.keys():
            message = 'Neighbor with given ip address already exists'
            raise RuntimeConfigError(desc=message)

        # Add this neighbor to known configured neighbors and generate update
        # event
        self._neighbors[neigh_conf.ip_address] = neigh_conf
        self._notify_listeners(NeighborsConf.ADD_NEIGH_CONF_EVT, neigh_conf)

    def remove_neighbor_conf(self, neigh_ip_address):
        neigh_conf = self._neighbors.pop(neigh_ip_address, None)
        if not neigh_conf:
            raise RuntimeConfigError(desc='Tried to remove a neighbor that '
                                     'does not exists')
        else:
            self._notify_listeners(NeighborsConf.REMOVE_NEIGH_CONF_EVT,
                                   neigh_conf)
        return neigh_conf

    def get_neighbor_conf(self, neigh_ip_address):
        return self._neighbors.get(neigh_ip_address, None)

    def __repr__(self):
        return '<%s(%r)>' % (self.__class__.__name__, self._neighbors)

    def __str__(self):
        return '\'Neighbors\': %s' % self._neighbors

    @property
    def settings(self):
        return [neighbor.settings for _, neighbor in
                self._neighbors.items()]


class NeighborConfListener(ConfWithIdListener, ConfWithStatsListener):
    """Base listener for change events to a specific neighbors' configurations.
    """
    def __init__(self, neigh_conf):
        super(NeighborConfListener, self).__init__(neigh_conf)
        neigh_conf.add_listener(NeighborConf.UPDATE_ENABLED_EVT,
                                self.on_update_enabled)
        neigh_conf.add_listener(NeighborConf.UPDATE_MED_EVT,
                                self.on_update_med)
        neigh_conf.add_listener(NeighborConf.UPDATE_CONNECT_MODE_EVT,
                                self.on_update_connect_mode)

    @abstractmethod
    def on_update_enabled(self, evt):
        raise NotImplementedError('This method should be overridden.')

    @abstractmethod
    def on_update_med(self, evt):
        raise NotImplementedError('This method should be overridden.')

    @abstractmethod
    def on_update_connect_mode(self, evt):
        raise NotImplementedError('This method should be overridden.')


class NeighborsConfListener(BaseConfListener):
    """Base listener for change events to neighbor configuration container."""

    def __init__(self, neighbors_conf):
        super(NeighborsConfListener, self).__init__(neighbors_conf)
        neighbors_conf.add_listener(NeighborsConf.ADD_NEIGH_CONF_EVT,
                                    self.on_add_neighbor_conf)
        neighbors_conf.add_listener(NeighborsConf.REMOVE_NEIGH_CONF_EVT,
                                    self.on_remove_neighbor_conf)

    @abstractmethod
    def on_add_neighbor_conf(self, evt):
        raise NotImplementedError('This method should be overridden.')

    @abstractmethod
    def on_remove_neighbor_conf(self, evt):
        raise NotImplementedError('This method should be overridden.')
