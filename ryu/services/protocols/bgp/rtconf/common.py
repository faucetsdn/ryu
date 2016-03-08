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
 Runtime configuration that applies to all bgp sessions, i.e. global settings.
"""
import logging
import numbers

from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.utils.validation import is_valid_old_asn

from ryu.services.protocols.bgp import rtconf
from ryu.services.protocols.bgp.rtconf.base import BaseConf
from ryu.services.protocols.bgp.rtconf.base import BaseConfListener
from ryu.services.protocols.bgp.rtconf.base import compute_optional_conf
from ryu.services.protocols.bgp.rtconf.base import ConfigTypeError
from ryu.services.protocols.bgp.rtconf.base import ConfigValueError
from ryu.services.protocols.bgp.rtconf.base import MissingRequiredConf
from ryu.services.protocols.bgp.rtconf.base import validate

LOG = logging.getLogger('bgpspeaker.rtconf.common')


# Global configuration settings.
LOCAL_AS = 'local_as'
ROUTER_ID = 'router_id'
LABEL_RANGE = 'label_range'
LABEL_RANGE_MAX = 'max'
LABEL_RANGE_MIN = 'min'

# Configuration that can be set at global level as well as per context
# (session/vrf) level
# Nested configuration override global or higher level configuration as they
# are more granular.
# TODO(apgw-dev) Nested configuration overriding higher level configuration is
# currently low priority

# Similar to Cisco command 'bgp refresh stalepath-time'. To cause the router to
# remove stale routes from the BGP table even if the router does not receive a
# Route-Refresh EOR message The bgp refresh stalepath-time command is not
# needed under normal circumstances.
# TODO(PH): Support this feature (currently low priority)
REFRESH_STALEPATH_TIME = 'refresh_stalepath_time'

# Similar to Cisco command 'bgp refresh max-eor-time'. The bgp refresh max-eor-
# time command is not needed under normal  circumstances. You might configure
# the bgp refresh max-eor-time command in the event of continuous route
# flapping, when the router is unable to generate a Route- Refresh EOR message,
# in which case a Route-Refresh EOR is generated after the timer expires.
# TODO(PH): Support this feature (currently low priority)
REFRESH_MAX_EOR_TIME = 'refresh_max_eor_time'

BGP_CONN_RETRY_TIME = 'bgp_conn_retry_time'
BGP_SERVER_PORT = 'bgp_server_port'
TCP_CONN_TIMEOUT = 'tcp_conn_timeout'
MAX_PATH_EXT_RTFILTER_ALL = 'maximum_paths_external_rtfilter_all'


# Valid default values of some settings.
DEFAULT_LABEL_RANGE = (100, 100000)
DEFAULT_REFRESH_STALEPATH_TIME = 0
DEFAULT_REFRESH_MAX_EOR_TIME = 0
DEFAULT_BGP_SERVER_PORT = 179
DEFAULT_TCP_CONN_TIMEOUT = 30
DEFAULT_BGP_CONN_RETRY_TIME = 30
DEFAULT_MED = 0
DEFAULT_MAX_PATH_EXT_RTFILTER_ALL = True


@validate(name=LOCAL_AS)
def validate_local_as(asn):
    if asn is None:
        raise MissingRequiredConf(conf_name=LOCAL_AS)

    if not is_valid_old_asn(asn):
        raise ConfigValueError(desc='Invalid local_as configuration value: %s'
                               % asn)
    return asn


@validate(name=ROUTER_ID)
def validate_router_id(router_id):
    if not router_id:
        raise MissingRequiredConf(conf_name=ROUTER_ID)

    if not isinstance(router_id, str):
        raise ConfigTypeError(conf_name=ROUTER_ID)
    if not is_valid_ipv4(router_id):
        raise ConfigValueError(desc='Invalid router id %s' % router_id)

    return router_id


@validate(name=REFRESH_STALEPATH_TIME)
def validate_refresh_stalepath_time(rst):
    if not isinstance(rst, numbers.Integral):
        raise ConfigTypeError(desc=('Configuration value for %s has to be '
                                    'integral type' % REFRESH_STALEPATH_TIME))
    if rst < 0:
        raise ConfigValueError(desc='Invalid refresh stalepath time %s' % rst)

    return rst


@validate(name=REFRESH_MAX_EOR_TIME)
def validate_refresh_max_eor_time(rmet):
    if not isinstance(rmet, numbers.Integral):
        raise ConfigTypeError(desc=('Configuration value for %s has to be of '
                                    'integral type ' % REFRESH_MAX_EOR_TIME))
    if rmet < 0:
        raise ConfigValueError(desc='Invalid refresh stalepath time %s' % rmet)

    return rmet


@validate(name=LABEL_RANGE)
def validate_label_range(label_range):
    min_label, max_label = label_range
    if (not min_label or
            not max_label or
            not isinstance(min_label, numbers.Integral) or
            not isinstance(max_label, numbers.Integral) or min_label < 17 or
            min_label >= max_label):
        raise ConfigValueError(desc=('Invalid label_range configuration value:'
                                     ' (%s).' % label_range))

    return label_range


@validate(name=BGP_SERVER_PORT)
def validate_bgp_server_port(server_port):
    if not isinstance(server_port, numbers.Integral):
        raise ConfigTypeError(desc=('Invalid bgp sever port configuration '
                                    'value %s' % server_port))
    if server_port < 0 or server_port > 65535:
        raise ConfigValueError(desc='Invalid server port %s' % server_port)

    return server_port


@validate(name=TCP_CONN_TIMEOUT)
def validate_tcp_conn_timeout(tcp_conn_timeout):
    # TODO(apgw-dev) made-up some valid values for this settings, check if we
    # have a standard value in any routers
    if not isinstance(tcp_conn_timeout, numbers.Integral):
        raise ConfigTypeError(desc=('Invalid tcp connection timeout '
                                    'configuration value %s' %
                                    tcp_conn_timeout))

    if tcp_conn_timeout < 10:
        raise ConfigValueError(desc=('Invalid tcp connection timeout'
                                     ' configuration value %s' %
                                     tcp_conn_timeout))

    return tcp_conn_timeout


@validate(name=BGP_CONN_RETRY_TIME)
def validate_bgp_conn_retry_time(bgp_conn_retry_time):
    if not isinstance(bgp_conn_retry_time, numbers.Integral):
        raise ConfigTypeError(desc=('Invalid bgp conn. retry time '
                                    'configuration value %s' %
                                    bgp_conn_retry_time))

    if bgp_conn_retry_time < 10:
        raise ConfigValueError(desc=('Invalid bgp connection retry time'
                                     ' configuration value %s' %
                                     bgp_conn_retry_time))
    return bgp_conn_retry_time


@validate(name=MAX_PATH_EXT_RTFILTER_ALL)
def validate_max_path_ext_rtfilter_all(max_path_ext_rtfilter_all):
    if max_path_ext_rtfilter_all not in (True, False):
        raise ConfigTypeError(desc=('Invalid max_path_ext_rtfilter_all'
                                    ' configuration value %s' %
                                    max_path_ext_rtfilter_all))
    return max_path_ext_rtfilter_all


class CommonConf(BaseConf):
    """Encapsulates configurations applicable to all peer sessions.

    Currently if any of these configurations change, it is assumed that current
    active peer session will be bought down and restarted.
    """
    CONF_CHANGED_EVT = 1

    VALID_EVT = frozenset([CONF_CHANGED_EVT])

    REQUIRED_SETTINGS = frozenset([ROUTER_ID, LOCAL_AS])

    OPTIONAL_SETTINGS = frozenset([REFRESH_STALEPATH_TIME,
                                   REFRESH_MAX_EOR_TIME,
                                   LABEL_RANGE, BGP_SERVER_PORT,
                                   TCP_CONN_TIMEOUT,
                                   BGP_CONN_RETRY_TIME,
                                   MAX_PATH_EXT_RTFILTER_ALL])

    def __init__(self, **kwargs):
        super(CommonConf, self).__init__(**kwargs)

    def _init_opt_settings(self, **kwargs):
        super(CommonConf, self)._init_opt_settings(**kwargs)
        self._settings[LABEL_RANGE] = compute_optional_conf(
            LABEL_RANGE, DEFAULT_LABEL_RANGE, **kwargs)
        self._settings[REFRESH_STALEPATH_TIME] = compute_optional_conf(
            REFRESH_STALEPATH_TIME, DEFAULT_REFRESH_STALEPATH_TIME, **kwargs)
        self._settings[REFRESH_MAX_EOR_TIME] = compute_optional_conf(
            REFRESH_MAX_EOR_TIME, DEFAULT_REFRESH_MAX_EOR_TIME, **kwargs)
        self._settings[BGP_SERVER_PORT] = compute_optional_conf(
            BGP_SERVER_PORT, DEFAULT_BGP_SERVER_PORT, **kwargs)
        self._settings[TCP_CONN_TIMEOUT] = compute_optional_conf(
            TCP_CONN_TIMEOUT, DEFAULT_TCP_CONN_TIMEOUT, **kwargs)
        self._settings[BGP_CONN_RETRY_TIME] = compute_optional_conf(
            BGP_CONN_RETRY_TIME, DEFAULT_BGP_CONN_RETRY_TIME, **kwargs)
        self._settings[MAX_PATH_EXT_RTFILTER_ALL] = compute_optional_conf(
            MAX_PATH_EXT_RTFILTER_ALL, DEFAULT_MAX_PATH_EXT_RTFILTER_ALL,
            **kwargs)

    # =========================================================================
    # Required attributes
    # =========================================================================

    @property
    def local_as(self):
        return self._settings[LOCAL_AS]

    @property
    def router_id(self):
        return self._settings[ROUTER_ID]

    # =========================================================================
    # Optional attributes with valid defaults.
    # =========================================================================

    @property
    def bgp_conn_retry_time(self):
        return self._settings[BGP_CONN_RETRY_TIME]

    @property
    def tcp_conn_timeout(self):
        return self._settings[TCP_CONN_TIMEOUT]

    @property
    def refresh_stalepath_time(self):
        return self._settings[REFRESH_STALEPATH_TIME]

    @property
    def refresh_max_eor_time(self):
        return self._settings[REFRESH_MAX_EOR_TIME]

    @property
    def label_range(self):
        return self._settings[LABEL_RANGE]

    @property
    def bgp_server_port(self):
        return self._settings[BGP_SERVER_PORT]

    @property
    def max_path_ext_rtfilter_all(self):
        return self._settings[MAX_PATH_EXT_RTFILTER_ALL]

    @classmethod
    def get_opt_settings(self):
        self_confs = super(CommonConf, self).get_opt_settings()
        self_confs.update(CommonConf.OPTIONAL_SETTINGS)
        return self_confs

    @classmethod
    def get_req_settings(self):
        self_confs = super(CommonConf, self).get_req_settings()
        self_confs.update(CommonConf.REQUIRED_SETTINGS)
        return self_confs

    @classmethod
    def get_valid_evts(self):
        self_valid_evts = super(CommonConf, self).get_valid_evts()
        self_valid_evts.update(CommonConf.VALID_EVT)
        return self_valid_evts

    def update(self, **kwargs):
        """Updates global configuration settings with given values.

        First checks if given configuration values differ from current values.
        If any of the configuration values changed, generates a change event.
        Currently we generate change event for any configuration change.
        Note: This method is idempotent.
        """
        # Update inherited configurations
        super(CommonConf, self).update(**kwargs)
        conf_changed = False

        # Validate given configurations and check if value changed
        for conf_name, conf_value in kwargs.items():
            rtconf.base.get_validator(conf_name)(conf_value)
            item1 = self._settings.get(conf_name, None)
            item2 = kwargs.get(conf_name, None)

            if item1 != item2:
                conf_changed = True

        # If any configuration changed, we update configuration value and
        # notify listeners
        if conf_changed:
            for conf_name, conf_value in kwargs.items():
                # Since all new values are already validated, we can use them
                self._settings[conf_name] = conf_value

            self._notify_listeners(CommonConf.CONF_CHANGED_EVT, self)


class CommonConfListener(BaseConfListener):
    """Base listener for various changes to common configurations."""

    def __init__(self, global_conf):
        super(CommonConfListener, self).__init__(global_conf)
        global_conf.add_listener(CommonConf.CONF_CHANGED_EVT,
                                 self.on_update_common_conf)

    def on_update_common_conf(self, evt):
        raise NotImplementedError('This method should be overridden.')
