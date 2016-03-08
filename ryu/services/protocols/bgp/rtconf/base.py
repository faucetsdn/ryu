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
 Running or runtime configuration base classes.
"""
from abc import ABCMeta
from abc import abstractmethod
import functools
import numbers
import logging
import six
import uuid

from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.base import get_validator
from ryu.services.protocols.bgp.base import RUNTIME_CONF_ERROR_CODE
from ryu.services.protocols.bgp.base import validate
from ryu.services.protocols.bgp.utils import validation
from ryu.services.protocols.bgp.utils.validation import is_valid_old_asn

LOG = logging.getLogger('bgpspeaker.rtconf.base')

#
# Nested settings.
#
CAP_REFRESH = 'cap_refresh'
CAP_ENHANCED_REFRESH = 'cap_enhanced_refresh'
CAP_MBGP_IPV4 = 'cap_mbgp_ipv4'
CAP_MBGP_IPV6 = 'cap_mbgp_ipv6'
CAP_MBGP_VPNV4 = 'cap_mbgp_vpnv4'
CAP_MBGP_VPNV6 = 'cap_mbgp_vpnv6'
CAP_RTC = 'cap_rtc'
RTC_AS = 'rtc_as'
HOLD_TIME = 'hold_time'

# To control how many prefixes can be received from a neighbor.
# 0 value indicates no limit and other related options will be ignored.
# Current behavior is to log that limit has reached.
MAX_PREFIXES = 'max_prefixes'

# Has same meaning as: http://www.juniper.net/techpubs/software/junos/junos94
# /swconfig-routing/disabling-suppression-of-route-
# advertisements.html#id-13255463
ADVERTISE_PEER_AS = 'advertise_peer_as'

# MED - MULTI_EXIT_DISC
MULTI_EXIT_DISC = 'multi_exit_disc'

# Extended community attribute route origin.
SITE_OF_ORIGINS = 'site_of_origins'

# Constants related to errors.
CONF_NAME = 'conf_name'
CONF_VALUE = 'conf_value'

# Max. value  limits
MAX_NUM_IMPORT_RT = 1000
MAX_NUM_EXPORT_RT = 250
MAX_NUM_SOO = 10


# =============================================================================
# Runtime configuration errors or exceptions.
# =============================================================================

@add_bgp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=1,
                        def_desc='Error with runtime-configuration.')
class RuntimeConfigError(BGPSException):
    """Base class for all runtime configuration errors.
    """
    pass


@add_bgp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=2,
                        def_desc='Missing required configuration.')
class MissingRequiredConf(RuntimeConfigError):
    """Exception raised when trying to configure with missing required
    settings.
    """
    def __init__(self, **kwargs):
        conf_name = kwargs.get('conf_name')
        if conf_name:
            super(MissingRequiredConf, self).__init__(
                desc='Missing required configuration: %s' % conf_name)
        else:
            super(MissingRequiredConf, self).__init__(desc=kwargs.get('desc'))


@add_bgp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=3,
                        def_desc='Incorrect Type for configuration.')
class ConfigTypeError(RuntimeConfigError):
    """Exception raised when configuration value type miss-match happens.
    """
    def __init__(self, **kwargs):
        conf_name = kwargs.get(CONF_NAME)
        conf_value = kwargs.get(CONF_VALUE)
        if conf_name and conf_value:
            super(ConfigTypeError, self).__init__(
                desc='Incorrect Type %s for configuration: %s' %
                (conf_value, conf_name))
        elif conf_name:
            super(ConfigTypeError, self).__init__(
                desc='Incorrect Type for configuration: %s' % conf_name)
        else:
            super(ConfigTypeError, self).__init__(desc=kwargs.get('desc'))


@add_bgp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=4,
                        def_desc='Incorrect Value for configuration.')
class ConfigValueError(RuntimeConfigError):
    """Exception raised when configuration value is of correct type but
    incorrect value.
    """
    def __init__(self, **kwargs):
        conf_name = kwargs.get(CONF_NAME)
        conf_value = kwargs.get(CONF_VALUE)
        if conf_name and conf_value:
            super(ConfigValueError, self).__init__(
                desc='Incorrect Value %s for configuration: %s' %
                (conf_value, conf_name))
        elif conf_name:
            super(ConfigValueError, self).__init__(
                desc='Incorrect Value for configuration: %s' % conf_name)
        else:
            super(ConfigValueError, self).__init__(desc=kwargs.get('desc'))


# =============================================================================
# Configuration base classes.
# =============================================================================

class BaseConf(object):
    """Base class for a set of configuration values.

    Configurations can be required or optional. Also acts as a container of
    configuration change listeners.
    """
    __metaclass__ = ABCMeta

    def __init__(self, **kwargs):
        self._req_settings = self.get_req_settings()
        self._opt_settings = self.get_opt_settings()
        self._valid_evts = self.get_valid_evts()
        self._listeners = {}
        self._settings = {}

        # validate required and unknown settings
        self._validate_req_unknown_settings(**kwargs)

        # Initialize configuration settings.
        self._init_req_settings(**kwargs)
        self._init_opt_settings(**kwargs)

    @property
    def settings(self):
        """Returns a copy of current settings."""
        return self._settings.copy()

    @classmethod
    def get_valid_evts(self):
        return set()

    @classmethod
    def get_req_settings(self):
        return set()

    @classmethod
    def get_opt_settings(self):
        return set()

    @abstractmethod
    def _init_opt_settings(self, **kwargs):
        """Sub-classes should override this method to initialize optional
         settings.
        """
        pass

    @abstractmethod
    def update(self, **kwargs):
        # Validate given values
        self._validate_req_unknown_settings(**kwargs)

    def _validate_req_unknown_settings(self, **kwargs):
        """Checks if required settings are present.

        Also checks if unknown requirements are present.
        """
        # Validate given configuration.
        self._all_attrs = (self._req_settings | self._opt_settings)
        if not kwargs and len(self._req_settings) > 0:
            raise MissingRequiredConf(desc='Missing all required attributes.')

        given_attrs = frozenset(kwargs.keys())
        unknown_attrs = given_attrs - self._all_attrs
        if unknown_attrs:
            raise RuntimeConfigError(desc=(
                'Unknown attributes: %s' %
                ', '.join([str(i) for i in unknown_attrs]))
            )
        missing_req_settings = self._req_settings - given_attrs
        if missing_req_settings:
            raise MissingRequiredConf(conf_name=list(missing_req_settings))

    def _init_req_settings(self, **kwargs):
        for req_attr in self._req_settings:
            req_attr_value = kwargs.get(req_attr)
            if req_attr_value is None:
                raise MissingRequiredConf(conf_name=req_attr_value)
            # Validate attribute value
            req_attr_value = get_validator(req_attr)(req_attr_value)
            self._settings[req_attr] = req_attr_value

    def add_listener(self, evt, callback):
        #   if (evt not in self.get_valid_evts()):
        #       raise RuntimeConfigError(desc=('Unknown event %s' % evt))

        listeners = self._listeners.get(evt, None)
        if not listeners:
            listeners = set()
            self._listeners[evt] = listeners
        listeners.update([callback])

    def remove_listener(self, evt, callback):
        if evt in self.get_valid_evts():
            listeners = self._listeners.get(evt, None)
            if listeners and (callback in listeners):
                listeners.remove(callback)
                return True

        return False

    def _notify_listeners(self, evt, value):
        listeners = self._listeners.get(evt, [])
        for callback in listeners:
            callback(ConfEvent(self, evt, value))

    def __repr__(self):
        return '%s(%r)' % (self.__class__, self._settings)


class ConfWithId(BaseConf):
    """Configuration settings related to identity."""
    # Config./resource identifier.
    ID = 'id'
    # Config./resource name.
    NAME = 'name'
    # Config./resource description.
    DESCRIPTION = 'description'

    UPDATE_NAME_EVT = 'update_name_evt'
    UPDATE_DESCRIPTION_EVT = 'update_description_evt'

    VALID_EVT = frozenset([UPDATE_NAME_EVT, UPDATE_DESCRIPTION_EVT])
    OPTIONAL_SETTINGS = frozenset([ID, NAME, DESCRIPTION])

    def __init__(self, **kwargs):
        super(ConfWithId, self).__init__(**kwargs)

    @classmethod
    def get_opt_settings(cls):
        self_confs = super(ConfWithId, cls).get_opt_settings()
        self_confs.update(ConfWithId.OPTIONAL_SETTINGS)
        return self_confs

    @classmethod
    def get_req_settings(cls):
        self_confs = super(ConfWithId, cls).get_req_settings()
        return self_confs

    @classmethod
    def get_valid_evts(cls):
        self_valid_evts = super(ConfWithId, cls).get_valid_evts()
        self_valid_evts.update(ConfWithId.VALID_EVT)
        return self_valid_evts

    def _init_opt_settings(self, **kwargs):
        super(ConfWithId, self)._init_opt_settings(**kwargs)
        self._settings[ConfWithId.ID] = \
            compute_optional_conf(ConfWithId.ID, str(uuid.uuid4()), **kwargs)
        self._settings[ConfWithId.NAME] = \
            compute_optional_conf(ConfWithId.NAME, str(self), **kwargs)
        self._settings[ConfWithId.DESCRIPTION] = \
            compute_optional_conf(ConfWithId.DESCRIPTION, str(self), **kwargs)

    @property
    def id(self):
        return self._settings[ConfWithId.ID]

    @property
    def name(self):
        return self._settings[ConfWithId.NAME]

    @name.setter
    def name(self, new_name):
        old_name = self.name
        if not new_name:
            new_name = repr(self)
        else:
            get_validator(ConfWithId.NAME)(new_name)

        if old_name != new_name:
            self._settings[ConfWithId.NAME] = new_name
            self._notify_listeners(ConfWithId.UPDATE_NAME_EVT,
                                   (old_name, self.name))

    @property
    def description(self):
        return self._settings[ConfWithId.DESCRIPTION]

    @description.setter
    def description(self, new_description):
        old_desc = self.description
        if not new_description:
            new_description = str(self)
        else:
            get_validator(ConfWithId.DESCRIPTION)(new_description)

        if old_desc != new_description:
            self._settings[ConfWithId.DESCRIPTION] = new_description
            self._notify_listeners(ConfWithId.UPDATE_DESCRIPTION_EVT,
                                   (old_desc, self.description))

    def update(self, **kwargs):
        # Update inherited configurations
        super(ConfWithId, self).update(**kwargs)
        self.name = compute_optional_conf(ConfWithId.NAME,
                                          str(self),
                                          **kwargs)
        self.description = compute_optional_conf(ConfWithId.DESCRIPTION,
                                                 str(self),
                                                 **kwargs)


class ConfWithStats(BaseConf):
    """Configuration settings related to statistics collection."""

    # Enable or disable statistics logging.
    STATS_LOG_ENABLED = 'statistics_log_enabled'
    DEFAULT_STATS_LOG_ENABLED = False

    # Statistics logging time.
    STATS_TIME = 'statistics_interval'
    DEFAULT_STATS_TIME = 60

    UPDATE_STATS_LOG_ENABLED_EVT = 'update_stats_log_enabled_evt'
    UPDATE_STATS_TIME_EVT = 'update_stats_time_evt'

    VALID_EVT = frozenset([UPDATE_STATS_LOG_ENABLED_EVT,
                           UPDATE_STATS_TIME_EVT])
    OPTIONAL_SETTINGS = frozenset([STATS_LOG_ENABLED, STATS_TIME])

    def __init__(self, **kwargs):
        super(ConfWithStats, self).__init__(**kwargs)

    def _init_opt_settings(self, **kwargs):
        super(ConfWithStats, self)._init_opt_settings(**kwargs)
        self._settings[ConfWithStats.STATS_LOG_ENABLED] = \
            compute_optional_conf(ConfWithStats.STATS_LOG_ENABLED,
                                  ConfWithStats.DEFAULT_STATS_LOG_ENABLED,
                                  **kwargs)
        self._settings[ConfWithStats.STATS_TIME] = \
            compute_optional_conf(ConfWithStats.STATS_TIME,
                                  ConfWithStats.DEFAULT_STATS_TIME,
                                  **kwargs)

    @property
    def stats_log_enabled(self):
        return self._settings[ConfWithStats.STATS_LOG_ENABLED]

    @stats_log_enabled.setter
    def stats_log_enabled(self, enabled):
        get_validator(ConfWithStats.STATS_LOG_ENABLED)(enabled)
        if enabled != self.stats_log_enabled:
            self._settings[ConfWithStats.STATS_LOG_ENABLED] = enabled
            self._notify_listeners(ConfWithStats.UPDATE_STATS_LOG_ENABLED_EVT,
                                   enabled)

    @property
    def stats_time(self):
        return self._settings[ConfWithStats.STATS_TIME]

    @stats_time.setter
    def stats_time(self, stats_time):
        get_validator(ConfWithStats.STATS_TIME)(stats_time)
        if stats_time != self.stats_time:
            self._settings[ConfWithStats.STATS_TIME] = stats_time
            self._notify_listeners(ConfWithStats.UPDATE_STATS_TIME_EVT,
                                   stats_time)

    @classmethod
    def get_opt_settings(cls):
        confs = super(ConfWithStats, cls).get_opt_settings()
        confs.update(ConfWithStats.OPTIONAL_SETTINGS)
        return confs

    @classmethod
    def get_valid_evts(cls):
        valid_evts = super(ConfWithStats, cls).get_valid_evts()
        valid_evts.update(ConfWithStats.VALID_EVT)
        return valid_evts

    def update(self, **kwargs):
        # Update inherited configurations
        super(ConfWithStats, self).update(**kwargs)
        self.stats_log_enabled = \
            compute_optional_conf(ConfWithStats.STATS_LOG_ENABLED,
                                  ConfWithStats.DEFAULT_STATS_LOG_ENABLED,
                                  **kwargs)
        self.stats_time = \
            compute_optional_conf(ConfWithStats.STATS_TIME,
                                  ConfWithStats.DEFAULT_STATS_TIME,
                                  **kwargs)


class BaseConfListener(object):
    """Base class of all configuration listeners."""
    __metaclass__ = ABCMeta

    def __init__(self, base_conf):
        pass
    # TODO(PH): re-vist later and check if we need this check
#         if not isinstance(base_conf, BaseConf):
#             raise TypeError('Currently we only support listening to '
#                             'instances of BaseConf')


class ConfWithIdListener(BaseConfListener):

    def __init__(self, conf_with_id):
        assert conf_with_id
        super(ConfWithIdListener, self).__init__(conf_with_id)
        conf_with_id.add_listener(ConfWithId.UPDATE_NAME_EVT,
                                  self.on_chg_name_conf_with_id)
        conf_with_id.add_listener(ConfWithId.UPDATE_DESCRIPTION_EVT,
                                  self.on_chg_desc_conf_with_id)

    def on_chg_name_conf_with_id(self, conf_evt):
        # Note did not makes this method abstract as this is not important
        # event.
        raise NotImplementedError()

    def on_chg_desc_conf_with_id(self, conf_evt):
        # Note did not makes this method abstract as this is not important
        # event.
        raise NotImplementedError()


class ConfWithStatsListener(BaseConfListener):

    def __init__(self, conf_with_stats):
        assert conf_with_stats
        super(ConfWithStatsListener, self).__init__(conf_with_stats)
        conf_with_stats.add_listener(
            ConfWithStats.UPDATE_STATS_LOG_ENABLED_EVT,
            self.on_chg_stats_enabled_conf_with_stats)

        conf_with_stats.add_listener(ConfWithStats.UPDATE_STATS_TIME_EVT,
                                     self.on_chg_stats_time_conf_with_stats)

    @abstractmethod
    def on_chg_stats_time_conf_with_stats(self, conf_evt):
        raise NotImplementedError()

    @abstractmethod
    def on_chg_stats_enabled_conf_with_stats(self, conf_evt):
        raise NotImplementedError()


@functools.total_ordering
class ConfEvent(object):
    """Encapsulates configuration settings change/update event."""

    def __init__(self, evt_src, evt_name, evt_value):
        """Creates an instance using given parameters.

        Parameters:
            -`evt_src`: (BaseConf) source of the event
            -`evt_name`: (str) name of event, has to be one of the valid
            event of `evt_src`
            - `evt_value`: (tuple) event context that helps event handler
        """
        if evt_name not in evt_src.get_valid_evts():
            raise ValueError('Event %s is not a valid event for type %s.' %
                             (evt_name, type(evt_src)))
        self._src = evt_src
        self._name = evt_name
        self._value = evt_value

    @property
    def src(self):
        return self._src

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return '<ConfEvent(%s, %s, %s)>' % (self.src, self.name, self.value)

    def __str__(self):
        return ('ConfEvent(src=%s, name=%s, value=%s)' %
                (self.src, self.name, self.value))

    def __lt__(self, other):
        return ((self.src, self.name, self.value) <
                (other.src, other.name, other.value))

    def __eq__(self, other):
        return ((self.src, self.name, self.value) ==
                (other.src, other.name, other.value))


# =============================================================================
# Runtime configuration setting validators and their registry.
# =============================================================================

@validate(name=ConfWithId.ID)
def validate_conf_id(identifier):
    if not isinstance(identifier, str):
        raise ConfigTypeError(conf_name=ConfWithId.ID, conf_value=identifier)
    if len(identifier) > 128:
        raise ConfigValueError(conf_name=ConfWithId.ID, conf_value=identifier)
    return identifier


@validate(name=ConfWithId.NAME)
def validate_conf_name(name):
    if not isinstance(name, str):
        raise ConfigTypeError(conf_name=ConfWithId.NAME, conf_value=name)
    if len(name) > 128:
        raise ConfigValueError(conf_name=ConfWithId.NAME, conf_value=name)
    return name


@validate(name=ConfWithId.DESCRIPTION)
def validate_conf_desc(description):
    if not isinstance(description, str):
        raise ConfigTypeError(conf_name=ConfWithId.DESCRIPTION,
                              conf_value=description)
    return description


@validate(name=ConfWithStats.STATS_LOG_ENABLED)
def validate_stats_log_enabled(stats_log_enabled):
    if stats_log_enabled not in (True, False):
        raise ConfigTypeError(desc='Statistics log enabled settings can only'
                              ' be boolean type.')
    return stats_log_enabled


@validate(name=ConfWithStats.STATS_TIME)
def validate_stats_time(stats_time):
    if not isinstance(stats_time, numbers.Integral):
        raise ConfigTypeError(desc='Statistics log timer value has to be of '
                              'integral type but got: %r' % stats_time)
    if stats_time < 10:
        raise ConfigValueError(desc='Statistics log timer cannot be set to '
                               'less then 10 sec, given timer value %s.' %
                               stats_time)
    return stats_time


@validate(name=CAP_REFRESH)
def validate_cap_refresh(crefresh):
    if crefresh not in (True, False):
        raise ConfigTypeError(desc='Invalid Refresh capability settings: %s '
                              ' boolean value expected' % crefresh)
    return crefresh


@validate(name=CAP_ENHANCED_REFRESH)
def validate_cap_enhanced_refresh(cer):
    if cer not in (True, False):
        raise ConfigTypeError(desc='Invalid Enhanced Refresh capability '
                              'settings: %s boolean value expected' % cer)
    return cer


@validate(name=CAP_MBGP_IPV4)
def validate_cap_mbgp_ipv4(cmv4):
    if cmv4 not in (True, False):
        raise ConfigTypeError(desc='Invalid Enhanced Refresh capability '
                              'settings: %s boolean value expected' % cmv4)

    return cmv4


@validate(name=CAP_MBGP_IPV6)
def validate_cap_mbgp_ipv6(cmv6):
    if cmv6 not in (True, False):
        raise ConfigTypeError(desc='Invalid Enhanced Refresh capability '
                              'settings: %s boolean value expected' % cmv6)

    return cmv6


@validate(name=CAP_MBGP_VPNV4)
def validate_cap_mbgp_vpnv4(cmv4):
    if cmv4 not in (True, False):
        raise ConfigTypeError(desc='Invalid Enhanced Refresh capability '
                              'settings: %s boolean value expected' % cmv4)

    return cmv4


@validate(name=CAP_MBGP_VPNV6)
def validate_cap_mbgp_vpnv6(cmv6):
    if cmv6 not in (True, False):
        raise ConfigTypeError(desc='Invalid Enhanced Refresh capability '
                              'settings: %s boolean value expected' % cmv6)

    return cmv6


@validate(name=CAP_RTC)
def validate_cap_rtc(cap_rtc):
    if cap_rtc not in (True, False):
        raise ConfigTypeError(desc='Invalid type for specifying RTC '
                              'capability. Expected boolean got: %s' %
                              type(cap_rtc))
    return cap_rtc


@validate(name=RTC_AS)
def validate_cap_rtc_as(rtc_as):
    if not is_valid_old_asn(rtc_as):
        raise ConfigValueError(desc='Invalid RTC AS configuration value: %s'
                               % rtc_as)
    return rtc_as


@validate(name=HOLD_TIME)
def validate_hold_time(hold_time):
    if ((hold_time is None) or (not isinstance(hold_time, int)) or
            hold_time < 10):
        raise ConfigValueError(desc='Invalid hold_time configuration value %s'
                               % hold_time)

    return hold_time


@validate(name=MULTI_EXIT_DISC)
def validate_med(med):
    if med is not None and not validation.is_valid_med(med):
        raise ConfigValueError(desc='Invalid multi-exit-discriminatory (med)'
                               ' value: %s.' % med)
    return med


@validate(name=SITE_OF_ORIGINS)
def validate_soo_list(soo_list):
    if not isinstance(soo_list, list):
        raise ConfigTypeError(conf_name=SITE_OF_ORIGINS, conf_value=soo_list)
    if not (len(soo_list) <= MAX_NUM_SOO):
        raise ConfigValueError(desc='Max. SOO is limited to %s' %
                               MAX_NUM_SOO)
    if not all(validation.is_valid_ext_comm_attr(attr) for attr in soo_list):
        raise ConfigValueError(conf_name=SITE_OF_ORIGINS,
                               conf_value=soo_list)
    # Check if we have duplicates
    unique_rts = set(soo_list)
    if len(unique_rts) != len(soo_list):
        raise ConfigValueError(desc='Duplicate value provided in %s' %
                               (soo_list))
    return soo_list


@validate(name=MAX_PREFIXES)
def validate_max_prefixes(max_prefixes):
    if not isinstance(max_prefixes, six.integer_types):
        raise ConfigTypeError(desc='Max. prefixes value should be of type '
                              'int or long but found %s' % type(max_prefixes))
    if max_prefixes < 0:
        raise ConfigValueError(desc='Invalid max. prefixes value: %s' %
                               max_prefixes)
    return max_prefixes


@validate(name=ADVERTISE_PEER_AS)
def validate_advertise_peer_as(advertise_peer_as):
    if not isinstance(advertise_peer_as, bool):
        raise ConfigTypeError(desc='Invalid type for advertise-peer-as, '
                              'expected bool got %s' %
                              type(advertise_peer_as))
    return advertise_peer_as


# =============================================================================
# Other utils.
# =============================================================================

def compute_optional_conf(conf_name, default_value, **all_config):
    """Returns *conf_name* settings if provided in *all_config*, else returns
     *default_value*.

    Validates *conf_name* value if provided.
    """
    conf_value = all_config.get(conf_name)
    if conf_value is not None:
        # Validate configuration value.
        conf_value = get_validator(conf_name)(conf_value)
    else:
        conf_value = default_value
    return conf_value
