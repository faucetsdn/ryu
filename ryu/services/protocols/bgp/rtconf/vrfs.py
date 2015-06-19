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
 Running or runtime configuration related to Virtual Routing and Forwarding
 tables (VRFs).
"""
import abc
import logging

from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import BGPPathAttributeExtendedCommunities

from ryu.services.protocols.bgp.utils import validation
from ryu.services.protocols.bgp.base import get_validator
from ryu.services.protocols.bgp.rtconf.base import BaseConf
from ryu.services.protocols.bgp.rtconf.base import BaseConfListener
from ryu.services.protocols.bgp.rtconf.base import ConfigTypeError
from ryu.services.protocols.bgp.rtconf.base import ConfigValueError
from ryu.services.protocols.bgp.rtconf.base import ConfWithId
from ryu.services.protocols.bgp.rtconf.base import ConfWithIdListener
from ryu.services.protocols.bgp.rtconf.base import ConfWithStats
from ryu.services.protocols.bgp.rtconf.base import ConfWithStatsListener
from ryu.services.protocols.bgp.rtconf.base import MAX_NUM_EXPORT_RT
from ryu.services.protocols.bgp.rtconf.base import MAX_NUM_IMPORT_RT
from ryu.services.protocols.bgp.rtconf.base import MULTI_EXIT_DISC
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.base import SITE_OF_ORIGINS
from ryu.services.protocols.bgp.rtconf.base import validate
from ryu.services.protocols.bgp.rtconf.base import validate_med
from ryu.services.protocols.bgp.rtconf.base import validate_soo_list


LOG = logging.getLogger('bgpspeaker.rtconf.vrfs')

# Configuration setting names.
ROUTE_DISTINGUISHER = 'route_dist'
IMPORT_RTS = 'import_rts'
EXPORT_RTS = 'export_rts'
VRF_NAME = 'vrf_name'
VRF_DESC = 'vrf_desc'
VRF_RF = 'route_family'
IMPORT_MAPS = 'import_maps'

# Two supported VRF route-families
VRF_RF_IPV6 = 'ipv6'
VRF_RF_IPV4 = 'ipv4'
SUPPORTED_VRF_RF = (VRF_RF_IPV4, VRF_RF_IPV6)


# Default configuration values.
DEFAULT_VRF_NAME = 'no-vrf-name'
DEFAULT_VRF_DESC = 'no-vrf-desc'


@validate(name=IMPORT_RTS)
def validate_import_rts(import_rts):
    if not isinstance(import_rts, list):
        raise ConfigTypeError(conf_name=IMPORT_RTS, conf_value=import_rts)
    if not (len(import_rts) <= MAX_NUM_IMPORT_RT):
        raise ConfigValueError(desc='Max. import RT is limited to %s' %
                               MAX_NUM_IMPORT_RT)
    if not all(validation.is_valid_ext_comm_attr(rt) for rt in import_rts):
        raise ConfigValueError(conf_name=IMPORT_RTS, conf_value=import_rts)
    # Check if we have duplicates
    unique_rts = set(import_rts)
    if len(unique_rts) != len(import_rts):
        raise ConfigValueError(desc='Duplicate value provided %s' %
                               (import_rts))

    return import_rts


@validate(name=EXPORT_RTS)
def validate_export_rts(export_rts):
    if not isinstance(export_rts, list):
        raise ConfigTypeError(conf_name=EXPORT_RTS, conf_value=export_rts)
    if not (len(export_rts) <= MAX_NUM_EXPORT_RT):
        raise ConfigValueError(desc='Max. import RT is limited to %s' %
                               MAX_NUM_EXPORT_RT)

    if not all(validation.is_valid_ext_comm_attr(rt) for rt in export_rts):
        raise ConfigValueError(conf_name=EXPORT_RTS, conf_value=export_rts)
    # Check if we have duplicates
    unique_rts = set(export_rts)
    if len(unique_rts) != len(export_rts):
        raise ConfigValueError(desc='Duplicate value provided in %s' %
                               (export_rts))
    return export_rts


@validate(name=ROUTE_DISTINGUISHER)
def validate_rd(route_dist):
    if not validation.is_valid_route_dist(route_dist):
        raise ConfigValueError(conf_name=ROUTE_DISTINGUISHER,
                               conf_value=route_dist)
    return route_dist


@validate(name=VRF_RF)
def validate_vrf_rf(vrf_rf):
    if vrf_rf not in SUPPORTED_VRF_RF:
        raise ConfigValueError(desc='Give VRF route family %s is not '
                               'supported.' % vrf_rf)
    return vrf_rf


class VrfConf(ConfWithId, ConfWithStats):
    """Class that encapsulates configurations for one VRF."""

    VRF_CHG_EVT = 'vrf_chg_evt'

    VALID_EVT = frozenset([VRF_CHG_EVT])

    REQUIRED_SETTINGS = frozenset([ROUTE_DISTINGUISHER,
                                   IMPORT_RTS,
                                   EXPORT_RTS])

    OPTIONAL_SETTINGS = frozenset(
        [VRF_NAME, MULTI_EXIT_DISC, SITE_OF_ORIGINS, VRF_RF, IMPORT_MAPS]
    )

    def __init__(self, **kwargs):
        """Create an instance of VRF runtime configuration."""
        super(VrfConf, self).__init__(**kwargs)

    def _init_opt_settings(self, **kwargs):
        super(VrfConf, self)._init_opt_settings(**kwargs)
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

        # Current we we only support VRF for IPv4 and IPv6 with default IPv4
        vrf_rf = kwargs.pop(VRF_RF, VRF_RF_IPV4)
        if vrf_rf and validate_vrf_rf(vrf_rf):
            self._settings[VRF_RF] = vrf_rf

        import_maps = kwargs.pop(IMPORT_MAPS, [])
        self._settings[IMPORT_MAPS] = import_maps

    # =========================================================================
    # Required attributes
    # =========================================================================

    @property
    def route_dist(self):
        return self._settings[ROUTE_DISTINGUISHER]

    # =========================================================================
    # Optional attributes with valid defaults.
    # =========================================================================

    @property
    def import_rts(self):
        return list(self._settings[IMPORT_RTS])

    @property
    def export_rts(self):
        return list(self._settings[EXPORT_RTS])

    @property
    def soo_list(self):
        soos = self._settings.get(SITE_OF_ORIGINS)
        if soos:
            soos = list(soos)
        else:
            soos = []
        return soos

    @property
    def multi_exit_disc(self):
        """Returns configured value of MED, else None.

        This configuration does not have default value.
        """
        return self._settings.get(MULTI_EXIT_DISC)

    @property
    def route_family(self):
        """Returns configured route family for this VRF

        This configuration does not change.
        """
        return self._settings.get(VRF_RF)

    @property
    def rd_rf_id(self):
        return VrfConf.create_rd_rf_id(self.route_dist, self.route_family)

    @property
    def import_maps(self):
        return self._settings.get(IMPORT_MAPS)

    @staticmethod
    def create_rd_rf_id(route_dist, route_family):
        return route_dist, route_family

    @staticmethod
    def vrf_rf_2_rf(vrf_rf):
        if vrf_rf == VRF_RF_IPV4:
            return RF_IPv4_UC
        elif vrf_rf == VRF_RF_IPV6:
            return RF_IPv6_UC
        else:
            raise ValueError('Unsupported VRF route family given %s' % vrf_rf)

    @staticmethod
    def rf_2_vrf_rf(route_family):
        if route_family == RF_IPv4_UC:
            return VRF_RF_IPV4
        elif route_family == RF_IPv6_UC:
            return VRF_RF_IPV6
        else:
            raise ValueError('No supported mapping for route family '
                             'to vrf_route_family exists for %s' %
                             route_family)

    @property
    def settings(self):
        """Returns a copy of current settings.

        As some of the attributes are themselves containers, we clone the
        settings to provide clones for those containers as well.
        """
        # Shallow copy first
        cloned_setting = self._settings.copy()
        # Don't want clone to link to same RT containers
        cloned_setting[IMPORT_RTS] = self.import_rts
        cloned_setting[EXPORT_RTS] = self.export_rts
        cloned_setting[SITE_OF_ORIGINS] = self.soo_list
        return cloned_setting

    @classmethod
    def get_opt_settings(cls):
        self_confs = super(VrfConf, cls).get_opt_settings()
        self_confs.update(VrfConf.OPTIONAL_SETTINGS)
        return self_confs

    @classmethod
    def get_req_settings(cls):
        self_confs = super(VrfConf, cls).get_req_settings()
        self_confs.update(VrfConf.REQUIRED_SETTINGS)
        return self_confs

    @classmethod
    def get_valid_evts(cls):
        self_valid_evts = super(VrfConf, cls).get_valid_evts()
        self_valid_evts.update(VrfConf.VALID_EVT)
        return self_valid_evts

    def update(self, **kwargs):
        """Updates this `VrfConf` settings.

        Notifies listeners if any settings changed. Returns `True` if update
        was successful. This vrfs' route family, id and route dist settings
        cannot be updated/changed.
        """
        # Update inherited configurations
        super(VrfConf, self).update(**kwargs)
        vrf_id = kwargs.get(ConfWithId.ID)
        vrf_rd = kwargs.get(ROUTE_DISTINGUISHER)
        vrf_rf = kwargs.get(VRF_RF)
        if (vrf_id != self.id or
                vrf_rd != self.route_dist or
                vrf_rf != self.route_family):
            raise ConfigValueError(desc='id/route-distinguisher/route-family'
                                   ' do not match configured value.')

        # Validate and update individual settings
        new_imp_rts, old_imp_rts = \
            self._update_import_rts(**kwargs)
        export_rts_changed = self._update_export_rts(**kwargs)
        soos_list_changed = self._update_soo_list(**kwargs)
        med_changed = self._update_med(**kwargs)
        re_export_needed = (export_rts_changed or
                            soos_list_changed or
                            med_changed)
        import_maps = kwargs.get(IMPORT_MAPS, [])
        re_import_needed = self._update_importmaps(import_maps)

        # If we did have any change in value of any settings, we notify
        # listeners
        if (new_imp_rts is not None or
                old_imp_rts is not None or
                re_export_needed or re_import_needed):
            evt_value = (
                new_imp_rts,
                old_imp_rts,
                import_maps,
                re_export_needed,
                re_import_needed
            )
            self._notify_listeners(VrfConf.VRF_CHG_EVT, evt_value)
        return True

    def _update_import_rts(self, **kwargs):
        import_rts = kwargs.get(IMPORT_RTS)
        get_validator(IMPORT_RTS)(import_rts)
        curr_import_rts = set(self._settings[IMPORT_RTS])

        import_rts = set(import_rts)
        if not import_rts.symmetric_difference(curr_import_rts):
            return (None, None)

        # Get the difference between current and new RTs
        new_import_rts = import_rts - curr_import_rts
        old_import_rts = curr_import_rts - import_rts

        # Update current RTs and notify listeners.
        self._settings[IMPORT_RTS] = import_rts
        return (new_import_rts, old_import_rts)

    def _update_export_rts(self, **kwargs):
        export_rts = kwargs.get(EXPORT_RTS)
        get_validator(EXPORT_RTS)(export_rts)
        curr_export_rts = set(self._settings[EXPORT_RTS])

        if curr_export_rts.symmetric_difference(export_rts):
            # Update current RTs and notify listeners.
            self._settings[EXPORT_RTS] = list(export_rts)
            return True

        return False

    def _update_soo_list(self, **kwargs):
        soo_list = kwargs.get(SITE_OF_ORIGINS, [])
        get_validator(SITE_OF_ORIGINS)(soo_list)
        curr_soos = set(self.soo_list)

        # If given list is different from existing settings, we update it
        if curr_soos.symmetric_difference(soo_list):
            self._settings[SITE_OF_ORIGINS] = soo_list[:]
            return True

        return False

    def _update_med(self, **kwargs):
        multi_exit_disc = kwargs.get(MULTI_EXIT_DISC, None)
        if multi_exit_disc:
            get_validator(MULTI_EXIT_DISC)(multi_exit_disc)

        if multi_exit_disc != self.multi_exit_disc:
            self._settings[MULTI_EXIT_DISC] = multi_exit_disc
            return True

        return False

    def _update_importmaps(self, import_maps):
        if set(self._settings[IMPORT_MAPS]).symmetric_difference(import_maps):
            self._settings[IMPORT_MAPS] = import_maps
            return True

        return False

    def __repr__(self):
        return ('<%s(route_dist: %r, import_rts: %r, export_rts: %r, '
                'soo_list: %r)>' % (self.__class__.__name__,
                                    self.route_dist, self.import_rts,
                                    self.export_rts, self.soo_list))

    def __str__(self):
        return ('VrfConf-%s' % (self.route_dist))


class VrfsConf(BaseConf):
    """Container for all VRF configurations."""

    ADD_VRF_CONF_EVT, REMOVE_VRF_CONF_EVT = range(2)

    VALID_EVT = frozenset([ADD_VRF_CONF_EVT, REMOVE_VRF_CONF_EVT])

    def __init__(self):
        super(VrfsConf, self).__init__()
        self._vrfs_by_rd_rf = {}
        self._vrfs_by_id = {}

    def _init_opt_settings(self, **kwargs):
        pass

    @property
    def vrf_confs(self):
        """Returns a list of configured `VrfConf`s
        """
        return list(self._vrfs_by_rd_rf.values())

    @property
    def vrf_interested_rts(self):
        interested_rts = set()
        for vrf_conf in self._vrfs_by_id.values():
            interested_rts.update(vrf_conf.import_rts)
        return interested_rts

    def update(self, **kwargs):
        raise NotImplementedError('Use either add/remove_vrf_conf'
                                  ' methods instead.')

    def add_vrf_conf(self, vrf_conf):
        if vrf_conf.rd_rf_id in self._vrfs_by_rd_rf.keys():
            raise RuntimeConfigError(
                desc='VrfConf with rd_rf %s already exists'
                     % str(vrf_conf.rd_rf_id)
            )
        if vrf_conf.id in self._vrfs_by_id:
            raise RuntimeConfigError(
                desc='VrfConf with id %s already exists' % str(vrf_conf.id)
            )

        self._vrfs_by_rd_rf[vrf_conf.rd_rf_id] = vrf_conf
        self._vrfs_by_id[vrf_conf.id] = vrf_conf
        self._notify_listeners(VrfsConf.ADD_VRF_CONF_EVT, vrf_conf)

    def remove_vrf_conf(self, route_dist=None, vrf_id=None,
                        vrf_rf=None):
        """Removes any matching `VrfConf` for given `route_dist` or `vrf_id`

        Paramters:
            - `route_dist`: (str) route distinguisher of a configured VRF
            - `vrf_id`: (str) vrf ID
            - `vrf_rf`: (str) route family of the VRF configuration
        If only `route_dist` is given, removes `VrfConf`s for all supported
        address families for this `route_dist`. If `vrf_rf` is given, than only
        removes `VrfConf` for that specific route family. If only `vrf_id` is
        given, matching `VrfConf` will be removed.
        """
        if route_dist is None and vrf_id is None:
            raise RuntimeConfigError(desc='To delete supply route_dist or id.')

        # By default we remove all VRFs for given Id or RD
        vrf_rfs = SUPPORTED_VRF_RF
        # If asked to delete specific route family vrf conf.
        if vrf_rf:
            vrf_rfs = (vrf_rf)

        # For all vrf route family asked to be deleted, we collect all deleted
        # VrfConfs
        removed_vrf_confs = []
        for route_family in vrf_rfs:
            if route_dist is not None:
                rd_rf_id = VrfConf.create_rd_rf_id(route_dist, route_family)
                vrf_conf = self._vrfs_by_rd_rf.pop(rd_rf_id, None)
                if vrf_conf:
                    self._vrfs_by_id.pop(vrf_conf.id, None)
                    removed_vrf_confs.append(vrf_conf)
            else:
                vrf_conf = self._vrfs_by_id.pop(vrf_id, None)
                if vrf_conf:
                    self._vrfs_by_rd_rf.pop(vrf_conf.rd_rd_id, None)
                    removed_vrf_confs.append(vrf_conf)

        # We do not raise any exception if we cannot find asked VRF.
        for vrf_conf in removed_vrf_confs:
            self._notify_listeners(VrfsConf.REMOVE_VRF_CONF_EVT, vrf_conf)
        return removed_vrf_confs

    def get_vrf_conf(self, route_dist, vrf_rf, vrf_id=None):
        if route_dist is None and vrf_id is None:
            raise RuntimeConfigError(desc='To get VRF supply route_dist '
                                     'or vrf_id.')
        vrf = None
        if route_dist is not None and vrf_id is not None:
            vrf1 = self._vrfs_by_id.get(vrf_id)
            rd_rf_id = VrfConf.create_rd_rf_id(route_dist, vrf_rf)
            vrf2 = self._vrfs_by_rd_rf.get(rd_rf_id)
            if vrf1 is not vrf2:
                raise RuntimeConfigError(desc='Given VRF ID (%s) and RD (%s)'
                                         ' are not of same VRF.' %
                                         (vrf_id, route_dist))
            vrf = vrf1
        elif route_dist is not None:
            rd_rf_id = VrfConf.create_rd_rf_id(route_dist, vrf_rf)
            vrf = self._vrfs_by_rd_rf.get(rd_rf_id)
        else:
            vrf = self._vrfs_by_id.get(vrf_id)
        return vrf

    @property
    def vrfs_by_rd_rf_id(self):
        return dict(self._vrfs_by_rd_rf)

    @classmethod
    def get_valid_evts(self):
        self_valid_evts = super(VrfsConf, self).get_valid_evts()
        self_valid_evts.update(VrfsConf.VALID_EVT)
        return self_valid_evts

    def __repr__(self):
        return '<%s(%r)>' % (self.__class__.__name__, self._vrfs_by_id)

    @property
    def settings(self):
        return [vrf.settings for vrf in self._vrfs_by_id.values()]


class VrfConfListener(ConfWithIdListener, ConfWithStatsListener):
    """Base listener for various VRF configuration change event."""

    def __init__(self, vrf_conf):
        super(VrfConfListener, self).__init__(vrf_conf)
        vrf_conf.add_listener(VrfConf.VRF_CHG_EVT, self.on_chg_vrf_conf)

    def on_chg_vrf_conf(self, evt):
        raise NotImplementedError('This method should be overridden')


class VrfsConfListener(BaseConfListener):
    """Base listener for VRF container change events."""

    def __init__(self, vrfs_conf):
        super(VrfsConfListener, self).__init__(vrfs_conf)
        vrfs_conf.add_listener(VrfsConf.ADD_VRF_CONF_EVT, self.on_add_vrf_conf)
        vrfs_conf.add_listener(VrfsConf.REMOVE_VRF_CONF_EVT,
                               self.on_remove_vrf_conf)

    @abc.abstractmethod
    def on_add_vrf_conf(self, evt):
        raise NotImplementedError('This method should be overridden')

    @abc.abstractmethod
    def on_remove_vrf_conf(self, evt):
        raise NotImplementedError('This method should be overridden')
