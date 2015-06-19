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
 Defines base data types and models required specifically for VRF support.
"""

import abc
import logging

from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MULTI_EXIT_DISC
from ryu.lib.packet.bgp import BGPPathAttributeOrigin
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGPPathAttributeExtendedCommunities
from ryu.lib.packet.bgp import BGPTwoOctetAsSpecificExtendedCommunity
from ryu.lib.packet.bgp import BGPPathAttributeMultiExitDisc

from ryu.services.protocols.bgp.base import OrderedDict
from ryu.services.protocols.bgp.constants import VPN_TABLE
from ryu.services.protocols.bgp.constants import VRF_TABLE
from ryu.services.protocols.bgp.info_base.base import Destination
from ryu.services.protocols.bgp.info_base.base import Path
from ryu.services.protocols.bgp.info_base.base import Table
from ryu.services.protocols.bgp.utils.stats import LOCAL_ROUTES
from ryu.services.protocols.bgp.utils.stats import REMOTE_ROUTES
from ryu.services.protocols.bgp.utils.stats import RESOURCE_ID
from ryu.services.protocols.bgp.utils.stats import RESOURCE_NAME

LOG = logging.getLogger('bgpspeaker.info_base.vrf')


class VrfTable(Table):
    """Virtual Routing and Forwarding information base.
     Keeps destination imported to given vrf in represents.
     """

    __metaclass__ = abc.ABCMeta
    ROUTE_FAMILY = None
    VPN_ROUTE_FAMILY = None
    NLRI_CLASS = None
    VRF_PATH_CLASS = None
    VRF_DEST_CLASS = None

    def __init__(self, vrf_conf, core_service, signal_bus):
        Table.__init__(self, vrf_conf.route_dist, core_service, signal_bus)
        self._vrf_conf = vrf_conf
        self._import_maps = []
        self.init_import_maps(vrf_conf.import_maps)

    def init_import_maps(self, import_maps):
        LOG.debug(
            "Initializing import maps (%s) for %r", import_maps, self
        )
        del self._import_maps[:]
        importmap_manager = self._core_service.importmap_manager
        for name in import_maps:
            import_map = importmap_manager.get_import_map_by_name(name)
            if import_map is None:
                raise KeyError('No import map with name %s' % name)
            self._import_maps.append(import_map)

    @property
    def import_rts(self):
        return self._vrf_conf.import_rts

    @property
    def vrf_conf(self):
        return self._vrf_conf

    def _table_key(self, nlri):
        """Return a key that will uniquely identify this NLRI inside
        this table.
        """
        return str(nlri)

    def _create_dest(self, nlri):
        return self.VRF_DEST_CLASS(self, nlri)

    def append_import_map(self, import_map):
        self._import_maps.append(import_map)

    def remove_import_map(self, import_map):
        self._import_maps.remove(import_map)

    def get_stats_summary_dict(self):
        """Returns count of local and remote paths."""

        remote_route_count = 0
        local_route_count = 0
        for dest in self.values():
            for path in dest.known_path_list:
                if (hasattr(path.source, 'version_num')
                        or path.source == VPN_TABLE):
                    remote_route_count += 1
                else:
                    local_route_count += 1
        return {RESOURCE_ID: self._vrf_conf.id,
                RESOURCE_NAME: self._vrf_conf.name,
                REMOTE_ROUTES: remote_route_count,
                LOCAL_ROUTES: local_route_count}

    def import_vpn_paths_from_table(self, vpn_table, import_rts=None):
        for vpn_dest in vpn_table.values():
            vpn_path = vpn_dest.best_path
            if not vpn_path:
                continue

            if import_rts is None:
                import_rts = set(self.import_rts)
            else:
                import_rts = set(import_rts)

            path_rts = vpn_path.get_rts()
            if import_rts.intersection(path_rts):
                # TODO(PH): When (re-)implementing extranet, check what should
                # be the label reported back to NC for local paths coming from
                # other VRFs.
                self.import_vpn_path(vpn_path)

    def import_vpn_path(self, vpn_path):
        """Imports `vpnv(4|6)_path` into `vrf(4|6)_table`.

        :Parameters:
            - `vpn_path`: (Path) VPN path that will be cloned and imported
            into VRF.
        Note: Does not do any checking if this import is valid.
        """
        assert vpn_path.route_family == self.VPN_ROUTE_FAMILY
        # If source of given vpnv4 path is NC we import it to given VRF
        # table because of extranet setting. Hence we identify source of
        # EXTRANET prefixes as VRF_TABLE, else VPN_TABLE.
        source = vpn_path.source
        if not source:
            source = VRF_TABLE
        ip, masklen = vpn_path.nlri.prefix.split('/')
        vrf_nlri = self.NLRI_CLASS(length=int(masklen), addr=ip)

        vpn_nlri = vpn_path.nlri
        puid = self.VRF_PATH_CLASS.create_puid(vpn_nlri.route_dist,
                                               vpn_nlri.prefix)
        vrf_path = self.VRF_PATH_CLASS(
            puid,
            source,
            vrf_nlri,
            vpn_path.source_version_num,
            pattrs=vpn_path.pathattr_map,
            nexthop=vpn_path.nexthop,
            is_withdraw=vpn_path.is_withdraw,
            label_list=vpn_path.nlri.label_list
        )
        if self._is_vrf_path_already_in_table(vrf_path):
            return None

        if self._is_vrf_path_filtered_out_by_import_maps(vrf_path):
            return None
        else:
            vrf_dest = self.insert(vrf_path)
            self._signal_bus.dest_changed(vrf_dest)

    def _is_vrf_path_filtered_out_by_import_maps(self, vrf_path):
        for import_map in self._import_maps:
            if import_map.match(vrf_path):
                return True

        return False

    def _is_vrf_path_already_in_table(self, vrf_path):
        dest = self._get_dest(vrf_path.nlri)
        if dest is None:
            return False
        return vrf_path in dest.known_path_list

    def apply_import_maps(self):
        changed_dests = []
        for dest in self.values():
            assert isinstance(dest, VrfDest)
            for import_map in self._import_maps:
                for path in dest.known_path_list:
                    if import_map.match(path):
                        dest.withdraw_path(path)
                        changed_dests.append(dest)
        return changed_dests

    def insert_vrf_path(self, ip_nlri, next_hop=None,
                        gen_lbl=False, is_withdraw=False):
        assert ip_nlri
        pattrs = None
        label_list = []
        vrf_conf = self.vrf_conf
        if not is_withdraw:
            # Create a dictionary for path-attrs.
            pattrs = OrderedDict()

            # MpReachNlri and/or MpUnReachNlri attribute info. is contained
            # in the path. Hence we do not add these attributes here.
            from ryu.services.protocols.bgp.core import EXPECTED_ORIGIN

            pattrs[BGP_ATTR_TYPE_ORIGIN] = BGPPathAttributeOrigin(
                EXPECTED_ORIGIN)
            pattrs[BGP_ATTR_TYPE_AS_PATH] = BGPPathAttributeAsPath([])
            communities = []
            for rt in vrf_conf.export_rts:
                as_num, local_admin = rt.split(':')
                subtype = 2
                communities.append(BGPTwoOctetAsSpecificExtendedCommunity(
                                   as_number=int(as_num),
                                   local_administrator=int(local_admin),
                                   subtype=subtype))
            for soo in vrf_conf.soo_list:
                as_num, local_admin = soo.split(':')
                subtype = 3
                communities.append(BGPTwoOctetAsSpecificExtendedCommunity(
                                   as_number=int(as_num),
                                   local_administrator=int(local_admin),
                                   subtype=subtype))

            pattrs[BGP_ATTR_TYPE_EXTENDED_COMMUNITIES] = \
                BGPPathAttributeExtendedCommunities(communities=communities)
            if vrf_conf.multi_exit_disc:
                pattrs[BGP_ATTR_TYPE_MULTI_EXIT_DISC] = \
                    BGPPathAttributeMultiExitDisc(vrf_conf.multi_exit_disc)

            table_manager = self._core_service.table_manager
            if gen_lbl and next_hop:
                # Label per next_hop demands we use a different label
                # per next_hop. Here connected interfaces are advertised per
                # VRF.
                label_key = (vrf_conf.route_dist, next_hop)
                nh_label = table_manager.get_nexthop_label(label_key)
                if not nh_label:
                    nh_label = table_manager.get_next_vpnv4_label()
                    table_manager.set_nexthop_label(label_key, nh_label)
                label_list.append(nh_label)

            elif gen_lbl:
                # If we do not have next_hop, get a new label.
                label_list.append(table_manager.get_next_vpnv4_label())

        puid = self.VRF_PATH_CLASS.create_puid(
            vrf_conf.route_dist, ip_nlri.prefix
        )
        path = self.VRF_PATH_CLASS(
            puid, None, ip_nlri, 0, pattrs=pattrs,
            nexthop=next_hop, label_list=label_list,
            is_withdraw=is_withdraw
        )

        # Insert the path into VRF table, get affected destination so that we
        # can process it further.
        eff_dest = self.insert(path)
        # Enqueue the eff_dest for further processing.
        self._signal_bus.dest_changed(eff_dest)
        return label_list

    def clean_uninteresting_paths(self, interested_rts=None):
        if interested_rts is None:
            interested_rts = set(self.vrf_conf.import_rts)
        return super(VrfTable, self).clean_uninteresting_paths(interested_rts)


class VrfDest(Destination):
    """Base class for VRF destination."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, table, nlri):
        super(VrfDest, self).__init__(table, nlri)
        self._route_dist = self._table.vrf_conf.route_dist

    def _best_path_lost(self):
        # Have to send update messages for withdraw of best-path to Network
        # controller or Global table.
        old_best_path = self._best_path
        self._best_path = None

        if old_best_path is None:
            return

        if old_best_path.source is not None:
            # Send update-withdraw msg. to Sink. Create withdraw path
            # out of old best path and queue it into flexinet sinks.
            old_best_path = old_best_path.clone(for_withdrawal=True)
            self._core_service.update_flexinet_peers(old_best_path,
                                                     self._route_dist)
        else:
            # Create withdraw-path out of old best path.
            gpath = old_best_path.clone_to_vpn(self._route_dist,
                                               for_withdrawal=True)
            # Insert withdraw into global table and enqueue the destination
            # for further processing.
            tm = self._core_service.table_manager
            tm.learn_path(gpath)

    def _new_best_path(self, best_path):
        LOG.debug('New best path selected for destination %s', self)

        old_best_path = self._best_path
        assert (best_path != old_best_path)
        self._best_path = best_path
        # Distribute new best-path to flexinet-peers.
        if best_path.source is not None:
            # Since route-refresh just causes the version number to
            # go up and this changes best-path, we check if new-
            # best-path is really different than old-best-path that
            # warrants sending update to flexinet peers.

            def really_diff():
                old_labels = old_best_path.label_list
                new_labels = best_path.label_list
                return old_best_path.nexthop != best_path.nexthop \
                    or set(old_labels) != set(new_labels)

            if not old_best_path or (old_best_path and really_diff()):
                # Create OutgoingRoute and queue it into NC sink.
                self._core_service.update_flexinet_peers(
                    best_path, self._route_dist
                )
        else:
            # If NC is source, we create new path and insert into global
            # table.
            gpath = best_path.clone_to_vpn(self._route_dist)
            tm = self._core_service.table_manager
            tm.learn_path(gpath)
            LOG.debug('VRF table %s has new best path: %s',
                      self._route_dist, self.best_path)

    def _remove_withdrawals(self):
        """Removes withdrawn paths.

        Note:
        We may have disproportionate number of withdraws compared to know paths
        since not all paths get installed into the table due to bgp policy and
        we can receive withdraws for such paths and withdrawals may not be
        stopped by the same policies.
        """

        LOG.debug('Removing %s withdrawals', len(self._withdraw_list))

        # If we have not withdrawals, we have nothing to do.
        if not self._withdraw_list:
            return

        # If we have some withdrawals and no know-paths, it means it is safe to
        # delete these withdraws.
        if not self._known_path_list:
            LOG.debug('Found %s withdrawals for path(s) that did not get'
                      ' installed.', len(self._withdraw_list))
            del (self._withdraw_list[:])
            return

        # If we have some known paths and some withdrawals, we find matches and
        # delete them first.
        matches = []
        w_matches = []
        # Match all withdrawals from destination paths.
        for withdraw in self._withdraw_list:
            match = None
            for path in self._known_path_list:
                # We have a match if the source are same.
                if path.puid == withdraw.puid:
                    match = path
                    matches.append(path)
                    w_matches.append(withdraw)
                    # One withdraw can remove only one path.
                    break
                # We do no have any match for this withdraw.
            if not match:
                LOG.debug('No matching path for withdraw found, may be path '
                          'was not installed into table: %s',
                          withdraw)
            # If we have partial match.
        if len(matches) != len(self._withdraw_list):
            LOG.debug('Did not find match for some withdrawals. Number of '
                      'matches(%s), number of withdrawals (%s)',
                      len(matches), len(self._withdraw_list))

        # Clear matching paths and withdrawals.
        for match in matches:
            self._known_path_list.remove(match)
        for w_match in w_matches:
            self._withdraw_list.remove(w_match)

    def _remove_old_paths(self):
        """Identifies which of known paths are old and removes them.

        Known paths will no longer have paths whose new version is present in
        new paths.
        """
        new_paths = self._new_path_list
        known_paths = self._known_path_list
        for new_path in new_paths:
            old_paths = []
            for path in known_paths:
                # Here we just check if source is same and not check if path
                # version num. as new_paths are implicit withdrawal of old
                # paths and when doing RouteRefresh (not EnhancedRouteRefresh)
                # we get same paths again.
                if (new_path.puid == path.puid):
                    old_paths.append(path)
                    break

            for old_path in old_paths:
                known_paths.remove(old_path)
                LOG.debug('Implicit withdrawal of old path, since we have'
                          ' learned new path from same source: %s', old_path)

    def _validate_path(self, path):
        if not path or not hasattr(path, 'label_list'):
            raise ValueError('Invalid value of path. Expected type '
                             'with attribute label_list got %s' % path)


class VrfPath(Path):
    """Represents a way of reaching an IP destination with a VPN.
    """
    __slots__ = ('_label_list', '_puid')
    __metaclass__ = abc.ABCMeta

    ROUTE_FAMILY = None
    VPN_PATH_CLASS = None
    VPN_NLRI_CLASS = None

    def __init__(self, puid, source, nlri, src_ver_num,
                 pattrs=None, nexthop=None,
                 is_withdraw=False, label_list=None):
        """Initializes a Vrf path.

            Parameters:
                - `puid`: (str) path ID, identifies VPN path from which this
                VRF path was imported.
                - `label_list`: (list) List of labels for this path.
            Note: other parameters are as documented in super class.
        """
        Path.__init__(self, source, nlri, src_ver_num, pattrs, nexthop,
                      is_withdraw)
        if label_list is None:
            label_list = []
        self._label_list = label_list
        self._puid = puid

    @property
    def puid(self):
        return self._puid

    @property
    def origin_rd(self):
        tokens = self.puid.split(':')
        return tokens[0] + ':' + tokens[1]

    @property
    def label_list(self):
        return self._label_list[:]

    @staticmethod
    def create_puid(route_dist, ip_prefix):
        assert route_dist and ip_prefix
        return str(route_dist) + ':' + ip_prefix

    def clone(self, for_withdrawal=False):
        pathattrs = None
        if not for_withdrawal:
            pathattrs = self.pathattr_map

        clone = self.__class__(
            self.puid,
            self._source,
            self.nlri,
            self.source_version_num,
            pattrs=pathattrs,
            nexthop=self.nexthop,
            is_withdraw=for_withdrawal,
            label_list=self.label_list
        )
        return clone

    def clone_to_vpn(self, route_dist, for_withdrawal=False):
        ip, masklen = self._nlri.prefix.split('/')
        vpn_nlri = self.VPN_NLRI_CLASS(length=int(masklen),
                                       addr=ip,
                                       labels=self.label_list,
                                       route_dist=route_dist)

        pathattrs = None
        if not for_withdrawal:
            pathattrs = self.pathattr_map
        vpnv_path = self.VPN_PATH_CLASS(
            self.source, vpn_nlri,
            self.source_version_num,
            pattrs=pathattrs,
            nexthop=self.nexthop,
            is_withdraw=for_withdrawal
        )
        return vpnv_path

    def __eq__(self, b_path):
        if not isinstance(b_path, self.__class__):
            return False
        if not self.route_family == b_path.route_family:
            return False
        if not self.puid == b_path.puid:
            return False
        if not self.label_list == b_path.label_list:
            return False
        if not self.nexthop == b_path.nexthop:
            return False
        if not self.pathattr_map == b_path.pathattr_map:
            return False

        return True


class ImportMap(object):
    def match(self, vrf_path):
        raise NotImplementedError()


class VrfNlriImportMap(ImportMap):
    VRF_PATH_CLASS = None
    NLRI_CLASS = None

    def __init__(self, prefix):
        assert self.VRF_PATH_CLASS is not None
        assert self.NLRI_CLASS is not None
        self._nlri = self.NLRI_CLASS(prefix)

    def match(self, vrf_path):
        if vrf_path.route_family != self.VRF_PATH_CLASS.ROUTE_FAMILY:
            LOG.error(
                "vrf_paths route_family doesn\'t match importmaps"
                "route_family. Applied to wrong table?")
            return False

        return vrf_path.nlri == self._nlri


class VrfRtImportMap(ImportMap):
    def __init__(self, rt):
        self._rt = rt

    def match(self, vrf_path):
        extcomm = vrf_path.pathattr_map.get(BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
        return extcomm is not None and self._rt in extcomm.rt_list
