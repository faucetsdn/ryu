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
 Module for RT Filter related functionality.
"""
import logging

from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import RouteTargetMembershipNLRI
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGPPathAttributeOrigin
from ryu.services.protocols.bgp.base import OrderedDict
from ryu.services.protocols.bgp.info_base.rtc import RtcPath

LOG = logging.getLogger('bgpspeaker.util.rtfilter')


class RouteTargetManager(object):
    def __init__(self, core_service, neighbors_conf, vrfs_conf):
        self._core_service = core_service
        # TODO(PH): Consider extending VrfsConfListener and
        # NeighborsConfListener
        self._neighbors_conf = neighbors_conf
        self._vrfs_conf = vrfs_conf

        # Peer to its current RT filter map
        # <key>/value = <peer_ip>/<rt filter set>
        self._peer_to_rtfilter_map = {}

        # Collection of import RTs of all configured VRFs
        self._all_vrfs_import_rts_set = set()

        # Collection of current RTC AS for all configured Neighbors
        self._all_rtc_as_set = set()
        # Interested RTs according to current entries in RTC global table
        self._global_interested_rts = set()

    @property
    def peer_to_rtfilter_map(self):
        return self._peer_to_rtfilter_map.copy()

    @peer_to_rtfilter_map.setter
    def peer_to_rtfilter_map(self, new_map):
        self._peer_to_rtfilter_map = new_map.copy()

    @property
    def global_interested_rts(self):
        return set(self._global_interested_rts)

    def add_rt_nlri(self, route_target, is_withdraw=False):
        assert route_target
        # Since we allow RTC AS setting for each neighbor, we collect all we
        # collect allRTC AS settings and add a RT NLRI using each AS number
        rtc_as_set = set()
        # Add RT NLRI with local AS
        rtc_as_set.add(self._core_service.asn)
        # Collect RTC AS from neighbor settings
        rtc_as_set.update(self._neighbors_conf.rtc_as_set)
        # Add RT NLRI path (withdraw) for each RTC AS
        for rtc_as in rtc_as_set:
            self._add_rt_nlri_for_as(rtc_as, route_target, is_withdraw)

    def _add_rt_nlri_for_as(self, rtc_as, route_target, is_withdraw=False):
        from ryu.services.protocols.bgp.core import EXPECTED_ORIGIN
        rt_nlri = RouteTargetMembershipNLRI(rtc_as, route_target)
        # Create a dictionary for path-attrs.
        pattrs = OrderedDict()
        if not is_withdraw:
            # MpReachNlri and/or MpUnReachNlri attribute info. is contained
            # in the path. Hence we do not add these attributes here.
            pattrs[BGP_ATTR_TYPE_ORIGIN] = BGPPathAttributeOrigin(
                EXPECTED_ORIGIN)
            pattrs[BGP_ATTR_TYPE_AS_PATH] = BGPPathAttributeAsPath([])

        # Create Path instance and initialize appropriately.
        path = RtcPath(None, rt_nlri, 0, is_withdraw=is_withdraw,
                       pattrs=pattrs)
        tm = self._core_service.table_manager
        tm.learn_path(path)

    def update_rtc_as_set(self):
        """Syncs RT NLRIs for new and removed RTC_ASes.

        This method should be called when a neighbor is added or removed.
        """
        # Compute the diffs in RTC_ASes
        curr_rtc_as_set = self._neighbors_conf.rtc_as_set
        # Always add local AS to RTC AS set
        curr_rtc_as_set.add(self._core_service.asn)
        removed_rtc_as_set = self._all_rtc_as_set - curr_rtc_as_set
        new_rtc_as_set = curr_rtc_as_set - self._all_rtc_as_set

        # Update to new RTC_AS set
        self._all_rtc_as_set = curr_rtc_as_set

        # Sync RT NLRI by adding/withdrawing as appropriate
        for new_rtc_as in new_rtc_as_set:
            for import_rt in self._all_vrfs_import_rts_set:
                self._add_rt_nlri_for_as(new_rtc_as, import_rt)
        for removed_rtc_as in removed_rtc_as_set:
            for import_rt in self._all_vrfs_import_rts_set:
                self._add_rt_nlri_for_as(removed_rtc_as, import_rt,
                                         is_withdraw=True)

    def update_local_rt_nlris(self):
        """Does book-keeping of local RT NLRIs based on all configured VRFs.

        Syncs all import RTs and RT NLRIs.
        The method should be called when any VRFs are added/removed/changed.
        """
        current_conf_import_rts = set()
        for vrf in self._vrfs_conf.vrf_confs:
            current_conf_import_rts.update(vrf.import_rts)

        removed_rts = self._all_vrfs_import_rts_set - current_conf_import_rts
        new_rts = current_conf_import_rts - self._all_vrfs_import_rts_set
        self._all_vrfs_import_rts_set = current_conf_import_rts

        # Add new and withdraw removed local RtNlris
        for new_rt in new_rts:
            self.add_rt_nlri(new_rt)
        for removed_rt in removed_rts:
            self.add_rt_nlri(removed_rt, is_withdraw=True)

    def on_rt_filter_chg_sync_peer(self, peer, new_rts, old_rts, table):
        LOG.debug('RT Filter changed for peer %s, new_rts %s, old_rts %s ',
                  peer, new_rts, old_rts)
        for dest in table.values():
            # If this destination does not have best path, we ignore it
            if not dest.best_path:
                continue

            desired_rts = set(dest.best_path.get_rts())

            # If this path was sent to peer and if all path RTs are now not of
            # interest, we need to send withdraw for this path to this peer
            if dest.was_sent_to(peer):
                if not (desired_rts - old_rts):
                    dest.withdraw_if_sent_to(peer)
            else:
                # New RT could be Default RT, which means we need to share this
                # path
                desired_rts.add(RouteTargetMembershipNLRI.DEFAULT_RT)
                # If we have RT filter has new RTs that are common with path
                # RTs, then we send this path to peer
                if desired_rts.intersection(new_rts):
                    peer.communicate_path(dest.best_path)

    def _compute_global_intrested_rts(self):
        """Computes current global interested RTs for global tables.

        Computes interested RTs based on current RT filters for peers. This
        filter should be used to check if for RTs on a path that is installed
        in any global table (expect RT Table).
        """
        interested_rts = set()
        for rtfilter in self._peer_to_rtfilter_map.values():
            interested_rts.update(rtfilter)

        interested_rts.update(self._vrfs_conf.vrf_interested_rts)
        # Remove default RT as it is not a valid RT for paths
        # TODO(PH): Check if we have better alternative than add and remove
        interested_rts.add(RouteTargetMembershipNLRI.DEFAULT_RT)
        interested_rts.remove(RouteTargetMembershipNLRI.DEFAULT_RT)
        return interested_rts

    def update_interested_rts(self):
        """Updates interested RT list.

        Check if interested RTs have changes from previous check.
        Takes appropriate action for new interesting RTs and removal of un-
        interesting RTs.
        """
        prev_global_rts = self._global_interested_rts
        curr_global_rts = self._compute_global_intrested_rts()

        new_global_rts = curr_global_rts - prev_global_rts
        removed_global_rts = prev_global_rts - curr_global_rts

        # Update current interested RTs for next iteration
        self._global_interested_rts = curr_global_rts

        LOG.debug('Global Interested RT changed, new RTs %s, removed RTs %s',
                  new_global_rts, removed_global_rts)
        tm = self._core_service.table_manager
        tm.on_interesting_rts_change(new_global_rts, removed_global_rts)

    def filter_by_origin_as(self, new_best_path, qualified_peers):
        path_rf = new_best_path.route_family

        # We need not filter any peer if this is not a RT NLRI path or if
        # source of this path is remote peer (i.e. if this is not a local path)
        if path_rf != RF_RTC_UC or new_best_path.source is not None:
            return qualified_peers
        else:
            filtered_qualified_peers = []
            rt_origin_as = new_best_path.nlri.origin_as
            # Collect peers whose RTC_AS setting match paths RT Origin AS
            for qualified_peer in qualified_peers:
                neigh_conf = \
                    self._neighbors_conf.get_neighbor_conf(
                        qualified_peer.ip_address)
                if neigh_conf.rtc_as == rt_origin_as:
                    filtered_qualified_peers.append(qualified_peer)

            # Update qualified peers to include only filtered peers
            return filtered_qualified_peers
