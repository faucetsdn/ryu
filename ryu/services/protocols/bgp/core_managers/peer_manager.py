import logging
import netaddr

from ryu.services.protocols.bgp.base import SUPPORTED_GLOBAL_RF
from ryu.services.protocols.bgp.model import OutgoingRoute
from ryu.services.protocols.bgp.peer import Peer
from ryu.lib.packet.bgp import BGPPathAttributeCommunities
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MULTI_EXIT_DISC
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_COMMUNITIES
from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import RouteTargetMembershipNLRI
from ryu.services.protocols.bgp.utils.bgp \
    import clone_path_and_update_med_for_target_neighbor
LOG = logging.getLogger('bgpspeaker.core_managers.peer_manager')


class PeerManager(object):
    def __init__(
            self, core_service, neighbors_conf,
    ):
        self._core_service = core_service
        self._signal_bus = core_service.signal_bus
        self._table_manager = core_service.table_manager
        self._rt_manager = core_service.rt_manager
        self._peers = {}

        # Peer to RTFilter map
        # Key: Peer instance
        # Value: set of RTs that constitute RT filter for this peer
        self._peer_to_rtfilter_map = {}
        self._neighbors_conf = neighbors_conf

    @property
    def iterpeers(self):
        return iter(self._peers.values())

    def set_peer_to_rtfilter_map(self, new_map):
        self._peer_to_rtfilter_map = new_map

    def add_peer(self, neigh_conf, common_conf):
        peer = Peer(common_conf, neigh_conf, self._core_service,
                    self._signal_bus, self)
        self._peers[neigh_conf.ip_address] = peer
        self._core_service.on_peer_added(peer)

    def remove_peer(self, neigh_conf):
        neigh_ip_address = neigh_conf.ip_address
        peer = self._peers.get(neigh_ip_address)
        peer.stop()
        del self._peers[neigh_ip_address]
        self._core_service.on_peer_removed(peer)

    def get_by_addr(self, addr):
        return self._peers.get(str(netaddr.IPAddress(addr)))

    def on_peer_down(self, peer):
        """Peer down handler.

        Cleans up the paths in global tables that was received from this peer.
        """
        LOG.debug('Cleaning obsolete paths whose source/version: %s/%s',
                  peer.ip_address, peer.version_num)
        # Launch clean-up for each global tables.
        self._table_manager.clean_stale_routes(peer)

    def _get_non_rtc_peers(self):
        non_rtc_peer_list = set()
        for peer in self._peers.values():
            if (peer.in_established() and
                    not peer.is_mpbgp_cap_valid(RF_RTC_UC)):
                non_rtc_peer_list.add(peer)
        return non_rtc_peer_list

    def curr_peer_rtfilter(self, peer):
        return self._peer_to_rtfilter_map.get(peer)

    def get_peers_in_established(self):
        """Returns list of peers in established state."""
        est_peers = []
        for peer in self._peers.values():
            if peer.in_established:
                est_peers.append(peer)
        return est_peers

    def resend_sent(self, route_family, peer):
        """For given `peer` re-send sent paths.

        Parameters:
            - `route-family`: (RouteFamily) of the sent paths to re-send
            - `peer`: (Peer) peer for which we need to re-send sent paths
        """
        if peer not in self._peers.values():
            raise ValueError('Could not find given peer (%s)' % peer)

        if route_family not in SUPPORTED_GLOBAL_RF:
            raise ValueError(
                'Given route family (%s) is not supported.' % route_family
            )

        # Iterate over the global table for given afi, safi and enqueue
        # out-going routes.
        table = self._table_manager.get_global_table_by_route_family(
            route_family
        )

        for destination in table.values():
            # Check if this destination's sent - routes include this peer.
            # i.e. check if this destinations was advertised and enqueue
            # the path only if it was. If the current best-path has not been
            # advertised before, it might already have a OutgoingRoute queued
            # to be sent to the peer.
            sent_routes = destination.sent_routes
            if sent_routes is None or len(sent_routes) == 0:
                continue
            for sent_route in sent_routes:
                if sent_route.sent_peer == peer:
                    # update med - if previously med was set per neighbor or
                    # wasn't set at all now it could have changed and we may
                    # need to set new value there
                    p = sent_route.path
                    if p.med_set_by_target_neighbor or p.get_pattr(
                            BGP_ATTR_TYPE_MULTI_EXIT_DISC) is None:
                        sent_route.path = \
                            clone_path_and_update_med_for_target_neighbor(
                                sent_route.path, peer.med
                            )

                    ogr = OutgoingRoute(sent_route.path,
                                        for_route_refresh=True)
                    peer.enque_outgoing_msg(ogr)

    def req_rr_to_non_rtc_peers(self, route_family):
        """Makes refresh request to all peers for given address family.

        Skips making request to peer that have valid RTC capability.
        """
        assert route_family != RF_RTC_UC
        for peer in self._peers.values():
            # First check if peer is in established state
            if (peer.in_established and
                # Check if peer has valid capability for given address
                # family
                    peer.is_mbgp_cap_valid(route_family) and
                # Check if peer has valid capability for RTC
                    not peer.is_mbgp_cap_valid(RF_RTC_UC)):
                peer.request_route_refresh(route_family)

    def make_route_refresh_request(self, peer_ip, *route_families):
        """Request route-refresh for peer with `peer_ip` for given
        `route_families`.

        Will make route-refresh request for a given `route_family` only if such
        capability is supported and if peer is in ESTABLISHED state. Else, such
        requests are ignored. Raises appropriate error in other cases. If
        `peer_ip` is equal to 'all' makes refresh request to all valid peers.
        """
        LOG.debug('Route refresh requested for peer %s and route families %s',
                  peer_ip, route_families)
        if not SUPPORTED_GLOBAL_RF.intersection(route_families):
            raise ValueError('Given route family(s) % is not supported.' %
                             route_families)

        peer_list = []
        # If route-refresh is requested for all peers.
        if peer_ip == 'all':
            peer_list.extend(self.get_peers_in_established())
        else:
            given_peer = self._peers.get(peer_ip)
            if not given_peer:
                raise ValueError('Invalid/unrecognized peer %s' % peer_ip)
            if not given_peer.in_established:
                raise ValueError('Peer currently do not have established'
                                 ' session.')
            peer_list.append(given_peer)

        # Make route refresh request to valid peers.
        for peer in peer_list:
            peer.request_route_refresh(*route_families)

        return True

    def comm_all_rt_nlris(self, peer):
        """Shares/communicates current best rt_nlri paths with this peers.

        Can be used to send initial updates after we have established session
        with `peer` with which RTC capability is valid. Takes into account
        peers RTC_AS setting and filters all RT NLRIs whose origin AS do not
        match this setting.
        """
        # First check if for this peer mpbgp-rtc is valid.
        if not peer.is_mbgp_cap_valid(RF_RTC_UC):
            return

        neigh_conf = self._neighbors_conf.get_neighbor_conf(peer.ip_address)
        peer_rtc_as = neigh_conf.rtc_as
        # Iterate over all RT_NLRI destination communicate qualifying RT_NLRIs
        rtc_table = self._table_manager.get_rtc_table()
        for dest in rtc_table.values():
            best_path = dest.best_path
            # Ignore a destination that currently does not have best path
            if not best_path:
                continue

            # If this is a local path
            if best_path.source is None:
                # Check RT NLRI's origin AS matches peer RTC_AS setting
                origin_as = best_path.nlri.origin_as
                if origin_as == peer_rtc_as:
                    peer.communicate_path(best_path)
            else:
                # Communicate all remote RT NLRIs
                peer.communicate_path(best_path)

        # Also communicate EOR as per RFC
        peer.enque_end_of_rib(RF_RTC_UC)

    def comm_all_best_paths(self, peer):
        """Shares/communicates current best paths with this peers.

        Can be used to send initial updates after we have established session
        with `peer`.
        """
        LOG.debug('Communicating current best path for all afi/safi except'
                  ' 1/132')
        # We will enqueue best path from all global destination.
        for route_family, table in self._table_manager.iter:
            if route_family == RF_RTC_UC:
                continue
            if peer.is_mbgp_cap_valid(route_family):
                for dest in table.values():
                    if dest.best_path:
                        peer.communicate_path(dest.best_path)

    def comm_new_best_to_bgp_peers(self, new_best_path):
        """Communicates/enqueues given best path to be sent to all qualifying
        bgp peers.

        If this path came from iBGP peers, it is not sent to other iBGP peers.
        If this path has community-attribute, and if settings for recognize-
        well-know attributes is set, we do as per [RFC1997], and queue outgoing
        route only to qualifying BGP peers.
        """
        # Filter based on standard community
        # If new best path has community attribute, it should be taken into
        # account when sending UPDATE to peers.
        comm_attr = new_best_path.get_pattr(BGP_ATTR_TYPE_COMMUNITIES)
        if comm_attr:
            comm_attr_na = comm_attr.has_comm_attr(
                BGPPathAttributeCommunities.NO_ADVERTISE
            )
            # If we have NO_ADVERTISE attribute is present, we do not send
            # UPDATE to any peers
            if comm_attr_na:
                LOG.debug('New best path has community attr. NO_ADVERTISE = %s'
                          '. Hence not advertising to any peer', comm_attr_na)
                return

        qualified_peers = self._collect_peers_of_interest(
            new_best_path
        )

        # Distribute new best-path to qualified peers.
        for peer in qualified_peers:
            peer.communicate_path(new_best_path)

    def _collect_peers_of_interest(self, new_best_path):
        """Collect all peers that qualify for sharing a path with given RTs.
        """
        path_rts = new_best_path.get_rts()
        qualified_peers = set(self._peers.values())

        # Filter out peers based on RTC_AS setting if path is for RT_NLRI
        qualified_peers = self._rt_manager.filter_by_origin_as(
            new_best_path, qualified_peers
        )

        # We continue to filter out qualified peer based on path RTs
        # If new best path has RTs, we need to share this UPDATE with
        # qualifying peers
        if path_rts:
            # We add Default_RTC_NLRI to path RTs so that we can send it to
            # peers that have expressed interest in all paths
            path_rts.append(RouteTargetMembershipNLRI.DEFAULT_RT)
            # All peers that do not have RTC capability qualify
            qualified_peers = set(self._get_non_rtc_peers())
            # Peers that have RTC capability and have common RT with the path
            # also qualify
            peer_to_rtfilter_map = self._peer_to_rtfilter_map
            for peer, rt_filter in peer_to_rtfilter_map.items():
                # Ignore Network Controller (its not a BGP peer)
                if peer is None:
                    continue

                if rt_filter is None:
                    qualified_peers.add(peer)
                elif rt_filter.intersection(path_rts):
                    qualified_peers.add(peer)

        return qualified_peers

    def schedule_rr_to_non_rtc_peers(self):
        for route_family in SUPPORTED_GLOBAL_RF:
            # Since we are dealing with peers that do not support RTC,
            # ignore this address family
            if route_family == RF_RTC_UC:
                continue

            self.req_rr_to_non_rtc_peers(route_family)
