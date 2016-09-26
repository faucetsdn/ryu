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
 Defines some model classes related BGP.

 These class include types used in saving information sent/received over BGP
 sessions.
"""
import abc
from abc import ABCMeta
from abc import abstractmethod
from copy import copy
import logging
import functools
import netaddr
import six

from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RouteTargetMembershipNLRI
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
from ryu.lib.packet.bgp import BGPPathAttributeLocalPref
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH

from ryu.services.protocols.bgp.base import OrderedDict
from ryu.services.protocols.bgp.constants import VPN_TABLE
from ryu.services.protocols.bgp.constants import VRF_TABLE
from ryu.services.protocols.bgp.model import OutgoingRoute
from ryu.services.protocols.bgp.processor import BPR_ONLY_PATH
from ryu.services.protocols.bgp.processor import BPR_UNKNOWN


LOG = logging.getLogger('bgpspeaker.info_base.base')


@six.add_metaclass(ABCMeta)
class Table(object):
    """A container for holding information about destination/prefixes.

    Routing information base for a particular afi/safi.
    This is a base class which should be sub-classed for different route
    family. A table can be uniquely identified by (Route Family, Scope Id).
    """
    ROUTE_FAMILY = RF_IPv4_UC

    def __init__(self, scope_id, core_service, signal_bus):
        self._destinations = dict()
        # Scope in which this table exists.
        # If this table represents the VRF, then this could be a VPN ID.
        # For global/VPN tables this should be None
        self._scope_id = scope_id
        self._signal_bus = signal_bus
        self._core_service = core_service

    @property
    def route_family(self):
        return self.__class__.ROUTE_FAMILY

    @property
    def core_service(self):
        return self._core_service

    @property
    def scope_id(self):
        return self._scope_id

    @abstractmethod
    def _create_dest(self, nlri):
        """Creates destination specific for this table.
        Returns destination that stores information of paths to *nlri*.
        """
        raise NotImplementedError()

    def values(self):
        return iter(self._destinations.values())

    def insert(self, path):
        self._validate_path(path)
        self._validate_nlri(path.nlri)
        if path.is_withdraw:
            updated_dest = self._insert_withdraw(path)
        else:
            updated_dest = self._insert_path(path)
        return updated_dest

    def insert_sent_route(self, sent_route):
        self._validate_path(sent_route.path)
        dest = self._get_or_create_dest(sent_route.path.nlri)
        dest.add_sent_route(sent_route)

    def _insert_path(self, path):
        """Add new path to destination identified by given prefix.
        """
        assert path.is_withdraw is False
        dest = self._get_or_create_dest(path.nlri)
        # Add given path to matching Dest.
        dest.add_new_path(path)
        # Return updated destination.
        return dest

    def _insert_withdraw(self, path):
        """Appends given path to withdraw list of Destination for given prefix.
        """
        assert path.is_withdraw is True
        dest = self._get_or_create_dest(path.nlri)
        # Add given path to matching destination.
        dest.add_withdraw(path)
        # Return updated destination.
        return dest

    def cleanup_paths_for_peer(self, peer):
        """Remove old paths from whose source is `peer`

        Old paths have source version number that is less than current peer
        version number. Also removes sent paths to this peer.
        """
        LOG.debug('Cleaning paths from table %s for peer %s', self, peer)
        for dest in self.values():
            # Remove paths learned from this source
            paths_deleted = dest.remove_old_paths_from_source(peer)
            # Remove sent paths to this peer
            had_sent = dest.remove_sent_route(peer)
            if had_sent:
                LOG.debug('Removed sent route %s for %s', dest.nlri, peer)
            # If any paths are removed we enqueue respective destination for
            # future processing.
            if paths_deleted:
                self._signal_bus.dest_changed(dest)

    def clean_uninteresting_paths(self, interested_rts):
        """Cleans table of any path that do not have any RT in common
         with `interested_rts`.
         Parameters:
             - `interested_rts`: (set) of RT that are of interest/that need to
             be preserved
        """
        LOG.debug('Cleaning table %s for given interested RTs %s',
                  self, interested_rts)
        uninteresting_dest_count = 0
        for dest in self.values():
            added_withdraw = \
                dest.withdraw_uninteresting_paths(interested_rts)
            if added_withdraw:
                self._signal_bus.dest_changed(dest)
                uninteresting_dest_count += 1
        return uninteresting_dest_count

    def delete_dest_by_nlri(self, nlri):
        """Deletes the destination identified by given prefix.

        Returns the deleted destination if a match is found. If not match is
        found return None.
        """
        self._validate_nlri(nlri)
        dest = self._get_dest(nlri)
        if dest:
            self._destinations.pop(dest)
        return dest

    def delete_dest(self, dest):
        del self._destinations[self._table_key(dest.nlri)]

    def _validate_nlri(self, nlri):
        """Validated *nlri* is the type that this table stores/supports.
        """
        if not nlri or not (nlri.ROUTE_FAMILY == self.route_family):
            raise ValueError('Invalid Vpnv4 prefix given.')

    def _validate_path(self, path):
        """Check if given path is an instance of *Path*.

        Raises ValueError if given is not a instance of *Path*.
        """
        if not path or not (path.route_family == self.route_family):
            raise ValueError('Invalid path. Expected instance of'
                             ' Vpnv4 route family path, got %s.' % path)

    def _get_or_create_dest(self, nlri):
        table_key = self._table_key(nlri)
        dest = self._destinations.get(table_key)
        # If destination for given prefix does not exist we create it.
        if dest is None:
            dest = self._create_dest(nlri)
            self._destinations[table_key] = dest
        return dest

    def _get_dest(self, nlri):
        table_key = self._table_key(nlri)
        dest = self._destinations.get(table_key)
        return dest

    def is_for_vrf(self):
        """Returns true if this table instance represents a VRF.
        """
        return self.scope_id is not None

    def __str__(self):
        return 'Table(scope_id: %s, rf: %s)' % (self.scope_id,
                                                self.route_family)

    @abstractmethod
    def _table_key(self, nlri):
        """Return a key that will uniquely identify this NLRI inside
        this table.
        """
        raise NotImplementedError()


class NonVrfPathProcessingMixin(object):
    """Mixin reacting to best-path selection algorithm on main table
    level. Intended to use with "Destination" subclasses.
    Applies to most of Destinations except for VrfDest
    because they are processed at VRF level, so different logic applies.
    """

    def __init__(self):
        self._core_service = None  # not assigned yet
        self._known_path_list = []

    def _best_path_lost(self):
        self._best_path = None

        if self._sent_routes:
            # We have to send update-withdraw to all peers to whom old best
            # path was sent.
            for sent_route in self._sent_routes.values():
                sent_path = sent_route.path
                withdraw_clone = sent_path.clone(for_withdrawal=True)
                outgoing_route = OutgoingRoute(withdraw_clone)
                sent_route.sent_peer.enque_outgoing_msg(outgoing_route)
                LOG.debug('Sending withdrawal to %s for %s',
                          sent_route.sent_peer, outgoing_route)

            # Have to clear sent_route list for this destination as
            # best path is removed.
            self._sent_routes = {}

    def _new_best_path(self, new_best_path):
        old_best_path = self._best_path
        self._best_path = new_best_path
        LOG.debug('New best path selected for destination %s', self)

        # If old best path was withdrawn
        if (old_best_path and
                old_best_path not in self._known_path_list and
                self._sent_routes):
            # Have to clear sent_route list for this destination as
            # best path is removed.
            self._sent_routes = {}

        # Communicate that we have new best path to all qualifying
        # bgp-peers.
        pm = self._core_service.peer_manager
        pm.comm_new_best_to_bgp_peers(new_best_path)

        # withdraw old best path
        if old_best_path and self._sent_routes:
            for sent_route in self._sent_routes.values():
                sent_path = sent_route.path
                withdraw_clone = sent_path.clone(for_withdrawal=True)
                outgoing_route = OutgoingRoute(withdraw_clone)
                sent_route.sent_peer.enque_outgoing_msg(outgoing_route)
                LOG.debug('Sending withdrawal to %s for %s',
                          sent_route.sent_peer, outgoing_route)
                self._sent_routes = {}


@six.add_metaclass(ABCMeta)
class Destination(object):
    """State about a particular destination.

    For example, an IP prefix. This is the data-structure that is hung of the
    a routing information base table *Table*.
    """

    ROUTE_FAMILY = RF_IPv4_UC

    def __init__(self, table, nlri):
        # Validate arguments.
        if table.route_family != self.__class__.ROUTE_FAMILY:
            raise ValueError('Table and destination route family '
                             'do not match.')

        # Back-pointer to the table that contains this destination.
        self._table = table

        self._core_service = table.core_service

        self._nlri = nlri

        # List of all known processed paths,
        self._known_path_list = []

        # List of new un-processed paths.
        self._new_path_list = []

        # Pointer to best-path. One from the the known paths.
        self._best_path = None

        # Reason current best path was chosen as best path.
        self._best_path_reason = None

        # List of withdrawn paths.
        self._withdraw_list = []

        # List of SentRoute objects. This is the Adj-Rib-Out for this
        # destination. (key/value: peer/sent_route)
        self._sent_routes = {}

        # This is an (optional) list of paths that were created as a
        # result of exporting this route to other tables.
        # self.exported_paths = None

        # Automatically generated
        #
        # On work queue for BGP processor.
        # self.next_dest_to_process
        # self.prev_dest_to_process

    @property
    def route_family(self):
        return self.__class__.ROUTE_FAMILY

    @property
    def nlri(self):
        return self._nlri

    @property
    def nlri_str(self):
        return self._nlri.formatted_nlri_str

    @property
    def best_path(self):
        return self._best_path

    @property
    def best_path_reason(self):
        return self._best_path_reason

    @property
    def known_path_list(self):
        return self._known_path_list[:]

    @property
    def sent_routes(self):
        return list(self._sent_routes.values())

    def add_new_path(self, new_path):
        self._validate_path(new_path)
        self._new_path_list.append(new_path)

    def add_withdraw(self, withdraw):
        self._validate_path(withdraw)
        self._withdraw_list.append(withdraw)

    def add_sent_route(self, sent_route):
        self._sent_routes[sent_route.sent_peer] = sent_route

    def remove_sent_route(self, peer):
        if self.was_sent_to(peer):
            del self._sent_routes[peer]
            return True
        return False

    def was_sent_to(self, peer):
        if peer in self._sent_routes.keys():
            return True
        return False

    def _process(self):
        """Calculate best path for this destination.

        A destination is processed when known paths to this destination has
        changed. We might have new paths or withdrawals of last known paths.
        Removes withdrawals and adds new learned paths from known path list.
        Uses bgp best-path calculation algorithm on new list of known paths to
        choose new best-path. Communicates best-path to core service.
        """
        LOG.debug('Processing destination: %s', self)
        new_best_path, reason = self._process_paths()
        self._best_path_reason = reason

        if self._best_path == new_best_path:
            return

        if new_best_path is None:
            # we lost best path
            assert not self._known_path_list, repr(self._known_path_list)
            return self._best_path_lost()
        else:
            return self._new_best_path(new_best_path)

    @abstractmethod
    def _best_path_lost(self):
        raise NotImplementedError()

    @abstractmethod
    def _new_best_path(self, new_best_path):
        raise NotImplementedError()

    @classmethod
    def _validate_path(cls, path):
        if not path or path.route_family != cls.ROUTE_FAMILY:
            raise ValueError(
                'Invalid path. Expected %s path got %s' %
                (cls.ROUTE_FAMILY, path)
            )

    def process(self):
        self._process()
        if not self._known_path_list and not self._best_path:
            self._remove_dest_from_table()

    def _remove_dest_from_table(self):
        self._table.delete_dest(self)

    def remove_old_paths_from_source(self, source):
        """Removes known old paths from *source*.

        Returns *True* if any of the known paths were found to be old and
        removed/deleted.
        """
        assert(source and hasattr(source, 'version_num'))
        removed_paths = []
        # Iterate over the paths in reverse order as we want to delete paths
        # whose source is this peer.
        source_ver_num = source.version_num
        for path_idx in range(len(self._known_path_list) - 1, -1, -1):
            path = self._known_path_list[path_idx]
            if (path.source == source and
                    path.source_version_num < source_ver_num):
                # If this peer is source of any paths, remove those path.
                del(self._known_path_list[path_idx])
                removed_paths.append(path)
        return removed_paths

    def withdraw_if_sent_to(self, peer):
        """Sends a withdraw for this destination to given `peer`.

        Check the records if we indeed advertise this destination to given peer
        and if so, creates a withdraw for advertised route and sends it to the
        peer.
        Parameter:
            - `peer`: (Peer) peer to send withdraw to
        """
        from ryu.services.protocols.bgp.peer import Peer
        if not isinstance(peer, Peer):
            raise TypeError('Currently we only support sending withdrawal'
                            ' to instance of peer')
        sent_route = self._sent_routes.pop(peer, None)
        if not sent_route:
            return False

        sent_path = sent_route.path
        withdraw_clone = sent_path.clone(for_withdrawal=True)
        outgoing_route = OutgoingRoute(withdraw_clone)
        sent_route.sent_peer.enque_outgoing_msg(outgoing_route)
        return True

    def _process_paths(self):
        """Calculates best-path among known paths for this destination.

        Returns:
         - Best path

        Modifies destination's state related to stored paths. Removes withdrawn
        paths from known paths. Also, adds new paths to known paths.
        """
        # First remove the withdrawn paths.
        # Note: If we want to support multiple paths per destination we may
        # have to maintain sent-routes per path.
        self._remove_withdrawals()

        # Have to select best-path from available paths and new paths.
        # If we do not have any paths, then we no longer have best path.
        if not self._known_path_list and len(self._new_path_list) == 1:
            # If we do not have any old but one new path
            # it becomes best path.
            self._known_path_list.append(self._new_path_list[0])
            del(self._new_path_list[0])
            return self._known_path_list[0], BPR_ONLY_PATH

        # If we have a new version of old/known path we use it and delete old
        # one.
        self._remove_old_paths()

        # Collect all new paths into known paths.
        self._known_path_list.extend(self._new_path_list)

        # Clear new paths as we copied them.
        del(self._new_path_list[:])

        # If we do not have any paths to this destination, then we do not have
        # new best path.
        if not self._known_path_list:
            return None, BPR_UNKNOWN

        # Compute new best path
        current_best_path, reason = self._compute_best_known_path()
        return current_best_path, reason

    def _remove_withdrawals(self):
        """Removes withdrawn paths.

        Note:
        We may have disproportionate number of withdraws compared to know paths
        since not all paths get installed into the table due to bgp policy and
        we can receive withdraws for such paths and withdrawals may not be
        stopped by the same policies.
        """

        LOG.debug('Removing %s withdrawals', len(self._withdraw_list))

        # If we have no withdrawals, we have nothing to do.
        if not self._withdraw_list:
            return

        # If we have some withdrawals and no know-paths, it means it is safe to
        # delete these withdraws.
        if not self._known_path_list:
            LOG.debug('Found %s withdrawals for path(s) that did not get'
                      ' installed.', len(self._withdraw_list))
            del(self._withdraw_list[:])
            return

        # If we have some known paths and some withdrawals, we find matches and
        # delete them first.
        matches = set()
        w_matches = set()
        # Match all withdrawals from destination paths.
        for withdraw in self._withdraw_list:
            match = None
            for path in self._known_path_list:
                # We have a match if the source are same.
                if path.source == withdraw.source:
                    match = path
                    matches.add(path)
                    w_matches.add(withdraw)
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
                if new_path.source == path.source:
                    old_paths.append(path)
                    break

            for old_path in old_paths:
                known_paths.remove(old_path)
                LOG.debug('Implicit withdrawal of old path, since we have'
                          ' learned new path from same source: %s', old_path)

    def _compute_best_known_path(self):
        """Computes the best path among known paths.

        Returns current best path among `known_paths`.
        """
        if not self._known_path_list:
            from ryu.services.protocols.bgp.processor import BgpProcessorError
            raise BgpProcessorError(desc='Need at-least one known path to'
                                    ' compute best path')

        # We pick the first path as current best path. This helps in breaking
        # tie between two new paths learned in one cycle for which best-path
        # calculation steps lead to tie.
        current_best_path = self._known_path_list[0]
        best_path_reason = BPR_ONLY_PATH
        for next_path in self._known_path_list[1:]:
            from ryu.services.protocols.bgp.processor import compute_best_path
            # Compare next path with current best path.
            new_best_path, reason = \
                compute_best_path(self._core_service.asn, current_best_path,
                                  next_path)
            best_path_reason = reason
            if new_best_path is not None:
                current_best_path = new_best_path

        return current_best_path, best_path_reason

    def withdraw_uninteresting_paths(self, interested_rts):
        """Withdraws paths that are no longer interesting.

        For all known paths that do not have any route target in common with
        given `interested_rts` we add a corresponding withdraw.

        Returns True if we added any withdraws.
        """
        add_withdraws = False
        for path in self._known_path_list:
            if not path.has_rts_in(interested_rts):
                self.withdraw_path(path)
                add_withdraws = True
        return add_withdraws

    def withdraw_path(self, path):
        if path not in self.known_path_list:
            raise ValueError("Path not known, no need to withdraw")
        withdraw = path.clone(for_withdrawal=True)
        self._withdraw_list.append(withdraw)

    def to_dict(self):
        return {'table': str(self._table),
                'nlri': str(self._nlri),
                'paths': self._known_path_list[:],
                'withdraws': self._get_num_withdraws()}

    def __str__(self):
        return ('Destination(table: %s, nlri: %s, paths: %s, withdraws: %s,'
                ' new paths: %s)' % (self._table, str(self._nlri),
                                     len(self._known_path_list),
                                     len(self._withdraw_list),
                                     len(self._new_path_list)))

    def _get_num_valid_paths(self):
        return len(self._known_path_list)

    def _get_num_withdraws(self):
        return len(self._withdraw_list)

    def sent_routes_by_peer(self, peer):
        """get sent routes corresponding to specified peer.

        Returns SentRoute list.
        """
        result = []
        for route in self._sent_routes.values():
            if route.sent_peer == peer:
                result.append(route)

        return result

    def __lt__(self, other):
        return str(self) < str(other)

    def __le__(self, other):
        return str(self) <= str(other)

    def __eq__(self, other):
        return str(self) == str(other)

    def __ne__(self, other):
        return str(self) != str(other)

    def __gt__(self, other):
        return str(self) > str(other)

    def __ge__(self, other):
        return str(self) >= str(other)


@six.add_metaclass(ABCMeta)
class Path(object):
    """Represents a way of reaching an IP destination.

    Also contains other meta-data given to us by a specific source (such as a
    peer).
    """
    __slots__ = ('_source', '_path_attr_map', '_nlri', '_source_version_num',
                 '_exported_from', '_nexthop', 'next_path', 'prev_path',
                 '_is_withdraw', 'med_set_by_target_neighbor')
    ROUTE_FAMILY = RF_IPv4_UC

    def __init__(self, source, nlri, src_ver_num, pattrs=None, nexthop=None,
                 is_withdraw=False, med_set_by_target_neighbor=False):
        """Initializes Ipv4 path.

        If this path is not a withdraw, then path attribute and nexthop both
        should be provided.
        Parameters:
            - `source`: (Peer/str) source of this path.
            - `nlri`: (Vpnv4) Nlri instance for Vpnv4 route family.
            - `src_ver_num`: (int) version number of *source* when this path
            was learned.
            - `pattrs`: (OrderedDict) various path attributes for this path.
            - `nexthop`: (str) nexthop advertised for this path.
            - `is_withdraw`: (bool) True if this represents a withdrawal.
        """
        self.med_set_by_target_neighbor = med_set_by_target_neighbor
        if nlri.ROUTE_FAMILY != self.__class__.ROUTE_FAMILY:
            raise ValueError('NLRI and Path route families do not'
                             ' match (%s, %s).' %
                             (nlri.ROUTE_FAMILY, self.__class__.ROUTE_FAMILY))

        # Currently paths injected directly into VRF has only one source
        # src_peer can be None to denote NC else has to be instance of Peer.
        # Paths can be exported from one VRF and then imported into another
        # VRF, in such cases it source is denoted as string VPN_TABLE.
        if not (source is None or
                hasattr(source, 'version_num') or
                source in (VRF_TABLE, VPN_TABLE)):
            raise ValueError('Invalid or Unsupported source for path: %s' %
                             source)

        # If this path is not a withdraw path, than it should have path-
        # attributes and nexthop.
        if not is_withdraw and not (pattrs and nexthop):
            raise ValueError('Need to provide nexthop and patattrs '
                             'for path that is not a withdraw.')

        # The entity (peer) that gave us this path.
        self._source = source

        # Path attribute of this path.
        if pattrs:
            self._path_attr_map = copy(pattrs)
        else:
            self._path_attr_map = OrderedDict()

        # NLRI that this path represents.
        self._nlri = nlri

        # If given nlri is withdrawn.
        self._is_withdraw = is_withdraw

        # @see Source.version_num
        self._source_version_num = src_ver_num

        self._nexthop = nexthop

        # Automatically generated.
        #
        # self.next_path
        # self.prev_path

        # The Destination from which this path was exported, if any.
        self._exported_from = None

    @property
    def source_version_num(self):
        return self._source_version_num

    @property
    def source(self):
        return self._source

    @property
    def route_family(self):
        return self.__class__.ROUTE_FAMILY

    @property
    def nlri(self):
        return self._nlri

    @property
    def nlri_str(self):
        return self._nlri.formatted_nlri_str

    @property
    def is_withdraw(self):
        return self._is_withdraw

    @property
    def pathattr_map(self):
        return copy(self._path_attr_map)

    @property
    def nexthop(self):
        return self._nexthop

    def get_pattr(self, pattr_type, default=None):
        """Returns path attribute of given type.

        Returns None if we do not attribute of type *pattr_type*.
        """
        return self._path_attr_map.get(pattr_type, default)

    def clone(self, for_withdrawal=False):
        pathattrs = None
        if not for_withdrawal:
            pathattrs = self.pathattr_map
        clone = self.__class__(
            self.source,
            self.nlri,
            self.source_version_num,
            pattrs=pathattrs,
            nexthop=self.nexthop,
            is_withdraw=for_withdrawal
        )
        return clone

    def get_rts(self):
        extcomm_attr = self._path_attr_map.get(
            BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
        if extcomm_attr is None:
            rts = []
        else:
            rts = extcomm_attr.rt_list
        return rts

    def has_rts_in(self, interested_rts):
        """Returns True if this `Path` has any `ExtCommunity` attribute
        route target common with `interested_rts`.
        """
        assert isinstance(interested_rts, set)
        curr_rts = self.get_rts()
        # Add default RT to path RTs so that we match interest for peers who
        # advertised default RT
        curr_rts.append(RouteTargetMembershipNLRI.DEFAULT_RT)

        return not interested_rts.isdisjoint(curr_rts)

    def is_local(self):
        return self._source is None

    def has_nexthop(self):
        return not (not self._nexthop or self._nexthop == '0.0.0.0' or
                    self._nexthop == '::')

    def __str__(self):
        return (
            'Path(source: %s, nlri: %s, source ver#: %s, '
            'path attrs.: %s, nexthop: %s, is_withdraw: %s)' %
            (
                self._source, self._nlri, self._source_version_num,
                self._path_attr_map, self._nexthop, self._is_withdraw
            )
        )

    def __repr__(self):
        return ('Path(%s, %s, %s, %s, %s, %s)' % (
            self._source, self._nlri, self._source_version_num,
            self._path_attr_map, self._nexthop, self._is_withdraw))


@six.add_metaclass(ABCMeta)
class Filter(object):
    """Represents a general filter for in-bound and out-bound filter

    ================ ==================================================
    Attribute        Description
    ================ ==================================================
    policy           Filter.POLICY_PERMIT or Filter.POLICY_DENY
    ================ ==================================================
    """

    ROUTE_FAMILY = RF_IPv4_UC

    POLICY_DENY = 0
    POLICY_PERMIT = 1

    def __init__(self, policy=POLICY_DENY):
        self._policy = policy

    @property
    def policy(self):
        return self._policy

    @abstractmethod
    def evaluate(self, path):
        """ This method evaluates the path.

        Returns this object's policy and the result of matching.
        If the specified prefix matches this object's prefix and
        ge and le condition,
        this method returns True as the matching result.

        ``path`` specifies the path. prefix must be string.
        """
        raise NotImplementedError()

    @abstractmethod
    def clone(self):
        """ This method clones Filter object.

        Returns Filter object that has the same values with the original one.
        """
        raise NotImplementedError()


@functools.total_ordering
class PrefixFilter(Filter):
    """
    Used to specify a prefix for filter.

    We can create PrefixFilter object as follows::

        prefix_filter = PrefixFilter('10.5.111.0/24',
                                     policy=PrefixFilter.POLICY_PERMIT)

    ================ ==================================================
    Attribute        Description
    ================ ==================================================
    prefix           A prefix used for this filter
    policy           One of the following values.

                     | PrefixFilter.POLICY.PERMIT
                     | PrefixFilter.POLICY_DENY
    ge               Prefix length that will be applied to this filter.
                     ge means greater than or equal.
    le               Prefix length that will be applied to this filter.
                     le means less than or equal.
    ================ ==================================================

    For example, when PrefixFilter object is created as follows::

        p = PrefixFilter('10.5.111.0/24',
                         policy=PrefixFilter.POLICY_DENY,
                         ge=26, le=28)

    Prefixes which match 10.5.111.0/24 and its length matches
    from 26 to 28 will be filtered.
    When this filter is used as an out-filter, it will stop sending
    the path to neighbor because of POLICY_DENY.
    When this filter is used as in-filter, it will stop importing the path
    to the global rib because of POLICY_DENY.
    If you specify POLICY_PERMIT, the path is sent to neighbor or imported to
    the global rib.

    If you don't want to send prefixes 10.5.111.64/26 and 10.5.111.32/27
    and 10.5.111.16/28, and allow to send other 10.5.111.0's prefixes,
    you can do it by specifying as follows::

        p = PrefixFilter('10.5.111.0/24',
                         policy=PrefixFilter.POLICY_DENY,
                         ge=26, le=28).
    """

    def __init__(self, prefix, policy, ge=None, le=None):
        super(PrefixFilter, self).__init__(policy)
        self._prefix = prefix
        self._network = netaddr.IPNetwork(prefix)
        self._ge = ge
        self._le = le

    def __lt__(self, other):
        return self._network < other._network

    def __eq__(self, other):
        return self._network == other._network

    def __repr__(self):
        policy = 'PERMIT' \
            if self._policy == self.POLICY_PERMIT else 'DENY'

        return 'PrefixFilter(prefix=%s,policy=%s,ge=%s,le=%s)'\
               % (self._prefix, policy, self._ge, self._le)

    @property
    def prefix(self):
        return self._prefix

    @property
    def policy(self):
        return self._policy

    @property
    def ge(self):
        return self._ge

    @property
    def le(self):
        return self._le

    def evaluate(self, path):
        """ This method evaluates the prefix.

        Returns this object's policy and the result of matching.
        If the specified prefix matches this object's prefix and
        ge and le condition,
        this method returns True as the matching result.

        ``path`` specifies the path that has prefix.
        """
        nlri = path.nlri

        result = False
        length = nlri.length
        net = netaddr.IPNetwork(nlri.prefix)

        if net in self._network:
            if self._ge is None and self._le is None:
                result = True

            elif self._ge is None and self._le:
                if length <= self._le:
                    result = True

            elif self._ge and self._le is None:
                if self._ge <= length:
                    result = True

            elif self._ge and self._le:
                if self._ge <= length <= self._le:
                    result = True

        return self.policy, result

    def clone(self):
        """ This method clones PrefixFilter object.

        Returns PrefixFilter object that has the same values with the
        original one.
        """

        return self.__class__(self.prefix,
                              policy=self._policy,
                              ge=self._ge,
                              le=self._le)


@functools.total_ordering
class ASPathFilter(Filter):
    """
    Used to specify a prefix for AS_PATH attribute.

    We can create ASPathFilter object as follows::

        as_path_filter = ASPathFilter(65000,policy=ASPathFilter.TOP)

    ================ ==================================================
    Attribute        Description
    ================ ==================================================
    as_number        A AS number used for this filter
    policy           One of the following values.

                     | ASPathFilter.POLICY_TOP
                     | ASPathFilter.POLICY_END
                     | ASPathFilter.POLICY_INCLUDE
                     | ASPathFilter.POLICY_NOT_INCLUDE
    ================ ==================================================

    Meaning of each policy is as follows:

    * POLICY_TOP
        Filter checks if the specified AS number is at the top of
        AS_PATH attribute.

    * POLICY_END
        Filter checks is the specified AS number
        is at the last of AS_PATH attribute.

    * POLICY_INCLUDE
        Filter checks if specified AS number
        exists in AS_PATH attribute

    * POLICY_NOT_INCLUDE
        Opposite to POLICY_INCLUDE
    """

    POLICY_TOP = 2
    POLICY_END = 3
    POLICY_INCLUDE = 4
    POLICY_NOT_INCLUDE = 5

    def __init__(self, as_number, policy):
        super(ASPathFilter, self).__init__(policy)
        self._as_number = as_number

    def __lt__(self, other):
        return self.as_number < other.as_number

    def __eq__(self, other):
        return self.as_number == other.as_number

    def __repr__(self):
        policy = 'TOP'
        if self._policy == self.POLICY_INCLUDE:
            policy = 'INCLUDE'
        elif self._policy == self.POLICY_NOT_INCLUDE:
            policy = 'NOT_INCLUDE'
        elif self._policy == self.POLICY_END:
            policy = 'END'

        return 'ASPathFilter(as_number=%s,policy=%s)'\
               % (self._as_number, policy)

    @property
    def as_number(self):
        return self._as_number

    @property
    def policy(self):
        return self._policy

    def evaluate(self, path):
        """ This method evaluates as_path list.

        Returns this object's policy and the result of matching.
        If the specified AS number matches this object's AS number
        according to the policy,
        this method returns True as the matching result.

        ``path`` specifies the path.
        """

        path_aspath = path.pathattr_map.get(BGP_ATTR_TYPE_AS_PATH)
        path_seg_list = path_aspath.path_seg_list
        if path_seg_list:
            path_seg = path_seg_list[0]
        else:
            path_seg = []
        result = False

        LOG.debug("path_seg : %s", path_seg)
        if self.policy == ASPathFilter.POLICY_TOP:

            if len(path_seg) > 0 and path_seg[0] == self._as_number:
                result = True

        elif self.policy == ASPathFilter.POLICY_INCLUDE:
            for aspath in path_seg:
                LOG.debug("POLICY_INCLUDE as_number : %s", aspath)
                if aspath == self._as_number:
                    result = True
                    break

        elif self.policy == ASPathFilter.POLICY_END:

            if len(path_seg) > 0 and path_seg[-1] == self._as_number:
                result = True

        elif self.policy == ASPathFilter.POLICY_NOT_INCLUDE:

            if self._as_number not in path_seg:
                result = True

        return self.policy, result

    def clone(self):
        """ This method clones ASPathFilter object.

        Returns ASPathFilter object that has the same values with the
        original one.
        """

        return self.__class__(self._as_number,
                              policy=self._policy)


class AttributeMap(object):
    """
    This class is used to specify an attribute to add if the path matches
    filters.
    We can create AttributeMap object as follows::

        pref_filter = PrefixFilter('192.168.103.0/30',
                                   PrefixFilter.POLICY_PERMIT)

        attribute_map = AttributeMap([pref_filter],
                                     AttributeMap.ATTR_LOCAL_PREF, 250)

        speaker.attribute_map_set('192.168.50.102', [attribute_map])

    AttributeMap.ATTR_LOCAL_PREF means that 250 is set as a
    local preference value if nlri in the path matches pref_filter.

    ASPathFilter is also available as a filter. ASPathFilter checks if AS_PATH
    attribute in the path matches AS number in the filter.

    =================== ==================================================
    Attribute           Description
    =================== ==================================================
    filters             A list of filter.
                        Each object should be a Filter class or its sub-class
    attr_type           A type of attribute to map on filters. Currently
                        AttributeMap.ATTR_LOCAL_PREF is available.
    attr_value          A attribute value
    =================== ==================================================
    """

    ATTR_LOCAL_PREF = '_local_pref'

    def __init__(self, filters, attr_type, attr_value):

        assert all(isinstance(f, Filter) for f in filters),\
            'all the items in filters must be an instance of Filter sub-class'
        self.filters = filters
        self.attr_type = attr_type
        self.attr_value = attr_value

    def evaluate(self, path):
        """ This method evaluates attributes of the path.

        Returns the cause and result of matching.
        Both cause and result are returned from filters
        that this object contains.

        ``path`` specifies the path.
        """
        result = False
        cause = None

        for f in self.filters:

            cause, result = f.evaluate(path)
            if not result:
                break

        return cause, result

    def get_attribute(self):
        func = getattr(self, 'get' + self.attr_type)
        return func()

    def get_local_pref(self):
        local_pref_attr = BGPPathAttributeLocalPref(value=self.attr_value)
        return local_pref_attr

    def clone(self):
        """ This method clones AttributeMap object.

        Returns AttributeMap object that has the same values with the
        original one.
        """

        cloned_filters = [f.clone() for f in self.filters]
        return self.__class__(cloned_filters, self.attr_type, self.attr_value)

    def __repr__(self):

        attr_type = 'LOCAL_PREF'\
            if self.attr_type == self.ATTR_LOCAL_PREF else None

        filter_string = ','.join(repr(f) for f in self.filters)
        return ('AttributeMap(filters=[%s],'
                'attribute_type=%s,'
                'attribute_value=%s)' % (filter_string,
                                         attr_type,
                                         self.attr_value))
