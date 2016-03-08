import logging
import netaddr
from collections import OrderedDict

from ryu.services.protocols.bgp.base import SUPPORTED_GLOBAL_RF
from ryu.services.protocols.bgp.info_base.rtc import RtcTable
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Path
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Table
from ryu.services.protocols.bgp.info_base.ipv6 import Ipv6Path
from ryu.services.protocols.bgp.info_base.ipv6 import Ipv6Table
from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Path
from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Table
from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Path
from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Table
from ryu.services.protocols.bgp.info_base.vrf4 import Vrf4Table
from ryu.services.protocols.bgp.info_base.vrf6 import Vrf6Table
from ryu.services.protocols.bgp.rtconf import vrfs
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV6

from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import BGPPathAttributeOrigin
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_IGP
from ryu.lib.packet.bgp import IPAddrPrefix
from ryu.lib.packet.bgp import IP6AddrPrefix

from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4_prefix
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv6
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv6_prefix


LOG = logging.getLogger('bgpspeaker.core_managers.table_mixin')


class TableCoreManager(object):
    """Methods performing core operations on tables."""

    def __init__(self, core_service, common_conf):

        self._tables = {}
        self._rt_mgr = core_service.rt_manager
        self._signal_bus = core_service.signal_bus

        # (VRF) Tables to which the routes with a given route target
        # should be imported.
        #
        # Key: RouteTarget
        # Value: List of tables.
        self._tables_for_rt = {}

        # Global/Default tables, keyed by RouteFamily.
        self._global_tables = {}

        self._core_service = core_service
        self._signal_bus = self._core_service.signal_bus

        # VPN label range
        self._asbr_label_range = common_conf.label_range

        self._next_vpnv4_label = int(self._asbr_label_range[0])

        self._next_hop_label = {}

    @property
    def global_tables(self):
        return self._global_tables

    def remove_vrf_by_vrf_conf(self, vrf_conf):

        route_family = vrf_conf.route_family
        assert route_family in (vrfs.VRF_RF_IPV4, vrfs.VRF_RF_IPV6)
        table_id = (vrf_conf.route_dist, route_family)

        vrf_table = self._tables.pop(table_id)

        self._remove_links_to_vrf_table(vrf_table)

        # Withdraw the best-path whose source was NC since it may have been
        # exported to VPN table.
        for destination in vrf_table.values():
            best_path = destination.best_path
            if best_path and best_path.source is None:
                vpn_clone = best_path.clone_to_vpn(vrf_conf.route_dist,
                                                   for_withdrawal=True)
                self.learn_path(vpn_clone)
        LOG.debug('VRF with RD %s marked for removal', vrf_conf.route_dist)

    def import_all_vpn_paths_to_vrf(self, vrf_table, import_rts=None):
        """Imports Vpnv4/6 paths from Global/VPN table into given Vrfv4/6
         table.
        :param vrf_table: Vrf table to which we import
        :type vrf_table: VrfTable
        :param import_rts: import RTs to override default import_rts of
         vrf table for this import
        :type import_rts: set of strings


        Checks if we have any path RT common with VRF table's import RT.
        """
        rfs = (Vrf4Table.ROUTE_FAMILY, Vrf6Table.ROUTE_FAMILY)
        assert vrf_table.route_family in rfs, 'Invalid VRF table.'

        if vrf_table.route_family == Vrf4Table.ROUTE_FAMILY:
            vpn_table = self.get_vpn4_table()
        else:
            vpn_table = self.get_vpn6_table()

        vrf_table.import_vpn_paths_from_table(vpn_table, import_rts)

    def learn_path(self, path):
        """Inserts `path` into correct global table.

        Since known paths to `Destination` has changes, we queue it for further
        processing.
        """
        # Get VPN/Global table
        table = self.get_global_table_by_route_family(path.route_family)
        gpath_dest = table.insert(path)
        # Since destination was updated, we enqueue it for processing.
        self._signal_bus.dest_changed(gpath_dest)

    def remember_sent_route(self, sent_route):
        """Records `sent_route` inside proper table.

        Records of `sent_route` from Adj-RIB-out.
        """
        route_family = sent_route.path.route_family
        table = self.get_global_table_by_route_family(route_family)
        table.insert_sent_route(sent_route)

    def on_interesting_rts_change(self, new_global_rts, removed_global_rts):
        """Update global tables as interested RTs changed.

        Adds `new_rts` and removes `removed_rts` rt nlris. Does not check if
        `new_rts` or `removed_rts` are already present. Schedules refresh
        request to peers that do not participate in RTC address-family.
        """
        # We add new RT NLRI and request RR for other peers.
        if new_global_rts:
            LOG.debug(
                'Sending route_refresh to all neighbors that'
                ' did not negotiate RTC capability.'
            )

            pm = self._core_service.peer_manager
            pm.schedule_rr_to_non_rtc_peers()
        if removed_global_rts:
            LOG.debug(
                'Cleaning up global tables as some interested RTs were removed'
            )
            self._clean_global_uninteresting_paths()

    def get_global_table_by_route_family(self, route_family):
        if route_family not in SUPPORTED_GLOBAL_RF:
            raise ValueError(
                'Given route family: %s currently not supported' % route_family
            )

        global_table = None
        if route_family == RF_IPv4_UC:
            global_table = self.get_ipv4_table()
        elif route_family == RF_IPv6_UC:
            global_table = self.get_ipv6_table()
        elif route_family == RF_IPv4_VPN:
            global_table = self.get_vpn4_table()

        elif route_family == RF_IPv6_VPN:
            global_table = self.get_vpn6_table()

        elif route_family == RF_RTC_UC:
            global_table = self.get_rtc_table()

        return global_table

    def get_vrf_table(self, vrf_rd, vrf_rf):
        assert vrf_rd is not None
        return self._tables.get((vrf_rd, vrf_rf))

    def get_vrf_tables(self, vrf_rf=None):
        vrf_tables = {}
        for (scope_id, table_id), table in self._tables.items():
            if scope_id is None:
                continue
            if vrf_rf is not None and table_id != vrf_rf:
                continue
            vrf_tables[(scope_id, table_id)] = table
        return vrf_tables

    def get_ipv4_table(self):
        """Returns global IPv4 table.

        Creates the table if it does not exist.
        """

        vpn_table = self._global_tables.get(RF_IPv4_UC)
        # Lazy initialize the table.
        if not vpn_table:
            vpn_table = Ipv4Table(self._core_service, self._signal_bus)
            self._global_tables[RF_IPv4_UC] = vpn_table
            self._tables[(None, RF_IPv4_UC)] = vpn_table

        return vpn_table

    def get_ipv6_table(self):
        table = self._global_tables.get(RF_IPv6_UC)
        if not table:
            table = Ipv6Table(self._core_service, self._signal_bus)
            self._global_tables[RF_IPv6_UC] = table
            self._tables[(None, RF_IPv6_UC)] = table
        return table

    def get_vpn6_table(self):
        """Returns global VPNv6 table.

        Creates the table if it does not exist.
        """
        vpn_table = self._global_tables.get(RF_IPv6_VPN)
        # Lazy initialize the table.
        if not vpn_table:
            vpn_table = Vpnv6Table(self._core_service, self._signal_bus)
            self._global_tables[RF_IPv6_VPN] = vpn_table
            self._tables[(None, RF_IPv6_VPN)] = vpn_table

        return vpn_table

    def get_vpn4_table(self):
        """Returns global VPNv6 table.

        Creates the table if it does not exist.
        """
        vpn_table = self._global_tables.get(RF_IPv4_VPN)
        # Lazy initialize the table.
        if not vpn_table:
            vpn_table = Vpnv4Table(self._core_service, self._signal_bus)
            self._global_tables[RF_IPv4_VPN] = vpn_table
            self._tables[(None, RF_IPv4_VPN)] = vpn_table

        return vpn_table

    def get_rtc_table(self):
        """Returns global RTC table.

        Creates the table if it does not exist.
        """
        rtc_table = self._global_tables.get(RF_RTC_UC)
        # Lazy initialization of the table.
        if not rtc_table:
            rtc_table = RtcTable(self._core_service, self._signal_bus)
            self._global_tables[RF_RTC_UC] = rtc_table
            self._tables[(None, RF_RTC_UC)] = rtc_table
        return rtc_table

    def get_next_vpnv4_label(self):
        # Get next available label
        lbl = self._next_vpnv4_label
        # Check if label is within max. range allowed.
        if lbl > int(self._asbr_label_range[1]):
            # Currently we log error message if we exceed configured range.
            message = 'Have reached max label range'
            LOG.error(message)
            raise ValueError(message)
            # Increment label by 1 as next label.
        self._next_vpnv4_label += 1
        return lbl

    def get_nexthop_label(self, label_key):
        return self._next_hop_label.get(label_key, None)

    def set_nexthop_label(self, key, value):
        self._next_hop_label[key] = value

    def update_vrf_table_links(self, vrf_table, new_imp_rts,
                               removed_imp_rts):
        """Update mapping from RT to VRF table."""
        assert vrf_table
        if new_imp_rts:
            self._link_vrf_table(vrf_table, new_imp_rts)
        if removed_imp_rts:
            self._remove_links_to_vrf_table_for_rts(vrf_table,
                                                    removed_imp_rts)

    def re_install_net_ctrl_paths(self, vrf_table):
        """Re-installs paths from NC with current BGP policy.

        Iterates over known paths from NC installed in `vrf4_table` and
        adds new path with path attributes as per current VRF configuration.
        """
        assert vrf_table
        for dest in vrf_table.values():
            for path in dest.known_path_list:
                if path.source is None:
                    vrf_table.insert_vrf_path(
                        path.nlri,
                        path.nexthop,
                        gen_lbl=True
                    )
        LOG.debug('Re-installed NC paths with current policy for table %s.',
                  vrf_table)

    def _remove_links_to_vrf_table(self, vrf_table):
        """Removes any links to given `vrf_table`."""
        assert vrf_table
        vrf_conf = vrf_table.vrf_conf
        self._remove_links_to_vrf_table_for_rts(vrf_table,
                                                vrf_conf.import_rts)

    def _remove_links_to_vrf_table_for_rts(self, vrf_table, rts):
        rts_with_no_table = set()
        affected_tables = set()
        route_family = vrf_table.route_family
        for rt in rts:
            rt_rf_id = rt + ':' + str(route_family)
            rt_specific_tables = self._tables_for_rt.get(rt_rf_id)
            affected_tables.update(rt_specific_tables)
            if rt_specific_tables:
                try:
                    rt_specific_tables.remove(vrf_table)
                except KeyError:
                    LOG.debug('Did not find table listed as interested '
                              'for its import RT: %s', rt)
                if len(rt_specific_tables) == 0:
                    rts_with_no_table.add(rt)

        # Remove records of RT that have no tables associated with it.
        for rt in rts_with_no_table:
            rt_rf_id = rt + ':' + str(route_family)
            del self._tables_for_rt[rt_rf_id]

    def create_and_link_vrf_table(self, vrf_conf):
        """Factory method to create VRF table for given `vrf_conf`.

        Adds mapping to this table with appropriate scope. Also, adds mapping
        for import RT of this VRF to created table to facilitate
        importing/installing of paths from global tables.
        Returns created table.
        """

        route_family = vrf_conf.route_family
        assert route_family in (VRF_RF_IPV4, VRF_RF_IPV6)
        vrf_table = None
        if route_family == VRF_RF_IPV4:
            vrf_table = Vrf4Table(
                vrf_conf, self._core_service, self._signal_bus
            )
            table_id = (vrf_conf.route_dist, route_family)
            self._tables[table_id] = vrf_table

        elif route_family == VRF_RF_IPV6:
            vrf_table = Vrf6Table(
                vrf_conf, self._core_service, self._signal_bus
            )
            table_id = (vrf_conf.route_dist, route_family)
            self._tables[table_id] = vrf_table

        assert vrf_table is not None
        LOG.debug('Added new VrfTable with rd: %s and add_fmly: %s',
                  vrf_conf.route_dist, route_family)

        import_rts = vrf_conf.import_rts
        # If VRF is configured with import RT, we put this table
        # in a list corresponding to this RT for easy access.
        if import_rts:
            self._link_vrf_table(vrf_table, import_rts)

        return vrf_table

    def _link_vrf_table(self, vrf_table, rt_list):
        route_family = vrf_table.route_family
        for rt in rt_list:
            rt_rf_id = rt + ':' + str(route_family)
            table_set = self._tables_for_rt.get(rt_rf_id)
            if table_set is None:
                table_set = set()
                self._tables_for_rt[rt_rf_id] = table_set
            table_set.add(vrf_table)
            LOG.debug('Added VrfTable %s to import RT table list: %s',
                      vrf_table, rt)

    def _clean_global_uninteresting_paths(self):
        """Marks paths that do not have any route targets of interest
        for withdrawal.

        Since global tables can have paths with route targets that are not
        interesting any more, we have to clean these paths so that appropriate
        withdraw are sent out to NC and other peers. Interesting route targets
        change as VRF are modified or some filter is that specify what route
        targets are allowed are updated. This clean up should only be done when
        a route target is no longer considered interesting and some paths with
        that route target was installing in any of the global table.
        """
        uninteresting_dest_count = 0
        interested_rts = self._rt_mgr.global_interested_rts
        LOG.debug('Cleaning uninteresting paths. Global interested RTs %s',
                  interested_rts)
        for route_family in [RF_IPv4_VPN, RF_IPv6_VPN, RF_RTC_UC]:
            # TODO(PH): We currently do not install RT_NLRI paths based on
            # extended path attributes (RT)
            if route_family == RF_RTC_UC:
                continue
            table = self.get_global_table_by_route_family(route_family)
            uninteresting_dest_count += \
                table.clean_uninteresting_paths(interested_rts)

        LOG.debug('Found %s number of destinations had uninteresting paths.',
                  uninteresting_dest_count)

    def import_single_vpn_path_to_all_vrfs(self, vpn_path, path_rts=None):
        """Imports *vpnv4_path* to qualifying VRF tables.

        Import RTs of VRF table is matched with RTs from *vpn4_path* and if we
        have any common RTs we import the path into VRF.
        """
        assert (vpn_path.route_family in
                (Vpnv4Path.ROUTE_FAMILY, Vpnv6Path.ROUTE_FAMILY))
        LOG.debug('Importing path %s to qualifying VRFs', vpn_path)

        # If this path has no RTs we are done.
        if not path_rts:
            LOG.info('Encountered a path with no RTs: %s', vpn_path)
            return

        # We match path RTs with all VRFs that are interested in them.
        interested_tables = set()

        # Get route family of VRF to when this VPN Path can be imported to
        route_family = RF_IPv4_UC
        if vpn_path.route_family != RF_IPv4_VPN:
            route_family = RF_IPv6_UC
        for rt in path_rts:
            rt_rf_id = rt + ':' + str(route_family)
            vrf_rt_tables = self._tables_for_rt.get(rt_rf_id)
            if vrf_rt_tables:
                interested_tables.update(vrf_rt_tables)

        if interested_tables:
            # We iterate over all VRF tables that are interested in the RT
            # of the given path and import this path into them.
            route_dist = vpn_path.nlri.route_dist
            for vrf_table in interested_tables:
                if (vpn_path.source is not None and
                        route_dist != vrf_table.vrf_conf.route_dist):
                    update_vrf_dest = vrf_table.import_vpn_path(vpn_path)
                    # Queue the destination for further processing.
                    if update_vrf_dest is not None:
                        self._signal_bus.\
                            dest_changed(update_vrf_dest)
        else:
            # If we do not have any VRF with import RT that match with path RT
            LOG.debug('No VRF table found that imports RTs: %s', path_rts)

    def add_to_vrf(self, route_dist, prefix, next_hop, route_family):
        """Adds `prefix` to VRF identified by `route_dist` with given
         `next_hop`.

        Returns assigned VPN label.
        """
        from ryu.services.protocols.bgp.core import BgpCoreError

        assert route_dist and prefix and next_hop
        if route_family not in (VRF_RF_IPV4, VRF_RF_IPV6):
            raise ValueError('Given route_family %s is not supported.' %
                             route_family)

        vrf_table = None
        table_id = (route_dist, route_family)
        if route_family == VRF_RF_IPV4:
            vrf_table = self._tables.get(table_id)
            if vrf_table is None:
                raise BgpCoreError(desc='VRF table for RD: %s does not '
                                        'exist.' % route_dist)
            if not is_valid_ipv4_prefix(prefix) or not is_valid_ipv4(next_hop):
                raise BgpCoreError(desc='Invalid Ipv4 prefix or nexthop.')
            ip, masklen = prefix.split('/')
            prefix = IPAddrPrefix(int(masklen), ip)
        elif route_family == VRF_RF_IPV6:
            vrf_table = self._tables.get(table_id)
            if vrf_table is None:
                raise BgpCoreError(desc='VRF table for RD: %s does not '
                                        'exist.' % route_dist)
            if not is_valid_ipv6_prefix(prefix) or not is_valid_ipv6(next_hop):
                raise BgpCoreError(desc='Invalid Ipv6 prefix or nexthop.')
            ip6, masklen = prefix.split('/')
            prefix = IP6AddrPrefix(int(masklen), ip6)

        return vrf_table.insert_vrf_path(
            prefix, next_hop=next_hop,
            gen_lbl=True
        )

    def add_to_global_table(self, prefix, nexthop=None,
                            is_withdraw=False):
        src_ver_num = 1
        peer = None
        # set mandatory path attributes
        origin = BGPPathAttributeOrigin(BGP_ATTR_ORIGIN_IGP)
        aspath = BGPPathAttributeAsPath([[]])

        pathattrs = OrderedDict()
        pathattrs[BGP_ATTR_TYPE_ORIGIN] = origin
        pathattrs[BGP_ATTR_TYPE_AS_PATH] = aspath

        net = netaddr.IPNetwork(prefix)
        ip = str(net.ip)
        masklen = net.prefixlen
        if netaddr.valid_ipv4(ip):
            _nlri = IPAddrPrefix(masklen, ip)
            if nexthop is None:
                nexthop = '0.0.0.0'
            p = Ipv4Path
        else:
            _nlri = IP6AddrPrefix(masklen, ip)
            if nexthop is None:
                nexthop = '::'
            p = Ipv6Path

        new_path = p(peer, _nlri, src_ver_num,
                     pattrs=pathattrs, nexthop=nexthop,
                     is_withdraw=is_withdraw)

        # add to global ipv4 table and propagates to neighbors
        self.learn_path(new_path)

    def remove_from_vrf(self, route_dist, prefix, route_family):
        """Removes `prefix` from VRF identified by `route_dist`.

        Returns assigned VPN label.
        """
        from ryu.services.protocols.bgp.core import BgpCoreError
        # Validate given
        if route_family not in (VRF_RF_IPV4, VRF_RF_IPV6):
            raise BgpCoreError(desc='Unsupported route family %s' %
                                    route_family)
        val_ipv4 = route_family == VRF_RF_IPV4\
            and is_valid_ipv4_prefix(prefix)
        val_ipv6 = route_family == VRF_RF_IPV6\
            and is_valid_ipv6_prefix(prefix)

        if not val_ipv4 and not val_ipv6:
            raise BgpCoreError(desc='Invalid prefix or nexthop.')

        table_id = (route_dist, route_family)
        if route_family == VRF_RF_IPV4:
            vrf_table = self._tables.get(table_id)
            if not vrf_table:
                raise BgpCoreError(desc='Vrf for route distinguisher %s does '
                                        'not exist.' % route_dist)
            ip, masklen = prefix.split('/')
            prefix = IPAddrPrefix(int(masklen), ip)
        else:
            vrf_table = self._tables.get(table_id)
            if not vrf_table:
                raise BgpCoreError(desc='Vrf for route distinguisher %s does '
                                        'not exist.' % route_dist)
            ip6, masklen = prefix.split('/')
            prefix = IP6AddrPrefix(int(masklen), ip6)
            # We do not check if we have a path to given prefix, we issue
        # withdrawal. Hence multiple withdrawals have not side effect.
        return vrf_table.insert_vrf_path(prefix, is_withdraw=True)

    def clean_stale_routes(self, peer, route_family=None):
        """Removes old routes from `peer` from `route_family` table.

        Routes/paths version number is compared with `peer`s current version
        number.
        """

        if route_family is not None:
            if route_family not in SUPPORTED_GLOBAL_RF:
                raise ValueError('Given route family %s is not supported.' %
                                 route_family)

            tables = [self._global_tables.get(route_family)]
        else:
            tables = self._global_tables.values()
        for table in tables:
            table.cleanup_paths_for_peer(peer)
