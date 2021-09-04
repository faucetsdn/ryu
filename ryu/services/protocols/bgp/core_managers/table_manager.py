import logging
from collections import OrderedDict

import netaddr

from ryu.services.protocols.bgp.base import SUPPORTED_GLOBAL_RF
from ryu.services.protocols.bgp.info_base.rtc import RtcTable
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Path
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Table
from ryu.services.protocols.bgp.info_base.ipv6 import Ipv6Path
from ryu.services.protocols.bgp.info_base.ipv6 import Ipv6Table
from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Table
from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Table
from ryu.services.protocols.bgp.info_base.vrf4 import Vrf4Table
from ryu.services.protocols.bgp.info_base.vrf6 import Vrf6Table
from ryu.services.protocols.bgp.info_base.vrfevpn import VrfEvpnTable
from ryu.services.protocols.bgp.info_base.evpn import EvpnTable
from ryu.services.protocols.bgp.info_base.ipv4fs import IPv4FlowSpecPath
from ryu.services.protocols.bgp.info_base.ipv4fs import IPv4FlowSpecTable
from ryu.services.protocols.bgp.info_base.vpnv4fs import VPNv4FlowSpecTable
from ryu.services.protocols.bgp.info_base.vrf4fs import Vrf4FlowSpecTable
from ryu.services.protocols.bgp.info_base.ipv6fs import IPv6FlowSpecPath
from ryu.services.protocols.bgp.info_base.ipv6fs import IPv6FlowSpecTable
from ryu.services.protocols.bgp.info_base.vpnv6fs import VPNv6FlowSpecTable
from ryu.services.protocols.bgp.info_base.vrf6fs import Vrf6FlowSpecTable
from ryu.services.protocols.bgp.info_base.l2vpnfs import L2VPNFlowSpecTable
from ryu.services.protocols.bgp.info_base.vrfl2vpnfs import L2vpnFlowSpecPath
from ryu.services.protocols.bgp.info_base.vrfl2vpnfs import L2vpnFlowSpecTable
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV6
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_L2_EVPN
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4_FLOWSPEC
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV6_FLOWSPEC
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_L2VPN_FLOWSPEC
from ryu.services.protocols.bgp.rtconf.vrfs import SUPPORTED_VRF_RF
from ryu.services.protocols.bgp.utils.bgp import create_v4flowspec_actions
from ryu.services.protocols.bgp.utils.bgp import create_v6flowspec_actions
from ryu.services.protocols.bgp.utils.bgp import create_l2vpnflowspec_actions

from ryu.lib import type_desc
from ryu.lib import ip
from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import RF_L2_EVPN
from ryu.lib.packet.bgp import RF_IPv4_FLOWSPEC
from ryu.lib.packet.bgp import RF_IPv6_FLOWSPEC
from ryu.lib.packet.bgp import RF_VPNv4_FLOWSPEC
from ryu.lib.packet.bgp import RF_VPNv6_FLOWSPEC
from ryu.lib.packet.bgp import RF_L2VPN_FLOWSPEC
from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import BGPPathAttributeOrigin
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGPPathAttributeExtendedCommunities
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_IGP
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
from ryu.lib.packet.bgp import EvpnEsi
from ryu.lib.packet.bgp import EvpnArbitraryEsi
from ryu.lib.packet.bgp import EvpnNLRI
from ryu.lib.packet.bgp import EvpnMacIPAdvertisementNLRI
from ryu.lib.packet.bgp import EvpnInclusiveMulticastEthernetTagNLRI
from ryu.lib.packet.bgp import IPAddrPrefix
from ryu.lib.packet.bgp import IP6AddrPrefix
from ryu.lib.packet.bgp import FlowSpecIPv4NLRI
from ryu.lib.packet.bgp import FlowSpecIPv6NLRI
from ryu.lib.packet.bgp import FlowSpecL2VPNNLRI

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
        assert route_family in SUPPORTED_VRF_RF
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
        """Imports VPNv4/6 or EVPN paths from Global/VPN table into given
        VRFv4/6  or VRFEVPN table.
        :param vrf_table: Vrf table to which we import
        :type vrf_table: VrfTable
        :param import_rts: import RTs to override default import_rts of
         vrf table for this import
        :type import_rts: set of strings

        Checks if we have any path RT common with VRF table's import RT.
        """
        if vrf_table.route_family == Vrf4Table.ROUTE_FAMILY:
            vpn_table = self.get_vpn4_table()
        elif vrf_table.route_family == Vrf6Table.ROUTE_FAMILY:
            vpn_table = self.get_vpn6_table()
        elif vrf_table.route_family == VrfEvpnTable.ROUTE_FAMILY:
            vpn_table = self.get_evpn_table()
        elif vrf_table.route_family == Vrf4FlowSpecTable.ROUTE_FAMILY:
            vpn_table = self.get_vpnv4fs_table()
        elif vrf_table.route_family == Vrf6FlowSpecTable.ROUTE_FAMILY:
            vpn_table = self.get_vpnv6fs_table()
        elif vrf_table.route_family == L2vpnFlowSpecTable.ROUTE_FAMILY:
            vpn_table = self.get_l2vpnfs_table()
        else:
            raise ValueError('Invalid VRF table route family: %s' %
                             vrf_table.route_family)

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
        elif route_family == RF_L2_EVPN:
            global_table = self.get_evpn_table()
        elif route_family == RF_IPv4_FLOWSPEC:
            global_table = self.get_ipv4fs_table()
        elif route_family == RF_IPv6_FLOWSPEC:
            global_table = self.get_ipv6fs_table()
        elif route_family == RF_VPNv4_FLOWSPEC:
            global_table = self.get_vpnv4fs_table()
        elif route_family == RF_VPNv6_FLOWSPEC:
            global_table = self.get_vpnv6fs_table()
        elif route_family == RF_L2VPN_FLOWSPEC:
            global_table = self.get_l2vpnfs_table()
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

    def get_evpn_table(self):
        """Returns global EVPN table.

        Creates the table if it does not exist.
        """
        evpn_table = self._global_tables.get(RF_L2_EVPN)
        # Lazy initialization of the table.
        if not evpn_table:
            evpn_table = EvpnTable(self._core_service, self._signal_bus)
            self._global_tables[RF_L2_EVPN] = evpn_table
            self._tables[(None, RF_L2_EVPN)] = evpn_table

        return evpn_table

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

    def get_ipv4fs_table(self):
        """Returns global IPv4 Flow Specification table.

        Creates the table if it does not exist.
        """
        ipv4fs_table = self._global_tables.get(RF_IPv4_FLOWSPEC)
        # Lazy initialization of the table.
        if not ipv4fs_table:
            ipv4fs_table = IPv4FlowSpecTable(self._core_service,
                                             self._signal_bus)
            self._global_tables[RF_IPv4_FLOWSPEC] = ipv4fs_table
            self._tables[(None, RF_IPv4_FLOWSPEC)] = ipv4fs_table

        return ipv4fs_table

    def get_ipv6fs_table(self):
        """Returns global IPv6 Flow Specification table.

        Creates the table if it does not exist.
        """
        ipv6fs_table = self._global_tables.get(RF_IPv6_FLOWSPEC)
        # Lazy initialization of the table.
        if not ipv6fs_table:
            ipv6fs_table = IPv6FlowSpecTable(self._core_service,
                                             self._signal_bus)
            self._global_tables[RF_IPv6_FLOWSPEC] = ipv6fs_table
            self._tables[(None, RF_IPv6_FLOWSPEC)] = ipv6fs_table

        return ipv6fs_table

    def get_vpnv4fs_table(self):
        """Returns global VPNv4 Flow Specification table.

        Creates the table if it does not exist.
        """
        vpnv4fs_table = self._global_tables.get(RF_VPNv4_FLOWSPEC)
        # Lazy initialization of the table.
        if not vpnv4fs_table:
            vpnv4fs_table = VPNv4FlowSpecTable(self._core_service,
                                               self._signal_bus)
            self._global_tables[RF_VPNv4_FLOWSPEC] = vpnv4fs_table
            self._tables[(None, RF_VPNv4_FLOWSPEC)] = vpnv4fs_table

        return vpnv4fs_table

    def get_vpnv6fs_table(self):
        """Returns global VPNv6 Flow Specification table.

        Creates the table if it does not exist.
        """
        vpnv6fs_table = self._global_tables.get(RF_VPNv6_FLOWSPEC)
        # Lazy initialization of the table.
        if not vpnv6fs_table:
            vpnv6fs_table = VPNv6FlowSpecTable(self._core_service,
                                               self._signal_bus)
            self._global_tables[RF_VPNv6_FLOWSPEC] = vpnv6fs_table
            self._tables[(None, RF_VPNv6_FLOWSPEC)] = vpnv6fs_table

        return vpnv6fs_table

    def get_l2vpnfs_table(self):
        """Returns global L2VPN Flow Specification table.

        Creates the table if it does not exist.
        """
        l2vpnfs_table = self._global_tables.get(RF_L2VPN_FLOWSPEC)
        # Lazy initialization of the table.
        if not l2vpnfs_table:
            l2vpnfs_table = L2VPNFlowSpecTable(self._core_service,
                                               self._signal_bus)
            self._global_tables[RF_L2VPN_FLOWSPEC] = l2vpnfs_table
            self._tables[(None, RF_L2VPN_FLOWSPEC)] = l2vpnfs_table

        return l2vpnfs_table

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
                        nlri=path.nlri,
                        next_hop=path.nexthop,
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

        if route_family == VRF_RF_IPV4:
            vrf_table = Vrf4Table
        elif route_family == VRF_RF_IPV6:
            vrf_table = Vrf6Table
        elif route_family == VRF_RF_L2_EVPN:
            vrf_table = VrfEvpnTable
        elif route_family == VRF_RF_IPV4_FLOWSPEC:
            vrf_table = Vrf4FlowSpecTable
        elif route_family == VRF_RF_IPV6_FLOWSPEC:
            vrf_table = Vrf6FlowSpecTable
        elif route_family == VRF_RF_L2VPN_FLOWSPEC:
            vrf_table = L2vpnFlowSpecTable
        else:
            raise ValueError('Unsupported route family for VRF: %s' %
                             route_family)

        vrf_table = vrf_table(vrf_conf, self._core_service, self._signal_bus)
        table_id = (vrf_conf.route_dist, route_family)
        self._tables[table_id] = vrf_table

        assert vrf_table is not None
        LOG.debug('Added new VrfTable with route_dist:%s and route_family:%s',
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
        """Imports *vpn_path* to qualifying VRF tables.

        Import RTs of VRF table is matched with RTs from *vpn4_path* and if we
        have any common RTs we import the path into VRF.
        """
        LOG.debug('Importing path %s to qualifying VRFs', vpn_path)

        # If this path has no RTs we are done.
        if not path_rts:
            LOG.info('Encountered a path with no RTs: %s', vpn_path)
            return

        # We match path RTs with all VRFs that are interested in them.
        interested_tables = set()

        # Get route family of VRF to when this VPN Path can be imported to
        if vpn_path.route_family == RF_IPv4_VPN:
            route_family = RF_IPv4_UC
        elif vpn_path.route_family == RF_IPv6_VPN:
            route_family = RF_IPv6_UC
        elif vpn_path.route_family == RF_L2_EVPN:
            route_family = RF_L2_EVPN
        elif vpn_path.route_family == RF_VPNv4_FLOWSPEC:
            route_family = RF_IPv4_FLOWSPEC
        elif vpn_path.route_family == RF_VPNv6_FLOWSPEC:
            route_family = RF_IPv6_FLOWSPEC
        elif vpn_path.route_family == RF_L2VPN_FLOWSPEC:
            route_family = RF_L2VPN_FLOWSPEC
        else:
            raise ValueError('Unsupported route family for VRF: %s' %
                             vpn_path.route_family)

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
                if (vpn_path.source is not None or
                        route_dist != vrf_table.vrf_conf.route_dist):
                    update_vrf_dest = vrf_table.import_vpn_path(vpn_path)
                    # Queue the destination for further processing.
                    if update_vrf_dest is not None:
                        self._signal_bus.\
                            dest_changed(update_vrf_dest)
        else:
            # If we do not have any VRF with import RT that match with path RT
            LOG.debug('No VRF table found that imports RTs: %s', path_rts)

    def update_vrf_table(self, route_dist, prefix=None, next_hop=None,
                         route_family=None, route_type=None, tunnel_type=None,
                         is_withdraw=False, redundancy_mode=None,
                         pmsi_tunnel_type=None, tunnel_endpoint_ip=None,
                         mac_mobility=None, **kwargs):
        """Update a BGP route in the VRF table identified by `route_dist`
        with the given `next_hop`.

        If `is_withdraw` is False, which is the default, add a BGP route
        to the VRF table identified by `route_dist` with the given
        `next_hop`.
        If `is_withdraw` is True, remove a BGP route from the VRF table
        and the given `next_hop` is ignored.

        If `route_family` is VRF_RF_L2_EVPN, `route_type` and `kwargs`
        are required to construct EVPN NLRI and `prefix` is ignored.

        ``redundancy_mode`` specifies a redundancy mode type.

`       `pmsi_tunnel_type` specifies the type of the PMSI tunnel attribute
         used to encode the multicast tunnel identifier.
        This field is advertised only if route_type is
        EVPN_MULTICAST_ETAG_ROUTE.

        `tunnel_endpoint_ip` specifies a tunnel endpoint IP other than the
        default local router ID; only used in EVPN_MULTICAST_ETAG_ROUTE

        `mac_mobility` specifies an optional integer sequence number to insert
        as a MAC Mobility extended community; special value `-1` is used for
        static MACs (MAC Mobility sequence 0 with STATIC flag set)

        Returns assigned VPN label.
        """
        from ryu.services.protocols.bgp.core import BgpCoreError

        assert route_dist

        if is_withdraw:
            gen_lbl = False
            next_hop = None
        else:
            gen_lbl = True
            if not (is_valid_ipv4(next_hop) or is_valid_ipv6(next_hop)):
                raise BgpCoreError(
                    desc='Invalid IPv4/IPv6 nexthop: %s' % next_hop)

        vrf_table = self._tables.get((route_dist, route_family))
        if vrf_table is None:
            raise BgpCoreError(
                desc='VRF table  does not exist: route_dist=%s, '
                     'route_family=%s' % (route_dist, route_family))

        vni = kwargs.get('vni', None)

        if route_family == VRF_RF_IPV4:
            if not is_valid_ipv4_prefix(prefix):
                raise BgpCoreError(desc='Invalid IPv4 prefix: %s' % prefix)
            ip, masklen = prefix.split('/')
            prefix = IPAddrPrefix(int(masklen), ip)
        elif route_family == VRF_RF_IPV6:
            if not is_valid_ipv6_prefix(prefix):
                raise BgpCoreError(desc='Invalid IPv6 prefix: %s' % prefix)
            ip6, masklen = prefix.split('/')
            prefix = IP6AddrPrefix(int(masklen), ip6)
        elif route_family == VRF_RF_L2_EVPN:
            assert route_type
            if route_type == EvpnMacIPAdvertisementNLRI.ROUTE_TYPE_NAME:
                # MPLS labels will be assigned automatically
                kwargs['mpls_labels'] = []
            if route_type == EvpnInclusiveMulticastEthernetTagNLRI.ROUTE_TYPE_NAME:
                # Inclusive Multicast Ethernet Tag Route does not have "vni",
                # omit "vni" from "kwargs" here.
                vni = kwargs.pop('vni', None)
            subclass = EvpnNLRI._lookup_type_name(route_type)
            kwargs['route_dist'] = route_dist
            esi = kwargs.get('esi', None)
            if esi is not None:
                if isinstance(esi, dict):
                    esi_type = esi.get('type', 0)
                    esi_class = EvpnEsi._lookup_type(esi_type)
                    kwargs['esi'] = esi_class.from_jsondict(esi)
                else:  # isinstance(esi, numbers.Integral)
                    kwargs['esi'] = EvpnArbitraryEsi(
                        type_desc.Int9.from_user(esi))
            if vni is not None:
                # Disable to generate MPLS labels,
                # because encapsulation type is not MPLS.
                from ryu.services.protocols.bgp.api.prefix import (
                    TUNNEL_TYPE_VXLAN, TUNNEL_TYPE_NVGRE)
                assert tunnel_type in [
                    None, TUNNEL_TYPE_VXLAN, TUNNEL_TYPE_NVGRE]
                gen_lbl = False
            prefix = subclass(**kwargs)
        else:
            raise BgpCoreError(
                desc='Unsupported route family %s' % route_family)

        # We do not check if we have a path to given prefix, we issue
        # withdrawal. Hence multiple withdrawals have not side effect.
        return vrf_table.insert_vrf_path(
            nlri=prefix, next_hop=next_hop, gen_lbl=gen_lbl,
            is_withdraw=is_withdraw, redundancy_mode=redundancy_mode,
            mac_mobility=mac_mobility,
            vni=vni, tunnel_type=tunnel_type,
            pmsi_tunnel_type=pmsi_tunnel_type)

    def update_flowspec_vrf_table(self, flowspec_family, route_dist, rules,
                                  actions=None, is_withdraw=False):
        """Update a BGP route in the VRF table for Flow Specification.

        ``flowspec_family`` specifies one of the flowspec family name.

        ``route_dist`` specifies a route distinguisher value.

        ``rules`` specifies NLRIs of Flow Specification as
        a dictionary type value.

        `` actions`` specifies Traffic Filtering Actions of
        Flow Specification as a dictionary type value.

        If `is_withdraw` is False, which is the default, add a BGP route
        to the VRF table identified by `route_dist`.
        If `is_withdraw` is True, remove a BGP route from the VRF table.
        """
        from ryu.services.protocols.bgp.core import BgpCoreError
        from ryu.services.protocols.bgp.api.prefix import (
            FLOWSPEC_FAMILY_VPNV4,
            FLOWSPEC_FAMILY_VPNV6,
            FLOWSPEC_FAMILY_L2VPN,
        )

        if flowspec_family == FLOWSPEC_FAMILY_VPNV4:
            vrf_table = self._tables.get((route_dist, VRF_RF_IPV4_FLOWSPEC))
            prefix = FlowSpecIPv4NLRI.from_user(**rules)
            try:
                communities = create_v4flowspec_actions(actions)
            except ValueError as e:
                raise BgpCoreError(desc=str(e))
        elif flowspec_family == FLOWSPEC_FAMILY_VPNV6:
            vrf_table = self._tables.get((route_dist, VRF_RF_IPV6_FLOWSPEC))
            prefix = FlowSpecIPv6NLRI.from_user(**rules)
            try:
                communities = create_v6flowspec_actions(actions)
            except ValueError as e:
                raise BgpCoreError(desc=str(e))
        elif flowspec_family == FLOWSPEC_FAMILY_L2VPN:
            vrf_table = self._tables.get((route_dist, VRF_RF_L2VPN_FLOWSPEC))
            prefix = FlowSpecL2VPNNLRI.from_user(route_dist, **rules)
            try:
                communities = create_l2vpnflowspec_actions(actions)
            except ValueError as e:
                raise BgpCoreError(desc=str(e))
        else:
            raise BgpCoreError(
                desc='Unsupported flowspec_family %s' % flowspec_family)

        if vrf_table is None:
            raise BgpCoreError(
                desc='VRF table does not exist: route_dist=%s, '
                     'flowspec_family=%s' % (route_dist, flowspec_family))

        # We do not check if we have a path to given prefix, we issue
        # withdrawal. Hence multiple withdrawals have not side effect.
        vrf_table.insert_vrffs_path(
            nlri=prefix, communities=communities,
            is_withdraw=is_withdraw)

    def update_global_table(self, prefix, next_hop=None, is_withdraw=False):
        """Update a BGP route in the Global table for the given `prefix`
        with the given `next_hop`.

        If `is_withdraw` is False, which is the default, add a BGP route
        to the Global table.
        If `is_withdraw` is True, remove a BGP route from the Global table.
        """
        src_ver_num = 1
        peer = None
        # set mandatory path attributes
        origin = BGPPathAttributeOrigin(BGP_ATTR_ORIGIN_IGP)
        aspath = BGPPathAttributeAsPath([[]])

        pathattrs = OrderedDict()
        pathattrs[BGP_ATTR_TYPE_ORIGIN] = origin
        pathattrs[BGP_ATTR_TYPE_AS_PATH] = aspath

        net = netaddr.IPNetwork(prefix)
        addr = str(net.ip)
        masklen = net.prefixlen
        if ip.valid_ipv4(addr):
            _nlri = IPAddrPrefix(masklen, addr)
            if next_hop is None:
                next_hop = '0.0.0.0'
            p = Ipv4Path
        else:
            _nlri = IP6AddrPrefix(masklen, addr)
            if next_hop is None:
                next_hop = '::'
            p = Ipv6Path

        new_path = p(peer, _nlri, src_ver_num,
                     pattrs=pathattrs, nexthop=next_hop,
                     is_withdraw=is_withdraw)

        # add to global table and propagates to neighbors
        self.learn_path(new_path)

    def update_flowspec_global_table(self, flowspec_family, rules,
                                     actions=None, is_withdraw=False):
        """Update a BGP route in the Global table for Flow Specification.

        ``flowspec_family`` specifies one of the Flow Specification
         family name.

        ``rules`` specifies NLRIs of Flow Specification as
        a dictionary type value.

        `` actions`` specifies Traffic Filtering Actions of
        Flow Specification as a dictionary type value.

        If `is_withdraw` is False, which is the default, add a BGP route
        to the Global table.
        If `is_withdraw` is True, remove a BGP route from the Global table.
        """

        from ryu.services.protocols.bgp.core import BgpCoreError
        from ryu.services.protocols.bgp.api.prefix import (
            FLOWSPEC_FAMILY_IPV4,
            FLOWSPEC_FAMILY_IPV6,
            FLOWSPEC_FAMILY_L2VPN,
        )

        src_ver_num = 1
        peer = None

        # set mandatory path attributes
        origin = BGPPathAttributeOrigin(BGP_ATTR_ORIGIN_IGP)
        aspath = BGPPathAttributeAsPath([[]])

        pathattrs = OrderedDict()
        pathattrs[BGP_ATTR_TYPE_ORIGIN] = origin
        pathattrs[BGP_ATTR_TYPE_AS_PATH] = aspath

        if flowspec_family == FLOWSPEC_FAMILY_IPV4:
            _nlri = FlowSpecIPv4NLRI.from_user(**rules)
            p = IPv4FlowSpecPath

            try:
                communities = create_v4flowspec_actions(actions)
            except ValueError as e:
                raise BgpCoreError(desc=str(e))

            if communities:
                pathattrs[BGP_ATTR_TYPE_EXTENDED_COMMUNITIES] = (
                    BGPPathAttributeExtendedCommunities(
                        communities=communities))
        elif flowspec_family == FLOWSPEC_FAMILY_IPV6:
            _nlri = FlowSpecIPv6NLRI.from_user(**rules)
            p = IPv6FlowSpecPath

            try:
                communities = create_v6flowspec_actions(actions)
            except ValueError as e:
                raise BgpCoreError(desc=str(e))

            if communities:
                pathattrs[BGP_ATTR_TYPE_EXTENDED_COMMUNITIES] = (
                    BGPPathAttributeExtendedCommunities(
                        communities=communities))
        elif flowspec_family == FLOWSPEC_FAMILY_L2VPN:
            _nlri = FlowSpecL2VPNNLRI.from_user(**rules)
            p = L2vpnFlowSpecPath

            try:
                communities = create_l2vpnflowspec_actions(actions)
            except ValueError as e:
                raise BgpCoreError(desc=str(e))

            if communities:
                pathattrs[BGP_ATTR_TYPE_EXTENDED_COMMUNITIES] = (
                    BGPPathAttributeExtendedCommunities(
                        communities=communities))
        else:
            raise BgpCoreError(
                desc='Unsupported flowspec family %s' % flowspec_family)

        new_path = p(peer, _nlri, src_ver_num,
                     pattrs=pathattrs, is_withdraw=is_withdraw)

        # add to global table and propagates to neighbors
        self.learn_path(new_path)

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
