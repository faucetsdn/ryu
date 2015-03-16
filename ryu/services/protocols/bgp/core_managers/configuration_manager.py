from ryu.services.protocols.bgp.rtconf.base import ConfWithStats
from ryu.services.protocols.bgp.rtconf.common import CommonConfListener
from ryu.services.protocols.bgp.rtconf.neighbors import NeighborsConfListener
from ryu.services.protocols.bgp.rtconf import vrfs
from ryu.services.protocols.bgp.rtconf.vrfs import VrfConf
from ryu.services.protocols.bgp.rtconf.vrfs import VrfsConfListener

import logging

LOG = logging.getLogger('bgpspeaker.core_managers.table_mixin')


class ConfigurationManager(CommonConfListener, VrfsConfListener,
                           NeighborsConfListener):
    def __init__(self, core_service, common_conf, vrfs_conf, neighbors_conf):
        self._signal_bus = core_service.signal_bus
        self._common_config = common_conf
        self._peer_manager = core_service.peer_manager
        self._table_manager = core_service.table_manager
        self._rt_manager = core_service.rt_manager
        CommonConfListener.__init__(self, common_conf)
        VrfsConfListener.__init__(self, vrfs_conf)
        NeighborsConfListener.__init__(self, neighbors_conf)

    def on_update_common_conf(self, evt):
        raise NotImplementedError()

    def on_add_neighbor_conf(self, evt):
        neigh_conf = evt.value
        self._peer_manager.add_peer(neigh_conf, self._common_config)

    def on_remove_neighbor_conf(self, evt):
        neigh_conf = evt.value
        self._peer_manager.remove_peer(neigh_conf)

    def on_chg_vrf_conf(self, evt):
        evt_value = evt.value
        vrf_conf = evt.src
        new_imp_rts, removed_imp_rts, import_maps, re_export, re_import = \
            evt_value
        route_family = vrf_conf.route_family
        vrf_table = self._table_manager.get_vrf_table(
            vrf_conf.route_dist, route_family
        )
        assert vrf_table

        # If we have new import RTs we have to update RTC table and make route
        # refresh request to peers not participating in RT address-family
        self._table_manager.update_vrf_table_links(
            vrf_table, new_imp_rts, removed_imp_rts
        )

        # If other properties of VRF changed we re-install local paths.
        if re_export:
            self._table_manager.re_install_net_ctrl_paths(vrf_table)

        # We have to withdraw paths that do not have any RT that are or
        # interest
        vrf_table.clean_uninteresting_paths()
        if import_maps is not None:
            vrf_table.init_import_maps(import_maps)
            changed_dests = vrf_table.apply_import_maps()
            for dest in changed_dests:
                self._signal_bus.dest_changed(dest)

        # import new rts
        if re_import:
            LOG.debug(
                "RE-importing prefixes from VPN table to VRF %r", vrf_table
            )
            self._table_manager.import_all_vpn_paths_to_vrf(vrf_table)
        else:
            self._table_manager.import_all_vpn_paths_to_vrf(
                vrf_table, new_imp_rts
            )

        # Update local/global RT NLRIs
        self._rt_manager.update_local_rt_nlris()

    def on_remove_vrf_conf(self, evt):
        """Removes VRF table associated with given `vrf_conf`.

        Cleans up other links to this table as well.
        """
        vrf_conf = evt.value
        # Detach VrfConf change listener.
        vrf_conf.remove_listener(VrfConf.VRF_CHG_EVT, self.on_chg_vrf_conf)

        self._table_manager.remove_vrf_by_vrf_conf(vrf_conf)

        # Update local RT NLRIs
        self._rt_manager.update_local_rt_nlris()

        self._signal_bus.vrf_removed(vrf_conf.route_dist)

        # Remove AttributeMaps under the removed vrf
        rd = vrf_conf.route_dist
        rf = vrf_conf.route_family
        peers = self._peer_manager.iterpeers
        for peer in peers:
            key = ':'.join([rd, rf])
            peer.attribute_maps.pop(key, None)

    def on_add_vrf_conf(self, evt):
        """Event handler for new VrfConf.

        Creates a VrfTable to store routing information related to new Vrf.
        Also arranges for related paths to be imported to this VrfTable.
        """
        vrf_conf = evt.value
        route_family = vrf_conf.route_family
        assert route_family in vrfs.SUPPORTED_VRF_RF
        # Create VRF table with given configuration.
        vrf_table = self._table_manager.create_and_link_vrf_table(vrf_conf)

        # Attach VrfConf change listeners.
        vrf_conf.add_listener(ConfWithStats.UPDATE_STATS_LOG_ENABLED_EVT,
                              self.on_stats_config_change)
        vrf_conf.add_listener(ConfWithStats.UPDATE_STATS_TIME_EVT,
                              self.on_stats_config_change)
        vrf_conf.add_listener(VrfConf.VRF_CHG_EVT, self.on_chg_vrf_conf)

        # Import paths from VPN table that match this VRF/VPN.
        self._table_manager.import_all_vpn_paths_to_vrf(vrf_table)

        # Update local RT NLRIs
        self._rt_manager.update_local_rt_nlris()
        self._signal_bus.vrf_added(vrf_conf)

    def on_stats_config_change(self, evt):
        vrf_conf = evt.src
        self._signal_bus.stats_config_changed(vrf_conf)
