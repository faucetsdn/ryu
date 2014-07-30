from ryu.services.protocols.bgp.signals import SignalBus


class BgpSignalBus(SignalBus):
    BGP_ERROR = ('error', 'bgp')
    BGP_DEST_CHANGED = ('core', 'dest', 'changed')
    BGP_VRF_REMOVED = ('core', 'vrf', 'removed')
    BGP_VRF_ADDED = ('core', 'vrf', 'added')
    BGP_NOTIFICATION_RECEIVED = ('bgp', 'notification_received')
    BGP_NOTIFICATION_SENT = ('bgp', 'notification_sent')
    BGP_VRF_STATS_CONFIG_CHANGED = (
        'core', 'vrf', 'config', 'stats', 'changed'
    )
    BGP_BEST_PATH_CHANGED = ('core', 'best', 'changed')
    BGP_ADJ_RIB_IN_CHANGED = ('core', 'adj', 'rib', 'in', 'changed')
    BGP_ADJ_RIB_OUT_CHANGED = ('core', 'adj', 'rib', 'out', 'changed')
    BGP_ADJ_UP = ('core', 'adj', 'up')
    BGP_ADJ_DOWN = ('core', 'adj', 'down')

    def bgp_error(self, peer, code, subcode, reason):
        return self.emit_signal(
            self.BGP_ERROR + (peer, ),
            {'code': code, 'subcode': subcode, 'reason': reason, 'peer': peer}
        )

    def bgp_notification_received(self, peer, notification):
        return self.emit_signal(
            self.BGP_NOTIFICATION_RECEIVED + (peer,),
            notification
        )

    def bgp_notification_sent(self, peer, notification):
        return self.emit_signal(
            self.BGP_NOTIFICATION_SENT + (peer,),
            notification
        )

    def dest_changed(self, dest):
        return self.emit_signal(
            self.BGP_DEST_CHANGED,
            dest
        )

    def vrf_removed(self, route_dist):
        return self.emit_signal(
            self.BGP_VRF_REMOVED,
            route_dist
        )

    def vrf_added(self, vrf_conf):
        return self.emit_signal(
            self.BGP_VRF_ADDED,
            vrf_conf
        )

    def stats_config_changed(self, vrf_conf):
        return self.emit_signal(
            self.BGP_VRF_STATS_CONFIG_CHANGED,
            vrf_conf
        )

    def best_path_changed(self, path, is_withdraw):
        return self.emit_signal(
            self.BGP_BEST_PATH_CHANGED,
            {'path': path, 'is_withdraw': is_withdraw})

    def adj_rib_in_changed(self, peer, received_route):
        return self.emit_signal(
            self.BGP_ADJ_RIB_IN_CHANGED,
            {'peer': peer, 'received_route': received_route})

    def adj_rib_out_changed(self, peer, sent_route):
        return self.emit_signal(
            self.BGP_ADJ_RIB_OUT_CHANGED,
            {'peer': peer, 'sent_route': sent_route})

    def adj_up(self, peer):
        return self.emit_signal(self.BGP_ADJ_UP, {'peer': peer})

    def adj_down(self, peer):
        return self.emit_signal(self.BGP_ADJ_DOWN, {'peer': peer})
