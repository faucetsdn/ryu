# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

# This module updates flow table for OpenStack integration.
# Despite of the name, this module isn't GRE specific and
# should work for VXLAN etc as well.

import collections

from ryu import exception as ryu_exc
from ryu.app.rest_nw_id import (NW_ID_VPORT_GRE,
                                RESERVED_NETWORK_IDS)
from ryu.base import app_manager
from ryu.controller import (dpset,
                            event,
                            handler,
                            network,
                            ofp_event,
                            tunnels)
from ryu.ofproto import nx_match
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac


def _is_reserved_port(ofproto, port_no):
    return port_no > ofproto.OFPP_MAX


def _link_is_up(dpset_, dp, port_no):
    try:
        state = dpset_.get_port(dp.id, port_no).state
        return not (state & dp.ofproto.OFPPS_LINK_DOWN)
    except ryu_exc.PortNotFound:
        return False


class PortSet(app_manager.RyuApp):

    # Those events are higher level events than events of network tenant,
    # tunnel ports as the race conditions are masked.
    # Add event is generated only when all necessary informations are gathered,
    # Del event is generated when any one of the informations are deleted.
    #
    # Example: ports for VMs
    # there is a race condition between ofp port add/del event and
    # register network_id for the port.

    class EventTunnelKeyDel(event.EventBase):
        def __init__(self, tunnel_key):
            super(PortSet.EventTunnelKeyDel, self).__init__()
            self.tunnel_key = tunnel_key

    class EventPortBase(event.EventBase):
        def __init__(self, dpid, port_no):
            super(PortSet.EventPortBase, self).__init__()
            self.dpid = dpid
            self.port_no = port_no

    class EventVMPort(EventPortBase):
        def __init__(self, network_id, tunnel_key,
                     dpid, port_no, mac_address, add_del):
            super(PortSet.EventVMPort, self).__init__(dpid, port_no)
            self.network_id = network_id
            self.tunnel_key = tunnel_key
            self.mac_address = mac_address
            self.add_del = add_del

        def __str__(self):
            return ('EventVMPort<dpid %s port_no %d '
                    'network_id %s tunnel_key %s mac %s add_del %s>' %
                    (dpid_lib.dpid_to_str(self.dpid), self.port_no,
                     self.network_id, self.tunnel_key,
                     mac.haddr_to_str(self.mac_address), self.add_del))

    class EventTunnelPort(EventPortBase):
        def __init__(self, dpid, port_no, remote_dpid, add_del):
            super(PortSet.EventTunnelPort, self).__init__(dpid, port_no)
            self.remote_dpid = remote_dpid
            self.add_del = add_del

        def __str__(self):
            return ('EventTunnelPort<dpid %s port_no %d remote_dpid %s '
                    'add_del %s>' %
                    (dpid_lib.dpid_to_str(self.dpid), self.port_no,
                     dpid_lib.dpid_to_str(self.remote_dpid), self.add_del))

    def __init__(self, **kwargs):
        super(PortSet, self).__init__()
        self.nw = kwargs['network']
        self.tunnels = kwargs['tunnels']
        self.dpset = kwargs['dpset']
        app_manager.register_app(self)

    def _check_link_state(self, dp, port_no, add_del):
        if add_del:
            # When adding port, the link should be UP.
            return _link_is_up(self.dpset, dp, port_no)
        else:
            # When deleting port, the link status isn't cared.
            return True

    # Tunnel port
    # of connecting: self.dpids by (dpid, port_no)
    #    datapath: connected: EventDP event
    #    port status: UP: port add/delete/modify event
    # remote dpid: self.tunnels by (dpid, port_no): tunnel port add/del even
    def _tunnel_port_handler(self, dpid, port_no, add_del):
        dp = self.dpset.get(dpid)
        if dp is None:
            return
        if not self._check_link_state(dp, port_no, add_del):
            return
        try:
            remote_dpid = self.tunnels.get_remote_dpid(dpid, port_no)
        except ryu_exc.PortNotFound:
            return

        self.send_event_to_observers(self.EventTunnelPort(dpid, port_no,
                                     remote_dpid, add_del))

    # VM port
    # of connection: self.dpids by (dpid, port_no)
    #    datapath: connected: EventDP event
    #    port status: UP: Port add/delete/modify event
    # network_id: self.nw by (dpid, port_no): network port add/del event
    # mac_address: self.nw by (dpid, port_no): mac address add/del event
    # tunnel key: from self.tunnels by network_id: tunnel key add/del event
    def _vm_port_handler(self, dpid, port_no,
                         network_id, mac_address, add_del):
        if network_id in RESERVED_NETWORK_IDS:
            return
        if mac_address is None:
            return
        dp = self.dpset.get(dpid)
        if dp is None:
            return
        if _is_reserved_port(dp.ofproto, port_no):
            return
        if not self._check_link_state(dp, port_no, add_del):
            return
        try:
            tunnel_key = self.tunnels.get_key(network_id)
        except tunnels.TunnelKeyNotFound:
            return

        self.send_event_to_observers(self.EventVMPort(network_id, tunnel_key,
                                     dpid, port_no, mac_address, add_del))

    def _vm_port_mac_handler(self, dpid, port_no, network_id, add_del):
        if network_id == NW_ID_VPORT_GRE:
            self._tunnel_port_handler(dpid, port_no, add_del)
            return

        try:
            mac_address = self.nw.get_mac(dpid, port_no)
        except ryu_exc.PortNotFound:
            return
        self._vm_port_handler(dpid, port_no, network_id, mac_address,
                              add_del)

    def _port_handler(self, dpid, port_no, add_del):
        """
        :type add_del: bool
        :param add_del: True for add, False for del
        """
        try:
            port = self.nw.get_port(dpid, port_no)
        except ryu_exc.PortNotFound:
            return

        if port.network_id is None:
            return

        if port.network_id == NW_ID_VPORT_GRE:
            self._tunnel_port_handler(dpid, port_no, add_del)
            return

        self._vm_port_handler(dpid, port_no, port.network_id,
                              port.mac_address, add_del)

    def _tunnel_key_del(self, tunnel_key):
        self.send_event_to_observers(self.EventTunnelKeyDel(tunnel_key))

    # nw: network del
    #           port add/del (vm/tunnel port)
    #           mac address add/del(only vm port)
    # tunnels: tunnel key add/del
    #          tunnel port add/del
    # dpset: eventdp
    #        port add/delete/modify

    @handler.set_ev_cls(network.EventNetworkDel)
    def network_del_handler(self, ev):
        network_id = ev.network_id
        if network_id in RESERVED_NETWORK_IDS:
            return
        try:
            tunnel_key = self.tunnels.get_key(network_id)
        except tunnels.TunnelKeyNotFound:
            return
        self._tunnel_key_del(tunnel_key)

    @handler.set_ev_cls(network.EventNetworkPort)
    def network_port_handler(self, ev):
        self._vm_port_mac_handler(ev.dpid, ev.port_no, ev.network_id,
                                  ev.add_del)

    @handler.set_ev_cls(network.EventMacAddress)
    def network_mac_address_handler(self, ev):
        self._vm_port_handler(ev.dpid, ev.port_no, ev.network_id,
                              ev.mac_address, ev.add_del)

    @handler.set_ev_cls(tunnels.EventTunnelKeyAdd)
    def tunnel_key_add_handler(self, ev):
        network_id = ev.network_id
        for (dpid, port_no) in self.nw.list_ports_noraise(network_id):
            self._vm_port_mac_handler(dpid, port_no, network_id, True)

    @handler.set_ev_cls(tunnels.EventTunnelKeyDel)
    def tunnel_key_del_handler(self, ev):
        network_id = ev.network_id
        for (dpid, port_no) in self.nw.list_ports_noraise(network_id):
            self._vm_port_mac_handler(dpid, port_no, network_id, False)
        if self.nw.has_network(network_id):
            self._tunnel_key_del(ev.tunnel_key)

    @handler.set_ev_cls(tunnels.EventTunnelPort)
    def tunnel_port_handler(self, ev):
        self._port_handler(ev.dpid, ev.port_no, ev.add_del)

    @handler.set_ev_cls(dpset.EventDP)
    def dp_handler(self, ev):
        self.send_event_to_observers(ev)
        enter_leave = ev.enter
        if not enter_leave:
            # TODO:XXX
            # What to do on datapath disconnection?
            self.logger.debug('dp disconnection ev:%s', ev)

        dpid = ev.dp.id
        ports = set(port.port_no for port in ev.ports)
        ports.update(port.port_no for port in self.nw.get_ports(dpid))
        for port_no in ports:
            self._port_handler(dpid, port_no, enter_leave)

    @handler.set_ev_cls(dpset.EventPortAdd)
    def port_add_handler(self, ev):
        self._port_handler(ev.dp.id, ev.port.port_no, True)

    @handler.set_ev_cls(dpset.EventPortDelete)
    def port_del_handler(self, ev):
        self._port_handler(ev.dp.id, ev.port.port_no, False)

    @handler.set_ev_cls(dpset.EventPortModify)
    def port_modify_handler(self, ev):
        # We don't know LINK status has been changed.
        # So VM/TUNNEL port event can be triggered many times.
        dp = ev.dp
        port = ev.port
        self._port_handler(dp.id, port.port_no,
                           not (port.state & dp.ofproto.OFPPS_LINK_DOWN))

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn)
    def packet_in_handler(self, ev):
        # for debug
        self.send_event_to_observers(ev)


def cls_rule(in_port=None, tun_id=None, dl_src=None, dl_dst=None):
    """Convenience function to initialize nx_match.ClsRule()"""
    rule = nx_match.ClsRule()
    if in_port is not None:
        rule.set_in_port(in_port)
    if tun_id is not None:
        rule.set_tun_id(tun_id)
    if dl_src is not None:
        rule.set_dl_src(dl_src)
    if dl_dst is not None:
        rule.set_dl_dst(dl_dst)
    return rule


class GRETunnel(app_manager.RyuApp):
    """
    app for L2/L3 with gre tunneling

    PORTS
    VM-port: the port which is connected to VM instance
    TUNNEL-port: the ovs GRE vport

    TABLES: multi tables is used
    SRC_TABLE:
        This table is firstly used to match packets.
        by in_port, determine which port the packet comes VM-port or
        TUNNEL-port.
        If the packet came from VM-port, set tunnel id based on which network
        the VM belongs to, and send the packet to the tunnel out table.
        If the packet came from TUNNEL-port and its tunnel id is known to this
        switch, send the packet to local out table. Otherwise drop it.

    TUNNEL_OUT_TABLE:
        This table looks at tunnel id and dl_dst, send the packet to tunnel
        ports if necessary. And then, sends the packet to LOCAL_OUT_TABLE.
        By matching the packet with tunnel_id and dl_dst, determine which
        tunnel port the packet is send to.

    LOCAL_OUT_TABLE:
        This table looks at tunnel id and dl_dst, send the packet to local
        VM ports if necessary. Otherwise drop the packet.


    The packet from vm port traverses as
    SRC_TABLE -> TUNNEL_OUT_TABLE -> LOCAL_OUT_TABLE

    The packet from tunnel port traverses as
    SRC_TABLE -> LOCAL_OUT_TABLE


    The packet from vm port:
    SRC_TABLE
    match                       action
    in_port(VM) & dl_src        set_tunnel & goto TUNNEL_OUT_TABLE
    in_port(VM)                 drop                    (catch-all drop rule)

    in_port(TUNNEL) & tun_id    goto LOCAL_OUT_TABLE
    in_port(TUNNEL)             drop                    (catch-all drop rule)

    TUNNEL_OUT_TABLE
    match                       action
    tun_id & dl_dst             out tunnel port & goto LOCAL_OUT_TABLE
                                                        (unicast or broadcast)
    tun_id                      goto LOCAL_OUT_TABLE    (catch-all rule)

    LOCAL_OUT_TABLE
    tun_id & dl_dst             output(VM)              (unicast or broadcast)
    tun_id                      drop                    (catch-all drop rule)

    NOTE:
    adding/deleting flow entries should be done carefully in certain order
    such that packet in event should not be triggered.
    """
    _CONTEXTS = {
        'network': network.Network,
        'dpset': dpset.DPSet,
        'tunnels': tunnels.Tunnels,
    }

    DEFAULT_COOKIE = 0  # cookie isn't used. Just set 0

    # Tables
    SRC_TABLE = 0
    TUNNEL_OUT_TABLE = 1
    LOCAL_OUT_TABLE = 2
    FLOW_TABLES = [SRC_TABLE, TUNNEL_OUT_TABLE, LOCAL_OUT_TABLE]

    # Priorities. The only inequality is important.
    # '/ 2' is used just for easy looking instead of '- 1'.
    # 0x7ffff vs 0x4000
    TABLE_DEFAULT_PRPIRITY = 32768  # = ofproto.OFP_DEFAULT_PRIORITY

    # SRC_TABLE for VM-port
    SRC_PRI_MAC = TABLE_DEFAULT_PRPIRITY
    SRC_PRI_DROP = TABLE_DEFAULT_PRPIRITY / 2
    # SRC_TABLE for TUNNEL-port
    SRC_PRI_TUNNEL_PASS = TABLE_DEFAULT_PRPIRITY
    SRC_PRI_TUNNEL_DROP = TABLE_DEFAULT_PRPIRITY / 2

    # TUNNEL_OUT_TABLE
    TUNNEL_OUT_PRI_MAC = TABLE_DEFAULT_PRPIRITY
    TUNNEL_OUT_PRI_BROADCAST = TABLE_DEFAULT_PRPIRITY / 2
    TUNNEL_OUT_PRI_PASS = TABLE_DEFAULT_PRPIRITY / 4
    TUNNEL_OUT_PRI_DROP = TABLE_DEFAULT_PRPIRITY / 8

    # LOCAL_OUT_TABLE
    LOCAL_OUT_PRI_MAC = TABLE_DEFAULT_PRPIRITY
    LOCAL_OUT_PRI_BROADCAST = TABLE_DEFAULT_PRPIRITY / 2
    LOCAL_OUT_PRI_DROP = TABLE_DEFAULT_PRPIRITY / 4

    def __init__(self, *args, **kwargs):
        super(GRETunnel, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        self.dpset = kwargs['dpset']
        self.tunnels = kwargs['tunnels']

        self.port_set = PortSet(**kwargs)
        map(lambda ev_cls: self.port_set.register_observer(ev_cls, self.name),
            [dpset.EventDP, PortSet.EventTunnelKeyDel, PortSet.EventVMPort,
             PortSet.EventTunnelPort, ofp_event.EventOFPPacketIn])

    # TODO: track active vm/tunnel ports

    @handler.set_ev_handler(dpset.EventDP)
    def dp_handler(self, ev):
        if not ev.enter:
            return

        # enable nicira extension
        # TODO:XXX error handling
        dp = ev.dp
        ofproto = dp.ofproto

        dp.send_nxt_set_flow_format(ofproto.NXFF_NXM)
        flow_mod_table_id = dp.ofproto_parser.NXTFlowModTableId(dp, 1)
        dp.send_msg(flow_mod_table_id)
        dp.send_barrier()

        # delete all flows in all tables
        # current controller.handlers takes care of only table = 0
        for table in self.FLOW_TABLES:
            rule = cls_rule()
            self.send_flow_del(dp, rule, table, ofproto.OFPFC_DELETE,
                               None, None)
        dp.send_barrier()

    @staticmethod
    def _make_command(table, command):
        return table << 8 | command

    def send_flow_mod(self, dp, rule, table, command, priority, actions):
        command = self._make_command(table, command)
        dp.send_flow_mod(rule=rule, cookie=self.DEFAULT_COOKIE,
                         command=command, idle_timeout=0,
                         hard_timeout=0, priority=priority, actions=actions)

    def send_flow_del(self, dp, rule, table, command, priority, out_port):
        command = self._make_command(table, command)
        dp.send_flow_mod(rule=rule, cookie=self.DEFAULT_COOKIE,
                         command=command, idle_timeout=0,
                         hard_timeout=0, priority=priority, out_port=out_port)

    def _list_tunnel_port(self, dp, remote_dpids):
        dpid = dp.id
        tunnel_ports = []
        for other_dpid in remote_dpids:
            if other_dpid == dpid:
                continue
            other_dp = self.dpset.get(other_dpid)
            if other_dp is None:
                continue
            try:
                port_no = self.tunnels.get_port(dpid, other_dpid)
            except ryu_exc.PortNotFound:
                continue
            if not self._link_is_up(dp, port_no):
                continue
            tunnel_ports.append(port_no)

        return tunnel_ports

    def _link_is_up(self, dp, port_no):
        return _link_is_up(self.dpset, dp, port_no)

    def _port_is_active(self, network_id, dp, nw_port):
        return (nw_port.network_id == network_id and
                nw_port.mac_address is not None and
                self._link_is_up(dp, nw_port.port_no))

    def _tunnel_port_with_mac(self, remote_dp, dpid, network_id, port_no,
                              mac_address):
        tunnel_ports = []
        ports = self.nw.get_ports_with_mac(network_id, mac_address).copy()
        ports.discard((dpid, port_no))
        assert len(ports) <= 1
        for port in ports:
            try:
                tunnel_port_no = self.tunnels.get_port(remote_dp.id, port.dpid)
            except ryu_exc.PortNotFound:
                pass
            else:
                if self._link_is_up(remote_dp, tunnel_port_no):
                    tunnel_ports.append(tunnel_port_no)

        assert len(tunnel_ports) <= 1
        return tunnel_ports

    def _vm_port_add(self, ev):
        dpid = ev.dpid
        dp = self.dpset.get(dpid)
        assert dp is not None
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser
        mac_address = ev.mac_address
        network_id = ev.network_id
        tunnel_key = ev.tunnel_key
        remote_dpids = self.nw.get_dpids(network_id)
        remote_dpids.remove(dpid)

        # LOCAL_OUT_TABLE: unicast
        # live-migration: there can be two ports with same mac_address
        ports = self.nw.get_ports(dpid, network_id, mac_address)
        assert ev.port_no in [port.port_no for port in ports]
        rule = cls_rule(tun_id=tunnel_key, dl_dst=mac_address)
        actions = [ofproto_parser.OFPActionOutput(port.port_no)
                   for port in ports if self._link_is_up(dp, port.port_no)]
        self.send_flow_mod(dp, rule, self.LOCAL_OUT_TABLE, ofproto.OFPFC_ADD,
                           self.LOCAL_OUT_PRI_MAC, actions)

        # LOCAL_OUT_TABLE: broad cast
        rule = cls_rule(tun_id=tunnel_key, dl_dst=mac.BROADCAST)
        actions = []
        for port in self.nw.get_ports(dpid):
            if not self._port_is_active(network_id, dp, port):
                continue
            actions.append(ofproto_parser.OFPActionOutput(port.port_no))

        first_instance = (len(actions) == 1)
        assert actions
        if first_instance:
            command = ofproto.OFPFC_ADD
        else:
            command = ofproto.OFPFC_MODIFY_STRICT
        self.send_flow_mod(dp, rule, self.LOCAL_OUT_TABLE, command,
                           self.LOCAL_OUT_PRI_BROADCAST, actions)

        # LOCAL_OUT_TABLE: multicast TODO:XXX

        # LOCAL_OUT_TABLE: catch-all drop
        if first_instance:
            rule = cls_rule(tun_id=tunnel_key)
            self.send_flow_mod(dp, rule, self.LOCAL_OUT_TABLE,
                               ofproto.OFPFC_ADD, self.LOCAL_OUT_PRI_DROP, [])

        # TUNNEL_OUT_TABLE: unicast
        mac_to_ports = collections.defaultdict(set)
        for remote_dpid in remote_dpids:
            remote_dp = self.dpset.get(remote_dpid)
            if remote_dp is None:
                continue
            try:
                tunnel_port_no = self.tunnels.get_port(dpid, remote_dpid)
            except ryu_exc.PortNotFound:
                continue
            if not self._link_is_up(dp, tunnel_port_no):
                continue

            for port in self.nw.get_ports(remote_dpid):
                if not self._port_is_active(network_id, remote_dp, port):
                    continue
                # TUNNEL_OUT_TABLE: unicast
                # live-migration: there can be more than one tunnel-ports that
                #                 have a given mac address
                mac_to_ports[port.mac_address].add(tunnel_port_no)

            if first_instance:
                # SRC_TABLE: TUNNEL-port: resubmit to LOAL_OUT_TABLE
                rule = cls_rule(in_port=tunnel_port_no, tun_id=tunnel_key)
                resubmit_table = ofproto_parser.NXActionResubmitTable(
                    in_port=ofproto.OFPP_IN_PORT, table=self.LOCAL_OUT_TABLE)
                actions = [resubmit_table]
                self.send_flow_mod(dp, rule, self.SRC_TABLE,
                                   ofproto.OFPFC_ADD, self.SRC_PRI_TUNNEL_PASS,
                                   actions)

        # TUNNEL_OUT_TABLE: unicast
        for remote_mac_address, tunnel_ports in mac_to_ports.items():
            rule = cls_rule(tun_id=tunnel_key, dl_dst=remote_mac_address)
            outputs = [ofproto_parser.OFPActionOutput(tunnel_port_no)
                       for tunnel_port_no in tunnel_ports]
            resubmit_table = ofproto_parser.NXActionResubmitTable(
                in_port=ofproto.OFPP_IN_PORT, table=self.LOCAL_OUT_TABLE)
            actions = outputs + [resubmit_table]
            self.send_flow_mod(dp, rule, self.TUNNEL_OUT_TABLE,
                               ofproto.OFPFC_ADD, self.TUNNEL_OUT_PRI_MAC,
                               actions)

        if first_instance:
            # TUNNEL_OUT_TABLE: catch-all(resubmit to LOCAL_OUT_TABLE)
            rule = cls_rule(tun_id=tunnel_key)
            resubmit_table = ofproto_parser.NXActionResubmitTable(
                in_port=ofproto.OFPP_IN_PORT, table=self.LOCAL_OUT_TABLE)
            actions = [resubmit_table]
            self.send_flow_mod(dp, rule, self.TUNNEL_OUT_TABLE,
                               ofproto.OFPFC_ADD,
                               self.TUNNEL_OUT_PRI_PASS, actions)

            # TUNNEL_OUT_TABLE: broadcast
            rule = cls_rule(tun_id=tunnel_key, dl_dst=mac.BROADCAST)
            actions = [ofproto_parser.OFPActionOutput(tunnel_port_no)
                       for tunnel_port_no
                       in self._list_tunnel_port(dp, remote_dpids)]
            resubmit_table = ofproto_parser.NXActionResubmitTable(
                in_port=ofproto.OFPP_IN_PORT, table=self.LOCAL_OUT_TABLE)
            actions.append(resubmit_table)
            self.send_flow_mod(dp, rule, self.TUNNEL_OUT_TABLE,
                               ofproto.OFPFC_ADD,
                               self.TUNNEL_OUT_PRI_BROADCAST, actions)

        # TUNNEL_OUT_TABLE: multicast TODO:XXX

        # SRC_TABLE: VM-port unicast
        dp.send_barrier()
        rule = cls_rule(in_port=ev.port_no, dl_src=mac_address)
        set_tunnel = ofproto_parser.NXActionSetTunnel(tunnel_key)
        resubmit_table = ofproto_parser.NXActionResubmitTable(
            in_port=ofproto.OFPP_IN_PORT, table=self.TUNNEL_OUT_TABLE)
        actions = [set_tunnel, resubmit_table]
        self.send_flow_mod(dp, rule, self.SRC_TABLE, ofproto.OFPFC_ADD,
                           self.SRC_PRI_MAC, actions)

        # SRC_TABLE: VM-port catch-call drop
        rule = cls_rule(in_port=ev.port_no)
        self.send_flow_mod(dp, rule, self.SRC_TABLE, ofproto.OFPFC_ADD,
                           self.SRC_PRI_DROP, [])

        # remote dp
        for remote_dpid in remote_dpids:
            remote_dp = self.dpset.get(remote_dpid)
            if remote_dp is None:
                continue
            try:
                tunnel_port_no = self.tunnels.get_port(remote_dpid, dpid)
            except ryu_exc.PortNotFound:
                continue
            if not self._link_is_up(remote_dp, tunnel_port_no):
                continue

            remote_ofproto = remote_dp.ofproto
            remote_ofproto_parser = remote_dp.ofproto_parser

            # TUNNEL_OUT_TABLE: unicast
            # live-migration: there can be another port that has
            # same mac address
            tunnel_ports = self._tunnel_port_with_mac(remote_dp, dpid,
                                                      network_id, ev.port_no,
                                                      mac_address)
            tunnel_ports.append(tunnel_port_no)

            rule = cls_rule(tun_id=ev.tunnel_key, dl_dst=mac_address)
            outputs = [remote_ofproto_parser.OFPActionOutput(port_no)
                       for port_no in tunnel_ports]
            resubmit_table = remote_ofproto_parser.NXActionResubmitTable(
                in_port=remote_ofproto.OFPP_IN_PORT,
                table=self.LOCAL_OUT_TABLE)
            actions = outputs + [resubmit_table]
            self.send_flow_mod(remote_dp, rule, self.TUNNEL_OUT_TABLE,
                               remote_ofproto.OFPFC_ADD,
                               self.TUNNEL_OUT_PRI_MAC, actions)

            if not first_instance:
                continue

            # SRC_TABLE: TUNNEL-port
            rule = cls_rule(in_port=tunnel_port_no, tun_id=ev.tunnel_key)
            resubmit_table = remote_ofproto_parser.NXActionResubmitTable(
                in_port=remote_ofproto.OFPP_IN_PORT,
                table=self.LOCAL_OUT_TABLE)
            actions = [resubmit_table]
            self.send_flow_mod(remote_dp, rule, self.SRC_TABLE,
                               remote_ofproto.OFPFC_ADD,
                               self.SRC_PRI_TUNNEL_PASS, actions)

            # TUNNEL_OUT_TABLE: broadcast
            rule = cls_rule(tun_id=ev.tunnel_key, dl_dst=mac.BROADCAST)
            tunnel_ports = self._list_tunnel_port(remote_dp, remote_dpids)
            if tunnel_port_no not in tunnel_ports:
                tunnel_ports.append(tunnel_port_no)
            actions = [remote_ofproto_parser.OFPActionOutput(port_no)
                       for port_no in tunnel_ports]
            if len(actions) == 1:
                command = remote_dp.ofproto.OFPFC_ADD
            else:
                command = remote_dp.ofproto.OFPFC_MODIFY_STRICT
            resubmit_table = remote_ofproto_parser.NXActionResubmitTable(
                in_port=remote_ofproto.OFPP_IN_PORT,
                table=self.LOCAL_OUT_TABLE)
            actions.append(resubmit_table)
            self.send_flow_mod(remote_dp, rule, self.TUNNEL_OUT_TABLE,
                               command, self.TUNNEL_OUT_PRI_BROADCAST, actions)

            # TUNNEL_OUT_TABLE: multicast TODO:XXX

    def _vm_port_del(self, ev):
        dpid = ev.dpid
        dp = self.dpset.get(dpid)
        assert dp is not None
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser
        mac_address = ev.mac_address
        network_id = ev.network_id
        tunnel_key = ev.tunnel_key

        local_ports = []
        for port in self.nw.get_ports(dpid):
            if port.port_no == ev.port_no:
                continue
            if not self._port_is_active(network_id, dp, port):
                continue
            local_ports.append(port.port_no)

        last_instance = not local_ports

        # SRC_TABLE: VM-port unicast and catch-call
        rule = cls_rule(in_port=ev.port_no)
        self.send_flow_mod(dp, rule, self.SRC_TABLE, ofproto.OFPFC_DELETE,
                           ofproto.OFP_DEFAULT_PRIORITY,
                           [])  # priority is ignored

        if last_instance:
            # SRC_TABLE: TUNNEL-port: all tunnel matching
            rule = cls_rule(tun_id=tunnel_key)
            self.send_flow_mod(dp, rule, self.SRC_TABLE,
                               ofproto.OFPFC_DELETE,
                               ofproto.OFP_DEFAULT_PRIORITY,
                               [])  # priority is ignored

            # TUNNEL_OUT_TABLE: (tun_id & dl_dst) and tun_id
            rule = cls_rule(tun_id=tunnel_key)
            self.send_flow_mod(dp, rule, self.TUNNEL_OUT_TABLE,
                               ofproto.OFPFC_DELETE,
                               ofproto.OFP_DEFAULT_PRIORITY,
                               [])  # priority is ignored

            # LOCAL_OUT: tun_id catch-all drop rule
            rule = cls_rule(tun_id=tunnel_key)
            self.send_flow_mod(dp, rule, self.LOCAL_OUT_TABLE,
                               ofproto.OFPFC_DELETE,
                               ofproto.OFP_DEFAULT_PRIORITY,
                               [])  # priority is ignored
        else:
            # LOCAL_OUT_TABLE: unicast
            # live-migration: there can be two ports with same mac_address
            ports = self.nw.get_ports(dpid, network_id, mac_address)
            port_nos = [port.port_no for port in ports
                        if (port.port_no != ev.port_no and
                            self._link_is_up(dp, port.port_no))]
            rule = cls_rule(tun_id=tunnel_key, dl_dst=mac_address)
            if port_nos:
                assert len(ports) == 1
                actions = [ofproto_parser.OFPActionOutput(port_no)
                           for port_no in port_nos]
                self.send_flow_mod(dp, rule, self.LOCAL_OUT_TABLE,
                                   ofproto.OFPFC_MODIFY_STRICT,
                                   self.LOCAL_OUT_PRI_MAC, actions)
            else:
                self.send_flow_del(dp, rule, self.LOCAL_OUT_TABLE,
                                   ofproto.OFPFC_DELETE_STRICT,
                                   self.LOCAL_OUT_PRI_MAC, ev.port_no)

            # LOCAL_OUT_TABLE: broadcast
            rule = cls_rule(tun_id=tunnel_key, dl_dst=mac.BROADCAST)
            actions = [ofproto_parser.OFPActionOutput(port_no)
                       for port_no in local_ports]
            self.send_flow_mod(dp, rule, self.LOCAL_OUT_TABLE,
                               ofproto.OFPFC_MODIFY_STRICT,
                               self.LOCAL_OUT_PRI_BROADCAST, actions)

            # LOCAL_OUT_TABLE: multicast TODO:XXX

        # remote dp
        remote_dpids = self.nw.get_dpids(ev.network_id)
        if dpid in remote_dpids:
            remote_dpids.remove(dpid)
        for remote_dpid in remote_dpids:
            remote_dp = self.dpset.get(remote_dpid)
            if remote_dp is None:
                continue
            try:
                tunnel_port_no = self.tunnels.get_port(remote_dpid, dpid)
            except ryu_exc.PortNotFound:
                continue
            if not self._link_is_up(remote_dp, tunnel_port_no):
                continue

            remote_ofproto = remote_dp.ofproto
            remote_ofproto_parser = remote_dp.ofproto_parser

            if last_instance:
                # SRC_TABLE: TUNNEL-port
                rule = cls_rule(in_port=tunnel_port_no, tun_id=tunnel_key)
                self.send_flow_del(remote_dp, rule, self.SRC_TABLE,
                                   remote_ofproto.OFPFC_DELETE_STRICT,
                                   self.SRC_PRI_TUNNEL_PASS, None)

                # SRC_TABLE: TUNNEL-port catch-call drop rule
                rule = cls_rule(in_port=tunnel_port_no)
                self.send_flow_del(remote_dp, rule, self.SRC_TABLE,
                                   remote_ofproto.OFPFC_DELETE_STRICT,
                                   self.SRC_PRI_TUNNEL_DROP, None)

                # TUNNEL_OUT_TABLE: broadcast
                #                   tunnel_ports.remove(tunnel_port_no)
                rule = cls_rule(tun_id=tunnel_key, dl_dst=mac.BROADCAST)
                tunnel_ports = self._list_tunnel_port(remote_dp,
                                                      remote_dpids)
                assert tunnel_port_no not in tunnel_ports
                actions = [remote_ofproto_parser.OFPActionOutput(port_no)
                           for port_no in tunnel_ports]
                if not actions:
                    command = remote_dp.ofproto.OFPFC_DELETE_STRICT
                else:
                    command = remote_dp.ofproto.OFPFC_MODIFY_STRICT
                    resubmit_table = \
                        remote_ofproto_parser.NXActionResubmitTable(
                            in_port=remote_ofproto.OFPP_IN_PORT,
                            table=self.LOCAL_OUT_TABLE)
                    actions.append(resubmit_table)
                self.send_flow_mod(remote_dp, rule, self.TUNNEL_OUT_TABLE,
                                   command, self.TUNNEL_OUT_PRI_BROADCAST,
                                   actions)

            # TUNNEL_OUT_TABLE: unicast
            # live-migration: there can be more than one (dpid, port_no)
            #                 with a given mac address
            tunnel_ports = self._tunnel_port_with_mac(remote_dp, dpid,
                                                      network_id, ev.port_no,
                                                      mac_address)
            rule = cls_rule(tun_id=tunnel_key, dl_dst=mac_address)
            if tunnel_ports:
                outputs = [remote_ofproto_parser.OFPActionOutput(port_no)
                           for port_no in tunnel_ports]
                resubmit_table = remote_ofproto_parser.NXActionResubmitTable(
                    in_port=remote_ofproto.OFPP_IN_PORT,
                    table=self.LOCAL_OUT_TABLE)
                actions = outputs + [resubmit_table]
                self.send_flow_mod(remote_dp, rule, self.TUNNEL_OUT_TABLE,
                                   remote_ofproto.OFPFC_ADD,
                                   self.TUNNEL_OUT_PRI_MAC, actions)
            else:
                self.send_flow_del(remote_dp, rule, self.TUNNEL_OUT_TABLE,
                                   remote_ofproto.OFPFC_DELETE_STRICT,
                                   self.TUNNEL_OUT_PRI_MAC, tunnel_port_no)

            # TODO:XXX multicast

    def _get_vm_ports(self, dpid):
        ports = collections.defaultdict(list)
        for port in self.nw.get_ports(dpid):
            if port.network_id in RESERVED_NETWORK_IDS:
                continue
            ports[port.network_id].append(port)
        return ports

    def _tunnel_port_add(self, ev):
        dpid = ev.dpid
        dp = self.dpset.get(dpid)
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser
        remote_dpid = ev.remote_dpid

        local_ports = self._get_vm_ports(dpid)
        remote_ports = self._get_vm_ports(remote_dpid)

        # SRC_TABLE: TUNNEL-port catch-call drop rule
        # ingress flow from this tunnel port: remote -> tunnel port
        #            drop if unknown tunnel_key
        rule = cls_rule(in_port=ev.port_no)
        self.send_flow_mod(dp, rule, self.SRC_TABLE, ofproto.OFPFC_ADD,
                           self.SRC_PRI_TUNNEL_DROP, [])

        # SRC_TABLE: TUNNEL-port: pass if known tunnel_key
        for network_id in local_ports:
            try:
                tunnel_key = self.tunnels.get_key(network_id)
            except tunnels.TunnelKeyNotFound:
                continue
            if network_id not in remote_ports:
                continue

            rule = cls_rule(in_port=ev.port_no, tun_id=tunnel_key)
            resubmit_table = ofproto_parser.NXActionResubmitTable(
                in_port=ofproto.OFPP_IN_PORT, table=self.LOCAL_OUT_TABLE)
            actions = [resubmit_table]
            self.send_flow_mod(dp, rule, self.SRC_TABLE, ofproto.OFPFC_ADD,
                               self.SRC_PRI_TUNNEL_PASS, actions)

        # egress flow into this tunnel port: vm port -> tunnel port -> remote
        for network_id in local_ports:
            try:
                tunnel_key = self.tunnels.get_key(network_id)
            except tunnels.TunnelKeyNotFound:
                continue
            ports = remote_ports.get(network_id)
            if ports is None:
                continue

            # TUNNEL_OUT_TABLE: unicast
            for port in ports:
                if port.mac_address is None:
                    continue
                rule = cls_rule(tun_id=tunnel_key, dl_dst=port.mac_address)
                output = ofproto_parser.OFPActionOutput(ev.port_no)
                resubmit_table = ofproto_parser.NXActionResubmitTable(
                    in_port=ofproto.OFPP_IN_PORT, table=self.LOCAL_OUT_TABLE)
                actions = [output, resubmit_table]
                self.send_flow_mod(dp, rule, self.TUNNEL_OUT_TABLE,
                                   ofproto.OFPFC_ADD, self.TUNNEL_OUT_PRI_MAC,
                                   actions)

            # TUNNEL_OUT_TABLE: broadcast
            remote_dpids = self.nw.get_dpids(network_id)
            remote_dpids.remove(dpid)

            rule = cls_rule(tun_id=tunnel_key, dl_dst=mac.BROADCAST)
            tunnel_ports = self._list_tunnel_port(dp, remote_dpids)
            if ev.port_no not in tunnel_ports:
                tunnel_ports.append(ev.port_no)
            actions = [ofproto_parser.OFPActionOutput(port_no)
                       for port_no in tunnel_ports]
            resubmit_table = ofproto_parser.NXActionResubmitTable(
                in_port=ofproto.OFPP_IN_PORT, table=self.LOCAL_OUT_TABLE)
            actions.append(resubmit_table)
            if len(tunnel_ports) == 1:
                command = ofproto.OFPFC_ADD
            else:
                command = ofproto.OFPFC_MODIFY_STRICT
            self.send_flow_mod(dp, rule, self.TUNNEL_OUT_TABLE,
                               command, self.TUNNEL_OUT_PRI_BROADCAST, actions)

            # TUNNEL_OUT_TABLE: multicast TODO:XXX

    def _tunnel_port_del(self, ev):
        # almost nothing to do because all flow related to this tunnel port
        # should be handled by self._vm_port_del() as tunnel port deletion
        # follows vm port deletion.
        # the tunnel port is deleted if and only if no instance of same
        # tenants resides in both nodes of tunnel end points.
        self.logger.debug('tunnel_port_del %s', ev)
        dp = self.dpset.get(ev.dpid)

        # SRC_TABLE: TUNNEL-port catch-all drop rule
        rule = cls_rule(in_port=ev.port_no)
        self.send_flow_mod(dp, rule, self.SRC_TABLE,
                           dp.ofproto.OFPFC_DELETE_STRICT,
                           self.SRC_PRI_TUNNEL_DROP, [])

    @handler.set_ev_handler(PortSet.EventTunnelKeyDel)
    def tunnel_key_del_handler(self, ev):
        self.logger.debug('tunnel_key_del ev %s', ev)

    @handler.set_ev_handler(PortSet.EventVMPort)
    def vm_port_handler(self, ev):
        self.logger.debug('vm_port ev %s', ev)
        if ev.add_del:
            self._vm_port_add(ev)
        else:
            self._vm_port_del(ev)

    @handler.set_ev_handler(PortSet.EventTunnelPort)
    def tunnel_port_handler(self, ev):
        self.logger.debug('tunnel_port ev %s', ev)
        if ev.add_del:
            self._tunnel_port_add(ev)
        else:
            self._tunnel_port_del(ev)

    @handler.set_ev_handler(ofp_event.EventOFPPacketIn)
    def packet_in_handler(self, ev):
        # for debug
        msg = ev.msg
        self.logger.debug('packet in ev %s msg %s', ev, ev.msg)
        if msg.buffer_id != msg.datapath.ofproto.OFP_NO_BUFFER:
            msg.datapath.send_packet_out(msg.buffer_id, msg.in_port, [])
