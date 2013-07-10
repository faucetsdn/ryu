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

from ryu.app import (conf_switch_key,
                     rest_nw_id)
from ryu.base import app_manager
from ryu.controller import (conf_switch,
                            dpset,
                            handler,
                            network,
                            tunnels)
import ryu.exception as ryu_exc
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib.ovs import bridge
from ryu.ofproto import nx_match


def _is_reserved_port(dp, port_no):
    return port_no > dp.ofproto.OFPP_MAX


class SimpleVLAN(app_manager.RyuApp):
    _CONTEXTS = {
        'conf_switch': conf_switch.ConfSwitchSet,
        'dpset': dpset.DPSet,
        'network': network.Network,
        'tunnels': tunnels.Tunnels,
    }

    _PRIORITY_CATCHALL = 1
    _PRIORITY_NORMAL = 2

    _COOKIE_CATCHALL = 1
    _COOKIE_NORMAL = 2

    def __init__(self, *args, **kwargs):
        super(SimpleVLAN, self).__init__(*args, **kwargs)
        self.conf_sw = kwargs['conf_switch']
        self.dpset = kwargs['dpset']
        self.nw = kwargs['network']
        self.tunnels = kwargs['tunnels']

    def _port_flow_add(self, dp, port_no):
        self.logger.debug('ovs_port_update dpid %s port_no %s',
                          dpid_lib.dpid_to_str(dp.id), port_no)
        rule = nx_match.ClsRule()
        rule.set_in_port(port_no)
        ofproto = dp.ofproto
        actions = [dp.ofproto_parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        dp.send_flow_mod(rule=rule, cookie=self._COOKIE_NORMAL,
                         command=ofproto.OFPFC_ADD,
                         idle_timeout=0, hard_timeout=0,
                         priority=self._PRIORITY_NORMAL, actions=actions)

    def _port_flow_del(self, dp, port_no):
        self.logger.debug('_port_flow_del dp %s port_no %d',
                          dpid_lib.dpid_to_str(dp.id), port_no)
        rule = nx_match.ClsRule()
        rule.set_in_port(port_no)
        dp.send_flow_del(rule=rule, cookie=self._COOKIE_NORMAL)

    def _queue_port_flow_add(self, dp, port_no):
        self._port_flow_add(dp, port_no)

    def _queue_port_flow_del(self, dp, port_no):
        self._port_flow_del(dp, port_no)

    @handler.set_ev_cls(dpset.EventDP)
    def dp_handler(self, ev):
        if not ev.enter:
            return

        dp = ev.dp
        rule = nx_match.ClsRule()
        ofproto = dp.ofproto
        dp.send_flow_mod(rule=rule,
                         cookie=self._COOKIE_CATCHALL,
                         command=ofproto.OFPFC_ADD,
                         idle_timeout=0, hard_timeout=0,
                         priority=self._PRIORITY_CATCHALL,
                         actions=[])
        for port in ev.ports:
            self._port_add(dp, port.port_no)

    # There is no ordering between those events
    #   port creation: PortAdd event
    #   network_id assignment: NetworkPort event
    #   tunnel_key assignment: TunnelKeyAdd event
    #   ovsdb_addr: EventConfSwitchSet
    # So on each events, check all necessary parameters are setup
    def _port_setup(self, dp, port_no, tunnel_key):
        if _is_reserved_port(dp, port_no):
            return

        dpid = dp.id
        try:
            port = self.dpset.get_port(dpid, port_no)
        except ryu_exc.PortNotFound:
            self.logger.debug('port not found')
            return

        try:
            ovsdb_addr = self.conf_sw.get_key(dpid, conf_switch_key.OVSDB_ADDR)
        except KeyError:
            self.logger.debug('ovsdb_addr not found')
            return

        self._port_flow_add(dp, port_no)

        self.logger.debug('ovs_port_update dpid %s port_no %s', dpid, port_no)
        # ovs-vsctl --db=ovsdb_addr --timeout=2
        # set Port port.name tag=tunnel_key
        ovs_br = bridge.OVSBridge(dpid, ovsdb_addr, 2)
        # ofp_phy_port::name is zero-padded
        port_name = port.name.rstrip('\x00')
        try:
            ovs_br.set_db_attribute("Port", port_name, "tag", tunnel_key)
        except hub.Timeout:
            self.logger.error('timeout')
            return

        return True

    def _port_setup_netid(self, dpid, port_no, network_id):
        self.logger.debug('_port_setup_netid %s %s %s',
                          dpid_lib.dpid_to_str(dpid), port_no, network_id)
        dp = self.dpset.get(dpid)
        if dp is None:
            self.logger.debug('dp not found')
            return
        if _is_reserved_port(dp, port_no):
            return

        if network_id == rest_nw_id.NW_ID_EXTERNAL:
            self.logger.debug('external interface')
            self._queue_port_flow_add(dp, port_no)
            return True

        try:
            tunnel_key = self.tunnels.get_key(network_id)
        except tunnels.TunnelKeyNotFound:
            self.logger.debug('tunnel key not found')
            return

        return self._port_setup(dp, port_no, tunnel_key)

    def _port_add(self, dp, port_no):
        if _is_reserved_port(dp, port_no):
            return

        dpid = dp.id
        try:
            network_id = self.nw.get_network(dpid, port_no)
        except ryu_exc.PortUnknown:
            self.logger.debug('port_unknown')
            self._queue_port_flow_del(dp, port_no)
            return

        if not self._port_setup_netid(dpid, port_no, network_id):
            self.logger.debug('_port_setup_netid failed')
            self._queue_port_flow_del(dp, port_no)

    @handler.set_ev_cls(dpset.EventPortAdd)
    def port_add_handler(self, ev):
        self.logger.debug('port_add %s', ev)
        self._port_add(ev.dp, ev.port.port_no)

    @handler.set_ev_cls(dpset.EventPortDelete)
    def port_del_handler(self, ev):
        self.logger.debug('port_del %s', ev)
        dp = ev.dp
        port_no = ev.port.port_no
        if _is_reserved_port(dp, port_no):
            return
        self._queue_port_flow_del(dp, port_no)

    @handler.set_ev_cls(network.EventNetworkPort)
    def network_port_handler(self, ev):
        self.logger.debug('network_port %s', ev)
        if not ev.add_del:
            return
        self._port_setup_netid(ev.dpid, ev.port_no, ev.network_id)

    @handler.set_ev_cls(tunnels.EventTunnelKeyAdd)
    def tunnel_key_add_handler(self, ev):
        self.logger.debug('tunnel_add %s', ev)
        tunnel_key = ev.tunnel_key
        for (dpid, port_no) in self.nw.list_ports_noraise(ev.network_id):
            dp = self.dpset.get(dpid)
            if dp is None:
                continue
            self._port_setup(dp, port_no, tunnel_key)

    @handler.set_ev_cls(conf_switch.EventConfSwitchSet)
    def conf_switch_set_handler(self, ev):
        self.logger.debug('conf_switch_set %s', ev)
        if ev.key != conf_switch_key.OVSDB_ADDR:
            return

        dpid = ev.dpid
        try:
            ports = self.dpset.get_ports(dpid)
        except KeyError:
            return
        for port in ports:
            port_no = port.port_no
            try:
                network_id = self.nw.get_network(dpid, port_no)
            except ryu_exc.PortUnknown:
                continue
            self._port_setup_netid(dpid, port_no, network_id)
