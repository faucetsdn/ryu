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

# This module updates OVS tunnel ports for OpenStack integration.

import collections
from oslo.config import cfg
import logging
import netaddr

from ryu import exception as ryu_exc
from ryu.app import conf_switch_key as cs_key
from ryu.app import rest_nw_id
from ryu.base import app_manager
from ryu.controller import (conf_switch,
                            handler,
                            network,
                            tunnels)
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib.ovs import bridge as ovs_bridge


CONF = cfg.CONF
CONF.register_opts([
    cfg.StrOpt('tunnel-type', default='gre',
               help='tunnel type for ovs tunnel port')
])

_TUNNEL_TYPE_TO_NW_ID = {
    'gre': rest_nw_id.NW_ID_VPORT_GRE,
}


class NetworkAPI(object):
    """Internal adopter class for RestAPI"""
    def __init__(self, network_):
        super(NetworkAPI, self).__init__()
        self.nw = network_

    def update_network(self, network_id):
        self.nw.update_network(network_id)

    def create_port(self, network_id, dpid, port_id):
        self.nw.create_port(network_id, dpid, port_id)

    def update_port(self, network_id, dpid, port_id):
        self.nw.update_port(network_id, dpid, port_id)

    def delete_port(self, network_id, dpid, port_id):
        try:
            self.nw.remove_port(network_id, dpid, port_id)
        except (ryu_exc.NetworkNotFound, ryu_exc.PortNotFound):
            pass


class TunnelAPI(object):
    """Internal adopter class for RestTunnelAPI"""
    def __init__(self, tunnels_):
        super(TunnelAPI, self).__init__()
        self.tunnels = tunnels_

    def update_remote_dpid(self, dpid, port_id, remote_dpid):
        self.tunnels.update_port(dpid, port_id, remote_dpid)

    def create_remote_dpid(self, dpid, port_id, remote_dpid):
        self.tunnels.register_port(dpid, port_id, remote_dpid)

    def delete_port(self, dpid, port_id):
        try:
            self.tunnels.delete_port(dpid, port_id)
        except ryu_exc.PortNotFound:
            pass


class TunnelPort(object):
    def __init__(self, dpid, port_no, local_ip, remote_ip, remote_dpid=None):
        super(TunnelPort, self).__init__()
        self.dpid = dpid
        self.port_no = port_no
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.remote_dpid = remote_dpid

    def __eq__(self, other):
        return (self.dpid == other.dpid and
                self.port_no == other.port_no and
                self.local_ip == other.local_ip and
                self.remote_ip == other.remote_ip and
                self.remote_dpid == other.remote_dpid)


class TunnelDP(object):
    def __init__(self, dpid, ovsdb_addr, tunnel_ip, tunnel_type, conf_switch_,
                 network_api, tunnel_api, logger):
        super(TunnelDP, self).__init__()
        self.dpid = dpid
        self.network_api = network_api
        self.tunnel_api = tunnel_api
        self.logger = logger

        self.ovs_bridge = ovs_bridge.OVSBridge(dpid, ovsdb_addr)

        self.tunnel_ip = tunnel_ip
        self.tunnel_type = tunnel_type
        self.tunnel_nw_id = _TUNNEL_TYPE_TO_NW_ID[tunnel_type]
        self.tunnels = {}       # port number -> TunnelPort

        self.conf_switch = conf_switch_
        self.inited = False

        self.req_q = hub.Queue()
        self.thr = hub.spawn(self._serve_loop)

    def _init(self):
        self.ovs_bridge.init()
        for tp in self.ovs_bridge.get_tunnel_ports(self.tunnel_type):
            if tp.local_ip != self.tunnel_ip:
                self.logger.warn('unknown tunnel port %s', tp)
                continue

            remote_dpid = self.conf_switch.find_dpid(cs_key.OVS_TUNNEL_ADDR,
                                                     tp.remote_ip)
            self.tunnels[tp.ofport] = TunnelPort(self.dpid, tp.ofport,
                                                 self.tunnel_ip, tp.remote_ip,
                                                 remote_dpid)
            if remote_dpid:
                self._api_update(tp.ofport, remote_dpid)

        self.conf_switch = None
        self.inited = True

    def _api_update(self, port_no, remote_dpid):
        self.network_api.update_port(self.tunnel_nw_id, self.dpid, port_no)
        self.tunnel_api.update_remote_dpid(self.dpid, port_no, remote_dpid)

    def _api_delete(self, port_no):
        self.network_api.delete_port(self.tunnel_nw_id, self.dpid, port_no)
        self.tunnel_api.delete_port(self.dpid, port_no)

    def _update_remote(self, remote_dpid, remote_ip):
        if self.dpid == remote_dpid:
            if self.tunnel_ip == remote_ip:
                return

            # tunnel ip address is changed.
            self.logger.warn('local ip address is changed %s: %s -> %s',
                             dpid_lib.dpid_to_str(remote_dpid),
                             self.tunnel_ip, remote_ip)
            # recreate tunnel ports.
            for tp in list(self.tunnels.values()):
                if tp.remote_dpid is None:
                    # TODO:XXX
                    continue

                self._del_tunnel_port(tp.port_no, tp.local_ip, tp.remote_ip)

                new_tp = self._add_tunnel_port(tp.remote_dpid, tp.remote_ip)
                self._api_update(new_tp.ofport, tp.remote_dpid)
            return

        if self.tunnel_ip == remote_ip:
            self.logger.error('ip conflict: %s %s %s',
                              dpid_lib.dpid_to_str(self.dpid),
                              dpid_lib.dpid_to_str(remote_dpid), remote_ip)
            # XXX What should we do?
            return

        for tp in list(self.tunnels.values()):
            if tp.remote_dpid == remote_dpid:
                if tp.remote_ip == remote_ip:
                    self._api_update(tp.port_no, remote_dpid)
                    continue

                self.logger.warn('remote ip address is changed %s: %s -> %s',
                                 dpid_lib.dpid_to_str(remote_dpid),
                                 tp.remote_ip, remote_ip)
                self._del_tunnel_port(tp.port_no, self.tunnel_ip, tp.remote_ip)

                new_tp = self._add_tunnel_port(remote_dpid, remote_ip)
                self._api_update(new_tp.ofport, remote_dpid)
            elif tp.remote_ip == remote_ip:
                assert tp.remote_dpid is None
                self._api_update(tp.port_no, remote_dpid)
                tp.remote_dpid = remote_dpid

    @staticmethod
    def _to_hex(ip_addr):
        # assuming IPv4 address
        assert netaddr.IPAddress(ip_addr).ipv4()
        return "%02x%02x%02x%02x" % netaddr.IPAddress(ip_addr).words

    @staticmethod
    def _port_name(local_ip, remote_ip):
        # ovs requires requires less or equals to 14 bytes length
        # gre<remote>-<local lsb>
        _PORT_NAME_LENGTH = 14
        local_hex = TunnelDP._to_hex(local_ip)
        remote_hex = TunnelDP._to_hex(remote_ip)
        return ("gre%s-%s" % (remote_hex, local_hex))[:_PORT_NAME_LENGTH]

    def _tunnel_port_exists(self, remote_dpid, remote_ip):
        return any(tp.remote_dpid == remote_dpid and tp.remote_ip == remote_ip
                   for tp in self.tunnels.values())

    def _add_tunnel_port(self, remote_dpid, remote_ip):
        self.logger.debug('add_tunnel_port local %s %s remote %s %s',
                          dpid_lib.dpid_to_str(self.dpid), self.tunnel_ip,
                          dpid_lib.dpid_to_str(remote_dpid), remote_ip)
        if self._tunnel_port_exists(remote_dpid, remote_ip):
            self.logger.debug('add_tunnel_port nop')
            return

        self.logger.debug('add_tunnel_port creating port')
        port_name = self._port_name(self.tunnel_ip, remote_ip)
        self.ovs_bridge.add_tunnel_port(port_name, self.tunnel_type,
                                        self.tunnel_ip, remote_ip, 'flow')

        tp = self.ovs_bridge.get_tunnel_port(port_name, self.tunnel_type)
        self.tunnels[tp.ofport] = TunnelPort(self.dpid, tp.ofport,
                                             tp.local_ip, tp.remote_ip,
                                             remote_dpid)
        self.network_api.create_port(self.tunnel_nw_id, self.dpid, tp.ofport)
        self.tunnel_api.create_remote_dpid(self.dpid, tp.ofport, remote_dpid)
        return tp

    def _del_tunnel_port(self, port_no, local_ip, remote_ip):
        port_name = self._port_name(local_ip, remote_ip)
        self.ovs_bridge.del_port(port_name)
        del self.tunnels[port_no]
        self._api_delete(port_no)

    def _del_tunnel_port_ip(self, remote_ip):
        for tp in self.tunnels.values():
            if tp.remote_ip == remote_ip:
                self._del_tunnel_port(tp.port_no, self.tunnel_ip, remote_ip)
                break

    # serialize requests to this OVS DP
    _RequestUpdateRemote = collections.namedtuple('_RequestUpdateRemote',
                                                 ('remote_dpid', 'remote_ip'))
    _RequestAddTunnelPort = collections.namedtuple('_RequestAddTunnelPort',
                                                  ('remote_dpid', 'remote_ip'))
    _RequestDelTunnelPort = collections.namedtuple('_RequestDelTunnelPort',
                                                  ('remote_ip'))

    class _RequestClose(object):
        pass

    def request_update_remote(self, remote_dpid, remote_ip):
        self.req_q.put(self._RequestUpdateRemote(remote_dpid, remote_ip))

    def request_add_tunnel_port(self, remote_dpid, remote_ip):
        self.req_q.put(self._RequestAddTunnelPort(remote_dpid, remote_ip))

    def request_del_tunnel_port(self, remote_ip):
        self.req_q.put(self._RequestDelTunnelPort(remote_ip))

    def close(self):
        # self.thr.kill()
        self.req_q.put(self._RequestClose())
        self.thr.join()
        self.thr = None

    def _serve_loop(self):
        # TODO:XXX backoff timeout
        # TOOD:XXX and then, abandon and notify the caller(TunnelPortUpdater)

        # TODO: if possible, squash requests?
        #       For example, RequestAddTunnelPort and RequestDelTunnelPort
        #       with same dpid are in the queue. AddTunnelPort request
        #       can be skipped.
        #       When ovsdb-server and vswitchd are over-loaded
        #       (or connection to ovsdb are unstable), squashing request
        #       would increase stability a bit?
        #       But unsure how effective it would be.

        if not self.inited:
            try:
                self._init()
            except hub.Timeout:
                self.logger.warn('_init timeouted')

        req = None
        while True:
            if req is None:
                req = self.req_q.get()
                if isinstance(req, self._RequestClose):
                    return

            try:
                if not self.inited:
                    self._init()

                # shoud use dispatcher?
                if isinstance(req, self._RequestUpdateRemote):
                    self.logger.debug('update_remote')
                    self._update_remote(req.remote_dpid, req.remote_ip)
                elif isinstance(req, self._RequestAddTunnelPort):
                    self.logger.debug('add_tunnel_port')
                    self._add_tunnel_port(req.remote_dpid, req.remote_ip)
                elif isinstance(req, self._RequestDelTunnelPort):
                    self.logger.debug('del_tunnel_port')
                    self._del_tunnel_port_ip(req.remote_ip)
                else:
                    self.logger.error('unknown request %s', req)
            except hub.Timeout:
                # timeout. try again
                self.logger.warn('timeout try again')
                continue
            else:
                # Done. move onto next request
                req = None


class TunnelDPSet(dict):
    """ dpid -> TunndlDP """
    pass


#import collections
#class TunnelRequests(collections.defaultdict(set)):
class TunnelRequests(dict):
    def add(self, dpid0, dpid1):
        self.setdefault(dpid0, set()).add(dpid1)
        self.setdefault(dpid1, set()).add(dpid0)

    def remove(self, dpid0, dpid1):
        self[dpid0].remove(dpid1)
        self[dpid1].remove(dpid0)

    def get_remote(self, dpid):
        return self.setdefault(dpid, set())


class TunnelPortUpdater(app_manager.RyuApp):
    _CONTEXTS = {
        'conf_switch': conf_switch.ConfSwitchSet,
        'network': network.Network,
        'tunnels': tunnels.Tunnels,
    }

    def __init__(self, *args, **kwargs):
        super(TunnelPortUpdater, self).__init__(args, kwargs)
        self.tunnel_type = CONF.tunnel_type
        self.cs = kwargs['conf_switch']
        self.nw = kwargs['network']
        self.tunnels = kwargs['tunnels']
        self.tunnel_dpset = TunnelDPSet()
        self.tunnel_requests = TunnelRequests()

        self.network_api = NetworkAPI(self.nw)
        self.tunnel_api = TunnelAPI(self.tunnels)
        self.network_api.update_network(
            _TUNNEL_TYPE_TO_NW_ID[self.tunnel_type])

    def _ovsdb_update(self, dpid, ovsdb_addr, ovs_tunnel_addr):
        self.logger.debug('_ovsdb_update %s %s %s',
                          dpid_lib.dpid_to_str(dpid), ovsdb_addr,
                          ovs_tunnel_addr)
        if dpid not in self.tunnel_dpset:
            # TODO:XXX changing ovsdb_addr, ovs_tunnel_addr
            tunnel_dp = TunnelDP(dpid, ovsdb_addr, ovs_tunnel_addr,
                                 self.tunnel_type, self.cs,
                                 self.network_api, self.tunnel_api,
                                 self.logger)
            self.tunnel_dpset[dpid] = tunnel_dp

        tunnel_dp = self.tunnel_dpset.get(dpid)
        assert tunnel_dp
        self._add_tunnel_ports(tunnel_dp,
                               self.tunnel_requests.get_remote(dpid))

    @handler.set_ev_cls(conf_switch.EventConfSwitchSet)
    def conf_switch_set_handler(self, ev):
        self.logger.debug('conf_switch_set_handler %s %s %s',
                          dpid_lib.dpid_to_str(ev.dpid), ev.key, ev.value)
        dpid = ev.dpid
        if (ev.key == cs_key.OVSDB_ADDR or ev.key == cs_key.OVS_TUNNEL_ADDR):
            if ((dpid, cs_key.OVSDB_ADDR) in self.cs and
                    (dpid, cs_key.OVS_TUNNEL_ADDR) in self.cs):
                self._ovsdb_update(
                    dpid, self.cs.get_key(dpid, cs_key.OVSDB_ADDR),
                    self.cs.get_key(dpid, cs_key.OVS_TUNNEL_ADDR))

        if ev.key == cs_key.OVS_TUNNEL_ADDR:
            for tunnel_dp in self.tunnel_dpset.values():
                tunnel_dp.request_update_remote(ev.dpid, ev.value)

    @handler.set_ev_cls(conf_switch.EventConfSwitchDel)
    def conf_switch_del_handler(self, ev):
        # TODO:XXX
        pass

    def _add_tunnel_ports(self, tunnel_dp, remote_dpids):
        self.logger.debug('_add_tunnel_ports %s %s', tunnel_dp, remote_dpids)
        for remote_dpid in remote_dpids:
            remote_dp = self.tunnel_dpset.get(remote_dpid)
            if remote_dp is None:
                continue
            tunnel_dp.request_add_tunnel_port(remote_dp.dpid,
                                              remote_dp.tunnel_ip)
            remote_dp.request_add_tunnel_port(tunnel_dp.dpid,
                                              tunnel_dp.tunnel_ip)

    def _vm_port_add(self, network_id, dpid):
        self.logger.debug('_vm_port_add %s %s', network_id,
                          dpid_lib.dpid_to_str(dpid))
        dpids = self.nw.get_dpids(network_id)
        dpids.remove(dpid)
        for remote_dpid in dpids:
            self.tunnel_requests.add(dpid, remote_dpid)

        tunnel_dp = self.tunnel_dpset.get(dpid)
        if tunnel_dp is None:
            return
        self._add_tunnel_ports(tunnel_dp, dpids)

    def _vm_port_del(self, network_id, dpid):
        self.logger.debug('_vm_port_del %s %s', network_id,
                          dpid_lib.dpid_to_str(dpid))
        if len(self.nw.get_ports(dpid, network_id)) > 0:
            return

        tunnel_networks = set(p.network_id
                              for p in self.nw.get_networks(dpid))
        tunnel_networks.discard(network_id)
        tunnel_networks.difference_update(rest_nw_id.RESERVED_NETWORK_IDS)
        dpids = self.nw.get_dpids(network_id).copy()
        dpids.discard(dpid)
        del_dpids = []
        for remote_dpid in dpids:
            remote_networks = set(p.network_id
                                  for p in self.nw.get_networks(remote_dpid))
            if tunnel_networks & remote_networks:
                continue
            self.tunnel_requests.remove(dpid, remote_dpid)
            del_dpids.append(remote_dpid)

        tunnel_dp = self.tunnel_dpset.get(dpid)
        if tunnel_dp is None:
            return
        for remote_dpid in del_dpids:
            remote_dp = self.tunnel_dpset.get(remote_dpid)
            if remote_dp is None:
                continue
            tunnel_dp.request_del_tunnel_port(remote_dp.tunnel_ip)
            remote_dp.request_del_tunnel_port(tunnel_dp.tunnel_ip)

    @handler.set_ev_cls(network.EventNetworkPort)
    def network_port_handler(self, ev):
        self.logger.debug('network_port_handler %s', ev)
        if ev.network_id in rest_nw_id.RESERVED_NETWORK_IDS:
            return

        if ev.add_del:
            self._vm_port_add(ev.network_id, ev.dpid)
        else:
            self._vm_port_del(ev.network_id, ev.dpid)
