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

from oslo.config import cfg
import logging

from quantumclient import client as q_client
from quantumclient.common import exceptions as q_exc
from quantumclient.v2_0 import client as q_clientv2

from ryu.app import conf_switch_key as cs_key
from ryu.app import rest_nw_id
from ryu.base import app_manager
from ryu.controller import (conf_switch,
                            dpset,
                            event,
                            handler,
                            network)
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac as mac_lib
from ryu.lib import quantum_ifaces
from ryu.lib.ovs import bridge
from ryu.lib.quantum_ifaces import QuantumIfaces


from gevent import monkey
monkey.patch_all()


CONF = cfg.CONF


def _get_auth_token(logger):
    httpclient = q_client.HTTPClient(
        username=CONF.quantum_admin_username,
        tenant_name=CONF.quantum_admin_tenant_name,
        password=CONF.quantum_admin_password,
        auth_url=CONF.quantum_admin_auth_url,
        timeout=CONF.quantum_url_timeout,
        auth_strategy=CONF.quantum_auth_strategy)
    try:
        httpclient.authenticate()
    except (q_exc.Unauthorized, q_exc.Forbidden, q_exc.EndpointNotFound) as e:
        logger.error("authentication failure: %s", e)
        return None
    # logger.debug("_get_auth_token: token=%s", httpclient.auth_token)
    return httpclient.auth_token


def _get_quantum_client(token):
    if token:
        my_client = q_clientv2.Client(
            endpoint_url=CONF.quantum_url,
            token=token, timeout=CONF.quantum_url_timeout)
    else:
        my_client = q_clientv2.Client(
            endpoint_url=CONF.quantum_url,
            auth_strategy=None, timeout=CONF.quantum_url_timeout)
    return my_client


class OVSPort(object):
    PORT_ERROR = -1
    PORT_UNKNOWN = 0
    PORT_GATEWAY = 1
    PORT_VETH_GATEWAY = 2
    PORT_GUEST = 3
    PORT_TUNNEL = 4

    # extra-ids: 'attached-mac', 'iface-id', 'iface-status', 'vm-uuid'
    def __init__(self, ofport, port_name):
        super(OVSPort, self).__init__()
        self.ofport = ofport
        self.name = port_name
        self.type = None
        self.ext_ids = {}
        self.options = {}

    def update(self, port):
        self.__dict__.update((key, port[key]) for key
                             in ['name', 'ofport', 'type']
                             if key in port)
        if 'external_ids' in port:
            self.ext_ids = dict(port['external_ids'])
        if 'options' in port:
            self.options = dict(port['options'])

    def get_port_type(self):
        if not isinstance(self.ofport, int):
            return self.PORT_ERROR
        if self.type == 'internal' and 'iface-id' in self.ext_ids:
            return self.PORT_GATEWAY
        if self.type == '' and 'iface-id' in self.ext_ids:
            return self.PORT_VETH_GATEWAY
        if (self.type == 'gre' and 'local_ip' in self.options and
                'remote_ip' in self.options):
            return self.PORT_TUNNEL
        if self.type == '' and 'vm-uuid' in self.ext_ids:
            return self.PORT_GUEST
        return self.PORT_UNKNOWN

    def __str__(self):
        return "type=%s ofport=%s name=%s, ext_ids=%s options=%s" % (
            self.type, self.ofport, self.name, self.ext_ids, self.options)

    def __eq__(self, other):
        return (other is not None and
                self.ofport == other.ofport and
                self.type == other.type and
                self.ext_ids == other.ext_ids and
                self.options == other.options)


class OVSSwitch(object):
    def __init__(self, dpid, nw, ifaces, logger):
        # TODO: clean up
        token = None
        if CONF.quantum_auth_strategy:
            token = _get_auth_token(logger)
        q_api = _get_quantum_client(token)

        self.dpid = dpid
        self.network_api = nw
        self.ifaces = ifaces
        self.logger = logger
        self.q_api = q_api
        self.ctrl_addr = CONF.quantum_controller_addr

        self.ovsdb_addr = None
        self.tunnel_ip = None

        self.ovs_bridge = None
        self.ports = {}  # port_no -> OVSPort

        super(OVSSwitch, self).__init__()

    def set_ovsdb_addr(self, dpid, ovsdb_addr):
        # easy check if the address format valid
        self.logger.debug('set_ovsdb_addr dpid %s ovsdb_addr %s',
                          dpid_lib.dpid_to_str(dpid), ovsdb_addr)
        _proto, _host, _port = ovsdb_addr.split(':')

        old_address = self.ovsdb_addr
        if old_address == ovsdb_addr:
            return
        if ovsdb_addr is None:
            # TODO: clean up this ovs switch
            if self.ovs_bridge:
                self.ovs_bridge.del_controller()
                self.ovs_bridge = None
            return
        self.ovsdb_addr = ovsdb_addr
        if self.ovs_bridge is None:
            self.logger.debug('ovsdb: adding ports %s', self.ports)
            ovs_bridge = bridge.OVSBridge(dpid, ovsdb_addr)
            self.ovs_bridge = ovs_bridge
            ovs_bridge.init()
            # TODO: for multi-controller
            #       not overwrite controllers, but append this controller
            ovs_bridge.set_controller([self.ctrl_addr])
            for port in self.ports.values():
                self.logger.debug('adding port %s', port)
                self.update_port(port.ofport, port.name, True)

    def _update_external_port(self, port, add=True):
        if add:
            self.network_api.update_port(rest_nw_id.NW_ID_EXTERNAL,
                                         self.dpid, port.ofport)
        else:
            self.network_api.remove_port(rest_nw_id.NW_ID_EXTERNAL,
                                         self.dpid, port.ofport)

    def _update_vif_port(self, port, add=True):
        self.logger.debug("_update_vif_port: %s %s", port, add)
        iface_id = port.ext_ids.get('iface-id')
        if iface_id is None:
            return
        try:
            network_id = self.ifaces.get_key(iface_id,
                                             QuantumIfaces.KEY_NETWORK_ID)
        except KeyError:
            return

        if not add:
            self.network_api.remove_port(network_id, self.dpid, port.ofport)
            ports = self.ifaces.get_key(iface_id, QuantumIfaces.KEY_PORTS)
            other_ovs_ports = None
            for p in ports:
                dpid = p.get(QuantumIfaces.SUBKEY_DATAPATH_ID)
                if dpid is None:
                    continue
                if dpid != self.dpid:
                    continue

                other_ovs_ports = self.ifaces.del_key(iface_id,
                                                      QuantumIfaces.KEY_PORTS,
                                                      p)
            if other_ovs_ports:
                # When live-migration, one of the two OVS ports is deleted.
                return

            port_data = {
                'datapath_id': dpid_lib.dpid_to_str(self.dpid),
                'port_no': port.ofport,

                # In order to set
                # port.status = quantum.common.constants.PORT_STATUS_DOWN
                # port.status can't be changed via rest api directly,
                # so resort to ryu-specical parameter to tell it.
                'deleted': True
            }
            body = {'port': port_data}
            # self.logger.debug("port-body = %s", body)

            try:
                self.q_api.update_port(port.ext_ids['iface-id'], body)
            except (q_exc.ConnectionFailed, q_exc.QuantumClientException) as e:
                self.logger.error("quantum update port failed: %s", e)
                # TODO: When authentication failure occurred,
                # it should get auth token again
            return

        # update {network, port, mac}
        self.network_api.update_network(network_id)
        self.network_api.update_port(network_id, self.dpid, port.ofport)
        mac = port.ext_ids.get('attached-mac')
        if mac:
            self.network_api.update_mac(network_id, self.dpid, port.ofport,
                                        mac_lib.haddr_to_bin(mac))

    def update_port(self, port_no, port_name, add):
        self.logger.debug('update_port port_no %d %s %s', port_no, port_name,
                          add)
        assert port_name is not None
        old_port = self.ports.get(port_no)
        if not add:
            new_port = None
            self.ports.pop(port_no, None)
        else:
            new_port = OVSPort(port_no, port_name)
            if self.ovs_bridge:
                port_cfg = self.ovs_bridge.get_quantum_ports(port_name)
                if port_cfg:
                    if 'ofport' not in port_cfg or not port_cfg['ofport']:
                        port_cfg['ofport'] = port_no
                    elif port_cfg['ofport'] != port_no:
                        self.logger.warn('inconsistent port_no: %d port_cfg '
                                         '%s', port_no, port_cfg)
                        return
                    if port_cfg['name'] != port_name:
                        self.logger.warn('inconsistent port_name: %s '
                                         'port_cfg %s', port_name, port_cfg)
                        return
                    new_port.update(port_cfg)

            self.ports[port_no] = new_port
            iface_id = new_port.ext_ids.get('iface-id')
            if iface_id:
                p = {QuantumIfaces.SUBKEY_DATAPATH_ID: self.dpid,
                     QuantumIfaces.SUBKEY_OFPORT: port_no,
                     QuantumIfaces.SUBKEY_NAME: port_name}
                self.ifaces.update_key(iface_id, QuantumIfaces.KEY_PORTS, p)

        if old_port == new_port:
            return

        if not new_port:
            port_type = old_port.get_port_type()
            if port_type == OVSPort.PORT_ERROR:
                return
            elif port_type == OVSPort.PORT_UNKNOWN:
                # self.logger.info("delete external port: %s", old_port)
                self._update_external_port(old_port, add=False)
            else:
                # self.logger.info("delete port: %s", old_port)
                if port_type != OVSPort.PORT_TUNNEL:
                    self._update_vif_port(old_port, add=False)
            return

        if new_port.ofport == -1:
            return
        if not old_port or old_port.ofport == -1:
            port_type = new_port.get_port_type()
            if port_type == OVSPort.PORT_ERROR:
                return
            elif port_type == OVSPort.PORT_UNKNOWN:
                # self.logger.info("create external port: %s", new_port)
                self._update_external_port(new_port)
            else:
                # self.logger.info("create port: %s", new_port)
                if port_type != OVSPort.PORT_TUNNEL:
                    self._update_vif_port(new_port)
            return
        if new_port.get_port_type() in (OVSPort.PORT_GUEST,
                                        OVSPort.PORT_GATEWAY,
                                        OVSPort.PORT_VETH_GATEWAY):
            # self.logger.info("update port: %s", new_port)
            self._update_vif_port(new_port)


class QuantumAdapter(app_manager.RyuApp):
    _CONTEXTS = {
        'conf_switch': conf_switch.ConfSwitchSet,
        'network': network.Network,
        'quantum_ifaces': quantum_ifaces.QuantumIfaces,
    }

    def __init__(self, *_args, **kwargs):
        super(QuantumAdapter, self).__init__()

        self.cs = kwargs['conf_switch']
        self.nw = kwargs['network']
        self.ifaces = kwargs['quantum_ifaces']
        self.dps = {}

        for network_id in rest_nw_id.RESERVED_NETWORK_IDS:
            if network_id == rest_nw_id.NW_ID_UNKNOWN:
                continue
            self.nw.update_network(network_id)

    def _get_ovs_switch(self, dpid, create=True):
        ovs_switch = self.dps.get(dpid)
        if not ovs_switch:
            if create:
                ovs_switch = OVSSwitch(dpid, self.nw, self.ifaces, self.logger)
                self.dps[dpid] = ovs_switch
        else:
            self.logger.debug('ovs switch %s is already known', dpid)
        return ovs_switch

    def _port_handler(self, dpid, port_no, port_name, add):
        ovs_switch = self._get_ovs_switch(dpid)
        if ovs_switch:
            ovs_switch.update_port(port_no, port_name, add)
        else:
            self.logger.warn('unknown ovs switch %s %s %s %s\n',
                             dpid, port_no, port_name, add)

    @handler.set_ev_cls(dpset.EventDP)
    def dp_handler(self, ev):
        dpid = ev.dp.id
        ovs_switch = self._get_ovs_switch(dpid)
        if not ovs_switch:
            return

        if ev.enter:
            for port in ev.ports:
                ovs_switch.update_port(port.port_no, port.name, True)
        else:
            # When dp leaving, we don't delete ports because OF connection
            # can be disconnected for some reason.
            # TODO: configuration needed to tell that this dp is really
            # removed.
            self.dps.pop(dpid, None)

    @handler.set_ev_cls(dpset.EventPortAdd)
    def port_add_handler(self, ev):
        port = ev.port
        name = port.name.rstrip('\0')
        self._port_handler(ev.dp.id, port.port_no, name, True)

    @handler.set_ev_cls(dpset.EventPortDelete)
    def port_del_handler(self, ev):
        port = ev.port
        name = port.name.rstrip('\0')
        self._port_handler(ev.dp.id, port.port_no, name, False)

    def _conf_switch_set_ovsdb_addr(self, dpid, value):
        ovs_switch = self._get_ovs_switch(dpid)
        ovs_switch.set_ovsdb_addr(dpid, value)

    def _conf_switch_del_ovsdb_addr(self, dpid):
        ovs_switch = self._get_ovs_switch(dpid, False)
        if ovs_switch:
            ovs_switch.set_ovsdb_addr(dpid, None)

    @handler.set_ev_cls(conf_switch.EventConfSwitchSet)
    def conf_switch_set_handler(self, ev):
        self.logger.debug("conf_switch set: %s", ev)
        if ev.key == cs_key.OVSDB_ADDR:
            self._conf_switch_set_ovsdb_addr(ev.dpid, ev.value)
        else:
            self.logger.debug("unknown event: %s", ev)

    @handler.set_ev_cls(conf_switch.EventConfSwitchDel)
    def conf_switch_del_handler(self, ev):
        self.logger.debug("conf_switch del: %s", ev)
        if ev.key == cs_key.OVSDB_ADDR:
            self._conf_switch_del_ovsdb_addr(ev.dpid)
        else:
            self.logger.debug("unknown event: %s", ev)

    @handler.set_ev_cls(quantum_ifaces.EventQuantumIfaceSet)
    def quantum_iface_set_handler(self, ev):
        if ev.key != quantum_ifaces.QuantumIfaces.KEY_NETWORK_ID:
            # self.logger.debug("unknown key %s", ev.key)
            return
        iface_id = ev.iface_id
        try:
            ports = self.ifaces.get_key(iface_id, QuantumIfaces.KEY_PORTS)
        except KeyError:
            return
        for p in ports:
            try:
                dpid = p[QuantumIfaces.SUBKEY_DATAPATH_ID]
                ofport = p[QuantumIfaces.SUBKEY_OFPORT]
                port_name = p[QuantumIfaces.SUBKEY_NAME]
            except KeyError:
                continue
            ovs_switch = self._get_ovs_switch(dpid, False)
            if ovs_switch:
                ovs_switch.update_port(ofport, port_name, True)
