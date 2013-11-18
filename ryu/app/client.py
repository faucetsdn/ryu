# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

# This is a client library for Ryu REST API.  (ryu.app.rest_quantum etc)
# This module is *not* used by ryu-manager.
# Imported and used by OpenStack Ryu plug-in and agent.

import httplib
import json
import urlparse


def ignore_http_not_found(func):
    """
    Ignore http not found(404) with Ryu client library.
    Ryu client raises httplib.HTTPException with an error in args[0]
    """
    try:
        func()
    except httplib.HTTPException as e:
        res = e.args[0]
        if res.status != httplib.NOT_FOUND:
            raise


class RyuClientBase(object):
    def __init__(self, version, address):
        super(RyuClientBase, self).__init__()
        self.version = version
        res = urlparse.SplitResult('', address, '', '', '')
        self.host = res.hostname
        self.port = res.port
        self.url_prefix = '/' + self.version + '/'

    def _do_request(self, method, action, body=None):
        conn = httplib.HTTPConnection(self.host, self.port)
        url = self.url_prefix + action
        headers = {}
        if body is not None:
            body = json.dumps(body)
            headers['Content-Type'] = 'application/json'
        conn.request(method, url, body, headers)
        res = conn.getresponse()
        if res.status in (httplib.OK,
                          httplib.CREATED,
                          httplib.ACCEPTED,
                          httplib.NO_CONTENT):
            return res

        raise httplib.HTTPException(
            res, 'code %d reason %s' % (res.status, res.reason),
            res.getheaders(), res.read())

    def _do_request_read(self, method, action):
        res = self._do_request(method, action)
        return res.read()


class OFPClientV1_0(RyuClientBase):
    version = 'v1.0'

    # /networks/{network_id}/{dpid}_{port}/macs/{mac_address}
    path_networks = 'networks'
    path_network = path_networks + '/%s'
    path_port = path_network + '/%s_%s'
    path_macs = path_port + '/macs'
    path_mac = path_macs + '/%s'

    def __init__(self, address):
        super(OFPClientV1_0, self).__init__(OFPClientV1_0.version, address)

    def get_networks(self):
        return self._do_request_read('GET', self.path_networks)

    def create_network(self, network_id):
        self._do_request('POST', self.path_network % network_id)

    def update_network(self, network_id):
        self._do_request('PUT', self.path_network % network_id)

    def delete_network(self, network_id):
        self._do_request('DELETE', self.path_network % network_id)

    def get_ports(self, network_id):
        return self._do_request_read('GET', self.path_network % network_id)

    def create_port(self, network_id, dpid, port):
        self._do_request('POST', self.path_port % (network_id, dpid, port))

    def update_port(self, network_id, dpid, port):
        self._do_request('PUT', self.path_port % (network_id, dpid, port))

    def delete_port(self, network_id, dpid, port):
        self._do_request('DELETE', self.path_port % (network_id, dpid, port))

    def list_macs(self, network_id, dpid, port):
        return self._do_request_read('GET',
                                     self.path_macs % (network_id, dpid, port))

    def create_mac(self, network_id, dpid, port, mac_address):
        self._do_request('POST', self.path_mac % (network_id, dpid, port,
                                                  mac_address))

    def update_mac(self, network_id, dpid, port, mac_address):
        self._do_request('PUT', self.path_mac % (network_id, dpid, port,
                                                 mac_address))


OFPClient = OFPClientV1_0


class TunnelClientV1_0(RyuClientBase):
    version = 'v1.0'

    # /tunnels/networks/{network-id}/key/{tunnel_key}
    # /tunnels/switches/{dpid}/ports/{port-id}/{remote_dpip}
    path_tunnels = 'tunnels'
    path_key = path_tunnels + '/networks/%(network_id)s/key'
    path_tunnel_key = path_key + '/%(tunnel_key)s'
    path_ports = path_tunnels + '/switches/%(dpid)s/ports'
    path_port = path_ports + '/%(port_no)s'
    path_remote_dpid = path_port + '/%(remote_dpid)s'

    def __init__(self, address):
        super(TunnelClientV1_0, self).__init__(self.version, address)

    def get_tunnel_key(self, network_id):
        return self._do_request_read('GET', self.path_key % locals())

    def delete_tunnel_key(self, network_id):
        return self._do_request_read('DELETE', self.path_key % locals())

    def create_tunnel_key(self, network_id, tunnel_key):
        self._do_request('POST', self.path_tunnel_key % locals())

    def update_tunnel_key(self, network_id, tunnel_key):
        self._do_request('PUT', self.path_tunnel_key % locals())

    def list_ports(self, dpid):
        return self._do_request_read('GET', self.path_ports % locals())

    def delete_port(self, dpid, port_no):
        return self._do_request_read('DELETE', self.path_port % locals())

    def get_remote_dpid(self, dpid, port_no):
        return self._do_request_read('GET', self.path_port % locals())

    def create_remote_dpid(self, dpid, port_no, remote_dpid):
        self._do_request('POST', self.path_remote_dpid % locals())

    def update_remote_dpid(self, dpid, port_no, remote_dpid):
        self._do_request('PUT', self.path_remote_dpid % locals())


TunnelClient = TunnelClientV1_0


class SwitchConfClientV1_0(RyuClientBase):
    version = 'v1.0'

    # /conf/switches
    # /conf/switches/<dpid>
    # /conf/switches/<dpid>/<key>
    path_conf_switches = 'conf/switches'
    path_switch = path_conf_switches + '/%(dpid)s'
    path_key = path_switch + '/%(key)s'

    def __init__(self, address):
        super(SwitchConfClientV1_0, self).__init__(self.version, address)

    def list_switches(self):
        return self._do_request_read('GET', self.path_conf_switches)

    def delete_switch(self, dpid):
        self._do_request('DELETE', self.path_switch % locals())

    def list_keys(self, dpid):
        return self._do_request_read('GET', self.path_switch % locals())

    def set_key(self, dpid, key, value):
        self._do_request('PUT', self.path_key % locals(), value)

    def get_key(self, dpid, key):
        return self._do_request_read('GET', self.path_key % locals())

    def delete_key(self, dpid, key):
        self._do_request('DELETE', self.path_key % locals())


SwitchConfClient = SwitchConfClientV1_0


class QuantumIfaceClientV1_0(RyuClientBase):
    version = 'v1.0'

    # /quantum/ports
    # /quantum/ports/{iface_id}
    # /quantum/ports/{iface_id}/keys/
    # /quantum/ports/{iface_id}/keys/{key}/{value}
    path_quantum_ports = 'quantum/ports'
    path_iface_id = path_quantum_ports + '/%(iface_id)s'
    path_keys = path_iface_id + '/keys'
    path_key = path_keys + '/%(key)s'
    path_value = path_key + '/%(value)s'

    def __init__(self, address):
        super(QuantumIfaceClientV1_0, self).__init__(self.version, address)

    def list_ifaces(self):
        return self._do_request_read('GET', self.path_quantum_ports)

    def delete_iface(self, iface_id):
        self._do_request('DELETE', self.path_iface_id % locals())

    def list_keys(self, iface_id):
        return self._do_request_read('GET', self.path_keys % locals())

    def get_key(self, iface_id, key):
        return self._do_request_read('GET', self.path_key % locals())

    def create_key(self, iface_id, key, value):
        self._do_request('POST', self.path_value % locals())

    def update_key(self, iface_id, key, value):
        self._do_request('PUT', self.path_value % locals())

    # for convenience
    def get_network_id(self, iface_id):
        return self.get_key(iface_id, 'network_id')

    def create_network_id(self, iface_id, network_id):
        self.create_key(iface_id, 'network_id', network_id)

    def update_network_id(self, iface_id, network_id):
        self.update_key(iface_id, 'network_id', network_id)


QuantumIfaceClient = QuantumIfaceClientV1_0
NeutronIfaceClient = QuantumIfaceClient   # project rename quantum -> neutron


class TopologyClientV1_0(RyuClientBase):
    version = 'v1.0'

    # /topology/switches
    # /topology/switches/{dpid}
    # /topology/links
    # /topology/links/{dpid}
    _path_switches = 'topology/switches'
    _path_links = 'topology/links'

    def __init__(self, address):
        super(TopologyClientV1_0, self).__init__(self.version, address)

    # dpid: string representation (see ryu.lib.dpid)
    #       if None, get all
    def list_switches(self, dpid=None):
        uri = self._path_switches
        if dpid:
            uri += '/%s' % (dpid)

        return self._do_request('GET', uri)

    # dpid: string representation (see ryu.lib.dpid)
    #       if None, get all
    def list_links(self, dpid=None):
        uri = self._path_links
        if dpid:
            uri += '/%s' % (dpid)
        return self._do_request('GET', uri)


TopologyClient = TopologyClientV1_0
