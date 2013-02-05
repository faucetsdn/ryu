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

import httplib
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

    def _do_request(self, method, action):
        conn = httplib.HTTPConnection(self.host, self.port)
        url = self.url_prefix + action
        conn.request(method, url)
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

    # /networks/{network_id}/{dpid}_{port}
    path_networks = 'networks/%s'
    path_port = path_networks + '/%s_%s'

    def __init__(self, address):
        super(OFPClientV1_0, self).__init__(OFPClientV1_0.version, address)

    def get_networks(self):
        return self._do_request_read('GET', '')

    def create_network(self, network_id):
        self._do_request('POST', self.path_networks % network_id)

    def update_network(self, network_id):
        self._do_request('PUT', self.path_networks % network_id)

    def delete_network(self, network_id):
        self._do_request('DELETE', self.path_networks % network_id)

    def get_ports(self, network_id):
        return self._do_request_read('GET', self.path_networks % network_id)

    def create_port(self, network_id, dpid, port):
        self._do_request('POST', self.path_port % (network_id, dpid, port))

    def update_port(self, network_id, dpid, port):
        self._do_request('PUT', self.path_port % (network_id, dpid, port))

    def delete_port(self, network_id, dpid, port):
        self._do_request('DELETE', self.path_port % (network_id, dpid, port))


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
