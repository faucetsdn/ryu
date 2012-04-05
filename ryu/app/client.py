# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011,2012 Isaku Yamahata <yamahata at valinux co jp>
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


class OFPClientV1_0(object):
    version = 'v1.0'

    # /networks/{network_id}/{dpid}_{port}
    network_path = 'networks/%s'
    port_path = 'networks/%s/%s_%s'

    def __init__(self, address):
        r = urlparse.SplitResult('', address, '', '', '')
        self.host = r.hostname
        self.port = r.port
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

    def get_networks(self):
        res = self._do_request('GET', '')
        return res.read()

    def create_network(self, network_id):
        self._do_request('POST', self.network_path % network_id)

    def update_network(self, network_id):
        self._do_request('PUT', self.network_path % network_id)

    def delete_network(self, network_id):
        self._do_request('DELETE', self.network_path % network_id)

    def get_ports(self, network_id):
        res = self._do_request('GET', self.network_path % network_id)
        return res.read()

    def create_port(self, network_id, dpid, port):
        self._do_request('POST', self.port_path % (network_id, dpid, port))

    def update_port(self, network_id, dpid, port):
        self._do_request('PUT', self.port_path % (network_id, dpid, port))

    def delete_port(self, network_id, dpid, port):
        self._do_request('DELETE', self.port_path % (network_id, dpid, port))


OFPClient = OFPClientV1_0
