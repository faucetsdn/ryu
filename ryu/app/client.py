# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import httplib
import urlparse


class OFPClientV1_0(object):
    version = 'v1.0'

    # /{network_id}/{dpid}_{port}
    network_path = '%s'
    port_path = '%s/%s_%s'

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
