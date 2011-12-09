# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging

from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortAlreadyExist, PortNotFound, PortUnknown
from ryu.app.rest_nw_id import NW_ID_UNKNOWN

LOG = logging.getLogger('ryu.controller.network')


class network(object):
    def __init__(self, nw_id_unknown=NW_ID_UNKNOWN):
        self.nw_id_unknown = nw_id_unknown
        self.networks = {}
        self.dpids = {}

    def _check_nw_id_unknown(self, network_id):
        if network_id == self.nw_id_unknown:
            raise NetworkAlreadyExist(network_id=network_id)

    def list_networks(self):
        return self.networks.keys()

    def update_network(self, network_id):
        self._check_nw_id_unknown(network_id)
        self.networks.setdefault(network_id, set())

    def create_network(self, network_id):
        self._check_nw_id_unknown(network_id)
        if network_id in self.networks:
            raise NetworkAlreadyExist(network_id=network_id)

        self.networks[network_id] = set()

    def remove_network(self, network_id):
        try:
            del(self.networks[network_id])
        except KeyError:
            raise NetworkNotFound(network_id=network_id)

    def list_ports(self, network_id):
        try:
            # use list() to keep compatibility for output
            # set() isn't json serializable
            return list(self.networks[network_id])
        except KeyError:
            raise NetworkNotFound(network_id=network_id)

    def _update_port(self, network_id, dpid, port, port_may_exist):
        def _known_nw_id(nw_id):
            return nw_id is not None and nw_id != self.nw_id_unknown

        self._check_nw_id_unknown(network_id)
        try:
            old_network_id = self.dpids.get(dpid, {}).get(port, None)
            if ((dpid, port) in self.networks[network_id] or
                _known_nw_id(old_network_id)):
                if not port_may_exist:
                    raise PortAlreadyExist(network_id=network_id,
                                           dpid=dpid, port=port)

            if old_network_id != network_id:
                self.networks[network_id].add((dpid, port))
                if _known_nw_id(old_network_id):
                    self.networks[old_network_id].remove((dpid, port))
        except KeyError:
            raise NetworkNotFound(network_id=network_id)

        self.dpids.setdefault(dpid, {})
        self.dpids[dpid][port] = network_id

    def create_port(self, network_id, dpid, port):
        self._update_port(network_id, dpid, port, False)

    def update_port(self, network_id, dpid, port):
        self._update_port(network_id, dpid, port, True)

    def remove_port(self, network_id, dpid, port):
        try:
            self.networks[network_id].remove((dpid, port))
        except KeyError:
            raise NetworkNotFound(network_id=network_id)
        except ValueError:
            raise PortNotFound(network_id=network_id, dpid=dpid, port=port)

        del self.dpids[dpid][port]

    def same_network(self, dpid, nw_id, out_port, allow_nw_id_external=None):
        assert nw_id != self.nw_id_unknown
        dp = self.dpids.get(dpid, {})
        out_nw = dp.get(out_port)

        if nw_id == out_nw:
            return True

        if (allow_nw_id_external is not None and
            (allow_nw_id_external == nw_id or allow_nw_id_external == out_nw)):
            # allow external network -> known network id
            return True

        LOG.debug('blocked dpid %s nw_id %s out_port %d out_nw %s'
                  'external %s',
                  dpid, nw_id, out_port, out_nw, allow_nw_id_external)
        return False

    def get_network(self, dpid, port):
        try:
            return self.dpids[dpid][port]
        except KeyError:
            raise PortUnknown(dpid=dpid, port=port)

    def add_datapath(self, ofp_switch_features):
        datapath = ofp_switch_features.datapath
        dpid = ofp_switch_features.datapath_id
        ports = ofp_switch_features.ports
        self.dpids.setdefault(dpid, {})
        dp = self.dpids[dpid]
        for port_no in ports:
            if port_no == 0 or port_no >= datapath.ofproto.OFPP_MAX:
                # skip fake output ports
                continue

            if port_no not in dp:
                dp[port_no] = self.nw_id_unknown

    def filter_ports(self, dpid, in_port, nw_id, allow_nw_id_external=None):
        assert nw_id != self.nw_id_unknown
        ret = []

        ports = self.dpids.get(dpid, {})
        for port_no, _nw_id in ports.items():
            if port_no == in_port:
                continue

            if _nw_id == nw_id:
                ret.append(port_no)
            elif (allow_nw_id_external is not None and
                  _nw_id == allow_nw_id_external):
                ret.append(port_no)

        return ret
