# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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

import collections

from ryu.base import app_manager
import ryu.exception as ryu_exc
from ryu.app.rest_nw_id import NW_ID_UNKNOWN
from ryu.controller import event
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortAlreadyExist, PortNotFound, PortUnknown


class MacAddressAlreadyExist(ryu_exc.RyuException):
    message = 'port (%(dpid)s, %(port)s) has already mac %(mac_address)s'


class EventNetworkDel(event.EventBase):
    def __init__(self, network_id):
        super(EventNetworkDel, self).__init__()
        self.network_id = network_id


class EventNetworkPort(event.EventBase):
    def __init__(self, network_id, dpid, port_no, add_del):
        super(EventNetworkPort, self).__init__()
        self.network_id = network_id
        self.dpid = dpid
        self.port_no = port_no
        self.add_del = add_del


class EventMacAddress(event.EventBase):
    def __init__(self, dpid, port_no, network_id, mac_address, add_del):
        super(EventMacAddress, self).__init__()
        assert network_id is not None
        assert mac_address is not None
        self.dpid = dpid
        self.port_no = port_no
        self.network_id = network_id
        self.mac_address = mac_address
        self.add_del = add_del


class Networks(dict):
    "network_id -> set of (dpid, port_no)"
    def __init__(self, f):
        super(Networks, self).__init__()
        self.send_event = f

    def list_networks(self):
        return self.keys()

    def has_network(self, network_id):
        return network_id in self

    def update_network(self, network_id):
        self.setdefault(network_id, set())

    def create_network(self, network_id):
        if network_id in self:
            raise NetworkAlreadyExist(network_id=network_id)

        self[network_id] = set()

    def remove_network(self, network_id):
        try:
            ports = self[network_id]
        except KeyError:
            raise NetworkNotFound(network_id=network_id)

        while ports:
            (dpid, port_no) = ports.pop()
            self._remove_event(network_id, dpid, port_no)
        if self.pop(network_id, None) is not None:
            self.send_event(EventNetworkDel(network_id))

    def list_ports(self, network_id):
        try:
            # use list() to keep compatibility for output
            # set() isn't json serializable
            return list(self[network_id])
        except KeyError:
            raise NetworkNotFound(network_id=network_id)

    def add_raw(self, network_id, dpid, port_no):
        self[network_id].add((dpid, port_no))

    def add_event(self, network_id, dpid, port_no):
        self.send_event(
            EventNetworkPort(network_id, dpid, port_no, True))

    # def add(self, network_id, dpid, port_no):
    #     self.add_raw(network_id, dpid, port_no)
    #     self.add_event(network_id, dpid, port_no)

    def _remove_event(self, network_id, dpid, port_no):
        self.send_event(EventNetworkPort(network_id, dpid, port_no, False))

    def remove_raw(self, network_id, dpid, port_no):
        ports = self[network_id]
        if (dpid, port_no) in ports:
            ports.remove((dpid, port_no))
            self._remove_event(network_id, dpid, port_no)

    def remove(self, network_id, dpid, port_no):
        try:
            self.remove_raw(network_id, dpid, port_no)
        except KeyError:
            raise NetworkNotFound(network_id=network_id)
        except ValueError:
            raise PortNotFound(network_id=network_id, dpid=dpid, port=port_no)

    def has_port(self, network_id, dpid, port):
        return (dpid, port) in self[network_id]

    def get_dpids(self, network_id):
        try:
            ports = self[network_id]
        except KeyError:
            return set()

        # python 2.6 doesn't support set comprehension
        # port = (dpid, port_no)
        return set([port[0] for port in ports])


class Port(object):
    def __init__(self, port_no, network_id, mac_address=None):
        super(Port, self).__init__()
        self.port_no = port_no
        self.network_id = network_id
        self.mac_address = mac_address


class DPIDs(dict):
    """dpid -> port_no -> Port(port_no, network_id, mac_address)"""
    def __init__(self, f, nw_id_unknown):
        super(DPIDs, self).__init__()
        self.send_event = f
        self.nw_id_unknown = nw_id_unknown

    def setdefault_dpid(self, dpid):
        return self.setdefault(dpid, {})

    def _setdefault_network(self, dpid, port_no, default_network_id):
        dp = self.setdefault_dpid(dpid)
        return dp.setdefault(port_no, Port(port_no=port_no,
                                           network_id=default_network_id))

    def setdefault_network(self, dpid, port_no):
        self._setdefault_network(dpid, port_no, self.nw_id_unknown)

    def update_port(self, dpid, port_no, network_id):
        port = self._setdefault_network(dpid, port_no, network_id)
        port.network_id = network_id

    def remove_port(self, dpid, port_no):
        try:
            # self.dpids[dpid][port_no] can be already deleted by
            # port_deleted()
            port = self[dpid].pop(port_no, None)
            if port and port.network_id and port.mac_address:
                self.send_event(EventMacAddress(dpid, port_no,
                                                port.network_id,
                                                port.mac_address,
                                                False))
        except KeyError:
            raise PortNotFound(dpid=dpid, port=port_no, network_id=None)

    def get_ports(self, dpid, network_id=None, mac_address=None):
        if network_id is None:
            return self.get(dpid, {}).values()
        if mac_address is None:
            return [p for p in self.get(dpid, {}).values()
                    if p.network_id == network_id]

        # live-migration: There can be two ports that have same mac address.
        return [p for p in self.get(dpid, {}).values()
                if p.network_id == network_id and p.mac_address == mac_address]

    def get_port(self, dpid, port_no):
        try:
            return self[dpid][port_no]
        except KeyError:
            raise PortNotFound(dpid=dpid, port=port_no, network_id=None)

    def get_network(self, dpid, port_no):
        try:
            return self[dpid][port_no].network_id
        except KeyError:
            raise PortUnknown(dpid=dpid, port=port_no)

    def get_networks(self, dpid):
        return set(self[dpid].values())

    def get_network_safe(self, dpid, port_no):
        port = self.get(dpid, {}).get(port_no)
        if port is None:
            return self.nw_id_unknown
        return port.network_id

    def get_mac(self, dpid, port_no):
        port = self.get_port(dpid, port_no)
        return port.mac_address

    def _set_mac(self, network_id, dpid, port_no, port, mac_address):
        if not (port.network_id is None or
                port.network_id == network_id or
                port.network_id == self.nw_id_unknown):
            raise PortNotFound(network_id=network_id, dpid=dpid, port=port_no)

        port.network_id = network_id
        port.mac_address = mac_address
        if port.network_id and port.mac_address:
            self.send_event(EventMacAddress(
                            dpid, port_no, port.network_id, port.mac_address,
                            True))

    def set_mac(self, network_id, dpid, port_no, mac_address):
        port = self.get_port(dpid, port_no)
        if port.mac_address is not None:
            raise MacAddressAlreadyExist(dpid=dpid, port=port_no,
                                         mac_address=mac_address)
        self._set_mac(network_id, dpid, port_no, port, mac_address)

    def update_mac(self, network_id, dpid, port_no, mac_address):
        port = self.get_port(dpid, port_no)
        if port.mac_address is None:
            self._set_mac(network_id, dpid, port_no, port, mac_address)
            return

        # For now, we don't allow changing mac address.
        if port.mac_address != mac_address:
            raise MacAddressAlreadyExist(dpid=dpid, port=port_no,
                                         mac_address=port.mac_address)


MacPort = collections.namedtuple('MacPort', ('dpid', 'port_no'))


class MacToPort(collections.defaultdict):
    """mac_address -> set of MacPort(dpid, port_no)"""
    def __init__(self):
        super(MacToPort, self).__init__(set)

    def add_port(self, dpid, port_no, mac_address):
        self[mac_address].add(MacPort(dpid, port_no))

    def remove_port(self, dpid, port_no, mac_address):
        ports = self[mac_address]
        ports.discard(MacPort(dpid, port_no))
        if not ports:
            del self[mac_address]

    def get_ports(self, mac_address):
        return self[mac_address]


class MacAddresses(dict):
    """network_id -> mac_address -> set of (dpid, port_no)"""
    def add_port(self, network_id, dpid, port_no, mac_address):
        mac2port = self.setdefault(network_id, MacToPort())
        mac2port.add_port(dpid, port_no, mac_address)

    def remove_port(self, network_id, dpid, port_no, mac_address):
        mac2port = self.get(network_id)
        if mac2port is None:
            return
        mac2port.remove_port(dpid, port_no, mac_address)
        if not mac2port:
            del self[network_id]

    def get_ports(self, network_id, mac_address):
        mac2port = self.get(network_id)
        if not mac2port:
            return set()
        return mac2port.get_ports(mac_address)


class Network(app_manager.RyuApp):
    def __init__(self, nw_id_unknown=NW_ID_UNKNOWN):
        super(Network, self).__init__()
        self.name = 'network'
        self.nw_id_unknown = nw_id_unknown
        self.networks = Networks(self.send_event_to_observers)
        self.dpids = DPIDs(self.send_event_to_observers, nw_id_unknown)
        self.mac_addresses = MacAddresses()

    def _check_nw_id_unknown(self, network_id):
        if network_id == self.nw_id_unknown:
            raise NetworkAlreadyExist(network_id=network_id)

    def list_networks(self):
        return self.networks.list_networks()

    def update_network(self, network_id):
        self._check_nw_id_unknown(network_id)
        self.networks.update_network(network_id)

    def create_network(self, network_id):
        self._check_nw_id_unknown(network_id)
        self.networks.create_network(network_id)

    def remove_network(self, network_id):
        self.networks.remove_network(network_id)

    def list_ports(self, network_id):
        return self.networks.list_ports(network_id)

    def list_ports_noraise(self, network_id):
        try:
            return self.list_ports(network_id)
        except NetworkNotFound:
            return []

    def _update_port(self, network_id, dpid, port, port_may_exist):
        def _known_nw_id(nw_id):
            return nw_id is not None and nw_id != self.nw_id_unknown

        queue_add_event = False
        self._check_nw_id_unknown(network_id)
        try:
            old_network_id = self.dpids.get_network_safe(dpid, port)
            if (self.networks.has_port(network_id, dpid, port) or
                    _known_nw_id(old_network_id)):
                if not port_may_exist:
                    raise PortAlreadyExist(network_id=network_id,
                                           dpid=dpid, port=port)

            if old_network_id != network_id:
                queue_add_event = True
                self.networks.add_raw(network_id, dpid, port)
                if _known_nw_id(old_network_id):
                    self.networks.remove_raw(old_network_id, dpid, port)
        except KeyError:
            raise NetworkNotFound(network_id=network_id)

        self.dpids.update_port(dpid, port, network_id)
        if queue_add_event:
            self.networks.add_event(network_id, dpid, port)

    def create_port(self, network_id, dpid, port):
        self._update_port(network_id, dpid, port, False)

    def update_port(self, network_id, dpid, port):
        self._update_port(network_id, dpid, port, True)

    def _get_old_mac(self, network_id, dpid, port_no):
        try:
            port = self.dpids.get_port(dpid, port_no)
        except PortNotFound:
            pass
        else:
            if port.network_id == network_id:
                return port.mac_address
        return None

    def remove_port(self, network_id, dpid, port_no):
        # generate event first, then do the real task
        old_mac_address = self._get_old_mac(network_id, dpid, port_no)

        self.dpids.remove_port(dpid, port_no)
        try:
            self.networks.remove(network_id, dpid, port_no)
        except NetworkNotFound:
            # port deletion can be called after network deletion
            # due to Openstack auto deletion port.(dhcp/router port)
            pass
        if old_mac_address is not None:
            self.mac_addresses.remove_port(network_id, dpid, port_no,
                                           old_mac_address)

    #
    # methods for gre tunnel
    #

    def get_dpids(self, network_id):
        return self.networks.get_dpids(network_id)

    def has_network(self, network_id):
        return self.networks.has_network(network_id)

    def get_networks(self, dpid):
        return self.dpids.get_networks(dpid)

    def create_mac(self, network_id, dpid, port_no, mac_address):
        self.mac_addresses.add_port(network_id, dpid, port_no, mac_address)
        self.dpids.set_mac(network_id, dpid, port_no, mac_address)

    def update_mac(self, network_id, dpid, port_no, mac_address):
        old_mac_address = self._get_old_mac(network_id, dpid, port_no)

        self.dpids.update_mac(network_id, dpid, port_no, mac_address)
        if old_mac_address is not None:
            self.mac_addresses.remove_port(network_id, dpid, port_no,
                                           old_mac_address)
        self.mac_addresses.add_port(network_id, dpid, port_no, mac_address)

    def get_mac(self, dpid, port_no):
        return self.dpids.get_mac(dpid, port_no)

    def list_mac(self, dpid, port_no):
        mac_address = self.dpids.get_mac(dpid, port_no)
        if mac_address is None:
            return []
        return [mac_address]

    def get_ports(self, dpid, network_id=None, mac_address=None):
        return self.dpids.get_ports(dpid, network_id, mac_address)

    def get_port(self, dpid, port_no):
        return self.dpids.get_port(dpid, port_no)

    def get_ports_with_mac(self, network_id, mac_address):
        return self.mac_addresses.get_ports(network_id, mac_address)

    #
    # methods for simple_isolation
    #

    def same_network(self, dpid, nw_id, out_port, allow_nw_id_external=None):
        assert nw_id != self.nw_id_unknown
        out_nw = self.dpids.get_network_safe(dpid, out_port)

        if nw_id == out_nw:
            return True

        if (allow_nw_id_external is not None and
                (allow_nw_id_external == nw_id or
                    allow_nw_id_external == out_nw)):
            # allow external network -> known network id
            return True

        self.logger.debug('blocked dpid %s nw_id %s out_port %d out_nw %s'
                          'external %s',
                          dpid, nw_id, out_port, out_nw, allow_nw_id_external)
        return False

    def get_network(self, dpid, port):
        return self.dpids.get_network(dpid, port)

    def add_datapath(self, ofp_switch_features):
        datapath = ofp_switch_features.datapath
        dpid = ofp_switch_features.datapath_id
        ports = ofp_switch_features.ports
        self.dpids.setdefault_dpid(dpid)
        for port_no in ports:
            self.port_added(datapath, port_no)

    def port_added(self, datapath, port_no):
        if port_no == 0 or port_no >= datapath.ofproto.OFPP_MAX:
            # skip fake output ports
            return

        self.dpids.setdefault_network(datapath.id, port_no)

    def port_deleted(self, dpid, port_no):
        self.dpids.remove_port(dpid, port_no)

    def filter_ports(self, dpid, in_port, nw_id, allow_nw_id_external=None):
        assert nw_id != self.nw_id_unknown
        ret = []

        for port in self.get_ports(dpid):
            nw_id_ = port.network_id
            if port.port_no == in_port:
                continue

            if nw_id_ == nw_id:
                ret.append(port.port_no)
            elif (allow_nw_id_external is not None and
                  nw_id_ == allow_nw_id_external):
                ret.append(port.port_no)

        return ret
