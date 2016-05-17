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

import collections
import logging

import ryu.exception as ryu_exc
from ryu.base import app_manager
from ryu.controller import event


class RemoteDPIDAlreadyExist(ryu_exc.RyuException):
    message = ('port (%(dpid)s, %(port)s) has already '
               'remote dpid %(remote_dpid)s')


class TunnelKeyAlreadyExist(ryu_exc.RyuException):
    message = 'tunnel key %(tunnel_key)s already exists'


class TunnelKeyNotFound(ryu_exc.RyuException):
    message = 'no tunnel key for network %(network_id)s'


class EventTunnelKeyBase(event.EventBase):
    def __init__(self, network_id, tunnel_key):
        super(EventTunnelKeyBase, self).__init__()
        self.network_id = network_id
        self.tunnel_key = tunnel_key


class EventTunnelKeyAdd(EventTunnelKeyBase):
    """
    An event class for tunnel key registration.

    This event is generated when a tunnel key is registered or updated
    by the REST API.
    An instance has at least the following attributes.

    =========== ===============================================================
    Attribute   Description
    =========== ===============================================================
    network_id  Network ID
    tunnel_key  Tunnel Key
    =========== ===============================================================
    """

    def __init__(self, network_id, tunnel_key):
        super(EventTunnelKeyAdd, self).__init__(network_id, tunnel_key)


class EventTunnelKeyDel(EventTunnelKeyBase):
    """
    An event class for tunnel key registration.

    This event is generated when a tunnel key is removed by the REST API.
    An instance has at least the following attributes.

    =========== ===============================================================
    Attribute   Description
    =========== ===============================================================
    network_id  Network ID
    tunnel_key  Tunnel Key
    =========== ===============================================================
    """

    def __init__(self, network_id, tunnel_key):
        super(EventTunnelKeyDel, self).__init__(network_id, tunnel_key)


class EventTunnelPort(event.EventBase):
    """
    An event class for tunnel port registration.

    This event is generated when a tunnel port is added or removed
    by the REST API.
    An instance has at least the following attributes.

    =========== ===============================================================
    Attribute   Description
    =========== ===============================================================
    dpid        OpenFlow Datapath ID
    port_no     OpenFlow port number
    remote_dpid OpenFlow port number of the tunnel peer
    add_del     True for adding a tunnel.  False for removal.
    =========== ===============================================================
    """
    def __init__(self, dpid, port_no, remote_dpid, add_del):
        super(EventTunnelPort, self).__init__()
        self.dpid = dpid
        self.port_no = port_no
        self.remote_dpid = remote_dpid
        self.add_del = add_del


class TunnelKeys(dict):
    """network id(uuid) <-> tunnel key(32bit unsigned int)"""
    def __init__(self, f):
        super(TunnelKeys, self).__init__()
        self.send_event = f

    def get_key(self, network_id):
        try:
            return self[network_id]
        except KeyError:
            raise TunnelKeyNotFound(network_id=network_id)

    def _set_key(self, network_id, tunnel_key):
        self[network_id] = tunnel_key
        self.send_event(EventTunnelKeyAdd(network_id, tunnel_key))

    def register_key(self, network_id, tunnel_key):
        if network_id in self:
            raise ryu_exc.NetworkAlreadyExist(network_id=network_id)
        if tunnel_key in self.values():
            raise TunnelKeyAlreadyExist(tunnel_key=tunnel_key)
        self._set_key(network_id, tunnel_key)

    def update_key(self, network_id, tunnel_key):
        if network_id not in self and tunnel_key in self.values():
            raise TunnelKeyAlreadyExist(key=tunnel_key)

        key = self.get(network_id)
        if key is None:
            self._set_key(network_id, tunnel_key)
            return
        if key != tunnel_key:
            raise ryu_exc.NetworkAlreadyExist(network_id=network_id)

    def delete_key(self, network_id):
        try:
            tunnel_key = self[network_id]
            self.send_event(EventTunnelKeyDel(network_id, tunnel_key))
            del self[network_id]
        except KeyError:
            raise ryu_exc.NetworkNotFound(network_id=network_id)


class DPIDs(object):
    """dpid -> port_no -> remote_dpid"""
    def __init__(self, f):
        super(DPIDs, self).__init__()
        self.dpids = collections.defaultdict(dict)
        self.send_event = f

    def list_ports(self, dpid):
        return self.dpids[dpid]

    def _add_remote_dpid(self, dpid, port_no, remote_dpid):
        self.dpids[dpid][port_no] = remote_dpid
        self.send_event(EventTunnelPort(dpid, port_no, remote_dpid, True))

    def add_remote_dpid(self, dpid, port_no, remote_dpid):
        if port_no in self.dpids[dpid]:
            raise ryu_exc.PortAlreadyExist(dpid=dpid, port=port_no,
                                           network_id=None)
        self._add_remote_dpid(dpid, port_no, remote_dpid)

    def update_remote_dpid(self, dpid, port_no, remote_dpid):
        remote_dpid_ = self.dpids[dpid].get(port_no)
        if remote_dpid_ is None:
            self._add_remote_dpid(dpid, port_no, remote_dpid)
        elif remote_dpid_ != remote_dpid:
            raise ryu_exc.RemoteDPIDAlreadyExist(dpid=dpid, port=port_no,
                                                 remote_dpid=remote_dpid)

    def get_remote_dpid(self, dpid, port_no):
        try:
            return self.dpids[dpid][port_no]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=port_no)

    def delete_port(self, dpid, port_no):
        try:
            remote_dpid = self.dpids[dpid][port_no]
            self.send_event(EventTunnelPort(dpid, port_no, remote_dpid, False))
            del self.dpids[dpid][port_no]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=port_no)

    def get_port(self, dpid, remote_dpid):
        try:
            dp = self.dpids[dpid]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=None, network_id=None)

        res = [port_no for (port_no, remote_dpid_) in dp.items()
               if remote_dpid_ == remote_dpid]
        assert len(res) <= 1
        if len(res) == 0:
            raise ryu_exc.PortNotFound(dpid=dpid, port=None, network_id=None)
        return res[0]


class Tunnels(app_manager.RyuApp):
    def __init__(self):
        super(Tunnels, self).__init__()
        self.name = 'tunnels'
        self.tunnel_keys = TunnelKeys(self.send_event_to_observers)
        self.dpids = DPIDs(self.send_event_to_observers)

    def get_key(self, network_id):
        return self.tunnel_keys.get_key(network_id)

    def register_key(self, network_id, tunnel_key):
        self.tunnel_keys.register_key(network_id, tunnel_key)

    def update_key(self, network_id, tunnel_key):
        self.tunnel_keys.update_key(network_id, tunnel_key)

    def delete_key(self, network_id):
        self.tunnel_keys.delete_key(network_id)

    def list_ports(self, dpid):
        return self.dpids.list_ports(dpid).keys()

    def register_port(self, dpid, port_no, remote_dpid):
        self.dpids.add_remote_dpid(dpid, port_no, remote_dpid)

    def update_port(self, dpid, port_no, remote_dpid):
        self.dpids.update_remote_dpid(dpid, port_no, remote_dpid)

    def get_remote_dpid(self, dpid, port_no):
        return self.dpids.get_remote_dpid(dpid, port_no)

    def delete_port(self, dpid, port_no):
        self.dpids.delete_port(dpid, port_no)

    #
    # methods for gre tunnel
    #
    def get_port(self, dpid, remote_dpid):
        return self.dpids.get_port(dpid, remote_dpid)
