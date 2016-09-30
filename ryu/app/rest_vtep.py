# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

"""
This sample application performs as VTEP for EVPN VXLAN and constructs
a Single Subnet per EVI corresponding to the VLAN Based service in [RFC7432].

.. NOTE::

    This app will invoke OVSDB request to the switches.
    Please set the manager address before calling the API of this app.

    ::

        $ sudo ovs-vsctl set-manager ptcp:6640
        $ sudo ovs-vsctl show
            ...(snip)
            Manager "ptcp:6640"
            ...(snip)


Usage Example
=============

Environment
-----------

This example supposes the following environment::

     Host A (172.17.0.1)                      Host B (172.17.0.2)
    +--------------------+                   +--------------------+
    |   Ryu1             | --- BGP(EVPN) --- |   Ryu2             |
    +--------------------+                   +--------------------+
            |                                       |
    +--------------------+                   +--------------------+
    |   s1 (OVS)         | ===== vxlan ===== |   s2 (OVS)         |
    +--------------------+                   +--------------------+
    (s1-eth1)    (s1-eth2)                   (s2-eth1)    (s2-eth2)
       |            |                           |            |
    +--------+  +--------+                   +--------+  +--------+
    | s1h1   |  | s1h2   |                   | s2h1   |  | s2h2   |
    +--------+  +--------+                   +--------+  +--------+

Configuration steps
-------------------

1. Creates a new BGPSpeaker instance on each host.

    On Host A::

        (Host A)$ curl -X POST -d '{
         "dpid": 1,
         "as_number": 65000,
         "router_id": "172.17.0.1"
         }' http://localhost:8080/vtep/speakers | python -m json.tool

    On Host B::

        (Host B)$ curl -X POST -d '{
         "dpid": 1,
         "as_number": 65000,
         "router_id": "172.17.0.2"
         }' http://localhost:8080/vtep/speakers | python -m json.tool

2. Registers the neighbor for the speakers on each host.

    On Host A::

        (Host A)$ curl -X POST -d '{
         "address": "172.17.0.2",
         "remote_as": 65000
         }' http://localhost:8080/vtep/neighbors |
         python -m json.tool

    On Host B::

        (Host B)$ curl -X POST -d '{
         "address": "172.17.0.1",
         "remote_as": 65000
         }' http://localhost:8080/vtep/neighbors |
         python -m json.tool

3. Defines a new VXLAN network(VNI=10) on the Host A/B.

    On Host A::

        (Host A)$ curl -X POST -d '{
         "vni": 10
         }' http://localhost:8080/vtep/networks | python -m json.tool

    On Host B::

        (Host B)$ curl -X POST -d '{
         "vni": 10
         }' http://localhost:8080/vtep/networks | python -m json.tool

4. Registers the clients to the VXLAN network.

    For "s1h1"(ip="10.0.0.11", mac="aa:bb:cc:00:00:11") on Host A::

        (Host A)$ curl -X POST -d '{
         "port": "s1-eth1",
         "mac": "aa:bb:cc:00:00:11",
         "ip": "10.0.0.11"
         } ' http://localhost:8080/vtep/networks/10/clients |
         python -m json.tool

    For "s2h1"(ip="10.0.0.21", mac="aa:bb:cc:00:00:21") on Host B::

        (Host B)$ curl -X POST -d '{
         "port": "s2-eth1",
         "mac": "aa:bb:cc:00:00:21",
         "ip": "10.0.0.21"
         } ' http://localhost:8080/vtep/networks/10/clients |
         python -m json.tool

Testing
-------

If BGP (EVPN) connection between Ryu1 and Ryu2 has been established,
pings between the client s1h1 and s2h1 should work.

::

    (s1h1)$ ping 10.0.0.21


Troubleshooting
---------------

If connectivity between s1h1 and s2h1 isn't working,
please check the followings.

1. Make sure that Host A and Host B have full network connectivity.

    ::

        (Host A)$ ping 172.17.0.2

2. Make sure that BGP(EVPN) connection has been established.

    ::

        (Host A)$ curl -X GET http://localhost:8080/vtep/neighbors |
         python -m json.tool

        ...
        {
            "172.17.0.2": {
                "EvpnNeighbor": {
                    "address": "172.17.0.2",
                    "remote_as": 65000,
                    "state": "up"  # "up" shows the connection established
                }
            }
        }

3. Make sure that BGP(EVPN) routes have been advertised.

    ::

        (Host A)$ curl -X GET http://localhost:8080/vtep/networks |
         python -m json.tool

         ...
        {
            "10": {
                "EvpnNetwork": {
                    "clients": {
                        "aa:bb:cc:00:00:11": {
                            "EvpnClient": {
                                "ip": "10.0.0.11",
                                "mac": "aa:bb:cc:00:00:11",
                                "next_hop": "172.17.0.1",
                                "port": 1
                            }
                        },
                        "aa:bb:cc:00:00:21": {  # route for "s2h1" on Host B
                            "EvpnClient": {
                                "ip": "10.0.0.21",
                                "mac": "aa:bb:cc:00:00:21",
                                "next_hop": "172.17.0.2",
                                "port": 3
                            }
                        }
                    },
                    "ethernet_tag_id": 0,
                    "route_dist": "65000:10",
                    "vni": 10
                }
            }
        }
"""

import json

from ryu.app.ofctl import api as ofctl_api
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.exception import RyuException
from ryu.lib.ovs import bridge as ovs_bridge
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet.bgp import _RouteDistinguisher
from ryu.lib.packet.bgp import EvpnNLRI
from ryu.lib.stringify import StringifyMixin
from ryu.ofproto import ofproto_v1_3
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
from ryu.services.protocols.bgp.bgpspeaker import RF_L2_EVPN
from ryu.services.protocols.bgp.bgpspeaker import EVPN_MAC_IP_ADV_ROUTE
from ryu.services.protocols.bgp.bgpspeaker import EVPN_MULTICAST_ETAG_ROUTE
from ryu.services.protocols.bgp.info_base.evpn import EvpnPath


API_NAME = 'restvtep'

OVSDB_PORT = 6640  # The IANA registered port for OVSDB [RFC7047]

PRIORITY_D_PLANE = 1
PRIORITY_ARP_REPLAY = 2

TABLE_ID_INGRESS = 0
TABLE_ID_EGRESS = 1


# Utility functions

def to_int(i):
    return int(str(i), 0)


def to_str_list(l):
    str_list = []
    for s in l:
        str_list.append(str(s))
    return str_list


# Exception classes related to OpenFlow and OVSDB

class RestApiException(RyuException):

    def to_response(self, status):
        body = {
            "error": str(self),
            "status": status,
        }
        return Response(content_type='application/json',
                        body=json.dumps(body), status=status)


class DatapathNotFound(RestApiException):
    message = 'No such datapath: %(dpid)s'


class OFPortNotFound(RestApiException):
    message = 'No such OFPort: %(port_name)s'


# Exception classes related to BGP

class BGPSpeakerNotFound(RestApiException):
    message = 'BGPSpeaker could not be found'


class NeighborNotFound(RestApiException):
    message = 'No such neighbor: %(address)s'


class VniNotFound(RestApiException):
    message = 'No such VNI: %(vni)s'


class ClientNotFound(RestApiException):
    message = 'No such client: %(mac)s'


class ClientNotLocal(RestApiException):
    message = 'Specified client is not local: %(mac)s'


# Utility classes related to EVPN

class EvpnSpeaker(BGPSpeaker, StringifyMixin):
    _TYPE = {
        'ascii': [
            'router_id',
        ],
    }

    def __init__(self, dpid, as_number, router_id,
                 best_path_change_handler,
                 peer_down_handler, peer_up_handler,
                 neighbors=None):
        super(EvpnSpeaker, self).__init__(
            as_number=as_number,
            router_id=router_id,
            best_path_change_handler=best_path_change_handler,
            peer_down_handler=peer_down_handler,
            peer_up_handler=peer_up_handler,
            ssh_console=True)

        self.dpid = dpid
        self.as_number = as_number
        self.router_id = router_id
        self.neighbors = neighbors or {}


class EvpnNeighbor(StringifyMixin):
    _TYPE = {
        'ascii': [
            'address',
            'state',
        ],
    }

    def __init__(self, address, remote_as, state='down'):
        super(EvpnNeighbor, self).__init__()
        self.address = address
        self.remote_as = remote_as
        self.state = state


class EvpnNetwork(StringifyMixin):
    _TYPE = {
        'ascii': [
            'route_dist',
        ],
    }

    def __init__(self, vni, route_dist, ethernet_tag_id, clients=None):
        super(EvpnNetwork, self).__init__()
        self.vni = vni
        self.route_dist = route_dist
        self.ethernet_tag_id = ethernet_tag_id
        self.clients = clients or {}

    def get_clients(self, **kwargs):
        l = []
        for _, c in self.clients.items():
            for k, v in kwargs.items():
                if getattr(c, k) != v:
                    break
            else:
                l.append(c)
        return l


class EvpnClient(StringifyMixin):
    _TYPE = {
        'ascii': [
            'mac',
            'ip',
            'next_hop'
        ],
    }

    def __init__(self, port, mac, ip, next_hop):
        super(EvpnClient, self).__init__()
        self.port = port
        self.mac = mac
        self.ip = ip
        self.next_hop = next_hop


class RestVtep(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestVtep, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(RestVtepController, {RestVtep.__name__: self})

        # EvpnSpeaker instance instantiated later
        self.speaker = None

        # OVSBridge instance instantiated later
        self.ovs = None

        # Dictionary for retrieving the EvpnNetwork instance by VNI
        # self.networks = {
        #     <vni>: <instance 'EvpnNetwork'>,
        #     ...
        # }
        self.networks = {}

    # Utility methods related to OpenFlow

    def _get_datapath(self, dpid):
        return ofctl_api.get_datapath(self, dpid)

    @staticmethod
    def _add_flow(datapath, priority, match, instructions,
                  table_id=TABLE_ID_INGRESS):
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=instructions)

        datapath.send_msg(mod)

    @staticmethod
    def _del_flow(datapath, priority, match, table_id=TABLE_ID_INGRESS):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            command=ofproto.OFPFC_DELETE,
            priority=priority,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match)

        datapath.send_msg(mod)

    def _add_network_ingress_flow(self, datapath, tag, in_port, eth_src=None):
        parser = datapath.ofproto_parser

        if eth_src is None:
            match = parser.OFPMatch(in_port=in_port)
        else:
            match = parser.OFPMatch(in_port=in_port, eth_src=eth_src)
        instructions = [
            parser.OFPInstructionWriteMetadata(
                metadata=tag, metadata_mask=parser.UINT64_MAX),
            parser.OFPInstructionGotoTable(1)]

        self._add_flow(datapath, PRIORITY_D_PLANE, match, instructions)

    def _del_network_ingress_flow(self, datapath, in_port, eth_src=None):
        parser = datapath.ofproto_parser

        if eth_src is None:
            match = parser.OFPMatch(in_port=in_port)
        else:
            match = parser.OFPMatch(in_port=in_port, eth_src=eth_src)

        self._del_flow(datapath, PRIORITY_D_PLANE, match)

    def _add_arp_reply_flow(self, datapath, tag, arp_tpa, arp_tha):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            metadata=(tag, parser.UINT64_MAX),
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_op=arp.ARP_REQUEST,
            arp_tpa=arp_tpa)

        actions = [
            parser.NXActionRegMove(
                src_field="eth_src", dst_field="eth_dst", n_bits=48),
            parser.OFPActionSetField(eth_src=arp_tha),
            parser.OFPActionSetField(arp_op=arp.ARP_REPLY),
            parser.NXActionRegMove(
                src_field="arp_sha", dst_field="arp_tha", n_bits=48),
            parser.NXActionRegMove(
                src_field="arp_spa", dst_field="arp_tpa", n_bits=32),
            parser.OFPActionSetField(arp_sha=arp_tha),
            parser.OFPActionSetField(arp_spa=arp_tpa),
            parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        self._add_flow(datapath, PRIORITY_ARP_REPLAY, match, instructions,
                       table_id=TABLE_ID_EGRESS)

    def _del_arp_reply_flow(self, datapath, tag, arp_tpa):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            metadata=(tag, parser.UINT64_MAX),
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_op=arp.ARP_REQUEST,
            arp_tpa=arp_tpa)

        self._del_flow(datapath, PRIORITY_ARP_REPLAY, match,
                       table_id=TABLE_ID_EGRESS)

    def _add_l2_switching_flow(self, datapath, tag, eth_dst, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(metadata=(tag, parser.UINT64_MAX),
                                eth_dst=eth_dst)
        actions = [parser.OFPActionOutput(out_port)]
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        self._add_flow(datapath, PRIORITY_D_PLANE, match, instructions,
                       table_id=TABLE_ID_EGRESS)

    def _del_l2_switching_flow(self, datapath, tag, eth_dst):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(metadata=(tag, parser.UINT64_MAX),
                                eth_dst=eth_dst)

        self._del_flow(datapath, PRIORITY_D_PLANE, match,
                       table_id=TABLE_ID_EGRESS)

    def _del_network_egress_flow(self, datapath, tag):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(metadata=(tag, parser.UINT64_MAX))

        self._del_flow(datapath, PRIORITY_D_PLANE, match,
                       table_id=TABLE_ID_EGRESS)

    # Utility methods related to OVSDB

    def _get_ovs_bridge(self, dpid):
        datapath = self._get_datapath(dpid)
        if datapath is None:
            self.logger.debug('No such datapath: %s', dpid)
            return None

        ovsdb_addr = 'tcp:%s:%d' % (datapath.address[0], OVSDB_PORT)
        if (self.ovs is not None
                and self.ovs.datapath_id == dpid
                and self.ovs.vsctl.remote == ovsdb_addr):
            return self.ovs

        try:
            self.ovs = ovs_bridge.OVSBridge(
                CONF=self.CONF,
                datapath_id=datapath.id,
                ovsdb_addr=ovsdb_addr)
            self.ovs.init()
        except Exception as e:
            self.logger.exception('Cannot initiate OVSDB connection: %s', e)
            return None

        return self.ovs

    def _get_ofport(self, dpid, port_name):
        ovs = self._get_ovs_bridge(dpid)
        if ovs is None:
            return None

        try:
            return ovs.get_ofport(port_name)
        except Exception as e:
            self.logger.debug('Cannot get port number for %s: %s',
                              port_name, e)
            return None

    def _get_vxlan_port(self, dpid, remote_ip, key):
        # Searches VXLAN port named 'vxlan_<remote_ip>_<key>'
        return self._get_ofport(dpid, 'vxlan_%s_%s' % (remote_ip, key))

    def _add_vxlan_port(self, dpid, remote_ip, key):
        # If VXLAN port already exists, returns OFPort number
        vxlan_port = self._get_vxlan_port(dpid, remote_ip, key)
        if vxlan_port is not None:
            return vxlan_port

        ovs = self._get_ovs_bridge(dpid)
        if ovs is None:
            return None

        # Adds VXLAN port named 'vxlan_<remote_ip>_<key>'
        ovs.add_vxlan_port(
            name='vxlan_%s_%s' % (remote_ip, key),
            remote_ip=remote_ip,
            key=key)

        # Returns VXLAN port number
        return self._get_vxlan_port(dpid, remote_ip, key)

    def _del_vxlan_port(self, dpid, remote_ip, key):
        ovs = self._get_ovs_bridge(dpid)
        if ovs is None:
            return None

        # If VXLAN port does not exist, returns None
        vxlan_port = self._get_vxlan_port(dpid, remote_ip, key)
        if vxlan_port is None:
            return None

        # Adds VXLAN port named 'vxlan_<remote_ip>_<key>'
        ovs.del_port('vxlan_%s_%s' % (remote_ip, key))

        # Returns deleted VXLAN port number
        return vxlan_port

    # Event handlers for BGP

    def _evpn_mac_ip_adv_route_handler(self, ev):
        network = self.networks.get(ev.path.nlri.vni, None)
        if network is None:
            self.logger.debug('No such VNI registered: %s', ev.path.nlri)
            return

        datapath = self._get_datapath(self.speaker.dpid)
        if datapath is None:
            self.logger.debug('No such datapath: %s', self.speaker.dpid)
            return

        vxlan_port = self._add_vxlan_port(
            dpid=self.speaker.dpid,
            remote_ip=ev.nexthop,
            key=ev.path.nlri.vni)
        if vxlan_port is None:
            self.logger.debug('Cannot create a new VXLAN port: %s',
                              'vxlan_%s_%s' % (ev.nexthop, ev.path.nlri.vni))
            return

        self._add_l2_switching_flow(
            datapath=datapath,
            tag=network.vni,
            eth_dst=ev.path.nlri.mac_addr,
            out_port=vxlan_port)

        self._add_arp_reply_flow(
            datapath=datapath,
            tag=network.vni,
            arp_tpa=ev.path.nlri.ip_addr,
            arp_tha=ev.path.nlri.mac_addr)

        network.clients[ev.path.nlri.mac_addr] = EvpnClient(
            port=vxlan_port,
            mac=ev.path.nlri.mac_addr,
            ip=ev.path.nlri.ip_addr,
            next_hop=ev.nexthop)

    def _evpn_incl_mcast_etag_route_handler(self, ev):
        # Note: For the VLAN Based service, we use RT(=RD) assigned
        # field as vid.
        vni = _RouteDistinguisher.from_str(ev.path.nlri.route_dist).assigned

        network = self.networks.get(vni, None)
        if network is None:
            self.logger.debug('No such VNI registered: %s', vni)
            return

        datapath = self._get_datapath(self.speaker.dpid)
        if datapath is None:
            self.logger.debug('No such datapath: %s', self.speaker.dpid)
            return

        vxlan_port = self._add_vxlan_port(
            dpid=self.speaker.dpid,
            remote_ip=ev.nexthop,
            key=vni)
        if vxlan_port is None:
            self.logger.debug('Cannot create a new VXLAN port: %s',
                              'vxlan_%s_%s' % (ev.nexthop, vni))
            return

        self._add_network_ingress_flow(
            datapath=datapath,
            tag=vni,
            in_port=vxlan_port)

    def _evpn_route_handler(self, ev):
        if ev.path.nlri.type == EvpnNLRI.MAC_IP_ADVERTISEMENT:
            self._evpn_mac_ip_adv_route_handler(ev)
        elif ev.path.nlri.type == EvpnNLRI.INCLUSIVE_MULTICAST_ETHERNET_TAG:
            self._evpn_incl_mcast_etag_route_handler(ev)

    def _evpn_withdraw_mac_ip_adv_route_handler(self, ev):
        network = self.networks.get(ev.path.nlri.vni, None)
        if network is None:
            self.logger.debug('No such VNI registered: %s', ev.path.nlri)
            return

        datapath = self._get_datapath(self.speaker.dpid)
        if datapath is None:
            self.logger.debug('No such datapath: %s', self.speaker.dpid)
            return

        client = network.clients.get(ev.path.nlri.mac_addr, None)
        if client is None:
            self.logger.debug('No such client: %s', ev.path.nlri.mac_addr)
            return

        self._del_l2_switching_flow(
            datapath=datapath,
            tag=network.vni,
            eth_dst=ev.path.nlri.mac_addr)

        self._del_arp_reply_flow(
            datapath=datapath,
            tag=network.vni,
            arp_tpa=ev.path.nlri.ip_addr)

        network.clients.pop(ev.path.nlri.mac_addr)

    def _evpn_withdraw_incl_mcast_etag_route_handler(self, ev):
        # Note: For the VLAN Based service, we use RT(=RD) assigned
        # field as vid.
        vni = _RouteDistinguisher.from_str(ev.path.nlri.route_dist).assigned

        network = self.networks.get(vni, None)
        if network is None:
            self.logger.debug('No such VNI registered: %s', vni)
            return

        datapath = self._get_datapath(self.speaker.dpid)
        if datapath is None:
            self.logger.debug('No such datapath: %s', self.speaker.dpid)
            return

        vxlan_port = self._get_vxlan_port(
            dpid=self.speaker.dpid,
            remote_ip=ev.nexthop,
            key=vni)
        if vxlan_port is None:
            self.logger.debug('No such VXLAN port: %s',
                              'vxlan_%s_%s' % (ev.nexthop, vni))
            return

        self._del_network_ingress_flow(
            datapath=datapath,
            in_port=vxlan_port)

        vxlan_port = self._del_vxlan_port(
            dpid=self.speaker.dpid,
            remote_ip=ev.nexthop,
            key=vni)
        if vxlan_port is None:
            self.logger.debug('Cannot delete VXLAN port: %s',
                              'vxlan_%s_%s' % (ev.nexthop, vni))
            return

    def _evpn_withdraw_route_handler(self, ev):
        if ev.path.nlri.type == EvpnNLRI.MAC_IP_ADVERTISEMENT:
            self._evpn_withdraw_mac_ip_adv_route_handler(ev)
        elif ev.path.nlri.type == EvpnNLRI.INCLUSIVE_MULTICAST_ETHERNET_TAG:
            self._evpn_withdraw_incl_mcast_etag_route_handler(ev)

    def _best_path_change_handler(self, ev):
        if not isinstance(ev.path, EvpnPath):
            # Ignores non-EVPN routes
            return
        elif ev.nexthop == self.speaker.router_id:
            # Ignore local connected routes
            return
        elif ev.is_withdraw:
            self._evpn_withdraw_route_handler(ev)
        else:
            self._evpn_route_handler(ev)

    def _peer_down_handler(self, remote_ip, remote_as):
        neighbor = self.speaker.neighbors.get(remote_ip, None)
        if neighbor is None:
            self.logger.debug('No such neighbor: remote_ip=%s, remote_as=%s',
                              remote_ip, remote_as)
            return

        neighbor.state = 'down'

    def _peer_up_handler(self, remote_ip, remote_as):
        neighbor = self.speaker.neighbors.get(remote_ip, None)
        if neighbor is None:
            self.logger.debug('No such neighbor: remote_ip=%s, remote_as=%s',
                              remote_ip, remote_as)
            return

        neighbor.state = 'up'

    # API methods for REST controller

    def add_speaker(self, dpid, as_number, router_id):
        # Check if the datapath for the specified dpid exist or not
        datapath = self._get_datapath(dpid)
        if datapath is None:
            raise DatapathNotFound(dpid=dpid)

        self.speaker = EvpnSpeaker(
            dpid=dpid,
            as_number=as_number,
            router_id=router_id,
            best_path_change_handler=self._best_path_change_handler,
            peer_down_handler=self._peer_down_handler,
            peer_up_handler=self._peer_up_handler)

        return {self.speaker.router_id: self.speaker.to_jsondict()}

    def get_speaker(self):
        if self.speaker is None:
            return BGPSpeakerNotFound()

        return {self.speaker.router_id: self.speaker.to_jsondict()}

    def del_speaker(self):
        if self.speaker is None:
            return BGPSpeakerNotFound()

        for vni in list(self.networks.keys()):
            self.del_network(vni=vni)

        for address in list(self.speaker.neighbors.keys()):
            self.del_neighbor(address=address)

        self.speaker.shutdown()
        speaker = self.speaker
        self.speaker = None

        return {speaker.router_id: speaker.to_jsondict()}

    def add_neighbor(self, address, remote_as):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        self.speaker.neighbor_add(
            address=address,
            remote_as=remote_as,
            enable_evpn=True)

        neighbor = EvpnNeighbor(
            address=address,
            remote_as=remote_as)
        self.speaker.neighbors[address] = neighbor

        return {address: neighbor.to_jsondict()}

    def get_neighbors(self, address=None):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        if address is not None:
            neighbor = self.speaker.neighbors.get(address, None)
            if neighbor is None:
                raise NeighborNotFound(address=address)
            return {address: neighbor.to_jsondict()}

        neighbors = {}
        for address, neighbor in self.speaker.neighbors.items():
            neighbors[address] = neighbor.to_jsondict()

        return neighbors

    def del_neighbor(self, address):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        neighbor = self.speaker.neighbors.get(address, None)
        if neighbor is None:
            raise NeighborNotFound(address=address)

        for network in self.networks.values():
            for mac, client in list(network.clients.items()):
                if client.next_hop == address:
                    network.clients.pop(mac)

        self.speaker.neighbor_del(address=address)

        neighbor = self.speaker.neighbors.pop(address)

        return {address: neighbor.to_jsondict()}

    def add_network(self, vni):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        # Constructs type 0 RD with as_number and vni
        route_dist = "%s:%d" % (self.speaker.as_number, vni)

        self.speaker.vrf_add(
            route_dist=route_dist,
            import_rts=[route_dist],
            export_rts=[route_dist],
            route_family=RF_L2_EVPN)

        # Note: For the VLAN Based service, ethernet_tag_id
        # must be set to zero.
        self.speaker.evpn_prefix_add(
            route_type=EVPN_MULTICAST_ETAG_ROUTE,
            route_dist=route_dist,
            ethernet_tag_id=vni,
            ip_addr=self.speaker.router_id,
            next_hop=self.speaker.router_id)

        network = EvpnNetwork(
            vni=vni,
            route_dist=route_dist,
            ethernet_tag_id=0)
        self.networks[vni] = network

        return {vni: network.to_jsondict()}

    def get_networks(self, vni=None):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        if vni is not None:
            network = self.networks.get(vni, None)
            if network is None:
                raise VniNotFound(vni=vni)
            return {vni: network.to_jsondict()}

        networks = {}
        for vni, network in self.networks.items():
            networks[vni] = network.to_jsondict()

        return networks

    def del_network(self, vni):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        datapath = self._get_datapath(self.speaker.dpid)
        if datapath is None:
            raise DatapathNotFound(dpid=self.speaker.dpid)

        network = self.networks.get(vni, None)
        if network is None:
            raise VniNotFound(vni=vni)

        for client in network.get_clients(next_hop=self.speaker.router_id):
            self.del_client(
                vni=vni,
                mac=client.mac)

        self._del_network_egress_flow(
            datapath=datapath,
            tag=vni)

        for address in self.speaker.neighbors:
            self._del_vxlan_port(
                dpid=self.speaker.dpid,
                remote_ip=address,
                key=vni)

        self.speaker.evpn_prefix_del(
            route_type=EVPN_MULTICAST_ETAG_ROUTE,
            route_dist=network.route_dist,
            ethernet_tag_id=vni,
            ip_addr=self.speaker.router_id)

        self.speaker.vrf_del(route_dist=network.route_dist)

        network = self.networks.pop(vni)

        return {vni: network.to_jsondict()}

    def add_client(self, vni, port, mac, ip):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        datapath = self._get_datapath(self.speaker.dpid)
        if datapath is None:
            raise DatapathNotFound(dpid=self.speaker.dpid)

        network = self.networks.get(vni, None)
        if network is None:
            raise VniNotFound(vni=vni)

        port = self._get_ofport(self.speaker.dpid, port)
        if port is None:
            try:
                port = to_int(port)
            except ValueError:
                raise OFPortNotFound(port_name=port)

        self._add_network_ingress_flow(
            datapath=datapath,
            tag=network.vni,
            in_port=port,
            eth_src=mac)

        self._add_l2_switching_flow(
            datapath=datapath,
            tag=network.vni,
            eth_dst=mac,
            out_port=port)

        # Note: For the VLAN Based service, ethernet_tag_id
        # must be set to zero.
        self.speaker.evpn_prefix_add(
            route_type=EVPN_MAC_IP_ADV_ROUTE,
            route_dist=network.route_dist,
            esi=0,
            ethernet_tag_id=0,
            mac_addr=mac,
            ip_addr=ip,
            vni=vni,
            next_hop=self.speaker.router_id,
            tunnel_type='vxlan')

        # Stores local client info
        client = EvpnClient(
            port=port,
            mac=mac,
            ip=ip,
            next_hop=self.speaker.router_id)
        network.clients[mac] = client

        return {vni: client.to_jsondict()}

    def del_client(self, vni, mac):
        if self.speaker is None:
            raise BGPSpeakerNotFound()

        datapath = self._get_datapath(self.speaker.dpid)
        if datapath is None:
            raise DatapathNotFound(dpid=self.speaker.dpid)

        network = self.networks.get(vni, None)
        if network is None:
            raise VniNotFound(vni=vni)

        client = network.clients.get(mac, None)
        if client is None:
            raise ClientNotFound(mac=mac)
        elif client.next_hop != self.speaker.router_id:
            raise ClientNotLocal(mac=mac)

        self._del_network_ingress_flow(
            datapath=datapath,
            in_port=client.port,
            eth_src=mac)

        self._del_l2_switching_flow(
            datapath=datapath,
            tag=network.vni,
            eth_dst=mac)

        # Note: For the VLAN Based service, ethernet_tag_id
        # must be set to zero.
        self.speaker.evpn_prefix_del(
            route_type=EVPN_MAC_IP_ADV_ROUTE,
            route_dist=network.route_dist,
            esi=0,
            ethernet_tag_id=0,
            mac_addr=mac,
            ip_addr=client.ip)

        client = network.clients.pop(mac)

        return {vni: client.to_jsondict()}


def post_method(keywords):
    def _wrapper(method):
        def __wrapper(self, req, **kwargs):
            try:
                try:
                    body = req.json if req.body else {}
                except ValueError:
                    raise ValueError('Invalid syntax %s', req.body)
                kwargs.update(body)
                for key, converter in keywords.items():
                    value = kwargs.get(key, None)
                    if value is None:
                        raise ValueError('%s not specified' % key)
                    kwargs[key] = converter(value)
            except ValueError as e:
                return Response(content_type='application/json',
                                body={"error": str(e)}, status=400)
            try:
                return method(self, **kwargs)
            except Exception as e:
                status = 500
                body = {
                    "error": str(e),
                    "status": status,
                }
                return Response(content_type='application/json',
                                body=json.dumps(body), status=status)
        __wrapper.__doc__ = method.__doc__
        return __wrapper
    return _wrapper


def get_method(keywords=None):
    keywords = keywords or {}

    def _wrapper(method):
        def __wrapper(self, _, **kwargs):
            try:
                for key, converter in keywords.items():
                    value = kwargs.get(key, None)
                    if value is None:
                        continue
                    kwargs[key] = converter(value)
            except ValueError as e:
                return Response(content_type='application/json',
                                body={"error": str(e)}, status=400)
            try:
                return method(self, **kwargs)
            except Exception as e:
                status = 500
                body = {
                    "error": str(e),
                    "status": status,
                }
                return Response(content_type='application/json',
                                body=json.dumps(body), status=status)
        __wrapper.__doc__ = method.__doc__
        return __wrapper
    return _wrapper


delete_method = get_method


class RestVtepController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RestVtepController, self).__init__(req, link, data, **config)
        self.vtep_app = data[RestVtep.__name__]
        self.logger = self.vtep_app.logger

    @route(API_NAME, '/vtep/speakers', methods=['POST'])
    @post_method(
        keywords={
            "dpid": to_int,
            "as_number": to_int,
            "router_id": str,
        })
    def add_speaker(self, **kwargs):
        """
        Creates a new BGPSpeaker instance.

        Usage:

            ======= ================
            Method  URI
            ======= ================
            POST    /vtep/speakers
            ======= ================

        Request parameters:

            ========== ============================================
            Attribute  Description
            ========== ============================================
            dpid       ID of Datapath binding to speaker. (e.g. 1)
            as_number  AS number. (e.g. 65000)
            router_id  Router ID. (e.g. "172.17.0.1")
            ========== ============================================

        Example::

            $ curl -X POST -d '{
             "dpid": 1,
             "as_number": 65000,
             "router_id": "172.17.0.1"
             }' http://localhost:8080/vtep/speakers | python -m json.tool

        ::

            {
                "172.17.0.1": {
                    "EvpnSpeaker": {
                        "as_number": 65000,
                        "dpid": 1,
                        "neighbors": {},
                        "router_id": "172.17.0.1"
                    }
                }
            }
        """
        try:
            body = self.vtep_app.add_speaker(**kwargs)
        except DatapathNotFound as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/speakers', methods=['GET'])
    @get_method()
    def get_speakers(self, **kwargs):
        """
        Gets the info of BGPSpeaker instance.

        Usage:

            ======= ================
            Method  URI
            ======= ================
            GET     /vtep/speakers
            ======= ================

        Example::

            $ curl -X GET http://localhost:8080/vtep/speakers |
             python -m json.tool

        ::

            {
                "172.17.0.1": {
                    "EvpnSpeaker": {
                        "as_number": 65000,
                        "dpid": 1,
                        "neighbors": {
                            "172.17.0.2": {
                                "EvpnNeighbor": {
                                    "address": "172.17.0.2",
                                    "remote_as": 65000,
                                    "state": "up"
                                }
                            }
                        },
                        "router_id": "172.17.0.1"
                    }
                }
            }
        """
        try:
            body = self.vtep_app.get_speaker()
        except BGPSpeakerNotFound as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/speakers', methods=['DELETE'])
    @delete_method()
    def del_speaker(self, **kwargs):
        """
        Shutdowns BGPSpeaker instance.

        Usage:

            ======= ================
            Method  URI
            ======= ================
            DELETE  /vtep/speakers
            ======= ================

        Example::

            $ curl -X DELETE http://localhost:8080/vtep/speakers |
             python -m json.tool

        ::

            {
                "172.17.0.1": {
                    "EvpnSpeaker": {
                        "as_number": 65000,
                        "dpid": 1,
                        "neighbors": {},
                        "router_id": "172.17.0.1"
                    }
                }
            }
        """
        try:
            body = self.vtep_app.del_speaker()
        except BGPSpeakerNotFound as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/neighbors', methods=['POST'])
    @post_method(
        keywords={
            "address": str,
            "remote_as": to_int,
        })
    def add_neighbor(self, **kwargs):
        """
        Registers a new neighbor to the speaker.

        Usage:

            ======= ========================
            Method  URI
            ======= ========================
            POST    /vtep/neighbors
            ======= ========================

        Request parameters:

            ========== ================================================
            Attribute  Description
            ========== ================================================
            address    IP address of neighbor. (e.g. "172.17.0.2")
            remote_as  AS number of neighbor. (e.g. 65000)
            ========== ================================================

        Example::

            $ curl -X POST -d '{
             "address": "172.17.0.2",
             "remote_as": 65000
             }' http://localhost:8080/vtep/neighbors |
             python -m json.tool

        ::

            {
                "172.17.0.2": {
                    "EvpnNeighbor": {
                        "address": "172.17.0.2",
                        "remote_as": 65000,
                        "state": "down"
                    }
                }
            }
        """
        try:
            body = self.vtep_app.add_neighbor(**kwargs)
        except BGPSpeakerNotFound as e:
            return e.to_response(status=400)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    def _get_neighbors(self, **kwargs):
        try:
            body = self.vtep_app.get_neighbors(**kwargs)
        except (BGPSpeakerNotFound, NeighborNotFound) as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/neighbors', methods=['GET'])
    @get_method()
    def get_neighbors(self, **kwargs):
        """
        Gets a list of all neighbors.

        Usage:

            ======= ========================
            Method  URI
            ======= ========================
            GET     /vtep/neighbors
            ======= ========================

        Example::

            $ curl -X GET http://localhost:8080/vtep/neighbors |
             python -m json.tool

        ::

            {
                "172.17.0.2": {
                    "EvpnNeighbor": {
                        "address": "172.17.0.2",
                        "remote_as": 65000,
                        "state": "up"
                    }
                }
            }
        """
        return self._get_neighbors(**kwargs)

    @route(API_NAME, '/vtep/neighbors/{address}', methods=['GET'])
    @get_method(
        keywords={
            "address": str,
        })
    def get_neighbor(self, **kwargs):
        """
        Gets the neighbor for the specified address.

        Usage:

            ======= ==================================
            Method  URI
            ======= ==================================
            GET     /vtep/neighbors/{address}
            ======= ==================================

        Request parameters:

            ========== ================================================
            Attribute  Description
            ========== ================================================
            address    IP address of neighbor. (e.g. "172.17.0.2")
            ========== ================================================

        Example::

            $ curl -X GET http://localhost:8080/vtep/neighbors/172.17.0.2 |
             python -m json.tool

        ::

            {
                "172.17.0.2": {
                    "EvpnNeighbor": {
                        "address": "172.17.0.2",
                        "remote_as": 65000,
                        "state": "up"
                    }
                }
            }
        """
        return self._get_neighbors(**kwargs)

    @route(API_NAME, '/vtep/neighbors/{address}', methods=['DELETE'])
    @delete_method(
        keywords={
            "address": str,
        })
    def del_neighbor(self, **kwargs):
        """
        Unregister the specified neighbor from the speaker.

        Usage:

            ======= ==================================
            Method  URI
            ======= ==================================
            DELETE  /vtep/speaker/neighbors/{address}
            ======= ==================================

        Request parameters:

            ========== ================================================
            Attribute  Description
            ========== ================================================
            address    IP address of neighbor. (e.g. "172.17.0.2")
            ========== ================================================

        Example::

            $ curl -X DELETE http://localhost:8080/vtep/speaker/neighbors/172.17.0.2 |
             python -m json.tool

        ::

            {
                "172.17.0.2": {
                    "EvpnNeighbor": {
                        "address": "172.17.0.2",
                        "remote_as": 65000,
                        "state": "up"
                    }
                }
            }
        """
        try:
            body = self.vtep_app.del_neighbor(**kwargs)
        except (BGPSpeakerNotFound, NeighborNotFound) as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/networks', methods=['POST'])
    @post_method(
        keywords={
            "vni": to_int,
        })
    def add_network(self, **kwargs):
        """
        Defines a new network.

        Usage:

            ======= ===============
            Method  URI
            ======= ===============
            POST    /vtep/networks
            ======= ===============

        Request parameters:

            ================ ========================================
            Attribute        Description
            ================ ========================================
            vni              Virtual Network Identifier. (e.g. 10)
            ================ ========================================

        Example::

            $ curl -X POST -d '{
             "vni": 10
             }' http://localhost:8080/vtep/networks | python -m json.tool

        ::

            {
                "10": {
                    "EvpnNetwork": {
                        "clients": {},
                        "ethernet_tag_id": 0,
                        "route_dist": "65000:10",
                        "vni": 10
                    }
                }
            }
        """
        try:
            body = self.vtep_app.add_network(**kwargs)
        except BGPSpeakerNotFound as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    def _get_networks(self, **kwargs):
        try:
            body = self.vtep_app.get_networks(**kwargs)
        except (BGPSpeakerNotFound, VniNotFound) as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/networks', methods=['GET'])
    @get_method()
    def get_networks(self, **kwargs):
        """
        Gets a list of all networks.

        Usage:

            ======= ===============
            Method  URI
            ======= ===============
            GET     /vtep/networks
            ======= ===============

        Example::

            $ curl -X GET http://localhost:8080/vtep/networks |
             python -m json.tool

        ::

            {
                "10": {
                    "EvpnNetwork": {
                        "clients": {
                            "aa:bb:cc:dd:ee:ff": {
                                "EvpnClient": {
                                    "ip": "10.0.0.1",
                                    "mac": "aa:bb:cc:dd:ee:ff",
                                    "next_hop": "172.17.0.1",
                                    "port": 1
                                }
                            }
                        },
                        "ethernet_tag_id": 0,
                        "route_dist": "65000:10",
                        "vni": 10
                    }
                }
            }
        """
        return self._get_networks(**kwargs)

    @route(API_NAME, '/vtep/networks/{vni}', methods=['GET'])
    @get_method(
        keywords={
            "vni": to_int,
        })
    def get_network(self, **kwargs):
        """
        Gets the network for the specified VNI.

        Usage:

            ======= =====================
            Method  URI
            ======= =====================
            GET     /vtep/networks/{vni}
            ======= =====================

        Request parameters:

            ================ ========================================
            Attribute        Description
            ================ ========================================
            vni              Virtual Network Identifier. (e.g. 10)
            ================ ========================================

        Example::

            $ curl -X GET http://localhost:8080/vtep/networks/10 |
             python -m json.tool

        ::

            {
                "10": {
                    "EvpnNetwork": {
                        "clients": {
                            "aa:bb:cc:dd:ee:ff": {
                                "EvpnClient": {
                                    "ip": "10.0.0.1",
                                    "mac": "aa:bb:cc:dd:ee:ff",
                                    "next_hop": "172.17.0.1",
                                    "port": 1
                                }
                            }
                        },
                        "ethernet_tag_id": 0,
                        "route_dist": "65000:10",
                        "vni": 10
                    }
                }
            }
        """
        return self._get_networks(**kwargs)

    @route(API_NAME, '/vtep/networks/{vni}', methods=['DELETE'])
    @delete_method(
        keywords={
            "vni": to_int,
        })
    def del_network(self, **kwargs):
        """
        Deletes the network for the specified VNI.

        Usage:

            ======= =====================
            Method  URI
            ======= =====================
            DELETE  /vtep/networks/{vni}
            ======= =====================

        Request parameters:

            ================ ========================================
            Attribute        Description
            ================ ========================================
            vni              Virtual Network Identifier. (e.g. 10)
            ================ ========================================

        Example::

            $ curl -X DELETE http://localhost:8080/vtep/networks/10 |
             python -m json.tool

        ::

            {
                "10": {
                    "EvpnNetwork": {
                        "ethernet_tag_id": 10,
                        "clients": [
                            {
                                "EvpnClient": {
                                    "ip": "10.0.0.11",
                                    "mac": "e2:b1:0c:ba:42:ed",
                                    "port": 1
                                }
                            }
                        ],
                        "route_dist": "65000:100",
                        "vni": 10
                    }
                }
            }
        """
        try:
            body = self.vtep_app.del_network(**kwargs)
        except (BGPSpeakerNotFound, DatapathNotFound, VniNotFound) as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/networks/{vni}/clients', methods=['POST'])
    @post_method(
        keywords={
            "vni": to_int,
            "port": str,
            "mac": str,
            "ip": str,
        })
    def add_client(self, **kwargs):
        """
        Registers a new client to the specified network.

        Usage:

            ======= =============================
            Method  URI
            ======= =============================
            POST    /vtep/networks/{vni}/clients
            ======= =============================

        Request parameters:

            =========== ===============================================
            Attribute   Description
            =========== ===============================================
            vni         Virtual Network Identifier. (e.g. 10)
            port        Port number to connect client.
                        For convenience, port name can be specified
                        and automatically translated to port number.
                        (e.g. "s1-eth1" or 1)
            mac         Client MAC address to register.
                        (e.g. "aa:bb:cc:dd:ee:ff")
            ip          Client IP address. (e.g. "10.0.0.1")
            =========== ===============================================

        Example::

            $ curl -X POST -d '{
             "port": "s1-eth1",
             "mac": "aa:bb:cc:dd:ee:ff",
             "ip": "10.0.0.1"
             }' http://localhost:8080/vtep/networks/10/clients |
             python -m json.tool

        ::

            {
                "10": {
                    "EvpnClient": {
                        "ip": "10.0.0.1",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "next_hop": "172.17.0.1",
                        "port": 1
                    }
                }
            }
        """
        try:
            body = self.vtep_app.add_client(**kwargs)
        except (BGPSpeakerNotFound, DatapathNotFound,
                VniNotFound, OFPortNotFound) as e:
            return e.to_response(status=404)

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route(API_NAME, '/vtep/networks/{vni}/clients/{mac}', methods=['DELETE'])
    @delete_method(
        keywords={
            "vni": to_int,
            "mac": str,
        })
    def del_client(self, **kwargs):
        """
        Registers a new client to the specified network.

        Usage:

            ======= ===================================
            Method  URI
            ======= ===================================
            DELETE  /vtep/networks/{vni}/clients/{mac}
            ======= ===================================

        Request parameters:

            =========== ===============================================
            Attribute   Description
            =========== ===============================================
            vni         Virtual Network Identifier. (e.g. 10)
            mac         Client MAC address to register.
            =========== ===============================================

        Example::

            $ curl -X DELETE http://localhost:8080/vtep/networks/10/clients/aa:bb:cc:dd:ee:ff |
             python -m json.tool

        ::

            {
                "10": {
                    "EvpnClient": {
                        "ip": "10.0.0.1",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "next_hop": "172.17.0.1",
                        "port": 1
                    }
                }
            }
        """
        try:
            body = self.vtep_app.del_client(**kwargs)
        except (BGPSpeakerNotFound, DatapathNotFound,
                VniNotFound, ClientNotFound, ClientNotLocal) as e:
            return Response(body=str(e), status=500)

        return Response(content_type='application/json',
                        body=json.dumps(body))
