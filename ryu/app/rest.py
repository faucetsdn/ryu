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

# This module provides a basic set of REST API.
#   - Network registration
#   - End-point port management
#       - OpenFlow port number
#       - MAC address (for anti-spoofing)
#
# Used by OpenStack Ryu plug-in.

import json
from webob import Response

from ryu.app import wsgi as app_wsgi
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.controller import network
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac as mac_lib

## TODO:XXX
## define db interface and store those information into db

# REST API

# get the list of networks
# GET /v1.0/networks/
#
# register a new network.
# Fail if the network is already registered.
# POST /v1.0/networks/{network-id}
#
# update a new network.
# Success as nop even if the network is already registered.
#
# PUT /v1.0/networks/{network-id}
#
# remove a network
# DELETE /v1.0/networks/{network-id}
#
# get the list of sets of dpid and port
# GET /v1.0/networks/{network-id}/
#
# register a new set of dpid and port
# Fail if the port is already registered.
# POST /v1.0/networks/{network-id}/{dpid}_{port-id}
#
# update a new set of dpid and port
# Success as nop even if same port already registered
# PUT /v1.0/networks/{network-id}/{dpid}_{port-id}
#
# remove a set of dpid and port
# DELETE /v1.0/networks/{network-id}/{dpid}_{port-id}
#
# get the list of mac addresses of dpid and port
# GET /v1.0/networks/{network-id}/{dpid}_{port-id}/macs/
#
# register a new mac address for dpid and port
# Fail if mac address is already registered or the mac address is used
# for other ports of the same network-id
# POST /v1.0/networks/{network-id}/{dpid}_{port-id}/macs/{mac}
#
# update a new mac address for dpid and port
# Success as nop even if same mac address is already registered.
# For now, changing mac address is not allows as it fails.
# PUT /v1.0/networks/{network-id}/{dpid}_{port-id}/macs/{mac}
#
# For now DELETE /v1.0/networks/{network-id}/{dpid}_{port-id}/macs/{mac}
# is not supported. mac address is released when port is deleted.
#


class NetworkController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetworkController, self).__init__(req, link, data, **config)
        self.nw = data

    def create(self, req, network_id, **_kwargs):
        try:
            self.nw.create_network(network_id)
        except NetworkAlreadyExist:
            return Response(status=409)
        else:
            return Response(status=200)

    def update(self, req, network_id, **_kwargs):
        self.nw.update_network(network_id)
        return Response(status=200)

    def lists(self, req, **_kwargs):
        body = json.dumps(self.nw.list_networks())
        return Response(content_type='application/json', body=body)

    def delete(self, req, network_id, **_kwargs):
        try:
            self.nw.remove_network(network_id)
        except NetworkNotFound:
            return Response(status=404)

        return Response(status=200)


class PortController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PortController, self).__init__(req, link, data, **config)
        self.nw = data

    def create(self, req, network_id, dpid, port_id, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        try:
            self.nw.create_port(network_id, dpid, port_id)
        except NetworkNotFound:
            return Response(status=404)
        except PortAlreadyExist:
            return Response(status=409)

        return Response(status=200)

    def update(self, req, network_id, dpid, port_id, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        try:
            self.nw.update_port(network_id, dpid, port_id)
        except NetworkNotFound:
            return Response(status=404)

        return Response(status=200)

    def lists(self, req, network_id, **_kwargs):
        try:
            body = json.dumps(self.nw.list_ports(network_id))
        except NetworkNotFound:
            return Response(status=404)

        return Response(content_type='application/json', body=body)

    def delete(self, req, network_id, dpid, port_id, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        try:
            self.nw.remove_port(network_id, dpid, port_id)
        except (NetworkNotFound, PortNotFound):
            return Response(status=404)

        return Response(status=200)


class MacController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(MacController, self).__init__(req, link, data, **config)
        self.nw = data

    def create(self, _req, network_id, dpid, port_id, mac_addr, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        mac_addr = mac_lib.haddr_to_bin(mac_addr)
        try:
            self.nw.create_mac(network_id, dpid, port_id, mac_addr)
        except PortNotFound:
            return Response(status=404)
        except network.MacAddressAlreadyExist:
            return Response(status=409)

        return Response(status=200)

    def update(self, _req, network_id, dpid, port_id, mac_addr, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        mac_addr = mac_lib.haddr_to_bin(mac_addr)
        try:
            self.nw.update_mac(network_id, dpid, port_id, mac_addr)
        except PortNotFound:
            return Response(status=404)

        return Response(status=200)

    def lists(self, _req, network_id, dpid, port_id, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        try:
            body = json.dumps([mac_lib.haddr_to_str(mac_addr) for mac_addr in
                               self.nw.list_mac(dpid, port_id)])
        except PortNotFound:
            return Response(status=404)

        return Response(content_type='application/json', body=body)


class RestAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(RestAPI, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper

        wsgi.registory['NetworkController'] = self.nw
        route_name = 'networks'
        uri = '/v1.0/networks'
        mapper.connect(route_name, uri,
                       controller=NetworkController, action='lists',
                       conditions=dict(method=['GET', 'HEAD']))

        uri += '/{network_id}'
        s = mapper.submapper(controller=NetworkController)
        s.connect(route_name, uri, action='create',
                  conditions=dict(method=['POST']))
        s.connect(route_name, uri, action='update',
                  conditions=dict(method=['PUT']))
        s.connect(route_name, uri, action='delete',
                  conditions=dict(method=['DELETE']))

        wsgi.registory['PortController'] = self.nw
        route_name = 'ports'
        mapper.connect(route_name, uri,
                       controller=PortController, action='lists',
                       conditions=dict(method=['GET']))

        uri += '/{dpid}_{port_id}'
        requirements = {'dpid': dpid_lib.DPID_PATTERN,
                        'port_id': app_wsgi.DIGIT_PATTERN}
        s = mapper.submapper(controller=PortController,
                             requirements=requirements)
        s.connect(route_name, uri, action='create',
                  conditions=dict(method=['POST']))
        s.connect(route_name, uri, action='update',
                  conditions=dict(method=['PUT']))
        s.connect(route_name, uri, action='delete',
                  conditions=dict(method=['DELETE']))

        wsgi.registory['MacController'] = self.nw
        route_name = 'macs'
        uri += '/macs'
        mapper.connect(route_name, uri,
                       controller=MacController, action='lists',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        uri += '/{mac_addr}'
        requirements['mac_addr'] = mac_lib.HADDR_PATTERN
        s = mapper.submapper(controller=MacController,
                             requirements=requirements)
        s.connect(route_name, uri, action='create',
                  conditions=dict(method=['POST']))
        s.connect(route_name, uri, action='update',
                  conditions=dict(method=['PUT']))
