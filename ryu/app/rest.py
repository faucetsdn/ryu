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

import json
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist
from ryu.app.wsapi import WSPathComponent
from ryu.app.wsapi import WSPathExtractResult
from ryu.app.wsapi import WSPathStaticString
from ryu.app.wsapi import wsapi

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

# We store networks and ports like the following:
#
# {network_id: [(dpid, port), ...
# {3: [(3,4), (4,7)], 5: [(3,6)], 1: [(5,6), (4,5), (4, 10)]}
#


class WSPathNetwork(WSPathComponent):
    """ Match a network id string """

    def __str__(self):
        return "{network-id}"

    def extract(self, pc, _data):
        if pc == None:
            return WSPathExtractResult(error="End of requested URI")

        return WSPathExtractResult(value=pc)


class WSPathPort(WSPathComponent):
    """ Match a {dpid}_{port-id} string """

    def __str__(self):
        return "{dpid}_{port-id}"

    def extract(self, pc, _data):
        if pc == None:
            return WSPathExtractResult(error="End of requested URI")

        try:
            dpid_str, port_str = pc.split('_')
            dpid = int(dpid_str, 16)
            port = int(port_str)
        except ValueError:
            return WSPathExtractResult(error="Invalid format: %s" % pc)

        return WSPathExtractResult(value={'dpid': dpid, 'port': port})


class restapi:

    def __init__(self, *_args, **kwargs):
        self.ws = wsapi()
        self.api = self.ws.get_version("1.0")
        self.nw = kwargs['network']
        self.register()

    def list_networks_handler(self, request, _data):
        request.setHeader("Content-Type", 'application/json')
        return json.dumps(self.nw.list_networks())

    def create_network_handler(self, request, data):
        network_id = data['{network-id}']

        try:
            self.nw.create_network(network_id)
        except NetworkAlreadyExist:
            request.setResponseCode(409)

        return ""

    def update_network_handler(self, _request, data):
        network_id = data['{network-id}']
        self.nw.update_network(network_id)
        return ""

    def remove_network_handler(self, request, data):
        network_id = data['{network-id}']

        try:
            self.nw.remove_network(network_id)
        except NetworkNotFound:
            request.setResponseCode(404)

        return ""

    def list_ports_handler(self, request, data):
        network_id = data['{network-id}']

        try:
            body = json.dumps(self.nw.list_ports(network_id))
        except NetworkNotFound:
            body = ""
            request.setResponseCode(404)

        request.setHeader("Content-Type", 'application/json')
        return body

    def create_port_handler(self, request, data):
        network_id = data['{network-id}']
        dpid = data['{dpid}_{port-id}']['dpid']
        port = data['{dpid}_{port-id}']['port']

        try:
            self.nw.create_port(network_id, dpid, port)
        except NetworkNotFound:
            request.setResponseCode(404)
        except PortAlreadyExist:
            request.setResponseCode(409)

        return ""

    def update_port_handler(self, request, data):
        network_id = data['{network-id}']
        dpid = data['{dpid}_{port-id}']['dpid']
        port = data['{dpid}_{port-id}']['port']

        try:
            self.nw.update_port(network_id, dpid, port)
        except NetworkNotFound:
            request.setResponseCode(404)

        return ""

    def remove_port_handler(self, request, data):
        network_id = data['{network-id}']
        dpid = data['{dpid}_{port-id}']['dpid']
        port = data['{dpid}_{port-id}']['port']

        try:
            self.nw.remove_port(network_id, dpid, port)
        except (NetworkNotFound, PortNotFound):
            request.setResponseCode(404)

        return ""

    def register(self):
        path_networks = (WSPathStaticString('networks'), )
        self.api.register_request(self.list_networks_handler, "GET",
                                  path_networks,
                                  "get the list of networks")

        path_network = path_networks + (WSPathNetwork(), )
        self.api.register_request(self.create_network_handler, "POST",
                                  path_network,
                                  "register a new network")

        self.api.register_request(self.update_network_handler, "PUT",
                                  path_network,
                                  "update a network")

        self.api.register_request(self.remove_network_handler, "DELETE",
                                  path_network,
                                  "remove a network")

        self.api.register_request(self.list_ports_handler, "GET",
                                  path_network,
                                  "get the list of sets of dpid and port")

        path_port = path_network + (WSPathPort(), )
        self.api.register_request(self.create_port_handler, "POST",
                                  path_port,
                                  "register a new set of dpid and port")

        self.api.register_request(self.update_port_handler, "PUT",
                                  path_port,
                                  "update a set of dpid and port")

        self.api.register_request(self.remove_port_handler, "DELETE",
                                  path_port,
                                  "remove a set of dpid and port")
