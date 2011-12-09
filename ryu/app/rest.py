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

import json
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist
from ryu.app.wsapi import *

# REST API

# get the list of networks
# GET /v1.0/
#
# register a new network.
# Fail if the network is already registered.
# POST /v1.0/{network-id}
#
# update a new network.
# Success as nop even if the network is already registered.
#
# PUT /v1.0/{network-id}
#
# remove a network
# DELETE /v1.0/{network-id}
#
# get the list of sets of dpid and port
# GET /v1.0/{network-id}/
#
# register a new set of dpid and port
# Fail if the port is already registered.
# POST /v1.0/{network-id}/{dpid}_{port-id}
#
# update a new set of dpid and port
# Success as nop even if same port already registered
# PUT /v1.0/{network-id}/{dpid}_{port-id}
#
# remove a set of dpid and port
# DELETE /v1.0/{network-id}/{dpid}_{port-id}

# We store networks and ports like the following:
#
# {network_id: [(dpid, port), ...
# {3: [(3,4), (4,7)], 5: [(3,6)], 1: [(5,6), (4,5), (4, 10)]}
#


class WSPathNetwork(WSPathComponent):
    """ Match a network id string """

    def __str__(self):
        return "{network-id}"

    def extract(self, pc, data):
        if pc == None:
            return WSPathExtractResult(error="End of requested URI")

        return WSPathExtractResult(value=pc)


class WSPathPort(WSPathComponent):
    """ Match a {dpid}_{port-id} string """

    def __str__(self):
        return "{dpid}_{port-id}"

    def extract(self, pc, data):
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

    def __init__(self, *args, **kwargs):
        self.ws = wsapi()
        self.api = self.ws.get_version("1.0")
        self.nw = kwargs['network']
        self.register()

    def list_networks_handler(self, request, data):
        request.setHeader("Content-Type", 'application/json')
        return json.dumps(self.nw.list_networks())

    def create_network_handler(self, request, data):
        network_id = data['{network-id}']

        try:
            self.nw.create_network(network_id)
        except NetworkAlreadyExist:
            request.setResponseCode(409)

        return ""

    def update_network_handler(self, request, data):
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
        self.api.register_request(self.list_networks_handler, "GET",
                                  [],
                                  "get the list of networks")

        self.api.register_request(self.create_network_handler, "POST",
                                  [WSPathNetwork()],
                                  "register a new network")

        self.api.register_request(self.update_network_handler, "PUT",
                                  [WSPathNetwork()],
                                  "update a network")

        self.api.register_request(self.remove_network_handler, "DELETE",
                                  [WSPathNetwork()],
                                  "remove a network")

        self.api.register_request(self.list_ports_handler, "GET",
                                  [WSPathNetwork()],
                                  "get the list of sets of dpid and port")

        self.api.register_request(self.create_port_handler, "POST",
                                  [WSPathNetwork(), WSPathPort()],
                                  "register a new set of dpid and port")

        self.api.register_request(self.update_port_handler, "PUT",
                                  [WSPathNetwork(), WSPathPort()],
                                  "update a set of dpid and port")

        self.api.register_request(self.remove_port_handler, "DELETE",
                                  (WSPathNetwork(), WSPathPort()),
                                  "remove a set of dpid and port")
