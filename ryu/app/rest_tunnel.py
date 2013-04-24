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

import json
from webob import Response

from ryu.app import wsgi as app_wsgi
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.controller import network
from ryu.controller import tunnels
import ryu.exception as ryu_exc
from ryu.lib import dpid as dpid_lib


# REST API for tunneling
#
# register tunnel key of this network
# Fail if the key is already registered
# POST /v1.0/tunnels/networks/{network-id}/key/{tunnel_key}
#
# register tunnel key of this network
# Success as nop even if the same key is already registered
# PUT /v1.0/tunnels/networks/{network-id}/key/{tunnel_key}
#
# return allocated tunnel key of this network
# GET /v1.0/tunnels/networks/{network-id}/key
#
# get the ports of dpid that are used for tunneling
# GET /v1.0/tunnels/switches/{dpid}/ports
#
# get the dpid of the other end of tunnel
# GET /v1.0/tunnels/switches/{dpid}/ports/{port-id}/
#
# register the dpid of the other end of tunnel
# Fail if the dpid is already registered
# POST /v1.0/tunnels/switches/{dpid}/ports/{port-id}/{remote_dpid}
#
# register the dpid of the other end of tunnel
# Success as nop even if the dpid is already registered
# PUT /v1.0/tunnels/switches/{dpid}/ports/{port-id}/{remote_dpid}


class TunnelKeyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TunnelKeyController, self).__init__(req, link, data, **config)
        self.tunnels = data

    def create(self, _req, network_id, tunnel_key, **_kwargs):
        tunnel_key = int(tunnel_key)
        try:
            self.tunnels.register_key(network_id, tunnel_key)
        except (ryu_exc.NetworkAlreadyExist, tunnels.TunnelKeyAlreadyExist):
            return Response(status=409)

        return Response(status=200)

    def update(self, _req, network_id, tunnel_key, **_kwargs):
        tunnel_key = int(tunnel_key)
        try:
            self.tunnels.update_key(network_id, tunnel_key)
        except (ryu_exc.NetworkAlreadyExist, tunnels.TunnelKeyAlreadyExist):
            return Response(status=409)

        return Response(status=200)

    def lists(self, _req, network_id, **_kwargs):
        try:
            tunnel_key = self.tunnels.get_key(network_id)
        except tunnels.TunnelKeyNotFound:
            return Response(status=404)
        body = json.dumps(tunnel_key)

        return Response(content_type='application/json', body=body)

    def delete(self, _req, network_id, **_kwargs):
        try:
            self.tunnels.delete_key(network_id)
        except (ryu_exc.NetworkNotFound, tunnels.TunnelKeyNotFound):
            return Response(status=404)

        return Response(status=200)


class TunnelPortController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TunnelPortController, self).__init__(req, link, data, **config)
        self.tunnels = data

    def create(self, _req, dpid, port_id, remote_dpid, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        remote_dpid = dpid_lib.str_to_dpid(remote_dpid)
        try:
            self.tunnels.register_port(dpid, port_id, remote_dpid)
        except ryu_exc.PortAlreadyExist:
            return Response(status=409)

        return Response(status=200)

    def update(self, _req, dpid, port_id, remote_dpid, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        remote_dpid = dpid_lib.str_to_dpid(remote_dpid)
        try:
            self.tunnels.update_port(dpid, port_id, remote_dpid)
        except tunnels.RemoteDPIDAlreadyExist:
            return Response(status=409)

        return Response(status=200)

    def lists(self, _req, dpid, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        ports = self.tunnels.list_ports(dpid)
        body = json.dumps(ports)

        return Response(content_type='application/json', body=body)

    def get(self, _req, dpid, port_id, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        try:
            remote_dpid = self.tunnels.get_remote_dpid(dpid, port_id)
        except ryu_exc.PortNotFound:
            return Response(status=404)
        body = json.dumps(dpid_lib.dpid_to_str(remote_dpid))

        return Response(content_type='application/json', body=body)

    def delete(self, _req, dpid, port_id, **_kwargs):
        dpid = dpid_lib.str_to_dpid(dpid)
        port_id = int(port_id)
        try:
            self.tunnels.delete_port(dpid, port_id)
        except ryu_exc.PortNotFound:
            return Response(status=404)

        return Response(status=200)


class TunnelAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'tunnels': tunnels.Tunnels,
        'wsgi': WSGIApplication
    }

    def __init__(self, *_args, **kwargs):
        super(TunnelAPI, self).__init__()
        self.nw = kwargs['network']
        self.tunnels = kwargs['tunnels']
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper

        controller = TunnelKeyController
        wsgi.registory[controller.__name__] = self.tunnels
        route_name = 'tunnel_key'
        uri = '/v1.0/tunnels'
        key_uri = uri + '/networks/{network_id}/key'
        s = mapper.submapper(controller=controller)
        s.connect(route_name, key_uri, action='lists',
                  conditions=dict(method=['GET', 'HEAD']))
        s.connect(route_name, key_uri, action='delete',
                  conditions=dict(method=['DELETE']))

        key_uri += '/{tunnel_key}'
        requirements = {route_name: app_wsgi.DIGIT_PATTERN}
        s = mapper.submapper(controller=controller, requirements=requirements)
        s.connect(route_name, key_uri, action='create',
                  conditions=dict(method=['POST']))
        s.connect(route_name, key_uri, action='update',
                  conditions=dict(method=['PUT']))

        controller = TunnelPortController
        wsgi.registory[controller.__name__] = self.tunnels
        route_name = 'tunnel_port'
        sw_uri = uri + '/switches/{dpid}/ports'
        requirements = {'dpid': dpid_lib.DPID_PATTERN}
        mapper.connect(route_name, sw_uri, controller=controller,
                       action='lists', conditions=dict(method=['GET', 'HEAD']),
                       requirements=requirements)

        sw_uri += '/{port_id}'
        requirements['port_id'] = app_wsgi.DIGIT_PATTERN
        s = mapper.submapper(controller=controller, requirements=requirements)
        mapper.connect(route_name, sw_uri, action='get',
                       conditions=dict(method=['GET', 'HEAD']))
        mapper.connect(route_name, sw_uri, action='delete',
                       conditions=dict(method=['DELETE']))

        sw_uri += '/{remote_dpid}'
        requirements['remote_dpid'] = dpid_lib.DPID_PATTERN
        s = mapper.submapper(controller=controller, requirements=requirements)
        mapper.connect(route_name, sw_uri, action='create',
                       conditions=dict(method=['POST']))
        mapper.connect(route_name, sw_uri, action='update',
                       conditions=dict(method=['PUT']))
