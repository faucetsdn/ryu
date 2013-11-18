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

# This module provides a set of REST API dedicated to OpenStack Ryu plug-in.
#   - Interface (uuid in ovsdb) registration
#   - Maintain interface association to a network
#
# Used by OpenStack Ryu plug-in.

import json
from webob import Response

from ryu.base import app_manager
from ryu.app.wsgi import (ControllerBase,
                          WSGIApplication)
from ryu.lib import quantum_ifaces

# REST API for openstack quantum
# get the list of iface-ids
# GET /v1.0/quantum/ports/
#
# register the iface_id
# POST /v1.0/quantum/ports/{iface_id}
#
# unregister iface_id
# DELETE /v1.0/quantum/ports/{iface_id}
#
# associate network_id with iface_id
# GET /v1.0/quantum/ports/{iface_id}/network_id
#
# associate network_id with iface_id
# POST /v1.0/quantum/ports/{iface_id}/network_id/{network_id}
#
# update network_id with iface_id
# PUT /v1.0/quantum/ports/{iface_id}/network_id/{network_id}


class QuantumController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(QuantumController, self).__init__(req, link, data, **config)
        self.ifaces = data

    def list_ifaces(self, _req, **_kwargs):
        body = json.dumps(self.ifaces.keys())
        return Response(content_type='application/json', body=body)

    def delete_iface(self, _req, iface_id, **_kwargs):
        self.ifaces.unregister(iface_id)
        return Response(status=200)

    def list_keys(self, _req, iface_id, **_kwargs):
        try:
            keys = self.ifaces.list_keys(iface_id)
        except KeyError:
            return Response(status=404)
        body = json.dumps(keys)
        return Response(content_type='application/json', body=body)

    def get_key(self, _req, iface_id, key, **_kwargs):
        try:
            value = self.ifaces.get_key(iface_id, key)
        except KeyError:
            return Response(status=404)
        body = json.dumps(value)
        return Response(content_type='application/json', body=body)

    def create_value(self, _req, iface_id, key, value, **_kwargs):
        try:
            self.ifaces.set_key(iface_id, key, value)
        except ValueError:
            return Response(status=404)
        return Response(status=200)

    def update_value(self, _req, iface_id, key, value, **_kwargs):
        try:
            self.ifaces.update_key(iface_id, key, value)
        except ValueError:
            return Response(status=404)
        return Response(status=200)


class QuantumIfaceAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'quantum_ifaces': quantum_ifaces.QuantumIfaces,
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        super(QuantumIfaceAPI, self).__init__(*args, **kwargs)
        self.ifaces = kwargs['quantum_ifaces']
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper

        controller = QuantumController
        wsgi.registory[controller.__name__] = self.ifaces
        route_name = 'quantum_ifaces'
        uri = '/v1.0/quantum'

        ports_uri = uri + '/ports'
        s = mapper.submapper(controller=controller)
        s.connect(route_name, ports_uri, action='list_ifaces',
                  conditions=dict(method=['GET', 'HEAD']))

        iface_uri = ports_uri + '/{iface_id}'
        s.connect(route_name, iface_uri, action='delete_iface',
                  conditions=dict(method=['DELETE']))

        keys_uri = iface_uri + '/keys'
        s.connect(route_name, keys_uri, action='list_keys',
                  conditions=dict(method=['GET', 'HEAD']))

        key_uri = keys_uri + '/{key}'
        s.connect(route_name, key_uri, action='get_key',
                  conditions=dict(method=['GET', 'HEAD']))

        value_uri = keys_uri + '/{key}/{value}'
        s.connect(route_name, value_uri, action='create_value',
                  conditions=dict(method=['POST']))
        s.connect(route_name, value_uri, action='update_value',
                  conditions=dict(method=['PUT']))
