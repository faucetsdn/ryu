# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.lib import dpid as dpid_lib
from ryu.lib import port_no as port_no_lib
from ryu.topology.switches import get_switch, get_link

# REST API for switch configuration
#
# get all the switches
# GET /v1.0/topology/switches
#
# get the switch
# GET /v1.0/topology/switches/<dpid>
#
# get all the links
# GET /v1.0/topology/links
#
# get the links of a switch
# GET /v1.0/topology/links/<dpid>
#
# where
# <dpid>: datapath id in 16 hex


class TopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        self.topology_api_app = data['topology_api_app']

    def list_switches(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        switches = get_switch(self.topology_api_app, dpid)
        body = json.dumps([switch.to_dict() for switch in switches])
        return Response(content_type='application/json', body=body)

    def list_links(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        links = get_link(self.topology_api_app, dpid)
        body = json.dumps([link.to_dict() for link in links])
        return Response(content_type='application/json', body=body)


class TopologyAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(TopologyAPI, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper

        controller = TopologyController
        wsgi.registory[controller.__name__] = {'topology_api_app': self}
        route_name = 'topology'

        uri = '/v1.0/topology/switches'
        mapper.connect(route_name, uri, controller=controller,
                       action='list_switches',
                       conditions=dict(method=['GET']))

        uri = '/v1.0/topology/switches/{dpid}'
        requirements = {'dpid': dpid_lib.DPID_PATTERN}
        s = mapper.submapper(controller=controller, requirements=requirements)
        s.connect(route_name, uri, action='list_switches',
                  conditions=dict(method=['GET']))

        uri = '/v1.0/topology/links'
        mapper.connect(route_name, uri, controller=controller,
                       action='list_links',
                       conditions=dict(method=['GET']))

        uri = '/v1.0/topology/links/{dpid}'
        requirements = {'dpid': dpid_lib.DPID_PATTERN}
        s = mapper.submapper(controller=controller, requirements=requirements)
        s.connect(route_name, uri, action='list_links',
                  conditions=dict(method=['GET']))
