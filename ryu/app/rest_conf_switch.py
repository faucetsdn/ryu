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

"""
This module provides a set of REST API for switch configuration.
- Per-switch Key-Value store

Used by OpenStack Ryu agent.
"""

from six.moves import http_client
import json
import logging
from webob import Response

from ryu.app.wsgi import ControllerBase
from ryu.base import app_manager
from ryu.controller import conf_switch
from ryu.lib import dpid as dpid_lib


# REST API for switch configuration
#
# get all the switches
# GET /v1.0/conf/switches
#
# get all the configuration keys of a switch
# GET /v1.0/conf/switches/<dpid>
#
# delete all the configuration of a switch
# DELETE /v1.0/conf/switches/<dpid>
#
# set the <key> configuration of a switch
# PUT /v1.0/conf/switches/<dpid>/<key>
#
# get the <key> configuration of a switch
# GET /v1.0/conf/switches/<dpid>/<key>
#
# delete the <key> configuration of a switch
# DELETE /v1.0/conf/switches/<dpid>/<key>
#
# where
# <dpid>: datapath id in 16 hex


class ConfSwitchController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(ConfSwitchController, self).__init__(req, link, data, **config)
        self.conf_switch = data

    def list_switches(self, _req, **_kwargs):
        dpids = self.conf_switch.dpids()
        body = json.dumps([dpid_lib.dpid_to_str(dpid) for dpid in dpids])
        return Response(content_type='application/json', body=body)

    @staticmethod
    def _do_switch(dpid, func, ret_func):
        dpid = dpid_lib.str_to_dpid(dpid)
        try:
            ret = func(dpid)
        except KeyError:
            return Response(status=http_client.NOT_FOUND,
                            body='no dpid is found %s' %
                            dpid_lib.dpid_to_str(dpid))

        return ret_func(ret)

    def delete_switch(self, _req, dpid, **_kwargs):
        def _delete_switch(dpid):
            self.conf_switch.del_dpid(dpid)
            return None

        def _ret(_ret):
            return Response(status=http_client.ACCEPTED)

        return self._do_switch(dpid, _delete_switch, _ret)

    def list_keys(self, _req, dpid, **_kwargs):
        def _list_keys(dpid):
            return self.conf_switch.keys(dpid)

        def _ret(keys):
            body = json.dumps(keys)
            return Response(content_type='application/json', body=body)

        return self._do_switch(dpid, _list_keys, _ret)

    @staticmethod
    def _do_key(dpid, key, func, ret_func):
        dpid = dpid_lib.str_to_dpid(dpid)
        try:
            ret = func(dpid, key)
        except KeyError:
            return Response(status=http_client.NOT_FOUND,
                            body='no dpid/key is found %s %s' %
                            (dpid_lib.dpid_to_str(dpid), key))
        return ret_func(ret)

    def set_key(self, req, dpid, key, **_kwargs):
        def _set_val(dpid, key):
            val = json.loads(req.body)
            self.conf_switch.set_key(dpid, key, val)
            return None

        def _ret(_ret):
            return Response(status=http_client.CREATED)

        return self._do_key(dpid, key, _set_val, _ret)

    def get_key(self, _req, dpid, key, **_kwargs):
        def _get_key(dpid, key):
            return self.conf_switch.get_key(dpid, key)

        def _ret(val):
            return Response(content_type='application/json',
                            body=json.dumps(val))

        return self._do_key(dpid, key, _get_key, _ret)

    def delete_key(self, _req, dpid, key, **_kwargs):
        def _delete_key(dpid, key):
            self.conf_switch.del_key(dpid, key)
            return None

        def _ret(_ret):
            return Response()

        return self._do_key(dpid, key, _delete_key, _ret)


class ConfSwitchAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'conf_switch': conf_switch.ConfSwitchSet,
    }

    def __init__(self, *args, **kwargs):
        super(ConfSwitchAPI, self).__init__(*args, **kwargs)
        self.conf_switch = kwargs['conf_switch']
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper

        controller = ConfSwitchController
        wsgi.registory[controller.__name__] = self.conf_switch
        route_name = 'conf_switch'
        uri = '/v1.0/conf/switches'
        mapper.connect(route_name, uri, controller=controller,
                       action='list_switches',
                       conditions=dict(method=['GET']))

        uri += '/{dpid}'
        requirements = {'dpid': dpid_lib.DPID_PATTERN}
        s = mapper.submapper(controller=controller, requirements=requirements)
        s.connect(route_name, uri, action='delete_switch',
                  conditions=dict(method=['DELETE']))
        s.connect(route_name, uri, action='list_keys',
                  conditions=dict(method=['GET']))

        uri += '/{key}'
        s.connect(route_name, uri, action='set_key',
                  conditions=dict(method=['PUT']))
        s.connect(route_name, uri, action='get_key',
                  conditions=dict(method=['GET']))
        s.connect(route_name, uri, action='delete_key',
                  conditions=dict(method=['DELETE']))
