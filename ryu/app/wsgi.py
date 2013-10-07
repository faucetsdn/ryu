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

import inspect

from oslo.config import cfg
import webob.dec

from ryu.lib import hub
from routes import Mapper
from routes.util import URLGenerator


CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt('wsapi-host', default='', help='webapp listen host'),
    cfg.IntOpt('wsapi-port', default=8080, help='webapp listen port')
])

HEX_PATTERN = r'0x[0-9a-z]+'
DIGIT_PATTERN = r'[1-9][0-9]*'


def route(name, path, methods=None, requirements=None):
    def _route(controller_method):
        controller_method.routing_info = {
            'name': name,
            'path': path,
            'methods': methods,
            'requirements': requirements,
        }
        return controller_method
    return _route


class ControllerBase(object):
    special_vars = ['action', 'controller']

    def __init__(self, req, link, data, **config):
        self.req = req
        self.link = link
        for name, value in config.items():
            setattr(self, name, value)

    def __call__(self, req):
        action = self.req.urlvars.get('action', 'index')
        if hasattr(self, '__before__'):
            self.__before__()

        kwargs = self.req.urlvars.copy()
        for attr in self.special_vars:
            if attr in kwargs:
                del kwargs[attr]

        return getattr(self, action)(req, **kwargs)


class WSGIApplication(object):
    def __init__(self, **config):
        self.config = config
        self.mapper = Mapper()
        self.registory = {}
        super(WSGIApplication, self).__init__()
        # XXX: Switch how to call the API of Routes for every version
        match_argspec = inspect.getargspec(self.mapper.match)
        if 'environ' in match_argspec.args:
            # New API
            self._match = self._match_with_environ
        else:
            # Old API
            self._match = self._match_with_path_info

    def _match_with_environ(self, req):
        match = self.mapper.match(environ=req.environ)
        return match

    def _match_with_path_info(self, req):
        self.mapper.environ = req.environ
        match = self.mapper.match(req.path_info)
        return match

    @webob.dec.wsgify
    def __call__(self, req):
        match = self._match(req)

        if not match:
            return webob.exc.HTTPNotFound()

        req.urlvars = match
        link = URLGenerator(self.mapper, req.environ)

        data = None
        name = match['controller'].__name__
        if name in self.registory:
            data = self.registory[name]

        controller = match['controller'](req, link, data, **self.config)
        return controller(req)

    def register(self, controller, data=None):
        methods = inspect.getmembers(controller,
                                     lambda v: inspect.ismethod(v) and
                                     hasattr(v, 'routing_info'))
        for method_name, method in methods:
            routing_info = getattr(method, 'routing_info')
            name = routing_info['name']
            path = routing_info['path']
            conditions = {}
            if routing_info.get('methods'):
                conditions['method'] = routing_info['methods']
            requirements = routing_info.get('requirements') or {}
            self.mapper.connect(name,
                                path,
                                controller=controller,
                                requirements=requirements,
                                action=method_name,
                                conditions=conditions)
        if data:
            self.registory[controller.__name__] = data


class WSGIServer(hub.WSGIServer):
    def __init__(self, application, **config):
        super(WSGIServer, self).__init__((CONF.wsapi_host, CONF.wsapi_port),
                                         application, **config)

    def __call__(self):
        self.serve_forever()


def start_service(app_mgr):
    for instance in app_mgr.contexts.values():
        if instance.__class__ == WSGIApplication:
            return WSGIServer(instance)

    return None
