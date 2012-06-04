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

import gflags
import logging
import webob.dec

from gevent import pywsgi
from routes import Mapper
from routes.util import URLGenerator

LOG = logging.getLogger('ryu.app.wsgi')

FLAGS = gflags.FLAGS
gflags.DEFINE_string('wsapi_host', '', 'webapp listen host')
gflags.DEFINE_integer('wsapi_port', 8080, 'webapp listen port')


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

        # LOG.debug('kwargs %s', kwargs)
        return getattr(self, action)(req, **kwargs)


class WSGIApplication(object):
    def __init__(self, **config):
        self.config = config
        self.mapper = Mapper()
        self.registory = {}
        super(WSGIApplication, self).__init__()

    @webob.dec.wsgify
    def __call__(self, req):
        # LOG.debug('mapper %s', self.mapper)
        # LOG.debug('req: %s\n', req)
        # LOG.debug('\nreq.environ: %s', req.environ)
        match = self.mapper.match(environ=req.environ)

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


class WSGIServer(pywsgi.WSGIServer):
    def __init__(self, application, **config):
        super(WSGIServer, self).__init__((FLAGS.wsapi_host, FLAGS.wsapi_port),
                                         application, **config)

    def __call__(self):
        self.serve_forever()


def start_service(app_mgr):
    for instance in app_mgr.contexts.values():
        if instance.__class__ == WSGIApplication:
            return WSGIServer(instance)

    return None
