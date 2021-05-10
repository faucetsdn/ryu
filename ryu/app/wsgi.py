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
from types import MethodType

from routes import Mapper
from routes.util import URLGenerator
import six
from tinyrpc.server import RPCServer
from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.dispatch import public as rpc_public
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports import ServerTransport, ClientTransport
from tinyrpc.client import RPCClient
import webob.dec
import webob.exc
from webob.request import Request as webob_Request
from webob.response import Response as webob_Response

from ryu import cfg
from ryu.lib import hub

DEFAULT_WSGI_HOST = '0.0.0.0'
DEFAULT_WSGI_PORT = 8080

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt(
        'wsapi-host', default=DEFAULT_WSGI_HOST,
        help='webapp listen host (default %s)' % DEFAULT_WSGI_HOST),
    cfg.IntOpt(
        'wsapi-port', default=DEFAULT_WSGI_PORT,
        help='webapp listen port (default %s)' % DEFAULT_WSGI_PORT),
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


class Request(webob_Request):
    """
    Wrapper class for webob.request.Request.

    The behavior of this class is the same as webob.request.Request
    except for setting "charset" to "UTF-8" automatically.
    """
    DEFAULT_CHARSET = "UTF-8"

    def __init__(self, environ, charset=DEFAULT_CHARSET, *args, **kwargs):
        super(Request, self).__init__(
            environ, charset=charset, *args, **kwargs)


class Response(webob_Response):
    """
    Wrapper class for webob.response.Response.

    The behavior of this class is the same as webob.response.Response
    except for setting "charset" to "UTF-8" automatically.
    """
    DEFAULT_CHARSET = "UTF-8"

    def __init__(self, charset=DEFAULT_CHARSET, *args, **kwargs):
        super(Response, self).__init__(charset=charset, *args, **kwargs)


class WebSocketRegistrationWrapper(object):

    def __init__(self, func, controller):
        self._controller = controller
        self._controller_method = MethodType(func, controller)

    def __call__(self, ws):
        wsgi_application = self._controller.parent
        ws_manager = wsgi_application.websocketmanager
        ws_manager.add_connection(ws)
        try:
            self._controller_method(ws)
        finally:
            ws_manager.delete_connection(ws)


class _AlreadyHandledResponse(Response):
    # XXX: Eventlet API should not be used directly.
    # https://github.com/benoitc/gunicorn/pull/2581
    from packaging import version
    import eventlet
    if version.parse(eventlet.__version__) >= version.parse("0.30.3"):
        import eventlet.wsgi
        _ALREADY_HANDLED = getattr(eventlet.wsgi, "ALREADY_HANDLED", None)
    else:
        from eventlet.wsgi import ALREADY_HANDLED
        _ALREADY_HANDLED = ALREADY_HANDLED

    def __call__(self, environ, start_response):
        return self._ALREADY_HANDLED


def websocket(name, path):
    def _websocket(controller_func):
        def __websocket(self, req, **_):
            wrapper = WebSocketRegistrationWrapper(controller_func, self)
            ws_wsgi = hub.WebSocketWSGI(wrapper)
            ws_wsgi(req.environ, req.start_response)
            # XXX: In order to prevent the writing to a already closed socket.
            #      This issue is caused by combined use:
            #       - webob.dec.wsgify()
            #       - eventlet.wsgi.HttpProtocol.handle_one_response()
            return _AlreadyHandledResponse()
        __websocket.routing_info = {
            'name': name,
            'path': path,
            'methods': None,
            'requirements': None,
        }
        return __websocket
    return _websocket


class ControllerBase(object):
    special_vars = ['action', 'controller']

    def __init__(self, req, link, data, **config):
        self.req = req
        self.link = link
        self.data = data
        self.parent = None
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


class WebSocketDisconnectedError(Exception):
    pass


class WebSocketServerTransport(ServerTransport):
    def __init__(self, ws):
        self.ws = ws

    def receive_message(self):
        message = self.ws.wait()
        if message is None:
            raise WebSocketDisconnectedError()
        context = None
        return context, message

    def send_reply(self, context, reply):
        self.ws.send(six.text_type(reply))


class WebSocketRPCServer(RPCServer):
    def __init__(self, ws, rpc_callback):
        dispatcher = RPCDispatcher()
        dispatcher.register_instance(rpc_callback)
        super(WebSocketRPCServer, self).__init__(
            WebSocketServerTransport(ws),
            JSONRPCProtocol(),
            dispatcher,
        )

    def serve_forever(self):
        try:
            super(WebSocketRPCServer, self).serve_forever()
        except WebSocketDisconnectedError:
            return

    def _spawn(self, func, *args, **kwargs):
        hub.spawn(func, *args, **kwargs)


class WebSocketClientTransport(ClientTransport):

    def __init__(self, ws, queue):
        self.ws = ws
        self.queue = queue

    def send_message(self, message, expect_reply=True):
        self.ws.send(six.text_type(message))

        if expect_reply:
            return self.queue.get()


class WebSocketRPCClient(RPCClient):

    def __init__(self, ws):
        self.ws = ws
        self.queue = hub.Queue()
        super(WebSocketRPCClient, self).__init__(
            JSONRPCProtocol(),
            WebSocketClientTransport(ws, self.queue),
        )

    def serve_forever(self):
        while True:
            msg = self.ws.wait()
            if msg is None:
                break
            self.queue.put(msg)


class wsgify_hack(webob.dec.wsgify):
    def __call__(self, environ, start_response):
        self.kwargs['start_response'] = start_response
        return super(wsgify_hack, self).__call__(environ, start_response)


class WebSocketManager(object):

    def __init__(self):
        self._connections = []

    def add_connection(self, ws):
        self._connections.append(ws)

    def delete_connection(self, ws):
        self._connections.remove(ws)

    def broadcast(self, msg):
        for connection in self._connections:
            connection.send(msg)


class WSGIApplication(object):
    def __init__(self, **config):
        self.config = config
        self.mapper = Mapper()
        self.registory = {}
        self._wsmanager = WebSocketManager()
        super(WSGIApplication, self).__init__()

    def _match(self, req):
        # Note: Invoke the new API, first. If the arguments unmatched,
        # invoke the old API.
        try:
            return self.mapper.match(environ=req.environ)
        except TypeError:
            self.mapper.environ = req.environ
            return self.mapper.match(req.path_info)

    @wsgify_hack
    def __call__(self, req, start_response):
        match = self._match(req)

        if not match:
            return webob.exc.HTTPNotFound()

        req.start_response = start_response
        req.urlvars = match
        link = URLGenerator(self.mapper, req.environ)

        data = None
        name = match['controller'].__name__
        if name in self.registory:
            data = self.registory[name]

        controller = match['controller'](req, link, data, **self.config)
        controller.parent = self
        return controller(req)

    def register(self, controller, data=None):
        def _target_filter(attr):
            if not inspect.ismethod(attr) and not inspect.isfunction(attr):
                return False
            if not hasattr(attr, 'routing_info'):
                return False
            return True
        methods = inspect.getmembers(controller, _target_filter)
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

    @property
    def websocketmanager(self):
        return self._wsmanager


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
