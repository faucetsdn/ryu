# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
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

import inspect
import itertools
import logging
import sys

from ryu import utils
from ryu.controller.handler import register_instance, get_dependent_services
from ryu.controller.controller import Datapath
from ryu.controller.event import EventRequestBase, EventReplyBase
from ryu.lib import hub

LOG = logging.getLogger('ryu.base.app_manager')

SERVICE_BRICKS = {}


def lookup_service_brick(name):
    return SERVICE_BRICKS.get(name)


def register_app(app):
    assert isinstance(app, RyuApp)
    assert not app.name in SERVICE_BRICKS
    SERVICE_BRICKS[app.name] = app
    register_instance(app)


class RyuApp(object):
    """
    Base class for Ryu network application
    """
    _CONTEXTS = {}
    _EVENTS = []  # list of events to be generated in app

    @classmethod
    def context_iteritems(cls):
        """
        Return iterator over the (key, contxt class) of application context
        """
        return cls._CONTEXTS.iteritems()

    def __init__(self, *_args, **_kwargs):
        super(RyuApp, self).__init__()
        self.name = self.__class__.__name__
        self.event_handlers = {}        # ev_cls -> handlers:list
        self.observers = {}     # ev_cls -> observer-name -> states:set
        self.threads = []
        self.events = hub.Queue(128)
        self.replies = hub.Queue()
        self.logger = logging.getLogger(self.name)
        self.threads.append(hub.spawn(self._event_loop))

    def register_handler(self, ev_cls, handler):
        assert callable(handler)
        self.event_handlers.setdefault(ev_cls, [])
        self.event_handlers[ev_cls].append(handler)

    def register_observer(self, ev_cls, name, states=None):
        states = states or set()
        ev_cls_observers = self.observers.setdefault(ev_cls, {})
        ev_cls_observers.setdefault(name, set()).update(states)

    def get_handlers(self, ev, state=None):
        handlers = self.event_handlers.get(ev.__class__, [])
        if state is None:
            return handlers

        return [handler for handler in handlers
                if not handler.dispatchers or state in handler.dispatchers]

    def get_observers(self, ev, state):
        observers = []
        for k, v in self.observers.get(ev.__class__, {}).iteritems():
            if not state or not v or state in v:
                observers.append(k)

        return observers

    def send_reply(self, rep):
        assert isinstance(rep, EventReplyBase)
        SERVICE_BRICKS[rep.dst].replies.put(rep)

    def send_request(self, req):
        assert isinstance(req, EventRequestBase)
        req.sync = True
        self.send_event(req.dst, req)
        # going to sleep for the reply
        return self.replies.get()

    def _event_loop(self):
        while True:
            ev, state = self.events.get()
            handlers = self.get_handlers(ev, state)
            for handler in handlers:
                handler(ev)

    def _send_event(self, ev, state):
        self.events.put((ev, state))

    def send_event(self, name, ev, state=None):
        if name in SERVICE_BRICKS:
            if isinstance(ev, EventRequestBase):
                ev.src = self.name
            LOG.debug("EVENT %s->%s %s" %
                      (self.name, name, ev.__class__.__name__))
            SERVICE_BRICKS[name]._send_event(ev, state)
        else:
            LOG.debug("EVENT LOST %s->%s %s" %
                      (self.name, name, ev.__class__.__name__))

    def send_event_to_observers(self, ev, state=None):
        for observer in self.get_observers(ev, state):
            self.send_event(observer, ev, state)

    def reply_to_request(self, req, rep):
        rep.dst = req.src
        if req.sync:
            self.send_reply(rep)
        else:
            self.send_event(rep.dst, rep)

    def close(self):
        """
        teardown method.
        The method name, close, is chosen for python context manager
        """
        pass


class AppManager(object):
    def __init__(self):
        self.applications_cls = {}
        self.applications = {}
        self.contexts_cls = {}
        self.contexts = {}

    def load_app(self, name):
        mod = utils.import_module(name)
        clses = inspect.getmembers(mod, lambda cls: (inspect.isclass(cls) and
                                                     issubclass(cls, RyuApp)))
        if clses:
            return clses[0][1]
        return None

    def load_apps(self, app_lists):
        app_lists = [app for app
                     in itertools.chain.from_iterable(app.split(',')
                                                      for app in app_lists)]
        while len(app_lists) > 0:
            app_cls_name = app_lists.pop(0)

            LOG.info('loading app %s', app_cls_name)

            cls = self.load_app(app_cls_name)
            if cls is None:
                continue

            self.applications_cls[app_cls_name] = cls

            services = []
            for key, context_cls in cls.context_iteritems():
                cls = self.contexts_cls.setdefault(key, context_cls)
                assert cls == context_cls

                if issubclass(context_cls, RyuApp):
                    services.extend(get_dependent_services(context_cls))

            services.extend(get_dependent_services(cls))
            if services:
                app_lists.extend(services)

    def create_contexts(self):
        for key, cls in self.contexts_cls.items():
            context = cls()
            LOG.info('creating context %s', key)
            assert not key in self.contexts
            self.contexts[key] = context
            # hack for dpset
            if issubclass(context.__class__, RyuApp):
                register_app(context)
        return self.contexts

    def instantiate_apps(self, *args, **kwargs):
        for app_name, cls in self.applications_cls.items():
            # for now, only single instance of a given module
            # Do we need to support multiple instances?
            # Yes, maybe for slicing.
            LOG.info('instantiating app %s', app_name)

            if hasattr(cls, 'OFP_VERSIONS'):
                for k in Datapath.supported_ofp_version.keys():
                    if not k in cls.OFP_VERSIONS:
                        del Datapath.supported_ofp_version[k]

            assert len(Datapath.supported_ofp_version), \
                'No OpenFlow version is available'

            assert app_name not in self.applications
            app = cls(*args, **kwargs)
            register_app(app)
            self.applications[app_name] = app

        for i in SERVICE_BRICKS.values():
            for _k, m in inspect.getmembers(i, inspect.ismethod):
                if not hasattr(m, 'observer'):
                    continue

                # name is module name of ev_cls
                name = m.observer.split('.')[-1]
                if name in SERVICE_BRICKS:
                    brick = SERVICE_BRICKS[name]
                    brick.register_observer(m.ev_cls, i.name, m.dispatchers)

                # allow RyuApp and Event class are in different module
                for brick in SERVICE_BRICKS.itervalues():
                    if m.ev_cls in brick._EVENTS:
                        brick.register_observer(m.ev_cls, i.name,
                                                m.dispatchers)

        for brick, i in SERVICE_BRICKS.items():
            LOG.debug("BRICK %s" % brick)
            for ev_cls, list in i.observers.items():
                LOG.debug("  PROVIDES %s TO %s" % (ev_cls.__name__, list))
            for ev_cls in i.event_handlers.keys():
                LOG.debug("  CONSUMES %s" % (ev_cls.__name__,))

    def close(self):
        def close_all(close_dict):
            for app in close_dict.values():
                close_method = getattr(app, 'close', None)
                if callable(close_method):
                    close_method()
            close_dict.clear()

        close_all(self.applications)
        close_all(self.contexts)
