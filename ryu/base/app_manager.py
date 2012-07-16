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

import itertools
import logging

from ryu import utils
from ryu.controller.handler import register_instance
from ryu.controller.controller import Datapath

LOG = logging.getLogger('ryu.base.app_manager')


class RyuAppContext(object):
    """
    Base class for Ryu application context
    """
    def __init__(self):
        super(RyuAppContext, self).__init__()

    def close(self):
        """
        teardown method
        The method name, close, is chosen for python context manager
        """
        pass


class RyuApp(object):
    """
    Base class for Ryu network application
    """
    _CONTEXTS = {}

    @classmethod
    def context_iteritems(cls):
        """
        Return iterator over the (key, contxt class) of application context
        """
        return cls._CONTEXTS.iteritems()

    def __init__(self, *_args, **_kwargs):
        super(RyuApp, self).__init__()

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
        for k, v in mod.__dict__.items():
            try:
                if issubclass(v, RyuApp):
                    return getattr(mod, k)
            except TypeError:
                pass
        return None

    def load_apps(self, app_lists):
        for app_cls_name in itertools.chain.from_iterable([app_list.split(',')
                                                           for app_list
                                                           in app_lists]):
            LOG.info('loading app %s', app_cls_name)

            # for now, only single instance of a given module
            # Do we need to support multiple instances?
            # Yes, maybe for slicing.
            assert app_cls_name not in self.applications_cls

            cls = self.load_app(app_cls_name)
            if cls is None:
                continue

            self.applications_cls[app_cls_name] = cls

            for key, context_cls in cls.context_iteritems():
                cls = self.contexts_cls.setdefault(key, context_cls)
                assert cls == context_cls

    def create_contexts(self):
        for key, cls in self.contexts_cls.items():
            self.contexts[key] = cls()
        return self.contexts

    def instantiate_apps(self, *args, **kwargs):
        for app_name, cls in self.applications_cls.items():
            # for now, only single instance of a given module
            # Do we need to support multiple instances?
            # Yes, maybe for slicing.
            LOG.info('instantiating app %s', app_name)

            if 'OFP_VERSIONS' in cls.__dict__:
                for k in Datapath.supported_ofp_version.keys():
                    if not k in cls.OFP_VERSIONS:
                        del Datapath.supported_ofp_version[k]

            assert len(Datapath.supported_ofp_version), \
                'No OpenFlow version is available'

            assert app_name not in self.applications
            app = cls(*args, **kwargs)
            register_instance(app)
            self.applications[app_name] = app

    def close(self):
        def close_all(close_dict):
            for app in close_dict:
                close_method = getattr(app, 'close', None)
                if callable(close_method):
                    close_method()
            close_dict.clear()

        close_all(self.applications)
        close_all(self.contexts)
