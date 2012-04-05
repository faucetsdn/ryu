# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

LOG = logging.getLogger('ryu.base.app_manager')


class AppManager(object):
    def __init__(self):
        self.applications = {}

    def load(self, app_mod_name, *args, **kwargs):
        # for now, only single instance of a given module
        # Do we need to support multiple instances?
        # Yes, maybe for slicing.
        assert app_mod_name not in self.applications

        cls = utils.import_object(app_mod_name)
        app = cls(*args, **kwargs)
        register_instance(app)

        self.applications[app_mod_name] = app

    def load_apps(self, app_lists, *args, **kwargs):
        for app in itertools.chain.from_iterable([app_list.split(',')
                                                  for app_list in app_lists]):
            self.load(app, *args, **kwargs)
            LOG.info('loading app %s', app)
