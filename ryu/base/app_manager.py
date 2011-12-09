# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
