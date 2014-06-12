#!/usr/bin/env python

# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 VA Linux Systems Japan K.K.
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
# @author: Fumihiko Kakuma, VA Linux Systems Japan K.K.

from ryu.lib import hub
hub.patch()

from ryu import cfg

from neutron.common import config as logging_config
from neutron.openstack.common import log as logging

from ryu.base.app_manager import AppManager


LOG = logging.getLogger(__name__)


def main():
    cfg.CONF(project='ryu')
    logging_config.setup_logging(cfg.CONF)
    AppManager.run_apps(['neutron.plugins.ofagent.agent.ofa_neutron_agent'])


if __name__ == "__main__":
    main()
