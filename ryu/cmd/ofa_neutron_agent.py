#!/usr/bin/env python

# Copyright (C) 2014 VA Linux Systems Japan K.K.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Fumihiko Kakuma, VA Linux Systems Japan K.K.
# @author: YAMAMOTO Takashi, VA Linux Systems Japan K.K.

# NOTE: This module is used by Neutron "ofagent" agent for
# IceHouse release.  Juno and later releases do not use this.
# TODO: Remove this module when IceHouse is EOL'ed.

from ryu.lib import hub
hub.patch()

from ryu import cfg

from neutron.common import config as logging_config

from ryu.base.app_manager import AppManager


def main():
    cfg.CONF(project='ryu')
    logging_config.setup_logging(cfg.CONF)
    AppManager.run_apps(['neutron.plugins.ofagent.agent.ofa_neutron_agent'])


if __name__ == "__main__":
    main()
