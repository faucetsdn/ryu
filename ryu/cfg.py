# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import oslo_config.cfg

# there are 3 ways to access the configuration.
#
#    a. ryu.cfg.CONF  (used to register cli options)
#    b. RyuApp.CONF  (preferred way for ryu applications)
#    c. oslo_config.cfg.CONF
#
# Currently a. and b. shares a single ConfigOpts instance.
# We intentionally avoid using c. for our options as a python program
# which embeds ryu applications (eg. neutron agent) might want to put
# its own set of cli options into it, which can conflict with ours.
# (Currently there seems no conflict for the neutron agent.  But who knows?)
# At some point later we might want to unshare a. and b. as well, in order
# to allow app-specific options.

CONF = oslo_config.cfg.ConfigOpts()

# re-export for convenience

from oslo_config.cfg import ConfigOpts

from oslo_config.cfg import Opt
from oslo_config.cfg import BoolOpt
from oslo_config.cfg import IntOpt
from oslo_config.cfg import ListOpt
from oslo_config.cfg import MultiStrOpt
from oslo_config.cfg import StrOpt
from oslo_config.cfg import FloatOpt

from oslo_config.cfg import RequiredOptError
from oslo_config.cfg import ConfigFilesNotFoundError
