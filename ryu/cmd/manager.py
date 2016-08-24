#!/usr/bin/env python
#
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

from ryu.lib import hub
hub.patch(thread=False)

# TODO:
#   Right now, we have our own patched copy of ovs python bindings
#   Once our modification is upstreamed and widely deployed,
#   use it
#
# NOTE: this modifies sys.path and thus affects the following imports.
import ryu.contrib
ryu.contrib.update_module_path()

from ryu import cfg
import logging
import sys

from ryu import log
log.early_init_log(logging.DEBUG)

from ryu import flags
from ryu import version
from ryu.app import wsgi
from ryu.base.app_manager import AppManager
from ryu.controller import controller
from ryu.topology import switches


CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.ListOpt('app-lists', default=[],
                help='application module name to run'),
    cfg.MultiStrOpt('app', positional=True, default=[],
                    help='application module name to run'),
    cfg.StrOpt('pid-file', default=None, help='pid file name'),
    cfg.BoolOpt('enable-debugger', default=False,
                help='don\'t overwrite Python standard threading library'
                '(use only for debugging)'),
])


def main(args=None, prog=None):
    try:
        CONF(args=args, prog=prog,
             project='ryu', version='ryu-manager %s' % version,
             default_config_files=['/usr/local/etc/ryu/ryu.conf'])
    except cfg.ConfigFilesNotFoundError:
        CONF(args=args, prog=prog,
             project='ryu', version='ryu-manager %s' % version)

    log.init_log()
    logger = logging.getLogger(__name__)

    if CONF.enable_debugger:
        msg = 'debugging is available (--enable-debugger option is turned on)'
        logger.info(msg)
    else:
        hub.patch(thread=True)

    if CONF.pid_file:
        import os
        with open(CONF.pid_file, 'w') as pid_file:
            pid_file.write(str(os.getpid()))

    app_lists = CONF.app_lists + CONF.app
    # keep old behavior, run ofp if no application is specified.
    if not app_lists:
        app_lists = ['ryu.controller.ofp_handler']

    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    services = []
    services.extend(app_mgr.instantiate_apps(**contexts))

    webapp = wsgi.start_service(app_mgr)
    if webapp:
        thr = hub.spawn(webapp)
        services.append(thr)

    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        logger.debug("Keyboard Interrupt received. "
                     "Closing RYU application manager...")
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()
