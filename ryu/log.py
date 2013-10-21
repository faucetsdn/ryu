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

from __future__ import print_function
from oslo.config import cfg
import inspect
import logging
import logging.config
import logging.handlers
import os
import sys
import ConfigParser


CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.IntOpt('default-log-level', default=None, help='default log level'),
    cfg.BoolOpt('verbose', default=False, help='show debug output'),
    cfg.BoolOpt('use-stderr', default=True, help='log to standard error'),
    cfg.BoolOpt('use-syslog', default=False, help='output to syslog'),
    cfg.StrOpt('log-dir', default=None, help='log file directory'),
    cfg.StrOpt('log-file', default=None, help='log file name'),
    cfg.StrOpt('log-file-mode', default='0644',
               help='default log file permission'),
    cfg.StrOpt('log-config-file', default=None,
               help='Path to a logging config file to use')
])


_EARLY_LOG_HANDLER = None


def early_init_log(level=None):
    global _EARLY_LOG_HANDLER
    _EARLY_LOG_HANDLER = logging.StreamHandler(sys.stderr)

    log = logging.getLogger()
    log.addHandler(_EARLY_LOG_HANDLER)
    if level is not None:
        log.setLevel(level)


def _get_log_file():
    if CONF.log_file:
        return CONF.log_file
    if CONF.log_dir:
        return os.path.join(CONF.log_dir,
                            os.path.basename(inspect.stack()[-1][1])) + '.log'
    return None


def init_log():
    global _EARLY_LOG_HANDLER

    log = logging.getLogger()

    if CONF.log_config_file:
        try:
            logging.config.fileConfig(CONF.log_config_file,
                                      disable_existing_loggers=True)
        except ConfigParser.Error as e:
            print('Failed to parse %s: %s' % (CONF.log_config_file, e),
                  file=sys.stderr)
            sys.exit(2)
        return

    if CONF.use_stderr:
        log.addHandler(logging.StreamHandler(sys.stderr))
    if _EARLY_LOG_HANDLER is not None:
        log.removeHandler(_EARLY_LOG_HANDLER)
        _EARLY_LOG_HANDLER = None

    if CONF.use_syslog:
        syslog = logging.handlers.SysLogHandler(address='/dev/log')
        log.addHandler(syslog)

    log_file = _get_log_file()
    if log_file is not None:
        log.addHandler(logging.handlers.WatchedFileHandler(log_file))
        mode = int(CONF.log_file_mode, 8)
        os.chmod(log_file, mode)

    if CONF.default_log_level is not None:
        log.setLevel(CONF.default_log_level)
    elif CONF.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
