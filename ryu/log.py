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

import gflags
import inspect
import logging
import os
import sys


FLAGS = gflags.FLAGS

gflags.DEFINE_integer('default_log_level', None, 'default log level')
gflags.DEFINE_bool('verbose', False, 'show debug output')

gflags.DEFINE_bool('use_stderr', True, 'log to standard error')
gflags.DEFINE_string('use_syslog', False, 'output to syslog')
gflags.DEFINE_string('log_dir', None, 'log file directory')
gflags.DEFINE_string('log_file', None, 'log file name')
gflags.DEFINE_string('log_file_mode', '0644', 'default log file permission')


_EARLY_LOG_HANDLER = None


def early_init_log(level=None):
    global _EARLY_LOG_HANDLER
    _EARLY_LOG_HANDLER = logging.StreamHandler(sys.stderr)

    log = logging.getLogger()
    log.addHandler(_EARLY_LOG_HANDLER)
    if level is not None:
        log.setLevel(level)


def _get_log_file():
    if FLAGS.log_file:
        return FLAGS.log_file
    if FLAGS.log_dir:
        return os.path.join(FLAGS.logdir,
                            os.path.basename(inspect.stack()[-1][1])) + '.log'
    return None


def init_log():
    global _EARLY_LOG_HANDLER

    log = logging.getLogger()
    if FLAGS.use_stderr:
        log.addHandler(logging.StreamHandler(sys.stderr))
    if _EARLY_LOG_HANDLER is not None:
        log.removeHandler(_EARLY_LOG_HANDLER)
        _EARLY_LOG_HANDLER = None

    if FLAGS.use_syslog:
        syslog = logging.handlers.SysLogHandler(address='/dev/log')
        log.addHandler(syslog)

    log_file = _get_log_file()
    if log_file is not None:
        logging.addHandler(logging.handlers.WatchedFileHandler(log_file))
        mode = int(FLAGS.log_file_mnode, 8)
        os.chmod(log_file, mode)

    if FLAGS.verbose:
        log.setLevel(logging.DEBUG)
    elif FLAGS.default_log_level is not None:
        log.setLevel(FLAGS.default_log_level)
    else:
        log.setLevel(logging.INFO)
