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
