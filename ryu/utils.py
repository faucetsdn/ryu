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

import inspect
import logging
import os
import sys

LOG = logging.getLogger('ryu.utils')


def import_module(modname):
    (f, s, t) = modname.rpartition('.')
    mod = __import__(modname, fromlist=[f])
    return mod


def import_object(modname):
    try:
        return import_module(modname)
    except ImportError:
        (from_mod, sep, target) = modname.rpartition('.')
        mod = import_module(from_mod)
        return getattr(mod, target)


RYU_DEFAULT_FLAG_FILE = ('ryu.conf', 'etc/ryu/ryu.conf' '/etc/ryu/ryu.conf')


def find_flagfile(default_path=RYU_DEFAULT_FLAG_FILE):
    if '--flagfile' in sys.argv:
        return

    script_dir = os.path.dirname(inspect.stack()[-1][1])

    for filename in RYU_DEFAULT_FLAG_FILE:
        if not os.path.abspath(filename):
            if os.path.exists(filename):
                # try relative to current path
                filename = os.path.abspath(filename)
            elif os.path.exists(os.path.join(script_dir, filename)):
                # try relative to script dir
                filename = os.path.join(script_dir, filename)

        if not os.path.exists(filename):
            continue

        flagfile = '--flagfile=%s' % filename
        sys.argv.insert(1, flagfile)
        LOG.debug('flagfile = %s', filename)
        return
