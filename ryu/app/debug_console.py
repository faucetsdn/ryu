# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# a RyuApp to provide a python interactive console for debugging

import code
import os
import select
import sys
import signal

from ryu.base import app_manager
from ryu.lib import hub


# builtin raw_input() is written by C and doesn't yeild execution.
def _raw_input(message):
    sys.stdout.write(message)
    select.select([sys.stdin.fileno()], [], [])
    return sys.stdin.readline()


class DebugConsole(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(DebugConsole, self).__init__(*args, **kwargs)
        hub.spawn(self.__thread)

    def __thread(self):
        code.interact(banner="Ryu Debug Console", readfunc=_raw_input)

        # XXX should be a graceful shutdown
        os.kill(os.getpid(), signal.SIGTERM)
