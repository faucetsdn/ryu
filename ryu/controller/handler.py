# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

import inspect
import logging

from ryu.controller import ofp_event

LOG = logging.getLogger('ryu.controller.handler')

# just represent OF datapath state. datapath specific so should be moved.
HANDSHAKE_DISPATCHER = "handshake"
CONFIG_DISPATCHER = "config"
MAIN_DISPATCHER = "main"
DEAD_DISPATCHER = "dead"


# should be named something like 'observe_event'
def set_ev_cls(ev_cls, dispatchers=None):
    def _set_ev_cls_dec(handler):
        handler.ev_cls = ev_cls
        handler.dispatchers = _listify(dispatchers)
        handler.observer = ev_cls.__module__
        return handler
    return _set_ev_cls_dec


def set_ev_handler(ev_cls, dispatchers=None):
    def _set_ev_cls_dec(handler):
        handler.ev_cls = ev_cls
        handler.dispatchers = _listify(dispatchers)
        return handler
    return _set_ev_cls_dec


def _is_ev_cls(meth):
    return hasattr(meth, 'ev_cls')


def _listify(may_list):
    if may_list is None:
        may_list = []
    if not isinstance(may_list, list):
        may_list = [may_list]
    return may_list


def register_instance(i):
    for _k, m in inspect.getmembers(i, inspect.ismethod):
        # LOG.debug('instance %s k %s m %s', i, _k, m)
        if _is_ev_cls(m):
            i.register_handler(m.ev_cls, m)
