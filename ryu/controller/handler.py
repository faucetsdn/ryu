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

import copy
import inspect
import logging

from ryu.controller import dispatcher
from ryu.controller import ofp_event

LOG = logging.getLogger('ryu.controller.handler')

QUEUE_NAME_OFP_MSG = 'ofp_msg'
DISPATCHER_NAME_OFP_HANDSHAKE = 'ofp_handshake'
HANDSHAKE_DISPATCHER = dispatcher.EventDispatcher(
    DISPATCHER_NAME_OFP_HANDSHAKE)
DISPATCHER_NAME_OFP_CONFIG = 'ofp_config'
CONFIG_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_OFP_CONFIG)
DISPATCHER_NAME_OFP_MAIN = 'ofp_main'
MAIN_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_OFP_MAIN)
DISPATCHER_NAME_OFP_DEAD = 'ofp_dead'
DEAD_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_OFP_DEAD)


def set_ev_cls(ev_cls, dispatchers):
    def _set_ev_cls_dec(handler):
        handler.ev_cls = ev_cls
        handler.dispatchers = dispatchers
        return handler
    return _set_ev_cls_dec


def _is_ev_handler(meth):
    return 'ev_cls' in meth.__dict__


def _listify(may_list):
    if may_list is None:
        may_list = []
    if not isinstance(may_list, list):
        may_list = [may_list]
    return may_list


def register_instance(i):
    for _k, m in inspect.getmembers(i, inspect.ismethod):
        # LOG.debug('instance %s k %s m %s', i, _k, m)
        if not _is_ev_handler(m):
            continue

        _dispatchers = _listify(getattr(m, 'dispatchers', None))
        # LOG.debug("_dispatchers %s", _dispatchers)
        for d in _dispatchers:
            # LOG.debug('register dispatcher %s ev %s k %s m %s',
            #           d.name, m.ev_cls, _k, m)
            d.register_handler(m.ev_cls, m)
