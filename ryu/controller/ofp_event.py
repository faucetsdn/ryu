# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

import inspect

from ryu import utils
from . import event


class EventOFPMsgBase(event.EventBase):
    def __init__(self, msg):
        super(EventOFPMsgBase, self).__init__()
        self.msg = msg


#
# Create ofp_event type corresponding to OFP Msg
#

_OFP_MSG_EVENTS = {}


def _ofp_msg_name_to_ev_name(msg_name):
    return 'Event' + msg_name


def ofp_msg_to_ev(msg):
    name = _ofp_msg_name_to_ev_name(msg.__class__.__name__)
    return _OFP_MSG_EVENTS[name](msg)


def _create_ofp_msg_ev_class(msg_cls):
    name = _ofp_msg_name_to_ev_name(msg_cls.__name__)
    # print 'creating ofp_event %s' % name

    if name in _OFP_MSG_EVENTS:
        return

    cls = type(name, (EventOFPMsgBase,),
               dict(__init__=lambda self, msg:
                    super(self.__class__, self).__init__(msg)))
    globals()[name] = cls
    _OFP_MSG_EVENTS[name] = cls


def _create_ofp_msg_ev_from_module(modname):
    mod = utils.import_module(modname)
    # print mod
    for _k, cls in inspect.getmembers(mod, inspect.isclass):
        if not hasattr(cls, 'cls_msg_type'):
            continue
        _create_ofp_msg_ev_class(cls)


# TODO:XXX
_PARSER_MODULE_LIST = ['ryu.ofproto.ofproto_v1_0_parser',
                       'ryu.ofproto.ofproto_v1_2_parser',
                       'ryu.ofproto.ofproto_v1_3_parser']

for m in _PARSER_MODULE_LIST:
    # print 'loading module %s' % m
    _create_ofp_msg_ev_from_module(m)


class EventOFPStateChange(event.EventBase):
    def __init__(self, dp):
        super(EventOFPStateChange, self).__init__()
        self.datapath = dp
