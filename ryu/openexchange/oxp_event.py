"""
This file define OXP Event.
Author:www.muzixing.com
"""

import inspect

from ryu.controller import handler
from ryu import openexchange
from ryu import utils
from . import event


class EventOXPMsgBase(event.EventBase):
    def __init__(self, msg):
        super(EventOXPMsgBase, self).__init__()
        self.msg = msg


#
# Create oxp_event type corresponding to OXP Msg
#

_OXP_MSG_EVENTS = {}


def _oxp_msg_name_to_ev_name(msg_name):
    return 'Event' + msg_name


def oxp_msg_to_ev(msg):
    return oxp_msg_to_ev_cls(msg.__class__)(msg)


def oxp_msg_to_ev_cls(msg_cls):
    name = _oxp_msg_name_to_ev_name(msg_cls.__name__)
    return _OXP_MSG_EVENTS[name]


def _create_oxp_msg_ev_class(msg_cls):
    name = _oxp_msg_name_to_ev_name(msg_cls.__name__)
    # print 'creating oxp_event %s' % name

    if name in _OXP_MSG_EVENTS:
        return

    cls = type(name, (EventOXPMsgBase,),
               dict(__init__=lambda self, msg:
                    super(self.__class__, self).__init__(msg)))
    globals()[name] = cls
    _OXP_MSG_EVENTS[name] = cls


def _create_oxp_msg_ev_from_module(oxp_parser):
    # print mod
    for _k, cls in inspect.getmembers(oxp_parser, inspect.isclass):
        if not hasattr(cls, 'cls_msg_type'):
            continue
        _create_oxp_msg_ev_class(cls)


for oxp_mods in openexchange.get_oxp_modules().values():
    oxp_parser = oxp_mods[1]
    print 'loading module %s' % oxp_parser
    _create_oxp_msg_ev_from_module(oxp_parser)


class EventOXPStateChange(event.EventBase):
    def __init__(self, domain):
        super(EventOXPStateChange, self).__init__()
        self.domain_network = domain

handler.register_service('ryu.openexchange.oxp_handler')
