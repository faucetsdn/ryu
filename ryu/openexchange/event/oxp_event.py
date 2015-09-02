"""
This file define OXP Event.
Author:www.muzixing.com
"""

import inspect

from ryu.controller import handler
from ryu import openexchange
from ryu.openexchange import oxproto_v1_0
from ryu import ofproto
from ryu import utils
from . import event
from ryu import cfg

CONF = cfg.CONF


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
    if name in _OXP_MSG_EVENTS:
        return

    cls = type(name, (EventOXPMsgBase,),
               dict(__init__=lambda self, msg:
                    super(self.__class__, self).__init__(msg)))
    globals()[name] = cls
    _OXP_MSG_EVENTS[name] = cls


def _create_oxp_msg_ev_from_module(oxp_parser):
    for _k, cls in inspect.getmembers(oxp_parser, inspect.isclass):
        if not hasattr(cls, 'cls_msg_type'):
            continue
        _create_oxp_msg_ev_class(cls)


for oxp_mods in openexchange.get_oxp_modules().values():
    oxp_parser = oxp_mods[1]
    _create_oxp_msg_ev_from_module(oxp_parser)

#
# Create ofp_to_oxp_event type corresponding to OFP Msg in SBP.
#


def _sbp_to_oxp_msg_name_to_ev_name(msg_name):
    if CONF.sbp_proto_type == oxproto_v1_0.OXPS_OPENFLOW:
        msg_name = msg_name[len("OFP"):]
        return 'EventOXPSBP' + msg_name


def sbp_to_oxp_msg_to_ev(msg):
    return sbp_to_oxp_msg_to_ev_cls(msg.__class__)(msg)


def sbp_to_oxp_msg_to_ev_cls(msg_cls):
    name = _sbp_to_oxp_msg_name_to_ev_name(msg_cls.__name__)
    return _OXP_MSG_EVENTS[name]


def _create_sbp_to_oxp_msg_ev_class(msg_cls):
    name = _sbp_to_oxp_msg_name_to_ev_name(msg_cls.__name__)
    if name in _OXP_MSG_EVENTS:
        return

    cls = type(name, (EventOXPMsgBase,),
               dict(__init__=lambda self, msg:
                    super(self.__class__, self).__init__(msg)))
    globals()[name] = cls
    _OXP_MSG_EVENTS[name] = cls


def _create_sbp_to_oxp_msg_ev_from_module(parser):
    for _k, cls in inspect.getmembers(parser, inspect.isclass):
        if not hasattr(cls, 'cls_msg_type'):
            continue
        _create_sbp_to_oxp_msg_ev_class(cls)

if CONF.sbp_proto_type == oxproto_v1_0.OXPS_OPENFLOW:
    for ofp_mods in ofproto.get_ofp_modules().values():
        ofp_parser = ofp_mods[1]
        _create_sbp_to_oxp_msg_ev_from_module(ofp_parser)


class EventOXPStateChange(event.EventBase):
    def __init__(self, domain):
        super(EventOXPStateChange, self).__init__()
        self.domain = domain


class EventOXPVportStateChange(event.EventBase):
    def __init__(self, domain, vport_no, state):
        super(EventOXPVportStateChange, self).__init__()
        self.domain = domain
        self.vport_no = vport_no
        self.state = state


class EventOXPHostStateChange(event.EventBase):
    def __init__(self, domain, hosts):
        super(EventOXPHostStateChange, self).__init__()
        self.domain = domain
        self.hosts = hosts


if CONF.oxp_role == 'super':
    handler.register_service('ryu.openexchange.super.oxp_server_handler')
elif CONF.oxp_role == 'domain':
    handler.register_service('ryu.openexchange.domain.oxp_client_handler')
else:
    pass
