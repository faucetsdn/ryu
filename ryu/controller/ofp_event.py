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

"""
OpenFlow event definitions.
"""

import inspect
import time

from ryu.controller import handler
from ryu import ofproto
from . import event


NAME = 'ofp_event'


class EventOFPMsgBase(event.EventBase):
    """
    The base class of OpenFlow event class.

    OpenFlow event classes have at least the following attributes.

    .. tabularcolumns:: |l|L|

    ============ ==============================================================
    Attribute    Description
    ============ ==============================================================
    msg          An object which describes the corresponding OpenFlow message.
    msg.datapath A ryu.controller.controller.Datapath instance
                 which describes an OpenFlow switch from which we received
                 this OpenFlow message.
    timestamp    Timestamp when Datapath instance generated this event.
    ============ ==============================================================

    The msg object has some more additional members whose values are extracted
    from the original OpenFlow message.
    """

    def __init__(self, msg):
        self.timestamp = time.time()
        super(EventOFPMsgBase, self).__init__()
        self.msg = msg


#
# Create ofp_event type corresponding to OFP Msg
#

_OFP_MSG_EVENTS = {}


def _ofp_msg_name_to_ev_name(msg_name):
    return 'Event' + msg_name


def ofp_msg_to_ev(msg):
    return ofp_msg_to_ev_cls(msg.__class__)(msg)


def ofp_msg_to_ev_cls(msg_cls):
    name = _ofp_msg_name_to_ev_name(msg_cls.__name__)
    return _OFP_MSG_EVENTS[name]


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


def _create_ofp_msg_ev_from_module(ofp_parser):
    # print mod
    for _k, cls in inspect.getmembers(ofp_parser, inspect.isclass):
        if not hasattr(cls, 'cls_msg_type'):
            continue
        _create_ofp_msg_ev_class(cls)


for ofp_mods in ofproto.get_ofp_modules().values():
    ofp_parser = ofp_mods[1]
    # print 'loading module %s' % ofp_parser
    _create_ofp_msg_ev_from_module(ofp_parser)


class EventOFPStateChange(event.EventBase):
    """
    An event class for negotiation phase change notification.

    An instance of this class is sent to observer after changing
    the negotiation phase.
    An instance has at least the following attributes.

    ========= =================================================================
    Attribute Description
    ========= =================================================================
    datapath  ryu.controller.controller.Datapath instance of the switch
    ========= =================================================================
    """

    def __init__(self, dp):
        super(EventOFPStateChange, self).__init__()
        self.datapath = dp


class EventOFPPortStateChange(event.EventBase):
    """
    An event class to notify the port state changes of Dtatapath instance.

    This event performs like EventOFPPortStatus, but Ryu will
    send this event after updating ``ports`` dict of Datapath instances.
    An instance has at least the following attributes.

    ========= =================================================================
    Attribute Description
    ========= =================================================================
    datapath  ryu.controller.controller.Datapath instance of the switch
    reason    one of OFPPR_*
    port_no   Port number which state was changed
    ========= =================================================================
    """

    def __init__(self, dp, reason, port_no):
        super(EventOFPPortStateChange, self).__init__()
        self.datapath = dp
        self.reason = reason
        self.port_no = port_no


handler.register_service('ryu.controller.ofp_handler')
