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
    (f, _s, _t) = modname.rpartition('.')
    mod = __import__(modname, fromlist=[f])
    print mod
    for _k, cls in mod.__dict__.items():
        if not inspect.isclass(cls):
            continue
        if 'cls_msg_type' not in cls.__dict__:
            continue
        _create_ofp_msg_ev_class(cls)


# TODO:XXX
_PARSER_MODULE_LIST = ['ryu.ofproto.ofproto_v1_0_parser']

for m in _PARSER_MODULE_LIST:
    # print 'loading module %s' % m
    _create_ofp_msg_ev_from_module(m)
