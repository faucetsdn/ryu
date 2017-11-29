# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import logging
from ryu.controller import handler
from ryu.controller import event

LOG = logging.getLogger(__name__)


class EventSwitchBase(event.EventBase):
    def __init__(self, switch):
        super(EventSwitchBase, self).__init__()
        self.switch = switch

    def __str__(self):
        return '%s<dpid=%s, %s ports>' % \
            (self.__class__.__name__,
             self.switch.dp.id, len(self.switch.ports))


class EventSwitchEnter(EventSwitchBase):
    def __init__(self, switch):
        super(EventSwitchEnter, self).__init__(switch)


class EventSwitchLeave(EventSwitchBase):
    def __init__(self, switch):
        super(EventSwitchLeave, self).__init__(switch)


class EventSwitchReconnected(EventSwitchBase):
    def __init__(self, switch):
        super(EventSwitchReconnected, self).__init__(switch)


class EventPortBase(event.EventBase):
    def __init__(self, port):
        super(EventPortBase, self).__init__()
        self.port = port

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.port)


class EventPortAdd(EventPortBase):
    def __init__(self, port):
        super(EventPortAdd, self).__init__(port)


class EventPortDelete(EventPortBase):
    def __init__(self, port):
        super(EventPortDelete, self).__init__(port)


class EventPortModify(EventPortBase):
    def __init__(self, port):
        super(EventPortModify, self).__init__(port)


class EventSwitchRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventSwitchRequest, self).__init__()
        self.dst = 'switches'
        self.dpid = dpid

    def __str__(self):
        return 'EventSwitchRequest<src=%s, dpid=%s>' % \
            (self.src, self.dpid)


class EventSwitchReply(event.EventReplyBase):
    def __init__(self, dst, switches):
        super(EventSwitchReply, self).__init__(dst)
        self.switches = switches

    def __str__(self):
        return 'EventSwitchReply<dst=%s, %s>' % \
            (self.dst, self.switches)


class EventLinkBase(event.EventBase):
    def __init__(self, link):
        super(EventLinkBase, self).__init__()
        self.link = link

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.link)


class EventLinkAdd(EventLinkBase):
    def __init__(self, link):
        super(EventLinkAdd, self).__init__(link)


class EventLinkDelete(EventLinkBase):
    def __init__(self, link):
        super(EventLinkDelete, self).__init__(link)


class EventLinkRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventLinkRequest, self).__init__()
        self.dst = 'switches'
        self.dpid = dpid

    def __str__(self):
        return 'EventLinkRequest<src=%s, dpid=%s>' % \
            (self.src, self.dpid)


class EventLinkReply(event.EventReplyBase):
    def __init__(self, dst, dpid, links):
        super(EventLinkReply, self).__init__(dst)
        self.dpid = dpid
        self.links = links

    def __str__(self):
        return 'EventLinkReply<dst=%s, dpid=%s, links=%s>' % \
            (self.dst, self.dpid, len(self.links))


class EventHostRequest(event.EventRequestBase):
    # if dpid is None, replay all hosts
    def __init__(self, dpid=None):
        super(EventHostRequest, self).__init__()
        self.dst = 'switches'
        self.dpid = dpid

    def __str__(self):
        return 'EventHostRequest<src=%s, dpid=%s>' % \
            (self.src, self.dpid)


class EventHostReply(event.EventReplyBase):
    def __init__(self, dst, dpid, hosts):
        super(EventHostReply, self).__init__(dst)
        self.dpid = dpid
        self.hosts = hosts

    def __str__(self):
        return 'EventHostReply<dst=%s, dpid=%s, hosts=%s>' % \
            (self.dst, self.dpid, len(self.hosts))


class EventHostBase(event.EventBase):
    def __init__(self, host):
        super(EventHostBase, self).__init__()
        self.host = host

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.host)


class EventHostAdd(EventHostBase):
    def __init__(self, host):
        super(EventHostAdd, self).__init__(host)


# Note: Currently, EventHostDelete will never be raised, because we have no
# appropriate way to detect the disconnection of hosts. Just defined for
# future use.
class EventHostDelete(EventHostBase):
    def __init__(self, host):
        super(EventHostDelete, self).__init__(host)


class EventHostMove(event.EventBase):
    def __init__(self, src, dst):
        super(EventHostMove, self).__init__()
        self.src = src
        self.dst = dst

    def __str__(self):
        return '%s<src=%s, dst=%s>' % (
            self.__class__.__name__, self.src, self.dst)


handler.register_service('ryu.topology.switches')
