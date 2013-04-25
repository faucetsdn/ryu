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
import time

from ryu.base import app_manager
from ryu.controller import handler
from ryu.lib import hub
from ryu.topology import event
from ryu.topology import switches

LOG = logging.getLogger(__name__)


class DiscoveryEventDumper(app_manager.RyuApp):
    ''' This app dumps discovery events
    '''
    _CONTEXTS = {
        'switches': switches.Switches,
    }

    def __init__(self, *args, **kwargs):
        super(DiscoveryEventDumper, self).__init__(*args, **kwargs)

        # For testing when sync and async request.
#        self.threads.append(
#            hub.spawn(self._switch_request_sync, 5))
#        self.threads.append(
#            hub.spawn(self._switch_request_async, 10))
#
#        self.threads.append(
#            hub.spawn(self._link_request_sync, 5))
#        self.threads.append(
#            hub.spawn(self._link_request_async, 10))

        self.is_active = True

    @handler.set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        LOG.debug(ev)

    @handler.set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        LOG.debug(ev)

    @handler.set_ev_cls(event.EventPortAdd)
    def port_add_handler(self, ev):
        LOG.debug(ev)

    @handler.set_ev_cls(event.EventPortDelete)
    def port_delete_handler(self, ev):
        LOG.debug(ev)

    @handler.set_ev_cls(event.EventPortModify)
    def port_modify_handler(self, ev):
        LOG.debug(ev)

    @handler.set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        LOG.debug(ev)

    @handler.set_ev_cls(event.EventLinkDelete)
    def link_del_handler(self, ev):
        LOG.debug(ev)

    def _switch_request_sync(self, interval):
        while self.is_active:
            request = event.EventSwitchRequest()
            LOG.debug('switch_request sync %s thread(%s)',
                      request, id(hub.getcurrent()))
            reply = self.send_request(request)
            LOG.debug('switch_reply sync %s', reply)
            if len(reply.switches) > 0:
                for sw in reply.switches:
                    LOG.debug('  %s', sw)
            hub.sleep(interval)

    def _switch_request_async(self, interval):
        while self.is_active:
            request = event.EventSwitchRequest()
            LOG.debug('switch_request async %s thread(%s)',
                      request, id(hub.getcurrent()))
            self.send_event(request.dst, request)

            start = time.time()
            busy = interval / 2
            i = 0
            while i < busy:
                if time.time() > start + i:
                    i += 1
                    LOG.debug('  thread is busy... %s/%s thread(%s)',
                              i, busy, id(hub.getcurrent()))
            LOG.debug('  thread yield to switch_reply handler. thread(%s)',
                      id(hub.getcurrent()))

            # yield
            hub.sleep(0)

            LOG.debug('  thread get back. thread(%s)',
                      id(hub.getcurrent()))
            hub.sleep(interval - busy)

    @handler.set_ev_cls(event.EventSwitchReply)
    def switch_reply_handler(self, reply):
        LOG.debug('switch_reply async %s', reply)
        if len(reply.switches) > 0:
            for sw in reply.switches:
                LOG.debug('  %s', sw)

    def _link_request_sync(self, interval):
        while self.is_active:
            request = event.EventLinkRequest()
            LOG.debug('link_request sync %s thread(%s)',
                      request, id(hub.getcurrent()))
            reply = self.send_request(request)
            LOG.debug('link_reply sync %s', reply)
            if len(reply.links) > 0:
                for link in reply.links:
                    LOG.debug('  %s', link)
            hub.sleep(interval)

    def _link_request_async(self, interval):
        while self.is_active:
            request = event.EventLinkRequest()
            LOG.debug('link_request async %s thread(%s)',
                      request, id(hub.getcurrent()))
            self.send_event(request.dst, request)

            start = time.time()
            busy = interval / 2
            i = 0
            while i < busy:
                if time.time() > start + i:
                    i += 1
                    LOG.debug('  thread is busy... %s/%s thread(%s)',
                              i, busy, id(hub.getcurrent()))
            LOG.debug('  thread yield to link_reply handler. thread(%s)',
                      id(hub.getcurrent()))

            # yield
            hub.sleep(0)

            LOG.debug('  thread get back. thread(%s)',
                      id(hub.getcurrent()))
            hub.sleep(interval - busy)

    @handler.set_ev_cls(event.EventLinkReply)
    def link_reply_handler(self, reply):
        LOG.debug('link_reply async %s', reply)
        if len(reply.links) > 0:
            for link in reply.links:
                LOG.debug('  %s', link)
