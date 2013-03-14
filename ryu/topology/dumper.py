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
import gevent
import gevent.queue
import time

from ryu.base import app_manager
from ryu.controller.handler import set_ev_handler
from ryu.topology import switches, event

LOG = logging.getLogger(__name__)


class DiscoveryEventDumper(app_manager.RyuApp):
    ''' This app dumps discovery events
    '''

    def __init__(self):
        super(DiscoveryEventDumper, self).__init__()

        # For testing when sync and async request.
#        self.threads.append(gevent.spawn_later(0, self._request_sync, 5))
        self.threads.append(gevent.spawn_later(0, self._request_async, 10))

        self.is_active = True

    @set_ev_handler(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        LOG.debug(ev)

    @set_ev_handler(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        LOG.debug(ev)

    @set_ev_handler(event.EventPortAdd)
    def port_add_handler(self, ev):
        LOG.debug(ev)

    @set_ev_handler(event.EventPortDelete)
    def port_delete_handler(self, ev):
        LOG.debug(ev)

    @set_ev_handler(event.EventPortModify)
    def port_modify_handler(self, ev):
        LOG.debug(ev)

    def _request_sync(self, interval):
        while self.is_active:
            request = event.EventSwitchRequest()
            LOG.debug('request sync %s thread(%s)',
                      request, id(gevent.getcurrent()))
            reply = self.send_request(request)
            LOG.debug('reply sync %s', reply)
            if len(reply.switches) > 0:
                for sw in reply.switches:
                    LOG.debug('  %s', sw)
            gevent.sleep(interval)

    def _request_async(self, interval):
        while self.is_active:
            request = event.EventSwitchRequest()
            LOG.debug('request async %s thread(%s)',
                      request, id(gevent.getcurrent()))
            self.send_event(request.dst, request)

            start = time.time()
            busy = interval / 2
            i = 0
            while i < busy:
                if time.time() > start + i:
                    i += 1
                    LOG.debug('  thread is busy... %s/%s thread(%s)',
                              i, busy, id(gevent.getcurrent()))
            LOG.debug('  thread yield to reply handler. thread(%s)',
                      id(gevent.getcurrent()))

            # yield
            gevent.sleep(0)

            LOG.debug('  thread get back. thread(%s)',
                      id(gevent.getcurrent()))
            gevent.sleep(interval - busy)

    @set_ev_handler(event.EventSwitchReply)
    def switch_reply_handler(self, reply):
        LOG.debug('reply async %s', reply)
        if len(reply.switches) > 0:
            for sw in reply.switches:
                LOG.debug('  %s', sw)
