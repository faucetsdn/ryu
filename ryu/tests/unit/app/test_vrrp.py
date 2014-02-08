# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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


import unittest

from nose.tools import eq_
from nose.tools import raises

from ryu.lib import hub
from ryu.lib import rpc
from ryu.services.protocols.vrrp.rpc_manager import RpcVRRPManager, Peer
from ryu.services.protocols.vrrp import event as vrrp_event


class DummyEndpoint(object):
    def __init__(self):
        self.response = []
        self.notification = []

    def send_response(self, msgid, error, result):
        self.response.append((msgid, error, result))

    def send_notification(self, method, params):
        self.notification.append((method, params))


class TestVRRP(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_rpc_request(self):
        rm = RpcVRRPManager()
        sent_events = []
        rm.send_event = lambda name, ev: sent_events.append((name, ev))
        peer = Peer(queue=rm._rpc_events)
        peer._endpoint = DummyEndpoint()
        rm._peers.append(peer)

        msgid = 10
        params = {}
        with hub.Timeout(2):
            peer._handle_vrrp_request((msgid, 'vrrp_list', [params]))
            hub.sleep(0.1)

        eq_(len(sent_events), 1)
        req = sent_events.pop()[1]
        eq_(req.__class__, vrrp_event.EventVRRPListRequest)

        req.reply_q.put(vrrp_event.EventVRRPListReply([]))
        hub.sleep(0.1)
        (msgid_, error, result) = peer._endpoint.response.pop()
        eq_(error, None)
        eq_(result, [])

        params = {'vrid': 1}
        with hub.Timeout(2):
            peer._handle_vrrp_request((msgid, 'vrrp_config', [params]))
            hub.sleep(0.1)

        msgid_, error, result = peer._endpoint.response.pop()
        eq_(result, None)

        params = {'version': 3,
                  'vrid': 1,
                  'ip_addr': '192.168.1.1',
                  'contexts': {'resource_id': 'XXX',
                               'resource_name': 'vrrp_session'},
                  'statistics_log_enabled': True,
                  'statistics_interval': 10,
                  'priority': 100,
                  'ifname': 'veth0',
                  'vlan_id': None,
                  'ip_address': '192.168.1.2',
                  'advertisement_interval': 10,
                  'preempt_mode': True,
                  'preempt_delay': 10,
                  'admin_state_up': True
                  }
        with hub.Timeout(2):
            peer._handle_vrrp_request((msgid, 'vrrp_config', [params]))
            hub.sleep(0.1)

        eq_(len(sent_events), 1)
        req = sent_events.pop()[1]
        eq_(req.__class__, vrrp_event.EventVRRPConfigRequest)
        req.reply_q.put(vrrp_event.EventVRRPConfigReply('hoge',
                                                        req.interface,
                                                        req.config))
        hub.sleep(0.1)
        (msgid_, error, result) = peer._endpoint.response.pop()
        eq_(error, None)
