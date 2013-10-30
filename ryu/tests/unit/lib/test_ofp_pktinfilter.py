# Copyright (C) 2013 Stratosphere Inc.
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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging

from nose.tools import *

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    set_ev_cls,
    MAIN_DISPATCHER,
)
from ryu.lib.packet import vlan, ethernet, ipv4
from ryu.lib.ofp_pktinfilter import packet_in_filter, RequiredTypeFilter
from ryu.lib import mac
from ryu.ofproto import ether, ofproto_v1_3, ofproto_v1_3_parser


LOG = logging.getLogger('test_pktinfilter')


class _Datapath(object):
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser


class _PacketInFilterApp(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(_PacketInFilterApp, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @packet_in_filter(RequiredTypeFilter, {'types': [
        vlan.vlan,
    ]})
    def packet_in_handler(self, ev):
        return True


class Test_packet_in_filter(unittest.TestCase):

    """ Test case for pktinfilter
    """

    def setUp(self):
        self.app = _PacketInFilterApp()

    def tearDown(self):
        pass

    def test_pkt_in_filter_pass(self):
        datapath = _Datapath()
        e = ethernet.ethernet(mac.BROADCAST_STR,
                              mac.BROADCAST_STR,
                              ether.ETH_TYPE_8021Q)
        v = vlan.vlan()
        i = ipv4.ipv4()
        pkt = (e / v / i)
        pkt.serialize()
        pkt_in = ofproto_v1_3_parser.OFPPacketIn(datapath,
                                                 data=buffer(pkt.data))
        ev = ofp_event.EventOFPPacketIn(pkt_in)
        ok_(self.app.packet_in_handler(ev))

    def test_pkt_in_filter_discard(self):
        datapath = _Datapath()
        e = ethernet.ethernet(mac.BROADCAST_STR,
                              mac.BROADCAST_STR,
                              ether.ETH_TYPE_IP)
        i = ipv4.ipv4()
        pkt = (e / i)
        pkt.serialize()
        pkt_in = ofproto_v1_3_parser.OFPPacketIn(datapath,
                                                 data=buffer(pkt.data))
        ev = ofp_event.EventOFPPacketIn(pkt_in)
        ok_(not self.app.packet_in_handler(ev))

    def test_pkt_in_filter_truncated(self):
        datapath = _Datapath()
        truncated_data = buffer('')
        pkt_in = ofproto_v1_3_parser.OFPPacketIn(datapath,
                                                 data=truncated_data)
        ev = ofp_event.EventOFPPacketIn(pkt_in)
        ok_(not self.app.packet_in_handler(ev))
