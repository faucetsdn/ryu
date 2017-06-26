# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

import sys
import logging
import itertools

from ryu import utils
from ryu.lib import mac
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2


LOG = logging.getLogger(__name__)


LOG_TEST_START = 'TEST_START: %s'
LOG_TEST_RESULTS = 'TEST_RESULTS:'
LOG_TEST_FINISH = 'TEST_FINISHED: Completed=[%s] (OK=%s NG=%s SKIP=%s)'
LOG_TEST_UNSUPPORTED = 'SKIP (unsupported)'


class TestFlowBase(app_manager.RyuApp):
    """
    To run the tests is required for the following pair of functions.
        1. test_<test name>()
            To send flows to switch.

        2. verify_<test name>() or _verify_default()
            To check flows of switch.
    """

    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(TestFlowBase, self).__init__(*args, **kwargs)
        self.pending = []
        self.results = {}
        self.current = None
        self.unclear = 0

        for t in dir(self):
            if t.startswith("test_"):
                self.pending.append(t)
        self.pending.sort(reverse=True)
        self.unclear = len(self.pending)

    def delete_all_flows(self, dp):
        if dp.ofproto == ofproto_v1_0:
            match = dp.ofproto_parser.OFPMatch(dp.ofproto.OFPFW_ALL,
                                               0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0)
            m = dp.ofproto_parser.OFPFlowMod(dp, match, 0,
                                             dp.ofproto.OFPFC_DELETE,
                                             0, 0, 0, 0,
                                             dp.ofproto.OFPP_NONE, 0, None)
        elif dp.ofproto == ofproto_v1_2:
            match = dp.ofproto_parser.OFPMatch()
            m = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, dp.ofproto.OFPTT_ALL,
                                             dp.ofproto.OFPFC_DELETE,
                                             0, 0, 0, 0xffffffff,
                                             dp.ofproto.OFPP_ANY,
                                             dp.ofproto.OFPG_ANY,
                                             0, match, [])

        dp.send_msg(m)

    def send_flow_stats(self, dp):
        if dp.ofproto == ofproto_v1_0:
            match = dp.ofproto_parser.OFPMatch(dp.ofproto.OFPFW_ALL,
                                               0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0)
            m = dp.ofproto_parser.OFPFlowStatsRequest(dp, 0, match,
                                                      0, dp.ofproto.OFPP_NONE)
        elif dp.ofproto == ofproto_v1_2:
            match = dp.ofproto_parser.OFPMatch()
            m = dp.ofproto_parser.OFPFlowStatsRequest(dp, dp.ofproto.OFPTT_ALL,
                                                      dp.ofproto.OFPP_ANY,
                                                      dp.ofproto.OFPG_ANY,
                                                      0, 0, match)

        dp.send_msg(m)

    def verify_default(self, dp, stats):
        return 'function %s() is not found.' % ("verify" + self.current[4:], )

    def start_next_test(self, dp):
        self.delete_all_flows(dp)
        dp.send_barrier()
        if len(self.pending):
            t = self.pending.pop()
            if self.is_supported(t):
                LOG.info(LOG_TEST_START, t)
                self.current = t
                getattr(self, t)(dp)
                dp.send_barrier()
                self.send_flow_stats(dp)
            else:
                self.results[t] = LOG_TEST_UNSUPPORTED
                self.unclear -= 1
                self.start_next_test(dp)
        else:
            self.print_results()

    def print_results(self):
        LOG.info("TEST_RESULTS:")
        ok = 0
        ng = 0
        skip = 0
        for t in sorted(self.results.keys()):
            if self.results[t] is True:
                ok += 1
            elif self.results[t] == LOG_TEST_UNSUPPORTED:
                skip += 1
            else:
                ng += 1
            LOG.info("    %s: %s", t, self.results[t])
        LOG.info(LOG_TEST_FINISH, self.unclear == 0, ok, ng, skip)

    @handler.set_ev_cls(ofp_event.EventOFPFlowStatsReply,
                        handler.MAIN_DISPATCHER)
    def flow_reply_handler(self, ev):
        self.run_verify(ev)

    @handler.set_ev_cls(ofp_event.EventOFPStatsReply,
                        handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        self.run_verify(ev)

    def run_verify(self, ev):
        msg = ev.msg
        dp = msg.datapath

        verify_func = self.verify_default
        v = "verify" + self.current[4:]
        if hasattr(self, v):
            verify_func = getattr(self, v)

        result = verify_func(dp, msg.body)
        if result is True:
            self.unclear -= 1

        self.results[self.current] = result
        self.start_next_test(dp)

    @handler.set_ev_cls(dpset.EventDP)
    def handler_datapath(self, ev):
        if ev.enter:
            self.start_next_test(ev.dp)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_replay_handler(self, ev):
        pass

    def haddr_to_str(self, addr):
        return mac.haddr_to_str(addr)

    def haddr_to_bin(self, string):
        return mac.haddr_to_bin(string)

    def haddr_masked(self, haddr_bin, mask_bin):
        return mac.haddr_bitand(haddr_bin, mask_bin)

    def ipv4_to_str(self, integre):
        ip_list = [str((integre >> (24 - (n * 8)) & 255)) for n in range(4)]
        return '.'.join(ip_list)

    def ipv4_to_int(self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = (i << 8) | b
        return i

    def ipv4_masked(self, ip_int, mask_int):
        return ip_int & mask_int

    def ipv6_to_str(self, integres):
        return ':'.join(hex(x)[2:] for x in integres)

    def ipv6_to_int(self, string):
        ip = string.split(':')
        assert len(ip) == 8
        return [int(x, 16) for x in ip]

    def ipv6_masked(self, ipv6_int, mask_int):
        return [x & y for (x, y) in
                itertools.izip(ipv6_int, mask_int)]

    def is_supported(self, t):
        return True
