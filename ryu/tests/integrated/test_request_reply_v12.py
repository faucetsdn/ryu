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

import time
import logging

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.tests.integrated import tester

LOG = logging.getLogger(__name__)


class RunTest(tester.TestFlowBase):
    """ Test case for Request-Reply messages.

        Some tests need attached port to switch.
        If use the OVS, can do it with the following commands.
            # ip link add <port> type dummy
            # ovs-vsctl add-port <bridge> <port>
    """

    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RunTest, self).__init__(*args, **kwargs)

        self._verify = None
        self.n_tables = ofproto_v1_2.OFPTT_MAX

    def start_next_test(self, dp):
        self._verify = None
        self.delete_all_flows(dp)
        dp.send_barrier()
        if len(self.pending):
            t = self.pending.pop()
            if self.is_supported(t):
                LOG.info(tester.LOG_TEST_START, t)
                self.current = t
                getattr(self, t)(dp)
            else:
                self.results[t] = 'SKIP (unsupported)'
                self.unclear -= 1
                self.start_next_test(dp)
        else:
            self.print_results()

    def run_verify(self, ev):
        msg = ev.msg
        dp = msg.datapath

        verify_func = self.verify_default
        v = "verify" + self.current[4:]
        if v in dir(self):
            verify_func = getattr(self, v)

        result = verify_func(dp, msg)
        if result is True:
            self.unclear -= 1

        self.results[self.current] = result
        self.start_next_test(dp)

    def verify_default(self, dp, msg):
        type_ = self._verify

        if msg.msg_type == dp.ofproto.OFPT_STATS_REPLY:
            return self.verify_stats(dp, msg.body, type_)
        elif msg.msg_type == type_:
            return True
        else:
            return 'Reply msg_type %s expected %s' \
                   % (msg.msg_type, type_)

    def verify_stats(self, dp, stats, type_):
        stats_types = dp.ofproto_parser.OFPStatsReply._STATS_TYPES
        expect = stats_types.get(type_).__name__

        if isinstance(stats, list):
            for s in stats:
                if expect == s.__class__.__name__:
                    return True
        else:
            if expect == stats.__class__.__name__:
                return True
        return 'Reply msg has not \'%s\' class.\n%s' % (expect, stats)

    def mod_flow(self, dp, cookie=0, cookie_mask=0, table_id=0,
                 command=None, idle_timeout=0, hard_timeout=0,
                 priority=0xff, buffer_id=0xffffffff, match=None,
                 actions=None, inst_type=None, out_port=None,
                 out_group=None, flags=0, inst=None):

        if command is None:
            command = dp.ofproto.OFPFC_ADD

        if inst is None:
            if inst_type is None:
                inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

            inst = []
            if actions is not None:
                inst = [dp.ofproto_parser.OFPInstructionActions(
                        inst_type, actions)]

        if match is None:
            match = dp.ofproto_parser.OFPMatch()

        if out_port is None:
            out_port = dp.ofproto.OFPP_ANY

        if out_group is None:
            out_group = dp.ofproto.OFPG_ANY

        m = dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                         table_id, command,
                                         idle_timeout, hard_timeout,
                                         priority, buffer_id,
                                         out_port, out_group,
                                         flags, match, inst)

        dp.send_msg(m)

    def get_port(self, dp):
        for port_no, port in dp.ports.items():
            if port_no != dp.ofproto.OFPP_LOCAL:
                return port
        return None

    # Test for Reply message type
    def test_desc_stats_request(self, dp):
        self._verify = dp.ofproto.OFPST_DESC
        m = dp.ofproto_parser.OFPDescStatsRequest(dp)
        dp.send_msg(m)

    def test_flow_stats_request(self, dp):
        self._verify = dp.ofproto.OFPST_FLOW
        self.mod_flow(dp)
        self.send_flow_stats(dp)

    def test_aggregate_stats_request(self, dp):
        self._verify = dp.ofproto.OFPST_AGGREGATE
        match = dp.ofproto_parser.OFPMatch()
        m = dp.ofproto_parser.OFPAggregateStatsRequest(
            dp, dp.ofproto.OFPTT_ALL, dp.ofproto.OFPP_ANY,
            dp.ofproto.OFPG_ANY, 0, 0, match)
        dp.send_msg(m)

    def test_table_stats_request(self, dp):
        self._verify = dp.ofproto.OFPST_TABLE
        m = dp.ofproto_parser.OFPTableStatsRequest(dp)
        dp.send_msg(m)

    def test_port_stats_request(self, dp):
        self._verify = dp.ofproto.OFPST_PORT
        m = dp.ofproto_parser.OFPPortStatsRequest(dp, dp.ofproto.OFPP_ANY)
        dp.send_msg(m)

    def test_echo_request(self, dp):
        self._verify = dp.ofproto.OFPT_ECHO_REPLY
        m = dp.ofproto_parser.OFPEchoRequest(dp)
        dp.send_msg(m)

    def test_features_request(self, dp):
        self._verify = dp.ofproto.OFPT_FEATURES_REPLY
        m = dp.ofproto_parser.OFPFeaturesRequest(dp)
        dp.send_msg(m)

    def test_get_config_request(self, dp):
        self._verify = dp.ofproto.OFPT_GET_CONFIG_REPLY
        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def test_barrier_request(self, dp):
        self._verify = dp.ofproto.OFPT_BARRIER_REPLY
        dp.send_barrier()

    def test_error_reply(self, dp):
        ports = [0]
        for p in dp.ports:
            if p != dp.ofproto.OFPP_LOCAL:
                ports.append(p)

        port_no = max(ports) + 1
        self._verify = dp.ofproto.OFPT_ERROR
        m = dp.ofproto_parser.OFPPortMod(
            dp, port_no, 'ff:ff:ff:ff:ff:ff', 0, 0, 0)
        dp.send_msg(m)

    # Test for reply value
    def test_flow_stats_none(self, dp):
        self.send_flow_stats(dp)

    def verify_flow_stats_none(self, dp, msg):
        stats = msg.body
        if len(stats):
            return 'Reply msg has body. %s' % (stats, )
        return True

    def test_flow_stats_reply_value(self, dp):
        self._verify = []
        c = 0
        while c < self.n_tables:
            # value = (talbe_id, cookie, idle_timeout, hard_timeout, priority)
            v = (c, c + 1, c + 2, c + 3, c + 4)
            self._verify.append(v)
            self.mod_flow(dp, table_id=v[0], cookie=v[1],
                          idle_timeout=v[2], hard_timeout=v[3], priority=v[4])
            c += 1
        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_stats_reply_value(self, dp, msg):
        c = 0
        for f in msg.body:
            f_value = (f.table_id, f.cookie, f.idle_timeout,
                       f.hard_timeout, f.priority, )
            if f_value != self._verify[c]:
                return 'param is mismatched. verify=%s, reply=%s' \
                       % (self._verify[c], f_value,)
            c += 1
        return len(msg.body) == self.n_tables

    def test_echo_request_has_data(self, dp):
        data = 'test'
        self._verify = data
        m = dp.ofproto_parser.OFPEchoRequest(dp)
        m.data = data
        dp.send_msg(m)

    def verify_echo_request_has_data(self, dp, msg):
        data = msg.data
        return self._verify == data

    def test_aggregate_stats_flow_count(self, dp):
        c = 0
        while c < self.n_tables:
            self.mod_flow(dp, table_id=c)
            c += 1
        dp.send_barrier()
        match = dp.ofproto_parser.OFPMatch()
        m = dp.ofproto_parser.OFPAggregateStatsRequest(
            dp, dp.ofproto.OFPTT_ALL, dp.ofproto.OFPP_ANY,
            dp.ofproto.OFPG_ANY, 0, 0, match)
        dp.send_msg(m)

    def verify_aggregate_stats_flow_count(self, dp, msg):
        stats = msg.body
        return stats.flow_count == self.n_tables

    def test_aggregate_stats_flow_count_out_port(self, dp):
        actions = [dp.ofproto_parser.OFPActionOutput(1, 1500)]
        self.mod_flow(dp, table_id=1, actions=actions)

        actions = [dp.ofproto_parser.OFPActionOutput(2, 1500)]
        self.mod_flow(dp, table_id=2, actions=actions)
        dp.send_barrier()

        out_port = 2
        match = dp.ofproto_parser.OFPMatch()
        m = dp.ofproto_parser.OFPAggregateStatsRequest(
            dp, dp.ofproto.OFPTT_ALL, out_port,
            dp.ofproto.OFPG_ANY, 0, 0, match)
        dp.send_msg(m)

    def verify_aggregate_stats_flow_count_out_port(self, dp, msg):
        stats = msg.body
        return stats.flow_count == 1

    def test_aggregate_stats_packet_count(self, dp):
        in_port = 1
        data = 'test'
        self._verify = {'packet_count': 1,
                        'byte_count': len(data)}

        # add flow
        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        self.mod_flow(dp, table_id=0, match=match)

        # packet out
        output = dp.ofproto.OFPP_TABLE
        actions = [dp.ofproto_parser.OFPActionOutput(output, 0)]
        m = dp.ofproto_parser.OFPPacketOut(dp, 0xffffffff, in_port,
                                           actions, data)
        dp.send_msg(m)
        dp.send_barrier()

        match = dp.ofproto_parser.OFPMatch()
        m = dp.ofproto_parser.OFPAggregateStatsRequest(
            dp, dp.ofproto.OFPTT_ALL, dp.ofproto.OFPP_ANY,
            dp.ofproto.OFPG_ANY, 0, 0, match)
        dp.send_msg(m)

    def verify_aggregate_stats_packet_count(self, dp, msg):
        for name, val in self._verify.items():
            r_val = getattr(msg.body, name)
            if val != r_val:
                return '%s is mismatched. verify=%s, reply=%s' \
                    % (name, val, r_val)
        return True

    def test_set_config_nomal(self, dp):
        flags = dp.ofproto.OFPC_FRAG_NORMAL
        self._verify = flags
        m = dp.ofproto_parser.OFPSetConfig(dp, flags, 0)
        dp.send_msg(m)
        dp.send_barrier()

        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def verify_set_config_nomal(self, dp, msg):
        return self._verify == msg.flags

    def test_set_config_drop(self, dp):
        flags = dp.ofproto.OFPC_FRAG_DROP
        self._verify = flags
        m = dp.ofproto_parser.OFPSetConfig(dp, flags, 0)
        dp.send_msg(m)
        dp.send_barrier()

        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def verify_set_config_drop(self, dp, msg):
        return self._verify == msg.flags

    def test_set_config_mask(self, dp):
        flags = dp.ofproto.OFPC_FRAG_MASK
        self._verify = flags
        m = dp.ofproto_parser.OFPSetConfig(dp, flags, 0)
        dp.send_msg(m)
        dp.send_barrier()

        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def verify_set_config_mask(self, dp, msg):
        return self._verify == msg.flags

    def test_set_config_ttl_to_controller(self, dp):
        flags = dp.ofproto.OFPC_INVALID_TTL_TO_CONTROLLER
        self._verify = flags
        m = dp.ofproto_parser.OFPSetConfig(dp, flags, 0)
        dp.send_msg(m)
        dp.send_barrier()

        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def verify_set_config_ttl_to_controller(self, dp, msg):
        return self._verify == msg.flags

    def test_set_config_miss_send_len(self, dp):
        flags = dp.ofproto.OFPC_FRAG_NORMAL
        ms_len = 256
        self._verify = ms_len
        m = dp.ofproto_parser.OFPSetConfig(dp, flags, ms_len)
        dp.send_msg(m)
        dp.send_barrier()

        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def verify_set_config_miss_send_len(self, dp, msg):
        return self._verify == msg.miss_send_len

    def test_set_config_miss_send_len_max(self, dp):
        flags = dp.ofproto.OFPC_FRAG_NORMAL
        ms_len = dp.ofproto.OFPCML_MAX
        self._verify = ms_len
        m = dp.ofproto_parser.OFPSetConfig(dp, flags, ms_len)
        dp.send_msg(m)
        dp.send_barrier()

        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def verify_set_config_miss_send_len_max(self, dp, msg):
        return self._verify == msg.miss_send_len

    def test_set_config_no_buffer(self, dp):
        flags = dp.ofproto.OFPC_FRAG_NORMAL
        ms_len = dp.ofproto.OFPCML_NO_BUFFER
        self._verify = ms_len
        m = dp.ofproto_parser.OFPSetConfig(dp, flags, ms_len)
        dp.send_msg(m)
        dp.send_barrier()

        m = dp.ofproto_parser.OFPGetConfigRequest(dp)
        dp.send_msg(m)

    def verify_set_config_no_buffer(self, dp, msg):
        return self._verify == msg.miss_send_len

    def _verify_flow_inst_type(self, dp, msg):
        inst_type = self._verify
        stats = msg.body

        for s in stats:
            for i in s.instructions:
                if i.type == inst_type:
                    return True
        return 'not found inst_type[%s]' % (inst_type, )

    def test_flow_add_apply_actions(self, dp):
        inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS
        self._verify = inst_type

        actions = [dp.ofproto_parser.OFPActionOutput(1, 1500)]
        self.mod_flow(dp, actions=actions, inst_type=inst_type)
        self.send_flow_stats(dp)

    def verify_flow_add_apply_actions(self, dp, msg):
        return self._verify_flow_inst_type(dp, msg)

    def test_flow_add_goto_table(self, dp):
        self._verify = dp.ofproto.OFPIT_GOTO_TABLE

        inst = [dp.ofproto_parser.OFPInstructionGotoTable(1), ]
        self.mod_flow(dp, inst=inst)
        self.send_flow_stats(dp)

    def verify_flow_add_goto_table(self, dp, msg):
        return self._verify_flow_inst_type(dp, msg)

    def _verify_flow_value(self, dp, msg):
        stats = msg.body
        verify = self._verify

        if len(verify) != len(stats):
            return 'flow_count is mismatched. verify=%s stats=%s' \
                   % (len(verify), len(stats))

        for s in stats:
            v_port = -1
            v = verify.get(s.table_id, None)
            if v:
                v_port = v[3].port

            s_port = s.instructions[0].actions[0].port

            if v_port != s_port:
                return 'port is mismatched. table_id=%s verify=%s, stats=%s' \
                       % (s.table_id, v_port, s_port)
        return True

    def _add_flow_for_flow_mod_tests(self, dp):
        a1 = dp.ofproto_parser.OFPActionOutput(1, 1500)
        a2 = dp.ofproto_parser.OFPActionOutput(2, 1500)

        # table_id, cookie, priority, dl_dst, action)
        tables = {0: [0xffff, 10, b'\xee' * 6, a1],
                  1: [0xff00, 10, b'\xee' * 6, a2],
                  2: [0xf000, 100, b'\xee' * 6, a1],
                  3: [0x0000, 10, b'\xff' * 6, a1]}

        self._verify = tables
        for table_id, val in tables.items():
            match = dp.ofproto_parser.OFPMatch()
            match.set_dl_dst(val[2])
            self.mod_flow(dp, match=match, actions=[val[3]],
                          table_id=table_id, cookie=val[0], priority=val[1])
        dp.send_barrier()

    def test_flow_mod_table_id(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # modify flow of table_id=3
        action = dp.ofproto_parser.OFPActionOutput(3, 1500)
        self._verify[3][3] = action

        table_id = 3
        self.mod_flow(dp, command=dp.ofproto.OFPFC_MODIFY,
                      actions=[action], table_id=table_id)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_mod_table_id(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_mod_cookie(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # modify flow of table_id=1
        action = dp.ofproto_parser.OFPActionOutput(3, 1500)
        self._verify[1][3] = action

        cookie = 0xff00
        cookie_mask = 0xffff
        table_id = 1
        self.mod_flow(dp, command=dp.ofproto.OFPFC_MODIFY,
                      actions=[action], table_id=table_id,
                      cookie=cookie, cookie_mask=cookie_mask)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_mod_cookie(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_mod_cookie_mask(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # modify flow of table_id=0,1
        action = dp.ofproto_parser.OFPActionOutput(3, 1500)
        self._verify[0][3] = action
        self._verify[1][3] = action

        cookie = 0xffff
        cookie_mask = 0xff00
        for table_id in range(2):
            self.mod_flow(dp, command=dp.ofproto.OFPFC_MODIFY,
                          actions=[action], table_id=table_id,
                          cookie=cookie, cookie_mask=cookie_mask)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_mod_cookie_mask(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_mod_match(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # modify flow of table_id=3
        action = dp.ofproto_parser.OFPActionOutput(3, 1500)
        self._verify[3][3] = action

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst(b'\xff' * 6)
        table_id = 3
        self.mod_flow(dp, command=dp.ofproto.OFPFC_MODIFY,
                      actions=[action], table_id=table_id, match=match)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_mod_match(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_mod_strict(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # modify flow of table_id=2
        action = dp.ofproto_parser.OFPActionOutput(3, 1500)
        self._verify[2][3] = action

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst(b'\xee' * 6)
        priority = 100
        table_id = 2
        self.mod_flow(dp, command=dp.ofproto.OFPFC_MODIFY_STRICT,
                      actions=[action], table_id=table_id,
                      match=match, priority=priority)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_mod_strict(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_del_table_id(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # delete flow of table_id=3
        del self._verify[3]

        table_id = 3
        self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE,
                      table_id=table_id)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_del_table_id(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_del_table_id_all(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # delete all flows
        self._verify = {}

        self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE,
                      table_id=dp.ofproto.OFPTT_ALL)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_del_table_id_all(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_del_cookie(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # delete flow of table_id=1
        del self._verify[1]

        cookie = 0xff00
        cookie_mask = 0xffff
        self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE,
                      table_id=dp.ofproto.OFPTT_ALL,
                      cookie=cookie, cookie_mask=cookie_mask)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_del_cookie(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_del_cookie_mask(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # delete flow of table_id=0,1
        del self._verify[0]
        del self._verify[1]

        cookie = 0xffff
        cookie_mask = 0xff00
        self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE,
                      table_id=dp.ofproto.OFPTT_ALL,
                      cookie=cookie, cookie_mask=cookie_mask)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_del_cookie_mask(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_del_match(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # delete flow of table_id=3
        del self._verify[3]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst(b'\xff' * 6)
        self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE,
                      table_id=dp.ofproto.OFPTT_ALL, match=match)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_del_match(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_del_out_port(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # delete flow of table_id=1
        del self._verify[1]

        out_port = 2
        self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE,
                      table_id=dp.ofproto.OFPTT_ALL, out_port=out_port)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_del_out_port(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def test_flow_del_strict(self, dp):
        self._add_flow_for_flow_mod_tests(dp)

        # delete flow of table_id=2
        del self._verify[2]

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_dst(b'\xee' * 6)
        priority = 100
        self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE_STRICT,
                      table_id=dp.ofproto.OFPTT_ALL,
                      match=match, priority=priority)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def verify_flow_del_strict(self, dp, msg):
        return self._verify_flow_value(dp, msg)

    def _send_port_mod(self, dp, config, mask):
        p = self.get_port(dp)
        if not p:
            err = 'need attached port to switch.'
            self.results[self.current] = err
            self.start_next_test(dp)
            return

        self._verify = [p.port_no, config & mask]
        m = dp.ofproto_parser.OFPPortMod(dp, p.port_no, p.hw_addr,
                                         config, mask, 0)
        dp.send_msg(m)
        dp.send_barrier()

        # TODO: waiting to port UP|DOWN.
        time.sleep(1)
        m = dp.ofproto_parser.OFPFeaturesRequest(dp)
        dp.send_msg(m)

    def _verify_port_mod_config(self, dp, msg):
        port_no = self._verify[0]
        config = self._verify[1]

        port = msg.ports[port_no]
        if config != port.config:
            return "config is mismatched. verify=%s, stats=%s" \
                % (bin(config), bin(port.config))
        return True

    def test_port_mod_config_01_all(self, dp):
        config = 0b1100101
        mask = 0b1111111
        self._send_port_mod(dp, config, mask)

    def verify_port_mod_config_01_all(self, dp, msg):
        return self._verify_port_mod_config(dp, msg)

    def test_port_mod_config_02_none(self, dp):
        config = 0
        mask = 0b1111111
        self._send_port_mod(dp, config, mask)

    def verify_port_mod_config_02_none(self, dp, msg):
        return self._verify_port_mod_config(dp, msg)

    def test_port_mod_config_03_mask(self, dp):
        config = 0b1100101
        mask = 0b1111000
        self._send_port_mod(dp, config, mask)

    def verify_port_mod_config_03_mask(self, dp, msg):
        res = self._verify_port_mod_config(dp, msg)
        # reset port config
        port_no = self._verify[0]
        p = msg.ports[port_no]
        m = dp.ofproto_parser.OFPPortMod(dp, p.port_no, p.hw_addr,
                                         0, 0b1111111, 0)
        dp.send_msg(m)
        dp.send_barrier()
        return res

    def test_port_stats_port_no(self, dp):
        p = self.get_port(dp)
        if not p:
            err = 'need attached port to switch.'
            self.results[self.current] = err
            self.start_next_test(dp)
            return

        self._verify = p.port_no
        m = dp.ofproto_parser.OFPPortStatsRequest(dp, p.port_no)
        dp.send_msg(m)

    def verify_port_stats_port_no(self, dp, msg):
        ports = msg.body
        if len(ports) > 1:
            return 'reply some ports.\n%s' % (ports)

        if ports[0].port_no != self._verify:
            return 'port_no is mismatched. request=%s reply=%s' \
                % (self._verify, ports[0].port_no)

        return True

    def _add_flow_flow_removed(self, dp, reason, table_id=0,
                               cookie=0xff, priority=100, in_port=1,
                               idle_timeout=0, hard_timeout=0):
        self._verify = {}
        self._verify['params'] = {'reason': reason,
                                  'table_id': table_id,
                                  'cookie': cookie,
                                  'priority': priority}
        self._verify['in_port'] = in_port
        self._verify['timeout'] = idle_timeout
        if hard_timeout:
            if (idle_timeout == 0 or idle_timeout > hard_timeout):
                self._verify['timeout'] = hard_timeout

        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        self.mod_flow(dp, match=match, cookie=cookie,
                      priority=priority, table_id=table_id,
                      idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                      flags=dp.ofproto.OFPFF_SEND_FLOW_REM)

    def _verify_flow_removed(self, dp, msg):
        params = self._verify['params']
        in_port = self._verify['in_port']
        timeout = self._verify['timeout']

        if timeout:
            duration_nsec = (msg.duration_sec * 10 ** 9) + msg.duration_nsec
            timeout_nsec = timeout * 10 ** 9

            # grace of -0.5 and +1.5 second to timeout.
            l = (timeout - 0.5) * 10 ** 9
            h = (timeout + 1.5) * 10 ** 9
            if not l < duration_nsec < h:
                return 'bad duration time. set=%s(nsec), duration=%s(nsec)' \
                    % (timeout_nsec, duration_nsec)

        for name, val in params.items():
            r_val = getattr(msg, name)
            if val != r_val:
                return '%s is mismatched. verify=%s, reply=%s' \
                    % (name, val, r_val)

        for f in msg.match.fields:
            if f.header == ofproto_v1_2.OXM_OF_IN_PORT:
                if f.value != in_port:
                    return 'in_port is mismatched. verify=%s, reply=%s' \
                        % (in_port, f.value)
        return True

    def test_flow_removed_idle_timeout(self, dp):
        reason = dp.ofproto.OFPRR_IDLE_TIMEOUT
        idle_timeout = 2
        self._add_flow_flow_removed(dp, reason,
                                    idle_timeout=idle_timeout)

    def verify_flow_removed_idle_timeout(self, dp, msg):
        return self._verify_flow_removed(dp, msg)

    def test_flow_removed_idle_timeout_hit(self, dp):
        reason = dp.ofproto.OFPRR_IDLE_TIMEOUT
        idle_timeout = 5
        in_port = 1
        sleep = 2

        # add target flow
        self._add_flow_flow_removed(dp, reason, in_port=in_port,
                                    idle_timeout=idle_timeout)
        self._verify['timeout'] = idle_timeout + sleep

        # sleep
        time.sleep(sleep)

        # packet out
        output = dp.ofproto.OFPP_TABLE
        actions = [dp.ofproto_parser.OFPActionOutput(output, 0)]
        m = dp.ofproto_parser.OFPPacketOut(dp, 0xffffffff, in_port,
                                           actions, None)
        dp.send_msg(m)

    def verify_flow_removed_idle_timeout_hit(self, dp, msg):
        return self._verify_flow_removed(dp, msg)

    def test_flow_removed_hard_timeout(self, dp):
        reason = dp.ofproto.OFPRR_HARD_TIMEOUT
        hard_timeout = 2
        self._add_flow_flow_removed(dp, reason,
                                    hard_timeout=hard_timeout)

    def verify_flow_removed_hard_timeout(self, dp, msg):
        return self._verify_flow_removed(dp, msg)

    def test_flow_removed_hard_timeout_hit(self, dp):
        reason = dp.ofproto.OFPRR_HARD_TIMEOUT
        hard_timeout = 5
        in_port = 1
        sleep = 2

        self._add_flow_flow_removed(dp, reason, in_port=in_port,
                                    hard_timeout=hard_timeout)
        dp.send_barrier()

        # sleep
        time.sleep(sleep)

        # packet out
        output = dp.ofproto.OFPP_TABLE
        actions = [dp.ofproto_parser.OFPActionOutput(output, 0)]
        m = dp.ofproto_parser.OFPPacketOut(dp, 0xffffffff, in_port,
                                           actions, None)
        dp.send_msg(m)

    def verify_flow_removed_hard_timeout_hit(self, dp, msg):
        return self._verify_flow_removed(dp, msg)

    def test_flow_removed_delete(self, dp):
        reason = dp.ofproto.OFPRR_DELETE
        self._add_flow_flow_removed(dp, reason)
        dp.send_barrier()
        self.delete_all_flows(dp)

    def verify_flow_removed_delete(self, dp, msg):
        return self._verify_flow_removed(dp, msg)

    def test_flow_removed_table_id(self, dp):
        reason = dp.ofproto.OFPRR_DELETE
        table_id = 1
        self._add_flow_flow_removed(dp, reason, table_id=table_id)
        dp.send_barrier()
        self.delete_all_flows(dp)

    def verify_flow_removed_table_id(self, dp, msg):
        return self._verify_flow_removed(dp, msg)

    def _send_packet_out(self, dp, buffer_id=0xffffffff,
                         in_port=None, output=None, data=''):
        if in_port is None:
            in_port = dp.ofproto.OFPP_LOCAL

        if output is None:
            output = dp.ofproto.OFPP_CONTROLLER

        self._verify['in_port'] = in_port
        self._verify['data'] = data

        actions = [dp.ofproto_parser.OFPActionOutput(output, len(data))]
        m = dp.ofproto_parser.OFPPacketOut(dp, buffer_id, in_port,
                                           actions, data)
        dp.send_msg(m)

    def _verify_packet_in(self, dp, msg):
        for name, val in self._verify.items():
            if name == 'in_port':
                for f in msg.match.fields:
                    if f.header == ofproto_v1_2.OXM_OF_IN_PORT:
                        r_val = f.value
            else:
                r_val = getattr(msg, name)

            if val != r_val:
                return '%s is mismatched. verify=%s, reply=%s' \
                    % (name, val, r_val)
        return True

    def test_packet_in_action(self, dp):
        self._verify = {}
        self._verify['reason'] = dp.ofproto.OFPR_ACTION
        self._send_packet_out(dp)

    def verify_packet_in_action(self, dp, msg):
        return self._verify_packet_in(dp, msg)

    def test_packet_in_data(self, dp):
        self._verify = {}
        self._verify['reason'] = dp.ofproto.OFPR_ACTION
        data = 'test'
        self._send_packet_out(dp, data=data)

    def verify_packet_in_data(self, dp, msg):
        return self._verify_packet_in(dp, msg)

    def test_packet_in_table_id(self, dp):
        in_port = 1
        table_id = 2
        output = dp.ofproto.OFPP_TABLE

        self._verify = {}
        self._verify['reason'] = dp.ofproto.OFPR_ACTION
        self._verify['table_id'] = table_id

        # add flow (goto_table)
        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        inst = [dp.ofproto_parser.OFPInstructionGotoTable(table_id)]
        self.mod_flow(dp, inst=inst, match=match)

        # add flow (output)
        match = dp.ofproto_parser.OFPMatch()
        match.set_in_port(in_port)
        out = dp.ofproto.OFPP_CONTROLLER
        actions = [dp.ofproto_parser.OFPActionOutput(out, 0)]
        self.mod_flow(dp, actions=actions, match=match, table_id=table_id)
        dp.send_barrier()

        # packet out
        self._send_packet_out(dp, in_port=in_port, output=output)

    def verify_packet_in_table_id(self, dp, msg):
        return self._verify_packet_in(dp, msg)

    # handler
    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_replay_handler(self, ev):
        if self.current.find('echo_request') > 0:
            self.run_verify(ev)

    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        if self.current is None:
            msg = ev.msg
            dp = msg.datapath
            if self._verify == dp.ofproto.OFPST_TABLE:
                self.table_stats = msg.body
            self.start_next_test(dp)
        else:
            self.run_verify(ev)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def features_replay_handler(self, ev):
        if self.current is None:
            pass
        else:
            self.run_verify(ev)

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
    def get_config_replay_handler(self, ev):
        self.run_verify(ev)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_replay_handler(self, ev):
        if self.current == 'test_barrier_request':
            self.run_verify(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if self.current.find('packet_in'):
            self.run_verify(ev)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        if self.current.find('flow_removed') > 0:
            self.run_verify(ev)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_handler(self, ev):
        if self.current.find('error') > 0:
            self.run_verify(ev)

    def is_supported(self, t):
        unsupported = [
        ]
        for u in unsupported:
            if t.find(u) != -1:
                return False

        return True
