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

import inspect
import json
import logging
import os
import signal
import sys
import time
import traceback

from ryu import cfg

# import all packet libraries.
PKT_LIB_PATH = 'ryu.lib.packet'
for modname, moddef in sys.modules.iteritems():
    if not modname.startswith(PKT_LIB_PATH) or not moddef:
        continue
    for (clsname, clsdef, ) in inspect.getmembers(moddef):
        if not inspect.isclass(clsdef):
            continue
        exec 'from %s import %s' % (modname, clsname)

from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import stringify
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


""" Required test network:

                      +-----------+
           +----------| target sw | The switch to be tested
           |          +-----------+
    +------------+      (1)   (2)
    | controller |       |     |
    +------------+      (1)   (2)
           |          +-----------+
           +----------| tester sw | OpenFlow Switch
                      +-----------+

      (X) : port number

    Tests send a packet from port 1 of the tester sw.
    If the packet matched with a flow entry of the target sw,
     the target sw resends the packet from port 2 (or the port which
     connected with the controller), according to the flow entry.
    Then the tester sw receives the packet and sends a PacketIn message.
    If the packet did not match, the target sw drops the packet.

"""


CONF = cfg.CONF


# Default settings.
TESTER_SENDER_PORT = 1
TESTER_RECEIVE_PORT = 2
TARGET_SENDER_PORT = 2
TARGET_RECEIVE_PORT = 1

INTERVAL = 1  # sec
WAIT_TIMER = 3  # sec
CONTINUOUS_THREAD_INTVL = float(0.01)  # sec
CONTINUOUS_PROGRESS_SPAN = 3  # sec
THROUGHPUT_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY+1
THROUGHPUT_COOKIE = THROUGHPUT_PRIORITY

# Default settings for 'ingress: packets'
DEFAULT_DURATION_TIME = 30
DEFAULT_PKTPS = 1000

# Test file format.
KEY_DESC = 'description'
KEY_PREREQ = 'prerequisite'
KEY_FLOW = 'OFPFlowMod'
KEY_METER = 'OFPMeterMod'
KEY_TESTS = 'tests'
KEY_INGRESS = 'ingress'
KEY_EGRESS = 'egress'
KEY_PKT_IN = 'PACKET_IN'
KEY_TBL_MISS = 'table-miss'
KEY_PACKETS = 'packets'
KEY_DATA = 'data'
KEY_KBPS = 'kbps'
KEY_PKTPS = 'pktps'
KEY_DURATION_TIME = 'duration_time'
KEY_THROUGHPUT = 'throughput'
KEY_MATCH = 'OFPMatch'

# Test state.
STATE_INIT_FLOW = 0
STATE_FLOW_INSTALL = 1
STATE_FLOW_EXIST_CHK = 2
STATE_TARGET_PKT_COUNT = 3
STATE_TESTER_PKT_COUNT = 4
STATE_FLOW_MATCH_CHK = 5
STATE_NO_PKTIN_REASON = 6
STATE_GET_MATCH_COUNT = 7
STATE_SEND_BARRIER = 8
STATE_FLOW_UNMATCH_CHK = 9
STATE_INIT_METER = 10
STATE_METER_INSTALL = 11
STATE_METER_EXIST_CHK = 12
STATE_INIT_THROUGHPUT_FLOW = 13
STATE_THROUGHPUT_FLOW_INSTALL = 14
STATE_THROUGHPUT_FLOW_EXIST_CHK = 15
STATE_GET_THROUGHPUT = 16

STATE_DISCONNECTED = 99

# Test result.
TEST_OK = 'OK'
TEST_ERROR = 'ERROR'
RYU_INTERNAL_ERROR = '- (Ryu internal error.)'
TEST_FILE_ERROR = '%(file)s : Test file format error (%(detail)s)'
NO_TEST_FILE = 'Test file (*.json) is not found.'
INVALID_PATH = '%(path)s : No such file or directory.'

# Test result details.
FAILURE = 0
ERROR = 1
TIMEOUT = 2
RCV_ERR = 3

MSG = {STATE_INIT_FLOW:
       {TIMEOUT: 'Failed to initialize flow tables: barrier request timeout.',
        RCV_ERR: 'Failed to initialize flow tables: %(err_msg)s'},
       STATE_INIT_THROUGHPUT_FLOW:
       {TIMEOUT: 'Failed to initialize flow tables of tester_sw: '
                 'barrier request timeout.',
        RCV_ERR: 'Failed to initialize flow tables of tester_sw: '
                 '%(err_msg)s'},
       STATE_FLOW_INSTALL:
       {TIMEOUT: 'Failed to add flows: barrier request timeout.',
        RCV_ERR: 'Failed to add flows: %(err_msg)s'},
       STATE_THROUGHPUT_FLOW_INSTALL:
       {TIMEOUT: 'Failed to add flows to tester_sw: barrier request timeout.',
        RCV_ERR: 'Failed to add flows to tester_sw: %(err_msg)s'},
       STATE_METER_INSTALL:
       {TIMEOUT: 'Failed to add meters: barrier request timeout.',
        RCV_ERR: 'Failed to add meters: %(err_msg)s'},
       STATE_FLOW_EXIST_CHK:
       {FAILURE: 'Added incorrect flows: %(flows)s',
        TIMEOUT: 'Failed to add flows: flow stats request timeout.',
        RCV_ERR: 'Failed to add flows: %(err_msg)s'},
       STATE_METER_EXIST_CHK:
       {FAILURE: 'Added incorrect meters: %(meters)s',
        TIMEOUT: 'Failed to add meters: meter config stats request timeout.',
        RCV_ERR: 'Failed to add meters: %(err_msg)s'},
       STATE_TARGET_PKT_COUNT:
       {TIMEOUT: 'Failed to request port stats from target: request timeout.',
        RCV_ERR: 'Failed to request port stats from target: %(err_msg)s'},
       STATE_TESTER_PKT_COUNT:
       {TIMEOUT: 'Failed to request port stats from tester: request timeout.',
        RCV_ERR: 'Failed to request port stats from tester: %(err_msg)s'},
       STATE_FLOW_MATCH_CHK:
       {FAILURE: 'Received incorrect %(pkt_type)s: %(detail)s',
        TIMEOUT: '',  # for check no packet-in reason.
        RCV_ERR: 'Failed to send packet: %(err_msg)s'},
       STATE_NO_PKTIN_REASON:
       {FAILURE: 'Receiving timeout: %(detail)s'},
       STATE_GET_MATCH_COUNT:
       {TIMEOUT: 'Failed to request table stats: request timeout.',
        RCV_ERR: 'Failed to request table stats: %(err_msg)s'},
       STATE_SEND_BARRIER:
       {TIMEOUT: 'Faild to send packet: barrier request timeout.',
        RCV_ERR: 'Faild to send packet: %(err_msg)s'},
       STATE_FLOW_UNMATCH_CHK:
       {FAILURE: 'Table-miss error: increment in matched_count.',
        ERROR: 'Table-miss error: no change in lookup_count.',
        TIMEOUT: 'Failed to request table stats: request timeout.',
        RCV_ERR: 'Failed to request table stats: %(err_msg)s'},
       STATE_THROUGHPUT_FLOW_EXIST_CHK:
       {FAILURE: 'Added incorrect flows to tester_sw: %(flows)s',
        TIMEOUT: 'Failed to add flows to tester_sw: '
                 'flow stats request timeout.',
        RCV_ERR: 'Failed to add flows to tester_sw: %(err_msg)s'},
       STATE_GET_THROUGHPUT:
       {TIMEOUT: 'Failed to request flow stats: request timeout.',
        RCV_ERR: 'Failed to request flow stats: %(err_msg)s'},
       STATE_DISCONNECTED:
       {ERROR: 'Disconnected from switch'}}

ERR_MSG = 'OFPErrorMsg[type=0x%02x, code=0x%02x]'


class TestMessageBase(RyuException):
    def __init__(self, state, message_type, **argv):
        msg = MSG[state][message_type] % argv
        super(TestMessageBase, self).__init__(msg=msg)


class TestFailure(TestMessageBase):
    def __init__(self, state, **argv):
        super(TestFailure, self).__init__(state, FAILURE, **argv)


class TestTimeout(TestMessageBase):
    def __init__(self, state):
        super(TestTimeout, self).__init__(state, TIMEOUT)


class TestReceiveError(TestMessageBase):
    def __init__(self, state, err_msg):
        argv = {'err_msg': ERR_MSG % (err_msg.type, err_msg.code)}
        super(TestReceiveError, self).__init__(state, RCV_ERR, **argv)


class TestError(TestMessageBase):
    def __init__(self, state, **argv):
        super(TestError, self).__init__(state, ERROR, **argv)


class OfTester(app_manager.RyuApp):
    """ OpenFlow Switch Tester. """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self):
        super(OfTester, self).__init__()
        self._set_logger()

        self.target_dpid = self._convert_dpid(CONF['test-switch']['target'])
        self.tester_dpid = self._convert_dpid(CONF['test-switch']['tester'])
        self.logger.info('target_dpid=%s',
                         dpid_lib.dpid_to_str(self.target_dpid))
        self.logger.info('tester_dpid=%s',
                         dpid_lib.dpid_to_str(self.tester_dpid))
        test_dir = CONF['test-switch']['dir']
        self.logger.info('Test files directory = %s', test_dir)

        self.target_sw = TargetSw(DummyDatapath(), self.logger)
        self.tester_sw = TesterSw(DummyDatapath(), self.logger)
        self.state = STATE_INIT_FLOW
        self.sw_waiter = None
        self.waiter = None
        self.send_msg_xids = []
        self.rcv_msgs = []
        self.ingress_event = None
        self.ingress_threads = []
        self.thread_msg = None
        self.test_thread = hub.spawn(
            self._test_sequential_execute, test_dir)

    def _set_logger(self):
        self.logger.propagate = False
        s_hdlr = logging.StreamHandler()
        self.logger.addHandler(s_hdlr)
        if CONF.log_file:
            f_hdlr = logging.handlers.WatchedFileHandler(CONF.log_file)
            self.logger.addHandler(f_hdlr)

    def _convert_dpid(self, dpid_str):
        try:
            dpid = int(dpid_str, 16)
        except ValueError as err:
            self.logger.error('Invarid dpid parameter. %s', err)
            self._test_end()
        return dpid

    def close(self):
        if self.test_thread is not None:
            hub.kill(self.test_thread)
        if self.ingress_event:
            self.ingress_event.set()
        hub.joinall([self.test_thread])
        self._test_end('--- Test terminated ---')

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self._register_sw(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self._unregister_sw(ev.datapath)

    def _register_sw(self, dp):
        if dp.id == self.target_dpid:
            self.target_sw.dp = dp
            msg = 'Join target SW.'
        elif dp.id == self.tester_dpid:
            self.tester_sw.dp = dp
            self.tester_sw.add_flow(
                in_port=TESTER_RECEIVE_PORT,
                out_port=dp.ofproto.OFPP_CONTROLLER)
            msg = 'Join tester SW.'
        else:
            msg = 'Connect unknown SW.'
        if dp.id:
            self.logger.info('dpid=%s : %s',
                             dpid_lib.dpid_to_str(dp.id), msg)

        if not (isinstance(self.target_sw.dp, DummyDatapath) or
                isinstance(self.tester_sw.dp, DummyDatapath)):
            if self.sw_waiter is not None:
                self.sw_waiter.set()

    def _unregister_sw(self, dp):
        if dp.id == self.target_dpid:
            self.target_sw.dp = DummyDatapath()
            msg = 'Leave target SW.'
        elif dp.id == self.tester_dpid:
            self.tester_sw.dp = DummyDatapath()
            msg = 'Leave tester SW.'
        else:
            msg = 'Disconnect unknown SW.'
        if dp.id:
            self.logger.info('dpid=%s : %s',
                             dpid_lib.dpid_to_str(dp.id), msg)

    def _test_sequential_execute(self, test_dir):
        """ Execute OpenFlow Switch test. """
        # Parse test pattern from test files.
        tests = TestPatterns(test_dir, self.logger)
        if not tests:
            self.logger.warning(NO_TEST_FILE)
            self._test_end()

        test_report = {}
        self.logger.info('--- Test start ---')
        test_keys = tests.keys()
        test_keys.sort()
        for file_name in test_keys:
            report = self._test_file_execute(tests[file_name])
            for result, descriptions in report.items():
                test_report.setdefault(result, [])
                test_report[result].extend(descriptions)
        self._test_end(msg='---  Test end  ---', report=test_report)

    def _test_file_execute(self, testfile):
        report = {}
        for i, test in enumerate(testfile.tests):
            desc = testfile.description if i == 0 else None
            result = self._test_execute(test, desc)
            report.setdefault(result, [])
            report[result].append([testfile.description, test.description])
        return report

    def _test_execute(self, test, description):
        if isinstance(self.target_sw.dp, DummyDatapath) or \
                isinstance(self.tester_sw.dp, DummyDatapath):
            self.logger.info('waiting for switches connection...')
            self.sw_waiter = hub.Event()
            self.sw_waiter.wait()
            self.sw_waiter = None

        if description:
            self.logger.info('%s', description)
        self.thread_msg = None

        # Test execute.
        try:
            # Initialize.
            self._test(STATE_INIT_METER)
            self._test(STATE_INIT_FLOW)
            self._test(STATE_INIT_THROUGHPUT_FLOW)
            # Install flows.
            for flow in test.prerequisite:
                if isinstance(flow, ofproto_v1_3_parser.OFPFlowMod):
                    self._test(STATE_FLOW_INSTALL, self.target_sw, flow)
                    self._test(STATE_FLOW_EXIST_CHK, self.target_sw, flow)
                elif isinstance(flow, ofproto_v1_3_parser.OFPMeterMod):
                    self._test(STATE_METER_INSTALL, flow)
                    self._test(STATE_METER_EXIST_CHK, flow)
            # Do tests.
            for pkt in test.tests:

                # Get stats before sending packet(s).
                if KEY_EGRESS in pkt or KEY_PKT_IN in pkt:
                    target_pkt_count = [self._test(STATE_TARGET_PKT_COUNT,
                                                   True)]
                    tester_pkt_count = [self._test(STATE_TESTER_PKT_COUNT,
                                                   False)]
                elif KEY_THROUGHPUT in pkt:
                    # install flows for throughput analysis
                    for throughput in pkt[KEY_THROUGHPUT]:
                        flow = throughput[KEY_FLOW]
                        self._test(STATE_THROUGHPUT_FLOW_INSTALL,
                                   self.tester_sw, flow)
                        self._test(STATE_THROUGHPUT_FLOW_EXIST_CHK,
                                   self.tester_sw, flow)
                elif KEY_TBL_MISS in pkt:
                    before_stats = self._test(STATE_GET_MATCH_COUNT)

                # Send packet(s).
                if KEY_INGRESS in pkt:
                    self._one_time_packet_send(pkt)
                elif KEY_PACKETS in pkt:
                    self._continuous_packet_send(pkt)

                # Check a result.
                if KEY_EGRESS in pkt or KEY_PKT_IN in pkt:
                    result = self._test(STATE_FLOW_MATCH_CHK, pkt)
                    if result == TIMEOUT:
                        target_pkt_count.append(self._test(
                            STATE_TARGET_PKT_COUNT, True))
                        tester_pkt_count.append(self._test(
                            STATE_TESTER_PKT_COUNT, False))
                        test_type = (KEY_EGRESS if KEY_EGRESS in pkt
                                     else KEY_PKT_IN)
                        self._test(STATE_NO_PKTIN_REASON, test_type,
                                   target_pkt_count, tester_pkt_count)
                elif KEY_TBL_MISS in pkt:
                    self._test(STATE_SEND_BARRIER)
                    hub.sleep(INTERVAL)
                    self._test(STATE_FLOW_UNMATCH_CHK, before_stats, pkt)

            result = [TEST_OK]
            result_type = TEST_OK
        except (TestFailure, TestError,
                TestTimeout, TestReceiveError) as err:
            result = [TEST_ERROR, str(err)]
            result_type = str(err).split(':', 1)[0]
        except Exception:
            result = [TEST_ERROR, RYU_INTERNAL_ERROR]
            result_type = RYU_INTERNAL_ERROR
        finally:
            self.ingress_event = None
            for tid in self.ingress_threads:
                hub.kill(tid)
            self.ingress_threads = []

        # Output test result.
        self.logger.info('    %-100s %s', test.description, result[0])
        if 1 < len(result):
            self.logger.info('        %s', result[1])
            if (result[1] == RYU_INTERNAL_ERROR
                    or result == 'An unknown exception'):
                self.logger.error(traceback.format_exc())

        hub.sleep(0)
        return result_type

    def _test_end(self, msg=None, report=None):
        self.test_thread = None
        if msg:
            self.logger.info(msg)
        if report:
            self._output_test_report(report)
        pid = os.getpid()
        os.kill(pid, signal.SIGTERM)

    def _output_test_report(self, report):
        self.logger.info('%s--- Test report ---', os.linesep)
        ok_count = error_count = 0
        for result_type in sorted(report.keys()):
            test_descriptions = report[result_type]
            if result_type == TEST_OK:
                ok_count = len(test_descriptions)
                continue
            error_count += len(test_descriptions)
            self.logger.info('%s(%d)', result_type, len(test_descriptions))
            for file_desc, test_desc in test_descriptions:
                self.logger.info('    %-40s %s', file_desc, test_desc)
        self.logger.info('%s%s(%d) / %s(%d)', os.linesep,
                         TEST_OK, ok_count, TEST_ERROR, error_count)

    def _test(self, state, *args):
        test = {STATE_INIT_FLOW: self._test_initialize_flow,
                STATE_INIT_THROUGHPUT_FLOW: self._test_initialize_flow_tester,
                STATE_INIT_METER: self._test_initialize_meter,
                STATE_FLOW_INSTALL: self._test_flow_install,
                STATE_THROUGHPUT_FLOW_INSTALL: self._test_flow_install,
                STATE_METER_INSTALL: self._test_meter_install,
                STATE_FLOW_EXIST_CHK: self._test_flow_exist_check,
                STATE_THROUGHPUT_FLOW_EXIST_CHK: self._test_flow_exist_check,
                STATE_METER_EXIST_CHK: self._test_meter_exist_check,
                STATE_TARGET_PKT_COUNT: self._test_get_packet_count,
                STATE_TESTER_PKT_COUNT: self._test_get_packet_count,
                STATE_FLOW_MATCH_CHK: self._test_flow_matching_check,
                STATE_NO_PKTIN_REASON: self._test_no_pktin_reason_check,
                STATE_GET_MATCH_COUNT: self._test_get_match_count,
                STATE_SEND_BARRIER: self._test_send_barrier,
                STATE_FLOW_UNMATCH_CHK: self._test_flow_unmatching_check,
                STATE_GET_THROUGHPUT: self._test_get_throughput}

        self.send_msg_xids = []
        self.rcv_msgs = []

        self.state = state
        return test[state](*args)

    def _test_initialize_flow(self):
        xid = self.target_sw.del_test_flow()
        self.send_msg_xids.append(xid)

        xid = self.target_sw.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_initialize_flow_tester(self):
        xid = self.tester_sw.del_flows_for_throughput_analysis()
        self.send_msg_xids.append(xid)

        xid = self.tester_sw.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_initialize_meter(self):
        self.target_sw.del_test_meter()

    def _test_flow_install(self, datapath, flow):
        xid = datapath.add_flow(flow_mod=flow)
        self.send_msg_xids.append(xid)

        xid = datapath.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_meter_install(self, meter):
        xid = self.target_sw._send_msg(meter)
        self.send_msg_xids.append(xid)

        xid = self.target_sw.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_exist_check(self, datapath, flow_mod):
        xid = datapath.send_flow_stats()
        self.send_msg_xids.append(xid)
        self._wait()

        ng_stats = []
        for msg in self.rcv_msgs:
            assert isinstance(msg, ofproto_v1_3_parser.OFPFlowStatsReply)
            for stats in msg.body:
                result, stats = self._compare_flow(stats, flow_mod)
                if result:
                    return
                else:
                    ng_stats.append(stats)
        raise TestFailure(self.state, flows=', '.join(ng_stats))

    def _test_meter_exist_check(self, meter_mod):
        xid = self.target_sw.send_meter_config_stats()
        self.send_msg_xids.append(xid)
        self._wait()

        ng_stats = []
        for msg in self.rcv_msgs:
            assert isinstance(
                msg, ofproto_v1_3_parser.OFPMeterConfigStatsReply)
            for stats in msg.body:
                result, stats = self._compare_meter(stats, meter_mod)
                if result:
                    return
                else:
                    ng_stats.append(stats)
        raise TestFailure(self.state, meters=', '.join(ng_stats))

    def _test_get_packet_count(self, is_target):
        sw = self.target_sw if is_target else self.tester_sw
        xid = sw.send_port_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        result = {}
        for msg in self.rcv_msgs:
            for stats in msg.body:
                result[stats.port_no] = {'rx': stats.rx_packets,
                                         'tx': stats.tx_packets}
        return result

    def _test_flow_matching_check(self, pkt):
        self.logger.debug("egress:[%s]", packet.Packet(pkt.get(KEY_EGRESS)))
        self.logger.debug("packet_in:[%s]",
                          packet.Packet(pkt.get(KEY_PKT_IN)))

        # receive a PacketIn message.
        try:
            self._wait()
        except TestTimeout:
            return TIMEOUT

        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPPacketIn)
        self.logger.debug("dpid=%s : receive_packet[%s]",
                          dpid_lib.dpid_to_str(msg.datapath.id),
                          packet.Packet(msg.data))

        # check the SW which sended PacketIn and output packet.
        pkt_in_src_model = (self.tester_sw if KEY_EGRESS in pkt
                            else self.target_sw)
        model_pkt = (pkt[KEY_EGRESS] if KEY_EGRESS in pkt
                     else pkt[KEY_PKT_IN])

        if msg.datapath.id != pkt_in_src_model.dp.id:
            pkt_type = 'packet-in'
            err_msg = 'SW[dpid=%s]' % dpid_lib.dpid_to_str(msg.datapath.id)
        elif msg.reason != ofproto_v1_3.OFPR_ACTION:
            pkt_type = 'packet-in'
            err_msg = 'OFPPacketIn[reason=%d]' % msg.reason
        elif repr(msg.data) != repr(model_pkt):
            pkt_type = 'packet'
            err_msg = self._diff_packets(packet.Packet(model_pkt),
                                         packet.Packet(msg.data))
        else:
            return TEST_OK

        raise TestFailure(self.state, pkt_type=pkt_type,
                          detail=err_msg)

    def _test_no_pktin_reason_check(self, test_type,
                                    target_pkt_count, tester_pkt_count):
        before_target_receive = target_pkt_count[0][TARGET_RECEIVE_PORT]['rx']
        before_target_send = target_pkt_count[0][TARGET_SENDER_PORT]['tx']
        before_tester_receive = tester_pkt_count[0][TESTER_RECEIVE_PORT]['rx']
        before_tester_send = tester_pkt_count[0][TESTER_SENDER_PORT]['tx']
        after_target_receive = target_pkt_count[1][TARGET_RECEIVE_PORT]['rx']
        after_target_send = target_pkt_count[1][TARGET_SENDER_PORT]['tx']
        after_tester_receive = tester_pkt_count[1][TESTER_RECEIVE_PORT]['rx']
        after_tester_send = tester_pkt_count[1][TESTER_SENDER_PORT]['tx']

        if after_tester_send == before_tester_send:
            log_msg = 'no change in tx_packets on tester.'
        elif after_target_receive == before_target_receive:
            log_msg = 'no change in rx_packtes on target.'
        elif test_type == KEY_EGRESS:
            if after_target_send == before_target_send:
                log_msg = 'no change in tx_packets on target.'
            elif after_tester_receive == before_tester_receive:
                log_msg = 'no change in rx_packets on tester.'
            else:
                log_msg = 'increment in rx_packets in tester.'
        else:
            assert test_type == KEY_PKT_IN
            log_msg = 'no packet-in.'

        raise TestFailure(self.state, detail=log_msg)

    def _test_get_match_count(self):
        xid = self.target_sw.send_table_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        result = {}
        for msg in self.rcv_msgs:
            for stats in msg.body:
                result[stats.table_id] = {'lookup': stats.lookup_count,
                                          'matched': stats.matched_count}
        return result

    def _test_send_barrier(self):
        # Wait OFPBarrierReply.
        xid = self.tester_sw.send_barrier_request()
        self.send_msg_xids.append(xid)
        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_unmatching_check(self, before_stats, pkt):
        # Check matched packet count.
        rcv_msgs = self._test_get_match_count()

        lookup = False
        for target_tbl_id in pkt[KEY_TBL_MISS]:
            before = before_stats[target_tbl_id]
            after = rcv_msgs[target_tbl_id]
            if before['lookup'] < after['lookup']:
                lookup = True
                if before['matched'] < after['matched']:
                    raise TestFailure(self.state)
        if not lookup:
            raise TestError(self.state)

    def _one_time_packet_send(self, pkt):
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt[KEY_INGRESS]))
        xid = self.tester_sw.send_packet_out(pkt[KEY_INGRESS])
        self.send_msg_xids.append(xid)

    def _continuous_packet_send(self, pkt):
        assert self.ingress_event is None

        pkt_data = pkt[KEY_PACKETS][KEY_DATA]
        pktps = pkt[KEY_PACKETS][KEY_PKTPS]
        duration_time = pkt[KEY_PACKETS][KEY_DURATION_TIME]

        self.logger.debug("send_packet:[%s]", packet.Packet(pkt_data))
        self.logger.debug("pktps:[%d]", pktps)
        self.logger.debug("duration_time:[%d]", duration_time)

        arg = {'pkt_data': pkt_data,
               'thread_counter': 0,
               'dot_span': int(CONTINUOUS_PROGRESS_SPAN /
                               CONTINUOUS_THREAD_INTVL),
               'packet_counter': float(0),
               'packet_counter_inc': pktps * CONTINUOUS_THREAD_INTVL}

        try:
            self.ingress_event = hub.Event()
            tid = hub.spawn(self._send_packet_thread, arg)
            self.ingress_threads.append(tid)
            self.ingress_event.wait(duration_time)
            if self.thread_msg is not None:
                raise self.thread_msg  # pylint: disable=E0702
        finally:
            sys.stdout.write("\r\n")
            sys.stdout.flush()

    def _send_packet_thread(self, arg):
        """ Send several packets continuously. """
        if self.ingress_event is None or self.ingress_event._cond:
            return

        # display dots to express progress of sending packets
        if not arg['thread_counter'] % arg['dot_span']:
            sys.stdout.write(".")
            sys.stdout.flush()

        arg['thread_counter'] += 1

        # pile up float values and
        # use integer portion as the number of packets this thread sends
        arg['packet_counter'] += arg['packet_counter_inc']
        count = int(arg['packet_counter'])
        arg['packet_counter'] -= count

        hub.sleep(CONTINUOUS_THREAD_INTVL)

        tid = hub.spawn(self._send_packet_thread, arg)
        self.ingress_threads.append(tid)
        hub.sleep(0)
        for _ in range(count):
            try:
                self.tester_sw.send_packet_out(arg['pkt_data'])
            except Exception as err:
                self.thread_msg = err
                self.ingress_event.set()
                break

    def _compare_flow(self, stats1, stats2):
        attr_list = ['cookie', 'priority', 'hard_timeout', 'idle_timeout',
                     'table_id', 'instructions', 'match']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if attr == 'instructions':
                value1 = sorted(value1)
                value2 = sorted(value2)
            if str(value1) != str(value2):
                flow_stats = []
                for attr in attr_list:
                    flow_stats.append('%s=%s' % (attr, getattr(stats1, attr)))
                return False, 'flow_stats(%s)' % ','.join(flow_stats)
        return True, None

    def _compare_meter(self, stats1, stats2):
        """compare the message used to install and the message got from
           the switch."""
        attr_list = ['flags', 'meter_id', 'bands']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if str(value1) != str(value2):
                meter_stats = []
                for attr in attr_list:
                    meter_stats.append('%s=%s' % (attr, getattr(stats1, attr)))
                return False, 'meter_stats(%s)' % ','.join(meter_stats)
            return True, None

    def _diff_packets(self, model_pkt, rcv_pkt):
        msg = []
        for rcv_p in rcv_pkt.protocols:
            if type(rcv_p) != str:
                model_protocols = model_pkt.get_protocols(type(rcv_p))
                if len(model_protocols) == 1:
                    model_p = model_protocols[0]
                    diff = []
                    for attr in rcv_p.__dict__:
                        if attr.startswith('_'):
                            continue
                        if callable(attr):
                            continue
                        if hasattr(rcv_p.__class__, attr):
                            continue
                        rcv_attr = repr(getattr(rcv_p, attr))
                        model_attr = repr(getattr(model_p, attr))
                        if rcv_attr != model_attr:
                            diff.append('%s=%s' % (attr, rcv_attr))
                    if diff:
                        msg.append('%s(%s)' %
                                   (rcv_p.__class__.__name__,
                                    ','.join(diff)))
                else:
                    if (not model_protocols or
                            not str(rcv_p) in str(model_protocols)):
                        msg.append(str(rcv_p))
            else:
                model_p = ''
                for p in model_pkt.protocols:
                    if type(p) == str:
                        model_p = p
                        break
                if model_p != rcv_p:
                    msg.append('str(%s)' % repr(rcv_p))
        if msg:
            return '/'.join(msg)
        else:
            return ('Encounter an error during packet comparison.'
                    ' it is malformed.')

    def _test_get_throughput(self):
        xid = self.tester_sw.send_flow_stats()
        self.send_msg_xids.append(xid)
        self._wait()

        assert len(self.rcv_msgs) == 1
        flow_stats = self.rcv_msgs[0].body
        self.logger.debug(flow_stats)
        result = {}
        for stat in flow_stats:
            if stat.cookie != THROUGHPUT_COOKIE:
                continue
            result[str(stat.match)] = (stat.byte_count, stat.packet_count)
        return (time.time(), result)

    def _wait(self):
        """ Wait until specific OFP message received
             or timer is exceeded. """
        assert self.waiter is None

        self.waiter = hub.Event()
        self.rcv_msgs = []
        timeout = False

        timer = hub.Timeout(WAIT_TIMER)
        try:
            self.waiter.wait()
        except hub.Timeout as t:
            if t is not timer:
                raise RyuException('Internal error. Not my timeout.')
            timeout = True
        finally:
            timer.cancel()

        self.waiter = None

        if timeout:
            raise TestTimeout(self.state)
        if (self.rcv_msgs and isinstance(
                self.rcv_msgs[0], ofproto_v1_3_parser.OFPErrorMsg)):
            raise TestReceiveError(self.state, self.rcv_msgs[0])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, handler.MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        state_list = [STATE_FLOW_EXIST_CHK,
                      STATE_THROUGHPUT_FLOW_EXIST_CHK,
                      STATE_GET_THROUGHPUT]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags & ofproto_v1_3.OFPMPF_REPLY_MORE:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPMeterConfigStatsReply,
                handler.MAIN_DISPATCHER)
    def meter_config_stats_reply_handler(self, ev):
        state_list = [STATE_METER_EXIST_CHK]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags & ofproto_v1_3.OFPMPF_REPLY_MORE:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPTableStatsReply, handler.MAIN_DISPATCHER)
    def table_stats_reply_handler(self, ev):
        state_list = [STATE_GET_MATCH_COUNT,
                      STATE_FLOW_UNMATCH_CHK]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags & ofproto_v1_3.OFPMPF_REPLY_MORE:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, handler.MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        state_list = [STATE_TARGET_PKT_COUNT,
                      STATE_TESTER_PKT_COUNT]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags & ofproto_v1_3.OFPMPF_REPLY_MORE:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, handler.MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        state_list = [STATE_INIT_FLOW,
                      STATE_INIT_THROUGHPUT_FLOW,
                      STATE_INIT_METER,
                      STATE_FLOW_INSTALL,
                      STATE_THROUGHPUT_FLOW_INSTALL,
                      STATE_METER_INSTALL,
                      STATE_SEND_BARRIER]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                self.waiter.set()
                hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        state_list = [STATE_FLOW_MATCH_CHK]
        if self.state in state_list:
            if self.waiter:
                self.rcv_msgs.append(ev.msg)
                self.waiter.set()
                hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [handler.HANDSHAKE_DISPATCHER,
                                             handler.CONFIG_DISPATCHER,
                                             handler.MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        if ev.msg.xid in self.send_msg_xids:
            self.rcv_msgs.append(ev.msg)
            if self.waiter:
                self.waiter.set()
                hub.sleep(0)


class OpenFlowSw(object):
    def __init__(self, dp, logger):
        super(OpenFlowSw, self).__init__()
        self.dp = dp
        self.logger = logger

    def _send_msg(self, msg):
        if isinstance(self.dp, DummyDatapath):
            raise TestError(STATE_DISCONNECTED)
        msg.xid = None
        self.dp.set_xid(msg)
        self.dp.send_msg(msg)
        return msg.xid

    def add_flow(self, flow_mod=None, in_port=None, out_port=None):
        """ Add flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser

        if flow_mod:
            mod = flow_mod
        else:
            match = parser.OFPMatch(in_port=in_port)
            max_len = (0 if out_port != ofp.OFPP_CONTROLLER
                       else ofp.OFPCML_MAX)
            actions = [parser.OFPActionOutput(out_port, max_len)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(self.dp, cookie=0,
                                    command=ofp.OFPFC_ADD,
                                    match=match, instructions=inst)
        return self._send_msg(mod)

    def send_barrier_request(self):
        """ send a BARRIER_REQUEST message."""
        parser = self.dp.ofproto_parser
        req = parser.OFPBarrierRequest(self.dp)
        return self._send_msg(req)

    def send_port_stats(self):
        """ Get port stats."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        flags = 0
        req = parser.OFPPortStatsRequest(self.dp, flags, ofp.OFPP_ANY)
        return self._send_msg(req)

    def send_flow_stats(self):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         0, 0, parser.OFPMatch())
        return self._send_msg(req)


class TargetSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(TargetSw, self).__init__(dp, logger)

    def del_test_flow(self):
        """ Delete all flow except default flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        mod = parser.OFPFlowMod(self.dp,
                                table_id=ofp.OFPTT_ALL,
                                command=ofp.OFPFC_DELETE,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY)
        return self._send_msg(mod)

    def del_test_meter(self):
        """ Delete all meter entries. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        mod = parser.OFPMeterMod(self.dp,
                                 command=ofp.OFPMC_DELETE,
                                 flags=0,
                                 meter_id=ofp.OFPM_ALL)
        return self._send_msg(mod)

    def send_meter_config_stats(self):
        """ Get all meter. """
        parser = self.dp.ofproto_parser
        stats = parser.OFPMeterConfigStatsRequest(self.dp)
        return self._send_msg(stats)

    def send_table_stats(self):
        """ Get table stats. """
        parser = self.dp.ofproto_parser
        req = parser.OFPTableStatsRequest(self.dp, 0)
        return self._send_msg(req)


class TesterSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(TesterSw, self).__init__(dp, logger)

    def del_flows_for_throughput_analysis(self):
        """ Delete all flow except default flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        mod = parser.OFPFlowMod(self.dp,
                                cookie=THROUGHPUT_COOKIE,
                                cookie_mask=0xffffffffffffffff,
                                table_id=ofp.OFPTT_ALL,
                                command=ofp.OFPFC_DELETE,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY)
        return self._send_msg(mod)

    def send_packet_out(self, data):
        """ send a PacketOut message."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(TESTER_SENDER_PORT)]
        out = parser.OFPPacketOut(
            datapath=self.dp, buffer_id=ofp.OFP_NO_BUFFER,
            data=data, in_port=ofp.OFPP_CONTROLLER, actions=actions)
        return self._send_msg(out)


class TestPatterns(dict):
    """ List of Test class objects. """
    def __init__(self, test_dir, logger):
        super(TestPatterns, self).__init__()
        self.logger = logger
        # Parse test pattern from test files.
        self._get_tests(test_dir)

    def _get_tests(self, path):
        if not os.path.exists(path):
            msg = INVALID_PATH % {'path': path}
            self.logger.warning(msg)
            return

        if os.path.isdir(path):  # Directory
            for test_path in os.listdir(path):
                test_path = path + (test_path if path[-1:] == '/'
                                    else '/%s' % test_path)
                self._get_tests(test_path)

        elif os.path.isfile(path):  # File
            (dummy, ext) = os.path.splitext(path)
            if ext == '.json':
                test = TestFile(path, self.logger)
                self[test.description] = test


class TestFile(stringify.StringifyMixin):
    """Test File object include Test objects."""
    def __init__(self, path, logger):
        super(TestFile, self).__init__()
        self.logger = logger
        self.description = None
        self.tests = []
        self._get_tests(path)

    def _get_tests(self, path):
        with open(path, 'rb') as fhandle:
            buf = fhandle.read()
            try:
                json_list = json.loads(buf)
                for test_json in json_list:
                    if isinstance(test_json, unicode):
                        self.description = test_json
                    else:
                        self.tests.append(Test(test_json))
            except (ValueError, TypeError) as e:
                result = (TEST_FILE_ERROR %
                          {'file': path, 'detail': e.message})
                self.logger.warning(result)


class Test(stringify.StringifyMixin):
    def __init__(self, test_json):
        super(Test, self).__init__()
        (self.description,
         self.prerequisite,
         self.tests) = self._parse_test(test_json)

    def _parse_test(self, buf):
        def __test_pkt_from_json(test):
            data = eval('/'.join(test))
            data.serialize()
            return str(data.data)

        # parse 'description'
        description = buf.get(KEY_DESC)

        # parse 'prerequisite'
        prerequisite = []
        if not KEY_PREREQ in buf:
            raise ValueError('a test requires a "%s" block' % KEY_PREREQ)
        allowed_mod = [KEY_FLOW, KEY_METER]
        for flow in buf[KEY_PREREQ]:
            key, value = flow.popitem()
            if key not in allowed_mod:
                raise ValueError(
                    '"%s" block allows only the followings: %s' % (
                        KEY_PREREQ, allowed_mod))
            cls = getattr(ofproto_v1_3_parser, key)
            msg = cls.from_jsondict(value, datapath=DummyDatapath())
            msg.version = ofproto_v1_3.OFP_VERSION
            msg.msg_type = msg.cls_msg_type
            msg.xid = 0
            prerequisite.append(msg)

        # parse 'tests'
        tests = []
        if not KEY_TESTS in buf:
            raise ValueError('a test requires a "%s" block.' % KEY_TESTS)

        for test in buf[KEY_TESTS]:
            if len(test) != 2:
                raise ValueError(
                    '"%s" block requires "%s" field and one of "%s" or "%s"'
                    ' or "%s" field.' % (KEY_TESTS, KEY_INGRESS, KEY_EGRESS,
                                         KEY_PKT_IN, KEY_TBL_MISS))
            test_pkt = {}
            # parse 'ingress'
            if not KEY_INGRESS in test:
                raise ValueError('a test requires "%s" field.' % KEY_INGRESS)
            if isinstance(test[KEY_INGRESS], list):
                test_pkt[KEY_INGRESS] = __test_pkt_from_json(test[KEY_INGRESS])
            elif isinstance(test[KEY_INGRESS], dict):
                test_pkt[KEY_PACKETS] = {
                    KEY_DATA: __test_pkt_from_json(
                        test[KEY_INGRESS][KEY_PACKETS][KEY_DATA]),
                    KEY_DURATION_TIME: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_DURATION_TIME, DEFAULT_DURATION_TIME),
                    KEY_PKTPS: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_PKTPS, DEFAULT_PKTPS)}
            else:
                raise ValueError('invalid format: "%s" field' % KEY_INGRESS)
            # parse 'egress' or 'PACKET_IN' or 'table-miss'
            if KEY_EGRESS in test:
                if isinstance(test[KEY_EGRESS], list):
                    test_pkt[KEY_EGRESS] = __test_pkt_from_json(
                        test[KEY_EGRESS])
                elif isinstance(test[KEY_EGRESS], dict):
                    throughputs = []
                    for throughput in test[KEY_EGRESS][KEY_THROUGHPUT]:
                        one = {}
                        mod = {'match': {'OFPMatch': throughput[KEY_MATCH]}}
                        cls = getattr(ofproto_v1_3_parser, KEY_FLOW)
                        msg = cls.from_jsondict(
                            mod, datapath=DummyDatapath(),
                            cookie=THROUGHPUT_COOKIE,
                            priority=THROUGHPUT_PRIORITY)
                        one[KEY_FLOW] = msg
                        one[KEY_KBPS] = throughput.get(KEY_KBPS)
                        one[KEY_PKTPS] = throughput.get(KEY_PKTPS)
                        if not bool(one[KEY_KBPS]) != bool(one[KEY_PKTPS]):
                            raise ValueError(
                                '"%s" requires either "%s" or "%s".' % (
                                    KEY_THROUGHPUT, KEY_KBPS, KEY_PKTPS))
                        throughputs.append(one)
                    test_pkt[KEY_THROUGHPUT] = throughputs
                else:
                    raise ValueError('invalid format: "%s" field' % KEY_EGRESS)
            elif KEY_PKT_IN in test:
                test_pkt[KEY_PKT_IN] = __test_pkt_from_json(test[KEY_PKT_IN])
            elif KEY_TBL_MISS in test:
                test_pkt[KEY_TBL_MISS] = test[KEY_TBL_MISS]

            tests.append(test_pkt)

        return (description, prerequisite, tests)


class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
