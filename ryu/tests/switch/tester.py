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

import binascii
import inspect
import json
import logging
import math
import netaddr
import os
import signal
import six
import sys
import time
import traceback
from random import randint

from ryu import cfg
from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import stringify
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5

# import all packet libraries.
PKT_LIB_PATH = 'ryu.lib.packet'
for modname, moddef in sys.modules.items():
    if not modname.startswith(PKT_LIB_PATH) or not moddef:
        continue
    for (clsname, clsdef, ) in inspect.getmembers(moddef):
        if not inspect.isclass(clsdef):
            continue
        exec('from %s import %s' % (modname, clsname))


""" Required test network:

                      +-------------------+
           +----------|     target sw     | The switch to be tested
           |          +-------------------+
    +------------+      (1)   (2)   (3)
    | controller |       |     |     |
    +------------+      (1)   (2)   (3)
           |          +-------------------+
           +----------|     tester sw     | OpenFlow Switch
                      +-------------------+

      (X) : port number

    Tests send a packet from port 1 of the tester sw.
    If the packet matched with a flow entry of the target sw,
     the target sw resends the packet from port 2 (or the port which
     connected with the controller), according to the flow entry.
    Then the tester sw receives the packet and sends a PacketIn message.
    If the packet did not match, the target sw drops the packet.

    If you want to use the other port number which differ from above chart,
    you can specify the port number in the options when this tool is started.
    For details of this options, please refer to the Help command.
    Also, if you describe the name of an option argument
    (e.g. "target_send_port_1") in test files,
    this tool sets the argument value in the port number.

        e.g.)
            "OFPActionOutput":{
                "port":"target_send_port_1"
            }

"""


CONF = cfg.CONF


# Default settings.
INTERVAL = 1  # sec
WAIT_TIMER = 3  # sec
CONTINUOUS_THREAD_INTVL = float(0.01)  # sec
CONTINUOUS_PROGRESS_SPAN = 3  # sec
THROUGHPUT_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY + 1
THROUGHPUT_COOKIE = THROUGHPUT_PRIORITY
THROUGHPUT_THRESHOLD = float(0.10)  # expected throughput plus/minus 10 %

# Default settings for 'ingress: packets'
DEFAULT_DURATION_TIME = 30
DEFAULT_PKTPS = 1000

# Test file format.
KEY_DESC = 'description'
KEY_PREREQ = 'prerequisite'
KEY_FLOW = 'OFPFlowMod'
KEY_METER = 'OFPMeterMod'
KEY_GROUP = 'OFPGroupMod'
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
STATE_THROUGHPUT_CHK = 17
STATE_INIT_GROUP = 18
STATE_GROUP_INSTALL = 19
STATE_GROUP_EXIST_CHK = 20

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
       STATE_GROUP_INSTALL:
       {TIMEOUT: 'Failed to add groups: barrier request timeout.',
        RCV_ERR: 'Failed to add groups: %(err_msg)s'},
       STATE_FLOW_EXIST_CHK:
       {FAILURE: 'Added incorrect flows: %(flows)s',
        TIMEOUT: 'Failed to add flows: flow stats request timeout.',
        RCV_ERR: 'Failed to add flows: %(err_msg)s'},
       STATE_METER_EXIST_CHK:
       {FAILURE: 'Added incorrect meters: %(meters)s',
        TIMEOUT: 'Failed to add meters: meter config stats request timeout.',
        RCV_ERR: 'Failed to add meters: %(err_msg)s'},
       STATE_GROUP_EXIST_CHK:
       {FAILURE: 'Added incorrect groups: %(groups)s',
        TIMEOUT: 'Failed to add groups: group desc stats request timeout.',
        RCV_ERR: 'Failed to add groups: %(err_msg)s'},
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
       {TIMEOUT: 'Failed to send packet: barrier request timeout.',
        RCV_ERR: 'Failed to send packet: %(err_msg)s'},
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
       STATE_THROUGHPUT_CHK:
       {FAILURE: 'Received unexpected throughput: %(detail)s'},
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

    tester_ver = None
    target_ver = None

    def __init__(self):
        super(OfTester, self).__init__()
        self._set_logger()

        self.interval = CONF['test-switch']['interval']
        self.target_dpid = self._convert_dpid(CONF['test-switch']['target'])
        self.target_send_port_1 = CONF['test-switch']['target_send_port_1']
        self.target_send_port_2 = CONF['test-switch']['target_send_port_2']
        self.target_recv_port = CONF['test-switch']['target_recv_port']
        self.tester_dpid = self._convert_dpid(CONF['test-switch']['tester'])
        self.tester_send_port = CONF['test-switch']['tester_send_port']
        self.tester_recv_port_1 = CONF['test-switch']['tester_recv_port_1']
        self.tester_recv_port_2 = CONF['test-switch']['tester_recv_port_2']
        self.logger.info('target_dpid=%s',
                         dpid_lib.dpid_to_str(self.target_dpid))
        self.logger.info('tester_dpid=%s',
                         dpid_lib.dpid_to_str(self.tester_dpid))

        def __get_version(opt):
            vers = {
                'openflow10': ofproto_v1_0.OFP_VERSION,
                'openflow13': ofproto_v1_3.OFP_VERSION,
                'openflow14': ofproto_v1_4.OFP_VERSION,
                'openflow15': ofproto_v1_5.OFP_VERSION
            }
            ver = vers.get(opt.lower())
            if ver is None:
                self.logger.error(
                    '%s is not supported. '
                    'Supported versions are %s.',
                    opt, list(vers.keys()))
                self._test_end()
            return ver

        target_opt = CONF['test-switch']['target_version']
        self.logger.info('target ofp version=%s', target_opt)
        OfTester.target_ver = __get_version(target_opt)
        tester_opt = CONF['test-switch']['tester_version']
        self.logger.info('tester ofp version=%s', tester_opt)
        OfTester.tester_ver = __get_version(tester_opt)
        # set app_supported_versions later.
        ofproto_protocol.set_app_supported_versions(
            [OfTester.target_ver, OfTester.tester_ver])

        test_dir = CONF['test-switch']['dir']
        self.logger.info('Test files directory = %s', test_dir)

        self.target_sw = OpenFlowSw(DummyDatapath(), self.logger)
        self.tester_sw = OpenFlowSw(DummyDatapath(), self.logger)
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
            return int(dpid_str, 16)
        except ValueError as err:
            self.logger.error('Invarid dpid parameter. %s', err)
            self._test_end()

    def close(self):
        if self.test_thread is not None:
            hub.kill(self.test_thread)
        if self.ingress_event:
            self.ingress_event.set()
        hub.joinall([self.test_thread])
        self._test_end('--- Test terminated ---')

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispatcher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self._register_sw(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self._unregister_sw(ev.datapath)

    def _register_sw(self, dp):
        vers = {
            ofproto_v1_0.OFP_VERSION: 'openflow10',
            ofproto_v1_3.OFP_VERSION: 'openflow13',
            ofproto_v1_4.OFP_VERSION: 'openflow14',
            ofproto_v1_5.OFP_VERSION: 'openflow15'
        }
        if dp.id == self.target_dpid:
            if dp.ofproto.OFP_VERSION != OfTester.target_ver:
                msg = 'Join target SW, but ofp version is not %s.' % \
                    vers[OfTester.target_ver]
            else:
                self.target_sw.dp = dp
                msg = 'Join target SW.'
        elif dp.id == self.tester_dpid:
            if dp.ofproto.OFP_VERSION != OfTester.tester_ver:
                msg = 'Join tester SW, but ofp version is not %s.' % \
                    vers[OfTester.tester_ver]
            else:
                self.tester_sw.dp = dp
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
        test_keys = list(tests.keys())
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
            hub.sleep(self.interval)
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
            self._test(STATE_INIT_GROUP)
            self._test(STATE_INIT_FLOW, self.target_sw)
            self._test(STATE_INIT_THROUGHPUT_FLOW, self.tester_sw)

            # Install flows.
            for flow in test.prerequisite:
                if isinstance(
                        flow, self.target_sw.dp.ofproto_parser.OFPFlowMod):
                    self._test(STATE_FLOW_INSTALL, self.target_sw, flow)
                    self._test(STATE_FLOW_EXIST_CHK,
                               self.target_sw.send_flow_stats, flow)
                elif isinstance(
                        flow, self.target_sw.dp.ofproto_parser.OFPMeterMod):
                    self._test(STATE_METER_INSTALL, self.target_sw, flow)
                    self._test(STATE_METER_EXIST_CHK,
                               self.target_sw.send_meter_config_stats, flow)
                elif isinstance(
                        flow, self.target_sw.dp.ofproto_parser.OFPGroupMod):
                    self._test(STATE_GROUP_INSTALL, self.target_sw, flow)
                    self._test(STATE_GROUP_EXIST_CHK,
                               self.target_sw.send_group_desc_stats, flow)
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
                                   self.tester_sw.send_flow_stats, flow)
                    start = self._test(STATE_GET_THROUGHPUT)
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
                elif KEY_THROUGHPUT in pkt:
                    end = self._test(STATE_GET_THROUGHPUT)
                    self._test(STATE_THROUGHPUT_CHK, pkt[KEY_THROUGHPUT],
                               start, end)
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
        finally:
            self.ingress_event = None
            for tid in self.ingress_threads:
                hub.kill(tid)
            self.ingress_threads = []

        # Output test result.
        self.logger.info('    %-100s %s', test.description, result[0])
        if 1 < len(result):
            self.logger.info('        %s', result[1])
            if result[1] == RYU_INTERNAL_ERROR\
                    or result == 'An unknown exception':
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
        error_count = 0
        for result_type in sorted(list(report.keys())):
            test_descriptions = report[result_type]
            if result_type == TEST_OK:
                continue
            error_count += len(test_descriptions)
            self.logger.info('%s(%d)', result_type, len(test_descriptions))
            for file_desc, test_desc in test_descriptions:
                self.logger.info('    %-40s %s', file_desc, test_desc)
        self.logger.info('%s%s(%d) / %s(%d)', os.linesep,
                         TEST_OK, len(report.get(TEST_OK, [])),
                         TEST_ERROR, error_count)

    def _test(self, state, *args):
        test = {STATE_INIT_FLOW: self._test_initialize_flow,
                STATE_INIT_THROUGHPUT_FLOW: self._test_initialize_flow,
                STATE_INIT_METER: self.target_sw.del_meters,
                STATE_INIT_GROUP: self.target_sw.del_groups,
                STATE_FLOW_INSTALL: self._test_msg_install,
                STATE_THROUGHPUT_FLOW_INSTALL: self._test_msg_install,
                STATE_METER_INSTALL: self._test_msg_install,
                STATE_GROUP_INSTALL: self._test_msg_install,
                STATE_FLOW_EXIST_CHK: self._test_exist_check,
                STATE_THROUGHPUT_FLOW_EXIST_CHK: self._test_exist_check,
                STATE_METER_EXIST_CHK: self._test_exist_check,
                STATE_GROUP_EXIST_CHK: self._test_exist_check,
                STATE_TARGET_PKT_COUNT: self._test_get_packet_count,
                STATE_TESTER_PKT_COUNT: self._test_get_packet_count,
                STATE_FLOW_MATCH_CHK: self._test_flow_matching_check,
                STATE_NO_PKTIN_REASON: self._test_no_pktin_reason_check,
                STATE_GET_MATCH_COUNT: self._test_get_match_count,
                STATE_SEND_BARRIER: self._test_send_barrier,
                STATE_FLOW_UNMATCH_CHK: self._test_flow_unmatching_check,
                STATE_GET_THROUGHPUT: self._test_get_throughput,
                STATE_THROUGHPUT_CHK: self._test_throughput_check}

        self.send_msg_xids = []
        self.rcv_msgs = []

        self.state = state
        return test[state](*args)

    def _test_initialize_flow(self, datapath):
        # Note: Because DELETE and DELETE_STRICT commands in OpenFlow 1.0
        # can not be filtered by the cookie value, this tool deletes all
        # flow entries of the tester switch temporarily and inserts default
        # flow entry immediately.
        xid = datapath.del_flows()
        self.send_msg_xids.append(xid)

        xid = datapath.add_flow(
            in_port=self.tester_recv_port_1,
            out_port=datapath.dp.ofproto.OFPP_CONTROLLER)
        self.send_msg_xids.append(xid)

        xid = datapath.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, datapath.dp.ofproto_parser.OFPBarrierReply)

    def _test_msg_install(self, datapath, message):
        xid = datapath.send_msg(message)
        self.send_msg_xids.append(xid)

        xid = datapath.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, datapath.dp.ofproto_parser.OFPBarrierReply)

    def _test_exist_check(self, method, message):
        ofp = method.__self__.dp.ofproto
        parser = method.__self__.dp.ofproto_parser
        method_dict = {
            OpenFlowSw.send_flow_stats.__name__: {
                'reply': parser.OFPFlowStatsReply,
                'compare': self._compare_flow
            }
        }
        if ofp.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            method_dict[OpenFlowSw.send_group_desc_stats.__name__] = {
                'reply': parser.OFPGroupDescStatsReply,
                'compare': self._compare_group
            }
        if ofp.OFP_VERSION >= ofproto_v1_3.OFP_VERSION:
            method_dict[OpenFlowSw.send_meter_config_stats.__name__] = {
                'reply': parser.OFPMeterConfigStatsReply,
                'compare': self._compare_meter
            }
        xid = method()
        self.send_msg_xids.append(xid)
        self._wait()

        ng_stats = []
        for msg in self.rcv_msgs:
            assert isinstance(msg, method_dict[method.__name__]['reply'])
            for stats in msg.body:
                result, stats = method_dict[method.__name__]['compare'](
                    stats, message)
                if result:
                    return
                else:
                    ng_stats.append(stats)

        error_dict = {
            OpenFlowSw.send_flow_stats.__name__: {
                'flows': ', '.join(ng_stats)
            }
        }
        if ofp.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            error_dict[OpenFlowSw.send_group_desc_stats.__name__] = {
                'groups': ', '.join(ng_stats)
            }
        if ofp.OFP_VERSION >= ofproto_v1_3.OFP_VERSION:
            error_dict[OpenFlowSw.send_meter_config_stats.__name__] = {
                'meters': ', '.join(ng_stats)
            }
        raise TestFailure(self.state, **error_dict[method.__name__])

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
        # Compare a received message with OFPPacketIn
        #
        # We compare names of classes instead of classes themselves
        # due to OVS bug. The code below should be as follows:
        #
        # assert isinstance(msg, msg.datapath.ofproto_parser.OFPPacketIn)
        #
        # At this moment, OVS sends Packet-In messages of of13 even if
        # OVS is configured to use of14, so the above code causes an
        # assertion.
        assert msg.__class__.__name__ == 'OFPPacketIn'
        self.logger.debug("dpid=%s : receive_packet[%s]",
                          dpid_lib.dpid_to_str(msg.datapath.id),
                          packet.Packet(msg.data))

        # check the SW which sended PacketIn and output packet.
        pkt_in_src_model = (self.tester_sw if KEY_EGRESS in pkt
                            else self.target_sw)
        model_pkt = (pkt[KEY_EGRESS] if KEY_EGRESS in pkt
                     else pkt[KEY_PKT_IN])

        if hasattr(msg.datapath.ofproto, "OFPR_NO_MATCH"):
            invalid_packet_in_reason = [msg.datapath.ofproto.OFPR_NO_MATCH]
        else:
            invalid_packet_in_reason = [msg.datapath.ofproto.OFPR_TABLE_MISS]
        if hasattr(msg.datapath.ofproto, "OFPR_INVALID_TTL"):
            invalid_packet_in_reason.append(
                msg.datapath.ofproto.OFPR_INVALID_TTL)

        if msg.datapath.id != pkt_in_src_model.dp.id:
            pkt_type = 'packet-in'
            err_msg = 'SW[dpid=%s]' % dpid_lib.dpid_to_str(msg.datapath.id)
        elif msg.reason in invalid_packet_in_reason:
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
        before_target_receive = target_pkt_count[
            0][self.target_recv_port]['rx']
        before_target_send = target_pkt_count[0][self.target_send_port_1]['tx']
        before_tester_receive = tester_pkt_count[
            0][self.tester_recv_port_1]['rx']
        before_tester_send = tester_pkt_count[0][self.tester_send_port]['tx']
        after_target_receive = target_pkt_count[1][self.target_recv_port]['rx']
        after_target_send = target_pkt_count[1][self.target_send_port_1]['tx']
        after_tester_receive = tester_pkt_count[
            1][self.tester_recv_port_1]['rx']
        after_tester_send = tester_pkt_count[1][self.tester_send_port]['tx']

        if after_tester_send == before_tester_send:
            log_msg = 'no change in tx_packets on tester.'
        elif after_target_receive == before_target_receive:
            log_msg = 'no change in rx_packets on target.'
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
        assert isinstance(
            msg, self.tester_sw.dp.ofproto_parser.OFPBarrierReply)

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

        pkt_text = pkt[KEY_PACKETS]['packet_text']
        pkt_bin = pkt[KEY_PACKETS]['packet_binary']
        pktps = pkt[KEY_PACKETS][KEY_PKTPS]
        duration_time = pkt[KEY_PACKETS][KEY_DURATION_TIME]
        randomize = pkt[KEY_PACKETS]['randomize']

        self.logger.debug("send_packet:[%s]", packet.Packet(pkt_bin))
        self.logger.debug("pktps:[%d]", pktps)
        self.logger.debug("duration_time:[%d]", duration_time)

        arg = {'packet_text': pkt_text,
               'packet_binary': pkt_bin,
               'thread_counter': 0,
               'dot_span': int(CONTINUOUS_PROGRESS_SPAN /
                               CONTINUOUS_THREAD_INTVL),
               'packet_counter': float(0),
               'packet_counter_inc': pktps * CONTINUOUS_THREAD_INTVL,
               'randomize': randomize}

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
            if arg['randomize']:
                msg = eval('/'.join(arg['packet_text']))
                msg.serialize()
                data = msg.data
            else:
                data = arg['packet_binary']
            try:
                self.tester_sw.send_packet_out(data)
            except Exception as err:
                self.thread_msg = err
                self.ingress_event.set()
                break

    def _compare_flow(self, stats1, stats2):

        def __reasm_match(match):
            """ reassemble match_fields. """
            match_fields = match.to_jsondict()
            # For only OpenFlow1.0
            match_fields['OFPMatch'].pop('wildcards', None)
            return match_fields

        attr_list = ['cookie', 'priority', 'hard_timeout', 'idle_timeout',
                     'match']
        if self.target_sw.dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            attr_list += ['actions']
        else:
            attr_list += ['table_id', 'instructions']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if attr in ['actions', 'instructions']:
                value1 = sorted(value1, key=lambda x: x.type)
                value2 = sorted(value2, key=lambda x: x.type)
            elif attr == 'match':
                value1 = __reasm_match(value1)
                value2 = __reasm_match(value2)
            if str(value1) != str(value2):
                return False, 'flow_stats(%s != %s)' % (value1, value2)
        return True, None

    @classmethod
    def _compare_meter(cls, stats1, stats2):
        """compare the message used to install and the message got from
           the switch."""
        attr_list = ['flags', 'meter_id', 'bands']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if str(value1) != str(value2):
                return False, 'meter_stats(%s != %s)' % (value1, value2)
        return True, None

    @classmethod
    def _compare_group(cls, stats1, stats2):
        attr_list = ['type', 'group_id', 'buckets']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if str(value1) != str(value2):
                return False, 'group_stats(%s != %s)' % (value1, value2)
            return True, None

    @classmethod
    def _diff_packets(cls, model_pkt, rcv_pkt):
        msg = []
        for rcv_p in rcv_pkt.protocols:
            if not isinstance(rcv_p, six.binary_type):
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
                    if isinstance(p, six.binary_type):
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
        return time.time(), result

    def _test_throughput_check(self, throughputs, start, end):
        msgs = []
        elapsed_sec = end[0] - start[0]

        for throughput in throughputs:
            match = str(throughput[KEY_FLOW].match)
            # get oxm_fields of OFPMatch
            fields = dict(throughput[KEY_FLOW].match._fields2)

            if match not in start[1] or match not in end[1]:
                raise TestError(self.state, match=match)
            increased_bytes = end[1][match][0] - start[1][match][0]
            increased_packets = end[1][match][1] - start[1][match][1]

            if throughput[KEY_PKTPS]:
                key = KEY_PKTPS
                conv = 1
                measured_value = increased_packets
                unit = 'pktps'
            elif throughput[KEY_KBPS]:
                key = KEY_KBPS
                conv = 1024 / 8  # Kilobits -> bytes
                measured_value = increased_bytes
                unit = 'kbps'
            else:
                raise RyuException(
                    'An invalid key exists that is neither "%s" nor "%s".'
                    % (KEY_KBPS, KEY_PKTPS))

            expected_value = throughput[key] * elapsed_sec * conv
            margin = expected_value * THROUGHPUT_THRESHOLD
            self.logger.debug("measured_value:[%s]", measured_value)
            self.logger.debug("expected_value:[%s]", expected_value)
            self.logger.debug("margin:[%s]", margin)
            if math.fabs(measured_value - expected_value) > margin:
                msgs.append('{0} {1:.2f}{2}'.format(fields,
                            measured_value / elapsed_sec / conv, unit))

        if msgs:
            raise TestFailure(self.state, detail=', '.join(msgs))

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
                self.rcv_msgs[0],
                self.rcv_msgs[0].datapath.ofproto_parser.OFPErrorMsg)):
            raise TestReceiveError(self.state, self.rcv_msgs[0])

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPMeterConfigStatsReply,
                 ofp_event.EventOFPTableStatsReply,
                 ofp_event.EventOFPPortStatsReply,
                 ofp_event.EventOFPGroupDescStatsReply],
                handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        # keys: stats reply event classes
        # values: states in which the events should be processed
        ofp = ev.msg.datapath.ofproto
        event_states = {
            ofp_event.EventOFPFlowStatsReply:
                [STATE_FLOW_EXIST_CHK,
                 STATE_THROUGHPUT_FLOW_EXIST_CHK,
                 STATE_GET_THROUGHPUT],
            ofp_event.EventOFPTableStatsReply:
                [STATE_GET_MATCH_COUNT,
                 STATE_FLOW_UNMATCH_CHK],
            ofp_event.EventOFPPortStatsReply:
                [STATE_TARGET_PKT_COUNT,
                 STATE_TESTER_PKT_COUNT],
        }
        if ofp.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            event_states[ofp_event.EventOFPGroupDescStatsReply] = [
                STATE_GROUP_EXIST_CHK
            ]
        if ofp.OFP_VERSION >= ofproto_v1_3.OFP_VERSION:
            event_states[ofp_event.EventOFPMeterConfigStatsReply] = [
                STATE_METER_EXIST_CHK
            ]
        if self.state in event_states[ev.__class__]:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, handler.MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        state_list = [STATE_INIT_FLOW,
                      STATE_INIT_THROUGHPUT_FLOW,
                      STATE_INIT_METER,
                      STATE_INIT_GROUP,
                      STATE_FLOW_INSTALL,
                      STATE_THROUGHPUT_FLOW_INSTALL,
                      STATE_METER_INSTALL,
                      STATE_GROUP_INSTALL,
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
        self.tester_send_port = CONF['test-switch']['tester_send_port']

    def send_msg(self, msg):
        if isinstance(self.dp, DummyDatapath):
            raise TestError(STATE_DISCONNECTED)
        msg.xid = None
        self.dp.set_xid(msg)
        self.dp.send_msg(msg)
        return msg.xid

    def add_flow(self, in_port=None, out_port=None):
        """ Add flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)
        actions = [parser.OFPActionOutput(out_port)]
        if ofp.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            mod = parser.OFPFlowMod(
                self.dp, match=match, cookie=0, command=ofp.OFPFC_ADD,
                actions=actions)
        else:
            inst = [parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                self.dp, cookie=0, command=ofp.OFPFC_ADD, match=match,
                instructions=inst)
        return self.send_msg(mod)

    def del_flows(self, cookie=0):
        """
        Delete all flow except default flow by using the cookie value.

        Note: In OpenFlow 1.0, DELETE and DELETE_STRICT commands can
        not be filtered by the cookie value and this value is ignored.
        """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        cookie_mask = 0
        if cookie:
            cookie_mask = 0xffffffffffffffff
        if ofp.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            match = parser.OFPMatch()
            mod = parser.OFPFlowMod(self.dp, match, cookie, ofp.OFPFC_DELETE)
        else:
            mod = parser.OFPFlowMod(
                self.dp, cookie=cookie, cookie_mask=cookie_mask,
                table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
        return self.send_msg(mod)

    def del_meters(self):
        """ Delete all meter entries. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        if ofp.OFP_VERSION < ofproto_v1_3.OFP_VERSION:
            return None
        mod = parser.OFPMeterMod(self.dp,
                                 command=ofp.OFPMC_DELETE,
                                 flags=0,
                                 meter_id=ofp.OFPM_ALL)
        return self.send_msg(mod)

    def del_groups(self):
        """ Delete all group entries. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        if ofp.OFP_VERSION < ofproto_v1_2.OFP_VERSION:
            return None
        mod = parser.OFPGroupMod(self.dp,
                                 command=ofp.OFPGC_DELETE,
                                 type_=0,
                                 group_id=ofp.OFPG_ALL)
        return self.send_msg(mod)

    def send_barrier_request(self):
        """ send a BARRIER_REQUEST message."""
        parser = self.dp.ofproto_parser
        req = parser.OFPBarrierRequest(self.dp)
        return self.send_msg(req)

    def send_port_stats(self):
        """ Get port stats."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        flags = 0
        if ofp.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            port = ofp.OFPP_NONE
        else:
            port = ofp.OFPP_ANY
        req = parser.OFPPortStatsRequest(self.dp, flags, port)
        return self.send_msg(req)

    def send_flow_stats(self):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        if ofp.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            req = parser.OFPFlowStatsRequest(
                self.dp, 0, parser.OFPMatch(), 0xff, ofp.OFPP_NONE)
        else:
            req = parser.OFPFlowStatsRequest(
                self.dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
                0, 0, parser.OFPMatch())
        return self.send_msg(req)

    def send_meter_config_stats(self):
        """ Get all meter. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        if ofp.OFP_VERSION < ofproto_v1_3.OFP_VERSION:
            return None
        stats = parser.OFPMeterConfigStatsRequest(self.dp)
        return self.send_msg(stats)

    def send_group_desc_stats(self):
        """ Get all group. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        if ofp.OFP_VERSION < ofproto_v1_2.OFP_VERSION:
            return None
        stats = parser.OFPGroupDescStatsRequest(self.dp)
        return self.send_msg(stats)

    def send_table_stats(self):
        """ Get table stats. """
        parser = self.dp.ofproto_parser
        req = parser.OFPTableStatsRequest(self.dp, 0)
        return self.send_msg(req)

    def send_packet_out(self, data):
        """ send a PacketOut message."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(self.tester_send_port)]
        out = parser.OFPPacketOut(
            datapath=self.dp, buffer_id=ofp.OFP_NO_BUFFER,
            data=data, in_port=ofp.OFPP_CONTROLLER, actions=actions)
        return self.send_msg(out)


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

    def _normalize_test_json(self, val):
        def __replace_port_name(k, v):
            for port_name in [
                'target_recv_port', 'target_send_port_1',
                'target_send_port_2', 'tester_send_port',
                    'tester_recv_port_1', 'tester_recv_port_2']:
                if v[k] == port_name:
                    v[k] = CONF['test-switch'][port_name]
        if isinstance(val, dict):
            for k, v in val.items():
                if k == "OFPActionOutput":
                    if 'port' in v:
                        __replace_port_name("port", v)
                elif k == "OXMTlv":
                    if v.get("field", "") == "in_port":
                        __replace_port_name("value", v)
                self._normalize_test_json(v)
        elif isinstance(val, list):
            for v in val:
                self._normalize_test_json(v)

    def _get_tests(self, path):
        with open(path, 'r') as fhandle:
            buf = fhandle.read()
            try:
                json_list = json.loads(buf)
                for test_json in json_list:
                    if isinstance(test_json, six.text_type):
                        self.description = test_json
                    else:
                        self._normalize_test_json(test_json)
                        self.tests.append(Test(test_json))
            except (ValueError, TypeError) as e:
                result = (TEST_FILE_ERROR %
                          {'file': path, 'detail': str(e)})
                self.logger.warning(result)


class Test(stringify.StringifyMixin):
    def __init__(self, test_json):
        super(Test, self).__init__()
        (self.description,
         self.prerequisite,
         self.tests) = self._parse_test(test_json)

    @classmethod
    def _parse_test(cls, buf):
        def __test_pkt_from_json(test):
            data = eval('/'.join(test))
            data.serialize()
            return six.binary_type(data.data)

        # create Datapath instance using user-specified versions
        target_dp = DummyDatapath(OfTester.target_ver)
        tester_dp = DummyDatapath(OfTester.tester_ver)

        # parse 'description'
        description = buf.get(KEY_DESC)

        # parse 'prerequisite'
        prerequisite = []
        if KEY_PREREQ not in buf:
            raise ValueError('a test requires a "%s" block' % KEY_PREREQ)
        for flow in buf[KEY_PREREQ]:
            msg = ofproto_parser.ofp_msg_from_jsondict(
                target_dp, flow)
            msg.serialize()
            prerequisite.append(msg)

        # parse 'tests'
        tests = []
        if KEY_TESTS not in buf:
            raise ValueError('a test requires a "%s" block.' % KEY_TESTS)

        for test in buf[KEY_TESTS]:
            if len(test) != 2:
                raise ValueError(
                    '"%s" block requires "%s" field and one of "%s" or "%s"'
                    ' or "%s" field.' % (KEY_TESTS, KEY_INGRESS, KEY_EGRESS,
                                         KEY_PKT_IN, KEY_TBL_MISS))
            test_pkt = {}
            # parse 'ingress'
            if KEY_INGRESS not in test:
                raise ValueError('a test requires "%s" field.' % KEY_INGRESS)
            if isinstance(test[KEY_INGRESS], list):
                test_pkt[KEY_INGRESS] = __test_pkt_from_json(test[KEY_INGRESS])
            elif isinstance(test[KEY_INGRESS], dict):
                test_pkt[KEY_PACKETS] = {
                    'packet_text': test[KEY_INGRESS][KEY_PACKETS][KEY_DATA],
                    'packet_binary': __test_pkt_from_json(
                        test[KEY_INGRESS][KEY_PACKETS][KEY_DATA]),
                    KEY_DURATION_TIME: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_DURATION_TIME, DEFAULT_DURATION_TIME),
                    KEY_PKTPS: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_PKTPS, DEFAULT_PKTPS),
                    'randomize': True in [
                        line.find('randint') != -1
                        for line in test[KEY_INGRESS][KEY_PACKETS][KEY_DATA]]}
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
                        mod = {
                            "OFPFlowMod": {
                                'cookie': THROUGHPUT_COOKIE,
                                'priority': THROUGHPUT_PRIORITY,
                                'match': {
                                    'OFPMatch': throughput[KEY_MATCH]
                                }
                            }
                        }
                        msg = ofproto_parser.ofp_msg_from_jsondict(
                            tester_dp, mod)
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

        return description, prerequisite, tests


class DummyDatapath(ofproto_protocol.ProtocolDesc):
    def __init__(self, version=None):
        super(DummyDatapath, self).__init__(version)

    def set_xid(self, _):
        pass

    def send_msg(self, _):
        pass
