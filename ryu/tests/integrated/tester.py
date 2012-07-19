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
import gflags
import logging
import subprocess
import traceback

from ryu import utils
from ryu.lib import mac
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dispatcher
from ryu.controller import event
from ryu.controller import handler
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2


LOG = logging.getLogger(__name__)

FLAGS = gflags.FLAGS
gflags.DEFINE_string('run_test_mod', '', 'Test run the module name.')


class EventRunTest(event.EventBase):
    def __init__(self, datapath):
        super(EventRunTest, self).__init__()
        self.datapath = datapath


QUEUE_NAME_RUN_TEST_EV = 'run_test_event'
DISPATCHER_NAME_RUN_TEST_EV = 'run_test_event'
RUN_TEST_EV_DISPATCHER = dispatcher.EventDispatcher(
    DISPATCHER_NAME_RUN_TEST_EV)


LOG_TEST_START = 'TEST_START: %s'
LOG_TEST_RESULTS = 'TEST_RESULTS:'
LOG_TEST_FINISH = 'TEST_FINISHED: Completed=[%s], OK=[%s], NG=[%s]'


class Tester(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(Tester, self).__init__()
        self.ev_q = dispatcher.EventQueue(QUEUE_NAME_RUN_TEST_EV,
                                         RUN_TEST_EV_DISPATCHER)

        run_test_mod = utils.import_module(FLAGS.run_test_mod)
        LOG.debug('import run_test_mod.[%s]', run_test_mod.__name__)

        self.run_test = run_test_mod.RunTest(*args, **kwargs)
        handler.register_instance(self.run_test)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        send_delete_all_flows(datapath)
        datapath.send_barrier()

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_replay_handler(self, ev):
        self.ev_q.queue(EventRunTest(ev.msg.datapath))

    @set_ev_cls(EventRunTest, RUN_TEST_EV_DISPATCHER)
    def run_test_halder(self, ev):
        dp = ev.datapath
        t = self.run_test

        if not t._test_started():
            t._test_init(dp)

        if not self._run_test(t):
            # run_test was throwing exception.
            LOG.info(LOG_TEST_FINISH, False, t._RESULTS_OK, t._RESULTS_NG)
            return

        if not t._test_completed():
            t.datapath.send_barrier()
            return

        # Completed all tests.
        LOG.info(LOG_TEST_FINISH, True, t._RESULTS_OK, t._RESULTS_NG)

    def _run_test(self, t):
        running = t._running()

        if len(running) == 0:
            # next test
            name = t._pop_test()
            LOG.info(LOG_TEST_START, name)
            try:
                getattr(t, name)()
            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_exception(exc_type, exc_value,
                                          exc_traceback, file=sys.stdout)
                send_delete_all_flows(t.datapath)
                return False
        else:
            # check
            name = 'check_' + running[5:]

            if not name in dir(t):
                name = '_check_default'

            err = 0
            try:
                # LOG.debug('_run_test: CHECK_TEST = [%s]', name)
                getattr(t, name)()
            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_exception(exc_type, exc_value,
                                          exc_traceback, file=sys.stdout)
                err = 1
            finally:
                send_delete_all_flows(t.datapath)
                if err:
                    return False
            t._check_run()

        return True


def _send_delete_all_flows_v10(dp):
    rule = nx_match.ClsRule()
    match = dp.ofproto_parser.OFPMatch(dp.ofproto.OFPFW_ALL,
                                       0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0)
    m = dp.ofproto_parser.OFPFlowMod(
                                     dp, match, 0,
                                     dp.ofproto.OFPFC_DELETE,
                                     0, 0, 0, 0,
                                     dp.ofproto.OFPP_NONE, 0, None)
    dp.send_msg(m)


def _send_delete_all_flows_v12(dp):
    match = dp.ofproto_parser.OFPMatch()
    inst = []
    m = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, 0,
                                     dp.ofproto.OFPFC_DELETE,
                                     0, 0, 0, 0,
                                     dp.ofproto.OFPP_ANY, 0xffffffff,
                                     0, match, inst)
    dp.send_msg(m)


def send_delete_all_flows(dp):
    assert dp.ofproto in (ofproto_v1_0, ofproto_v1_2)
    if dp.ofproto == ofproto_v1_0:
        _send_delete_all_flows_v10(dp)
    elif dp.ofproto == ofproto_v1_2:
        _send_delete_all_flows_v12(dp)
    else:
        # this function will be remove.
        dp.send_delete_all_flows()


def run_command(cmd, redirect_output=True, check_exit_code=True, env=None):
    if redirect_output:
        stdout = subprocess.PIPE
    else:
        stdout = None

    proc = subprocess.Popen(cmd, stdout=stdout,
                            stderr=subprocess.STDOUT, env=env)
    output = proc.communicate()[0]

    LOG.debug('Exec command "%s" \n%s', ' '.join(cmd), output)
    if check_exit_code and proc.returncode != 0:
        raise Exception('Command "%s" failed.\n%s' % (' '.join(cmd), output))
    return output


class RunTestBase(object):
    """
    To run the tests is required for the following pair of functions.
        1. test_<test name>()
            To send flows to switch.

        2. check_<test name>() or _check_default()
            To check flows of switch.

    To deal common values to the functions(test_ and check_)
    can use `set_val('name', val)` and `get_val('name')`.
    This values is initialized before the next tests.
    """

    def __init__(self):
        super(RunTestBase, self).__init__()

        self._TEST_STARTED = False
        self._TESTS = []
        self._RUNNING = ''
        self._RESULTS_OK = 0
        self._RESULTS_NG = 0
        self._CHECK = {}

    def _test_started(self):
        return self._TEST_STARTED

    def _test_init(self, dp):
        self.datapath = dp
        self.ofproto = dp.ofproto
        self.ofproto_parser = dp.ofproto_parser

        for name in dir(self):
            if name.startswith("test_"):
                self._TESTS.append(name)
        self._TEST_STARTED = True

    def _test_completed(self):
        if self._TEST_STARTED:
            if len(self._RUNNING) + len(self._TESTS) == 0:
                return True
        return False

    def _pop_test(self):
        self._RUNNING = self._TESTS.pop()
        return self._RUNNING

    def _running(self):
        return self._RUNNING

    def _check_run(self):
        self._RUNNING = ''

    def _check_default(self):
        err = 'function %s() is not found.' % (self._RUNNING, )
        self.results(ret=False, msg=err)

    def results(self, name=None, ret=True, msg=''):
        if not name:
            name = self._RUNNING

        if ret:
            res = 'OK'
            self._RESULTS_OK += 1
        else:
            res = 'NG'
            self._RESULTS_NG += 1

        LOG.info('%s %s [%s] %s', LOG_TEST_RESULTS, name, res, '\n' + msg)

    def set_val(self, name, val):
        self._CHECK[name] = val

    def get_val(self, name):
        return self._CHECK[name]

    def del_val(self, name):
        del self._CHECK[name]

    def del_val_all(self):
        self._CHECK.clear()

    def get_ovs_flows(self, target):
        # flows (return):
        #     [flow1, flow2,...]
        # flow:
        #     {'actions': actions, 'rules': rules}
        #     or {'apply_actions': actions, 'rules': rules}
        #     or {'write_actions': actions, 'rules': rules}
        #     or {'clear_actions': actions, 'rules': rules}
        # actions, rules:
        #     {'<name>': <val>}

        cmd = ('sudo', 'ovs-ofctl', 'dump-flows', target)
        output = run_command(cmd)

        flows = []
        for line in output.splitlines():
            if line.startswith(" "):
                flow = {}
                rules, actions = line.split('actions=')
                rules = self.cnv_list(rules, '=')

                if actions.startswith("apply_actions"):
                    a_name = 'apply_actions'
                    actions = actions[len(a_name) + 1:-1]
                elif actions.startswith("write_actions"):
                    a_name = 'write_actions'
                    actions = actions[len(a_name) + 1:-1]
                elif actions.startswith("clear_actions"):
                    a_name = 'clear_actions'
                    actions = actions[len(a_name) + 1:-1]
                else:
                    a_name = 'actions'
                actions = self.cnv_list(actions, ':')
                flows.append({'rules': rules, a_name: actions, })

        return flows

    def cnv_list(self, tmp, sep):
        list_ = {}
        for p in tmp.split(','):
            if len(p.strip()) == 0:
                continue

            if p.find(sep) > 0:
                name, val = p.strip().split(sep, 1)
            else:
                name = val = p.strip()
            list_[name] = val
        return list_

    def cnv_txt(self, tmp, sep='='):
        return ",".join([(str(x) + sep + str(tmp[x])) for x in tmp if x >= 0])

    def haddr_to_str(self, addr):
        return mac.haddr_to_str(addr)

    def haddr_to_bin(self, string):
        return mac.haddr_to_bin(string)

    def ipv4_to_int(self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = (i << 8) | b
        return i

    def ipv6_to_int(self, string):
        ip = string.split(':')
        assert len(ip) == 8
        return [int(x, 16) for x in ip]
