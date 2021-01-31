# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Stratosphere Inc.
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

try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3

import json
import os
import ssl
import sys
import warnings
import logging
import random
import unittest

from nose.tools import eq_, raises

from ryu.base import app_manager  # To suppress cyclic import
from ryu.controller import controller
from ryu.controller import handler
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_0_parser
hub.patch()


LOG = logging.getLogger('test_controller')


class TestUtils(unittest.TestCase):
    """
    Test cases for utilities defined in controller module.
    """

    def test_split_addr_with_ipv4(self):
        addr, port = controller._split_addr('127.0.0.1:6653')
        eq_('127.0.0.1', addr)
        eq_(6653, port)

    def test_split_addr_with_ipv6(self):
        addr, port = controller._split_addr('[::1]:6653')
        eq_('::1', addr)
        eq_(6653, port)

    @raises(ValueError)
    def test_split_addr_with_invalid_addr(self):
        controller._split_addr('127.0.0.1')

    @raises(ValueError)
    def test_split_addr_with_invalid_ipv4_addr(self):
        controller._split_addr('xxx.xxx.xxx.xxx:6653')

    @raises(ValueError)
    def test_split_addr_with_invalid_ipv6_addr(self):
        controller._split_addr('[::xxxx]:6653')

    @raises(ValueError)
    def test_split_addr_with_non_bracketed_ipv6_addr(self):
        controller._split_addr('::1:6653')


class Test_Datapath(unittest.TestCase):
    """
    Test cases for controller.Datapath
    """

    def _test_ports_accessibility(self, ofproto_parser, msgs_len):
        with mock.patch('ryu.controller.controller.Datapath.set_state'):

            # Ignore warnings
            with warnings.catch_warnings(record=True) as msgs:
                warnings.simplefilter('always')

                # Test target
                sock_mock = mock.Mock()
                addr_mock = mock.Mock()
                dp = controller.Datapath(sock_mock, addr_mock)
                dp.ofproto_parser = ofproto_parser

                # Create
                dp.ports = {}

                # Update
                port_mock = mock.Mock()
                dp.ports[0] = port_mock

                # Read & Delete
                del dp.ports[0]

                self.assertEqual(len(msgs), msgs_len)
                for msg in msgs:
                    self.assertTrue(issubclass(msg.category, UserWarning))

    def test_ports_accessibility_v13(self):
        self._test_ports_accessibility(ofproto_v1_3_parser, 0)

    def test_ports_accessibility_v12(self):
        self._test_ports_accessibility(ofproto_v1_2_parser, 0)

    def test_ports_accessibility_v10(self):
        self._test_ports_accessibility(ofproto_v1_0_parser, 0)

    @mock.patch("ryu.base.app_manager", spec=app_manager)
    def test_recv_loop(self, app_manager_mock):
        # Prepare test data
        test_messages = [
            "4-6-ofp_features_reply.packet",
            "4-14-ofp_echo_reply.packet",
            "4-14-ofp_echo_reply.packet",
            "4-4-ofp_packet_in.packet",
            "4-14-ofp_echo_reply.packet",
            "4-14-ofp_echo_reply.packet",
        ]
        this_dir = os.path.dirname(sys.modules[__name__].__file__)
        packet_data_dir = os.path.join(this_dir, '../../packet_data/of13')
        json_dir = os.path.join(this_dir, '../ofproto/json/of13')

        packet_buf = bytearray()
        expected_json = list()
        for msg in test_messages:
            # Construct the received packet buffer as one packet data in order
            # to test the case of the OpenFlow messages composed in one packet.
            packet_data_file = os.path.join(packet_data_dir, msg)
            packet_buf += open(packet_data_file, 'rb').read()
            json_data_file = os.path.join(json_dir, msg + '.json')
            expected_json.append(json.load(open(json_data_file)))

        # Prepare mock for socket
        class SocketMock(mock.MagicMock):
            buf = bytearray()
            random = None

            def recv(self, bufsize):
                size = self.random.randint(1, bufsize)
                out = self.buf[:size]
                self.buf = self.buf[size:]
                return out

        # Prepare mock
        ofp_brick_mock = mock.MagicMock(spec=app_manager.RyuApp)
        app_manager_mock.lookup_service_brick.return_value = ofp_brick_mock
        sock_mock = SocketMock()
        sock_mock.buf = packet_buf
        sock_mock.random = random.Random('Ryu SDN Framework')
        addr_mock = mock.MagicMock()

        # Prepare test target
        dp = controller.Datapath(sock_mock, addr_mock)
        dp.set_state(handler.MAIN_DISPATCHER)
        ofp_brick_mock.reset_mock()

        # Test
        dp._recv_loop()

        # Assert calls
        output_json = list()
        for call in ofp_brick_mock.send_event_to_observers.call_args_list:
            args, kwargs = call
            ev, state = args
            if not hasattr(ev, 'msg'):
                continue
            output_json.append(ev.msg.to_jsondict())
            self.assertEqual(state, handler.MAIN_DISPATCHER)
            self.assertEqual(kwargs, {})
        self.assertEqual(expected_json, output_json)


class TestOpenFlowController(unittest.TestCase):
    """
    Test cases for OpenFlowController
    """
    @mock.patch("ryu.controller.controller.CONF")
    def _test_ssl(self, this_dir, port, conf_mock):
        conf_mock.ofp_ssl_listen_port = port
        conf_mock.ofp_listen_host = "127.0.0.1"
        conf_mock.ca_certs = None
        conf_mock.ciphers = None
        conf_mock.ctl_cert = os.path.join(this_dir, 'cert.crt')
        conf_mock.ctl_privkey = os.path.join(this_dir, 'cert.key')
        c = controller.OpenFlowController()
        c()

    def test_ssl(self):
        """Tests SSL server functionality."""
        # TODO: TLS version enforcement is necessary to avoid
        # vulnerable versions. Currently, this only tests TLS
        # connectivity.
        this_dir = os.path.dirname(sys.modules[__name__].__file__)
        saved_exception = None
        try:
            ssl_version = ssl.PROTOCOL_TLS
        except AttributeError:
            # For compatibility with older pythons.
            ssl_version = ssl.PROTOCOL_TLSv1
        for i in range(3):
            try:
                # Try a few times as this can fail with EADDRINUSE
                port = random.randint(5000, 10000)
                server = hub.spawn(self._test_ssl, this_dir, port)
                hub.sleep(1)
                client = hub.StreamClient(("127.0.0.1", port),
                                          timeout=5,
                                          ssl_version=ssl_version)
                if client.connect() is not None:
                    break
            except Exception as e:
                saved_exception = e
                continue
            finally:
                try:
                    hub.kill(server)
                except Exception:
                    pass
        else:
            self.fail("Failed to connect: " + str(saved_exception))
