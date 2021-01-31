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
from socket import error as SocketError

import mock

from ryu.app.ws_topology import WebSocketTopology


class Test_ws_topology(unittest.TestCase):

    def test_when_sock_error(self):
        args = {
            'wsgi': mock.Mock(),
        }
        app = WebSocketTopology(**args)

        rpc_client_mock1 = mock.Mock()
        config = {
            'get_proxy.return_value.event_link_add.side_effect': SocketError,
        }
        rpc_client_mock1.configure_mock(**config)

        rpc_client_mock2 = mock.Mock()

        app.rpc_clients = [
            rpc_client_mock1,
            rpc_client_mock2,
        ]

        ev_mock = mock.Mock()
        app._event_link_add_handler(ev_mock)

        rpc_client_mock1.get_proxy.assert_called_once_with()
        rpc_client_mock2.get_proxy.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
