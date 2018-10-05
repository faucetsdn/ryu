# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

"""
OpenFlow related APIs of ryu.controller module.
"""

import netaddr

from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib import ip
from . import ofp_event


_TMP_ADDRESSES = {}


def register_switch_address(addr, interval=None):
    """
    Registers a new address to initiate connection to switch.

    Registers a new IP address and port pair of switch to let
    ryu.controller.controller.OpenFlowController to try to initiate
    connection to switch.

    :param addr: A tuple of (host, port) pair of switch.
    :param interval: Interval in seconds to try to connect to switch
    """
    assert len(addr) == 2
    assert ip.valid_ipv4(addr[0]) or ip.valid_ipv6(addr[0])
    ofp_handler = app_manager.lookup_service_brick(ofp_event.NAME)
    _TMP_ADDRESSES[addr] = interval

    def _retry_loop():
        # Delays registration if ofp_handler is not started yet
        while True:
            if ofp_handler.controller is not None:
                for a, i in _TMP_ADDRESSES.items():
                    ofp_handler.controller.spawn_client_loop(a, i)
                    hub.sleep(1)
                break
            hub.sleep(1)

    hub.spawn(_retry_loop)


def unregister_switch_address(addr):
    """
    Unregister the given switch address.

    Unregisters the given switch address to let
    ryu.controller.controller.OpenFlowController stop trying to initiate
    connection to switch.

    :param addr: A tuple of (host, port) pair of switch.
    """
    ofp_handler = app_manager.lookup_service_brick(ofp_event.NAME)
    # Do nothing if ofp_handler is not started yet
    if ofp_handler.controller is None:
        return
    ofp_handler.controller.stop_client_loop(addr)
