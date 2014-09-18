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
"""
 Module that holds various constants.

 This module helps in breaking circular dependencies too.
"""

# Various states of bgp state machine.
BGP_FSM_IDLE = 'Idle'
BGP_FSM_CONNECT = 'Connect'
BGP_FSM_ACTIVE = 'Active'
BGP_FSM_OPEN_SENT = 'OpenSent'
BGP_FSM_OPEN_CONFIRM = 'OpenConfirm'
BGP_FSM_ESTABLISHED = 'Established'

# All valid BGP finite state machine states.
BGP_FSM_VALID_STATES = (BGP_FSM_IDLE, BGP_FSM_CONNECT, BGP_FSM_ACTIVE,
                        BGP_FSM_OPEN_SENT, BGP_FSM_OPEN_CONFIRM,
                        BGP_FSM_ESTABLISHED)

# Supported bgp protocol version number.
BGP_VERSION_NUM = 4

# Standard BGP server port number.
STD_BGP_SERVER_PORT_NUM = 179

#
# Constants used to indicate VRF prefix source.
#
# It indicates prefix inside VRF table came from bgp peer to VPN table and then
# to VRF table..
VPN_TABLE = 'vpn_table'
VRF_TABLE = 'vrf_table'

# RTC EOR timer default value
# Time to wait for RTC-EOR, before we can send initial UPDATE as per RFC
RTC_EOR_DEFAULT_TIME = 60

# Constants for AttributeMaps
ATTR_MAPS_ORG_KEY = '__orig'
ATTR_MAPS_LABEL_KEY = 'at_maps_key'
ATTR_MAPS_LABEL_DEFAULT = 'default'
ATTR_MAPS_VALUE = 'at_maps'
