# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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


NW_ID_EXTERNAL = '__NW_ID_EXTERNAL__'
NW_ID_RESERVED = '__NW_ID_RESERVED__'
NW_ID_VPORT_GRE = '__NW_ID_VPORT_GRE__'
NW_ID_UNKNOWN = '__NW_ID_UNKNOWN__'

RESERVED_NETWORK_IDS = (
    NW_ID_EXTERNAL,
    NW_ID_RESERVED,
    NW_ID_VPORT_GRE,
    NW_ID_UNKNOWN,
)

# tunnel type
_TUNNEL_TYPE_TO_NETWORK_ID = {
    'gre': NW_ID_VPORT_GRE,
}


def tunnel_type_to_network_id(tunnel_type):
    return _TUNNEL_TYPE_TO_NETWORK_ID[tunnel_type.lower()]

# PORT_TYPE_VM = 'guestvm'
# PORT_TYPE_GW = 'gateway'
# PORT_TYPE_EXTERNAL = 'external'
