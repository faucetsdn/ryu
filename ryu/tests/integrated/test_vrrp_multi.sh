#! /bin/sh

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

if [ -z "$VSCTL" ]; then
    VSCTL=ovs-vsctl
fi

# create two bridges.
# conncect them using patch ports.

create() {
    BR=$1
    LOCAL_PORT=patch$2
    PEER_PORT=patch$3
    CONT=$4
    ${VSCTL} add-br ${BR} -- set bridge ${BR} datapath_type=netdev
    ${VSCTL} add-port ${BR} ${LOCAL_PORT}
    ${VSCTL} set interface ${LOCAL_PORT} type=patch
    ${VSCTL} set interface ${LOCAL_PORT} options:peer=${PEER_PORT}
    ${VSCTL} set bridge ${BR} protocols='[OpenFlow12]'
    ${VSCTL} set-controller ${BR} ${CONT}
}

CONT=tcp:127.0.0.1:6633

create s0 0 1 ${CONT}
create s1 1 0 ${CONT}
