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

ip link add veth0 type veth peer name veth0-br
ip link add veth1 type veth peer name veth1-br
ip link add veth2 type veth peer name veth2-br

brctl addbr vrrpbr
brctl addif vrrpbr veth0-br
brctl addif vrrpbr veth1-br
brctl addif vrrpbr veth2-br

ip link set veth0 up
ip link set veth0-br up
ip link set veth1 up
ip link set veth1-br up
ip link set veth2 up
ip link set veth2-br up
ip link set vrrpbr up
