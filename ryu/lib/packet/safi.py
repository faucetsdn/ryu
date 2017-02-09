# Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
Subsequent Address Family Idenitifier (SAFI)
http://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
"""

UNICAST = 1
MULTICAST = 2
MPLS_LABEL = 4  # RFC 3107
EVPN = 70       # RFC 7432
MPLS_VPN = 128  # RFC 4364
ROUTE_TARGET_CONSTRAINTS = 132  # RFC 4684
IP_FLOW_SPEC = 133  # RFC 5575
VPN_FLOW_SPEC = 134  # RFC 5575
