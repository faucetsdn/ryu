# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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

from struct import calcsize


OFP_HEADER_PACK_STR = '!BBHI'
OFP_HEADER_SIZE = 8
assert calcsize(OFP_HEADER_PACK_STR) == OFP_HEADER_SIZE

# note: while IANA assigned port number for OpenFlow is 6653,
# 6633 is (still) the defacto standard.
OFP_TCP_PORT = 6633
OFP_SSL_PORT = 6633

# Vendor/Experimenter IDs
NX_EXPERIMENTER_ID = 0x00002300  # Nicira
BSN_EXPERIMENTER_ID = 0x005c16c7  # Big Switch Networks
ONF_EXPERIMENTER_ID = 0x4f4e4600  # OpenFlow Extensions for 1.3.X Pack 1
