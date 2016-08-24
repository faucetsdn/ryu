# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

# Internal representation of datapath id is quad int
# string representation is in hex without '0x'

_DPID_LEN = 16
_DPID_FMT = '%0{0}x'.format(_DPID_LEN)
DPID_PATTERN = r'[0-9a-f]{%d}' % _DPID_LEN


def dpid_to_str(dpid):
    return _DPID_FMT % dpid


def str_to_dpid(dpid_str):
    assert len(dpid_str) == _DPID_LEN
    return int(dpid_str, 16)
