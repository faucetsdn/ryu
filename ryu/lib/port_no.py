# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

# Internal representation of port_no id is int(32bit)
# string representation is in hex without '0x'

_PORT_NO_LEN = 8
_PORT_NO_LEN_STR = str(_PORT_NO_LEN)
_PORT_NO_FMT = '%0' + _PORT_NO_LEN_STR + 'x'
PORT_NO_PATTERN = r'[0-9a-f]{%d}' % _PORT_NO_LEN


def port_no_to_str(port_no):
    return _PORT_NO_FMT % port_no


def str_to_port_no(port_no_str):
    assert len(port_no_str) == _PORT_NO_LEN
    return int(port_no_str, 16)
