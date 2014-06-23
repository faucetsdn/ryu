# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import platform
import socket
import struct

from ryu.lib import addrconv


system = platform.system()
if system == 'Linux':
    # on linux,
    #    no ss_len
    #    u16 ss_family
    _HDR_FMT = "H"
    _HAVE_SS_LEN = False
else:
    # assume
    #    u8 ss_len
    #    u8 ss_family
    _HDR_FMT = "BB"
    _HAVE_SS_LEN = True


# RFC 2553
_SS_MAXSIZE = 128
_SS_ALIGNSIZE = 8

_SIN_SIZE = 16  # sizeof(struct sockaddr_in)

_HDR_LEN = struct.calcsize(_HDR_FMT)


def _hdr(ss_len, af):
    if _HAVE_SS_LEN:
        return struct.pack(_HDR_FMT, ss_len, af)
    else:
        return struct.pack(_HDR_FMT, af)


def _pad_to(data, total_len):
    pad_len = total_len - len(data)
    return data + pad_len * '\0'


def sa_in4(addr, port=0):
    data = struct.pack("!H4s", port, addrconv.ipv4.text_to_bin(addr))
    hdr = _hdr(_SIN_SIZE, socket.AF_INET)
    return _pad_to(hdr + data, _SIN_SIZE)


def sa_in6(addr, port=0, flowinfo=0, scope_id=0):
    data = struct.pack("!HI16sI", port, flowinfo,
                       addrconv.ipv6.text_to_bin(addr), scope_id)
    hdr = _hdr(_HDR_LEN + len(data), socket.AF_INET6)
    return hdr + data


def sa_to_ss(sa):
    return _pad_to(sa, _SS_MAXSIZE)
