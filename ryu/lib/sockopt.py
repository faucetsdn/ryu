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

from ryu.lib import sockaddr


TCP_MD5SIG_LINUX = 0x0e
TCP_MD5SIG_BSD = 0x10


def _set_tcp_md5sig_linux(s, addr, key):
    # struct tcp_md5sig {
    #     struct sockaddr_storage addr;
    #     u16 pad1;
    #     u16 keylen;
    #     u32 pad2;
    #     u8 key[80];
    # }
    af = s.family
    if af == socket.AF_INET:
        sa = sockaddr.sa_in4(addr)
    elif af == socket.AF_INET6:
        sa = sockaddr.sa_in6(addr)
    else:
        raise ValueError("unsupported af %s" % (af,))
    ss = sockaddr.sa_to_ss(sa)
    tcp_md5sig = ss + struct.pack("2xH4x80s", len(key), key)
    s.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG_LINUX, tcp_md5sig)


def _set_tcp_md5sig_bsd(s, _addr, _key):
    # NOTE: On this platform, address and key need to be set using setkey(8).
    tcp_md5sig = struct.pack("I", 1)
    s.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG_BSD, tcp_md5sig)


def set_tcp_md5sig(s, addr, key):
    """Enable TCP-MD5 on the given socket.

    :param s: Socket
    :param addr: Associated address.  On some platforms, this has no effect.
    :param key: Key.  On some platforms, this has no effect.
    """
    impls = {
        'FreeBSD': _set_tcp_md5sig_bsd,
        'Linux': _set_tcp_md5sig_linux,
        'NetBSD': _set_tcp_md5sig_bsd,
    }
    system = platform.system()
    try:
        impl = impls[system]
    except KeyError:
        raise NotImplementedError("TCP-MD5 unsupported on this platform")
    impl(s, addr, key)
