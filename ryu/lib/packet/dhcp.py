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

"""
DHCP packet parser/serializer
"""
# RFC 2131
# DHCP packet format
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                            xid (4)                            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |           secs (2)            |           flags (2)           |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          ciaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          yiaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          siaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          giaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          chaddr  (16)                         |
#  |                                                               |
#  |                                                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          sname   (64)                         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          file    (128)                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          options (variable)                   |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

import random
import struct

import netaddr

from ryu.lib import addrconv
from ryu.lib import stringify
from . import packet_base

DHCP_BOOT_REQUEST = 1
DHCP_BOOT_REPLY = 2

# DHCP message type code
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

# DHCP options tag code
DHCP_PAD_OPT = 0
DHCP_SUBNET_MASK_OPT = 1
DHCP_GATEWAY_ADDR_OPT = 3
DHCP_DNS_SERVER_ADDR_OPT = 6
DHCP_HOST_NAME_OPT = 12
DHCP_DOMAIN_NAME_OPT = 15
DHCP_INTERFACE_MTU_OPT = 26
DHCP_REQUESTED_IP_ADDR_OPT = 50
DHCP_IP_ADDR_LEASE_TIME_OPT = 51
DHCP_MESSAGE_TYPE_OPT = 53
DHCP_SERVER_IDENTIFIER_OPT = 54
DHCP_PARAMETER_REQUEST_LIST_OPT = 55
DHCP_RENEWAL_TIME_OPT = 58
DHCP_REBINDING_TIME_OPT = 59
DHCP_CLASSLESS_ROUTE_OPT = 121
DHCP_END_OPT = 255


class dhcp(packet_base.PacketBase):
    """DHCP (RFC 2131) header encoder/decoder class.

    The serialized packet would looks like the ones described
    in the following sections.

    * RFC 2131 DHCP packet format

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== ====================
    Attribute      Description
    ============== ====================
    op             Message op code / message type.\
                   1 = BOOTREQUEST, 2 = BOOTREPLY
    htype          Hardware address type (e.g.  '1' = 10mb ethernet).
    hlen           Hardware address length (e.g.  '6' = 10mb ethernet).
    hops           Client sets to zero, optionally used by relay agent\
                   when booting via a relay agent.
    xid            Transaction ID, a random number chosen by the client,\
                   used by the client and serverto associate messages\
                   and responses between a client and a server.
    secs           Filled in by client, seconds elapsed since client\
                   began address acquisition or renewal process.
    flags          Flags.
    ciaddr         Client IP address; only filled in if client is in\
                   BOUND, RENEW or REBINDING state and can respond\
                   to ARP requests.
    yiaddr         'your' (client) IP address.
    siaddr         IP address of next server to use in bootstrap;\
                   returned in DHCPOFFER, DHCPACK by server.
    giaddr         Relay agent IP address, used in booting via a\
                   relay agent.
    chaddr         Client hardware address.
    sname          Optional server host name, null terminated string.
    boot_file      Boot file name, null terminated string; "generic"\
                   name or null in DHCPDISCOVER, fully qualified\
                   directory-path name in DHCPOFFER.
    options        Optional parameters field\
                   ('DHCP message type' option must be included in\
                    every DHCP message).
    ============== ====================
    """
    _DHCP_PACK_STR = '!BBBBIHH4s4s4s4s16s64s128s'
    _MIN_LEN = struct.calcsize(_DHCP_PACK_STR)
    _MAC_ADDRESS_LEN = 6
    _HARDWARE_TYPE_ETHERNET = 1
    _class_prefixes = ['options']
    _TYPE = {
        'ascii': [
            'ciaddr', 'yiaddr', 'siaddr', 'giaddr', 'chaddr',
            'sname', 'boot_file'
        ]
    }

    def __init__(self, op, chaddr, options=None, htype=_HARDWARE_TYPE_ETHERNET,
                 hlen=0, hops=0, xid=None, secs=0, flags=0,
                 ciaddr='0.0.0.0', yiaddr='0.0.0.0', siaddr='0.0.0.0',
                 giaddr='0.0.0.0', sname='', boot_file=''):
        super(dhcp, self).__init__()
        self.op = op
        self.htype = htype
        self.hlen = hlen
        self.hops = hops
        if xid is None:
            self.xid = random.randint(0, 0xffffffff)
        else:
            self.xid = xid
        self.secs = secs
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr
        self.sname = sname
        self.boot_file = boot_file
        self.options = options

    @classmethod
    def parser(cls, buf):
        (op, htype, hlen, hops, xid, secs, flags,
         ciaddr, yiaddr, siaddr, giaddr, chaddr, sname,
         boot_file) = struct.unpack_from(cls._DHCP_PACK_STR, buf)

        if hlen == cls._MAC_ADDRESS_LEN:
            chaddr = addrconv.mac.bin_to_text(chaddr[:cls._MAC_ADDRESS_LEN])

        length = cls._MIN_LEN
        parse_opt = None
        if len(buf) > length:
            parse_opt = options.parser(buf[length:])
            length += parse_opt.options_len
        return (cls(op, chaddr, parse_opt,
                    htype, hlen, hops, xid, secs, flags,
                    addrconv.ipv4.bin_to_text(ciaddr),
                    addrconv.ipv4.bin_to_text(yiaddr),
                    addrconv.ipv4.bin_to_text(siaddr),
                    addrconv.ipv4.bin_to_text(giaddr),
                    sname.decode('ascii'), boot_file.decode('ascii')),
                None, buf[length:])

    def serialize(self, _payload=None, _prev=None):
        opt_buf = bytearray()
        if self.options is not None:
            opt_buf = self.options.serialize()
        if netaddr.valid_mac(self.chaddr):
            chaddr = addrconv.mac.text_to_bin(self.chaddr)
        else:
            chaddr = self.chaddr
        self.hlen = len(chaddr)
        return struct.pack(self._DHCP_PACK_STR, self.op, self.htype, self.hlen,
                           self.hops, self.xid, self.secs, self.flags,
                           addrconv.ipv4.text_to_bin(self.ciaddr),
                           addrconv.ipv4.text_to_bin(self.yiaddr),
                           addrconv.ipv4.text_to_bin(self.siaddr),
                           addrconv.ipv4.text_to_bin(self.giaddr),
                           chaddr,
                           self.sname.encode('ascii'),
                           self.boot_file.encode('ascii')) + opt_buf


class options(stringify.StringifyMixin):
    """DHCP (RFC 2132) options encoder/decoder class.

    This is used with ryu.lib.packet.dhcp.dhcp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== ====================
    Attribute      Description
    ============== ====================
    option_list    'end option' and 'pad option' are added automatically\
                   after the option class is stored in array.
    options_len    Option's byte length.\
                   ('magic cookie', 'end option' and 'pad option'\
                    length including.)
    magic_cookie   The first four octets contain the decimal values\
                   99, 130, 83 and 99.
    ============== ====================
    """
    _MAGIC_COOKIE_UNPACK_STR = '!4s'
    # same magic cookie as is defined in RFC 1497
    _MAGIC_COOKIE = '99.130.83.99'
    _OPT_TAG_LEN_BYTE = 2
    _class_prefixes = ['option']
    _TYPE = {
        'ascii': [
            'magic_cookie'
        ]
    }

    def __init__(self, option_list=None, options_len=0,
                 magic_cookie=_MAGIC_COOKIE):
        super(options, self).__init__()
        self.option_list = option_list or []
        self.options_len = options_len
        self.magic_cookie = magic_cookie

    @classmethod
    def parser(cls, buf):
        opt_parse_list = []
        offset = struct.calcsize(cls._MAGIC_COOKIE_UNPACK_STR)
        magic_cookie = struct.unpack_from(cls._MAGIC_COOKIE_UNPACK_STR, buf)[0]
        while len(buf) > offset:
            opt_buf = buf[offset:]
            try:
                opt = option.parser(opt_buf)
            except struct.error:
                opt_parse_list.append(opt_buf)
                break
            if opt is None:
                break
            opt_parse_list.append(opt)
            offset += opt.length + cls._OPT_TAG_LEN_BYTE
        return cls(opt_parse_list, len(buf),
                   addrconv.ipv4.bin_to_text(magic_cookie))

    def serialize(self):
        seri_opt = addrconv.ipv4.text_to_bin(self.magic_cookie)
        for opt in self.option_list:
            if isinstance(opt, option):
                seri_opt += opt.serialize()
            else:
                seri_opt += opt
        if isinstance(self.option_list[-1], option):
            seri_opt += b'\xff'
        self.options_len = len(seri_opt)
        return seri_opt


class option(stringify.StringifyMixin):
    """DHCP (RFC 2132) options encoder/decoder class.

    This is used with ryu.lib.packet.dhcp.dhcp.options.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    tag            Option type.\
                   (except for the 'magic cookie', 'pad option'\
                    and 'end option'.)
    value          Option's value.\
                   (set the value that has been converted to hexadecimal.)
    length         Option's value length.\
                   (calculated automatically from the length of value.)
    ============== ====================
    """
    _UNPACK_STR = '!B'
    _MIN_LEN = struct.calcsize(_UNPACK_STR)

    def __init__(self, tag, value, length=0):
        super(option, self).__init__()
        self.tag = tag
        self.value = value
        self.length = length

    @classmethod
    def parser(cls, buf):
        tag = struct.unpack_from(cls._UNPACK_STR, buf)[0]
        if tag == DHCP_END_OPT or tag == DHCP_PAD_OPT:
            return None
        buf = buf[cls._MIN_LEN:]
        length = struct.unpack_from(cls._UNPACK_STR, buf)[0]
        buf = buf[cls._MIN_LEN:]
        value_unpack_str = '%ds' % length
        value = struct.unpack_from(value_unpack_str, buf)[0]
        return cls(tag, value, length)

    def serialize(self):
        self.length = len(self.value)
        options_pack_str = '!BB%ds' % self.length
        return struct.pack(options_pack_str, self.tag, self.length, self.value)
