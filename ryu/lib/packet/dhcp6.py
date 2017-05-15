# Copyright (C) 2016 Bouygues Telecom.
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
DHCPv6 packet parser/serializer

[RFC 3315] DHCPv6 packet format:

The following diagram illustrates the format of DHCP messages sent
between clients and servers::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    msg_type   |               transaction_id                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                            options                            .
    .                           (variable)                          .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

There are two relay agent messages, which share the following format::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    msg_type   |   hop_count   |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
    |                                                               |
    |                         link_address                          |
    |                                                               |
    |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    |                               |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
    |                                                               |
    |                         peer_address                          |
    |                                                               |
    |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    |                               |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
    .                                                               .
    .            options (variable number and length)   ....        .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
import random
import struct

from . import packet_base
from ryu.lib import addrconv
from ryu.lib import stringify

# DHCPv6 message types
DHCPV6_SOLICIT = 1
DHCPV6_ADVERTISE = 2
DHCPV6_REQUEST = 3
DHCPV6_CONFIRM = 4
DHCPV6_RENEW = 5
DHCPV6_REBIND = 6
DHCPV6_REPLY = 7
DHCPV6_RELEASE = 8
DHCPV6_DECLINE = 9
DHCPV6_RECONFIGURE = 10
DHCPV6_INFORMATION_REQUEST = 11
DHCPV6_RELAY_FORW = 12
DHCPV6_RELAY_REPL = 13

# DHCPv6 option-codes
DHCPV6_OPTION_CLIENTID = 1
DHCPV6_OPTION_SERVERID = 2
DHCPV6_OPTION_IA_NA = 3
DHCPV6_OPTION_IA_TA = 4
DHCPV6_OPTION_IAADDR = 5
DHCPV6_OPTION_ORO = 6
DHCPV6_OPTION_PREFERENCE = 7
DHCPV6_OPTION_ELAPSED_TIME = 8
DHCPV6_OPTION_RELAY_MSG = 9
DHCPV6_OPTION_AUTH = 11
DHCPV6_OPTION_UNICAST = 12
DHCPV6_OPTION_STATUS_CODE = 13
DHCPV6_OPTION_RAPID_COMMIT = 14
DHCPV6_OPTION_USER_CLASS = 15
DHCPV6_OPTION_VENDOR_CLASS = 16
DHCPV6_OPTION_VENDOR_OPTS = 17
DHCPV6_OPTION_INTERFACE_ID = 18
DHCPV6_OPTION_RECONF_MSG = 19
DHCPV6_OPTION_RECONF_ACCEPT = 20


class dhcp6(packet_base.PacketBase):
    """DHCPv6 (RFC 3315) header encoder/decoder class.

    The serialized packet would looks like the ones described
    in the following sections.

    * RFC 3315 DHCP packet format

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.


    ============== ====================
    Attribute      Description
    ============== ====================
    msg_type       Identifies the DHCP message type
    transaction_id For unrelayed messages only: the transaction ID for\
                   this message exchange.
    hop_count      For relayed messages only: number of relay agents that\
                   have relayed this message.
    link_address   For relayed messages only: a global or site-local address\
                   that will be used by the server to identify the link on\
                   which the client is located.
    peer_address   For relayed messages only: the address of the client or\
                   relay agent from which the message to be relayed was\
                   received.
    options        Options carried in this message
    ============== ====================
    """
    _MIN_LEN = 8
    _DHCPV6_UNPACK_STR = '!I'
    _DHCPV6_RELAY_UNPACK_STR = '!H16s16s'
    _DHCPV6_UNPACK_STR_LEN = struct.calcsize(_DHCPV6_UNPACK_STR)
    _DHCPV6_RELAY_UNPACK_STR_LEN = struct.calcsize(_DHCPV6_RELAY_UNPACK_STR)
    _DHCPV6_PACK_STR = '!I'
    _DHCPV6_RELAY_PACK_STR = '!H16s16s'

    def __init__(self, msg_type, options, transaction_id=None, hop_count=0,
                 link_address='::', peer_address='::'):
        super(dhcp6, self).__init__()
        self.msg_type = msg_type
        self.options = options
        if transaction_id is None:
            self.transaction_id = random.randint(0, 0xffffff)
        else:
            self.transaction_id = transaction_id
        self.hop_count = hop_count
        self.link_address = link_address
        self.peer_address = peer_address

    @classmethod
    def parser(cls, buf):
        (msg_type, ) = struct.unpack_from('!B', buf)

        buf = b'\x00' + buf[1:]  # unpack xid as a 4-byte integer
        if msg_type == DHCPV6_RELAY_FORW or msg_type == DHCPV6_RELAY_REPL:
            (hop_count, link_address, peer_address) \
                = struct.unpack_from(cls._DHCPV6_RELAY_UNPACK_STR, buf)
            length = struct.calcsize(cls._DHCPV6_RELAY_UNPACK_STR)
        else:
            (transaction_id, ) \
                = struct.unpack_from(cls._DHCPV6_UNPACK_STR, buf)
            length = struct.calcsize(cls._DHCPV6_UNPACK_STR)

        if len(buf) > length:
            parse_opt = options.parser(buf[length:])
            length += parse_opt.options_len
            if msg_type == DHCPV6_RELAY_FORW or msg_type == DHCPV6_RELAY_REPL:
                return (cls(msg_type, parse_opt, 0, hop_count,
                            addrconv.ipv6.bin_to_text(link_address),
                            addrconv.ipv6.bin_to_text(peer_address)),
                        None, buf[length:])
            else:
                return (cls(msg_type, parse_opt, transaction_id),
                        None, buf[length:])
        else:
            return None, None, buf

    def serialize(self, payload=None, prev=None):
        seri_opt = self.options.serialize()
        if (self.msg_type == DHCPV6_RELAY_FORW or
                self.msg_type == DHCPV6_RELAY_REPL):
            pack_str = '%s%ds' % (self._DHCPV6_RELAY_PACK_STR,
                                  self.options.options_len)
            buf = struct.pack(pack_str, self.hop_count,
                              addrconv.ipv6.text_to_bin(self.link_address),
                              addrconv.ipv6.text_to_bin(self.peer_address),
                              seri_opt)
        else:
            pack_str = '%s%ds' % (self._DHCPV6_PACK_STR,
                                  self.options.options_len)
            buf = struct.pack(pack_str, self.transaction_id, seri_opt)
        return struct.pack('!B', self.msg_type) + buf[1:]


class options(stringify.StringifyMixin):
    """DHCP (RFC 3315) options encoder/decoder class.

    This is used with ryu.lib.packet.dhcp6.dhcp6.
    """

    def __init__(self, option_list=None, options_len=0):
        super(options, self).__init__()
        if option_list is None:
            self.option_list = []
        else:
            self.option_list = option_list
        self.options_len = options_len

    @classmethod
    def parser(cls, buf):
        opt_parse_list = []
        offset = 0
        while len(buf) > offset:
            opt_buf = buf[offset:]
            opt = option.parser(opt_buf)
            opt_parse_list.append(opt)
            offset += opt.length + 4
        return cls(opt_parse_list, len(buf))

    def serialize(self):
        seri_opt = bytes()
        for opt in self.option_list:
            seri_opt += opt.serialize()
        if self.options_len == 0:
            self.options_len = len(seri_opt)
        return seri_opt


class option(stringify.StringifyMixin):
    """DHCP (RFC 3315) options encoder/decoder class.

    This is used with ryu.lib.packet.dhcp6.dhcp6.options.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    The format of DHCP options is::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          option-code          |           option-len          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          option-data                          |
        |                      (option-len octets)                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ============== ====================
    Attribute      Description
    ============== ====================
    option-code    An unsigned integer identifying the specific option\
                   type carried in this option.
    option-len     An unsigned integer giving the length of the\
                   option-data field in this option in octets.
    option-data    The data for the option; the format of this data\
                   depends on the definition of the option.
    ============== ====================
    """
    _UNPACK_STR = '!H'
    _UNPACK_STR_LEN = struct.calcsize(_UNPACK_STR)
    _PACK_STR = '!HH%ds'

    def __init__(self, code, data, length=0):
        super(option, self).__init__()
        self.code = code
        self.data = data
        self.length = length

    @classmethod
    def parser(cls, buf):
        code = struct.unpack_from(cls._UNPACK_STR, buf)[0]
        buf = buf[cls._UNPACK_STR_LEN:]
        length = struct.unpack_from(cls._UNPACK_STR, buf)[0]
        buf = buf[cls._UNPACK_STR_LEN:]
        value_unpack_str = '%ds' % length
        data = struct.unpack_from(value_unpack_str, buf)[0]
        return cls(code, data, length)

    def serialize(self):
        if self.length == 0:
            self.length = len(self.data)
        options_pack_str = self._PACK_STR % self.length
        return struct.pack(options_pack_str, self.code, self.length, self.data)
