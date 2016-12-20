# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
Geneve packet parser/serializer
"""

import struct

from ryu.lib import stringify
from ryu.lib import type_desc
from . import packet_base
from . import ether_types


UDP_DST_PORT = 6081


class geneve(packet_base.PacketBase):
    """Geneve (RFC draft-ietf-nvo3-geneve-03) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ========================================================
    Attribute      Description
    ============== ========================================================
    version        Version.
    opt_len        The length of the options fields.
    flags          Flag field for OAM packet and Critical options present.
    protocol       Protocol Type field.
                   The Protocol Type is defined as "ETHER TYPES".
    vni            Identifier for unique element of virtual network.
    options        List of ``Option*`` instance.
    ============== ========================================================
    """
    _HEADER_FMT = "!BBHI"
    _MIN_LEN = struct.calcsize(_HEADER_FMT)

    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Virtual Network Identifier (VNI)       |    Reserved   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Variable Length Options                    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Flags
    OAM_PACKET_FLAG = 1 << 7
    CRITICAL_OPTIONS_FLAG = 1 << 6

    def __init__(self, version=0, opt_len=0, flags=0,
                 protocol=ether_types.ETH_TYPE_TEB, vni=None, options=None):
        super(geneve, self).__init__()

        self.version = version
        self.opt_len = opt_len
        assert (flags & 0x3F) == 0
        self.flags = flags
        self.protocol = protocol
        self.vni = vni
        for o in options:
            assert isinstance(o, Option)
        self.options = options

    @classmethod
    def parser(cls, buf):
        (ver_opt_len, flags, protocol,
         vni) = struct.unpack_from(cls._HEADER_FMT, buf)
        version = ver_opt_len >> 6
        # The Opt Len field expressed in four byte multiples.
        opt_len = (ver_opt_len & 0x3F) * 4

        opt_bin = buf[cls._MIN_LEN:cls._MIN_LEN + opt_len]
        options = []
        while opt_bin:
            option, opt_bin = Option.parser(opt_bin)
            options.append(option)

        msg = cls(version, opt_len, flags, protocol, vni >> 8, options)

        from . import ethernet
        geneve._TYPES = ethernet.ethernet._TYPES
        geneve.register_packet_type(ethernet.ethernet,
                                    ether_types.ETH_TYPE_TEB)

        return (msg, geneve.get_packet_type(protocol),
                buf[cls._MIN_LEN + opt_len:])

    def serialize(self, payload=None, prev=None):
        tunnel_options = bytearray()
        for o in self.options:
            tunnel_options += o.serialize()
        self.opt_len = len(tunnel_options)
        # The Opt Len field expressed in four byte multiples.
        opt_len = self.opt_len // 4

        return (struct.pack(self._HEADER_FMT,
                            (self.version << 6) | opt_len,
                            self.flags, self.protocol, self.vni << 8)
                + tunnel_options)


class Option(stringify.StringifyMixin, type_desc.TypeDisp):
    """
    Tunnel Options
    """
    _OPTION_PACK_STR = "!HBB"
    _OPTION_LEN = struct.calcsize(_OPTION_PACK_STR)

    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Option Class         |      Type     |R|R|R| Length  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Variable Option Data                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    def __init__(self, option_class=None, type_=None, length=0):
        super(Option, self).__init__()
        if option_class is None or type_ is None:
            (option_class, type_) = self._rev_lookup_type(self.__class__)
        self.option_class = option_class
        self.type = type_
        self.length = length

    @classmethod
    def parse_value(cls, buf):
        # Sub-classes should override this method, if needed.
        return {}

    def serialize_value(self):
        # Sub-classes should override this method, if needed.
        return b''

    @classmethod
    def parser(cls, buf):
        (option_class, type_,
         length) = struct.unpack_from(cls._OPTION_PACK_STR, buf)

        # The Length field expressed in four byte multiples.
        length *= 4
        subcls = Option._lookup_type((option_class, type_))

        return (
            subcls(option_class=option_class, type_=type_, length=length,
                   **subcls.parse_value(
                       buf[cls._OPTION_LEN:cls._OPTION_LEN + length])),
            buf[cls._OPTION_LEN + length:])

    def serialize(self, _payload=None, _prev=None):
        data = self.serialize_value()
        self.length = len(data)
        # The Length field expressed in four byte multiples.
        length = self.length // 4

        return (struct.pack(self._OPTION_PACK_STR, int(self.option_class),
                            self.type, length) + data)


@Option.register_unknown_type()
class OptionDataUnknown(Option):
    """
    Unknown Option Class and Type specific Option
    """
    def __init__(self, buf, option_class=None, type_=None, length=0):
        super(OptionDataUnknown, self).__init__(option_class=option_class,
                                                type_=type_,
                                                length=length)
        self.buf = buf

    @classmethod
    def parse_value(cls, buf):
        return {"buf": buf}

    def serialize_value(self):
        return self.buf
