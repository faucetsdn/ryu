# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

import inspect
import struct
import base64

import six

from . import packet_base
from . import ethernet

from ryu import utils
from ryu.lib.stringify import StringifyMixin


# Packet class dictionary
mod = inspect.getmembers(utils.import_module("ryu.lib.packet"),
                         lambda cls: (inspect.ismodule(cls)))
cls_list = []
for _, m in mod:
    cl = inspect.getmembers(m,
                            lambda cls: (
                                inspect.isclass(cls) and
                                issubclass(cls, packet_base.PacketBase)))
    cls_list.extend(list(cl))
PKT_CLS_DICT = dict(cls_list)


class Packet(StringifyMixin):
    """A packet decoder/encoder class.

    An instance is used to either decode or encode a single packet.

    *data* is a bytearray to describe a raw datagram to decode.
    When decoding, a Packet object is iteratable.
    Iterated values are protocol (ethernet, ipv4, ...) headers and the payload.
    Protocol headers are instances of subclass of packet_base.PacketBase.
    The payload is a bytearray.  They are iterated in on-wire order.

    *data* should be omitted when encoding a packet.
    """

    # Ignore data field when outputting json representation.
    _base_attributes = ['data']

    def __init__(self, data=None, protocols=None, parse_cls=ethernet.ethernet):
        super(Packet, self).__init__()
        self.data = data
        if protocols is None:
            self.protocols = []
        else:
            self.protocols = protocols
        if self.data:
            self._parser(parse_cls)

    def _parser(self, cls):
        rest_data = self.data
        while cls:
            # Ignores an empty buffer
            if not six.binary_type(rest_data).strip(b'\x00'):
                break
            try:
                proto, cls, rest_data = cls.parser(rest_data)
            except struct.error:
                break
            if proto:
                self.protocols.append(proto)
        # If rest_data is all padding, we ignore rest_data
        if rest_data and six.binary_type(rest_data).strip(b'\x00'):
            self.protocols.append(rest_data)

    def serialize(self):
        """Encode a packet and store the resulted bytearray in self.data.

        This method is legal only when encoding a packet.
        """

        self.data = bytearray()
        r = self.protocols[::-1]
        for i, p in enumerate(r):
            if isinstance(p, packet_base.PacketBase):
                if i == len(r) - 1:
                    prev = None
                else:
                    prev = r[i + 1]
                data = p.serialize(self.data, prev)
            else:
                data = six.binary_type(p)
            self.data = bytearray(data + self.data)

    @classmethod
    def from_jsondict(cls, dict_, decode_string=base64.b64decode,
                      **additional_args):
        protocols = []
        for proto in dict_['protocols']:
            for key, value in proto.items():
                if key in PKT_CLS_DICT:
                    pkt_cls = PKT_CLS_DICT[key]
                    protocols.append(pkt_cls.from_jsondict(value))
                else:
                    raise ValueError('unknown protocol name %s' % key)

        return cls(protocols=protocols)

    def add_protocol(self, proto):
        """Register a protocol *proto* for this packet.

        This method is legal only when encoding a packet.

        When encoding a packet, register a protocol (ethernet, ipv4, ...)
        header to add to this packet.
        Protocol headers should be registered in on-wire order before calling
        self.serialize.
        """

        self.protocols.append(proto)

    def get_protocols(self, protocol):
        """Returns a list of protocols that matches to the specified protocol.
        """
        if isinstance(protocol, packet_base.PacketBase):
            protocol = protocol.__class__
        assert issubclass(protocol, packet_base.PacketBase)
        return [p for p in self.protocols if isinstance(p, protocol)]

    def get_protocol(self, protocol):
        """Returns the firstly found protocol that matches to the
        specified protocol.
        """
        result = self.get_protocols(protocol)
        if len(result) > 0:
            return result[0]
        return None

    def __div__(self, trailer):
        self.add_protocol(trailer)
        return self

    def __truediv__(self, trailer):
        return self.__div__(trailer)

    def __iter__(self):
        return iter(self.protocols)

    def __getitem__(self, idx):
        return self.protocols[idx]

    def __setitem__(self, idx, item):
        self.protocols[idx] = item

    def __delitem__(self, idx):
        del self.protocols[idx]

    def __len__(self):
        return len(self.protocols)

    def __contains__(self, protocol):
        if (inspect.isclass(protocol) and
                issubclass(protocol, packet_base.PacketBase)):
            return protocol in [p.__class__ for p in self.protocols]
        return protocol in self.protocols

    def __str__(self):
        return ', '.join(repr(protocol) for protocol in self.protocols)
    __repr__ = __str__  # note: str(list) uses __repr__ for elements


# XXX: Hack for preventing recursive import
def _PacketBase__div__(self, trailer):
    pkt = Packet()
    pkt.add_protocol(self)
    pkt.add_protocol(trailer)
    return pkt

packet_base.PacketBase.__div__ = _PacketBase__div__
packet_base.PacketBase.__truediv__ = _PacketBase__div__
