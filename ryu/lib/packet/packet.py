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

from . import packet_base
from . import ethernet


class Packet(object):
    """A packet decoder/encoder class.

    An instance is used to either decode or encode a single packet.

    *data* is a bytearray to describe a raw datagram to decode.
    When decoding, a Packet object is iteratable.
    Iterated values are protocol (ethernet, ipv4, ...) headers and the payload.
    Protocol headers are instances of subclass of packet_base.PacketBase.
    The payload is a bytearray.  They are iterated in on-wire order.

    *data* should be omitted when encoding a packet.
    """

    def __init__(self, data=None, protocols=None, parse_cls=ethernet.ethernet):
        super(Packet, self).__init__()
        self.data = data
        if protocols is None:
            self.protocols = []
        else:
            self.protocols = protocols
        self.protocol_idx = 0
        self.parsed_bytes = 0
        if self.data:
            self._parser(parse_cls)

    def _parser(self, cls):
        while cls:
            try:
                proto, cls = cls.parser(self.data[self.parsed_bytes:])
                if proto:
                    self.parsed_bytes += proto.length
                    self.protocols.append(proto)
            except struct.error:
                cls = None
        if len(self.data) > self.parsed_bytes:
            self.protocols.append(self.data[self.parsed_bytes:])

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
                data = str(p)
            self.data = data + self.data

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

    def next(self):
        try:
            p = self.protocols[self.protocol_idx]
        except:
            self.protocol_idx = 0
            raise StopIteration

        self.protocol_idx += 1
        return p

    def __iter__(self):
        return self

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
