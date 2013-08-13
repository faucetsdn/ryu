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

import abc
from ryu.lib import stringify


class PacketBase(stringify.StringifyMixin):
    """A base class for a protocol (ethernet, ipv4, ...) header."""
    __metaclass__ = abc.ABCMeta
    _TYPES = {}

    @classmethod
    def get_packet_type(cls, type_):
        """Per-protocol dict-like get method.

        Provided for convenience of protocol implementers.
        Internal use only."""
        return cls._TYPES.get(type_)

    @classmethod
    def register_packet_type(cls, cls_, type_):
        """Per-protocol dict-like set method.

        Provided for convenience of protocol implementers.
        Internal use only."""
        cls._TYPES[type_] = cls_

    def __init__(self):
        super(PacketBase, self).__init__()

    def __len__(self):
        return self._MIN_LEN

    @property
    def protocol_name(self):
        return self.__class__.__name__

    @classmethod
    @abc.abstractmethod
    def parser(cls, buf):
        """Decode a protocol header.

        This method is used only when decoding a packet.

        Decode a protocol header at offset 0 in bytearray *buf*.
        Returns the following three objects.

        * An object to describe the decoded header.

        * A packet_base.PacketBase subclass appropriate for the rest of
          the packet.  None when the rest of the packet should be considered
          as raw payload.

        * The rest of packet.

        """
        pass

    def serialize(self, payload, prev):
        """Encode a protocol header.

        This method is used only when encoding a packet.

        Encode a protocol header.
        Returns a bytearray which contains the header.

        *payload* is the rest of the packet which will immediately follow
        this header.

        *prev* is a packet_base.PacketBase subclass for the outer protocol
        header.  *prev* is None if the current header is the outer-most.
        For example, *prev* is ipv4 or ipv6 for tcp.serialize.
        """
        pass
