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

from . import packet_base
from . import ethernet


class Packet(object):
    def __init__(self, data=None):
        super(Packet, self).__init__()
        self.data = data
        self.protocols = []
        self.protocol_idx = 0
        self.parsed_bytes = 0
        if self.data:
            # Do we need to handle non ethernet?
            self.parser(ethernet.ethernet)

    def parser(self, cls):
        while cls:
            proto, cls = cls.parser(self.data[self.parsed_bytes:])
            if proto:
                self.parsed_bytes += proto.length
                self.protocols.append(proto)

        if len(self.data) > self.parsed_bytes:
            self.protocols.append(self.data[self.parsed_bytes:])

    def serialize(self):
        self.data = bytearray()
        r = self.protocols[::-1]
        for i, p in enumerate(r):
            if p.__class__.__bases__[0] == packet_base.PacketBase:
                if i == len(r) - 1:
                    prev = None
                else:
                    prev = r[i + 1]
                data = p.serialize(self.data, prev)
            else:
                data = str(p)
            self.data = data + self.data

    def add_protocol(self, proto):
        self.protocols.append(proto)

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
