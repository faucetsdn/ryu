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


class PacketBase(object):
    _TYPES = {}

    @classmethod
    def get_packet_type(cls, type_):
        return cls._TYPES.get(type_)

    @classmethod
    def register_packet_type(cls, cls_, type_):
        cls._TYPES[type_] = cls_

    def __init__(self):
        super(PacketBase, self).__init__()
        self.length = 0
        self.protocol_name = self.__class__.__name__

    @classmethod
    def parser(cls):
        pass

    def serialize(self):
        pass
