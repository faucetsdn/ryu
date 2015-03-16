# Copyright (C) 2013 Stratosphere Inc.
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
# vim: tabstop=4 shiftwidth=4 softtabstop=4

import logging
from abc import ABCMeta, abstractmethod
import six

from ryu.lib.packet import packet

LOG = logging.getLogger(__name__)


def packet_in_filter(cls, args=None, logging=False):
    def _packet_in_filter(packet_in_handler):
        def __packet_in_filter(self, ev):
            pkt = packet.Packet(ev.msg.data)
            if not packet_in_handler.pkt_in_filter.filter(pkt):
                if logging:
                    LOG.debug('The packet is discarded by %s: %s', cls, pkt)
                return
            return packet_in_handler(self, ev)
        pkt_in_filter = cls(args)
        packet_in_handler.pkt_in_filter = pkt_in_filter
        return __packet_in_filter
    return _packet_in_filter


@six.add_metaclass(ABCMeta)
class PacketInFilterBase(object):
    def __init__(self, args):
        self.args = args

    @abstractmethod
    def filter(self, pkt):
        pass


class RequiredTypeFilter(PacketInFilterBase):

    def filter(self, pkt):
        required_types = self.args.get('types') or []
        for required_type in required_types:
            if not pkt.get_protocol(required_type):
                return False
        return True
