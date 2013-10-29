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
import struct
from . import packet_base
from . import arp
from . import ipv4
from . import ipv6
from . import lldp
from . import slow
from . import llc
from . import pbb
from ryu.ofproto import ether


class _vlan(packet_base.PacketBase):

    __metaclass__ = abc.ABCMeta
    _PACK_STR = "!HH"
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @abc.abstractmethod
    def __init__(self, pcp, cfi, vid, ethertype):
        super(_vlan, self).__init__()
        self.pcp = pcp
        self.cfi = cfi
        self.vid = vid
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf):
        tci, ethertype = struct.unpack_from(cls._PACK_STR, buf)
        pcp = tci >> 13
        cfi = (tci >> 12) & 1
        vid = tci & ((1 << 12) - 1)
        return (cls(pcp, cfi, vid, ethertype),
                vlan.get_packet_type(ethertype), buf[vlan._MIN_LEN:])

    def serialize(self, payload, prev):
        tci = self.pcp << 13 | self.cfi << 12 | self.vid
        return struct.pack(vlan._PACK_STR, tci, self.ethertype)


class vlan(_vlan):
    """VLAN (IEEE 802.1Q) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    pcp            Priority Code Point
    cfi            Canonical Format Indicator
    vid            VLAN Identifier
    ethertype      EtherType
    ============== ====================
    """

    def __init__(self, pcp=0, cfi=0, vid=0, ethertype=ether.ETH_TYPE_IP):
        super(vlan, self).__init__(pcp, cfi, vid, ethertype)

    @classmethod
    def get_packet_type(cls, type_):
        """Override method for the Length/Type field (self.ethertype).
        The Length/Type field means Length or Type interpretation,
        same as ethernet IEEE802.3.
        If the value of Length/Type field is less than or equal to
        1500 decimal(05DC hexadecimal), it means Length interpretation
        and be passed to the LLC sublayer."""
        if type_ <= ether.ETH_TYPE_IEEE802_3:
            type_ = ether.ETH_TYPE_IEEE802_3
        return cls._TYPES.get(type_)


class svlan(_vlan):
    """S-VLAN (IEEE 802.1ad) header encoder/decoder class.


    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    pcp            Priority Code Point
    cfi            Canonical Format Indicator.
                   In a case to be used as B-TAG,
                   this field means DEI(Drop Eligible Indication).
    vid            VLAN Identifier
    ethertype      EtherType
    ============== ====================
    """

    def __init__(self, pcp=0, cfi=0, vid=0, ethertype=ether.ETH_TYPE_8021Q):
        super(svlan, self).__init__(pcp, cfi, vid, ethertype)

    @classmethod
    def get_packet_type(cls, type_):
        return cls._TYPES.get(type_)


vlan.register_packet_type(arp.arp, ether.ETH_TYPE_ARP)
vlan.register_packet_type(ipv4.ipv4, ether.ETH_TYPE_IP)
vlan.register_packet_type(ipv6.ipv6, ether.ETH_TYPE_IPV6)
vlan.register_packet_type(lldp.lldp, ether.ETH_TYPE_LLDP)
vlan.register_packet_type(slow.slow, ether.ETH_TYPE_SLOW)
vlan.register_packet_type(llc.llc, ether.ETH_TYPE_IEEE802_3)

svlan.register_packet_type(vlan, ether.ETH_TYPE_8021Q)
svlan.register_packet_type(pbb.itag, ether.ETH_TYPE_8021AH)
