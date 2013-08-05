# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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
Link Layer Discovery Protocol(LLDP, IEEE 802.1AB)
http://standards.ieee.org/getieee802/download/802.1AB-2009.pdf


basic TLV format

octets | 1          | 2             | 3 ...             n + 2 |
       --------------------------------------------------------
       | TLV type | TLV information | TLV information string  |
       | (7bits)  | string length   | ( 0 <= n <= 511 octets) |
       |          | (9bits)         |                         |
       --------------------------------------------------------
bits   |8        2|1|8             1|


LLDPDU format

 ------------------------------------------------------------------------
 | Chassis ID | Port ID | TTL | optional TLV | ... | optional TLV | End |
 ------------------------------------------------------------------------

Chasis ID, Port ID, TTL, End are mandatory
optional TLV may be inserted in any order
"""

import struct
from ryu.lib import stringify
from ryu.lib.packet import packet_base


# LLDP destination MAC address
LLDP_MAC_NEAREST_BRIDGE = '01:80:c2:00:00:0e'
LLDP_MAC_NEAREST_NON_TPMR_BRIDGE = '01:80:c2:00:00:03'
LLDP_MAC_NEAREST_CUSTOMER_BRIDGE = '01:80:c2:00:00:00'


LLDP_TLV_TYPELEN_STR = '!H'
LLDP_TLV_SIZE = 2
LLDP_TLV_TYPE_MASK = 0xfe00
LLDP_TLV_TYPE_SHIFT = 9
LLDP_TLV_LENGTH_MASK = 0x01ff


# LLDP TLV type
LLDP_TLV_END = 0                        # End of LLDPDU
LLDP_TLV_CHASSIS_ID = 1                 # Chassis ID
LLDP_TLV_PORT_ID = 2                    # Port ID
LLDP_TLV_TTL = 3                        # Time To Live
LLDP_TLV_PORT_DESCRIPTION = 4           # Port Description
LLDP_TLV_SYSTEM_NAME = 5                # System Name
LLDP_TLV_SYSTEM_DESCRIPTION = 6         # System Description
LLDP_TLV_SYSTEM_CAPABILITIES = 7        # System Capabilities
LLDP_TLV_MANAGEMENT_ADDRESS = 8         # Management Address
LLDP_TLV_ORGANIZATIONALLY_SPECIFIC = 127  # organizationally Specific TLVs


class LLDPBasicTLV(stringify.StringifyMixin):
    _LEN_MIN = 0
    _LEN_MAX = 511
    tlv_type = None

    def __init__(self, buf=None, *_args, **_kwargs):
        super(LLDPBasicTLV, self).__init__()
        if buf:
            (self.typelen, ) = struct.unpack(
                LLDP_TLV_TYPELEN_STR, buf[:LLDP_TLV_SIZE])
            tlv_type = \
                (self.typelen & LLDP_TLV_TYPE_MASK) >> LLDP_TLV_TYPE_SHIFT
            assert self.tlv_type == tlv_type

            self.len = self.typelen & LLDP_TLV_LENGTH_MASK
            assert len(buf) >= self.len + LLDP_TLV_SIZE

            self.tlv_info = buf[LLDP_TLV_SIZE:]
            self.tlv_info = self.tlv_info[:self.len]

    @staticmethod
    def get_type(buf):
        (typelen, ) = struct.unpack(LLDP_TLV_TYPELEN_STR, buf[:LLDP_TLV_SIZE])
        return (typelen & LLDP_TLV_TYPE_MASK) >> LLDP_TLV_TYPE_SHIFT

    @staticmethod
    def set_tlv_type(subcls, tlv_type):
        assert issubclass(subcls, LLDPBasicTLV)
        subcls.tlv_type = tlv_type

    def _len_valid(self):
        return self._LEN_MIN <= self.len and self.len <= self._LEN_MAX


class lldp(packet_base.PacketBase):
    _tlv_parsers = {}

    def __init__(self, tlvs):
        super(lldp, self).__init__()
        self.tlvs = tlvs

    # at least it must have chassis id, port id, ttl and end
    def _tlvs_len_valid(self):
        return len(self.tlvs) >= 4

    # chassis id, port id, ttl and end
    def _tlvs_valid(self):
        return (self.tlvs[0].tlv_type == LLDP_TLV_CHASSIS_ID and
                self.tlvs[1].tlv_type == LLDP_TLV_PORT_ID and
                self.tlvs[2].tlv_type == LLDP_TLV_TTL and
                self.tlvs[-1].tlv_type == LLDP_TLV_END)

    @classmethod
    def parser(cls, buf):
        tlvs = []

        while buf:
            tlv_type = LLDPBasicTLV.get_type(buf)
            tlv = cls._tlv_parsers[tlv_type](buf)
            tlvs.append(tlv)
            offset = LLDP_TLV_SIZE + tlv.len
            buf = buf[offset:]
            if tlv.tlv_type == LLDP_TLV_END:
                break
            assert len(buf) > 0

        lldp_pkt = cls(tlvs)

        assert lldp_pkt._tlvs_len_valid()
        assert lldp_pkt._tlvs_valid()

        return lldp_pkt, None, buf

    def serialize(self, payload, prev):
        data = bytearray()
        for tlv in self.tlvs:
            data += tlv.serialize()

        return data

    @classmethod
    def set_type(cls, tlv_cls):
        cls._tlv_parsers[tlv_cls.tlv_type] = tlv_cls

    @classmethod
    def get_type(cls, tlv_type):
        return cls._tlv_parsers[tlv_type]

    @classmethod
    def set_tlv_type(cls, tlv_type):
        def _set_type(tlv_cls):
            tlv_cls.set_tlv_type(tlv_cls, tlv_type)
            cls.set_type(tlv_cls)
            return tlv_cls
        return _set_type

    def __len__(self):
        return sum(LLDP_TLV_SIZE + tlv.len for tlv in self.tlvs)


@lldp.set_tlv_type(LLDP_TLV_END)
class End(LLDPBasicTLV):
    def __init__(self, buf=None, *args, **kwargs):
        super(End, self).__init__(buf, *args, **kwargs)
        if buf:
            pass
        else:
            self.len = 0
            self.typelen = 0

    def serialize(self):
        return struct.pack('!H', self.typelen)


@lldp.set_tlv_type(LLDP_TLV_CHASSIS_ID)
class ChassisID(LLDPBasicTLV):
    _PACK_STR = '!B'
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    # subtype id(1 octet) + chassis id length(1 - 255 octet)
    _LEN_MIN = 2
    _LEN_MAX = 256

    # Chassis ID subtype
    SUB_CHASSIS_COMPONENT = 1   # EntPhysicalAlias (IETF RFC 4133)
    SUB_INTERFACE_ALIAS = 2     # IfAlias (IETF RFC 2863)
    SUB_PORT_COMPONENT = 3      # EntPhysicalAlias (IETF RFC 4133)
    SUB_MAC_ADDRESS = 4         # MAC address (IEEE std 802)
    SUB_NETWORK_ADDRESS = 5     # networkAddress
    SUB_INTERFACE_NAME = 6      # IfName (IETF RFC 2863)
    SUB_LOCALLY_ASSIGNED = 7    # local

    def __init__(self, buf=None, *args, **kwargs):
        super(ChassisID, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.subtype, ) = struct.unpack(
                self._PACK_STR, self.tlv_info[:self._PACK_SIZE])
            self.chassis_id = self.tlv_info[self._PACK_SIZE:]
        else:
            self.subtype = kwargs['subtype']
            self.chassis_id = kwargs['chassis_id']
            self.len = self._PACK_SIZE + len(self.chassis_id)
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!HB', self.typelen, self.subtype) + self.chassis_id


@lldp.set_tlv_type(LLDP_TLV_PORT_ID)
class PortID(LLDPBasicTLV):
    _PACK_STR = '!B'
    _PACK_SIZE = struct.calcsize(_PACK_STR)

    # subtype id(1 octet) + port id length(1 - 255 octet)
    _LEN_MIN = 2
    _LEN_MAX = 256

    # Port ID subtype
    SUB_INTERFACE_ALIAS = 1     # ifAlias (IETF RFC 2863)
    SUB_PORT_COMPONENT = 2      # entPhysicalAlias (IETF RFC 4133)
    SUB_MAC_ADDRESS = 3         # MAC address (IEEE Std 802)
    SUB_NETWORK_ADDRESS = 4     # networkAddress
    SUB_INTERFACE_NAME = 5      # ifName (IETF RFC 2863)
    SUB_AGENT_CIRCUIT_ID = 6    # agent circuit ID(IETF RFC 3046)
    SUB_LOCALLY_ASSIGNED = 7    # local

    def __init__(self, buf=None, *args, **kwargs):
        super(PortID, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.subtype, ) = struct.unpack(
                self._PACK_STR, self.tlv_info[:self._PACK_SIZE])
            self.port_id = self.tlv_info[self._PACK_SIZE:]
        else:
            self.subtype = kwargs['subtype']
            self.port_id = kwargs['port_id']
            self.len = self._PACK_SIZE + len(self.port_id)
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!HB', self.typelen, self.subtype) + self.port_id


@lldp.set_tlv_type(LLDP_TLV_TTL)
class TTL(LLDPBasicTLV):
    _PACK_STR = '!H'
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = _PACK_SIZE

    def __init__(self, buf=None, *args, **kwargs):
        super(TTL, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.ttl, ) = struct.unpack(
                self._PACK_STR, self.tlv_info[:self._PACK_SIZE])
        else:
            self.ttl = kwargs['ttl']
            self.len = self._PACK_SIZE
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!HH', self.typelen, self.ttl)


@lldp.set_tlv_type(LLDP_TLV_PORT_DESCRIPTION)
class PortDescription(LLDPBasicTLV):
    _LEN_MAX = 255

    def __init__(self, buf=None, *args, **kwargs):
        super(PortDescription, self).__init__(buf, *args, **kwargs)
        if buf:
            pass
        else:
            self.port_description = kwargs['port_description']
            self.len = len(self.port_description)
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!H', self.typelen) + self.port_description

    @property
    def port_description(self):
        return self.tlv_info

    @port_description.setter
    def port_description(self, value):
        self.tlv_info = value


@lldp.set_tlv_type(LLDP_TLV_SYSTEM_NAME)
class SystemName(LLDPBasicTLV):
    _LEN_MAX = 255

    def __init__(self, buf=None, *args, **kwargs):
        super(SystemName, self).__init__(buf, *args, **kwargs)
        if buf:
            pass
        else:
            self.system_name = kwargs['system_name']
            self.len = len(self.system_name)
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!H', self.typelen) + self.tlv_info

    @property
    def system_name(self):
        return self.tlv_info

    @system_name.setter
    def system_name(self, value):
        self.tlv_info = value


@lldp.set_tlv_type(LLDP_TLV_SYSTEM_DESCRIPTION)
class SystemDescription(LLDPBasicTLV):
    _LEN_MAX = 255

    def __init__(self, buf=None, *args, **kwargs):
        super(SystemDescription, self).__init__(buf, *args, **kwargs)
        if buf:
            pass
        else:
            self.system_description = kwargs['system_description']
            self.len = len(self.system_description)
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!H', self.typelen) + self.tlv_info

    @property
    def system_description(self):
        return self.tlv_info

    @system_description.setter
    def system_description(self, value):
        self.tlv_info = value


@lldp.set_tlv_type(LLDP_TLV_SYSTEM_CAPABILITIES)
class SystemCapabilities(LLDPBasicTLV):
    # chassis subtype(1) + system cap(2) + enabled cap(2)
    _PACK_STR = '!BHH'
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = _PACK_SIZE

    # System Capabilities
    CAP_REPEATER = (1 << 1)             # IETF RFC 2108
    CAP_MAC_BRIDGE = (1 << 2)           # IEEE Std 802.1D
    CAP_WLAN_ACCESS_POINT = (1 << 3)    # IEEE Std 802.11 MIB
    CAP_ROUTER = (1 << 4)               # IETF RFC 1812
    CAP_TELEPHONE = (1 << 5)            # IETF RFC 4293
    CAP_DOCSIS = (1 << 6)               # IETF RFC 4639 and IETF RFC 4546
    CAP_STATION_ONLY = (1 << 7)         # IETF RFC 4293
    CAP_CVLAN = (1 << 8)                # IEEE Std 802.1Q
    CAP_SVLAN = (1 << 9)                # IEEE Std 802.1Q
    CAP_TPMR = (1 << 10)                # IEEE Std 802.1Q

    def __init__(self, buf=None, *args, **kwargs):
        super(SystemCapabilities, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.subtype, self.system_cap, self.enabled_cap) = \
                struct.unpack(self._PACK_STR, self.tlv_info[:self._PACK_SIZE])
        else:
            self.subtype = kwargs['subtype']
            self.system_cap = kwargs['system_cap']
            self.enabled_cap = kwargs['enabled_cap']
            self.len = self._PACK_SIZE
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!HBHH',
                           self.typelen, self.subtype,
                           self.system_cap, self.enabled_cap)


@lldp.set_tlv_type(LLDP_TLV_MANAGEMENT_ADDRESS)
class ManagementAddress(LLDPBasicTLV):
    _LEN_MIN = 9
    _LEN_MAX = 167

    _ADDR_PACK_STR = '!BB'    # address string length, address subtype
    _ADDR_PACK_SIZE = struct.calcsize(_ADDR_PACK_STR)
    _ADDR_LEN_MIN = 1
    _ADDR_LEN_MAX = 31

    _INTF_PACK_STR = '!BIB'   # interface subtype, interface number, oid length
    _INTF_PACK_SIZE = struct.calcsize(_INTF_PACK_STR)
    _OID_LEN_MIN = 0
    _OID_LEN_MAX = 128

    def __init__(self, buf=None, *args, **kwargs):
        super(ManagementAddress, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.addr_len, self.addr_subtype) = struct.unpack(
                self._ADDR_PACK_STR, self.tlv_info[:self._ADDR_PACK_SIZE])
            assert self._addr_len_valid()
            offset = self._ADDR_PACK_SIZE + self.addr_len - 1
            self.addr = self.tlv_info[self._ADDR_PACK_SIZE:offset]

            (self.intf_subtype, self.intf_num, self.oid_len) = struct.unpack(
                self._INTF_PACK_STR,
                self.tlv_info[offset:offset + self._INTF_PACK_SIZE])
            assert self._oid_len_valid()

            offset = offset + self._INTF_PACK_SIZE
            self.oid = self.tlv_info[offset:]
        else:
            self.addr_subtype = kwargs['addr_subtype']
            self.addr = kwargs['addr']
            self.addr_len = len(self.addr) + 1  # 1 octet subtype
            assert self._addr_len_valid()

            self.intf_subtype = kwargs['intf_subtype']
            self.intf_num = kwargs['intf_num']

            self.oid = kwargs['oid']
            self.oid_len = len(self.oid)
            assert self._oid_len_valid()

            self.len = self._ADDR_PACK_SIZE + self.addr_len - 1 \
                + self._INTF_PACK_SIZE + self.oid_len
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        tlv_info = struct.pack(self._ADDR_PACK_STR,
                               self.addr_len, self.addr_subtype)
        tlv_info += self.addr
        tlv_info += struct.pack(self._INTF_PACK_STR,
                                self.intf_subtype, self.intf_num, self.oid_len)
        tlv_info += self.oid
        return struct.pack('!H', self.typelen) + tlv_info

    def _addr_len_valid(self):
        return (self._ADDR_LEN_MIN <= self.addr_len or
                self.addr_len <= self._ADDR_LEN_MAX)

    def _oid_len_valid(self):
        return (self._OID_LEN_MIN <= self.oid_len and
                self.oid_len <= self._OID_LEN_MAX)


@lldp.set_tlv_type(LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
class OrganizationallySpecific(LLDPBasicTLV):
    _PACK_STR = '!3sB'
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = 511

    def __init__(self, buf=None, *args, **kwargs):
        super(OrganizationallySpecific, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.oui, self.subtype) = struct.unpack(
                self._PACK_STR, self.tlv_info[:self._PACK_SIZE])
        else:
            self.oui = kwargs['oui']
            self.subtype = kwargs['subtype']
            self.info = kwargs['info']
            self.len = self._PACK_SIZE + len(self.info)
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!H3sB', self.typelen, self.oui, self.subtype)
