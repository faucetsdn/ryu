# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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
VRRP packet parser/serializer

[RFC 3768] VRRP v2 packet format::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Auth Type   |   Adver Int   |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         IP Address (1)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            .                                  |
   |                            .                                  |
   |                            .                                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         IP Address (n)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Authentication Data (1)                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Authentication Data (2)                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


[RFC 5798] VRRP v3 packet format::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    IPv4 Fields or IPv6 Fields                 |
   ...                                                             ...
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |(rsvd) |     Max Adver Int     |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                       IPvX Address(es)                        |
    +                                                               +
    +                                                               +
    +                                                               +
    +                                                               +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import struct

from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types as ether
from ryu.lib.packet import in_proto as inet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet_utils
from ryu.lib.packet import vlan
from ryu.lib import addrconv


# IPv4
# the LSB 8 bits is used for VRID
VRRP_IPV4_SRC_MAC_ADDRESS_FMT = '00:00:5E:00:01:%02x'
VRRP_IPV4_DST_MAC_ADDRESS = '01:00:5E:00:00:12'
VRRP_IPV4_DST_ADDRESS = '224.0.0.18'
VRRP_IPV4_TTL = 255


def vrrp_ipv4_src_mac_address(vrid):
    return VRRP_IPV4_SRC_MAC_ADDRESS_FMT % vrid


# IPv6
# the LSB 8 bits is used for VRID
VRRP_IPV6_SRC_MAC_ADDRESS_FMT = '00:00:5E:00:02:%02x'
VRRP_IPV6_DST_MAC_ADDRESS = '33:33:00:00:00:12'
VRRP_IPV6_DST_ADDRESS = 'ff02::12'
VRRP_IPV6_HOP_LIMIT = 255


def vrrp_ipv6_src_mac_address(vrid):
    return VRRP_IPV6_SRC_MAC_ADDRESS_FMT % vrid


VRRP_VERSION_SHIFT = 4
VRRP_TYPE_MASK = 0xf


def vrrp_from_version_type(version_type):
    return (version_type >> VRRP_VERSION_SHIFT, version_type & VRRP_TYPE_MASK)


def vrrp_to_version_type(version, type_):
    return (version << VRRP_VERSION_SHIFT) | type_


# VRRP version
VRRP_VERSION_V2 = 2
VRRP_VERSION_V3 = 3

# VRRP type
VRRP_TYPE_ADVERTISEMENT = 1

# VRRP VRID: 0 isn't used
VRRP_VRID_MIN = 1
VRRP_VRID_MAX = 255

# VRRP priority
VRRP_PRIORITY_MIN = 0
VRRP_PRIORITY_MAX = 255
VRRP_PRIORITY_RELEASE_RESPONSIBILITY = 0
VRRP_PRIORITY_BACKUP_MIN = 1
VRRP_PRIORITY_BACKUP_DEFAULT = 100
VRRP_PRIORITY_BACKUP_MAX = 254
VRRP_PRIORITY_ADDRESS_OWNER = 255

# VRRP auth type (VRRP v2 only)
VRRP_AUTH_NO_AUTH = 0
VRRP_AUTH_RESERVED1 = 1
VRRP_AUTH_RESERVED2 = 2
VRRP_AUTH_DATA1 = 0
VRRP_AUTH_DATA2 = 0
VRRP_AUTH_DATA = (VRRP_AUTH_DATA1, VRRP_AUTH_DATA2)

# VRRP Max advertisement interval
VRRP_MAX_ADVER_INT_DEFAULT_IN_SEC = 1   # 1 second

VRRP_V3_MAX_ADVER_INT_MASK = 0xfff      # in centiseconds
VRRP_V3_MAX_ADVER_INT_DEFAULT = 100     # = 1 second
VRRP_V3_MAX_ADVER_INT_MIN = 1           # don't allow 0
VRRP_V3_MAX_ADVER_INT_MAX = 0xfff

VRRP_V2_MAX_ADVER_INT_MASK = 0xff       # in seconds
VRRP_V2_MAX_ADVER_INT_DEFAULT = 1       # 1 second
VRRP_V2_MAX_ADVER_INT_MIN = 1           # don't allow 0
VRRP_V2_MAX_ADVER_INT_MAX = 0xff


def is_ipv6(ip_address):
    assert type(ip_address) == str
    try:
        addrconv.ipv4.text_to_bin(ip_address)
    except:
        addrconv.ipv6.text_to_bin(ip_address)  # sanity
        return True
    return False


def ip_text_to_bin(ip_text):
    if is_ipv6(ip_text):
        return addrconv.ipv6.text_to_bin(ip_text)
    else:
        return addrconv.ipv4.text_to_bin(ip_text)


# This is used for master selection
def ip_address_lt(ip1, ip2):
    return ip_text_to_bin(ip1) < ip_text_to_bin(ip2)


class vrrp(packet_base.PacketBase):
    """The base class for VRRPv2 (RFC 3768) and VRRPv3 (RFC 5798)
    header encoder/decoder classes.

    Unlike other ryu.lib.packet.packet_base.PacketBase derived classes,
    This class should not be directly instantiated by user.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.

    ============== ====================
    Attribute      Description
    ============== ====================
    version        Version
    type           Type
    vrid           Virtual Rtr ID (VRID)
    priority       Priority
    count_ip       Count IPvX Addr. \
                   Calculated automatically when encoding.
    max_adver_int  Maximum Advertisement Interval (Max Adver Int)
    checksum       Checksum. \
                   Calculated automatically when encoding.
    ip_addresses   IPvX Address(es).  A python list of IP addresses.
    auth_type      Authentication Type (only for VRRPv2)
    auth_data      Authentication Data (only for VRRPv2)
    ============== ====================
    """

    _VERSION_PACK_STR = '!B'
    _IPV4_ADDRESS_PACK_STR_RAW = '4s'
    _IPV4_ADDRESS_PACK_STR = '!' + _IPV4_ADDRESS_PACK_STR_RAW
    _IPV4_ADDRESS_LEN = struct.calcsize(_IPV4_ADDRESS_PACK_STR)
    _IPV6_ADDRESS_LEN = 16
    _IPV6_ADDRESS_PACK_STR_RAW = '%ds' % _IPV6_ADDRESS_LEN
    _IPV6_ADDRESS_PACK_STR = '!' + _IPV6_ADDRESS_PACK_STR_RAW
    _IPV6_ADDRESS_LEN = struct.calcsize(_IPV6_ADDRESS_PACK_STR)

    _VRRP_VERSIONS = {}
    _SEC_IN_MAX_ADVER_INT_UNIT = {}

    @staticmethod
    def get_payload(packet_):
        may_ip = None
        may_vrrp = None

        idx = 0
        for protocol in packet_:
            if isinstance(protocol, ipv4.ipv4) or isinstance(protocol,
                                                             ipv6.ipv6):
                may_ip = protocol
                try:
                    if isinstance(packet_.protocols[idx + 1], vrrp):
                        may_vrrp = packet_.protocols[idx + 1]
                finally:
                    break
            idx += 1

        if may_ip and may_vrrp:
            return may_ip, may_vrrp
        else:
            return None, None

    @classmethod
    def register_vrrp_version(cls, version,
                              sec_in_max_adver_int_unit):
        def _register_vrrp_version(cls_):
            cls._VRRP_VERSIONS[version] = cls_
            cls._SEC_IN_MAX_ADVER_INT_UNIT[version] = sec_in_max_adver_int_unit
            return cls_
        return _register_vrrp_version

    @staticmethod
    def sec_to_max_adver_int(version, seconds):
        return int(seconds * vrrp._SEC_IN_MAX_ADVER_INT_UNIT[version])

    @staticmethod
    def max_adver_int_to_sec(version, max_adver_int):
        return float(max_adver_int) / vrrp._SEC_IN_MAX_ADVER_INT_UNIT[version]

    def __init__(self, version, type_, vrid, priority, count_ip,
                 max_adver_int, checksum, ip_addresses,

                 # auth_type/auth_data is for vrrp v2
                 auth_type=None, auth_data=None):
        super(vrrp, self).__init__()
        self.version = version
        self.type = type_
        self.vrid = vrid
        self.priority = priority
        self.count_ip = count_ip
        self.max_adver_int = max_adver_int

        self.checksum = checksum
        self.ip_addresses = ip_addresses
        assert len(list(ip_addresses)) == self.count_ip

        self.auth_type = auth_type
        self.auth_data = auth_data

        self._is_ipv6 = is_ipv6(list(self.ip_addresses)[0])
        self.identification = 0         # used for ipv4 identification

    def checksum_ok(self, ipvx, vrrp_buf):
        cls_ = self._VRRP_VERSIONS[self.version]
        return cls_.checksum_ok(self, ipvx, vrrp_buf)

    @property
    def max_adver_int_in_sec(self):
        # return seconds of float as time.sleep() accepts such type.
        return self.max_adver_int_to_sec(self.version, self.max_adver_int)

    @property
    def is_ipv6(self):
        return self._is_ipv6

    def __len__(self):
        cls_ = self._VRRP_VERSIONS[self.version]
        return cls_.__len__(self)

    @staticmethod
    def create_version(version, type_, vrid, priority, max_adver_int,
                       ip_addresses, auth_type=None, auth_data=None):
        cls_ = vrrp._VRRP_VERSIONS.get(version, None)
        if not cls_:
            raise ValueError('unknown VRRP version %d' % version)

        if priority is None:
            priority = VRRP_PRIORITY_BACKUP_DEFAULT
        count_ip = len(ip_addresses)
        if max_adver_int is None:
            max_adver_int = cls_.sec_to_max_adver_int(
                VRRP_MAX_ADVER_INT_DEFAULT_IN_SEC)
        return cls_(version, type_, vrid, priority, count_ip, max_adver_int,
                    None, ip_addresses,
                    auth_type=auth_type, auth_data=auth_data)

    def get_identification(self):
        self.identification += 1
        self.identification &= 0xffff
        if self.identification == 0:
            self.identification += 1
            self.identification &= 0xffff
        return self.identification

    def create_packet(self, primary_ip_address, vlan_id=None):
        """Prepare a VRRP packet.

        Returns a newly created ryu.lib.packet.packet.Packet object
        with appropriate protocol header objects added by add_protocol().
        It's caller's responsibility to serialize().
        The serialized packet would looks like the ones described in
        the following sections.

        * RFC 3768 5.1. VRRP Packet Format
        * RFC 5798 5.1. VRRP Packet Format

        ================== ====================
        Argument           Description
        ================== ====================
        primary_ip_address Source IP address
        vlan_id            VLAN ID.  None for no VLAN.
        ================== ====================
        """
        if self.is_ipv6:
            traffic_class = 0xc0        # set tos to internetwork control
            flow_label = 0
            payload_length = ipv6.ipv6._MIN_LEN + len(self)     # XXX _MIN_LEN
            e = ethernet.ethernet(VRRP_IPV6_DST_MAC_ADDRESS,
                                  vrrp_ipv6_src_mac_address(self.vrid),
                                  ether.ETH_TYPE_IPV6)
            ip = ipv6.ipv6(6, traffic_class, flow_label, payload_length,
                           inet.IPPROTO_VRRP, VRRP_IPV6_HOP_LIMIT,
                           primary_ip_address, VRRP_IPV6_DST_ADDRESS)
        else:
            header_length = ipv4.ipv4._MIN_LEN // 4      # XXX _MIN_LEN
            total_length = 0
            tos = 0xc0  # set tos to internetwork control
            identification = self.get_identification()
            e = ethernet.ethernet(VRRP_IPV4_DST_MAC_ADDRESS,
                                  vrrp_ipv4_src_mac_address(self.vrid),
                                  ether.ETH_TYPE_IP)
            ip = ipv4.ipv4(4, header_length, tos, total_length, identification,
                           0, 0, VRRP_IPV4_TTL, inet.IPPROTO_VRRP, 0,
                           primary_ip_address, VRRP_IPV4_DST_ADDRESS)

        p = packet.Packet()
        p.add_protocol(e)
        if vlan_id is not None:
            vlan_ = vlan.vlan(0, 0, vlan_id, e.ethertype)
            e.ethertype = ether.ETH_TYPE_8021Q
            p.add_protocol(vlan_)
        p.add_protocol(ip)
        p.add_protocol(self)
        return p

    @classmethod
    def parser(cls, buf):
        (version_type,) = struct.unpack_from(cls._VERSION_PACK_STR, buf)
        version, _type = vrrp_from_version_type(version_type)
        cls_ = cls._VRRP_VERSIONS[version]
        return cls_.parser(buf)

    @staticmethod
    def serialize_static(vrrp_, prev):
        # self can be a instance of vrrpv2 or vrrpv3.
        assert isinstance(vrrp_, vrrp)
        cls = vrrp._VRRP_VERSIONS[vrrp_.version]
        return cls.serialize_static(vrrp_, prev)

    def serialize(self, payload, prev):
        return self.serialize_static(self, prev)

    @staticmethod
    def is_valid_ttl(ipvx):
        version = ipvx.version
        if version == 4:
            return ipvx.ttl == VRRP_IPV4_TTL
        if version == 6:
            return ipvx.hop_limit == VRRP_IPV6_HOP_LIMIT

        raise ValueError('invalid ip version %d' % version)

    def is_valid(self):
        cls = self._VRRP_VERSIONS.get(self.version, None)
        if cls is None:
            return False
        return cls.is_valid(self)


# max_adver_int is in seconds
@vrrp.register_vrrp_version(VRRP_VERSION_V2, 1)
class vrrpv2(vrrp):
    """VRRPv2 (RFC 3768) header encoder/decoder class.

    Unlike other ryu.lib.packet.packet_base.PacketBase derived classes,
    *create* method should be used to instantiate an object of this class.
    """

    _PACK_STR = '!BBBBBBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _CHECKSUM_PACK_STR = '!H'
    _CHECKSUM_OFFSET = 6
    _AUTH_DATA_PACK_STR = '!II'
    _AUTH_DATA_LEN = struct.calcsize('!II')

    def __len__(self):
        return (self._MIN_LEN + self._IPV4_ADDRESS_LEN * self.count_ip +
                self._AUTH_DATA_LEN)

    def checksum_ok(self, ipvx, vrrp_buf):
        return packet_utils.checksum(vrrp_buf) == 0

    @staticmethod
    def create(type_, vrid, priority, max_adver_int, ip_addresses):
        """Unlike other ryu.lib.packet.packet_base.PacketBase derived classes,
        this method should be used to instantiate an object of this class.

        This method's arguments are same as ryu.lib.packet.vrrp.vrrp object's
        attributes of the same name.  (except that *type_* corresponds to
        *type* attribute.)
        """

        return vrrp.create_version(VRRP_VERSION_V2, type_, vrid, priority,
                                   max_adver_int,
                                   ip_addresses,
                                   auth_type=VRRP_AUTH_NO_AUTH,
                                   auth_data=VRRP_AUTH_DATA)

    @staticmethod
    def _ip_addresses_pack_str(count_ip):
        return '!' + vrrpv2._IPV4_ADDRESS_PACK_STR_RAW * count_ip

    @classmethod
    def parser(cls, buf):
        (version_type, vrid, priority, count_ip, auth_type, adver_int,
         checksum) = struct.unpack_from(cls._PACK_STR, buf)
        (version, type_) = vrrp_from_version_type(version_type)

        offset = cls._MIN_LEN
        ip_addresses_pack_str = cls._ip_addresses_pack_str(count_ip)
        ip_addresses_bin = struct.unpack_from(ip_addresses_pack_str, buf,
                                              offset)
        ip_addresses = [addrconv.ipv4.bin_to_text(x) for x in ip_addresses_bin]

        offset += struct.calcsize(ip_addresses_pack_str)
        auth_data = struct.unpack_from(cls._AUTH_DATA_PACK_STR, buf, offset)

        msg = cls(version, type_, vrid, priority, count_ip, adver_int,
                  checksum, ip_addresses, auth_type, auth_data)
        return msg, None, buf[len(msg):]

    @staticmethod
    def serialize_static(vrrp_, prev):
        assert not vrrp_.is_ipv6        # vrrpv2 defines only IPv4
        ip_addresses_pack_str = vrrpv2._ip_addresses_pack_str(vrrp_.count_ip)
        ip_addresses_len = struct.calcsize(ip_addresses_pack_str)
        vrrp_len = vrrpv2._MIN_LEN + ip_addresses_len + vrrpv2._AUTH_DATA_LEN

        checksum = False
        if vrrp_.checksum is None:
            checksum = True
            vrrp_.checksum = 0

        if vrrp_.auth_type is None:
            vrrp_.auth_type = VRRP_AUTH_NO_AUTH
        if vrrp_.auth_data is None:
            vrrp_.auth_data = VRRP_AUTH_DATA

        buf = bytearray(vrrp_len)
        offset = 0
        struct.pack_into(vrrpv2._PACK_STR, buf, offset,
                         vrrp_to_version_type(vrrp_.version, vrrp_.type),
                         vrrp_.vrid, vrrp_.priority,
                         vrrp_.count_ip, vrrp_.auth_type, vrrp_.max_adver_int,
                         vrrp_.checksum)
        offset += vrrpv2._MIN_LEN
        struct.pack_into(ip_addresses_pack_str, buf, offset,
                         *[addrconv.ipv4.text_to_bin(x) for x in vrrp_.ip_addresses])
        offset += ip_addresses_len
        struct.pack_into(vrrpv2._AUTH_DATA_PACK_STR, buf, offset,
                         *vrrp_.auth_data)
        if checksum:
            vrrp_.checksum = packet_utils.checksum(buf)
            struct.pack_into(vrrpv2._CHECKSUM_PACK_STR, buf,
                             vrrpv2._CHECKSUM_OFFSET, vrrp_.checksum)
        return buf

    def is_valid(self):
        return (self.version == VRRP_VERSION_V2 and
                self.type == VRRP_TYPE_ADVERTISEMENT and
                VRRP_VRID_MIN <= self.vrid and self.vrid <= VRRP_VRID_MAX and
                VRRP_PRIORITY_MIN <= self.priority and
                self.priority <= VRRP_PRIORITY_MAX and
                self.auth_type == VRRP_AUTH_NO_AUTH and
                VRRP_V2_MAX_ADVER_INT_MIN <= self.max_adver_int and
                self.max_adver_int <= VRRP_V2_MAX_ADVER_INT_MAX and
                self.count_ip == len(self.ip_addresses))


# max_adver_int is in centi seconds: 1 second = 100 centiseconds
@vrrp.register_vrrp_version(VRRP_VERSION_V3, 100)
class vrrpv3(vrrp):
    """VRRPv3 (RFC 5798) header encoder/decoder class.

    Unlike other ryu.lib.packet.packet_base.PacketBase derived classes,
    *create* method should be used to instantiate an object of this class.
    """

    _PACK_STR = '!BBBBHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _CHECKSUM_PACK_STR = '!H'
    _CHECKSUM_OFFSET = 6

    def __len__(self):
        if self.is_ipv6:
            address_len = self._IPV6_ADDRESS_LEN
        else:
            address_len = self._IPV4_ADDRESS_LEN
        return self._MIN_LEN + address_len * self.count_ip

    def checksum_ok(self, ipvx, vrrp_buf):
        # There are two interpretation of IPv4 checksum
        # include IPv4 pseudo header or not.
        # http://www.ietf.org/mail-archive/web/vrrp/current/msg01473.html
        # if not self.is_ipv6:
        #     return packet_utils.checksum(vrrp_buf) == 0
        return packet_utils.checksum_ip(ipvx, len(self), vrrp_buf) == 0

    @staticmethod
    def create(type_, vrid, priority, max_adver_int, ip_addresses):
        """Unlike other ryu.lib.packet.packet_base.PacketBase derived classes,
        this method should be used to instantiate an object of this class.

        This method's arguments are same as ryu.lib.packet.vrrp.vrrp object's
        attributes of the same name.  (except that *type_* corresponds to
        *type* attribute.)
        """
        return vrrp.create_version(VRRP_VERSION_V3, type_, vrid, priority,
                                   max_adver_int, ip_addresses)

    @classmethod
    def parser(cls, buf):
        (version_type, vrid, priority, count_ip, max_adver_int,
         checksum) = struct.unpack_from(cls._PACK_STR, buf)
        (version, type_) = vrrp_from_version_type(version_type)

        # _rsvd = (max_adver_int & ~VRRP_V3_MAX_ADVER_INT_MASK) >> 12
        # asssert _rsvd == 0
        max_adver_int &= VRRP_V3_MAX_ADVER_INT_MASK

        offset = cls._MIN_LEN
        address_len = (len(buf) - offset) // count_ip
        # Address version (IPv4 or IPv6) is determined by network layer
        # header type.
        # Unfortunately it isn't available. Guess it by vrrp packet length.
        if address_len == cls._IPV4_ADDRESS_LEN:
            pack_str = '!' + cls._IPV4_ADDRESS_PACK_STR_RAW * count_ip
            conv = addrconv.ipv4.bin_to_text
        elif address_len == cls._IPV6_ADDRESS_LEN:
            pack_str = '!' + cls._IPV6_ADDRESS_PACK_STR_RAW * count_ip
            conv = addrconv.ipv6.bin_to_text
        else:
            raise ValueError(
                'unknown address version address_len %d count_ip %d' % (
                    address_len, count_ip))

        ip_addresses_bin = struct.unpack_from(pack_str, buf, offset)
        ip_addresses = [conv(x) for x in ip_addresses_bin]
        msg = cls(version, type_, vrid, priority,
                  count_ip, max_adver_int, checksum, ip_addresses)
        return msg, None, buf[len(msg):]

    @staticmethod
    def serialize_static(vrrp_, prev):
        if isinstance(prev, ipv4.ipv4):
            assert type(vrrp_.ip_addresses[0]) == str
            conv = addrconv.ipv4.text_to_bin
            ip_address_pack_raw = vrrpv3._IPV4_ADDRESS_PACK_STR_RAW
        elif isinstance(prev, ipv6.ipv6):
            assert type(vrrp_.ip_addresses[0]) == str
            conv = addrconv.ipv6.text_to_bin
            ip_address_pack_raw = vrrpv3._IPV6_ADDRESS_PACK_STR_RAW
        else:
            raise ValueError('Unkown network layer %s' % type(prev))

        ip_addresses_pack_str = '!' + ip_address_pack_raw * vrrp_.count_ip
        ip_addresses_len = struct.calcsize(ip_addresses_pack_str)
        vrrp_len = vrrpv3._MIN_LEN + ip_addresses_len

        checksum = False
        if vrrp_.checksum is None:
            checksum = True
            vrrp_.checksum = 0

        buf = bytearray(vrrp_len)
        assert vrrp_.max_adver_int <= VRRP_V3_MAX_ADVER_INT_MASK
        struct.pack_into(vrrpv3._PACK_STR, buf, 0,
                         vrrp_to_version_type(vrrp_.version, vrrp_.type),
                         vrrp_.vrid, vrrp_.priority,
                         vrrp_.count_ip, vrrp_.max_adver_int, vrrp_.checksum)
        struct.pack_into(ip_addresses_pack_str, buf, vrrpv3._MIN_LEN,
                         *[conv(x) for x in vrrp_.ip_addresses])

        if checksum:
            vrrp_.checksum = packet_utils.checksum_ip(prev, len(buf), buf)
            struct.pack_into(vrrpv3._CHECKSUM_PACK_STR, buf,
                             vrrpv3._CHECKSUM_OFFSET, vrrp_.checksum)
        return buf

    def is_valid(self):
        return (self.version == VRRP_VERSION_V3 and
                self.type == VRRP_TYPE_ADVERTISEMENT and
                VRRP_VRID_MIN <= self.vrid and self.vrid <= VRRP_VRID_MAX and
                VRRP_PRIORITY_MIN <= self.priority and
                self.priority <= VRRP_PRIORITY_MAX and
                VRRP_V3_MAX_ADVER_INT_MIN <= self.max_adver_int and
                self.max_adver_int <= VRRP_V3_MAX_ADVER_INT_MAX and
                self.count_ip == len(self.ip_addresses))


ipv4.ipv4.register_packet_type(vrrp, inet.IPPROTO_VRRP)
ipv6.ipv6.register_packet_type(vrrp, inet.IPPROTO_VRRP)
