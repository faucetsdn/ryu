# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
Bridge Protocol Data Unit(BPDU, IEEE 802.1D) parser/serializer
http://standards.ieee.org/getieee802/download/802.1D-2004.pdf


Configuration BPDUs format

    +----------------------------------------------+---------+
    |                  Structure                   |  Octet  |
    +==============================================+=========+
    | Protocol Identifier = 0000 0000 0000 0000    |  1 - 2  |
    |                                              |         |
    +----------------------------------------------+---------+
    | Protocol Version Identifier = 0000 0000      |  3      |
    +----------------------------------------------+---------+
    | BPDU Type = 0000 0000                        |  4      |
    +----------------------------------------------+---------+
    | Flags                                        |  5      |
    +----------------------------------------------+---------+
    | Root Identifier                              |  6 - 13 |
    |  include - priority                          |         |
    |            system ID extension               |         |
    |            MAC address                       |         |
    +----------------------------------------------+---------+
    | Root Path Cost                               | 14 - 17 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Bridge Identifier                            | 18 - 25 |
    |  include - priority                          |         |
    |            system ID extension               |         |
    |            MAC address                       |         |
    +----------------------------------------------+---------+
    | Port Identifier                              | 26 - 27 |
    |  include - priority                          |         |
    |            port number                       |         |
    +----------------------------------------------+---------+
    | Message Age                                  | 28 - 29 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Max Age                                      | 30 - 31 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Hello Time                                   | 32 - 33 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Forward Delay                                | 34 - 35 |
    |                                              |         |
    +----------------------------------------------+---------+


Topology Change NotificationBPDUs format

    +----------------------------------------------+---------+
    |                  Structure                   |  Octet  |
    +==============================================+=========+
    | Protocol Identifier = 0000 0000 0000 0000    |  1 - 2  |
    |                                              |         |
    +----------------------------------------------+---------+
    | Protocol Version Identifier = 0000 0000      |  3      |
    +----------------------------------------------+---------+
    | BPDU Type = 1000 0000                        |  4      |
    +----------------------------------------------+---------+


Rapid Spanning Tree BPDUs(RST BPDUs) format

    +----------------------------------------------+---------+
    |                  Structure                   |  Octet  |
    +==============================================+=========+
    | Protocol Identifier = 0000 0000 0000 0000    |  1 - 2  |
    |                                              |         |
    +----------------------------------------------+---------+
    | Protocol Version Identifier = 0000 0010      |  3      |
    +----------------------------------------------+---------+
    | BPDU Type = 0000 0010                        |  4      |
    +----------------------------------------------+---------+
    | Flags                                        |  5      |
    +----------------------------------------------+---------+
    | Root Identifier                              |  6 - 13 |
    |  include - priority                          |         |
    |            system ID extension               |         |
    |            MAC address                       |         |
    +----------------------------------------------+---------+
    | Root Path Cost                               | 14 - 17 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Bridge Identifier                            | 18 - 25 |
    |  include - priority                          |         |
    |            system ID extension               |         |
    |            MAC address                       |         |
    +----------------------------------------------+---------+
    | Port Identifier                              | 26 - 27 |
    |  include - priority                          |         |
    |            port number                       |         |
    +----------------------------------------------+---------+
    | Message Age                                  | 28 - 29 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Max Age                                      | 30 - 31 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Hello Time                                   | 32 - 33 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Forward Delay                                | 34 - 35 |
    |                                              |         |
    +----------------------------------------------+---------+
    | Version 1 Length = 0000 0000                 | 36      |
    +----------------------------------------------+---------+

"""


import binascii
import struct
from . import packet_base
from ryu.lib import addrconv


# BPDU destination
BRIDGE_GROUP_ADDRESS = '01:80:c2:00:00:00'


PROTOCOL_IDENTIFIER = 0
PROTOCOLVERSION_ID_BPDU = 0
PROTOCOLVERSION_ID_RSTBPDU = 2
TYPE_CONFIG_BPDU = 0
TYPE_TOPOLOGY_CHANGE_BPDU = 128
TYPE_RSTBPDU = 2
DEFAULT_BRIDGE_PRIORITY = 32768
DEFAULT_PORT_PRIORITY = 128
PORT_PATH_COST_100KB = 200000000
PORT_PATH_COST_1MB = 20000000
PORT_PATH_COST_10MB = 2000000
PORT_PATH_COST_100MB = 200000
PORT_PATH_COST_1GB = 20000
PORT_PATH_COST_10GB = 2000
PORT_PATH_COST_100GB = 200
PORT_PATH_COST_1TB = 20
PORT_PATH_COST_10TB = 2
DEFAULT_MAX_AGE = 20
DEFAULT_HELLO_TIME = 2
DEFAULT_FORWARD_DELAY = 15
VERSION_1_LENGTH = 0


class bpdu(packet_base.PacketBase):
    """Bridge Protocol Data Unit(BPDU) header encoder/decoder base class.
    """
    _PACK_STR = '!HBB'
    _PACK_LEN = struct.calcsize(_PACK_STR)
    _BPDU_TYPES = {}

    _MIN_LEN = _PACK_LEN

    @staticmethod
    def register_bpdu_type(sub_cls):
        bpdu._BPDU_TYPES[sub_cls.BPDU_TYPE] = sub_cls
        return sub_cls

    def __init__(self):
        super(bpdu, self).__init__()

        assert hasattr(self, 'VERSION_ID')
        assert hasattr(self, 'BPDU_TYPE')

        self.protocol_id = PROTOCOL_IDENTIFIER
        self.version_id = self.VERSION_ID
        self.bpdu_type = self.BPDU_TYPE

        if hasattr(self, 'check_parameters'):
            self.check_parameters()

    @classmethod
    def parser(cls, buf):
        assert len(buf) >= cls._PACK_LEN
        (protocol_id, version_id,
         bpdu_type) = struct.unpack_from(cls._PACK_STR, buf)
        assert protocol_id == PROTOCOL_IDENTIFIER

        bpdu_cls = cls._BPDU_TYPES.get(bpdu_type, None)

        if bpdu_cls:
            assert version_id == bpdu_cls.VERSION_ID
            assert len(buf[cls._PACK_LEN:]) >= bpdu_cls.PACK_LEN
            return bpdu_cls.parser(buf[cls._PACK_LEN:])
        else:
            # Unknown bdpu type.
            return buf, None, None

    def serialize(self, payload, prev):
        return struct.pack(bpdu._PACK_STR, self.protocol_id,
                           self.version_id, self.bpdu_type)


@bpdu.register_bpdu_type
class ConfigurationBPDUs(bpdu):
    """Configuration BPDUs(IEEE 802.1D) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    flags                      | Bit 1: Topology Change flag
                               | Bits 2 through 7: unused and take the value 0
                               | Bit 8: Topology Change Acknowledgment flag
    root_priority              Root Identifier priority \
                               set 0-61440 in steps of 4096
    root_system_id_extension   Root Identifier system ID extension
    root_mac_address           Root Identifier MAC address
    root_path_cost             Root Path Cost
    bridge_priority            Bridge Identifier priority \
                               set 0-61440 in steps of 4096
    bridge_system_id_extension Bridge Identifier system ID extension
    bridge_mac_address         Bridge Identifier MAC address
    port_priority              Port Identifier priority \
                               set 0-240 in steps of 16
    port_number                Port Identifier number
    message_age                Message Age timer value
    max_age                    Max Age timer value
    hello_time                 Hello Time timer value
    forward_delay              Forward Delay timer value
    ========================== ===============================================
    """

    VERSION_ID = PROTOCOLVERSION_ID_BPDU
    BPDU_TYPE = TYPE_CONFIG_BPDU
    _PACK_STR = '!BQIQHHHHH'
    PACK_LEN = struct.calcsize(_PACK_STR)

    _BRIDGE_PRIORITY_STEP = 4096
    _PORT_PRIORITY_STEP = 16
    _TIMER_STEP = float(1)/256

    def __init__(self, flags=0, root_priority=DEFAULT_BRIDGE_PRIORITY,
                 root_system_id_extension=0,
                 root_mac_address='00:00:00:00:00:00',
                 root_path_cost=0, bridge_priority=DEFAULT_BRIDGE_PRIORITY,
                 bridge_system_id_extension=0,
                 bridge_mac_address='00:00:00:00:00:00',
                 port_priority=DEFAULT_PORT_PRIORITY, port_number=0,
                 message_age=0, max_age=DEFAULT_MAX_AGE,
                 hello_time=DEFAULT_HELLO_TIME,
                 forward_delay=DEFAULT_FORWARD_DELAY):
        self.flags = flags
        self.root_priority = root_priority
        self.root_system_id_extension = root_system_id_extension
        self.root_mac_address = root_mac_address
        self.root_path_cost = root_path_cost
        self.bridge_priority = bridge_priority
        self.bridge_system_id_extension = bridge_system_id_extension
        self.bridge_mac_address = bridge_mac_address
        self.port_priority = port_priority
        self.port_number = port_number
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay

        super(ConfigurationBPDUs, self).__init__()

    def check_parameters(self):
        assert (self.flags >> 1 & 0b111111) == 0
        assert self.root_priority % self._BRIDGE_PRIORITY_STEP == 0
        assert self.bridge_priority % self._BRIDGE_PRIORITY_STEP == 0
        assert self.port_priority % self._PORT_PRIORITY_STEP == 0
        assert self.message_age % self._TIMER_STEP == 0
        assert self.max_age % self._TIMER_STEP == 0
        assert self.hello_time % self._TIMER_STEP == 0
        assert self.forward_delay % self._TIMER_STEP == 0

    @classmethod
    def parser(cls, buf):
        (flags, root_id, root_path_cost, bridge_id,
         port_id, message_age, max_age, hello_time,
         forward_delay) = struct.unpack_from(ConfigurationBPDUs._PACK_STR, buf)

        (root_priority,
         root_system_id_extension,
         root_mac_address) = cls._decode_bridge_id(root_id)
        (bridge_priority,
         bridge_system_id_extension,
         bridge_mac_address) = cls._decode_bridge_id(bridge_id)
        (port_priority,
         port_number) = cls._decode_port_id(port_id)

        return (cls(flags, root_priority, root_system_id_extension,
                    root_mac_address, root_path_cost,
                    bridge_priority, bridge_system_id_extension,
                    bridge_mac_address, port_priority, port_number,
                    cls._decode_timer(message_age),
                    cls._decode_timer(max_age),
                    cls._decode_timer(hello_time),
                    cls._decode_timer(forward_delay)),
                None, buf[ConfigurationBPDUs.PACK_LEN:])

    def serialize(self, payload, prev):
        base = super(ConfigurationBPDUs, self).serialize(payload, prev)

        root_id = self.encode_bridge_id(self.root_priority,
                                        self.root_system_id_extension,
                                        self.root_mac_address)
        bridge_id = self.encode_bridge_id(self.bridge_priority,
                                          self.bridge_system_id_extension,
                                          self.bridge_mac_address)
        port_id = self.encode_port_id(self.port_priority,
                                      self.port_number)
        sub = struct.pack(ConfigurationBPDUs._PACK_STR,
                          self.flags,
                          root_id,
                          self.root_path_cost,
                          bridge_id,
                          port_id,
                          self._encode_timer(self.message_age),
                          self._encode_timer(self.max_age),
                          self._encode_timer(self.hello_time),
                          self._encode_timer(self.forward_delay))

        return base + sub

    @staticmethod
    def _decode_bridge_id(bridge_id):
        priority = (bridge_id >> 48) & 0xf000
        system_id_extension = (bridge_id >> 48) & 0xfff
        mac_addr = bridge_id & 0xffffffffffff

        mac_addr_list = [format((mac_addr >> (8 * i)) & 0xff, '02x')
                         for i in range(0, 6)]
        mac_addr_list.reverse()
        mac_address_bin = binascii.a2b_hex(''.join(mac_addr_list))
        mac_address = addrconv.mac.bin_to_text(mac_address_bin)

        return priority, system_id_extension, mac_address

    @staticmethod
    def encode_bridge_id(priority, system_id_extension, mac_address):
        mac_addr = int(binascii.hexlify(addrconv.mac.text_to_bin(mac_address)),
                       16)
        return ((priority + system_id_extension) << 48) + mac_addr

    @staticmethod
    def _decode_port_id(port_id):
        priority = port_id >> 8 & 0xf0
        port_number = port_id & 0xfff
        return priority, port_number

    @staticmethod
    def encode_port_id(priority, port_number):
        return (priority << 8) + port_number

    @staticmethod
    def _decode_timer(timer):
        return timer / float(0x100)

    @staticmethod
    def _encode_timer(timer):
        return timer * 0x100


@bpdu.register_bpdu_type
class TopologyChangeNotificationBPDUs(bpdu):
    """Topology Change Notification BPDUs(IEEE 802.1D)
    header encoder/decoder class.
    """

    VERSION_ID = PROTOCOLVERSION_ID_BPDU
    BPDU_TYPE = TYPE_TOPOLOGY_CHANGE_BPDU
    _PACK_STR = ''
    PACK_LEN = struct.calcsize(_PACK_STR)

    def __init__(self):
        super(TopologyChangeNotificationBPDUs, self).__init__()

    @classmethod
    def parser(cls, buf):
        return cls(), None, buf[bpdu._PACK_LEN:]


@bpdu.register_bpdu_type
class RstBPDUs(ConfigurationBPDUs):
    """Rapid Spanning Tree BPDUs(RST BPDUs, IEEE 802.1D)
    header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    ========================== ===========================================
    Attribute                  Description
    ========================== ===========================================
    flags                      | Bit 1: Topology Change flag
                               | Bit 2: Proposal flag
                               | Bits 3 and 4: Port Role
                               | Bit 5: Learning flag
                               | Bit 6: Forwarding flag
                               | Bit 7: Agreement flag
                               | Bit 8: Topology Change Acknowledgment flag
    root_priority              Root Identifier priority \
                               set 0-61440 in steps of 4096
    root_system_id_extension   Root Identifier system ID extension
    root_mac_address           Root Identifier MAC address
    root_path_cost             Root Path Cost
    bridge_priority            Bridge Identifier priority \
                               set 0-61440 in steps of 4096
    bridge_system_id_extension Bridge Identifier system ID extension
    bridge_mac_address         Bridge Identifier MAC address
    port_priority              Port Identifier priority \
                               set 0-240 in steps of 16
    port_number                Port Identifier number
    message_age                Message Age timer value
    max_age                    Max Age timer value
    hello_time                 Hello Time timer value
    forward_delay              Forward Delay timer value
    ========================== ===========================================
    """

    VERSION_ID = PROTOCOLVERSION_ID_RSTBPDU
    BPDU_TYPE = TYPE_RSTBPDU
    _PACK_STR = '!B'
    PACK_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, flags=0, root_priority=DEFAULT_BRIDGE_PRIORITY,
                 root_system_id_extension=0,
                 root_mac_address='00:00:00:00:00:00',
                 root_path_cost=0, bridge_priority=DEFAULT_BRIDGE_PRIORITY,
                 bridge_system_id_extension=0,
                 bridge_mac_address='00:00:00:00:00:00',
                 port_priority=DEFAULT_PORT_PRIORITY, port_number=0,
                 message_age=0, max_age=DEFAULT_MAX_AGE,
                 hello_time=DEFAULT_HELLO_TIME,
                 forward_delay=DEFAULT_FORWARD_DELAY):
        self.version_1_length = VERSION_1_LENGTH

        super(RstBPDUs, self).__init__(flags, root_priority,
                                       root_system_id_extension,
                                       root_mac_address, root_path_cost,
                                       bridge_priority,
                                       bridge_system_id_extension,
                                       bridge_mac_address,
                                       port_priority, port_number,
                                       message_age, max_age,
                                       hello_time, forward_delay)

    def check_parameters(self):
        assert self.root_priority % self._BRIDGE_PRIORITY_STEP == 0
        assert self.bridge_priority % self._BRIDGE_PRIORITY_STEP == 0
        assert self.port_priority % self._PORT_PRIORITY_STEP == 0
        assert self.message_age % self._TIMER_STEP == 0
        assert self.max_age % self._TIMER_STEP == 0
        assert self.hello_time % self._TIMER_STEP == 0
        assert self.forward_delay % self._TIMER_STEP == 0

    @classmethod
    def parser(cls, buf):
        get_cls, next_type, buf = super(RstBPDUs, cls).parser(buf)

        (version_1_length,) = struct.unpack_from(RstBPDUs._PACK_STR, buf)
        assert version_1_length == VERSION_1_LENGTH

        return get_cls, next_type, buf[RstBPDUs.PACK_LEN:]

    def serialize(self, payload, prev):
        base = super(RstBPDUs, self).serialize(payload, prev)
        sub = struct.pack(RstBPDUs._PACK_STR, self.version_1_length)
        return base + sub
