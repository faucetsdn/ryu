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
Logical Link Control(LLC, IEEE 802.2) parser/serializer
http://standards.ieee.org/getieee802/download/802.2-1998.pdf


LLC format

    +-----------------+--------------+
    | DSAP address    | 8 bits       |
    +-----------------+--------------+
    | SSAP address    | 8 bits       |
    +-----------------+--------------+
    | Control         | 8 or 16 bits |
    +-----------------+--------------+


DSAP address field

      LSB
    +-----+---+---+---+---+---+---+---+
    | I/G | D | D | D | D | D | D | D |
    +-----+---+---+---+---+---+---+---+
     I/G bit = 0 : Individual DSAP
     I/G bit = 1 : Group DSA
     D : DSAP address

SSAP address field

      LSB
    +-----+---+---+---+---+---+---+---+
    | C/R | S | S | S | S | S | S | S |
    +-----+---+---+---+---+---+---+---+
     C/R bit = 0 : Command
     C/R bit = 1 : Response
     S : SSAP address


Control field

 Information transfer
 command/response
 (I-format PDU)
      1   2   3   4   5   6   7   8    9   10-16
    +---+---+---+---+---+---+---+---+-----+------+
    | 0 |           N(S)            | P/F | N(R) |
    +---+---+---+---+---+---+---+---+-----+------+

 Supervisory
 commands/responses
 (S-format PDUs)
      1   2   3   4   5   6   7   8    9   10-16
    +---+---+---+---+---+---+---+---+-----+------+
    | 1   0 | S   S | 0   0   0   0 | P/F | N(R) |
    +---+---+---+---+---+---+---+---+-----+------+

 Unnumbered
 commands/responses
 (U-format PDUs)
      1   2   3    4    5    6   7    8
    +---+---+----+---+-----+---+----+---+
    | 1   1 | M1  M1 | P/F | M2  M2  M2 |
    +---+---+----+---+-----+---+----+---+

    N(S) : sender send sequence number (Bit 2=lower-order-bit)
    N(R) : sender receive sequence number (Bit 10=lower-order-bit)
    S    : supervisory function bit
    M1/M2: modifier function bit
    P/F  : poll bit - command LLC PDUs
           final bit - response LLC PDUs

"""


import struct
from . import bpdu
from . import packet_base
from ryu.lib import stringify


SAP_BPDU = 0x42


class llc(packet_base.PacketBase):
    """LLC(IEEE 802.2) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============== ===============================================
    Attribute       Description
    =============== ===============================================
    dsap_addr       Destination service access point address field \
                    includes I/G bit at least significant bit.
    ssap_addr       Source service access point address field \
                    includes C/R bit at least significant bit.
    control         Control field \
                    [16 bits for formats that include sequence \
                    numbering, and 8 bits for formats that do not]. \
                    Either ryu.lib.packet.llc.ControlFormatI or \
                    ryu.lib.packet.llc.ControlFormatS or \
                    ryu.lib.packet.llc.ControlFormatU object.
    =============== ===============================================
    """

    _PACK_STR = '!BB'
    _PACK_LEN = struct.calcsize(_PACK_STR)
    _CTR_TYPES = {}
    _CTR_PACK_STR = '!2xB'

    _MIN_LEN = _PACK_LEN

    @staticmethod
    def register_control_type(register_cls):
        llc._CTR_TYPES[register_cls.TYPE] = register_cls
        return register_cls

    def __init__(self, dsap_addr, ssap_addr, control):
        super(llc, self).__init__()

        assert getattr(control, 'TYPE', None) in self._CTR_TYPES

        self.dsap_addr = dsap_addr
        self.ssap_addr = ssap_addr
        self.control = control

    @classmethod
    def parser(cls, buf):
        assert len(buf) >= cls._PACK_LEN
        (dsap_addr, ssap_addr) = struct.unpack_from(cls._PACK_STR, buf)

        (control,) = struct.unpack_from(cls._CTR_PACK_STR, buf)
        ctrl = cls._get_control(control)
        control, information = ctrl.parser(buf[cls._PACK_LEN:])

        return (cls(dsap_addr, ssap_addr, control),
                cls.get_packet_type(dsap_addr), information)

    def serialize(self, payload, prev):
        addr = struct.pack(self._PACK_STR, self.dsap_addr, self.ssap_addr)
        control = self.control.serialize()
        return addr + control

    @classmethod
    def _get_control(cls, buf):
        key = buf & 0b1 if buf & 0b1 == ControlFormatI.TYPE else buf & 0b11
        return cls._CTR_TYPES[key]


@llc.register_control_type
class ControlFormatI(stringify.StringifyMixin):
    """LLC sub encoder/decoder class for control I-format field.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    ======================== ===============================
    Attribute                Description
    ======================== ===============================
    send_sequence_number     sender send sequence number
    pf_bit                   poll/final bit
    receive_sequence_number  sender receive sequence number
    ======================== ===============================
    """
    TYPE = 0b0
    _PACK_STR = '!H'
    _PACK_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, send_sequence_number=0, pf_bit=0,
                 receive_sequence_number=0):
        super(ControlFormatI, self).__init__()
        self.send_sequence_number = send_sequence_number
        self.pf_bit = pf_bit
        self.receive_sequence_number = receive_sequence_number

    @classmethod
    def parser(cls, buf):
        assert len(buf) >= cls._PACK_LEN
        (control,) = struct.unpack_from(cls._PACK_STR, buf)
        assert (control >> 8) & 0b1 == cls.TYPE

        send_sequence_number = (control >> 9) & 0b1111111
        pf_bit = (control >> 8) & 0b1
        receive_sequence_number = (control >> 1) & 0b1111111

        return cls(send_sequence_number, pf_bit,
                   receive_sequence_number), buf[cls._PACK_LEN:]

    def serialize(self):
        control = (self.send_sequence_number << 9 |
                   self.TYPE << 8 |
                   self.receive_sequence_number << 1 |
                   self.pf_bit)
        return struct.pack(self._PACK_STR, control)


@llc.register_control_type
class ControlFormatS(stringify.StringifyMixin):
    """LLC sub encoder/decoder class for control S-format field.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    ======================== ===============================
    Attribute                Description
    ======================== ===============================
    supervisory_function     supervisory function bit
    pf_bit                   poll/final bit
    receive_sequence_number  sender receive sequence number
    ======================== ===============================
    """

    TYPE = 0b01
    _PACK_STR = '!H'
    _PACK_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, supervisory_function=0, pf_bit=0,
                 receive_sequence_number=0):
        super(ControlFormatS, self).__init__()
        self.supervisory_function = supervisory_function
        self.pf_bit = pf_bit
        self.receive_sequence_number = receive_sequence_number

    @classmethod
    def parser(cls, buf):
        assert len(buf) >= cls._PACK_LEN
        (control,) = struct.unpack_from(cls._PACK_STR, buf)

        assert (control >> 8) & 0b11 == cls.TYPE
        assert (control >> 12) & 0b1111 == 0

        supervisory_function = (control >> 10) & 0b11
        pf_bit = (control >> 8) & 0b1
        receive_sequence_number = (control >> 1) & 0b1111111

        return cls(supervisory_function, pf_bit,
                   receive_sequence_number), buf[cls._PACK_LEN:]

    def serialize(self):
        control = (self.supervisory_function << 10 |
                   self.TYPE << 8 |
                   self.receive_sequence_number << 1 |
                   self.pf_bit)
        return struct.pack(self._PACK_STR, control)


@llc.register_control_type
class ControlFormatU(stringify.StringifyMixin):
    """LLC sub encoder/decoder class for control U-format field.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    ======================== ===============================
    Attribute                Description
    ======================== ===============================
    modifier_function1       modifier function bit
    pf_bit                   poll/final bit
    modifier_function2       modifier function bit
    ======================== ===============================
    """

    TYPE = 0b11
    _PACK_STR = '!B'
    _PACK_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, modifier_function1=0, pf_bit=0, modifier_function2=0):
        super(ControlFormatU, self).__init__()
        self.modifier_function1 = modifier_function1
        self.pf_bit = pf_bit
        self.modifier_function2 = modifier_function2

    @classmethod
    def parser(cls, buf):
        assert len(buf) >= cls._PACK_LEN
        (control,) = struct.unpack_from(cls._PACK_STR, buf)

        assert control & 0b11 == cls.TYPE

        modifier_function1 = (control >> 2) & 0b11
        pf_bit = (control >> 4) & 0b1
        modifier_function2 = (control >> 5) & 0b111

        return cls(modifier_function1, pf_bit,
                   modifier_function2), buf[cls._PACK_LEN:]

    def serialize(self):
        control = (self.modifier_function2 << 5 |
                   self.pf_bit << 4 |
                   self.modifier_function1 << 2 |
                   self.TYPE)
        return struct.pack(self._PACK_STR, control)


llc.register_packet_type(bpdu.bpdu, SAP_BPDU)
