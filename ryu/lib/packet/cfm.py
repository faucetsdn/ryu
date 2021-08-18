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

import abc
import six
import struct
from ryu.lib import addrconv
from ryu.lib import stringify
from ryu.lib.packet import packet_base

# IEEE 802.1ag OpCode
CFM_CC_MESSAGE = 0x01
CFM_LOOPBACK_REPLY = 0x02
CFM_LOOPBACK_MESSAGE = 0x03
CFM_LINK_TRACE_REPLY = 0x04
CFM_LINK_TRACE_MESSAGE = 0x05

# IEEE 802.1ag TLV type
CFM_END_TLV = 0x00
CFM_SENDER_ID_TLV = 0x01
CFM_PORT_STATUS_TLV = 0x02
CFM_DATA_TLV = 0x03
CFM_INTERFACE_STATUS_TLV = 0x04
CFM_REPLY_INGRESS_TLV = 0x05
CFM_REPLY_EGRESS_TLV = 0x06
CFM_LTM_EGRESS_IDENTIFIER_TLV = 0x07
CFM_LTR_EGRESS_IDENTIFIER_TLV = 0x08
CFM_ORGANIZATION_SPECIFIC_TLV = 0x1f

# IEEE 802.1ag CFM version
CFM_VERSION = 0


class cfm(packet_base.PacketBase):
    """CFM (Connectivity Fault Management) Protocol header class.

    http://standards.ieee.org/getieee802/download/802.1ag-2007.pdf

    OpCode Field range assignments

    +---------------+--------------------------------------------------+
    | OpCode range  | CFM PDU or organization                          |
    +===============+==================================================+
    | 0             | Reserved for IEEE 802.1                          |
    +---------------+--------------------------------------------------+
    | 1             | Continuity Check Message (CCM)                   |
    +---------------+--------------------------------------------------+
    | 2             | Loopback Reply (LBR)                             |
    +---------------+--------------------------------------------------+
    | 3             | Loopback Message (LBM)                           |
    +---------------+--------------------------------------------------+
    | 4             | Linktrace Reply (LTR)                            |
    +---------------+--------------------------------------------------+
    | 5             | Linktrace Message (LTM)                          |
    +---------------+--------------------------------------------------+
    | 06 - 31       | Reserved for IEEE 802.1                          |
    +---------------+--------------------------------------------------+
    | 32 - 63       | Defined by ITU-T Y.1731                          |
    +---------------+--------------------------------------------------+
    | 64 - 255      | Reserved for IEEE 802.1.                         |
    +---------------+--------------------------------------------------+

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== ========================================
    Attribute      Description
    ============== ========================================
    op             CFM PDU
    ============== ========================================

    """
    _PACK_STR = '!B'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _CFM_OPCODE = {}
    _TYPE = {
        'ascii': [
            'ltm_orig_addr', 'ltm_targ_addr'
        ]
    }

    @staticmethod
    def register_cfm_opcode(type_):
        def _register_cfm_opcode(cls):
            cfm._CFM_OPCODE[type_] = cls
            return cls
        return _register_cfm_opcode

    def __init__(self, op=None):
        super(cfm, self).__init__()
        assert isinstance(op, operation)
        self.op = op

    @classmethod
    def parser(cls, buf):
        (opcode, ) = struct.unpack_from(cls._PACK_STR, buf, cls._MIN_LEN)
        cls_ = cls._CFM_OPCODE.get(opcode)
        op = cls_.parser(buf)
        instance = cls(op)
        rest = buf[len(instance):]
        return instance, None, rest

    def serialize(self, payload, prev):
        buf = self.op.serialize()
        return buf

    def __len__(self):
        return len(self.op)


@six.add_metaclass(abc.ABCMeta)
class operation(stringify.StringifyMixin):

    _TLV_TYPES = {}
    _END_TLV_LEN = 1

    @staticmethod
    def register_tlv_types(type_):
        def _register_tlv_types(cls):
            operation._TLV_TYPES[type_] = cls
            return cls
        return _register_tlv_types

    def __init__(self, md_lv, version, tlvs):
        self.md_lv = md_lv
        self.version = version
        tlvs = tlvs or []
        assert isinstance(tlvs, list)
        for tlv_ in tlvs:
            assert isinstance(tlv_, tlv)
        self.tlvs = tlvs

    @classmethod
    @abc.abstractmethod
    def parser(cls, buf):
        pass

    @abc.abstractmethod
    def serialize(self):
        pass

    @abc.abstractmethod
    def __len__(self):
        pass

    @classmethod
    def _parser_tlvs(cls, buf):
        offset = 0
        tlvs = []
        while True:
            (type_, ) = struct.unpack_from('!B', buf, offset)
            cls_ = cls._TLV_TYPES.get(type_)
            if not cls_:
                assert type_ is CFM_END_TLV
                break
            tlv_ = cls_.parser(buf[offset:])
            tlvs.append(tlv_)
            offset += len(tlv_)
        return tlvs

    @staticmethod
    def _serialize_tlvs(tlvs):
        buf = bytearray()
        for tlv_ in tlvs:
            buf.extend(tlv_.serialize())
        return buf

    def _calc_len(self, len_):
        for tlv_ in self.tlvs:
            len_ += len(tlv_)
        len_ += self._END_TLV_LEN
        return len_


@cfm.register_cfm_opcode(CFM_CC_MESSAGE)
class cc_message(operation):

    """CFM (IEEE Std 802.1ag-2007) Continuity Check Message (CCM)
    encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    md_lv                Maintenance Domain Level.
    version              The protocol version number.
    rdi                  RDI bit.
    interval             CCM Interval.The default is 4 (1 frame/s)
    seq_num              Sequence Number.
    mep_id               Maintenance association End Point Identifier.
    md_name_format       Maintenance Domain Name Format.
                         The default is 4 (Character string)
    md_name_length       Maintenance Domain Name Length.
                         (0 means automatically-calculate
                         when encoding.)
    md_name              Maintenance Domain Name.
    short_ma_name_format Short MA Name Format.
                         The default is 2 (Character string)
    short_ma_name_length Short MA Name Format Length.
                         (0 means automatically-calculate
                         when encoding.)
    short_ma_name        Short MA Name.
    tlvs                 TLVs.
    ==================== =======================================
    """

    _PACK_STR = '!4BIHB'

    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TLV_OFFSET = 70
    _MD_NAME_FORMAT_LEN = 1
    _MD_NAME_LENGTH_LEN = 1
    _SHORT_MA_NAME_FORMAT_LEN = 1
    _SHORT_MA_NAME_LENGTH_LEN = 1
    _MA_ID_LEN = 64

    # Maintenance Domain Name Format
    _MD_FMT_NO_MD_NAME_PRESENT = 1
    _MD_FMT_DOMAIN_NAME_BASED_STRING = 2
    _MD_FMT_MAC_ADDRESS_TWO_OCTET_INTEGER = 3
    _MD_FMT_CHARACTER_STRING = 4

    # Short MA Name Format
    _SHORT_MA_FMT_PRIMARY_VID = 1
    _SHORT_MA_FMT_CHARACTER_STRING = 2
    _SHORT_MA_FMT_TWO_OCTET_INTEGER = 3
    _SHORT_MA_FMT_RFC_2685_VPN_ID = 4

    # CCM Transmission Interval
    _INTERVAL_300_HZ = 1
    _INTERVAL_10_MSEC = 2
    _INTERVAL_100_MSEC = 3
    _INTERVAL_1_SEC = 4
    _INTERVAL_10_SEC = 5
    _INTERVAL_1_MIN = 6
    _INTERVAL_10_MIN = 6

    def __init__(self, md_lv=0, version=CFM_VERSION,
                 rdi=0, interval=_INTERVAL_1_SEC, seq_num=0, mep_id=1,
                 md_name_format=_MD_FMT_CHARACTER_STRING,
                 md_name_length=0, md_name=b"0",
                 short_ma_name_format=_SHORT_MA_FMT_CHARACTER_STRING,
                 short_ma_name_length=0, short_ma_name=b"1",
                 tlvs=None):
        super(cc_message, self).__init__(md_lv, version, tlvs)
        self._opcode = CFM_CC_MESSAGE
        assert rdi in [0, 1]
        self.rdi = rdi
        assert interval != 0
        self.interval = interval
        self.seq_num = seq_num
        assert 1 <= mep_id <= 8191
        self.mep_id = mep_id
        self.md_name_format = md_name_format
        self.md_name_length = md_name_length
        self.md_name = md_name
        self.short_ma_name_format = short_ma_name_format
        self.short_ma_name_length = short_ma_name_length
        self.short_ma_name = short_ma_name

    @classmethod
    def parser(cls, buf):
        (md_lv_version, opcode, flags, tlv_offset, seq_num, mep_id,
         md_name_format) = struct.unpack_from(cls._PACK_STR, buf)
        md_name_length = 0
        md_name = b""
        md_lv = int(md_lv_version >> 5)
        version = int(md_lv_version & 0x1f)
        rdi = int(flags >> 7)
        interval = int(flags & 0x07)
        offset = cls._MIN_LEN
        # parse md_name
        if md_name_format != cls._MD_FMT_NO_MD_NAME_PRESENT:
            (md_name_length, ) = struct.unpack_from("!B", buf, offset)
            offset += cls._MD_NAME_LENGTH_LEN
            form = "%dB" % md_name_length
            md_name = struct.unpack_from(form, buf, offset)
            offset += md_name_length
        # parse short_ma_name
        (short_ma_name_format,
         short_ma_name_length) = struct.unpack_from("!2B", buf, offset)
        offset += (cls._SHORT_MA_NAME_FORMAT_LEN +
                   cls._SHORT_MA_NAME_LENGTH_LEN)
        form = "%dB" % short_ma_name_length
        short_ma_name = struct.unpack_from(form, buf, offset)
        offset = cls._MIN_LEN + (cls._MA_ID_LEN - cls._MD_NAME_FORMAT_LEN)
        tlvs = cls._parser_tlvs(buf[offset:])
        # ascii to text
        if md_name_format == cls._MD_FMT_DOMAIN_NAME_BASED_STRING or \
           md_name_format == cls._MD_FMT_CHARACTER_STRING:
            md_name = b"".join(map(six.int2byte, md_name))
        if short_ma_name_format == cls._SHORT_MA_FMT_CHARACTER_STRING:
            short_ma_name = b"".join(map(six.int2byte, short_ma_name))
        return cls(md_lv, version, rdi, interval, seq_num, mep_id,
                   md_name_format, md_name_length,
                   md_name,
                   short_ma_name_format, short_ma_name_length,
                   short_ma_name,
                   tlvs)

    def serialize(self):
        buf = struct.pack(self._PACK_STR,
                          (self.md_lv << 5) | self.version,
                          self._opcode,
                          (self.rdi << 7) | self.interval,
                          self._TLV_OFFSET,
                          self.seq_num, self.mep_id, self.md_name_format)
        buf = bytearray(buf)
        # Maintenance Domain Name
        if self.md_name_format != self._MD_FMT_NO_MD_NAME_PRESENT:
            if self.md_name_length == 0:
                self.md_name_length = len(self.md_name)
            buf.extend(struct.pack('!B%ds' % self.md_name_length,
                                   self.md_name_length, self.md_name))
        # Short MA Name
        if self.short_ma_name_length == 0:
            self.short_ma_name_length = len(self.short_ma_name)
        buf.extend(struct.pack('!2B%ds' % self.short_ma_name_length,
                               self.short_ma_name_format,
                               self.short_ma_name_length,
                               self.short_ma_name
                               ))
        # 0 pad
        maid_length = (self._MD_NAME_FORMAT_LEN +
                       self._SHORT_MA_NAME_FORMAT_LEN +
                       self._SHORT_MA_NAME_LENGTH_LEN +
                       self.short_ma_name_length)
        if self.md_name_format != self._MD_FMT_NO_MD_NAME_PRESENT:
            maid_length += self._MD_NAME_LENGTH_LEN + self.md_name_length
        buf.extend(bytearray(self._MA_ID_LEN - maid_length))
        # tlvs
        if self.tlvs:
            buf.extend(self._serialize_tlvs(self.tlvs))
        buf.extend(struct.pack("!B", CFM_END_TLV))
        return buf

    def __len__(self):
        return self._calc_len(
            (self._MIN_LEN - self._MD_NAME_FORMAT_LEN) + self._MA_ID_LEN)


class loopback(operation):

    _PACK_STR = '!4BI'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TLV_OFFSET = 4

    @abc.abstractmethod
    def __init__(self, md_lv, version, transaction_id, tlvs):
        super(loopback, self).__init__(md_lv, version, tlvs)
        self._flags = 0
        self.transaction_id = transaction_id

    @classmethod
    def parser(cls, buf):
        (md_lv_version, opcode, flags, tlv_offset,
         transaction_id) = struct.unpack_from(cls._PACK_STR, buf)
        md_lv = int(md_lv_version >> 5)
        version = int(md_lv_version & 0x1f)
        tlvs = cls._parser_tlvs(buf[cls._MIN_LEN:])
        return cls(md_lv, version, transaction_id, tlvs)

    def serialize(self):
        buf = struct.pack(self._PACK_STR,
                          (self.md_lv << 5) | self.version,
                          self._opcode,
                          self._flags,
                          self._TLV_OFFSET,
                          self.transaction_id,
                          )
        buf = bytearray(buf)
        # tlvs
        if self.tlvs:
            buf.extend(self._serialize_tlvs(self.tlvs))
        buf.extend(struct.pack("!B", CFM_END_TLV))

        return buf

    def __len__(self):
        return self._calc_len(self._MIN_LEN)


@cfm.register_cfm_opcode(CFM_LOOPBACK_MESSAGE)
class loopback_message(loopback):

    """CFM (IEEE Std 802.1ag-2007) Loopback Message (LBM) encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ================= =======================================
    Attribute         Description
    ================= =======================================
    md_lv             Maintenance Domain Level.
    version           The protocol version number.
    transaction_id    Loopback Transaction Identifier.
    tlvs              TLVs.
    ================= =======================================
    """

    def __init__(self, md_lv=0, version=CFM_VERSION,
                 transaction_id=0,
                 tlvs=None,
                 ):
        super(loopback_message, self).__init__(md_lv, version,
                                               transaction_id,
                                               tlvs)
        self._opcode = CFM_LOOPBACK_MESSAGE


@cfm.register_cfm_opcode(CFM_LOOPBACK_REPLY)
class loopback_reply(loopback):

    """CFM (IEEE Std 802.1ag-2007) Loopback Reply (LBR) encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    md_lv                Maintenance Domain Level.
    version              The protocol version number.
    transaction_id       Loopback Transaction Identifier.
    tlvs                 TLVs.
    ==================== =======================================
    """

    def __init__(self, md_lv=0, version=CFM_VERSION,
                 transaction_id=0,
                 tlvs=None,
                 ):
        super(loopback_reply, self).__init__(md_lv, version,
                                             transaction_id,
                                             tlvs)
        self._opcode = CFM_LOOPBACK_REPLY


class link_trace(operation):

    @abc.abstractmethod
    def __init__(self, md_lv, version, use_fdb_only,
                 transaction_id, ttl, tlvs):
        super(link_trace, self).__init__(md_lv, version, tlvs)
        assert use_fdb_only in [0, 1]
        self.use_fdb_only = use_fdb_only
        self.transaction_id = transaction_id
        self.ttl = ttl

    @classmethod
    @abc.abstractmethod
    def parser(cls, buf):
        pass

    @abc.abstractmethod
    def serialize(self):
        pass

    def __len__(self):
        return self._calc_len(self._MIN_LEN)


@cfm.register_cfm_opcode(CFM_LINK_TRACE_MESSAGE)
class link_trace_message(link_trace):

    """CFM (IEEE Std 802.1ag-2007) Linktrace Message (LTM)
    encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    md_lv                Maintenance Domain Level.
    version              The protocol version number.
    use_fdb_only         UseFDBonly bit.
    transaction_id       LTM Transaction Identifier.
    ttl                  LTM TTL.
    ltm_orig_addr        Original MAC Address.
    ltm_targ_addr        Target MAC Address.
    tlvs                 TLVs.
    ==================== =======================================
    """

    _PACK_STR = '!4BIB6s6s'
    _ALL_PACK_LEN = struct.calcsize(_PACK_STR)
    _MIN_LEN = _ALL_PACK_LEN
    _TLV_OFFSET = 17
    _TYPE = {
        'ascii': [
            'ltm_orig_addr', 'ltm_targ_addr'
        ]
    }

    def __init__(self, md_lv=0, version=CFM_VERSION,
                 use_fdb_only=1,
                 transaction_id=0,
                 ttl=64,
                 ltm_orig_addr='00:00:00:00:00:00',
                 ltm_targ_addr='00:00:00:00:00:00',
                 tlvs=None
                 ):
        super(link_trace_message, self).__init__(md_lv, version,
                                                 use_fdb_only,
                                                 transaction_id,
                                                 ttl,
                                                 tlvs)
        self._opcode = CFM_LINK_TRACE_MESSAGE
        self.ltm_orig_addr = ltm_orig_addr
        self.ltm_targ_addr = ltm_targ_addr

    @classmethod
    def parser(cls, buf):
        (md_lv_version, opcode, flags, tlv_offset, transaction_id, ttl,
         ltm_orig_addr, ltm_targ_addr) = struct.unpack_from(cls._PACK_STR, buf)
        md_lv = int(md_lv_version >> 5)
        version = int(md_lv_version & 0x1f)
        use_fdb_only = int(flags >> 7)
        tlvs = cls._parser_tlvs(buf[cls._MIN_LEN:])
        return cls(md_lv, version, use_fdb_only,
                   transaction_id, ttl,
                   addrconv.mac.bin_to_text(ltm_orig_addr),
                   addrconv.mac.bin_to_text(ltm_targ_addr),
                   tlvs)

    def serialize(self):
        buf = struct.pack(self._PACK_STR,
                          (self.md_lv << 5) | self.version,
                          self._opcode,
                          self.use_fdb_only << 7,
                          self._TLV_OFFSET,
                          self.transaction_id,
                          self.ttl,
                          addrconv.mac.text_to_bin(self.ltm_orig_addr),
                          addrconv.mac.text_to_bin(self.ltm_targ_addr),
                          )
        buf = bytearray(buf)
        if self.tlvs:
            buf.extend(self._serialize_tlvs(self.tlvs))
        buf.extend(struct.pack("!B", CFM_END_TLV))
        return buf


@cfm.register_cfm_opcode(CFM_LINK_TRACE_REPLY)
class link_trace_reply(link_trace):

    """CFM (IEEE Std 802.1ag-2007) Linktrace Reply (LTR) encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    version              The protocol version number.
    use_fdb_only         UseFDBonly bit.
    fwd_yes              FwdYes bit.
    terminal_mep         TerminalMep bit.
    transaction_id       LTR Transaction Identifier.
    ttl                  Reply TTL.
    relay_action         Relay Action.The default is 1 (RlyHit)
    tlvs                 TLVs.
    ==================== =======================================
    """
    _PACK_STR = '!4BIBB'
    _ALL_PACK_LEN = struct.calcsize(_PACK_STR)
    _MIN_LEN = _ALL_PACK_LEN
    _TLV_OFFSET = 6

    # Relay Action field values
    _RLY_HIT = 1
    _RLY_FDB = 2
    _RLY_MPDB = 3

    def __init__(self, md_lv=0, version=CFM_VERSION, use_fdb_only=1,
                 fwd_yes=0, terminal_mep=1, transaction_id=0,
                 ttl=64, relay_action=_RLY_HIT, tlvs=None
                 ):
        super(link_trace_reply, self).__init__(md_lv, version,
                                               use_fdb_only,
                                               transaction_id,
                                               ttl,
                                               tlvs)
        self._opcode = CFM_LINK_TRACE_REPLY
        assert fwd_yes in [0, 1]
        self.fwd_yes = fwd_yes
        assert terminal_mep in [0, 1]
        self.terminal_mep = terminal_mep
        assert relay_action in [self._RLY_HIT, self._RLY_FDB, self._RLY_MPDB]
        self.relay_action = relay_action

    @classmethod
    def parser(cls, buf):
        (md_lv_version, opcode, flags, tlv_offset, transaction_id, ttl,
         relay_action) = struct.unpack_from(cls._PACK_STR, buf)
        md_lv = int(md_lv_version >> 5)
        version = int(md_lv_version & 0x1f)
        use_fdb_only = int(flags >> 7)
        fwd_yes = int(flags >> 6 & 0x01)
        terminal_mep = int(flags >> 5 & 0x01)
        tlvs = cls._parser_tlvs(buf[cls._MIN_LEN:])
        return cls(md_lv, version, use_fdb_only, fwd_yes, terminal_mep,
                   transaction_id, ttl, relay_action, tlvs)

    def serialize(self):
        buf = struct.pack(self._PACK_STR,
                          (self.md_lv << 5) | self.version,
                          self._opcode,
                          (self.use_fdb_only << 7) |
                          (self.fwd_yes << 6) |
                          (self.terminal_mep << 5),
                          self._TLV_OFFSET,
                          self.transaction_id,
                          self.ttl,
                          self.relay_action,
                          )
        buf = bytearray(buf)
        if self.tlvs:
            buf.extend(self._serialize_tlvs(self.tlvs))
        buf.extend(struct.pack("!B", CFM_END_TLV))
        return buf


cfm.set_classes(cfm._CFM_OPCODE)


@six.add_metaclass(abc.ABCMeta)
class tlv(stringify.StringifyMixin):

    _TYPE_LEN = 1
    _LENGTH_LEN = 2
    _TYPE = {
        'ascii': [
            'egress_id_mac', 'last_egress_id_mac',
            'next_egress_id_mac', 'mac_address'
        ]
    }

    def __init__(self, length):
        self.length = length

    @classmethod
    @abc.abstractmethod
    def parser(cls, buf):
        pass

    @abc.abstractmethod
    def serialize(self):
        pass

    def __len__(self):
        return self.length + self._TYPE_LEN + self._LENGTH_LEN


@operation.register_tlv_types(CFM_SENDER_ID_TLV)
class sender_id_tlv(tlv):

    """CFM (IEEE Std 802.1ag-2007) Sender ID TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    length               Length of Value field.
                         (0 means automatically-calculate when encoding.)
    chassis_id_length    Chassis ID Length.
                         (0 means automatically-calculate when encoding.)
    chassis_id_subtype   Chassis ID Subtype.
                         The default is 4 (Mac Address)
    chassis_id           Chassis ID.
    ma_domain_length     Management Address Domain Length.
                         (0 means automatically-calculate when encoding.)
    ma_domain            Management Address Domain.
    ma_length            Management Address Length.
                         (0 means automatically-calculate when encoding.)
    ma                   Management Address.
    ==================== =======================================
    """

    _PACK_STR = '!BHB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _CHASSIS_ID_LENGTH_LEN = 1
    _CHASSIS_ID_SUBTYPE_LEN = 1
    _MA_DOMAIN_LENGTH_LEN = 1
    _MA_LENGTH_LEN = 1

    # Chassis ID subtype enumeration
    _CHASSIS_ID_CHASSIS_COMPONENT = 1
    _CHASSIS_ID_INTERFACE_ALIAS = 2
    _CHASSIS_ID_PORT_COMPONENT = 3
    _CHASSIS_ID_MAC_ADDRESS = 4
    _CHASSIS_ID_NETWORK_ADDRESS = 5
    _CHASSIS_ID_INTERFACE_NAME = 6
    _CHASSIS_ID_LOCALLY_ASSIGNED = 7

    def __init__(self,
                 length=0,
                 chassis_id_length=0,
                 chassis_id_subtype=_CHASSIS_ID_MAC_ADDRESS,
                 chassis_id=b'',
                 ma_domain_length=0,
                 ma_domain=b'',
                 ma_length=0,
                 ma=b''
                 ):
        super(sender_id_tlv, self).__init__(length)
        self._type = CFM_SENDER_ID_TLV
        self.chassis_id_length = chassis_id_length
        assert chassis_id_subtype in [
            self._CHASSIS_ID_CHASSIS_COMPONENT,
            self._CHASSIS_ID_INTERFACE_ALIAS,
            self._CHASSIS_ID_PORT_COMPONENT,
            self._CHASSIS_ID_MAC_ADDRESS,
            self._CHASSIS_ID_NETWORK_ADDRESS,
            self._CHASSIS_ID_INTERFACE_NAME,
            self._CHASSIS_ID_LOCALLY_ASSIGNED]
        self.chassis_id_subtype = chassis_id_subtype
        self.chassis_id = chassis_id
        self.ma_domain_length = ma_domain_length
        self.ma_domain = ma_domain
        self.ma_length = ma_length
        self.ma = ma

    @classmethod
    def parser(cls, buf):
        (type_, length, chassis_id_length) = struct.unpack_from(cls._PACK_STR,
                                                                buf)
        chassis_id_subtype = 4
        chassis_id = b''
        ma_domain_length = 0
        ma_domain = b''
        ma_length = 0
        ma = b''
        offset = cls._MIN_LEN
        if chassis_id_length != 0:
            (chassis_id_subtype, ) = struct.unpack_from("!B", buf, offset)
            offset += cls._CHASSIS_ID_SUBTYPE_LEN
            form = "%ds" % chassis_id_length
            (chassis_id,) = struct.unpack_from(form, buf, offset)
            offset += chassis_id_length
        if length + (cls._TYPE_LEN + cls._LENGTH_LEN) > offset:
            (ma_domain_length, ) = struct.unpack_from("!B", buf, offset)
            offset += cls._MA_DOMAIN_LENGTH_LEN
            form = "%ds" % ma_domain_length
            (ma_domain, ) = struct.unpack_from(form, buf, offset)
            offset += ma_domain_length
            if length + (cls._TYPE_LEN + cls._LENGTH_LEN) > offset:
                (ma_length, ) = struct.unpack_from("!B", buf, offset)
                offset += cls._MA_LENGTH_LEN
                form = "%ds" % ma_length
                (ma, ) = struct.unpack_from(form, buf, offset)
        return cls(length, chassis_id_length, chassis_id_subtype,
                   chassis_id, ma_domain_length, ma_domain, ma_length, ma)

    def serialize(self):
        # calculate length when it contains 0
        if self.chassis_id_length == 0:
            self.chassis_id_length = len(self.chassis_id)
        if self.ma_domain_length == 0:
            self.ma_domain_length = len(self.ma_domain)
        if self.ma_length == 0:
            self.ma_length = len(self.ma)
        if self.length == 0:
            self.length += self._CHASSIS_ID_LENGTH_LEN
            if self.chassis_id_length != 0:
                self.length += (self._CHASSIS_ID_SUBTYPE_LEN +
                                self.chassis_id_length)
            if self.chassis_id_length != 0 or self.ma_domain_length != 0:
                self.length += self._MA_DOMAIN_LENGTH_LEN
            if self.ma_domain_length != 0:
                self.length += (self.ma_domain_length +
                                self._MA_LENGTH_LEN + self.ma_length)
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length,
                          self.chassis_id_length
                          )
        buf = bytearray(buf)
        # Chassis ID Subtype and Chassis ID present
        # if the Chassis ID Length field contains not 0.
        if self.chassis_id_length != 0:
            buf.extend(struct.pack("!B", self.chassis_id_subtype))
            form = "%ds" % self.chassis_id_length
            buf.extend(struct.pack(form, self.chassis_id))
        # Management Address Domain Length present
        # if the Chassis ID Length field or Management Address Length field
        # contains not 0.
        if self.chassis_id_length != 0 or self.ma_domain_length != 0:
            buf.extend(struct.pack("!B", self.ma_domain_length))
        # Management Address Domain present
        # Management Address Domain Length field contains not 0.
        if self.ma_domain_length != 0:
            form = "%ds" % self.ma_domain_length
            buf.extend(struct.pack(form, self.ma_domain))
            buf.extend(struct.pack("!B", self.ma_length))
            # Management Address present
            # Management Address Length field contains not 0.
            if self.ma_length != 0:
                form = "%ds" % self.ma_length
                buf.extend(struct.pack(form, self.ma))
        return buf


@operation.register_tlv_types(CFM_PORT_STATUS_TLV)
class port_status_tlv(tlv):

    """CFM (IEEE Std 802.1ag-2007) Port Status TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    length               Length of Value field.
                         (0 means automatically-calculate when encoding.)
    port_status          Port Status.The default is 1 (psUp)
    ==================== =======================================
    """

    _PACK_STR = '!BHB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    # Port Status TLV values
    _PS_BLOCKED = 1
    _PS_UP = 2

    def __init__(self, length=0, port_status=_PS_UP):
        super(port_status_tlv, self).__init__(length)
        self._type = CFM_PORT_STATUS_TLV
        assert port_status in [self._PS_BLOCKED, self._PS_UP]
        self.port_status = port_status

    @classmethod
    def parser(cls, buf):
        (type_, length,
         port_status) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(length, port_status)

    def serialize(self):
        # calculate length when it contains 0
        if self.length == 0:
            self.length = 1
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length,
                          self.port_status)
        return bytearray(buf)


@operation.register_tlv_types(CFM_DATA_TLV)
class data_tlv(tlv):

    """CFM (IEEE Std 802.1ag-2007) Data TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    length         Length of Value field.
                   (0 means automatically-calculate when encoding)
    data_value     Bit pattern of any of n octets.(n = length)
    ============== =======================================
    """

    _PACK_STR = '!BH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, length=0, data_value=b""
                 ):
        super(data_tlv, self).__init__(length)
        self._type = CFM_DATA_TLV
        self.data_value = data_value

    @classmethod
    def parser(cls, buf):
        (type_, length) = struct.unpack_from(cls._PACK_STR, buf)
        form = "%ds" % length
        (data_value, ) = struct.unpack_from(form, buf, cls._MIN_LEN)
        return cls(length, data_value)

    def serialize(self):
        # calculate length when it contains 0
        if self.length == 0:
            self.length = len(self.data_value)
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length)
        buf = bytearray(buf)
        form = "%ds" % self.length
        buf.extend(struct.pack(form, self.data_value))
        return buf


@operation.register_tlv_types(CFM_INTERFACE_STATUS_TLV)
class interface_status_tlv(tlv):

    """CFM (IEEE Std 802.1ag-2007) Interface Status TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    length               Length of Value field.
                         (0 means automatically-calculate when encoding.)
    interface_status     Interface Status.The default is 1 (isUp)
    ==================== =======================================
    """

    _PACK_STR = '!BHB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    # Interface Status TLV values
    _IS_UP = 1
    _IS_DOWN = 2
    _IS_TESTING = 3
    _IS_UNKNOWN = 4
    _IS_DORMANT = 5
    _IS_NOT_PRESENT = 6
    _IS_LOWER_LAYER_DOWN = 7

    def __init__(self, length=0, interface_status=_IS_UP):
        super(interface_status_tlv, self).__init__(length)
        self._type = CFM_INTERFACE_STATUS_TLV
        assert interface_status in [
            self._IS_UP, self._IS_DOWN, self._IS_TESTING,
            self._IS_UNKNOWN, self._IS_DORMANT, self._IS_NOT_PRESENT,
            self._IS_LOWER_LAYER_DOWN]
        self.interface_status = interface_status

    @classmethod
    def parser(cls, buf):
        (type_, length,
         interface_status) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(length, interface_status)

    def serialize(self):
        # calculate length when it contains 0
        if self.length == 0:
            self.length = 1
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length,
                          self.interface_status)
        return bytearray(buf)


@operation.register_tlv_types(CFM_LTM_EGRESS_IDENTIFIER_TLV)
class ltm_egress_identifier_tlv(tlv):

    """CFM (IEEE Std 802.1ag-2007) LTM EGRESS TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    length         Length of Value field.
                   (0 means automatically-calculate when encoding.)
    egress_id_ui   Egress Identifier of Unique ID.
    egress_id_mac  Egress Identifier of MAC address.
    ============== =======================================
    """

    _PACK_STR = '!BHH6s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self,
                 length=0,
                 egress_id_ui=0,
                 egress_id_mac='00:00:00:00:00:00'
                 ):
        super(ltm_egress_identifier_tlv, self).__init__(length)
        self._type = CFM_LTM_EGRESS_IDENTIFIER_TLV
        self.egress_id_ui = egress_id_ui
        self.egress_id_mac = egress_id_mac

    @classmethod
    def parser(cls, buf):
        (type_, length, egress_id_ui,
         egress_id_mac) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(length, egress_id_ui,
                   addrconv.mac.bin_to_text(egress_id_mac))

    def serialize(self):
        # calculate length when it contains 0
        if self.length == 0:
            self.length = 8
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length,
                          self.egress_id_ui,
                          addrconv.mac.text_to_bin(self.egress_id_mac)
                          )
        return bytearray(buf)


@operation.register_tlv_types(CFM_LTR_EGRESS_IDENTIFIER_TLV)
class ltr_egress_identifier_tlv(tlv):

    """CFM (IEEE Std 802.1ag-2007) LTR EGRESS TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ==================== =======================================
    Attribute            Description
    ==================== =======================================
    length               Length of Value field.
                         (0 means automatically-calculate when encoding.)
    last_egress_id_ui    Last Egress Identifier of Unique ID.
    last_egress_id_mac   Last Egress Identifier of MAC address.
    next_egress_id_ui    Next Egress Identifier of Unique ID.
    next_egress_id_mac   Next Egress Identifier of MAC address.
    ==================== =======================================
    """

    _PACK_STR = '!BHH6sH6s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self,
                 length=0,
                 last_egress_id_ui=0,
                 last_egress_id_mac='00:00:00:00:00:00',
                 next_egress_id_ui=0,
                 next_egress_id_mac='00:00:00:00:00:00'
                 ):
        super(ltr_egress_identifier_tlv, self).__init__(length)
        self._type = CFM_LTR_EGRESS_IDENTIFIER_TLV
        self.last_egress_id_ui = last_egress_id_ui
        self.last_egress_id_mac = last_egress_id_mac
        self.next_egress_id_ui = next_egress_id_ui
        self.next_egress_id_mac = next_egress_id_mac

    @classmethod
    def parser(cls, buf):
        (type_, length,
         last_egress_id_ui, last_egress_id_mac,
         next_egress_id_ui, next_egress_id_mac
         ) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(length,
                   last_egress_id_ui,
                   addrconv.mac.bin_to_text(last_egress_id_mac),
                   next_egress_id_ui,
                   addrconv.mac.bin_to_text(next_egress_id_mac))

    def serialize(self):
        # calculate length when it contains 0
        if self.length == 0:
            self.length = 16
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length,
                          self.last_egress_id_ui,
                          addrconv.mac.text_to_bin(self.last_egress_id_mac),
                          self.next_egress_id_ui,
                          addrconv.mac.text_to_bin(self.next_egress_id_mac)
                          )
        return bytearray(buf)


@operation.register_tlv_types(CFM_ORGANIZATION_SPECIFIC_TLV)
class organization_specific_tlv(tlv):

    """CFM (IEEE Std 802.1ag-2007) Organization Specific TLV
       encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    length         Length of Value field.
                   (0 means automatically-calculate when encoding.)
    oui            Organizationally Unique Identifier.
    subtype        Subtype.
    value          Value.(optional)
    ============== =======================================
    """

    _PACK_STR = '!BH3sB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _OUI_AND_SUBTYPE_LEN = 4

    def __init__(self,
                 length=0,
                 oui=b"\x00\x00\x00",
                 subtype=0,
                 value=b""
                 ):
        super(organization_specific_tlv, self).__init__(length)
        self._type = CFM_ORGANIZATION_SPECIFIC_TLV
        self.oui = oui
        self.subtype = subtype
        self.value = value

    @classmethod
    def parser(cls, buf):
        (type_, length, oui, subtype) = struct.unpack_from(cls._PACK_STR, buf)
        value = b""
        if length > cls._OUI_AND_SUBTYPE_LEN:
            form = "%ds" % (length - cls._OUI_AND_SUBTYPE_LEN)
            (value,) = struct.unpack_from(form, buf, cls._MIN_LEN)
        return cls(length, oui, subtype, value)

    def serialize(self):
        # calculate length when it contains 0
        if self.length == 0:
            self.length = len(self.value) + self._OUI_AND_SUBTYPE_LEN
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length,
                          self.oui,
                          self.subtype,
                          )
        buf = bytearray(buf)
        form = "%ds" % (self.length - self._OUI_AND_SUBTYPE_LEN)
        buf.extend(struct.pack(form, self.value))
        return buf


class reply_tlv(tlv):

    _PACK_STR = '!BHB6s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _MIN_VALUE_LEN = _MIN_LEN - struct.calcsize('!BH')
    _PORT_ID_LENGTH_LEN = 1
    _PORT_ID_SUBTYPE_LEN = 1

    def __init__(self, length, action, mac_address, port_id_length,
                 port_id_subtype, port_id):
        super(reply_tlv, self).__init__(length)
        self.action = action
        self.mac_address = mac_address
        self.port_id_length = port_id_length
        self.port_id_subtype = port_id_subtype
        self.port_id = port_id

    @classmethod
    def parser(cls, buf):
        (type_, length, action,
         mac_address) = struct.unpack_from(cls._PACK_STR, buf)
        port_id_length = 0
        port_id_subtype = 0
        port_id = b''
        if length > cls._MIN_VALUE_LEN:
            (port_id_length,
             port_id_subtype) = struct.unpack_from('!2B', buf, cls._MIN_LEN)
            form = "%ds" % port_id_length
            (port_id,) = struct.unpack_from(form, buf,
                                            cls._MIN_LEN +
                                            cls._PORT_ID_LENGTH_LEN +
                                            cls._PORT_ID_SUBTYPE_LEN)
        return cls(length, action,
                   addrconv.mac.bin_to_text(mac_address),
                   port_id_length, port_id_subtype, port_id)

    def serialize(self):
        # calculate length when it contains 0
        if self.port_id_length == 0:
            self.port_id_length = len(self.port_id)
        if self.length == 0:
            self.length = self._MIN_VALUE_LEN
            if self.port_id_length != 0:
                self.length += (self.port_id_length +
                                self._PORT_ID_LENGTH_LEN +
                                self._PORT_ID_SUBTYPE_LEN)
        # start serialize
        buf = struct.pack(self._PACK_STR,
                          self._type,
                          self.length,
                          self.action,
                          addrconv.mac.text_to_bin(self.mac_address),
                          )
        buf = bytearray(buf)
        if self.port_id_length != 0:
            buf.extend(struct.pack("!BB",
                                   self.port_id_length,
                                   self.port_id_subtype))
            form = "%ds" % self.port_id_length
            buf.extend(struct.pack(form, self.port_id))
        return buf


@operation.register_tlv_types(CFM_REPLY_INGRESS_TLV)
class reply_ingress_tlv(reply_tlv):

    """CFM (IEEE Std 802.1ag-2007) Reply Ingress TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ================= =======================================
    Attribute         Description
    ================= =======================================
    length            Length of Value field.
                      (0 means automatically-calculate when encoding.)
    action            Ingress Action.The default is 1 (IngOK)
    mac_address       Ingress MAC Address.
    port_id_length    Ingress PortID Length.
                      (0 means automatically-calculate when encoding.)
    port_id_subtype   Ingress PortID Subtype.
    port_id           Ingress PortID.
    ================= =======================================
    """

    # Ingress Action field values
    _ING_OK = 1
    _ING_DOWN = 2
    _ING_BLOCKED = 3
    _ING_VID = 4

    def __init__(self,
                 length=0,
                 action=_ING_OK,
                 mac_address='00:00:00:00:00:00',
                 port_id_length=0,
                 port_id_subtype=0,
                 port_id=b''
                 ):
        super(reply_ingress_tlv, self).__init__(length, action,
                                                mac_address, port_id_length,
                                                port_id_subtype, port_id)
        assert action in [self._ING_OK, self._ING_DOWN,
                          self._ING_BLOCKED, self._ING_VID]
        self._type = CFM_REPLY_INGRESS_TLV


@operation.register_tlv_types(CFM_REPLY_EGRESS_TLV)
class reply_egress_tlv(reply_tlv):

    """CFM (IEEE Std 802.1ag-2007) Reply Egress TLV encoder/decoder class.

    This is used with ryu.lib.packet.cfm.cfm.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ================= =======================================
    Attribute         Description
    ================= =======================================
    length            Length of Value field.
                      (0 means automatically-calculate when encoding.)
    action            Egress Action.The default is 1 (EgrOK)
    mac_address       Egress MAC Address.
    port_id_length    Egress PortID Length.
                      (0 means automatically-calculate when encoding.)
    port_id_subtype   Egress PortID Subtype.
    port_id           Egress PortID.
    ================= =======================================
    """

    # Egress Action field values
    _EGR_OK = 1
    _EGR_DOWN = 2
    _EGR_BLOCKED = 3
    _EGR_VID = 4

    def __init__(self,
                 length=0,
                 action=_EGR_OK,
                 mac_address='00:00:00:00:00:00',
                 port_id_length=0,
                 port_id_subtype=0,
                 port_id=b''
                 ):
        super(reply_egress_tlv, self).__init__(length, action,
                                               mac_address, port_id_length,
                                               port_id_subtype, port_id)
        assert action in [self._EGR_OK, self._EGR_DOWN,
                          self._EGR_BLOCKED, self._EGR_VID]
        self._type = CFM_REPLY_EGRESS_TLV


operation.set_classes(operation._TLV_TYPES)
