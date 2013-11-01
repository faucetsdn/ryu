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
import struct

from ryu.lib import addrconv
from ryu.lib import stringify
from ryu.lib.packet import packet_base

# Chunk Types
TYPE_DATA = 0
TYPE_INIT = 1
TYPE_INIT_ACK = 2
TYPE_SACK = 3
TYPE_HEARTBEAT = 4
TYPE_HEARTBEAT_ACK = 5
TYPE_ABORT = 6
TYPE_SHUTDOWN = 7
TYPE_SHUTDOWN_ACK = 8
TYPE_ERROR = 9
TYPE_COOKIE_ECHO = 10
TYPE_COOKIE_ACK = 11
TYPE_ECN_ECHO = 12
TYPE_CWR = 13
TYPE_SHUTDOWN_COMPLETE = 14

# Cause Code
CCODE_INVALID_STREAM_ID = 1
CCODE_MISSING_PARAM = 2
CCODE_STALE_COOKIE = 3
CCODE_OUT_OF_RESOURCE = 4
CCODE_UNRESOLVABLE_ADDR = 5
CCODE_UNRECOGNIZED_CHUNK = 6
CCODE_INVALID_PARAM = 7
CCODE_UNRECOGNIZED_PARAM = 8
CCODE_NO_USERDATA = 9
CCODE_COOKIE_WHILE_SHUTDOWN = 10
CCODE_RESTART_WITH_NEW_ADDR = 11
CCODE_USER_INITIATED_ABORT = 12
CCODE_PROTOCOL_VIOLATION = 13

# Chunk Parameter Types
PTYPE_HEARTBEAT = 1
PTYPE_IPV4 = 5
PTYPE_IPV6 = 6
PTYPE_STATE_COOKIE = 7
PTYPE_UNRECOGNIZED_PARAM = 8
PTYPE_COOKIE_PRESERVE = 9
PTYPE_HOST_ADDR = 11
PTYPE_SUPPORTED_ADDR = 12
PTYPE_ECN = 32768


class sctp(packet_base.PacketBase):
    """Stream Control Transmission Protocol (SCTP)
    header encoder/decoder class (RFC 4960).

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    src_port       Source Port
    dst_port       Destination Port
    vtag           Verification Tag
    csum           Checksum
                   (0 means automatically-calculate when encoding)
    chunks         a list of derived classes of ryu.lib.packet.sctp.chunk.
    ============== =====================================================
    """

    _PACK_STR = '!HHII'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _SCTP_CHUNK_TYPE = {}
    _class_prefixes = ['chunk_']

    @staticmethod
    def register_chunk_type(*args):
        def _register_chunk_type(cls):
            sctp._SCTP_CHUNK_TYPE[cls.chunk_type()] = cls
            return cls
        return _register_chunk_type(args[0])

    def __init__(self, src_port=0, dst_port=0, vtag=0, csum=0, chunks=None):
        super(sctp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.vtag = vtag
        self.csum = csum
        chunks = chunks or []
        assert isinstance(chunks, list)
        for one in chunks:
            assert isinstance(one, chunk)
        self.chunks = chunks

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, vtag, csum) = struct.unpack_from(
            cls._PACK_STR, buf)
        chunks = []
        offset = cls._MIN_LEN
        while offset < len(buf):
            (type_, ) = struct.unpack_from('!B', buf, offset)
            cls_ = cls._SCTP_CHUNK_TYPE.get(type_)
            if not cls_:
                break
            ins = cls_.parser(buf[offset:])
            chunks.append(ins)
            offset += len(ins)
        msg = cls(src_port, dst_port, vtag, csum, chunks)
        return msg, None, buf[offset:]

    def serialize(self, payload, prev):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.src_port, self.dst_port, self.vtag,
            self.csum))
        if self.chunks:
            for one in self.chunks:
                buf.extend(one.serialize())
        if self.csum == 0:
            self.csum = self._checksum(buf)
            struct.pack_into('!I', buf, 8, self.csum)
        return str(buf)

    def __len__(self):
        length = self._MIN_LEN
        if self.chunks is not None:
            for one in self.chunks:
                length += len(one)
        return length

    def _checksum(self, data):
        # from RFC 3309
        crc_c = [
            0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
            0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
            0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
            0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
            0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
            0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
            0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
            0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
            0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
            0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
            0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
            0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
            0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
            0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
            0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
            0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
            0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
            0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
            0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
            0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
            0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
            0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
            0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
            0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
            0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
            0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
            0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
            0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
            0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
            0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
            0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
            0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
            0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
            0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
            0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
            0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
            0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
            0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
            0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
            0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
            0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
            0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
            0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
            0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
            0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
            0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
            0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
            0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
            0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
            0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
            0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
            0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
            0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
            0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
            0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
            0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
            0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
            0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
            0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
            0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
            0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
            0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
            0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
            0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
        ]

        crc32 = 0xffffffff
        for c in str(data):
            crc32 = (crc32 >> 8) ^ crc_c[(crc32 ^ (ord(c))) & 0xFF]
        crc32 = (~crc32) & 0xffffffff
        return struct.unpack(">I", struct.pack("<I", crc32))[0]


#=======================================================================
#
# Chunk Types
#
#=======================================================================
class chunk(stringify.StringifyMixin):

    __metaclass__ = abc.ABCMeta
    _PACK_STR = '!BBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    @abc.abstractmethod
    def chunk_type(cls):
        pass

    @abc.abstractmethod
    def __init__(self, type_, length):
        self._type = type_
        self.length = length

    @classmethod
    @abc.abstractmethod
    def parser(cls, buf):
        pass

    def __len__(self):
        return self.length


class chunk_init_base(chunk):

    __metaclass__ = abc.ABCMeta
    _PACK_STR = '!BBHIIHHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, flags=0, length=0, init_tag=0, a_rwnd=0, os=0,
                 mis=0, i_tsn=0, params=None):
        super(chunk_init_base, self).__init__(self.chunk_type(), length)
        self.flags = flags
        self.init_tag = init_tag
        self.a_rwnd = a_rwnd
        self.os = os
        self.mis = mis
        self.i_tsn = i_tsn
        params = params or []
        assert isinstance(params, list)
        for one in params:
            assert isinstance(one, param)
        self.params = params

    @classmethod
    def parser_base(cls, buf, recog):
        (_, flags, length, init_tag, a_rwnd, os, mis, i_tsn
         ) = struct.unpack_from(cls._PACK_STR, buf)
        params = []
        offset = cls._MIN_LEN
        while offset < length:
            (ptype, ) = struct.unpack_from('!H', buf, offset)
            cls_ = recog.get(ptype)
            if not cls_:
                break
            ins = cls_.parser(buf[offset:])
            params.append(ins)
            offset += len(ins)
        msg = cls(flags, length, init_tag, a_rwnd, os, mis, i_tsn, params)
        return msg

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags,
            self.length, self.init_tag, self.a_rwnd, self.os, self.mis,
            self.i_tsn))
        for one in self.params:
            buf.extend(one.serialize())
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)


class chunk_heartbeat_base(chunk):

    __metaclass__ = abc.ABCMeta

    def __init__(self, flags=0, length=0, info=None):
        super(chunk_heartbeat_base, self).__init__(
            self.chunk_type(), length)
        self.flags = flags
        if info is not None:
            assert isinstance(info, param)
        self.info = info

    @classmethod
    def parser_base(cls, buf, recog):
        (_, flags, length) = struct.unpack_from(cls._PACK_STR, buf)
        (ptype, ) = struct.unpack_from('!H', buf, cls._MIN_LEN)
        cls_ = recog.get(ptype)
        info = cls_.parser(buf[cls._MIN_LEN:])
        msg = cls(flags, length, info)
        return msg

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags,
            self.length))
        if self.info is not None:
            buf.extend(self.info.serialize())
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)


class chunk_ack_base(chunk):

    __metaclass__ = abc.ABCMeta

    def __init__(self, flags=0, length=0):
        super(chunk_ack_base, self).__init__(self.chunk_type(), length)
        self.flags = flags

    @classmethod
    def parser(cls, buf):
        (_, flags, length) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(flags, length)

    def serialize(self):
        if 0 == self.length:
            self.length = self._MIN_LEN
        buf = struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags,
            self.length)
        return buf


class chunk_ecn_base(chunk):

    __metaclass__ = abc.ABCMeta
    _PACK_STR = '!BBHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, flags=0, length=0, low_tsn=0):
        super(chunk_ecn_base, self).__init__(self.chunk_type(), length)
        self.flags = flags
        self.low_tsn = low_tsn

    @classmethod
    def parser(cls, buf):
        (_, flags, length, low_tsn) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(flags, length, low_tsn)

    def serialize(self):
        if 0 == self.length:
            self.length = self._MIN_LEN
        buf = struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags, self.length,
            self.low_tsn)
        return buf


@sctp.register_chunk_type
class chunk_data(chunk):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Payload Data (DATA) chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    unordered      if set to '1', the receiver ignores the sequence number.
    begin          if set to '1', this chunk is the first fragment.
    end            if set to '1', this chunk is the last fragment.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    tsn            Transmission Sequence Number.
    sid            stream id.
    seq            the sequence number.
    payload_id     application specified protocol id. '0' means that
                   no application id is identified.
    payload_data   user data.
    ============== =====================================================
    """

    _PACK_STR = '!BBHIHHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def chunk_type(cls):
        return TYPE_DATA

    def __init__(self, unordered=0, begin=0, end=0, length=0, tsn=0,
                 sid=0, seq=0, payload_id=0, payload_data=None):
        assert (1 == unordered | 1)
        assert (1 == begin | 1)
        assert (1 == end | 1)
        assert (payload_data is not None)
        super(chunk_data, self).__init__(self.chunk_type(), length)
        self.unordered = unordered
        self.begin = begin
        self.end = end
        self.tsn = tsn
        self.sid = sid
        self.seq = seq
        self.payload_id = payload_id
        self.payload_data = payload_data

    @classmethod
    def parser(cls, buf):
        (_, flags, length, tsn, sid, seq, payload_id
         ) = struct.unpack_from(cls._PACK_STR, buf)
        unordered = (flags >> 2) & 1
        begin = (flags >> 1) & 1
        end = (flags >> 0) & 1
        fmt = '!%ds' % (length - cls._MIN_LEN)
        (payload_data, ) = struct.unpack_from(fmt, buf, cls._MIN_LEN)
        return cls(unordered, begin, end, length, tsn, sid, seq,
                   payload_id, payload_data)

    def serialize(self):
        flags = (
            (self.unordered << 2) |
            (self.begin << 1) |
            (self.end << 0))
        buf = bytearray(struct.pack(
            self._PACK_STR, self.chunk_type(), flags, self.length,
            self.tsn, self.sid, self.seq, self.payload_id))
        buf.extend(self.payload_data)
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)


@sctp.register_chunk_type
class chunk_init(chunk_init_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Initiation (INIT) chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    init_tag       the tag that be used as Verification Tag.
    a_rwnd         Advertised Receiver Window Credit.
    os             number of outbound streams.
    mis            number of inbound streams.
    i_tsn          Transmission Sequence Number that the sender will use.
    params         Optional/Variable-Length Parameters.

                   a list of derived classes of ryu.lib.packet.sctp.param.
    ============== =====================================================
    """

    _RECOGNIZED_PARAMS = {}

    @staticmethod
    def register_param_type(*args):
        def _register_param_type(cls):
            chunk_init._RECOGNIZED_PARAMS[cls.param_type()] = cls
            return cls
        return _register_param_type(args[0])

    @classmethod
    def chunk_type(cls):
        return TYPE_INIT

    @classmethod
    def parser(cls, buf):
        return super(chunk_init, cls).parser_base(
            buf, cls._RECOGNIZED_PARAMS)


@sctp.register_chunk_type
class chunk_init_ack(chunk_init_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Initiation Acknowledgement (INIT ACK)
    chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    init_tag       the tag that be used as Verification Tag.
    a_rwnd         Advertised Receiver Window Credit.
    os             number of outbound streams.
    mis            number of inbound streams.
    i_tsn          Transmission Sequence Number that the sender will use.
    params         Optional/Variable-Length Parameters.

                   a list of derived classes of ryu.lib.packet.sctp.param.
    ============== =====================================================
    """

    _RECOGNIZED_PARAMS = {}

    @staticmethod
    def register_param_type(*args):
        def _register_param_type(cls):
            chunk_init_ack._RECOGNIZED_PARAMS[cls.param_type()] = cls
            return cls
        return _register_param_type(args[0])

    @classmethod
    def chunk_type(cls):
        return TYPE_INIT_ACK

    @classmethod
    def parser(cls, buf):
        return super(chunk_init_ack, cls).parser_base(
            buf, cls._RECOGNIZED_PARAMS)


@sctp.register_chunk_type
class chunk_sack(chunk):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Selective Acknowledgement (SACK) chunk
    (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    tsn_ack        TSN of the last DATA chunk received in sequence
                   before a gap.
    a_rwnd         Advertised Receiver Window Credit.
    gapack_num     number of Gap Ack blocks.
    duptsn_num     number of duplicate TSNs.
    gapacks        a list of Gap Ack blocks. one block is made of a list
                   with the start offset and the end offset from tsn_ack.
                   e.g.) gapacks = [[2, 3], [10, 12], [19, 21]]
    duptsns        a list of duplicate TSN.
    ============== =====================================================
    """

    _PACK_STR = '!BBHIIHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _GAPACK_STR = '!HH'
    _GAPACK_LEN = struct.calcsize(_GAPACK_STR)
    _DUPTSN_STR = '!I'
    _DUPTSN_LEN = struct.calcsize(_DUPTSN_STR)

    @classmethod
    def chunk_type(cls):
        return TYPE_SACK

    def __init__(self, flags=0, length=0, tsn_ack=0, a_rwnd=0,
                 gapack_num=0, duptsn_num=0, gapacks=None, duptsns=None):
        super(chunk_sack, self).__init__(self.chunk_type(), length)
        self.flags = flags
        self.tsn_ack = tsn_ack
        self.a_rwnd = a_rwnd
        self.gapack_num = gapack_num
        self.duptsn_num = duptsn_num
        gapacks = gapacks or []
        assert isinstance(gapacks, list)
        for one in gapacks:
            assert isinstance(one, list)
            assert 2 == len(one)
        self.gapacks = gapacks
        duptsns = duptsns or []
        assert isinstance(duptsns, list)
        self.duptsns = duptsns

    @classmethod
    def parser(cls, buf):
        (_, flags, length, tsn_ack, a_rwnd, gapack_num, duptsn_num
         ) = struct.unpack_from(cls._PACK_STR, buf)
        gapacks = []
        offset = cls._MIN_LEN
        for _ in range(gapack_num):
            (gapack_start, gapack_end) = struct.unpack_from(
                cls._GAPACK_STR, buf, offset)
            gapacks.append([gapack_start, gapack_end])
            offset += cls._GAPACK_LEN
        duptsns = []
        for _ in range(duptsn_num):
            (duptsn, ) = struct.unpack_from(cls._DUPTSN_STR, buf, offset)
            duptsns.append(duptsn)
            offset += cls._DUPTSN_LEN
        return cls(flags, length, tsn_ack, a_rwnd, gapack_num, duptsn_num,
                   gapacks, duptsns)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags,
            self.length, self.tsn_ack, self.a_rwnd, self.gapack_num,
            self.duptsn_num))
        for one in self.gapacks:
            buf.extend(struct.pack(chunk_sack._GAPACK_STR, one[0], one[1]))
        for one in self.duptsns:
            buf.extend(struct.pack(chunk_sack._DUPTSN_STR, one))
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)


@sctp.register_chunk_type
class chunk_heartbeat(chunk_heartbeat_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Heartbeat Request (HEARTBEAT) chunk
    (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    info           ryu.lib.packet.sctp.param_heartbeat.
    ============== =====================================================
    """

    _RECOGNIZED_PARAMS = {}

    @staticmethod
    def register_param_type(*args):
        def _register_param_type(cls):
            chunk_heartbeat._RECOGNIZED_PARAMS[cls.param_type()] = cls
            return cls
        return _register_param_type(args[0])

    @classmethod
    def chunk_type(cls):
        return TYPE_HEARTBEAT

    @classmethod
    def parser(cls, buf):
        return super(chunk_heartbeat, cls).parser_base(
            buf, cls._RECOGNIZED_PARAMS)


@sctp.register_chunk_type
class chunk_heartbeat_ack(chunk_heartbeat_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Heartbeat Acknowledgement
    (HEARTBEAT ACK) chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    info           ryu.lib.packet.sctp.param_heartbeat.
    ============== =====================================================
    """

    _RECOGNIZED_PARAMS = {}

    @staticmethod
    def register_param_type(*args):
        def _register_param_type(cls):
            chunk_heartbeat_ack._RECOGNIZED_PARAMS[cls.param_type()] = cls
            return cls
        return _register_param_type(args[0])

    @classmethod
    def chunk_type(cls):
        return TYPE_HEARTBEAT_ACK

    @classmethod
    def parser(cls, buf):
        return super(chunk_heartbeat_ack, cls).parser_base(
            buf, cls._RECOGNIZED_PARAMS)


@sctp.register_chunk_type
class chunk_abort(chunk):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Abort Association (ABORT) chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    tflag          '0' means the Verification tag is normal. '1' means
                   the Verification tag is copy of the sender.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    causes         a list of derived classes of ryu.lib.packet.sctp.causes.
    ============== =====================================================
    """

    _class_prefixes = ['cause_']
    _RECOGNIZED_CAUSES = {}

    @staticmethod
    def register_cause_code(*args):
        def _register_cause_code(cls):
            chunk_abort._RECOGNIZED_CAUSES[cls.cause_code()] = cls
            return cls
        return _register_cause_code(args[0])

    @classmethod
    def chunk_type(cls):
        return TYPE_ABORT

    def __init__(self, tflag=0, length=0, causes=None):
        super(chunk_abort, self).__init__(self.chunk_type(), length)
        assert (1 == tflag | 1)
        self.tflag = tflag
        causes = causes or []
        assert isinstance(causes, list)
        for one in causes:
            assert isinstance(one, cause)
        self.causes = causes

    @classmethod
    def parser(cls, buf):
        (_, flags, length) = struct.unpack_from(cls._PACK_STR, buf)
        tflag = (flags >> 0) & 1
        causes = []
        offset = cls._MIN_LEN
        while offset < length:
            (ccode, ) = struct.unpack_from('!H', buf, offset)
            cls_ = cls._RECOGNIZED_CAUSES.get(ccode)
            if not cls_:
                break
            ins = cls_.parser(buf[offset:])
            causes.append(ins)
            offset += len(ins)
        return cls(tflag, length, causes)

    def serialize(self):
        flags = (self.tflag << 0)
        buf = bytearray(struct.pack(
            self._PACK_STR, self.chunk_type(), flags, self.length))
        for one in self.causes:
            buf.extend(one.serialize())
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)


@sctp.register_chunk_type
class chunk_shutdown(chunk):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Shutdown Association (SHUTDOWN) chunk
    (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    tsn_ack        TSN of the last DATA chunk received in sequence
                   before a gap.
    ============== =====================================================
    """

    _PACK_STR = '!BBHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def chunk_type(cls):
        return TYPE_SHUTDOWN

    def __init__(self, flags=0, length=0, tsn_ack=0):
        super(chunk_shutdown, self).__init__(self.chunk_type(), length)
        self.flags = flags
        self.tsn_ack = tsn_ack

    @classmethod
    def parser(cls, buf):
        (_, flags, length, tsn_ack
         ) = struct.unpack_from(cls._PACK_STR, buf)
        msg = cls(flags, length, tsn_ack)
        return msg

    def serialize(self):
        if 0 == self.length:
            self.length = self._MIN_LEN
        buf = struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags,
            self.length, self.tsn_ack)
        return buf


@sctp.register_chunk_type
class chunk_shutdown_ack(chunk_ack_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Shutdown Acknowledgement (SHUTDOWN ACK)
    chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def chunk_type(cls):
        return TYPE_SHUTDOWN_ACK


@sctp.register_chunk_type
class chunk_error(chunk):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Operation Error (ERROR) chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    causes         a list of derived classes of ryu.lib.packet.sctp.causes.
    ============== =====================================================
    """

    _class_prefixes = ['cause_']
    _RECOGNIZED_CAUSES = {}

    @staticmethod
    def register_cause_code(*args):
        def _register_cause_code(cls):
            chunk_error._RECOGNIZED_CAUSES[cls.cause_code()] = cls
            return cls
        return _register_cause_code(args[0])

    @classmethod
    def chunk_type(cls):
        return TYPE_ERROR

    def __init__(self, flags=0, length=0, causes=None):
        super(chunk_error, self).__init__(self.chunk_type(), length)
        self.flags = flags
        causes = causes or []
        assert isinstance(causes, list)
        for one in causes:
            assert isinstance(one, cause)
        self.causes = causes

    @classmethod
    def parser(cls, buf):
        (_, flags, length) = struct.unpack_from(cls._PACK_STR, buf)
        causes = []
        offset = cls._MIN_LEN
        while offset < length:
            (ccode, ) = struct.unpack_from('!H', buf, offset)
            cls_ = cls._RECOGNIZED_CAUSES.get(ccode)
            if not cls_:
                break
            ins = cls_.parser(buf[offset:])
            causes.append(ins)
            offset += len(ins)
        return cls(flags, length, causes)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags, self.length))
        for one in self.causes:
            buf.extend(one.serialize())
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)


@sctp.register_chunk_type
class chunk_cookie_echo(chunk):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Cookie Echo (COOKIE ECHO) chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    cookie         cookie data.
    ============== =====================================================
    """

    _PACK_STR = '!BBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def chunk_type(cls):
        return TYPE_COOKIE_ECHO

    def __init__(self, flags=0, length=0, cookie=None):
        super(chunk_cookie_echo, self).__init__(self.chunk_type(), length)
        self.flags = flags
        self.cookie = cookie

    @classmethod
    def parser(cls, buf):
        (_, flags, length) = struct.unpack_from(cls._PACK_STR, buf)
        _len = length - cls._MIN_LEN
        cookie = None
        if _len:
            fmt = '%ds' % _len
            (cookie, ) = struct.unpack_from(fmt, buf, cls._MIN_LEN)
        return cls(flags, length, cookie)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.chunk_type(), self.flags,
            self.length))
        if self.cookie is not None:
            buf.extend(self.cookie)
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        mod = len(buf) % 4
        if mod:
            buf.extend(bytearray(4 - mod))
        return str(buf)


@sctp.register_chunk_type
class chunk_cookie_ack(chunk_ack_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Cookie Acknowledgement (COOKIE ACK)
    chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def chunk_type(cls):
        return TYPE_COOKIE_ACK


@sctp.register_chunk_type
class chunk_ecn_echo(chunk_ecn_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for ECN-Echo chunk (RFC 4960 Appendix A.).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    low_tsn        the lowest TSN.
    ============== =====================================================
    """

    @classmethod
    def chunk_type(cls):
        return TYPE_ECN_ECHO


@sctp.register_chunk_type
class chunk_cwr(chunk_ecn_base):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for CWR chunk (RFC 4960 Appendix A.).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    flags          set to '0'. this field will be ignored.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    low_tsn        the lowest TSN.
    ============== =====================================================
    """

    @classmethod
    def chunk_type(cls):
        return TYPE_CWR


@sctp.register_chunk_type
class chunk_shutdown_complete(chunk):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Shutdown Complete (SHUTDOWN COMPLETE)
    chunk (RFC 4960).

    This is used with ryu.lib.packet.sctp.sctp.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    tflag          '0' means the Verification tag is normal. '1' means
                   the Verification tag is copy of the sender.
    length         length of this chunk containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _PACK_STR = '!BBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def chunk_type(cls):
        return TYPE_SHUTDOWN_COMPLETE

    def __init__(self, tflag=0, length=0):
        assert (1 == tflag | 1)
        super(chunk_shutdown_complete, self).__init__(
            self.chunk_type(), length)
        self.tflag = tflag

    @classmethod
    def parser(cls, buf):
        (_, flags, length) = struct.unpack_from(cls._PACK_STR, buf)
        tflag = flags & 1
        msg = cls(tflag, length)
        return msg

    def serialize(self):
        if 0 == self.length:
            self.length = self._MIN_LEN
        buf = struct.pack(
            self._PACK_STR, self.chunk_type(),
            self.tflag, self.length)
        return buf


#=======================================================================
#
# Cause Code
#
#=======================================================================
class cause(stringify.StringifyMixin):

    __metaclass__ = abc.ABCMeta
    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    @abc.abstractmethod
    def cause_code(cls):
        pass

    def __init__(self, length=0):
        self.length = length

    @classmethod
    @abc.abstractmethod
    def parser(cls, buf):
        pass

    def serialize(self):
        if 0 == self.length:
            self.length = self._MIN_LEN
        buf = struct.pack(
            self._PACK_STR, self.cause_code(), self.length)
        return buf

    def __len__(self):
        length = self.length
        mod = length % 4
        if mod:
            length += 4 - mod
        return length


class cause_with_value(cause):

    __metaclass__ = abc.ABCMeta

    def __init__(self, value=None, length=0):
        super(cause_with_value, self).__init__(length)
        self.value = value

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        value = None
        if (cls._MIN_LEN < length):
            fmt = '%ds' % (length - cls._MIN_LEN)
            (value, ) = struct.unpack_from(fmt, buf, cls._MIN_LEN)
        return cls(value, length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.cause_code(), self.length))
        if self.value is not None:
            buf.extend(self.value)
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        mod = len(buf) % 4
        if mod:
            buf.extend(bytearray(4 - mod))
        return str(buf)


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_invalid_stream_id(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Invalid Stream Identifier (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          stream id.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _PACK_STR = '!HHH2x'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def cause_code(cls):
        return CCODE_INVALID_STREAM_ID

    def __init__(self, value=0, length=0):
        super(cause_invalid_stream_id, self).__init__(value, length)

    @classmethod
    def parser(cls, buf):
        (_, length, value) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(value, length)

    def serialize(self):
        if 0 == self.length:
            self.length = self._MIN_LEN
        buf = struct.pack(
            self._PACK_STR, self.cause_code(), self.length, self.value)
        return buf


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_missing_param(cause):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Missing Mandatory Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    types          a list of missing params.
    num            Number of missing params.
                   (0 means automatically-calculate when encoding)
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _PACK_STR = '!HHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def cause_code(cls):
        return CCODE_MISSING_PARAM

    def __init__(self, types=None, num=0, length=0):
        super(cause_missing_param, self).__init__(length)
        types = types or []
        assert isinstance(types, list)
        for one in types:
            assert isinstance(one, int)
        self.types = types
        self.num = num

    @classmethod
    def parser(cls, buf):
        (_, length, num) = struct.unpack_from(cls._PACK_STR, buf)
        types = []
        offset = cls._MIN_LEN
        for count in range(num):
            offset = cls._MIN_LEN + (struct.calcsize('!H') * count)
            (one, ) = struct.unpack_from('!H', buf, offset)
            types.append(one)
        return cls(types, num, length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.cause_code(), self.length, self.num))
        for one in self.types:
            buf.extend(struct.pack('!H', one))
        if 0 == self.num:
            self.num = len(self.types)
            struct.pack_into('!I', buf, 4, self.num)
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        mod = len(buf) % 4
        if mod:
            buf.extend(bytearray(4 - mod))
        return str(buf)


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_stale_cookie(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Stale Cookie Error (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          Measure of Staleness.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_STALE_COOKIE


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_out_of_resource(cause):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Out of Resource (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_OUT_OF_RESOURCE

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(length)


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_unresolvable_addr(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Unresolvable Address (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          Unresolvable Address. one of follows:

                   ryu.lib.packet.sctp.param_host_addr,

                   ryu.lib.packet.sctp.param_ipv4, or

                   ryu.lib.packet.sctp.param_ipv6.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _RECOGNIZED_PARAMS = {}

    @staticmethod
    def register_param_type(*args):
        def _register_param_type(cls):
            cause_unresolvable_addr._RECOGNIZED_PARAMS[cls.param_type()] = cls
            return cls
        return _register_param_type(args[0])

    @classmethod
    def cause_code(cls):
        return CCODE_UNRESOLVABLE_ADDR

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        (ptype, ) = struct.unpack_from('!H', buf, cls._MIN_LEN)
        cls_ = cls._RECOGNIZED_PARAMS.get(ptype)
        value = cls_.parser(buf[cls._MIN_LEN:])
        return cls(value, length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.cause_code(), self.length))
        buf.extend(self.value.serialize())
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        mod = len(buf) % 4
        if mod:
            buf.extend(bytearray(4 - mod))
        return str(buf)


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_unrecognized_chunk(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Unrecognized Chunk Type (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          Unrecognized Chunk.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_UNRECOGNIZED_CHUNK


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_invalid_param(cause):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Invalid Mandatory Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_INVALID_PARAM

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(length)


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_unrecognized_param(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Unrecognized Parameters (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          Unrecognized Parameter.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_UNRECOGNIZED_PARAM


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_no_userdata(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for No User Data (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          the TSN of the DATA chunk received with no user data
                   field.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_NO_USERDATA


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_cookie_while_shutdown(cause):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Cookie Received While Shutting Down
    (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_COOKIE_WHILE_SHUTDOWN

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(length)


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_restart_with_new_addr(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Restart of an Association with New
    Addresses (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          New Address TLVs.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _RECOGNIZED_PARAMS = {}

    @staticmethod
    def register_param_type(*args):
        def _register_param_type(cls):
            cause_restart_with_new_addr._RECOGNIZED_PARAMS[
                cls.param_type()] = cls
            return cls
        return _register_param_type(args[0])

    @classmethod
    def cause_code(cls):
        return CCODE_RESTART_WITH_NEW_ADDR

    def __init__(self, value=None, length=0):
        if not isinstance(value, list):
            value = [value]
        super(cause_restart_with_new_addr, self).__init__(value, length)

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        value = []
        offset = cls._MIN_LEN
        while offset < length:
            (ptype, ) = struct.unpack_from('!H', buf, offset)
            cls_ = cls._RECOGNIZED_PARAMS.get(ptype)
            if not cls_:
                break
            ins = cls_.parser(buf[offset:])
            value.append(ins)
            offset += len(ins)
        return cls(value, length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.cause_code(), self.length))
        for one in self.value:
            buf.extend(one.serialize())
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        mod = len(buf) % 4
        if mod:
            buf.extend(bytearray(4 - mod))
        return str(buf)


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_user_initiated_abort(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for User-Initiated Abort (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          Upper Layer Abort Reason.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_USER_INITIATED_ABORT


@chunk_abort.register_cause_code
@chunk_error.register_cause_code
class cause_protocol_violation(cause_with_value):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Protocol Violation (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_abort and
                      ryu.lib.packet.sctp.chunk_error.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          Additional Information.
    length         length of this cause containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def cause_code(cls):
        return CCODE_PROTOCOL_VIOLATION


#=======================================================================
#
# Chunk Parameter Types
#
#=======================================================================
class param(stringify.StringifyMixin):

    __metaclass__ = abc.ABCMeta
    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    @abc.abstractmethod
    def param_type(cls):
        pass

    def __init__(self, value=None, length=0):
        self.length = length
        self.value = value

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        value = None
        if (cls._MIN_LEN < length):
            fmt = '%ds' % (length - cls._MIN_LEN)
            (value, ) = struct.unpack_from(fmt, buf, cls._MIN_LEN)
        return cls(value, length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.param_type(), self.length))
        if self.value:
            buf.extend(self.value)
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        mod = len(buf) % 4
        if mod:
            buf.extend(bytearray(4 - mod))
        return str(buf)

    def __len__(self):
        length = self.length
        mod = length % 4
        if mod:
            length += 4 - mod
        return length


@chunk_heartbeat.register_param_type
@chunk_heartbeat_ack.register_param_type
class param_heartbeat(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Heartbeat Info Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_heartbeat and
                      ryu.lib.packet.sctp.chunk_heartbeat_ack.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          the sender-specific heartbeat information.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def param_type(cls):
        return PTYPE_HEARTBEAT


@chunk_init_ack.register_param_type
class param_state_cookie(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for State Cookie Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_init_ack.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          the state cookie. see Section 5.1.3 in RFC 4960.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def param_type(cls):
        return PTYPE_STATE_COOKIE


@chunk_init_ack.register_param_type
class param_unrecognized_param(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Unrecognized Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_init_ack.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          the unrecognized parameter in the INIT chunk.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def param_type(cls):
        return PTYPE_UNRECOGNIZED_PARAM


@chunk_init.register_param_type
class param_cookie_preserve(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Cookie Preservative Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_init.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          Suggested Cookie Life-Span Increment (msec).
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _PACK_STR = '!HHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def param_type(cls):
        return PTYPE_COOKIE_PRESERVE

    def __init__(self, value=0, length=0):
        super(param_cookie_preserve, self).__init__(value, length)

    @classmethod
    def parser(cls, buf):
        (_, length, value) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(value, length)

    def serialize(self):
        if 0 == self.length:
            self.length = self._MIN_LEN
        buf = struct.pack(
            self._PACK_STR, self.param_type(), self.length, self.value)
        return buf


@chunk_init.register_param_type
@chunk_init_ack.register_param_type
class param_ecn(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for ECN Parameter (RFC 4960 Appendix A.).

    This is used with ryu.lib.packet.sctp.chunk_init and
                      ryu.lib.packet.sctp.chunk_init_ack.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          set to None.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def param_type(cls):
        return PTYPE_ECN

    def __init__(self, value=None, length=0):
        super(param_ecn, self).__init__(value, length)
        assert 4 == length or 0 == length
        assert None is value


@chunk_init.register_param_type
@chunk_init_ack.register_param_type
@cause_unresolvable_addr.register_param_type
@cause_restart_with_new_addr.register_param_type
class param_host_addr(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Host Name Address Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_init and
                      ryu.lib.packet.sctp.chunk_init_ack.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          a host name that ends with null terminator.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    @classmethod
    def param_type(cls):
        return PTYPE_HOST_ADDR


@chunk_init.register_param_type
class param_supported_addr(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for Supported Address Types Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_init.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          a list of parameter types. odd cases pad with 0x0000.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _VALUE_STR = '!H'
    _VALUE_LEN = struct.calcsize(_VALUE_STR)

    @classmethod
    def param_type(cls):
        return PTYPE_SUPPORTED_ADDR

    def __init__(self, value=None, length=0):
        if not isinstance(value, list):
            value = [value]
        for one in value:
            assert isinstance(one, int)
        super(param_supported_addr, self).__init__(value, length)

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        value = []
        offset = cls._MIN_LEN
        while offset < length:
            (one, ) = struct.unpack_from(cls._VALUE_STR, buf, offset)
            value.append(one)
            offset += cls._VALUE_LEN
        return cls(value, length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.param_type(), self.length))
        for one in self.value:
            buf.extend(struct.pack(param_supported_addr._VALUE_STR, one))
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        mod = len(buf) % 4
        if mod:
            buf.extend(bytearray(4 - mod))
        return str(buf)


@chunk_init.register_param_type
@chunk_init_ack.register_param_type
@cause_unresolvable_addr.register_param_type
@cause_restart_with_new_addr.register_param_type
class param_ipv4(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for IPv4 Address Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_init and
                      ryu.lib.packet.sctp.chunk_init_ack.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          IPv4 address of the sending endpoint.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _TYPE = {'ascii': ['value']}

    @classmethod
    def param_type(cls):
        return PTYPE_IPV4

    def __init__(self, value='127.0.0.1', length=0):
        super(param_ipv4, self).__init__(value, length)

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        value = None
        if (cls._MIN_LEN < length):
            fmt = '%ds' % (length - cls._MIN_LEN)
            (value, ) = struct.unpack_from(fmt, buf, cls._MIN_LEN)
        return cls(addrconv.ipv4.bin_to_text(value), length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.param_type(), self.length))
        if self.value:
            buf.extend(addrconv.ipv4.text_to_bin(self.value))
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)


@chunk_init.register_param_type
@chunk_init_ack.register_param_type
@cause_unresolvable_addr.register_param_type
@cause_restart_with_new_addr.register_param_type
class param_ipv6(param):
    """Stream Control Transmission Protocol (SCTP)
    sub encoder/decoder class for IPv6 Address Parameter (RFC 4960).

    This is used with ryu.lib.packet.sctp.chunk_init and
                      ryu.lib.packet.sctp.chunk_init_ack.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =====================================================
    Attribute      Description
    ============== =====================================================
    value          IPv6 address of the sending endpoint.
    length         length of this param containing this header.
                   (0 means automatically-calculate when encoding)
    ============== =====================================================
    """

    _TYPE = {'ascii': ['value']}

    @classmethod
    def param_type(cls):
        return PTYPE_IPV6

    def __init__(self, value='::1', length=0):
        super(param_ipv6, self).__init__(value, length)

    @classmethod
    def parser(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        value = None
        if (cls._MIN_LEN < length):
            fmt = '%ds' % (length - cls._MIN_LEN)
            (value, ) = struct.unpack_from(fmt, buf, cls._MIN_LEN)
        return cls(addrconv.ipv6.bin_to_text(value), length)

    def serialize(self):
        buf = bytearray(struct.pack(
            self._PACK_STR, self.param_type(), self.length))
        if self.value:
            buf.extend(addrconv.ipv6.text_to_bin(self.value))
        if 0 == self.length:
            self.length = len(buf)
            struct.pack_into('!H', buf, 2, self.length)
        return str(buf)
