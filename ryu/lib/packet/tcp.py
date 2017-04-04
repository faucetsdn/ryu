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

import struct
import logging

import six

from ryu.lib import stringify
from . import packet_base
from . import packet_utils
from . import bgp
from . import openflow
from . import zebra


LOG = logging.getLogger(__name__)

# TCP Option Kind Numbers
TCP_OPTION_KIND_END_OF_OPTION_LIST = 0    # End of Option List
TCP_OPTION_KIND_NO_OPERATION = 1          # No-Operation
TCP_OPTION_KIND_MAXIMUM_SEGMENT_SIZE = 2  # Maximum Segment Size
TCP_OPTION_KIND_WINDOW_SCALE = 3          # Window Scale
TCP_OPTION_KIND_SACK_PERMITTED = 4        # SACK Permitted
TCP_OPTION_KIND_SACK = 5                  # SACK
TCP_OPTION_KIND_TIMESTAMPS = 8            # Timestamps
TCP_OPTION_KIND_USER_TIMEOUT = 28         # User Timeout Option
TCP_OPTION_KIND_AUTHENTICATION = 29       # TCP Authentication Option (TCP-AO)

TCP_FIN = 0x001
TCP_SYN = 0x002
TCP_RST = 0x004
TCP_PSH = 0x008
TCP_ACK = 0x010
TCP_URG = 0x020
TCP_ECE = 0x040
TCP_CWR = 0x080
TCP_NS = 0x100


class tcp(packet_base.PacketBase):
    """TCP (RFC 793) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    src_port       Source Port
    dst_port       Destination Port
    seq            Sequence Number
    ack            Acknowledgement Number
    offset         Data Offset \
                   (0 means automatically-calculate when encoding)
    bits           Control Bits
    window_size    Window
    csum           Checksum \
                   (0 means automatically-calculate when encoding)
    urgent         Urgent Pointer
    option         List of ``TCPOption`` sub-classes or an bytearray
                   containing options. \
                   None if no options.
    ============== ====================
    """

    _PACK_STR = '!HHIIBBHHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, src_port=1, dst_port=1, seq=0, ack=0, offset=0,
                 bits=0, window_size=0, csum=0, urgent=0, option=None):
        super(tcp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.offset = offset
        self.bits = bits
        self.window_size = window_size
        self.csum = csum
        self.urgent = urgent
        self.option = option

    def __len__(self):
        return self.offset * 4

    def has_flags(self, *flags):
        """Check if flags are set on this packet.

        returns boolean if all passed flags is set

        Example::

            >>> pkt = tcp.tcp(bits=(tcp.TCP_SYN | tcp.TCP_ACK))
            >>> pkt.has_flags(tcp.TCP_SYN, tcp.TCP_ACK)
            True
        """

        mask = sum(flags)
        return (self.bits & mask) == mask

    @staticmethod
    def get_payload_type(src_port, dst_port):
        from ryu.ofproto.ofproto_common import OFP_TCP_PORT, OFP_SSL_PORT_OLD
        if bgp.TCP_SERVER_PORT in [src_port, dst_port]:
            return bgp.BGPMessage
        elif(src_port in [OFP_TCP_PORT, OFP_SSL_PORT_OLD] or
             dst_port in [OFP_TCP_PORT, OFP_SSL_PORT_OLD]):
            return openflow.openflow
        elif src_port == zebra.ZEBRA_PORT:
            return zebra._ZebraMessageFromZebra
        elif dst_port == zebra.ZEBRA_PORT:
            return zebra.ZebraMessage
        else:
            return None

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, seq, ack, offset, bits, window_size,
         csum, urgent) = struct.unpack_from(cls._PACK_STR, buf)
        offset >>= 4
        bits &= 0x3f
        length = offset * 4
        if length > tcp._MIN_LEN:
            option_buf = buf[tcp._MIN_LEN:length]
            try:
                option = []
                while option_buf:
                    opt, option_buf = TCPOption.parser(option_buf)
                    option.append(opt)
            except struct.error:
                LOG.warning(
                    'Encounter an error during parsing TCP option field.'
                    'Skip parsing TCP option.')
                option = buf[tcp._MIN_LEN:length]
        else:
            option = None
        msg = cls(src_port, dst_port, seq, ack, offset, bits,
                  window_size, csum, urgent, option)

        return msg, cls.get_payload_type(src_port, dst_port), buf[length:]

    def serialize(self, payload, prev):
        offset = self.offset << 4
        h = bytearray(struct.pack(
            tcp._PACK_STR, self.src_port, self.dst_port, self.seq,
            self.ack, offset, self.bits, self.window_size, self.csum,
            self.urgent))

        if self.option:
            if isinstance(self.option, (list, tuple)):
                option_buf = bytearray()
                for opt in self.option:
                    option_buf.extend(opt.serialize())
                h.extend(option_buf)
                mod = len(option_buf) % 4
            else:
                h.extend(self.option)
                mod = len(self.option) % 4
            if mod:
                h.extend(bytearray(4 - mod))
            if self.offset:
                offset = self.offset << 2
                if len(h) < offset:
                    h.extend(bytearray(offset - len(h)))

        if self.offset == 0:
            self.offset = len(h) >> 2
            offset = self.offset << 4
            struct.pack_into('!B', h, 12, offset)

        if self.csum == 0:
            total_length = len(h) + len(payload)
            self.csum = packet_utils.checksum_ip(prev, total_length,
                                                 h + payload)
            struct.pack_into('!H', h, 16, self.csum)
        return six.binary_type(h)


class TCPOption(stringify.StringifyMixin):
    _KINDS = {}
    _KIND_PACK_STR = '!B'  # kind
    NO_BODY_OFFSET = 1     # kind(1 byte)
    WITH_BODY_OFFSET = 2   # kind(1 byte) + length(1 byte)
    cls_kind = None
    cls_length = None

    def __init__(self, kind=None, length=None):
        self.kind = self.cls_kind if kind is None else kind
        self.length = self.cls_length if length is None else length

    @classmethod
    def register(cls, kind, length):
        def _register(subcls):
            subcls.cls_kind = kind
            subcls.cls_length = length
            cls._KINDS[kind] = subcls
            return subcls
        return _register

    @classmethod
    def parse(cls, buf):
        # For no body TCP Options
        return cls(cls.cls_kind, cls.cls_length), buf[cls.cls_length:]

    @classmethod
    def parser(cls, buf):
        (kind,) = struct.unpack_from(cls._KIND_PACK_STR, buf)
        subcls = cls._KINDS.get(kind)
        if not subcls:
            subcls = TCPOptionUnknown
        return subcls.parse(buf)

    def serialize(self):
        # For no body TCP Options
        return struct.pack(self._KIND_PACK_STR, self.cls_kind)


class TCPOptionUnknown(TCPOption):
    _PACK_STR = '!BB'  # kind, length

    def __init__(self, value, kind, length):
        super(TCPOptionUnknown, self).__init__(kind, length)
        self.value = value if value is not None else b''

    @classmethod
    def parse(cls, buf):
        (kind, length) = struct.unpack_from(cls._PACK_STR, buf)
        value = buf[2:length]
        return cls(value, kind, length), buf[length:]

    def serialize(self):
        self.length = self.WITH_BODY_OFFSET + len(self.value)
        return struct.pack(self._PACK_STR,
                           self.kind, self.length) + self.value


@TCPOption.register(TCP_OPTION_KIND_END_OF_OPTION_LIST,
                    TCPOption.NO_BODY_OFFSET)
class TCPOptionEndOfOptionList(TCPOption):
    pass


@TCPOption.register(TCP_OPTION_KIND_NO_OPERATION,
                    TCPOption.NO_BODY_OFFSET)
class TCPOptionNoOperation(TCPOption):
    pass


@TCPOption.register(TCP_OPTION_KIND_MAXIMUM_SEGMENT_SIZE, 4)
class TCPOptionMaximumSegmentSize(TCPOption):
    _PACK_STR = '!BBH'  # kind, length, max_seg_size

    def __init__(self, max_seg_size, kind=None, length=None):
        super(TCPOptionMaximumSegmentSize, self).__init__(kind, length)
        self.max_seg_size = max_seg_size

    @classmethod
    def parse(cls, buf):
        (_, _, max_seg_size) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(max_seg_size,
                   cls.cls_kind, cls.cls_length), buf[cls.cls_length:]

    def serialize(self):
        return struct.pack(self._PACK_STR,
                           self.kind, self.length, self.max_seg_size)


@TCPOption.register(TCP_OPTION_KIND_WINDOW_SCALE, 3)
class TCPOptionWindowScale(TCPOption):
    _PACK_STR = '!BBB'  # kind, length, shift_cnt

    def __init__(self, shift_cnt, kind=None, length=None):
        super(TCPOptionWindowScale, self).__init__(kind, length)
        self.shift_cnt = shift_cnt

    @classmethod
    def parse(cls, buf):
        (_, _, shift_cnt) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(shift_cnt,
                   cls.cls_kind, cls.cls_length), buf[cls.cls_length:]

    def serialize(self):
        return struct.pack(self._PACK_STR,
                           self.kind, self.length, self.shift_cnt)


@TCPOption.register(TCP_OPTION_KIND_SACK_PERMITTED, 2)
class TCPOptionSACKPermitted(TCPOption):
    _PACK_STR = '!BB'  # kind, length

    def serialize(self):
        return struct.pack(self._PACK_STR, self.kind, self.length)


@TCPOption.register(TCP_OPTION_KIND_SACK,
                    2)  # variable length. 2 is the length except blocks.
class TCPOptionSACK(TCPOption):
    _PACK_STR = '!BB'        # kind, length
    _BLOCK_PACK_STR = '!II'  # Left Edge of Block, Right Edge of Block

    def __init__(self, blocks, kind=None, length=None):
        super(TCPOptionSACK, self).__init__(kind, length)
        # blocks is a list of tuple as followings.
        # self.blocks = [
        #     ('Left Edge of 1st Block', 'Right Edge of 1st Block'),
        #     ...
        #     ('Left Edge of nth Block', 'Right Edge of nth Block')
        # ]
        self.blocks = blocks

    @classmethod
    def parse(cls, buf):
        (_, length) = struct.unpack_from(cls._PACK_STR, buf)
        blocks_buf = buf[2:length]
        blocks = []
        while blocks_buf:
            lr_block = struct.unpack_from(cls._BLOCK_PACK_STR, blocks_buf)
            blocks.append(lr_block)  # (left, right)
            blocks_buf = blocks_buf[8:]
        return cls(blocks, cls.cls_kind, length), buf[length:]

    def serialize(self):
        buf = bytearray()
        for left, right in self.blocks:
            buf += struct.pack(self._BLOCK_PACK_STR, left, right)
        self.length = self.cls_length + len(buf)
        return struct.pack(self._PACK_STR, self.kind, self.length) + buf


@TCPOption.register(TCP_OPTION_KIND_TIMESTAMPS, 10)
class TCPOptionTimestamps(TCPOption):
    _PACK_STR = '!BBII'  # kind, length, ts_val, ts_ecr

    def __init__(self, ts_val, ts_ecr, kind=None, length=None):
        super(TCPOptionTimestamps, self).__init__(kind, length)
        self.ts_val = ts_val
        self.ts_ecr = ts_ecr

    @classmethod
    def parse(cls, buf):
        (_, _, ts_val, ts_ecr) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(ts_val, ts_ecr,
                   cls.cls_kind, cls.cls_length), buf[cls.cls_length:]

    def serialize(self):
        return struct.pack(self._PACK_STR,
                           self.kind, self.length, self.ts_val, self.ts_ecr)


@TCPOption.register(TCP_OPTION_KIND_USER_TIMEOUT, 4)
class TCPOptionUserTimeout(TCPOption):
    _PACK_STR = '!BBH'  # kind, length, granularity(1bit)|user_timeout(15bit)

    def __init__(self, granularity, user_timeout, kind=None, length=None):
        super(TCPOptionUserTimeout, self).__init__(kind, length)
        self.granularity = granularity
        self.user_timeout = user_timeout

    @classmethod
    def parse(cls, buf):
        (_, _, body) = struct.unpack_from(cls._PACK_STR, buf)
        granularity = body >> 15
        user_timeout = body & 0x7fff
        return cls(granularity, user_timeout,
                   cls.cls_kind, cls.cls_length), buf[cls.cls_length:]

    def serialize(self):
        body = (self.granularity << 15) | self.user_timeout
        return struct.pack(self._PACK_STR, self.kind, self.length, body)


@TCPOption.register(TCP_OPTION_KIND_AUTHENTICATION,
                    4)  # variable length. 4 is the length except MAC.
class TCPOptionAuthentication(TCPOption):
    _PACK_STR = '!BBBB'  # kind, length, key_id, r_next_key_id

    def __init__(self, key_id, r_next_key_id, mac, kind=None, length=None):
        super(TCPOptionAuthentication, self).__init__(kind, length)
        self.key_id = key_id
        self.r_next_key_id = r_next_key_id
        self.mac = mac

    @classmethod
    def parse(cls, buf):
        (_, length,
         key_id, r_next_key_id) = struct.unpack_from(cls._PACK_STR, buf)
        mac = buf[4:length]
        return cls(key_id, r_next_key_id, mac,
                   cls.cls_kind, length), buf[length:]

    def serialize(self):
        self.length = self.cls_length + len(self.mac)
        return struct.pack(self._PACK_STR, self.kind, self.length,
                           self.key_id, self.r_next_key_id) + self.mac
