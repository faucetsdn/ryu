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
import six
import struct
from . import packet_base
from . import icmpv6
from . import tcp
from . import udp
from . import sctp
from . import gre
from . import in_proto as inet
from ryu.lib import addrconv
from ryu.lib import stringify


IPV6_ADDRESS_PACK_STR = '!16s'
IPV6_ADDRESS_LEN = struct.calcsize(IPV6_ADDRESS_PACK_STR)
IPV6_PSEUDO_HEADER_PACK_STR = '!16s16s3xB'


class ipv6(packet_base.PacketBase):
    """IPv6 (RFC 2460) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    IPv6 addresses are represented as a string like 'ff02::1'.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|p{30em}|l|

    ============== ======================================== ==================
    Attribute      Description                              Example
    ============== ======================================== ==================
    version        Version
    traffic_class  Traffic Class
    flow_label     When decoding, Flow Label.
                   When encoding, the most significant 8
                   bits of Flow Label.
    payload_length Payload Length
    nxt            Next Header
    hop_limit      Hop Limit
    src            Source Address                           'ff02::1'
    dst            Destination Address                      '::'
    ext_hdrs       Extension Headers
    ============== ======================================== ==================
    """

    _PACK_STR = '!IHBB16s16s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _IPV6_EXT_HEADER_TYPE = {}
    _TYPE = {
        'ascii': [
            'src', 'dst'
        ]
    }

    @staticmethod
    def register_header_type(type_):
        def _register_header_type(cls):
            ipv6._IPV6_EXT_HEADER_TYPE[type_] = cls
            return cls
        return _register_header_type

    def __init__(self, version=6, traffic_class=0, flow_label=0,
                 payload_length=0, nxt=inet.IPPROTO_TCP, hop_limit=255,
                 src='10::10', dst='20::20', ext_hdrs=None):
        super(ipv6, self).__init__()
        self.version = version
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.payload_length = payload_length
        self.nxt = nxt
        self.hop_limit = hop_limit
        self.src = src
        self.dst = dst
        ext_hdrs = ext_hdrs or []
        assert isinstance(ext_hdrs, list)
        for ext_hdr in ext_hdrs:
            assert isinstance(ext_hdr, header)
        self.ext_hdrs = ext_hdrs

    @classmethod
    def parser(cls, buf):
        (v_tc_flow, payload_length, nxt, hlim, src, dst) = struct.unpack_from(
            cls._PACK_STR, buf)
        version = v_tc_flow >> 28
        traffic_class = (v_tc_flow >> 20) & 0xff
        flow_label = v_tc_flow & 0xfffff
        hop_limit = hlim
        offset = cls._MIN_LEN
        last = nxt
        ext_hdrs = []
        while True:
            cls_ = cls._IPV6_EXT_HEADER_TYPE.get(last)
            if not cls_:
                break
            hdr = cls_.parser(buf[offset:])
            ext_hdrs.append(hdr)
            offset += len(hdr)
            last = hdr.nxt
        msg = cls(version, traffic_class, flow_label, payload_length,
                  nxt, hop_limit, addrconv.ipv6.bin_to_text(src),
                  addrconv.ipv6.bin_to_text(dst), ext_hdrs)
        return (msg, ipv6.get_packet_type(last),
                buf[offset:offset + payload_length])

    def serialize(self, payload, prev):
        hdr = bytearray(40)
        v_tc_flow = (self.version << 28 | self.traffic_class << 20 |
                     self.flow_label)
        struct.pack_into(ipv6._PACK_STR, hdr, 0, v_tc_flow,
                         self.payload_length, self.nxt, self.hop_limit,
                         addrconv.ipv6.text_to_bin(self.src),
                         addrconv.ipv6.text_to_bin(self.dst))
        if self.ext_hdrs:
            for ext_hdr in self.ext_hdrs:
                hdr.extend(ext_hdr.serialize())
        if 0 == self.payload_length:
            payload_length = len(payload)
            for ext_hdr in self.ext_hdrs:
                payload_length += len(ext_hdr)
            self.payload_length = payload_length
            struct.pack_into('!H', hdr, 4, self.payload_length)
        return hdr

    def __len__(self):
        ext_hdrs_len = 0
        for ext_hdr in self.ext_hdrs:
            ext_hdrs_len += len(ext_hdr)
        return self._MIN_LEN + ext_hdrs_len


ipv6.register_packet_type(icmpv6.icmpv6, inet.IPPROTO_ICMPV6)
ipv6.register_packet_type(tcp.tcp, inet.IPPROTO_TCP)
ipv6.register_packet_type(udp.udp, inet.IPPROTO_UDP)
ipv6.register_packet_type(sctp.sctp, inet.IPPROTO_SCTP)
ipv6.register_packet_type(gre.gre, inet.IPPROTO_GRE)


@six.add_metaclass(abc.ABCMeta)
class header(stringify.StringifyMixin):
    """extension header abstract class."""

    def __init__(self, nxt):
        self.nxt = nxt

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


class opt_header(header):
    """an abstract class for Hop-by-Hop Options header and destination
    header."""

    _PACK_STR = '!BB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _FIX_SIZE = 8
    _class_prefixes = ['option']

    @abc.abstractmethod
    def __init__(self, nxt, size, data):
        super(opt_header, self).__init__(nxt)
        assert not (size % 8)
        self.size = size
        self.data = data

    @classmethod
    def parser(cls, buf):
        (nxt, len_) = struct.unpack_from(cls._PACK_STR, buf)
        data_len = cls._FIX_SIZE + int(len_)
        data = []
        size = cls._MIN_LEN
        while size < data_len:
            (type_, ) = struct.unpack_from('!B', buf[size:])
            if type_ == 0:
                opt = option(type_, -1, None)
                size += 1
            else:
                opt = option.parser(buf[size:])
                size += len(opt)
            data.append(opt)
        return cls(nxt, len_, data)

    def serialize(self):
        buf = struct.pack(self._PACK_STR, self.nxt, self.size)
        buf = bytearray(buf)
        if self.data is None:
            self.data = [option(type_=1, len_=4,
                                data=b'\x00\x00\x00\x00')]
        for opt in self.data:
            buf.extend(opt.serialize())
        return buf

    def __len__(self):
        return self._FIX_SIZE + self.size


@ipv6.register_header_type(inet.IPPROTO_HOPOPTS)
class hop_opts(opt_header):
    """IPv6 (RFC 2460) Hop-by-Hop Options header encoder/decoder class.

    This is used with ryu.lib.packet.ipv6.ipv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    nxt            Next Header
    size           the length of the Hop-by-Hop Options header,
                   not include the first 8 octet.
    data           IPv6 options.
    ============== =======================================
    """
    TYPE = inet.IPPROTO_HOPOPTS

    def __init__(self, nxt=inet.IPPROTO_TCP, size=0, data=None):
        super(hop_opts, self).__init__(nxt, size, data)


@ipv6.register_header_type(inet.IPPROTO_DSTOPTS)
class dst_opts(opt_header):
    """IPv6 (RFC 2460) destination header encoder/decoder class.

    This is used with ryu.lib.packet.ipv6.ipv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    nxt            Next Header
    size           the length of the destination header,
                   not include the first 8 octet.
    data           IPv6 options.
    ============== =======================================
    """
    TYPE = inet.IPPROTO_DSTOPTS

    def __init__(self, nxt=inet.IPPROTO_TCP, size=0, data=None):
        super(dst_opts, self).__init__(nxt, size, data)


class option(stringify.StringifyMixin):
    r"""IPv6 (RFC 2460) Options header encoder/decoder class.

    This is used with ryu.lib.packet.ipv6.hop_opts or
                      ryu.lib.packet.ipv6.dst_opts.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    type\_         option type.
    len\_          the length of data. -1 if type\_ is 0.
    data           an option value. None if len\_ is 0 or -1.
    ============== =======================================
    """

    _PACK_STR = '!BB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, type_=0, len_=-1, data=None):
        self.type_ = type_
        self.len_ = len_
        self.data = data

    @classmethod
    def parser(cls, buf):
        (type_, ) = struct.unpack_from('!B', buf)
        if not type_:
            cls_ = cls(type_, -1, None)
        else:
            data = None
            (type_, len_) = struct.unpack_from(cls._PACK_STR, buf)
            if len_:
                form = "%ds" % len_
                (data, ) = struct.unpack_from(form, buf, cls._MIN_LEN)
            cls_ = cls(type_, len_, data)
        return cls_

    def serialize(self):
        data = None
        if not self.type_:
            data = struct.pack('!B', self.type_)
        elif not self.len_:
            data = struct.pack(self._PACK_STR, self.type_, self.len_)
        else:
            form = "%ds" % self.len_
            data = struct.pack(self._PACK_STR + form, self.type_,
                               self.len_, self.data)
        return data

    def __len__(self):
        return self._MIN_LEN + self.len_


@ipv6.register_header_type(inet.IPPROTO_ROUTING)
class routing(header):
    """An IPv6 Routing Header decoder class.
    This class has only the parser method.

    IPv6 Routing Header types.

    http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml

    +-----------+----------------------------------+-------------------+
    | Value     | Description                      | Reference         |
    +===========+==================================+===================+
    | 0         | Source Route (DEPRECATED)        | [[IPV6]][RFC5095] |
    +-----------+----------------------------------+-------------------+
    | 1         | Nimrod (DEPRECATED 2009-05-06)   |                   |
    +-----------+----------------------------------+-------------------+
    | 2         | Type 2 Routing Header            | [RFC6275]         |
    +-----------+----------------------------------+-------------------+
    | 3         | RPL Source Route Header          | [RFC6554]         |
    +-----------+----------------------------------+-------------------+
    | 4 - 252   | Unassigned                       |                   |
    +-----------+----------------------------------+-------------------+
    | 253       | RFC3692-style Experiment 1 [2]   | [RFC4727]         |
    +-----------+----------------------------------+-------------------+
    | 254       | RFC3692-style Experiment 2 [2]   | [RFC4727]         |
    +-----------+----------------------------------+-------------------+
    | 255       | Reserved                         |                   |
    +-----------+----------------------------------+-------------------+
    """

    TYPE = inet.IPPROTO_ROUTING

    _OFFSET_LEN = struct.calcsize('!2B')

    # IPv6 Routing Header Type
    ROUTING_TYPE_2 = 0x02
    ROUTING_TYPE_3 = 0x03

    @classmethod
    def parser(cls, buf):
        (type_, ) = struct.unpack_from('!B', buf, cls._OFFSET_LEN)
        switch = {
            # TODO: make parsers of type2.
            cls.ROUTING_TYPE_2: None,
            cls.ROUTING_TYPE_3: routing_type3
        }
        cls_ = switch.get(type_)
        if cls_:
            return cls_.parser(buf)
        else:
            return None


class routing_type3(header):
    """
    An IPv6 Routing Header for Source Routes with the RPL (RFC 6554)
    encoder/decoder class.

    This is used with ryu.lib.packet.ipv6.ipv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    nxt            Next Header
    size           The length of the Routing header,
                   not include the first 8 octet.
                   (0 means automatically-calculate when encoding)
    type           Identifies the particular Routing header variant.
    seg            Number of route segments remaining.
    cmpi           Number of prefix octets from segments 1 through n-1.
    cmpe           Number of prefix octets from segment n.
    pad            Number of octets that are used for padding
                   after Address[n] at the end of the SRH.
    adrs           Vector of addresses, numbered 1 to n.
    ============== =======================================
    """

    _PACK_STR = '!BBBBBB2x'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = {
        'asciilist': [
            'adrs'
        ]
    }

    def __init__(self, nxt=inet.IPPROTO_TCP, size=0,
                 type_=3, seg=0, cmpi=0, cmpe=0, adrs=None):
        super(routing_type3, self).__init__(nxt)
        self.size = size
        self.type_ = type_
        self.seg = seg
        self.cmpi = cmpi
        self.cmpe = cmpe
        adrs = adrs or []
        assert isinstance(adrs, list)
        self.adrs = adrs
        self._pad = (8 - ((len(self.adrs) - 1) * (16 - self.cmpi) +
                          (16 - self.cmpe) % 8)) % 8

    @classmethod
    def _get_size(cls, size):
        return (int(size) + 1) * 8

    @classmethod
    def parser(cls, buf):
        (nxt, size, type_, seg, cmp_, pad) = struct.unpack_from(
            cls._PACK_STR, buf)
        data = cls._MIN_LEN
        header_len = cls._get_size(size)
        cmpi = int(cmp_ >> 4)
        cmpe = int(cmp_ & 0xf)
        pad = int(pad >> 4)
        adrs = []
        if size:
            # Address[1..n-1] has size (16 - CmprI) octets
            adrs_len_i = 16 - cmpi
            # Address[n] has size (16 - CmprE) octets
            adrs_len_e = 16 - cmpe
            form_i = "%ds" % adrs_len_i
            form_e = "%ds" % adrs_len_e
            while data < (header_len - (adrs_len_e + pad)):
                (adr, ) = struct.unpack_from(form_i, buf[data:])
                adr = (b'\x00' * cmpi) + adr
                adrs.append(addrconv.ipv6.bin_to_text(adr))
                data += adrs_len_i
            (adr, ) = struct.unpack_from(form_e, buf[data:])
            adr = (b'\x00' * cmpe) + adr
            adrs.append(addrconv.ipv6.bin_to_text(adr))
        return cls(nxt, size, type_, seg, cmpi, cmpe, adrs)

    def serialize(self):
        if self.size == 0:
            self.size = ((len(self.adrs) - 1) * (16 - self.cmpi) +
                         (16 - self.cmpe) + self._pad) // 8
        buf = struct.pack(self._PACK_STR, self.nxt, self.size,
                          self.type_, self.seg, (self.cmpi << 4) | self.cmpe,
                          self._pad << 4)
        buf = bytearray(buf)
        if self.size:
            form_i = "%ds" % (16 - self.cmpi)
            form_e = "%ds" % (16 - self.cmpe)
            slice_i = slice(self.cmpi, 16)
            slice_e = slice(self.cmpe, 16)
            for adr in self.adrs[:-1]:
                buf.extend(
                    struct.pack(
                        form_i, addrconv.ipv6.text_to_bin(adr)[slice_i]))
            buf.extend(struct.pack(
                form_e,
                addrconv.ipv6.text_to_bin(self.adrs[-1])[slice_e]))
        return buf

    def __len__(self):
        return routing_type3._get_size(self.size)


@ipv6.register_header_type(inet.IPPROTO_FRAGMENT)
class fragment(header):
    r"""IPv6 (RFC 2460) fragment header encoder/decoder class.

    This is used with ryu.lib.packet.ipv6.ipv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    nxt            Next Header
    offset         offset, in 8-octet units, relative to
                   the start of the fragmentable part of
                   the original packet.
    more           1 means more fragments follow;
                   0 means last fragment.
    id\_           packet identification value.
    ============== =======================================
    """
    TYPE = inet.IPPROTO_FRAGMENT

    _PACK_STR = '!BxHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, nxt=inet.IPPROTO_TCP, offset=0, more=0, id_=0):
        super(fragment, self).__init__(nxt)
        self.offset = offset
        self.more = more
        self.id_ = id_

    @classmethod
    def parser(cls, buf):
        (nxt, off_m, id_) = struct.unpack_from(cls._PACK_STR, buf)
        offset = off_m >> 3
        more = off_m & 0x1
        return cls(nxt, offset, more, id_)

    def serialize(self):
        off_m = (self.offset << 3 | self.more)
        buf = struct.pack(self._PACK_STR, self.nxt, off_m, self.id_)
        return buf

    def __len__(self):
        return self._MIN_LEN


@ipv6.register_header_type(inet.IPPROTO_AH)
class auth(header):
    """IP Authentication header (RFC 2402) encoder/decoder class.

    This is used with ryu.lib.packet.ipv6.ipv6.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============== =======================================
    Attribute      Description
    ============== =======================================
    nxt            Next Header
    size           the length of the Authentication Header
                   in 64-bit words, subtracting 1.
    spi            security parameters index.
    seq            sequence number.
    data           authentication data.
    ============== =======================================
    """
    TYPE = inet.IPPROTO_AH

    _PACK_STR = '!BB2xII'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, nxt=inet.IPPROTO_TCP, size=2, spi=0, seq=0,
                 data=b'\x00\x00\x00\x00'):
        super(auth, self).__init__(nxt)
        assert data is not None
        self.size = size
        self.spi = spi
        self.seq = seq
        self.data = data

    @classmethod
    def _get_size(cls, size):
        return (int(size) + 2) * 4

    @classmethod
    def parser(cls, buf):
        (nxt, size, spi, seq) = struct.unpack_from(cls._PACK_STR, buf)
        form = "%ds" % (cls._get_size(size) - cls._MIN_LEN)
        (data, ) = struct.unpack_from(form, buf, cls._MIN_LEN)
        return cls(nxt, size, spi, seq, data)

    def serialize(self):
        buf = struct.pack(self._PACK_STR, self.nxt, self.size, self.spi,
                          self.seq)
        buf = bytearray(buf)
        form = "%ds" % (auth._get_size(self.size) - self._MIN_LEN)
        buf.extend(struct.pack(form, self.data))
        return buf

    def __len__(self):
        return auth._get_size(self.size)


ipv6.set_classes(ipv6._IPV6_EXT_HEADER_TYPE)
