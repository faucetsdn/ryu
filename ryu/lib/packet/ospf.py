"""
RFC 2328 OSPF version 2
"""

import struct

from ryu.lib.stringify import StringifyMixin
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet_utils
from ryu.lib.packet import stream_parser

from ryu.lib import addrconv

_VERSION = 2

OSPF_MSG_UNKNOWN = 0
OSPF_MSG_HELLO = 1
OSPF_MSG_DB_DESC = 2
OSPF_MSG_LS_REQ = 3
OSPF_MSG_LS_UPD = 4
OSPF_MSG_LS_ACK = 5

OSPF_UNKNOWN_LSA = 0
OSPF_ROUTER_LSA = 1
OSPF_NETWORK_LSA = 2
OSPF_SUMMARY_LSA = 3
OSPF_ASBR_SUMMARY_LSA = 4
OSPF_AS_EXTERNAL_LSA = 5
OSPF_AS_NSSA_LSA = 7       # RFC 3101
OSPF_OPAQUE_LINK_LSA = 9   # RFC 5250
OSPF_OPAQUE_AREA_LSA = 10  # RFC 5250
OSPF_OPAQUE_AS_LSA = 11    # RFC 5250

OSPF_OPTION_T = 1        # Obsolete
OSPF_OPTION_E = 1 << 1   # RFC 2328
OSPF_OPTION_MC = 1 << 2  # RFC 1584
OSPF_OPTION_NP = 1 << 3  # RFC 3101
OSPF_OPTION_EA = 1 << 4  # Obsolete
OSPF_OPTION_DC = 1 << 5  # RFC 2370
OSPF_OPTION_DN = 1 << 7  # RFC 2567

LSA_LINK_TYPE_P2P = 1
LSA_LINK_TYPE_TRANSIT = 2
LSA_LINK_TYPE_STUB = 3
LSA_LINK_TYPE_VL = 4

ROUTER_LSA_BORDER = 0x01  # The router is an ABR
ROUTER_LSA_EXTERNAL = 0x02  # The router is an ASBR
ROUTER_LSA_VIRTUAL = 0x04  # The router has a VL in this area
ROUTER_LSA_NT = 0x10  # The router always translates Type-7
ROUTER_LSA_SHORTCUT = 0x20  # Shortcut-ABR specific flag

AS_EXTERNAL_METRIC = 0x80


class InvalidChecksum(Exception):
    pass


class _TypeDisp(object):
    _TYPES = {}
    _REV_TYPES = None
    _UNKNOWN_TYPE = None

    @classmethod
    def register_unknown_type(cls):
        def _register_type(subcls):
            cls._UNKNOWN_TYPE = subcls
            return subcls
        return _register_type

    @classmethod
    def register_type(cls, type_):
        cls._TYPES = cls._TYPES.copy()

        def _register_type(subcls):
            cls._TYPES[type_] = subcls
            cls._REV_TYPES = None
            return subcls
        return _register_type

    @classmethod
    def _lookup_type(cls, type_):
        try:
            return cls._TYPES[type_]
        except KeyError:
            return cls._UNKNOWN_TYPE

    @classmethod
    def _rev_lookup_type(cls, targ_cls):
        if cls._REV_TYPES is None:
            rev = dict((v, k) for k, v in cls._TYPES.iteritems())
            cls._REV_TYPES = rev
        return cls._REV_TYPES[targ_cls]


class LSAHeader(StringifyMixin):
    _HDR_PACK_STR = '!HBB4s4sIHH'
    _HDR_LEN = struct.calcsize(_HDR_PACK_STR)

    def __init__(self, ls_age=0, options=0, type_=OSPF_UNKNOWN_LSA,
                 id_='0.0.0.0', adv_router='0.0.0.0', ls_seqnum=0,
                 checksum=None, length=None):
        self.ls_age = ls_age
        self.options = options
        self.type_ = type_
        self.id_ = id_
        self.adv_router = adv_router
        self.ls_seqnum = ls_seqnum
        self.checksum = checksum
        self.length = length

    @classmethod
    def parser(cls, buf):
        if len(buf) < cls._HDR_LEN:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), cls._HDR_LEN))
        (ls_age, options, type_, id_, adv_router, ls_seqnum, checksum,
         length,) = struct.unpack_from(cls._HDR_PACK_STR, buffer(buf))
        id_ = addrconv.ipv4.bin_to_text(id_)
        adv_router = addrconv.ipv4.bin_to_text(adv_router)
        rest = buf[cls._HDR_LEN:]

        return {
            "ls_age": ls_age,
            "options": options,
            "type_": type_,
            "id_": id_,
            "adv_router": adv_router,
            "ls_seqnum": ls_seqnum,
            "checksum": checksum,
            "length": length,
            }, rest

    def serialize(self):
        id_ = addrconv.ipv4.text_to_bin(self.id_)
        adv_router = addrconv.ipv4.text_to_bin(self.adv_router)
        return bytearray(struct.pack(self._HDR_PACK_STR, self.ls_age,
                         self.options, self.type_, id_, adv_router,
                         self.ls_seqnum, self.checksum, self.length))


class LSA(_TypeDisp, StringifyMixin):
    def __init__(self, ls_age=0, options=0, type_=OSPF_UNKNOWN_LSA,
                 id_='0.0.0.0', adv_router='0.0.0.0', ls_seqnum=0,
                 checksum=None, length=None):
        self.header = LSAHeader(ls_age, options, type_, id_, adv_router,
                                ls_seqnum, 0, 0)
        if not (checksum or length):
            tail = self.serialize_tail()
            length = self.header._HDR_LEN + len(tail)
        if not checksum:
            head = self.header.serialize()
            checksum = packet_utils.fletcher_checksum(head[2:], 14)
        self.header.length = length
        self.header.checksum = checksum

    @classmethod
    def parser(cls, buf):
        hdr, rest = LSAHeader.parser(buf)
        #exclude ls_age for checksum calculation
        csum = packet_utils.fletcher_checksum(buf[2:hdr['length']], 14)
        if csum != hdr['checksum']:
            raise InvalidChecksum("header has %d, but calculated value is %d"
                                  % (hdr['checksum'], csum))
        subcls = cls._lookup_type(hdr['type_'])
        body = rest[:hdr['length']-LSAHeader._HDR_LEN]
        rest = rest[hdr['length']-LSAHeader._HDR_LEN:]
        kwargs = subcls.parser(body)
        kwargs.update(hdr)
        return subcls(**kwargs), subcls, rest

    def serialize(self):
        tail = self.serialize_tail()
        self.header.length = self.header._HDR_LEN + len(tail)
        head = self.header.serialize()
        #exclude ls_age for checksum calculation
        csum = packet_utils.fletcher_checksum(head[2:]+tail, 14)
        self.header.checksum = csum
        struct.pack_into("!H", head, 16, csum)
        return head + tail


@LSA.register_type(OSPF_ROUTER_LSA)
class RouterLSA(LSA):
    _PACK_STR = '!BBH'
    _PACK_LEN = struct.calcsize(_PACK_STR)  # 4bytes

    class Link(StringifyMixin):
        _PACK_STR = '!4s4sBBH'
        _PACK_LEN = struct.calcsize(_PACK_STR)  # 12bytes

        def __init__(self, id_='0.0.0.0', data='0.0.0.0',
                     type_=LSA_LINK_TYPE_STUB, tos=0, metric=10):
            self.id_ = id_
            self.data = data
            self.type_ = type_
            self.tos = tos
            self.metric = metric

        @classmethod
        def parser(cls, buf):
            if len(buf) < cls._PACK_LEN:
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._PACK_LEN))
            link = buf[:cls._PACK_LEN]
            rest = buf[cls._PACK_LEN:]
            (id_, data, type_, tos, metric) = \
                struct.unpack_from(cls._PACK_STR, buffer(link))
            id_ = addrconv.ipv4.bin_to_text(id_)
            data = addrconv.ipv4.bin_to_text(data)
            return cls(id_, data, type_, tos, metric), rest

        def serialize(self):
            id_ = addrconv.ipv4.text_to_bin(self.id_)
            data = addrconv.ipv4.text_to_bin(self.data)
            return bytearray(struct.pack(self._PACK_STR, id_, data, self.type_,
                             self.tos, self.metric))

    def __init__(self, ls_age=0, options=0, type_=OSPF_ROUTER_LSA,
                 id_='0.0.0.0', adv_router='0.0.0.0', ls_seqnum=0,
                 checksum=None, length=None, flags=0, links=[]):
        self.flags = flags
        self.links = links
        super(RouterLSA, self).__init__(ls_age, options, type_, id_,
                                        adv_router, ls_seqnum, checksum,
                                        length)

    @classmethod
    def parser(cls, buf):
        links = []
        hdr = buf[:cls._PACK_LEN]
        buf = buf[cls._PACK_LEN:]
        (flags, padding, num) = struct.unpack_from(cls._PACK_STR, buffer(hdr))
        while buf:
            link, buf = cls.Link.parser(buf)
            links.append(link)
        assert(len(links) == num)
        return {
            "flags": flags,
            "links": links,
        }

    def serialize_tail(self):
        head = bytearray(struct.pack(self._PACK_STR, self.flags, 0,
                         len(self.links)))
        try:
            return head + reduce(lambda a, b: a+b,
                                 (link.serialize() for link in self.links))
        except TypeError:
            return head


@LSA.register_type(OSPF_NETWORK_LSA)
class NetworkLSA(LSA):
    _PACK_STR = '!4s'
    _PACK_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, ls_age=0, options=0, type_=OSPF_NETWORK_LSA,
                 id_='0.0.0.0', adv_router='0.0.0.0', ls_seqnum=0,
                 checksum=None, length=None, mask='0.0.0.0', routers=[]):
        self.mask = mask
        self.routers = routers
        super(NetworkLSA, self).__init__(ls_age, options, type_, id_,
                                         adv_router, ls_seqnum, checksum,
                                         length)

    @classmethod
    def parser(cls, buf):
        if len(buf) < cls._PACK_LEN:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), cls._PACK_LEN))
        binmask = buf[:cls._PACK_LEN]
        (mask,) = struct.unpack_from(cls._PACK_STR, buffer(binmask))
        mask = addrconv.ipv4.bin_to_text(mask)
        buf = buf[cls._PACK_LEN:]
        routers = []
        while buf:
            binrouter = buf[:cls._PACK_LEN]
            (router,) = struct.unpack_from(cls._PACK_STR, buffer(binrouter))
            router = addrconv.ipv4.bin_to_text(router)
            routers.append(router)
            buf = buf[cls._PACK_LEN:]
        return {
            "mask": mask,
            "routers": routers,
        }

    def serialize_tail(self):
        mask = addrconv.ipv4.text_to_bin(self.mask)
        routers = [addrconv.ipv4.text_to_bin(
                   router) for router in self.routers]
        return bytearray(struct.pack("!"+"4s"*(1+len(routers)), mask,
                                     *routers))


@LSA.register_type(OSPF_SUMMARY_LSA)
class SummaryLSA(LSA):
    pass


@LSA.register_type(OSPF_ASBR_SUMMARY_LSA)
class ASBRSummaryLSA(LSA):
    pass


@LSA.register_type(OSPF_AS_EXTERNAL_LSA)
class ASExternalLSA(LSA):
    class ExternalNetwork(StringifyMixin):
        _PACK_STR = '!4sBBH4sI'
        _PACK_LEN = struct.calcsize(_PACK_STR)

        def __init__(self, mask='0.0.0.0', flags=0, metric=0,
                     fwd_addr='0.0.0.0', tag=0):
            self.mask = mask
            self.flags = flags
            self.metric = metric
            self.fwd_addr = fwd_addr
            self.tag = tag

        @classmethod
        def parser(cls, buf):
            if len(buf) < cls._PACK_LEN:
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._PACK_LEN))
            ext_nw = buf[:cls._PACK_LEN]
            rest = buf[cls._PACK_LEN:]
            (mask, flags, metric_fst, metric_lst, fwd_addr,
             tag) = struct.unpack_from(cls._PACK_STR, buffer(ext_nw))
            mask = addrconv.ipv4.bin_to_text(mask)
            metric = metric_fst << 16 | (metric_lst & 0xffff)
            fwd_addr = addrconv.ipv4.bin_to_text(fwd_addr)
            return cls(mask, flags, metric, fwd_addr, tag), rest

        def serialize(self):
            mask = addrconv.ipv4.text_to_bin(self.mask)
            metric_fst = (self.metric >> 16) & 0xff
            metric_lst = self.metric & 0xffff
            fwd_addr = addrconv.ipv4.text_to_bin(self.fwd_addr)
            return bytearray(struct.pack(self._PACK_STR, mask, self.flags,
                                         metric_fst, metric_lst, fwd_addr,
                                         self.tag))

    def __init__(self, ls_age=0, options=0, type_=OSPF_AS_EXTERNAL_LSA,
                 id_='0.0.0.0', adv_router='0.0.0.0', ls_seqnum=0,
                 checksum=None, length=None, extnws=[]):
        self.extnws = extnws
        super(ASExternalLSA, self).__init__(ls_age, options, type_, id_,
                                            adv_router, ls_seqnum, checksum,
                                            length)

    @classmethod
    def parser(cls, buf):
        extnws = []
        while buf:
            extnw, buf = cls.ExternalNetwork.parser(buf)
            extnws.append(extnw)
        return {
            "extnws": extnws,
        }

    def serialize_tail(self):
        return reduce(lambda a, b: a+b,
                      (extnw.serialize() for extnw in self.extnws))


@LSA.register_type(OSPF_AS_NSSA_LSA)
class NSSAExternalLSA(LSA):
    pass


@LSA.register_type(OSPF_OPAQUE_LINK_LSA)
class LocalOpaqueLSA(LSA):
    pass


@LSA.register_type(OSPF_OPAQUE_AREA_LSA)
class AreaOpaqueLSA(LSA):
    pass


@LSA.register_type(OSPF_OPAQUE_AS_LSA)
class ASOpaqueLSA(LSA):
    pass


class OSPFMessage(packet_base.PacketBase, _TypeDisp):
    """Base class for OSPF version 2 messages.
    """

    _HDR_PACK_STR = '!BBH4s4sHHQ'
    _HDR_LEN = struct.calcsize(_HDR_PACK_STR)

    def __init__(self, type_, length=None, router_id='0.0.0.0',
                 area_id='0.0.0.0', au_type=1, authentication=0, checksum=None,
                 version=_VERSION):
        self.version = version
        self.type_ = type_
        self.length = length
        self.router_id = router_id
        self.area_id = area_id
        self.checksum = checksum
        self.au_type = au_type
        self.authentication = authentication

    @classmethod
    def parser(cls, buf):
        if len(buf) < cls._HDR_LEN:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), cls._HDR_LEN))
        (version, type_, length, router_id, area_id, checksum, au_type,
         authentication) = struct.unpack_from(cls._HDR_PACK_STR, buffer(buf))

        #Exclude checksum and authentication field for checksum validation.
        if packet_utils.checksum(buf[:12]+buf[14:16]+buf[cls._HDR_LEN:]) \
                != checksum:
            raise InvalidChecksum

        if len(buf) < length:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), length))

        router_id = addrconv.ipv4.bin_to_text(router_id)
        area_id = addrconv.ipv4.bin_to_text(area_id)
        binmsg = buf[cls._HDR_LEN:length]
        rest = buf[length:]
        subcls = cls._lookup_type(type_)
        kwargs = subcls.parser(binmsg)
        return subcls(length, router_id, area_id, au_type, authentication,
                      checksum, version, **kwargs), None, rest

    def serialize(self):
        tail = self.serialize_tail()
        self.length = self._HDR_LEN + len(tail)
        head = bytearray(struct.pack(self._HDR_PACK_STR, self.version,
                         self.type_, self.length,
                         addrconv.ipv4.text_to_bin(self.router_id),
                         addrconv.ipv4.text_to_bin(self.area_id), 0,
                         self.au_type, self.authentication))
        buf = head + tail
        csum = packet_utils.checksum(buf[:12]+buf[14:16]+buf[self._HDR_LEN:])
        self.checksum = csum
        struct.pack_into("!H", buf, 12, csum)
        return buf

#alias
ospf = OSPFMessage


@OSPFMessage.register_type(OSPF_MSG_HELLO)
class OSPFHello(OSPFMessage):

    _PACK_STR = '!4sHBBI4s4s'  # + neighbors
    _PACK_LEN = struct.calcsize(_PACK_STR)
    _MIN_LEN = OSPFMessage._HDR_LEN + _PACK_LEN

    def __init__(self, length=None, router_id='0.0.0.0', area_id='0.0.0.0',
                 au_type=1, authentication=0, checksum=None, version=_VERSION,
                 mask='0.0.0.0', hello_interval=10, options=0, priority=1,
                 dead_interval=40, designated_router='0.0.0.0',
                 backup_router='0.0.0.0', neighbors=[]):
        super(OSPFHello, self).__init__(OSPF_MSG_HELLO, length, router_id,
                                        area_id, au_type, authentication,
                                        checksum, version)
        self.mask = mask
        self.hello_interval = hello_interval
        self.options = options
        self.priority = priority
        self.dead_interval = dead_interval
        self.designated_router = designated_router
        self.backup_router = backup_router
        self.neighbors = neighbors

    @classmethod
    def parser(cls, buf):
        (mask, hello_interval, options, priority, dead_interval,
         designated_router, backup_router) = struct.unpack_from(cls._PACK_STR,
                                                                buffer(buf))
        mask = addrconv.ipv4.bin_to_text(mask)
        designated_router = addrconv.ipv4.bin_to_text(designated_router)
        backup_router = addrconv.ipv4.bin_to_text(backup_router)
        neighbors = []
        binneighbors = buf[cls._PACK_LEN:len(buf)]
        while binneighbors:
            n = binneighbors[:4]
            n = addrconv.ipv4.bin_to_text(n)
            binneighbors = binneighbors[4:]
            neighbors.append(n)
        return {
            "mask": mask,
            "hello_interval": hello_interval,
            "options": options,
            "priority": priority,
            "dead_interval": dead_interval,
            "designated_router": designated_router,
            "backup_router": backup_router,
            "neighbors": neighbors,
        }

    def serialize_tail(self):
        head = bytearray(struct.pack(self._PACK_STR,
                         addrconv.ipv4.text_to_bin(self.mask),
                         self.hello_interval, self.options, self.priority,
                         self.dead_interval,
                         addrconv.ipv4.text_to_bin(self.designated_router),
                         addrconv.ipv4.text_to_bin(self.backup_router)))
        try:
            return head + reduce(lambda a, b: a+b,
                                 (addrconv.ipv4.text_to_bin(
                                  n) for n in self.neighbors))
        except TypeError:
            return head


@OSPFMessage.register_type(OSPF_MSG_DB_DESC)
class OSPFDBDesc(OSPFMessage):

    _PACK_STR = '!HBBI'  # + LSA_HEADERS
    _PACK_LEN = struct.calcsize(_PACK_STR)
    _MIN_LEN = OSPFMessage._HDR_LEN + _PACK_LEN

    def __init__(self, length=None, router_id='0.0.0.0', area_id='0.0.0.0',
                 au_type=1, authentication=0, checksum=None, version=_VERSION,
                 mtu=1500, options=0, i_flag=0, m_flag=0, ms_flag=0,
                 sequence_number=0, lsa_headers=[]):
        super(OSPFDBDesc, self).__init__(OSPF_MSG_DB_DESC, length, router_id,
                                         area_id, au_type, authentication,
                                         checksum, version)
        self.mtu = mtu
        self.options = options
        self.i_flag = i_flag
        self.m_flag = m_flag
        self.ms_flag = ms_flag
        self.sequence_number = sequence_number
        self.lsa_headers = lsa_headers

    @classmethod
    def parser(cls, buf):
        (mtu, options, flags,
         sequence_number) = struct.unpack_from(cls._PACK_STR, buffer(buf))
        i_flag = (flags >> 2) & 0x1
        m_flag = (flags >> 1) & 0x1
        ms_flag = flags & 0x1
        lsahdrs = []
        buf = buf[cls._PACK_LEN:]
        while buf:
            kwargs, buf = LSAHeader.parser(buf)
            lsahdrs.append(LSAHeader(**kwargs))
        return {
            "mtu": mtu,
            "options": options,
            "i_flag": i_flag,
            "m_flag": m_flag,
            "ms_flag": ms_flag,
            "sequence_number": sequence_number,
            "lsa_headers": lsahdrs,
        }

    def serialize_tail(self):
        flags = ((self.i_flag & 0x1) << 2) ^ \
                ((self.m_flag & 0x1) << 1) ^ \
                (self.ms_flag & 0x1)
        head = bytearray(struct.pack(self._PACK_STR, self.mtu,
                                     self.options, flags,
                                     self.sequence_number))
        try:
            return head + reduce(lambda a, b: a+b,
                                 (hdr.serialize() for hdr in self.lsa_headers))
        except TypeError:
            return head


@OSPFMessage.register_type(OSPF_MSG_LS_REQ)
class OSPFLSReq(OSPFMessage):
    _MIN_LEN = OSPFMessage._HDR_LEN

    class Request(StringifyMixin):
        _PACK_STR = '!I4s4s'
        _PACK_LEN = struct.calcsize(_PACK_STR)

        def __init__(self, type_=OSPF_UNKNOWN_LSA, id_='0.0.0.0',
                     adv_router='0.0.0.0'):
            self.type_ = type_
            self.id = id_
            self.adv_router = adv_router

        @classmethod
        def parser(cls, buf):
            if len(buf) < cls._PACK_LEN:
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._PACK_LEN))
            link = buf[:cls._PACK_LEN]
            rest = buf[cls._PACK_LEN:]
            (type_, id_, adv_router) = struct.unpack_from(cls._PACK_STR,
                                                          buffer(link))
            id_ = addrconv.ipv4.bin_to_text(id_)
            adv_router = addrconv.ipv4.bin_to_text(adv_router)
            return cls(type_, id_, adv_router), rest

        def serialize(self):
            id_ = addrconv.ipv4.text_to_bin(self.id)
            adv_router = addrconv.ipv4.text_to_bin(self.adv_router)
            return bytearray(struct.pack(self._PACK_STR, self.type_,
                                         id_, adv_router))

    def __init__(self, length=None, router_id='0.0.0.0', area_id='0.0.0.0',
                 au_type=1, authentication=0, checksum=None, version=_VERSION,
                 lsa_requests=[]):
        super(OSPFLSReq, self).__init__(OSPF_MSG_LS_REQ, length, router_id,
                                        area_id, au_type, authentication,
                                        checksum, version)
        self.lsa_requests = lsa_requests

    @classmethod
    def parser(cls, buf):
        reqs = []
        while buf:
            req, buf = cls.Request.parser(buf)
            reqs.append(req)
        return {
            "lsa_requests": reqs,
        }

    def serialize_tail(self):
        return reduce(lambda a, b: a+b,
                      (req.serialize() for req in self.lsa_requests))


@OSPFMessage.register_type(OSPF_MSG_LS_UPD)
class OSPFLSUpd(OSPFMessage):
    _PACK_STR = '!I'
    _PACK_LEN = struct.calcsize(_PACK_STR)
    _MIN_LEN = OSPFMessage._HDR_LEN + _PACK_LEN

    def __init__(self, length=None, router_id='0.0.0.0', area_id='0.0.0.0',
                 au_type=1, authentication=0, checksum=None, version=_VERSION,
                 lsas=[]):
        super(OSPFLSUpd, self).__init__(OSPF_MSG_LS_UPD, length, router_id,
                                        area_id, au_type, authentication,
                                        checksum, version)
        self.lsas = lsas

    @classmethod
    def parser(cls, buf):
        binnum = buf[:cls._PACK_LEN]
        (num,) = struct.unpack_from(cls._PACK_STR, buffer(binnum))

        buf = buf[cls._PACK_LEN:]
        lsas = []
        while buf:
            lsa, cls, buf = LSA.parser(buf)
            lsas.append(lsa)
        assert(len(lsas) == num)
        return {
            "lsas": lsas,
        }

    def serialize_tail(self):
        head = bytearray(struct.pack(self._PACK_STR, len(self.lsas)))
        try:
            return head + reduce(lambda a, b: a+b,
                                 (lsa.serialize() for lsa in self.lsas))
        except TypeError:
            return head


@OSPFMessage.register_type(OSPF_MSG_LS_ACK)
class OSPFLSAck(OSPFMessage):
    _MIN_LEN = OSPFMessage._HDR_LEN

    def __init__(self, length=None, router_id='0.0.0.0', area_id='0.0.0.0',
                 au_type=1, authentication=0, checksum=None, version=_VERSION,
                 lsa_headers=[]):
        super(OSPFLSAck, self).__init__(OSPF_MSG_LS_ACK, length, router_id,
                                        area_id, au_type, authentication,
                                        checksum, version)
        self.lsa_headers = lsa_headers

    @classmethod
    def parser(cls, buf):
        lsahdrs = []
        while buf:
            kwargs, buf = LSAHeader.parser(buf)
            lsahdrs.append(LSAHeader(**kwargs))
        return {
            "lsa_headers": lsahdrs,
        }

    def serialize_tail(self):
        return reduce(lambda a, b: a+b,
                      (hdr.serialize() for hdr in self.lsa_headers))
