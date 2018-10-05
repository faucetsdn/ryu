# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
BGP Monitoring Protocol draft-ietf-grow-bmp-07
"""

import struct

import six

from ryu.lib import addrconv
from ryu.lib.packet import packet_base
from ryu.lib.packet import stream_parser
from ryu.lib.packet.bgp import BGPMessage
from ryu.lib.type_desc import TypeDisp

VERSION = 3

BMP_MSG_ROUTE_MONITORING = 0
BMP_MSG_STATISTICS_REPORT = 1
BMP_MSG_PEER_DOWN_NOTIFICATION = 2
BMP_MSG_PEER_UP_NOTIFICATION = 3
BMP_MSG_INITIATION = 4
BMP_MSG_TERMINATION = 5

BMP_PEER_TYPE_GLOBAL = 0
BMP_PEER_TYPE_L3VPN = 1

BMP_INIT_TYPE_STRING = 0
BMP_INIT_TYPE_SYSDESCR = 1
BMP_INIT_TYPE_SYSNAME = 2

BMP_TERM_TYPE_STRING = 0
BMP_TERM_TYPE_REASON = 1

BMP_TERM_REASON_ADMIN = 0
BMP_TERM_REASON_UNSPEC = 1
BMP_TERM_REASON_OUT_OF_RESOURCE = 2
BMP_TERM_REASON_REDUNDANT_CONNECTION = 3

BMP_STAT_TYPE_REJECTED = 0
BMP_STAT_TYPE_DUPLICATE_PREFIX = 1
BMP_STAT_TYPE_DUPLICATE_WITHDRAW = 2
BMP_STAT_TYPE_INV_UPDATE_DUE_TO_CLUSTER_LIST_LOOP = 3
BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_PATH_LOOP = 4
BMP_STAT_TYPE_INV_UPDATE_DUE_TO_ORIGINATOR_ID = 5
BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_CONFED_LOOP = 6
BMP_STAT_TYPE_ADJ_RIB_IN = 7
BMP_STAT_TYPE_LOC_RIB = 8

BMP_PEER_DOWN_REASON_UNKNOWN = 0
BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION = 1
BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION = 2
BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION = 3
BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION = 4


class BMPMessage(packet_base.PacketBase, TypeDisp):
    r"""Base class for BGP Monitoring Protocol messages.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    ========================== ===============================================
    """

    _HDR_PACK_STR = '!BIB'  # version, padding, len, type, padding
    _HDR_LEN = struct.calcsize(_HDR_PACK_STR)

    def __init__(self, type_, len_=None, version=VERSION):
        self.version = version
        self.len = len_
        self.type = type_

    @classmethod
    def parse_header(cls, buf):
        if len(buf) < cls._HDR_LEN:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), cls._HDR_LEN))
        (version, len_, type_) = struct.unpack_from(cls._HDR_PACK_STR,
                                                    six.binary_type(buf))

        return version, len_, type_

    @classmethod
    def parser(cls, buf):
        version, msglen, type_ = cls.parse_header(buf)

        if version != VERSION:
            raise ValueError("not supportted bmp version: %d" % version)

        if len(buf) < msglen:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), msglen))

        binmsg = buf[cls._HDR_LEN:msglen]
        rest = buf[msglen:]
        subcls = cls._lookup_type(type_)

        if subcls == cls._UNKNOWN_TYPE:
            raise ValueError("unknown bmp type: %d" % type_)

        kwargs = subcls.parser(binmsg)
        return subcls(len_=msglen,
                      type_=type_, version=version, **kwargs), rest

    def serialize(self):
        # fixup
        tail = self.serialize_tail()
        self.len = self._HDR_LEN + len(tail)

        hdr = bytearray(struct.pack(self._HDR_PACK_STR, self.version,
                                    self.len, self.type))
        return hdr + tail

    def __len__(self):
        # XXX destructive
        buf = self.serialize()
        return len(buf)


class BMPPeerMessage(BMPMessage):
    r"""BMP Message with Per Peer Header

    Following BMP Messages contain Per Peer Header after Common BMP Header.

    - BMP_MSG_TYPE_ROUTE_MONITRING
    - BMP_MSG_TYPE_STATISTICS_REPORT
    - BMP_MSG_PEER_UP_NOTIFICATION

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    peer_type                  The type of the peer.
    is_post_policy             Indicate the message reflects the post-policy
                               Adj-RIB-In
    peer_distinguisher         Use for L3VPN router which can have multiple
                               instance.
    peer_address               The remote IP address associated with the TCP
                               session.
    peer_as                    The Autonomous System number of the peer.
    peer_bgp_id                The BGP Identifier of the peer
    timestamp                  The time when the encapsulated routes were
                               received.
    ========================== ===============================================
    """

    _PEER_HDR_PACK_STR = '!BBQ16sI4sII'
    _TYPE = {
        'ascii': [
            'peer_address',
            'peer_bgp_id'
        ]
    }

    def __init__(self, peer_type, is_post_policy, peer_distinguisher,
                 peer_address, peer_as, peer_bgp_id, timestamp,
                 version=VERSION, type_=None, len_=None):
        super(BMPPeerMessage, self).__init__(version=version,
                                             len_=len_,
                                             type_=type_)
        self.peer_type = peer_type
        self.is_post_policy = is_post_policy
        self.peer_distinguisher = peer_distinguisher
        self.peer_address = peer_address
        self.peer_as = peer_as
        self.peer_bgp_id = peer_bgp_id
        self.timestamp = timestamp

    @classmethod
    def parser(cls, buf):
        (peer_type, peer_flags, peer_distinguisher,
         peer_address, peer_as, peer_bgp_id,
         timestamp1, timestamp2) = struct.unpack_from(cls._PEER_HDR_PACK_STR,
                                                      six.binary_type(buf))

        rest = buf[struct.calcsize(cls._PEER_HDR_PACK_STR):]

        if peer_flags & (1 << 6):
            is_post_policy = True
        else:
            is_post_policy = False

        if peer_flags & (1 << 7):
            peer_address = addrconv.ipv6.bin_to_text(peer_address)
        else:
            peer_address = addrconv.ipv4.bin_to_text(peer_address[-4:])

        peer_bgp_id = addrconv.ipv4.bin_to_text(peer_bgp_id)

        timestamp = float(timestamp1) + timestamp2 * (10 ** -6)

        return {
            "peer_type": peer_type,
            "is_post_policy": is_post_policy,
            "peer_distinguisher": peer_distinguisher,
            "peer_address": peer_address,
            "peer_as": peer_as,
            "peer_bgp_id": peer_bgp_id,
            "timestamp": timestamp
        }, rest

    def serialize_tail(self):
        flags = 0

        if self.is_post_policy:
            flags |= (1 << 6)

        if ':' in self.peer_address:
            flags |= (1 << 7)
            peer_address = addrconv.ipv6.text_to_bin(self.peer_address)
        else:
            peer_address = struct.pack(
                '!12x4s', addrconv.ipv4.text_to_bin(self.peer_address))

        peer_bgp_id = addrconv.ipv4.text_to_bin(self.peer_bgp_id)

        t1, t2 = [int(t) for t in ("%.6f" % self.timestamp).split('.')]

        msg = bytearray(struct.pack(self._PEER_HDR_PACK_STR, self.peer_type,
                                    flags, self.peer_distinguisher,
                                    peer_address, self.peer_as,
                                    peer_bgp_id, t1, t2))
        return msg


@BMPMessage.register_type(BMP_MSG_ROUTE_MONITORING)
class BMPRouteMonitoring(BMPPeerMessage):
    r"""BMP Route Monitoring Message

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    peer_type                  The type of the peer.
    peer_flags                 Provide more information about the peer.
    peer_distinguisher         Use for L3VPN router which can have multiple
                               instance.
    peer_address               The remote IP address associated with the TCP
                               session.
    peer_as                    The Autonomous System number of the peer.
    peer_bgp_id                The BGP Identifier of the peer
    timestamp                  The time when the encapsulated routes were
                               received.
    bgp_update                 BGP Update PDU
    ========================== ===============================================
    """

    def __init__(self, bgp_update, peer_type, is_post_policy,
                 peer_distinguisher, peer_address, peer_as, peer_bgp_id,
                 timestamp, version=VERSION, type_=BMP_MSG_ROUTE_MONITORING,
                 len_=None):
        super(BMPRouteMonitoring,
              self).__init__(peer_type=peer_type,
                             is_post_policy=is_post_policy,
                             peer_distinguisher=peer_distinguisher,
                             peer_address=peer_address,
                             peer_as=peer_as,
                             peer_bgp_id=peer_bgp_id,
                             timestamp=timestamp,
                             len_=len_,
                             type_=type_,
                             version=version)
        self.bgp_update = bgp_update

    @classmethod
    def parser(cls, buf):
        kwargs, buf = super(BMPRouteMonitoring, cls).parser(buf)

        bgp_update, _, buf = BGPMessage.parser(buf)

        kwargs['bgp_update'] = bgp_update

        return kwargs

    def serialize_tail(self):
        msg = super(BMPRouteMonitoring, self).serialize_tail()
        msg += self.bgp_update.serialize()

        return msg


@BMPMessage.register_type(BMP_MSG_STATISTICS_REPORT)
class BMPStatisticsReport(BMPPeerMessage):
    r"""BMP Statistics Report Message

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    peer_type                  The type of the peer.
    peer_flags                 Provide more information about the peer.
    peer_distinguisher         Use for L3VPN router which can have multiple
                               instance.
    peer_address               The remote IP address associated with the TCP
                               session.
    peer_as                    The Autonomous System number of the peer.
    peer_bgp_id                The BGP Identifier of the peer
    timestamp                  The time when the encapsulated routes were
                               received.
    stats                      Statistics (one or more stats encoded as a TLV)
    ========================== ===============================================
    """

    _TLV_PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_TLV_PACK_STR)

    def __init__(self, stats, peer_type, is_post_policy, peer_distinguisher,
                 peer_address, peer_as, peer_bgp_id, timestamp,
                 version=VERSION, type_=BMP_MSG_STATISTICS_REPORT, len_=None):
        super(BMPStatisticsReport,
              self).__init__(peer_type=peer_type,
                             is_post_policy=is_post_policy,
                             peer_distinguisher=peer_distinguisher,
                             peer_address=peer_address,
                             peer_as=peer_as,
                             peer_bgp_id=peer_bgp_id,
                             timestamp=timestamp,
                             len_=len_,
                             type_=type_,
                             version=version)
        self.stats = stats

    @classmethod
    def parser(cls, buf):
        kwargs, rest = super(BMPStatisticsReport, cls).parser(buf)

        stats_count, = struct.unpack_from('!I', six.binary_type(rest))

        buf = rest[struct.calcsize('!I'):]

        stats = []

        while len(buf):
            if len(buf) < cls._MIN_LEN:
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._MIN_LEN))
            (type_, len_) = struct.unpack_from(cls._TLV_PACK_STR,
                                               six.binary_type(buf))

            if len(buf) < (cls._MIN_LEN + len_):
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._MIN_LEN + len_))

            value = buf[cls._MIN_LEN:cls._MIN_LEN + len_]

            if type_ == BMP_STAT_TYPE_REJECTED or \
               type_ == BMP_STAT_TYPE_DUPLICATE_PREFIX or \
               type_ == BMP_STAT_TYPE_DUPLICATE_WITHDRAW or \
               type_ == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_CLUSTER_LIST_LOOP or \
               type_ == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_PATH_LOOP or \
               type_ == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_ORIGINATOR_ID or \
               type_ == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_CONFED_LOOP:
                value, = struct.unpack_from('!I', six.binary_type(value))
            elif type_ == BMP_STAT_TYPE_ADJ_RIB_IN or \
                    type_ == BMP_STAT_TYPE_LOC_RIB:
                value, = struct.unpack_from('!Q', six.binary_type(value))

            buf = buf[cls._MIN_LEN + len_:]

            stats.append({'type': type_, 'len': len_, 'value': value})

        kwargs['stats'] = stats

        return kwargs

    def serialize_tail(self):
        msg = super(BMPStatisticsReport, self).serialize_tail()

        stats_count = len(self.stats)

        msg += bytearray(struct.pack('!I', stats_count))

        for v in self.stats:
            t = v['type']
            if t == BMP_STAT_TYPE_REJECTED or \
               t == BMP_STAT_TYPE_DUPLICATE_PREFIX or \
               t == BMP_STAT_TYPE_DUPLICATE_WITHDRAW or \
               t == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_CLUSTER_LIST_LOOP or \
               t == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_PATH_LOOP or \
               t == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_ORIGINATOR_ID or \
               t == BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_CONFED_LOOP:
                valuepackstr = 'I'
            elif t == BMP_STAT_TYPE_ADJ_RIB_IN or \
                    t == BMP_STAT_TYPE_LOC_RIB:
                valuepackstr = 'Q'
            else:
                continue

            v['len'] = struct.calcsize(valuepackstr)
            msg += bytearray(struct.pack(self._TLV_PACK_STR + valuepackstr,
                                         t, v['len'], v['value']))

        return msg


@BMPMessage.register_type(BMP_MSG_PEER_DOWN_NOTIFICATION)
class BMPPeerDownNotification(BMPPeerMessage):
    r"""BMP Peer Down Notification Message

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    reason                     Reason indicates why the session was closed.
    data                       vary by the reason.
    ========================== ===============================================
    """

    def __init__(self, reason, data, peer_type, is_post_policy,
                 peer_distinguisher, peer_address, peer_as, peer_bgp_id,
                 timestamp, version=VERSION,
                 type_=BMP_MSG_PEER_DOWN_NOTIFICATION, len_=None):

        super(BMPPeerDownNotification,
              self).__init__(peer_type=peer_type,
                             is_post_policy=is_post_policy,
                             peer_distinguisher=peer_distinguisher,
                             peer_address=peer_address,
                             peer_as=peer_as,
                             peer_bgp_id=peer_bgp_id,
                             timestamp=timestamp,
                             len_=len_,
                             type_=type_,
                             version=version)

        self.reason = reason
        self.data = data

    @classmethod
    def parser(cls, buf):
        kwargs, buf = super(BMPPeerDownNotification, cls).parser(buf)
        reason, = struct.unpack_from('!B', six.binary_type(buf))
        buf = buf[struct.calcsize('!B'):]

        if reason == BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION:
            data, _, rest = BGPMessage.parser(buf)
        elif reason == BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION:
            data = struct.unpack_from('!H', six.binary_type(buf))
        elif reason == BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
            data, _, rest = BGPMessage.parser(buf)
        elif reason == BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION:
            data = None
        else:
            reason = BMP_PEER_DOWN_REASON_UNKNOWN
            data = buf

        kwargs['reason'] = reason
        kwargs['data'] = data

        return kwargs

    def serialize_tail(self):
        msg = super(BMPPeerDownNotification, self).serialize_tail()
        msg += struct.pack('!B', self.reason)

        if self.reason == BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION:
            msg += self.data.serialize()
        elif self.reason == BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION:
            msg += struct.pack('!H', self.data)
        elif self.reason == BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
            msg += self.data.serialize()
        elif self.reason == BMP_PEER_DOWN_REASON_UNKNOWN:
            msg += str(self.data)

        return msg


@BMPMessage.register_type(BMP_MSG_PEER_UP_NOTIFICATION)
class BMPPeerUpNotification(BMPPeerMessage):
    r"""BMP Peer Up Notification Message

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    peer_type                  The type of the peer.
    peer_flags                 Provide more information about the peer.
    peer_distinguisher         Use for L3VPN router which can have multiple
                               instance.
    peer_address               The remote IP address associated with the TCP
                               session.
    peer_as                    The Autonomous System number of the peer.
    peer_bgp_id                The BGP Identifier of the peer
    timestamp                  The time when the encapsulated routes were
                               received.
    local_address              The local IP address associated with the
                               peering TCP session.
    local_port                 The local port number associated with the
                               peering TCP session.
    remote_port                The remote port number associated with the
                               peering TCP session.
    sent_open_message          The full OPEN message transmitted by the
                               monitored router to its peer.
    received_open_message      The full OPEN message received by the monitored
                               router from its peer.
    ========================== ===============================================
    """

    _PACK_STR = '!16sHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, local_address, local_port, remote_port,
                 sent_open_message, received_open_message,
                 peer_type, is_post_policy, peer_distinguisher,
                 peer_address, peer_as, peer_bgp_id, timestamp,
                 version=VERSION, type_=BMP_MSG_PEER_UP_NOTIFICATION,
                 len_=None):
        super(BMPPeerUpNotification,
              self).__init__(peer_type=peer_type,
                             is_post_policy=is_post_policy,
                             peer_distinguisher=peer_distinguisher,
                             peer_address=peer_address,
                             peer_as=peer_as,
                             peer_bgp_id=peer_bgp_id,
                             timestamp=timestamp,
                             len_=len_,
                             type_=type_,
                             version=version)
        self.local_address = local_address
        self.local_port = local_port
        self.remote_port = remote_port
        self.sent_open_message = sent_open_message
        self.received_open_message = received_open_message

    @classmethod
    def parser(cls, buf):
        kwargs, rest = super(BMPPeerUpNotification, cls).parser(buf)

        (local_address, local_port,
         remote_port) = struct.unpack_from(cls._PACK_STR, six.binary_type(rest))

        if '.' in kwargs['peer_address']:
            local_address = addrconv.ipv4.bin_to_text(local_address[-4:])
        elif ':' in kwargs['peer_address']:
            local_address = addrconv.ipv6.bin_to_text(local_address)
        else:
            raise ValueError("invalid local_address: %s" % local_address)

        kwargs['local_address'] = local_address
        kwargs['local_port'] = local_port
        kwargs['remote_port'] = remote_port

        rest = rest[cls._MIN_LEN:]

        sent_open_msg, _, rest = BGPMessage.parser(rest)
        received_open_msg, _, rest = BGPMessage.parser(rest)

        kwargs['sent_open_message'] = sent_open_msg
        kwargs['received_open_message'] = received_open_msg

        return kwargs

    def serialize_tail(self):
        msg = super(BMPPeerUpNotification, self).serialize_tail()

        if '.' in self.local_address:
            local_address = struct.pack(
                '!12x4s', addrconv.ipv4.text_to_bin(self.local_address))
        elif ':' in self.local_address:
            local_address = addrconv.ipv6.text_to_bin(self.local_address)
        else:
            raise ValueError("invalid local_address: %s" % self.local_address)

        msg += struct.pack(self._PACK_STR, local_address,
                           self.local_port, self.remote_port)

        msg += self.sent_open_message.serialize()
        msg += self.received_open_message.serialize()

        return msg


@BMPMessage.register_type(BMP_MSG_INITIATION)
class BMPInitiation(BMPMessage):
    r"""BMP Initiation Message

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    info                       One or more piece of information encoded as a
                               TLV
    ========================== ===============================================
    """

    _TLV_PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_TLV_PACK_STR)

    def __init__(self, info, type_=BMP_MSG_INITIATION, len_=None,
                 version=VERSION):
        super(BMPInitiation, self).__init__(type_, len_, version)
        self.info = info

    @classmethod
    def parser(cls, buf):
        info = []
        while len(buf):
            if len(buf) < cls._MIN_LEN:
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._MIN_LEN))
            (type_, len_) = struct.unpack_from(cls._TLV_PACK_STR,
                                               six.binary_type(buf))

            if len(buf) < (cls._MIN_LEN + len_):
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._MIN_LEN + len_))

            value = buf[cls._MIN_LEN:cls._MIN_LEN + len_]

            if type_ == BMP_INIT_TYPE_STRING:
                value = value.decode('utf-8')

            buf = buf[cls._MIN_LEN + len_:]

            info.append({'type': type_, 'len': len_, 'value': value})

        return {'info': info}

    def serialize_tail(self):
        msg = bytearray()

        for v in self.info:
            if v['type'] == BMP_INIT_TYPE_STRING:
                value = v['value'].encode('utf-8')
            else:
                value = v['value']

            v['len'] = len(value)
            msg += struct.pack(self._TLV_PACK_STR, v['type'], v['len'])
            msg += value

        return msg


@BMPMessage.register_type(BMP_MSG_TERMINATION)
class BMPTermination(BMPMessage):
    r"""BMP Termination Message

    ========================== ===============================================
    Attribute                  Description
    ========================== ===============================================
    version                    Version. this packet lib defines BMP ver. 3
    len                        Length field.  Ignored when encoding.
    type                       Type field.  one of BMP\_MSG\_ constants.
    info                       One or more piece of information encoded as a
                               TLV
    ========================== ===============================================
    """

    _TLV_PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_TLV_PACK_STR)

    def __init__(self, info, type_=BMP_MSG_TERMINATION, len_=None,
                 version=VERSION):
        super(BMPTermination, self).__init__(type_, len_, version)
        self.info = info

    @classmethod
    def parser(cls, buf):
        info = []
        while len(buf):
            if len(buf) < cls._MIN_LEN:
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._MIN_LEN))
            (type_, len_) = struct.unpack_from(cls._TLV_PACK_STR,
                                               six.binary_type(buf))

            if len(buf) < (cls._MIN_LEN + len_):
                raise stream_parser.StreamParser.TooSmallException(
                    '%d < %d' % (len(buf), cls._MIN_LEN + len_))

            value = buf[cls._MIN_LEN:cls._MIN_LEN + len_]
            if type_ == BMP_TERM_TYPE_STRING:
                value = value.decode('utf-8')
            elif type_ == BMP_TERM_TYPE_REASON:
                value, = struct.unpack_from('!H', six.binary_type(value))

            buf = buf[cls._MIN_LEN + len_:]

            info.append({'type': type_, 'len': len_, 'value': value})

        return {'info': info}

    def serialize_tail(self):
        msg = bytearray()

        for v in self.info:
            if v['type'] == BMP_TERM_TYPE_STRING:
                value = v['value'].encode('utf-8')
            elif v['type'] == BMP_TERM_TYPE_REASON:
                value = struct.pack('!H', v['value'])
            v['len'] = len(value)
            msg += struct.pack(self._TLV_PACK_STR, v['type'], v['len'])
            msg += value

        return msg
