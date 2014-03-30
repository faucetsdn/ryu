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
This module provides BGP protocol message classes and utility methods to encode
and decode them.

This file is adapted from pybgp open source project.
"""
from abc import ABCMeta
from abc import abstractmethod
from copy import copy
import cStringIO
import logging
import socket
import struct

from ryu.services.protocols.bgp.protocols.bgp import capabilities
from ryu.services.protocols.bgp.protocols.bgp.exceptions import BadBgpId
from ryu.services.protocols.bgp.protocols.bgp.exceptions import BadLen
from ryu.services.protocols.bgp.protocols.bgp.exceptions import BadMsg
from ryu.services.protocols.bgp.protocols.bgp.exceptions import BadNotification
from ryu.services.protocols.bgp.protocols.bgp.exceptions import \
    MalformedAttrList
from ryu.services.protocols.bgp.protocols.bgp.exceptions import \
    UnacceptableHoldTime
from ryu.services.protocols.bgp.protocols.bgp import nlri
from ryu.services.protocols.bgp.protocols.bgp.nlri import get_rf
from ryu.services.protocols.bgp.protocols.bgp import OrderedDict
from ryu.services.protocols.bgp.protocols.bgp import pathattr
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.utils.validation import is_valid_old_asn


LOG = logging.getLogger('bgpspeaker.bgp.proto.messages')

# BGP capability optional parameter type
CAP_OPT_PARA_TYPE = 2

# Registry for bgp message class by their type code.
# <key>: <value> - <type-code>: <msg class>
_BGP_MESSAGE_REGISTRY = {}


def _register_bgp_message(cls):
    """Used as class decorator for registering bgp message class by their
    type-code.
    """
    assert _BGP_MESSAGE_REGISTRY.get(cls.TYPE_CODE) is None
    assert hasattr(cls, 'from_bytes')
    _BGP_MESSAGE_REGISTRY[cls.TYPE_CODE] = cls
    return cls


class BgpMessage(object):
    """Super class of all bgp messages.
    """
    __metaclass__ = ABCMeta
    TYPE_CODE = 0
    MSG_NAME = 'abstract-msg'
    HEADER_SIZE = 19

    @abstractmethod
    def packvalue(self):
        """Encodes the body of this bgp message."""
        raise NotImplementedError()

    def encode(self):
        """Encodes this bgp message with header and body."""
        body = self.packvalue()
        return struct.pack('!16sHB', '\xff' * 16, 19 + len(body),
                           self.__class__.TYPE_CODE) + body


class RecognizedBgpMessage(BgpMessage):
    """Represents recognized/supported bgp message.

    Declares a factory method to create an instance from bytes.
    """
    @classmethod
    def from_bytes(cls, recv_bytes, total_msg_length):
        raise NotImplementedError()


@_register_bgp_message
class Open(RecognizedBgpMessage):
    """Represents bgp OPEN message.

    This is the first message sent by each peer after TCP connection is
    established.
    """
    MSG_NAME = 'open'
    TYPE_CODE = 1
    MIN_LENGTH = 29

    def __init__(self, version, asnum, holdtime, bgpid, caps,
                 unrec_params=None):
        # Validate arguments.
        if version < 1:
            raise ValueError('Invalid version number %s' % version)
        if not is_valid_old_asn(asnum):
            raise ValueError('Invalid AS number %s' % asnum)
        if holdtime <= 2:
            raise ValueError('Holdtime has to be greater than 2 sec.')
        if not caps:
            raise ValueError('Invalid capabilities.')
        if not is_valid_ipv4(bgpid):
            raise ValueError('Invalid bgp ID, should be valid IPv4, '
                             'but given %s' % bgpid)

        BgpMessage.__init__(self)
        self._version = version
        self._holdtime = holdtime
        self._asnum = asnum
        self._bgpid = bgpid
        self._caps = caps
        self._unrec_params = unrec_params
        if not unrec_params:
            self._unrec_params = OrderedDict()

    @property
    def version(self):
        return self._version

    @property
    def holdtime(self):
        return self._holdtime

    @property
    def asnum(self):
        return self._asnum

    @property
    def bgpid(self):
        return self._bgpid

    @property
    def caps(self):
        return copy(self._caps)

    @property
    def unrec_params(self):
        return copy(self._unrec_params)

    @classmethod
    def from_bytes(cls, recv_bytes, total_msg_len):
        # Validate OPEN message length.
        if len(recv_bytes) < 10:
            raise BadLen(Open.TYPE_CODE, len(recv_bytes) + cls.HEADER_SIZE)

        version, asnum, holdtime, bgpid, paramlen = \
            struct.unpack_from('!BHH4sB', recv_bytes)

        if len(recv_bytes) != (10 + paramlen):
            # TODO(PH): Check what RFC says to do here.
            LOG.debug('Open message: too short.')

        offset = 10

        # BGP implementation MUST reject Hold Time values of one or two
        # seconds.
        if holdtime <= 2:
            raise UnacceptableHoldTime()

        # BGP Identifier field MUST represents a valid unicast IP host address.
        bgpid = socket.inet_ntoa(bgpid)
        if not is_valid_ipv4(bgpid):
            raise BadBgpId()

        # Parse optional parameters.
        caps = OrderedDict()
        unrec_params = OrderedDict()
        while offset < len(recv_bytes):
            ptype, plen = struct.unpack_from('BB', recv_bytes, offset)
            offset += 2
            value = recv_bytes[offset:offset + plen]
            offset += plen

            # Parse capabilities optional parameter.
            if ptype == CAP_OPT_PARA_TYPE:
                bgp_caps = capabilities.decode(value)
                # store decoded bgp capabilities by their capability-code
                for cap in bgp_caps:
                    cap_code = cap.CODE
                    if cap_code in caps:
                        caps[cap_code].append(cap)
                    else:
                        caps[cap_code] = [cap]
            else:
                # Other unrecognized optional parameters.
                unrec_params[ptype] = value

        # Un-recognized capabilities are passed on, its up to application to
        # check if unrec-optional-paramters are a problem and send NOTIFICATION
        return cls(version, asnum, holdtime, bgpid, caps, unrec_params)

    def packvalue(self):
        params = cStringIO.StringIO()
        # Capabilities optional parameters.
        for capability in self.caps.itervalues():
            for cap in capability:
                encoded_cap = cStringIO.StringIO()
                encoded_cap.write(cap.encode())
                encoded_cap_value = encoded_cap.getvalue()
                encoded_cap.close()
                params.write(struct.pack('BB',
                                         CAP_OPT_PARA_TYPE,
                                         len(encoded_cap_value)))
                params.write(encoded_cap_value)

        # Other optional parameters.
        for ptype, pvalue in self.unrec_params.items():
            params.write(struct.pack('BB', ptype, len(pvalue)))
            params.write(pvalue)

        bgpid = socket.inet_aton(self.bgpid)
        params_value = params.getvalue()
        params.close()
        return struct.pack('!BHH4sB', self.version, self.asnum, self.holdtime,
                           bgpid, len(params_value)) + params_value

    def __str__(self):
        str_rep = cStringIO.StringIO()
        str_rep.write('Open message Ver=%s As#=%s Hold Time=%s Bgp Id=%s' %
                      (self.version, self.asnum, self.holdtime, self.bgpid))
        for param, value in self.unrec_params.items():
            str_rep.write(' unrec_param %s=%r' % (param, value))
        for cap, value in self.caps.items():
            str_rep.write(' cap %s=%r' % (cap, value))
        return str_rep.getvalue()


@_register_bgp_message
class Keepalive(BgpMessage):
    MSG_NAME = 'keepalive'
    TYPE_CODE = 4

    @classmethod
    def from_bytes(cls, recv_bytes, total_msg_len):
        # Validate KeepAlive msg. length
        if len(recv_bytes):
            LOG.info("Received keepalive msg. with data! %r" % (recv_bytes,))
            raise BadLen(
                Keepalive.TYPE_CODE,
                len(recv_bytes) + cls.HEADER_SIZE
            )

        self = cls()
        return self

    def packvalue(self):
        return ''

    def __str__(self):
        return 'Keepalive message'


@_register_bgp_message
class RouteRefresh(BgpMessage):
    MSG_NAME = 'route-refresh'
    TYPE_CODE = 5

    def __init__(self, route_family, demarcation=0):
        BgpMessage.__init__(self)
        self._route_family = route_family
        self._demarcation = demarcation
        self.eor_sent = False

    @property
    def route_family(self):
        return self._route_family

    @property
    def demarcation(self):
        return self._demarcation

    @classmethod
    def from_bytes(cls, recv_bytes, total_msg_len):
        # Validate length of RouteRefresh message.
        if len(recv_bytes) != 4:
            raise BadLen(
                RouteRefresh.TYPE_CODE,
                len(recv_bytes) + cls.HEADER_SIZE
            )

        afi, reserved, safi = struct.unpack_from('!HBB', recv_bytes)
        route_family = get_rf(afi, safi)
        return cls(route_family, reserved)

    def packvalue(self):
        return struct.pack('!HBB', self.route_family.afi, self.demarcation,
                           self._route_family.safi)

    def __str__(self):
        return 'Route-refresh message (%s, %s)' % \
            (self.route_family, self.demarcation)


@_register_bgp_message
class Notification(BgpMessage):
    MSG_NAME = 'notification'
    TYPE_CODE = 3
    REASONS = {
        (1, 1): 'Message Header Error: not synchronised',
        (1, 2): 'Message Header Error: bad message len',
        (1, 3): 'Message Header Error: bad message type',
        (2, 1): 'Open Message Error: unsupported version',
        (2, 2): 'Open Message Error: bad peer AS',
        (2, 3): 'Open Message Error: bad BGP identifier',
        (2, 4): 'Open Message Error: unsupported optional param',
        (2, 5): 'Open Message Error: authentication failure',
        (2, 6): 'Open Message Error: unacceptable hold time',
        (2, 7): 'Open Message Error: Unsupported Capability',
        (2, 8): 'Open Message Error: Unassigned',
        (3, 1): 'Update Message Error: malformed attribute list',
        (3, 2): 'Update Message Error: unrecognized well-known attr',
        (3, 3): 'Update Message Error: missing well-known attr',
        (3, 4): 'Update Message Error: attribute flags error',
        (3, 5): 'Update Message Error: attribute length error',
        (3, 6): 'Update Message Error: invalid origin attr',
        (3, 7): 'Update Message Error: as routing loop',
        (3, 8): 'Update Message Error: invalid next hop attr',
        (3, 9): 'Update Message Error: optional attribute error',
        (3, 10): 'Update Message Error: invalid network field',
        (3, 11): 'Update Message Error: malformed AS_PATH',
        (4, 1): 'Hold Timer Expired',
        (5, 1): 'Finite State Machine Error',
        (6, 1): 'Cease: Maximum Number of Prefixes Reached',
        (6, 2): 'Cease: Administrative Shutdown',
        (6, 3): 'Cease: Peer De-configured',
        (6, 4): 'Cease: Administrative Reset',
        (6, 5): 'Cease: Connection Rejected',
        (6, 6): 'Cease: Other Configuration Change',
        (6, 7): 'Cease: Connection Collision Resolution',
        (6, 8): 'Cease: Out of Resources',
    }

    def __init__(self, code, subcode, data=''):
        BgpMessage.__init__(self)
        self._code = code
        self._subcode = subcode
        self._data = data

    @property
    def code(self):
        return self._code

    @property
    def subcode(self):
        return self._subcode

    @property
    def data(self):
        return self._data

    @classmethod
    def from_bytes(cls, recv_bytes, total_msg_len):
        # Validate NOTIFICATION msg. length.
        if len(recv_bytes) < 2:
            LOG.error('Received NOTIFICATION msg. with bad length %s' %
                      (len(recv_bytes) + cls.HEADER_SIZE))
            raise BadNotification()

        code, subcode = struct.unpack_from('BB', recv_bytes)
        data = recv_bytes[2:]

        # Check code or sub-code are recognized.
        if not Notification.REASONS.get((code, subcode)):
            LOG.error('Received notification msg. with unrecognized Error '
                      'code or Sub-code (%s, %s)' % (code, subcode))
            raise BadNotification()

        return cls(code, subcode, data)

    def __str__(self):
        c, s = self.code, self.subcode
        if (c, s) in self.REASONS:
            return ('Notification "%s" params %r' %
                    (self.REASONS[c, s], self.data))
        return ('Notification message code=%d subcode=%d params=%r' %
                (self.code, self.subcode, self.data))

    def packvalue(self):
        v = struct.pack('BB', self.code, self.subcode)
        if self.data:
            v += self.data
        return v


@_register_bgp_message
class Update(BgpMessage):
    MSG_NAME = 'update'
    TYPE_CODE = 2
    WITHDRAW_NLRI = 'withdraw_nlri'
    PATH_ATTR_AND_NLRI = 'path_attr_and_nlri'
    MIN_LENGTH = 23

    def __init__(self, pathattr_map=None, nlri_list=None, withdraw_list=None):
        """Initailizes a new `Update` instance.

        Parameter:
            - `pathattr_map`: (OrderedDict) key -> attribute name,
            value -> attribute.
            - `nlri_list`: (list/iterable) NLRIs.
            - `withdraw_list`: (list/iterable) Withdraw routes.
        """
        if nlri_list is None:
            nlri_list = []
        if withdraw_list is None:
            withdraw_list = []
        if not pathattr_map:
            pathattr_map = OrderedDict()

        self._nlri_list = list(nlri_list)
        self._withdraw_list = list(withdraw_list)
        self._pathattr_map = copy(pathattr_map)

    @property
    def nlri_list(self):
        return self._nlri_list[:]

    @property
    def withdraw_list(self):
        return self._withdraw_list[:]

    @property
    def pathattr_map(self):
        return copy(self._pathattr_map)

    def get_path_attr(self, attr_name):
        return self._pathattr_map.get(attr_name)

    @classmethod
    def from_bytes(cls, recv_bytes, total_msg_len):
        # Validate UPDATE message length
        if len(recv_bytes) < 4:
            raise BadLen(Update.TYPE_CODE, len(recv_bytes) + cls.HEADER_SIZE)
        withdraw_list = None
        nlri_list = None
        pathattr_map = OrderedDict()

        d = {}
        idx = 0
        # Compute withdraw route length + total attribute length.
        recv_len = 0
        for kind in (Update.WITHDRAW_NLRI, Update.PATH_ATTR_AND_NLRI):
            plen, = struct.unpack_from('!H', recv_bytes, idx)
            idx += 2
            d[kind] = recv_bytes[idx: (idx + plen)]
            idx += plen
            recv_len += plen


        if d[Update.WITHDRAW_NLRI]:
            withdraw_list = nlri.parse(d[Update.WITHDRAW_NLRI])
        # TODO(PH): We have to test how ipv4 nlri packed after path-attr are
        # getting parsed.
        nlri_list = nlri.parse(recv_bytes[idx:])

        idx = 0
        recv_bytes = d[Update.PATH_ATTR_AND_NLRI]
        while idx < len(recv_bytes):
            used, pattr = pathattr.decode(recv_bytes, idx)
            # TODO(PH) Can optimize here by checking if path attribute is
            # MpReachNlri and stop parsing if RT are not interesting.
            idx += used
            pathattr_map[pattr.ATTR_NAME] = pattr

        return cls(pathattr_map=pathattr_map,
                   nlri_list=nlri_list, withdraw_list=withdraw_list)

    def __repr__(self):
        str_rep = cStringIO.StringIO()
        str_rep.write('<Update message withdraw=%r' % (self._withdraw_list,))
        for ptype, pattr in self._pathattr_map.items():
            str_rep.write('\n path attr %s, %s' % (ptype, pattr,))
#             if ptype in (MpReachNlri.ATTR_NAME, MpUnreachNlri):
#                 for nnlri in pattr.nlri_list:
#                     str_rep.write('\n  nlri=%s' % (nnlri,))
        for nnlri in self._nlri_list:
            str_rep.write('\nmp nlri %s' % (nnlri,))

        str_rep.write('>')

        return str_rep.getvalue()

    def __cmp__(self, other):
        if isinstance(other, Update):
            return cmp(
                (self._pathattr_map, self._withdraw_list, self._nlri_list),
                (other.pathattr_map, other.withdraw_list, other.nlri_list),
            )
        return -1

    def packvalue(self):
        bvalue = ''

        bwithdraw = ''
        for awithdraw in self._withdraw_list:
            bwithdraw += awithdraw.encode()

        bvalue += struct.pack('!H', len(bwithdraw))
        bvalue += bwithdraw

        pattr = ''
        for _, attr in self._pathattr_map.items():
            if attr is not None:
                pattr += attr.encode()
        bvalue += struct.pack('!H', len(pattr))
        bvalue += pattr

        for anlri in self._nlri_list:
            bvalue += anlri.encode()

        return bvalue


def decode(ptype, payload, msg_len):
    """Decodes given payload into bgp message instance of given type.
    """
    bgp_msg_class = _BGP_MESSAGE_REGISTRY.get(ptype)
    if not bgp_msg_class:
        raise BadMsg(ptype)

    return bgp_msg_class.from_bytes(payload, msg_len)
