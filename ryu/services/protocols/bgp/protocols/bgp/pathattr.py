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
This module provides BGP Path Attributes classes and utility methods to
encode and decode them.

This file was adapted from pybgp open source project.
"""
from abc import ABCMeta
from abc import abstractmethod
import copy
import logging
import socket
import StringIO
import struct

from ryu.services.protocols.bgp.protocols.bgp.exceptions import AttrFlagError
from ryu.services.protocols.bgp.protocols.bgp.exceptions import AttrLenError
from ryu.services.protocols.bgp.protocols.bgp.exceptions import InvalidNextHop
from ryu.services.protocols.bgp.protocols.bgp.exceptions import \
    InvalidOriginError
from ryu.services.protocols.bgp.protocols.bgp.exceptions import MalformedAsPath
from ryu.services.protocols.bgp.protocols.bgp.exceptions import OptAttrError
from ryu.services.protocols.bgp.protocols.bgp import nlri
from ryu.services.protocols.bgp.protocols.bgp.nlri import get_rf
from ryu.services.protocols.bgp.protocols.bgp.nlri import RF_IPv4_VPN
from ryu.services.protocols.bgp.protocols.bgp.nlri import RF_IPv6_VPN
from ryu.services.protocols.bgp.protocols.bgp.nlri import RF_RTC_UC
from ryu.services.protocols.bgp.utils.internable import Internable
from ryu.services.protocols.bgp.utils import validation
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv6


LOG = logging.getLogger('protocols.bgp.pathattr')

# BGP Attribute flags
EXTENDED_LEN_BGP_ATTR = 0x10
PARTIAL_BGP_ATTR = 0x20
TRANSITIVE_BGP_ATTR = 0x40
OPTIONAL_BGP_ATTR = 0x80

# BGP flag mask
DEFAULT_FLAGS_MASK = 0x3f

# BGP recognized path attribute class registry by type-code.
# i.e. <key, value>: <type-code, path-attr-class>
_PATH_ATTR_REGISTRY = {}


def _register_path_attr(cls):
    """Used as decorator for registering recognized bgp path attribute class
     by their type-code.
    """
    assert issubclass(cls, RcgPathAttr)
    assert hasattr(cls, 'TYPE_CODE') and hasattr(cls, 'FLAGS')
    assert _PATH_ATTR_REGISTRY.get(cls.TYPE_CODE) is None
    _PATH_ATTR_REGISTRY[cls.TYPE_CODE] = cls
    return cls


def decode(received, idx=0):
    """Decodes given bytes into corresponding BGP path attribute.
    """
    iidx = idx
    flagb, path_attr_type = struct.unpack_from('BB', received, idx)
    idx += 2
    used = 2

    if flagb & 16:
        length, = struct.unpack_from('>H', received, idx)
        idx += 2
        used += 2
    else:
        length, = struct.unpack_from('!B', received, idx)
        idx += 1
        used += 1

    recv_data = received[idx:(idx + length)]
    used += length

    # Check if this attribute type is recognized.
    path_attr_class = _PATH_ATTR_REGISTRY.get(path_attr_type)
    path_attr = None
    if path_attr_class:
        # Check if flags match expected from known/recognized attribute type.
        if not path_attr_class.check_flags(flagb):
            LOG.error(
                "Flags(%s) of pathattr %s received in update don't "
                "match expected flags(%s)"
                % (
                    flagb,
                    str(path_attr_class),
                    path_attr_class.FLAGS
                )
            )
            raise AttrFlagError(data=received[iidx:used])

        try:
            path_attr = path_attr_class.from_bytes(recv_data)
        except (AttrLenError, InvalidOriginError, InvalidNextHop,
                OptAttrError) as e:
            # Set attribute type, length and value as data/payload.
            e.data = received[iidx:used]
            raise e
    else:
        path_attr = UnRcgPathAttr(recv_data, flagb, path_attr_type)

    return used, path_attr


class PathAttr(Internable):
    """Abstract base class for bgp path attributes.

    Defines interface for all path attributes and provides some default util.
    methods.
    """
    __metaclass__ = ABCMeta
    __slots__ = ('_flags')
    TYPE_CODE = 0
    ATTR_NAME = 'default'

    def __init__(self, flags):
        super(PathAttr, self).__init__()
        self._flags = flags

    @property
    def flags(self):
        return self._flags

    @abstractmethod
    def packvalue(self):
        """Encodes path-attribute value/pay-load into binary format."""
        raise NotImplementedError()

    def encode(self):
        """Wraps packed path-attribute value with headers, such as,
        flags, type-code and length.
        """
        valueb = self.packvalue()
        flags = self._flags
        type_code = self.__class__.TYPE_CODE

        if len(valueb) > 255:
            flags = flags | 16
            return struct.pack('!BBH', flags, type_code, len(valueb)) + valueb

        flags = flags & (0xff ^ 16)
        return struct.pack('BBB', flags, type_code, len(valueb)) + valueb

    def str_flags(self):
        """Returns a list of attribute category for this bgp attribute."""

        if self._flags:
            flag_cat = []
            if self._flags & OPTIONAL_BGP_ATTR:
                flag_cat.append('optional')
            else:
                flag_cat.append('well-known')

            if self._flags & TRANSITIVE_BGP_ATTR:
                flag_cat.append('transitive')
            else:
                flag_cat.append('non-transitive')

            if self._flags & PARTIAL_BGP_ATTR:
                flag_cat.append('partial')
            else:
                flag_cat.append('complete')

            if self._flags & EXTENDED_LEN_BGP_ATTR:
                flag_cat.append('ext-length')
            else:
                flag_cat.append('regular-length')

            return ','.join(flag_cat)

        return 'None'

    def __repr__(self):
        return '<%s type/num=%s/%s flags %s>' % (
            self.__class__.__name__, 'unknown', self.__class__.TYPE_CODE,
            self.str_flags())

    def __cmp__(self, other):
        if isinstance(other, PathAttr):
            if other.__class__ == self.__class__:
                return cmp(self._flags, other._flags)

        return -1

    def __hash__(self):
        return hash(self._flags, self.__class__.TYPE_CODE)


class RcgPathAttr(PathAttr):
    """Base class for all recognized path attributes."""
    # Flags for this type of known path attribute.
    # Sub-classes should provide value as per RFC.
    FLAGS = None

    # There are some flags we don't care about. By default we don't care about
    # extended-length bit and partial bit, so mask is 0x3f (0011 1111)
    FLAGS_MASK = DEFAULT_FLAGS_MASK

    def __init__(self):
        PathAttr.__init__(self, self.__class__.FLAGS)

    @classmethod
    def from_bytes(cls, val):
        raise NotImplementedError()

    @classmethod
    def check_flags(cls, flags):
        """Check if provided flags match flags required by RFC (cls.FLAGS).

            RFC path attribute higher order bit rules:
            0    1     2    3    4    5    6    7

            Well Known
            0    1 - always
                    0 - always
                        0 - attribute length 1 octet
                        1 - attribute length 2 octet

            Optional
            1    1 - Transitive
                    1 - Partial
                    0 - Complete
                0 - Non-Transitive
                    0 - always
        """
        return cls.FLAGS | cls.FLAGS_MASK == flags | cls.FLAGS_MASK


class UnRcgPathAttr(PathAttr):
    """Class for all un-supported/un-recognized bgp path-attributes.
    """
    __slots__ = ('_type_code', '_value')
    ATTR_NAME = 'unknown'

    def __init__(self, value, flags, type_code):
        PathAttr.__init__(self, flags)
        self._type_code = type_code
        self._value = value

    @property
    def value(self):
        return self._value

    @property
    def type_code(self):
        return self._type_code

    def packvalue(self):
        return self._value

    def encode(self):
        all_flags = self._flags
        valueb = self.packvalue()

        if len(valueb) > 255:
            all_flags = all_flags | 16
            return struct.pack('!BBH', all_flags, self.type_code,
                               len(valueb)) + valueb

        all_flags = all_flags & (0xff ^ 16)
        return struct.pack('BBB', all_flags, self.type_code,
                           len(valueb)) + valueb

    def is_optional_transitive(self):
        """Returns true if this is an optional path attribute.
        """
        return self._flags & OPTIONAL_BGP_ATTR

    def is_transitive(self):
        """Returns true if this is an transitive path attribute.
        """
        return self._flags & TRANSITIVE_BGP_ATTR

    def __repr__(self):
        return '<%s type/num=%s/%s flags %s value %r>' % (
            self.__class__.__name__, 'unknown', self.type_code, self.flags,
            self.value)


@_register_path_attr
class Origin(RcgPathAttr):
    """ORIGIN is a well-known mandatory bgp path-attribute."""
    __slots__ = ('_value')
    TYPE_CODE = 1
    ATTR_NAME = 'origin'
    # 010 - well known, transitive, complete
    FLAGS = TRANSITIVE_BGP_ATTR

    # Various Origin values.
    IGP = 'igp'
    EGP = 'egp'
    INCOMPLETE = 'incomplete'

    def __init__(self, value='incomplete'):
        RcgPathAttr.__init__(self)
        if value not in (Origin.IGP, Origin.EGP, Origin.INCOMPLETE):
            raise ValueError('Invalid Origin attribute value.')
        self._value = value

    @property
    def value(self):
        return self._value

    @classmethod
    def from_bytes(cls, value):
        """Decodes bgp path-attribute with type-code 1, i.e. ORIGIN.
        """
        if value == '\x00':
            value = Origin.IGP
        elif value == '\x01':
            value = Origin.EGP
        elif value == '\x02':
            value = Origin.INCOMPLETE
        else:
            raise InvalidOriginError()

        return cls(value)

    def packvalue(self):
        if self.value == Origin.IGP:
            return '\x00'
        elif self.value == Origin.EGP:
            return '\x01'
        elif self.value == Origin.INCOMPLETE:
            return '\x02'
        return self.value

    def __repr__(self):
        return '<Origin ' + self.value + '>'

    def __str__(self):
        return str(self.value)


@_register_path_attr
class AsPath(RcgPathAttr):
    """AS_PATH is a well-known mandatory bgp path attribute.
    """
    __slots__ = ('_path_seg_list')
    TYPE_CODE = 2
    ATTR_NAME = 'aspath'
    # Higher order bits: 010 - well known, transitive, complete
    FLAGS = TRANSITIVE_BGP_ATTR
    SEG_TYP_AS_SET = 1
    SEG_TYP_AS_SEQ = 2

    def __init__(self, path_seg_list):
        RcgPathAttr.__init__(self)
        self._path_seg_list = None
        if isinstance(path_seg_list, str):
            self._path_seg_list = []
            for seg in path_seg_list.split():
                if seg.startswith('set(') and seg.endswith(')'):
                    seg = set([int(s) for s in seg[4:-1].split(',')])
                else:
                    seg = [int(s) for s in seg.split(',')]
                self._path_seg_list.append(seg)
        else:
            self._path_seg_list = path_seg_list[:]

    @property
    def path_seg_list(self):
        return copy.deepcopy(self._path_seg_list)

    def get_as_path_len(self):
        count = 0
        for seg in self._path_seg_list:
            if isinstance(seg, list):
                # Segment type 2 stored in list and all AS counted.
                count += len(seg)
            else:
                # Segment type 1 stored in set and count as one.
                count += 1

        return count

    def has_local_as(self, local_as):
        """Check if *local_as* is already present on path list."""
        for as_path_seg in self._path_seg_list:
            for as_num in as_path_seg:
                if as_num == local_as:
                    return True
        return False

    def has_matching_leftmost(self, remote_as):
        """Check if leftmost AS matches *remote_as*."""
        if not self._path_seg_list or not remote_as:
            return False

        leftmost_seg = self.path_seg_list[0]
        if leftmost_seg and leftmost_seg[0] == remote_as:
            return True

        return False

    @property
    def value(self):
        ret = []
        for as_path_seg in self._path_seg_list:
            for as_num in as_path_seg:
                ret.append(as_num)
        return ret

    def __repr__(self):
        rstring = StringIO.StringIO()
        rstring.write('<AsPath')
        for as_path_seg in self._path_seg_list:
            if isinstance(as_path_seg, set):
                rstring.write(' set(')
                rstring.write(','.join([str(asnum) for asnum in as_path_seg]))
                rstring.write(')')
            else:
                rstring.write(' ')
                rstring.write(','.join([str(asnum) for asnum in as_path_seg]))
        rstring.write('>')
        return rstring.getvalue()

    def __str__(self):
        ret = '['
        for as_path_seg in self._path_seg_list:
            ret += ', '.join([str(asnum) for asnum in as_path_seg])
        return ret + ']'

    @classmethod
    def from_bytes(cls, val):
        """Decodes bgp path-attribute with type-code 2, i.e. AS_PATH.
        """
        path_seg_list = []
        iidx = 0

        while iidx < len(val):
            segtype, numas = struct.unpack_from('BB', val, iidx)
            iidx += 2

            if segtype == AsPath.SEG_TYP_AS_SET:
                container = set()
                add = container.add
            elif segtype == AsPath.SEG_TYP_AS_SEQ:
                container = []
                add = container.append
            else:
                raise MalformedAsPath()

            for _ in range(numas):
                asnum, = struct.unpack_from('!H', val, iidx)
                iidx += 2
                add(asnum)
            path_seg_list.append(container)

        return cls(path_seg_list)

    def packvalue(self):
        valueb = ''
        for seg in self._path_seg_list:
            if isinstance(seg, set):
                segtype = 1
            elif isinstance(seg, (tuple, list)):
                segtype = 2
            else:
                raise Exception('unknown segment type %r' % (seg,))

            valueb += struct.pack('BB', segtype, len(seg))
            try:
                iter(seg)
            except TypeError:
                valueb += struct.pack('!H', int(seg))
            else:
                for asnum in seg:
                    if not isinstance(asnum, int):
                        asnum = int(asnum)
                    valueb += struct.pack('!H', asnum)

        return valueb


@_register_path_attr
class NextHop(RcgPathAttr):
    """NEXT_HOP is well-known mandatory bgp path-attribute.
    """
    __slots__ = ()
    TYPE_CODE = 3
    ATTR_NAME = 'nexthop'
    # Higher order bits: 010 - well known, transitive, complete
    FLAGS = TRANSITIVE_BGP_ATTR

    def __init__(self, ip_address):
        if not is_valid_ipv4(ip_address):
            raise ValueError('Invalid ipv4 address %s.' % ip_address)
        RcgPathAttr.__init__(self)
        self._ip_address = ip_address

    @property
    def ip_address(self):
        return self._ip_address

    def __repr__(self):
        return '<nexthop %s>' % (self.ip_address)

    def __str__(self):
        return str(self.ip_address)

    @classmethod
    def from_bytes(cls, value):
        """Decodes bgp path-attribute with type-code 3, i.e. NEXT_HOP.
        """
        value = socket.inet_ntoa(value)
        return cls(value)

    def packvalue(self):
        return socket.inet_aton(self._ip_address)


@_register_path_attr
class IntAttr(RcgPathAttr):
    """Super class of all bgp path-attribute whose value is an unsigned
    integer.
    """
    __slots__ = ('_value')

    def __init__(self, value):
        if not value:
            value = 0
        self._value = value
        RcgPathAttr.__init__(self)

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return '<%s(%d)>' % (self.__class__.__name__, self.value)

    def __str__(self):
        return str(self.value)

    @classmethod
    def from_bytes(cls, val):
        """Decode bgp path-attributes whose value is an unsigned integer.
        """
        value, = struct.unpack_from('!I', val)
        return cls(value)

    def packvalue(self):
        return struct.pack('!I', self.value)


@_register_path_attr
class Med(IntAttr):
    """MED is optional non-transitive bgp path-attribute."""
    __slots__ = ()
    TYPE_CODE = 4
    ATTR_NAME = 'med'
    # Higher order bits: 100 - optional, non-transitive, complete
    FLAGS = OPTIONAL_BGP_ATTR

    def __init__(self, value):
        IntAttr.__init__(self, value)


@_register_path_attr
class LocalPref(IntAttr):
    """LOCAL_PREF is a well-known discretionary attribute."""
    __slots__ = ()
    TYPE_CODE = 5
    ATTR_NAME = 'localpref'
    # Higher order bits: 010 - well-known, transitive, complete
    FLAGS = TRANSITIVE_BGP_ATTR

    def __init__(self, value):
        IntAttr.__init__(self, value)


@_register_path_attr
class Originator(RcgPathAttr):
    """ORIGINATOR_ID is a optional non-transitive attribute."""
    __slots__ = ('_value')
    TYPE_CODE = 9
    ATTR_NAME = 'originator'
    FLAGS = OPTIONAL_BGP_ATTR

    def __init__(self, value):
        RcgPathAttr.__init__(self)
        self._value = value

    @property
    def value(self):
        return self._value

    @classmethod
    def from_bytes(cls, val):
        """Decodes bgp path-attribute with type code 9, i.e. ORIGINATOR_ID.
        """
        if len(val) == 4:
            value = socket.inet_ntoa(val)
        else:
            raise Exception('Invalid originator')

        return cls(value)

    def packvalue(self):
        return socket.inet_aton(self.value)


@_register_path_attr
class ClusterList(RcgPathAttr):
    """CLUSTER_LIST is a optional non-transitive bgp path-attribute.
    """
    __slots__ = ('_cluster_list')
    TYPE_CODE = 10
    ATTR_NAME = 'cluster-list'
    FLAGS = OPTIONAL_BGP_ATTR

    def __init__(self, cluster_list):
        if not cluster_list:
            raise ValueError('Invalid cluster list.')
        # TODO(PH): add more validation of input here.
        RcgPathAttr.__init__(self)
        self._cluster_list = cluster_list

    @property
    def cluster_list(self):
        return self._cluster_list

    @classmethod
    def from_bytes(cls, val):
        """Decodes bgp path-attribute with type-code 10, i.e. CLUSTER_LIST.
        """
        cluster_list = []
        iidx = 0
        while iidx < len(val):
            cluster_list.append(
                socket.inet_ntoa(struct.unpack_from('4s', val, iidx)[0])
            )
            iidx += 4
        return cls(cluster_list)

    def packvalue(self):
        valueb = ''
        for c in self.cluster_list:
            valueb += socket.inet_aton(c)
        return valueb


@_register_path_attr
class MpReachNlri(RcgPathAttr):
    """MP_REACH_NLRI is a optional non-transitive bgp path-attribute.
    """
    __slots__ = ('_route_family', '_next_hop', '_nlri_list', '_reserved')
    TYPE_CODE = 14
    ATTR_NAME = 'mp-reach-nlri'
    NEXT_HOP = 'nh'
    NLRI = 'nlri'
    RESERVED = 'reserved'
    # Higher order bits: 100 - optional, non-transitive, complete
    FLAGS = OPTIONAL_BGP_ATTR

    def __init__(self, route_family, next_hop, nlri_list, reserved=None):
        if not (hasattr(route_family, 'afi') and
                hasattr(route_family, 'safi')):
            raise ValueError('Invalid parameter value for route_family %s.' %
                             route_family)

        if not next_hop:
            raise ValueError('Invalid next_hop %s' % next_hop)

        # MpReachNlri attribute should have next-hop belonging to same
        # route-family
        if ((route_family == RF_IPv4_VPN and not is_valid_ipv4(next_hop)) or
                (route_family == RF_IPv6_VPN and not is_valid_ipv6(next_hop))):
            raise ValueError('Next hop should belong to %s route family' %
                             route_family)

        if not nlri_list:
            nlri_list = []

        RcgPathAttr.__init__(self)
        self._route_family = route_family
        self._next_hop = next_hop
        self._nlri_list = nlri_list
        self._reserved = reserved

    @property
    def route_family(self):
        return self._route_family

    @property
    def next_hop(self):
        return self._next_hop

    @property
    def nlri_list(self):
        return self._nlri_list[:]

    @property
    def reserved(self):
        return self._reserved

    def __repr__(self):
        return '<MpReachNlri route_family=%r next_hop=%r nlri_list=%r>' % (
            self.route_family, self.next_hop, self._nlri_list)

    @classmethod
    def from_bytes(cls, val):
        """Decodes bgp path-attribute with type code 14, i.e MP_REACH_NLRI.
        """
        afi, safi, nhlen = struct.unpack_from('!HBB', val)
        fmt = '%dsB' % (nhlen,)
        next_hop, reserved = struct.unpack_from(fmt, val, 4)

        if afi == 1 and safi is 128:
            # Vpnv4
            _, _, nhip = struct.unpack('!II4s', next_hop)
            next_hop = socket.inet_ntop(socket.AF_INET, nhip)
        elif afi == 1 and safi == 132:
            # RtNlri
            nhip, = struct.unpack('!4s', next_hop)
            next_hop = socket.inet_ntop(socket.AF_INET, nhip)
        elif afi == 2 and safi == 128:
            # Vpnv6
            _, _, nhip = struct.unpack('!II16s', next_hop)
            next_hop = socket.inet_ntop(socket.AF_INET6, nhip)
        else:
            LOG.error('Received NLRI for afi/safi (%s/%s), which is not'
                      ' supported yet!' % (afi, safi))
            raise OptAttrError()

        n_nlri = nlri.parse(val[5 + nhlen:], afi, safi)
        route_family = get_rf(afi, safi)
        return cls(route_family, next_hop, n_nlri, reserved)

    def packvalue(self):
        afi = self._route_family.afi
        safi = self._route_family.safi
        if self._route_family == RF_IPv4_VPN:
            next_hop = '\0' * 8
            next_hop += socket.inet_aton(self.next_hop)
        elif self._route_family == RF_RTC_UC:
            next_hop = socket.inet_aton(self.next_hop)
        elif self._route_family == RF_IPv6_VPN:
            next_hop = '\0' * 8
            next_hop += socket.inet_pton(socket.AF_INET6, self.next_hop)
        else:
            next_hop = self.next_hop

        valueb = struct.pack('!HBB', afi, safi, len(next_hop))
        valueb += next_hop
        valueb += chr(self.reserved or 0)

        for n_nlri in self._nlri_list:
            valueb += n_nlri.encode()
        return valueb


@_register_path_attr
class MpUnreachNlri(RcgPathAttr):
    """MP_UNREACH_NLRI is a optional non-transitive bgp path-attribute.
    """
    __slots__ = ('_route_family', '_nlri_list')
    TYPE_CODE = 15
    ATTR_NAME = 'mp-unreach-nlri'
    NLRI = 'withdraw_nlri'
    # Higher order bits: 100 - optional, non-transitive, complete
    FLAGS = OPTIONAL_BGP_ATTR

    def __init__(self, route_family, nlri_list):
        if not (hasattr(route_family, 'afi') and
                hasattr(route_family, 'safi')):
            raise ValueError('Invalid parameter value for route_family %s' %
                             route_family)
        if not nlri_list:
            nlri_list = []

        RcgPathAttr.__init__(self)
        self._route_family = route_family
        self._nlri_list = nlri_list

    @property
    def nlri_list(self):
        return self._nlri_list[:]

    @property
    def route_family(self):
        return self._route_family

    def __repr__(self):
        return '<MpUneachNlri route_family=%r nlri_list=%r>' % (
            self._route_family, self._nlri_list)

    @classmethod
    def from_bytes(cls, val):
        """Decodes bgp path-attribute of type-code 15, i.e. MP_UNREACH_NLRI.
        """
        afi, safi = struct.unpack_from('!HB', val)
        route_family = get_rf(afi, safi)
        w_nlri = nlri.parse(val[3:], afi, safi)
        return cls(route_family, w_nlri)

    def packvalue(self):
        afi = self._route_family.afi
        safi = self._route_family.safi

        valueb = struct.pack('!HB', afi, safi)

        for w_nlri in self._nlri_list:
            valueb += w_nlri.encode()
        return valueb


@_register_path_attr
class Community(RcgPathAttr):
    """COMMUNITY is a optional transitive bgp path-attribute.
    """
    __slots__ = ('_attr_list')
    TYPE_CODE = 8
    ATTR_NAME = 'community'
    FLAGS = TRANSITIVE_BGP_ATTR | OPTIONAL_BGP_ATTR

    # String constants of well-known-communities
    NO_EXPORT = int('0xFFFFFF01', 16)
    NO_ADVERTISE = int('0xFFFFFF02', 16)
    NO_EXPORT_SUBCONFED = int('0xFFFFFF03', 16)
    WELL_KNOW_COMMUNITIES = (NO_EXPORT, NO_ADVERTISE, NO_EXPORT_SUBCONFED)

    def __init__(self, *attrs):
        if not attrs:
            raise ValueError('Invalid parameter for community attribute '
                             'list %r.' % attrs)
        self._attr_list = []
        for attr in attrs:
            if not isinstance(attr, int):
                raise ValueError('Invalid community attribute value %s.' %
                                 attr)
            self._attr_list.append(attr)

        RcgPathAttr.__init__(self)

    @property
    def attr_list(self):
        return self._attr_list[:]

    @classmethod
    def from_bytes(cls, val):
        """Decodes path attribute of type code 8, i.e. Community attribute.
        """
        att_list = []
        iidx = 0
        while iidx < len(val):
            comm_attr, = struct.unpack_from('!I', val, iidx)
            att_list.append(comm_attr)
            iidx += 4
        return cls(*att_list)

    def packvalue(self):
        commu_attr = ''
        for attr in self._attr_list:
            commu_attr += struct.pack('!I', int(attr))
        return commu_attr

    @staticmethod
    def is_no_export(comm_attr):
        """Returns True if given value matches well-known community NO_EXPORT
         attribute value.
         """
        return comm_attr == Community.NO_EXPORT

    @staticmethod
    def is_no_advertise(comm_attr):
        """Returns True if given value matches well-known community
        NO_ADVERTISE attribute value.
        """
        return comm_attr == Community.NO_ADVERTISE

    @staticmethod
    def is_no_export_subconfed(comm_attr):
        """Returns True if given value matches well-known community
         NO_EXPORT_SUBCONFED attribute value.
         """
        return comm_attr == Community.NO_EXPORT_SUBCONFED

    def has_comm_attr(self, attr):
        """Returns True if given community attribute is present."""

        for comm_attr in self._attr_list:
            if comm_attr == attr:
                return True

        return False

    def _community_repr(self, comm_attr):
        """Matches given value with all well-known community attribute values.

        Returns string representation of the well-known attribute if we
        have a match else returns given value.
        """

        if self.is_no_export(comm_attr):
            return 'NO_EXPORT'
        elif self.is_no_advertise(comm_attr):
            return 'NO_ADVERTISE'
        elif self.is_no_export_subconfed(comm_attr):
            return 'NO_EXPORT_SUBCONFED'
        return (str(comm_attr >> 16) + ':' +
                str(comm_attr & int('0x0000ffff', 16)))

    def __repr__(self):
        attr_list_repr = (','.join([self._community_repr(ca)
                                    for ca in self._attr_list]))
        return ('<Community([%s])>' % attr_list_repr)


@_register_path_attr
class ExtCommunity(RcgPathAttr):
    """EXTENDED COMMUNITIES is a optional and transitive bgp path-attribute.
    """
    __slots__ = ('_rt_list', '_soo_list', '_unknowns')
    TYPE_CODE = 16
    ATTR_NAME = 'extcommunity'
    RT = 'route_target'
    SOO = 'site_of_origin'
    UNKNOWN = 'unknown_community'
    # Higher order bits: 110 - optional, transitive, complete
    FLAGS = TRANSITIVE_BGP_ATTR | OPTIONAL_BGP_ATTR

    def __str__(self):
        return 'rt_list: {0}, soo_list: {1}'.format(
            self.rt_list,
            self.soo_list
        )

    def __init__(self, rt_list, soo_list, unknowns=None):
        if not rt_list and not soo_list:
            raise ValueError('Have to provide at-least one RT/SOO attribute.')
        if not rt_list:
            rt_list = []
        if not soo_list:
            soo_list = []
        if not unknowns:
            unknowns = {}

        ExtCommunity.validate_supported_attributes(rt_list)
        ExtCommunity.validate_supported_attributes(soo_list)

        RcgPathAttr.__init__(self)
        self._rt_list = list(rt_list)
        self._soo_list = list(soo_list)
        self._unknowns = unknowns

    @property
    def rt_list(self):
        """Returns a list of extracted/configured route target community."""
        # TODO(PH): Make sure we do not raise Exception here but return empty
        #  list instead.
        return self._rt_list[:]

    @property
    def soo_list(self):
        """Returns route origin community."""
        return self._soo_list[:]

    def __repr__(self):
        return '<%s type/num=%s/%s flags %s, rts: %s, soo: %s>' % (
            self.__class__.__name__, self.__class__.ATTR_NAME,
            self.__class__.TYPE_CODE,
            self.str_flags(), self.rt_list, self.soo_list)

    def has_unknown_communities(self):
        """Returns True if we have extracted/configured community other than
         route target or route origin community.
         """
        return True if self._unknowns else False

    @classmethod
    def validate_supported_attributes(cls, attr_list):
        """Validate *attr_list* has all valid RTs or SOO attribute
        representations.

        RTs and SOO are represented as string in following format:
        *global_admin_part:local_admin_part*
        """
        for attr in attr_list:
            if not validation.is_valid_ext_comm_attr(attr):
                raise ValueError('Attribute %s is not a valid RT/SOO' % attr)

    @classmethod
    def from_bytes(cls, val):
        """Decodes ext-community path-attribute.
        """
        rt_list = []
        soo_list = []
        unknowns = {}
        iidx = 0
        while iidx < len(val):
            etype, esubtype, payload = struct.unpack_from('BB6s', val, iidx)
            # RFC says: The value of the high-order octet of the Type field for
            # the Route Target Community can be 0x00, 0x01, or 0x02.  The value
            # of the low-order octet of the Type field for this community is
            # 0x02. TODO(PH): Remove this exception when it breaks something
            # Here we make exception as Routem packs lower-order octet as 0x00
            if etype in (0, 2) and esubtype in (0, 2):
                # If we have route target community in AS number format.
                asnum, i = struct.unpack('!HI', payload)
                rt_list.append('%s:%s' % (asnum, i))
            elif etype == 1 and esubtype == 2:
                # If we have route target community in IP address format.
                ip_addr, i = struct.unpack('!4sH', payload)
                ip_addr = socket.inet_ntoa(ip_addr)
                rt_list.append('%s:%s' % (ip_addr, i))
            elif etype in (0, 2) and esubtype == 3:
                # If we have route origin community in AS number format.
                asnum, nnum = struct.unpack('!HI', payload)
                soo_list.append('%s:%s' % (asnum, nnum))
            elif etype == 1 and esubtype == 3:
                # If we have route origin community in IP address format.
                ip_addr, nnum = struct.unpack('!4sH', payload)
                ip_addr = socket.inet_ntoa(ip_addr)
                soo_list.append('%s:%s' % (ip_addr, nnum))
            else:
                # All other communities, other than RT and SOO are unknown.
                unknown_list = unknowns.get(etype)
                if unknown_list is None:
                    unknown_list = []
                    unknowns[etype] = unknown_list
                unknown_list.append(
                    '%s:%s' % (etype, val[iidx + 1:iidx + 8].encode('hex'))
                )
            iidx += 8

        return cls(rt_list, soo_list, unknowns)

    def packvalue(self):
        excomb = ''
        # Pack route target community attrs.
        for route_target in self._rt_list:
            first, second = route_target.split(':')
            if '.' in first:
                ip_addr = socket.inet_aton(first)
                excomb += struct.pack('!BB4sH', 1, 2, ip_addr,
                                      int(second))
            else:
                excomb += struct.pack('!BBHI', 0, 2, int(first),
                                      int(second))
        # Pack route origin community attrs.
        for route_origin in self._soo_list:
            first, second = route_origin.split(':')
            if '.' in first:
                ip_addr = socket.inet_aton(first)
                excomb += struct.pack('!BB4sH', 1, 3, ip_addr,
                                      int(second))
            else:
                excomb += struct.pack('!BBHI', 0, 3, int(first),
                                      int(second))
        for type, attr_list in self._unknowns.items():
            # Pack all unknown ext. attrs.
            excomb += struct.pack('B', int(type))
            excomb += attr_list.decode('hex')
        return excomb
