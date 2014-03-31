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
  Module related to BGP Network layer reachability information (NLRI).
"""

from abc import ABCMeta
import logging
import socket
import struct
from types import IntType

from ryu.services.protocols.bgp.protocols.bgp.exceptions import OptAttrError
from ryu.services.protocols.bgp.utils.other import bytes2hex
from ryu.services.protocols.bgp.utils.other import hex2byte
from ryu.services.protocols.bgp.utils.validation import is_valid_ext_comm_attr
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4_prefix
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv6_prefix
from ryu.services.protocols.bgp.utils.validation import is_valid_mpls_label
from ryu.services.protocols.bgp.utils.validation import is_valid_old_asn
from ryu.services.protocols.bgp.utils.validation import is_valid_route_disc


LOG = logging.getLogger('protocols.bgp.nlri')

# Registry for bgp message class by their type code.
# <key>: <value> - <afi, safi>: <nlri class>
_NLRI_REGISTRY = {}


def _register_nlri(cls):
    """Used as class decorator for registering NLRI classes by their afi/safi.
    """
    assert _NLRI_REGISTRY.get((cls.AFI, cls.SAFI)) is None
    _NLRI_REGISTRY[(cls.AFI, cls.SAFI)] = cls
    return cls


#
# AddressFamily
#
class AddressFamily(object):
    """Subclasses of this class hold methods for a specific AF and
    help the calling code to stay AF-independent.

    Each subclass need have just a singleton instance (see below).
    """

    def __init__(self, afi):
        self.afi = afi

    def __hash__(self):
        return hash(self.afi)

    def __cmp__(self, other):
        afi1 = None
        afi2 = None
        if isinstance(other, IntType):
            afi2 = other
        else:
            afi2 = other.afi
        if isinstance(self, IntType):
            afi1 = self
        else:
            afi1 = self.afi
        return cmp(afi1, afi2)


class AfiIpv4(AddressFamily):
    def __init__(self):
        super(AfiIpv4, self).__init__(1)

    def __repr__(self):
        return "IPv4"


class AfiIpv6(AddressFamily):
    def __init__(self):
        super(AfiIpv6, self).__init__(2)

    def __repr__(self):
        return "IPv6"


#
# SubAddressFamily
#
# An sub-address family as defined by BGP.
#
class SubAddressFamily(object):

    def __init__(self, safi):
        self.safi = safi

    def __hash__(self):
        return hash(self.safi)

    def __cmp__(self, other):
        safi1 = None
        safi2 = None
        if isinstance(self, IntType):
            safi1 = self
        else:
            safi1 = self.safi
        if isinstance(other, IntType):
            safi2 = other
        else:
            safi2 = other.safi
        return cmp(safi1, safi2)


class SafiNlriUnicast(SubAddressFamily):
    def __init__(self):
        super(SafiNlriUnicast, self).__init__(1)

    def __repr__(self):
        return "SafiNlriUnicast"


class SafiVpn(SubAddressFamily):
    def __init__(self):
        super(SafiVpn, self).__init__(128)

    def __repr__(self):
        return "SafiVpn"


class SafiRtc(SubAddressFamily):
    def __init__(self):
        super(SafiRtc, self).__init__(132)

    def __repr__(self):
        return "SafiRtc"

NLRI_UC = SafiNlriUnicast()
SAF_VPN = SafiVpn()
SAF_RTC = SafiRtc()

# Singleton objects for each AF.
AF_IPv4 = AfiIpv4()
AF_IPv6 = AfiIpv6()

# Constants to represent address family and sub-address family.
ADD_FMLY = 'afi'
SUB_ADD_FMLY = 'safi'


#
# RouteFamily
#
class RouteFamily(object):
    """The family that a given route (or Network Layer Reachability
    Information) belongs to.

    Basically represents a combination of AFI/SAFI.
    """
    __slots__ = ('_add_fmly', '_sub_add_fmly')

    def __init__(self, add_fmly, sub_add_fmly):
        # Validate i/p.
        if not add_fmly or not sub_add_fmly:
            raise ValueError('Invalid arguments.')

        self._add_fmly = add_fmly
        self._sub_add_fmly = sub_add_fmly

    @property
    def afi(self):
        return self._add_fmly.afi

    @property
    def safi(self):
        return self._sub_add_fmly.safi

    def __repr__(self):
        return ('RouteFamily(afi=%s, safi=%s)' % (self.afi, self.safi))

    def __cmp__(self, other):
        other_rf = (other.afi, other.safi)
        self_rf = (self.afi, self.safi)
        return cmp(self_rf, other_rf)

    @staticmethod
    def is_valid(other):
        if other and (hasattr(other, 'afi') and hasattr(other, 'safi')):
            return True
        return False

# Various route family singletons.
RF_IPv4_UC = RouteFamily(AF_IPv4, NLRI_UC)
RF_IPv6_UC = RouteFamily(AF_IPv6, NLRI_UC)
RF_IPv4_VPN = RouteFamily(AF_IPv4, SAF_VPN)
RF_IPv6_VPN = RouteFamily(AF_IPv6, SAF_VPN)
RF_RTC_UC = RouteFamily(AF_IPv4, SAF_RTC)

_rf_by_afi_safi = {
    (1, 1): RF_IPv4_UC,
    (2, 1): RF_IPv6_UC,
    (1, 128): RF_IPv4_VPN,
    (2, 128): RF_IPv6_VPN,
    (1, 132): RF_RTC_UC
}


def get_rf(afi, safi):
    """Returns *RouteFamily* singleton instance for given *afi* and *safi*."""
    if not isinstance(afi, IntType):
        afi = int(afi)
    if not isinstance(safi, IntType):
        safi = int(safi)
    return _rf_by_afi_safi.get((afi, safi))


# TODO(PH): Consider trade-offs of making this extend Internable.
class Nlri(object):
    """Represents super class of all Network Layer Reachability Information.
    """
    __meta__ = ABCMeta
    __slots__ = ()

    # Sub-classes should set afi/safi constants appropriately.
    AFI = 0
    SAFI = 0

    @classmethod
    def encode(self):
        raise NotImplementedError()

    @property
    def route_family(self):
        return get_rf(self.__class__.AFI, self.__class__.SAFI)


@_register_nlri
class Vpnv4(Nlri):
    """Vpnv4 NLRI.
    """
    __slots__ = ('_labels', '_route_disc', '_prefix')

    AFI = 1
    SAFI = 128

    def __init__(self, labels, route_disc, prefix):
        Nlri.__init__(self)
        if not labels:
            labels = []

        # Validate given params
        for label in labels:
            if not is_valid_mpls_label(label):
                raise ValueError('Invalid label %s' % label)
        if (not is_valid_ipv4_prefix(prefix) or
                not is_valid_route_disc(route_disc)):
            raise ValueError('Invalid parameter value(s).')

        self._labels = labels
        self._route_disc = route_disc
        self._prefix = prefix

    @property
    def label_list(self):
        return self._labels[:]

    @property
    def route_disc(self):
        return self._route_disc

    @property
    def prefix(self):
        return self._prefix

    @property
    def formatted_nlri_str(self):
        return "%s:%s" % (self._route_disc, self.prefix)

    def __repr__(self):
        if self._labels:
            l = ','.join([str(l) for l in self._labels])
        else:
            l = 'none'

        return ('Vpnv4(label=%s, route_disc=%s, prefix=%s)' %
                (l, self.route_disc, self.prefix))

    def __str__(self):
        return 'Vpnv4 %s:%s, %s' % (self.route_disc, self.prefix, self._labels)

    def __cmp__(self, other):
        return cmp(
            (self._labels, self.route_disc, self.prefix),
            (other.label_list, other.route_disc, other.prefix),
        )

    def encode(self):
        plen = 0
        v = ''
        labels = self._labels[:]

        if not labels:
            return '\0'

        labels = [l << 4 for l in labels]
        labels[-1] |= 1

        for l in labels:
            lo = l & 0xff
            hi = (l & 0xffff00) >> 8
            v += struct.pack('>HB', hi, lo)
            plen += 24

        l, r = self.route_disc.split(':')
        if '.' in l:
            ip = socket.inet_aton(l)
            route_disc = struct.pack('!H4sH', 1, ip, int(r))
        else:
            route_disc = struct.pack('!HHI', 0, int(l), int(r))

        v += route_disc
        plen += 64

        ip, masklen = self.prefix.split('/')
        ip = socket.inet_aton(ip)
        masklen = int(masklen)

        plen += masklen
        if masklen > 24:
            v += ip
        elif masklen > 16:
            v += ip[:3]
        elif masklen > 8:
            v += ip[:2]
        elif masklen > 0:
            v += ip[:1]
        else:
            pass

        return struct.pack('B', plen) + v

    @classmethod
    def from_bytes(cls, plen, val):

        if plen == 0:
            # TODO(PH): Confirm this is valid case and implementation.
            return cls([], '0:0', '0.0.0.0/0')

        idx = 0

        # plen is the length, in bits, of all the MPLS labels,
        # plus the 8-byte RD, plus the IP prefix
        labels = []
        while True:
            ls, = struct.unpack_from('3s', val, idx)
            idx += 3
            plen -= 24

            if ls == '\x80\x00\x00':
                # special null label for vpnv4 withdraws
                labels = None
                break

            label, = struct.unpack_from('!I', '\x00' + ls)
            bottom = label & 1

            labels.append(label >> 4)
            if bottom:
                break
            # TODO(PH): We are breaking after first label as we support only
            # one label for now. Revisit if we need to support stack of labels.
            break

        rdtype, route_disc = struct.unpack_from('!H6s', val, idx)
        if rdtype == 1:
            rdip, num = struct.unpack('!4sH', route_disc)
            rdip = socket.inet_ntoa(rdip)
            route_disc = '%s:%s' % (rdip, num)
        else:
            num1, num2 = struct.unpack('!HI', route_disc)
            route_disc = '%s:%s' % (num1, num2)

        idx += 8
        plen -= 64

        ipl = pb(plen)
        ip = val[idx:idx + ipl]
        idx += ipl

        prefix = unpack_ipv4(ip, plen)

        return cls(labels, route_disc, prefix)


@_register_nlri
class Vpnv6(Nlri):
    """Vpnv4 NLRI.
    """
    __slots__ = ('_labels', '_route_disc', '_prefix')

    AFI = 2
    SAFI = 128

    def __init__(self, labels, route_disc, prefix):
        Nlri.__init__(self)
        if not labels:
            labels = []

        # Validate given params
        for label in labels:
            if not is_valid_mpls_label(label):
                raise ValueError('Invalid label %s' % label)
        if (not is_valid_route_disc(route_disc) or
                not is_valid_ipv6_prefix(prefix)):
            raise ValueError('Invalid parameter value(s).')

        self._labels = labels
        self._route_disc = route_disc
        self._prefix = prefix

    @property
    def label_list(self):
        return self._labels[:]

    @property
    def route_disc(self):
        return self._route_disc

    @property
    def prefix(self):
        return self._prefix

    @property
    def formatted_nlri_str(self):
        return "%s:%s" % (self._route_disc, self.prefix)

    def __repr__(self):
        if self._labels:
            l = ','.join([str(l) for l in self._labels])
        else:
            l = 'none'

        return ('Vpnv6(label=%s, route_disc=%s, prefix=%s)' %
                (l, self.route_disc, self.prefix))

    def __str__(self):
        return 'Vpnv6 %s:%s, %s' % (self.route_disc, self.prefix, self._labels)

    def __cmp__(self, other):
        return cmp(
            (self._labels, self.route_disc, Ipv6(self.prefix).encode()),
            (other.label_list, other.route_disc, Ipv6(other.prefix).encode()),
        )

    def encode(self):
        plen = 0
        v = ''
        labels = self._labels[:]

        if not labels:
            return '\0'

        labels = [l << 4 for l in labels]
        labels[-1] |= 1

        for l in labels:
            lo = l & 0xff
            hi = (l & 0xffff00) >> 8
            v += struct.pack('>HB', hi, lo)
            plen += 24

        l, r = self.route_disc.split(':')
        if '.' in l:
            ip = socket.inet_aton(l)
            route_disc = struct.pack('!H4sH', 1, ip, int(r))
        else:
            route_disc = struct.pack('!HHI', 0, int(l), int(r))
        v += route_disc
        plen += 64

        ip, masklen = self.prefix.split('/')
        ip = socket.inet_pton(socket.AF_INET6, ip)
        masklen = int(masklen)

        plen += masklen
        v += ip[:pb6(masklen)]

        return struct.pack('B', plen) + v

    @classmethod
    def from_bytes(cls, plen, val):
        if plen == 0:
            # TODO(PH): Confirm this is valid case and implementation.
            return cls([], '0:0', '::/0')

        idx = 0

        # plen is the length, in bits, of all the MPLS labels,
        # plus the 8-byte RD, plus the IP prefix
        labels = []
        while True:
            ls, = struct.unpack_from('3s', val, idx)
            idx += 3
            plen -= 24

            if ls == '\x80\x00\x00':
                # special null label for vpnv4 withdraws
                labels = None
                break

            label, = struct.unpack_from('!I', '\x00' + ls)
            bottom = label & 1

            labels.append(label >> 4)
            if bottom:
                break
            # TODO(PH): We are breaking after first label as we support only
            # one label for now. Revisit if we need to support stack of labels.
            break

        rdtype, route_disc = struct.unpack_from('!H6s', val, idx)
        if rdtype == 1:
            rdip, num = struct.unpack('!4sH', route_disc)
            rdip = socket.inet_ntoa(rdip)
            route_disc = '%s:%s' % (rdip, num)
        else:
            num1, num2 = struct.unpack('!HI', route_disc)
            route_disc = '%s:%s' % (num1, num2)

        idx += 8
        plen -= 64

        ipl = pb6(plen)
        ip = val[idx:idx + ipl]
        idx += ipl

        prefix = unpack_ipv6(ip, plen)

        return cls(labels, route_disc, prefix)


@_register_nlri
class Ipv4(Nlri):
    __slots__ = ('_prefix')

    AFI = 1
    SAFI = 1

    def __init__(self, prefix):
        if not is_valid_ipv4_prefix(prefix):
            raise ValueError('Invalid prefix %s.' % prefix)
        Nlri.__init__(self)
        self._prefix = prefix

    @property
    def prefix(self):
        return self._prefix

    @property
    def formatted_nlri_str(self):
        return self._prefix

    def __cmp__(self, other):
        aip, alen = self.prefix.split('/')
        alen = int(alen)
        aip = socket.inet_aton(aip)

        bip, blen = other.prefix.split('/')
        blen = int(blen)
        bip = socket.inet_aton(bip)

        return cmp((aip, alen), (bip, blen))

    def encode(self):
        plen = 0
        v = ''

        ip, masklen = self.prefix.split('/')
        ip = socket.inet_aton(ip)
        masklen = int(masklen)

        plen += masklen
        if masklen > 24:
            v += ip
        elif masklen > 16:
            v += ip[:3]
        elif masklen > 8:
            v += ip[:2]
        elif masklen > 0:
            v += ip[:1]
        else:
            pass

        return struct.pack('B', plen) + v

    def __repr__(self):
        return 'Ipv4(%s)' % (self.prefix)

    def __str__(self):
        return 'Ipv4 ' + self.prefix

    @classmethod
    def from_bytes(cls, plen, val):
        return cls(unpack_ipv4(val, plen))


@_register_nlri
class Ipv6(Nlri):
    __slots__ = ('_prefix')

    AFI = 2
    SAFI = 1

    def __init__(self, prefix):
        if not is_valid_ipv6_prefix(prefix):
            raise ValueError('Invalid prefix %s.' % prefix)
        Nlri.__init__(self)
        self._prefix = prefix

    @property
    def prefix(self):
        return self._prefix

    @property
    def formatted_nlri_str(self):
        return self._prefix

    def __cmp__(self, other):
        abin = self.encode()
        bbin = other.encode()
        return cmp(abin, bbin)

    def encode(self):
        plen = 0
        v = ''

        ip, masklen = self.prefix.split('/')
        ip = socket.inet_pton(socket.AF_INET6, ip)
        masklen = int(masklen)

        plen += masklen
        ip_slice = pb6(masklen)
        v += ip[:ip_slice]

        return struct.pack('B', plen) + v

    def __repr__(self):
        return 'Ipv6(%s)' % (self.prefix)

    def __str__(self):
        return 'Ipv6 ' + self.prefix

    @classmethod
    def from_bytes(cls, plen, val):
        return cls(unpack_ipv6(val, plen))


@_register_nlri
class RtNlri(Nlri):
    """Route Target Membership NLRI.

    Route Target membership NLRI is advertised in BGP UPDATE messages using
    the MP_REACH_NLRI and MP_UNREACH_NLRI attributes.
    """
    __slots__ = ('_origin_as', '_route_target')

    AFI = 1
    SAFI = 132
    DEFAULT_AS = '0:0'
    DEFAULT_RT = '0:0'

    def __init__(self, origin_as, route_target):
        Nlri.__init__(self)
        # If given is not default_as and default_rt
        if not (origin_as is RtNlri.DEFAULT_AS and
                route_target is RtNlri.DEFAULT_RT):
            # We validate them
            if (not is_valid_old_asn(origin_as) or
                    not is_valid_ext_comm_attr(route_target)):
                raise ValueError('Invalid params.')
        self._origin_as = origin_as
        self._route_target = route_target

    @property
    def origin_as(self):
        return self._origin_as

    @property
    def route_target(self):
        return self._route_target

    @property
    def formatted_nlri_str(self):
        return "%s:%s" % (self.origin_as, self.route_target)

    def is_default_rtnlri(self):
        if (self._origin_as is RtNlri.DEFAULT_AS and
                self._route_target is RtNlri.DEFAULT_RT):
            return True
        return False

    def __str__(self):
        return 'RtNlri ' + str(self._origin_as) + ':' + self._route_target

    def __repr__(self):
        return 'RtNlri(%s, %s)' % (self._origin_as, self._route_target)

    def __cmp__(self, other):
        return cmp(
            (self._origin_as, self._route_target),
            (other.origin_as, other.route_target),
        )

    @classmethod
    def from_bytes(cls, plen, val):
        idx = 0
        if plen == 0 and not val:
            return cls(RtNlri.DEFAULT_AS, RtNlri.DEFAULT_RT)

        # Extract origin AS.
        origin_as, = struct.unpack_from('!I', val, idx)
        idx += 4

        # Extract route target.
        route_target = ''
        etype, esubtype, payload = struct.unpack_from('BB6s', val, idx)
        # RFC says: The value of the high-order octet of the Type field for the
        # Route Target Community can be 0x00, 0x01, or 0x02.  The value of the
        # low-order octet of the Type field for this community is 0x02.
        # TODO(PH): Remove this exception when it breaks something Here we make
        # exception as Routem packs lower-order octet as 0x00
        if etype in (0, 2) and esubtype in (0, 2):
            # If we have route target community in AS number format.
            asnum, i = struct.unpack('!HI', payload)
            route_target = ('%s:%s' % (asnum, i))
        elif etype == 1 and esubtype == 2:
            # If we have route target community in IP address format.
            ip_addr, i = struct.unpack('!4sH', payload)
            ip_addr = socket.inet_ntoa(ip_addr)
            route_target = ('%s:%s' % (ip_addr, i))
        elif etype == 0 and esubtype == 1:
            # TODO(PH): Parsing of RtNlri 1:1:100:1
            asnum, i = struct.unpack('!HI', payload)
            route_target = ('%s:%s' % (asnum, i))

        return cls(origin_as, route_target)

    def encode(self):
        rt_nlri = ''
        if not self.is_default_rtnlri():
            rt_nlri += struct.pack('!I', self.origin_as)
            # Encode route target
            first, second = self.route_target.split(':')
            if '.' in first:
                ip_addr = socket.inet_aton(first)
                rt_nlri += struct.pack('!BB4sH', 1, 2, ip_addr, int(second))
            else:
                rt_nlri += struct.pack('!BBHI', 0, 2, int(first), int(second))

        # RT Nlri is 12 octets
        return struct.pack('B', (8 * 12)) + rt_nlri


def pb(masklen):
    if masklen > 24:
        return 4
    elif masklen > 16:
        return 3
    elif masklen > 8:
        return 2
    elif masklen > 0:
        return 1
    return 0

_v6_bits = range(120, -8, -8)
_v6_bytes = [i / 8 for i in range(128, 0, -8)]


def pb6(masklen):
    for idx, bits in enumerate(_v6_bits):
        if masklen > bits:
            return _v6_bytes[idx]
    return 0


def unpack_ipv4(pi, masklen):
    pi += '\x00' * 4
    return '%s/%s' % (socket.inet_ntoa(pi[:4]), masklen)


def unpack_ipv6(pi, masklen):
    pi += '\x00' * 16
    ip = socket.inet_ntop(socket.AF_INET6, pi[:16])
    return '%s/%s' % (ip, masklen)


def ipv4_mapped_ipv6(ipv4):
    if not is_valid_ipv4(ipv4):
        raise ValueError('Invalid ipv4 address given %s.' % ipv4)
    ipv4n = socket.inet_pton(socket.AF_INET, ipv4)
    ipv6_hex = '00' * 10 + 'ff' * 2 + bytes2hex(ipv4n)
    ipv6n = hex2byte(ipv6_hex)
    ipv6 = socket.inet_ntop(socket.AF_INET6, ipv6n)
    return ipv6


# TODO(PH): Consider refactoring common functionality new methods
# Look at previous commit
def parse(received, afi=1, safi=1):
    recv_nlri_list = []

    klass = _NLRI_REGISTRY.get((afi, safi))
    if not klass:
        raise ValueError('Asked to parse unsupported NLRI afi/safi: '
                         '(%s, %s)' % (afi, safi))

    try:
        idx = 0
        while idx < len(received):
            plen, = struct.unpack_from('B', received, idx)
            idx += 1
            nbytes, rest = divmod(plen, 8)
            if rest:
                nbytes += 1
            val = received[idx:idx + nbytes]
            idx += nbytes
            recv_nlri_list.append(klass.from_bytes(plen, val))
    except Exception:
        raise OptAttrError()

    return recv_nlri_list
