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
This module provides BGP protocol capabilities classes and utility methods to
encode and decode them.
"""

from abc import ABCMeta
from abc import abstractmethod
import logging
import struct

from ryu.services.protocols.bgp.protocols.bgp.exceptions import \
    MalformedOptionalParam
from ryu.services.protocols.bgp.protocols.bgp.nlri import get_rf
from ryu.services.protocols.bgp.protocols.bgp.nlri import \
    RouteFamily as route_fmly


# Logger instance for this module
LOG = logging.getLogger('bgpspeaker.bgp.proto.capabilities')

# Registry for bgp capability class by their code.
# <Key>: <Value> - <capability-code>: <capability-class>
_BGP_CAPABILITY_REGISTRY = {}


def _register_bgp_capabilities(cls):
    """Utility decorator used to register bgp supported/recognized
    capabilities.

    Capabilities classes are registered by their capability-code.
    """
    assert issubclass(cls, Capability)
    assert hasattr(cls, 'CODE')
    assert _BGP_CAPABILITY_REGISTRY.get(cls.CODE) is None
    _BGP_CAPABILITY_REGISTRY[cls.CODE] = cls
    return cls


def is_recognized_cap_codes(cap_code):
    return cap_code in _BGP_CAPABILITY_REGISTRY


def decode(byte_value):
    """Decodes given `byte_value` into appropriate capabilities.

        Parameter:
            - `byte_value`: (str) byte representation of one capability
            advertisement
        Returns:
            - list of capabilities decoded from given bytes
        Note: Different routers pack capability in one capability
        advertisement/optional parameter or group them into several capability
        advertisements. Hence we return a list of one or more decoded
        capabilities.
    """
    idx = 0
    total_len = len(byte_value)
    caps = []
    # Parse one of more capabilities packed inside given capability-
    # advertisement payload
    while idx < total_len:
        cap_code, clen = struct.unpack_from('BB', byte_value, idx)
        idx += 2
        cap = byte_value[idx:idx + clen]
        idx += clen

        cap_cls = _BGP_CAPABILITY_REGISTRY.get(cap_code)
        if cap_cls:
            cap = cap_cls.from_bytes(cap)
            caps.append(cap)
        else:
            # RFC 5492 says: If a BGP speaker receives from its peer a
            # capability that it does not itself support or recognize, it MUST
            # ignore that capability.  In particular, the Unsupported
            # Capability NOTIFICATION message MUST NOT be generated and the BGP
            # session MUST NOT be terminated in  response to reception of a
            # capability that is not supported by the local speaker.
            cap = UnSupportedCap(cap_code, cap)

    return caps


class Capability(object):
    """Super class of all bgp capability optional parameters.
    """
    __metaclass__ = ABCMeta
    CODE = -1
    NAME = 'abstract-cap'

    @abstractmethod
    def packvalue(self):
        """Encode this bgp capability."""
        raise NotImplementedError()

    def encode(self):
        """Encodes this bgp capability with header and body."""
        body = self.packvalue()
        return struct.pack('BB', self.__class__.CODE, len(body)) + body

    def __repr__(self):
        return '<%s>' % self.__class__.NAME


class UnSupportedCap(Capability):
    """Represents unknown capability.

    According to RFC 5492 it is recommended to that we do not sent NOTIFICATION
    message for "Unsupported Capability".
    """
    NAME = 'unsupported-cap'

    def __init__(self, code, value):
        self.CODE = code
        self._value = value

    def packvalue(self):
        return self._value

    def __repr__(self):
        return '<UnSupportedCap(code=%s)>' % self.CODE


@_register_bgp_capabilities
class MultiprotocolExtentionCap(Capability):
    """This class represents bgp multi-protocol extension capability.
    """
    CODE = 1
    NAME = 'mbgp'

    def __init__(self, route_family):
        if not route_fmly.is_valid(route_family):
            raise ValueError('Invalid argument %s' % route_family)

        Capability.__init__(self)
        self.route_family = route_family

    def packvalue(self):
        return struct.pack('!HH', self.route_family.afi,
                           self.route_family.safi)

    @classmethod
    def from_bytes(cls, value):
        afi, _, safi = struct.unpack_from('!HBB', value)
        return cls(get_rf(afi, safi))

    def __repr__(self):
        return ('<MultiprotocolExtenstionCap(af=%s, saf=%s)>' %
                (self.route_family.afi, self.route_family.safi))

    def __eq__(self, other):
        if (other.__class__.CODE == self.__class__.CODE and
                other.route_family.afi == self.route_family.afi and
                other.route_family.safi == self.route_family.safi):
            return True
        return False


class ZeroLengthCap(Capability):
    """This is a super class represent all bgp capability with zero length."""
    CODE = -1
    NAME = 'zero-length'

    def packvalue(self):
        return ''

    @classmethod
    def from_bytes(cls, value):
        if len(value) > 0:
            LOG.error('Zero length capability has non-zero length value!')
            raise MalformedOptionalParam()
        return cls.get_singleton()

    @staticmethod
    def get_singleton():
        raise NotImplementedError()


@_register_bgp_capabilities
class RouteRefreshCap(ZeroLengthCap):
    CODE = 2
    NAME = 'route-refresh'

    def __str__(self):
        return RouteRefreshCap.NAME

    @staticmethod
    def get_singleton():
        return _ROUTE_REFRESH_CAP


@_register_bgp_capabilities
class OldRouteRefreshCap(ZeroLengthCap):
    CODE = 128
    NAME = 'old-route-refresh'

    def __str__(self):
        return OldRouteRefreshCap.NAME

    @staticmethod
    def get_singleton():
        return _OLD_ROUTE_REFRESH_CAP


# Since four byte as capability is not fully supported, we do not register it
# as supported/recognized capability.
@_register_bgp_capabilities
class GracefulRestartCap(Capability):
    CODE = 64
    NAME = 'graceful-restart'

    def __init__(self, value):
        # TODO(PH): Provide implementation
        Capability.__init__(self)
        self.value = value

    def packvalue(self):
        # TODO(PH): Provide implementation
        return self.value

    @classmethod
    def from_bytes(cls, value):
        return cls(value)


# Since four byte as capability is not fully supported, we do not register it
# as supported/recognized capability.
@_register_bgp_capabilities
class FourByteAsCap(Capability):
    CODE = 65
    NAME = '4byteas'

    def __init__(self, four_byte_as):
        Capability.__init__(self)
        self.four_byte_as = four_byte_as

    def packvalue(self):
        return struct.pack('!I', self.four_byte_as)

    @classmethod
    def from_bytes(cls, value):
        value, = struct.unpack('!I', value)
        return cls(value)

    def __repr__(self):
        return '<FourByteAsCap(%s)>' % self.four_byte_as

    def __eq__(self, other):
        if (other and other.four_byte_as == self.four_byte_as):
            return True
        return False


@_register_bgp_capabilities
class EnhancedRouteRefreshCap(ZeroLengthCap):
    CODE = 70
    NAME = 'enhanced-refresh'

    @staticmethod
    def get_singleton():
        return _ENHANCED_ROUTE_REFRESH_CAP

# Zero length capability singletons
_ROUTE_REFRESH_CAP = RouteRefreshCap()
_ENHANCED_ROUTE_REFRESH_CAP = EnhancedRouteRefreshCap()
_OLD_ROUTE_REFRESH_CAP = OldRouteRefreshCap()
