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

import struct
from . import packet_base
from ryu.lib import addrconv

# Slow Protocol Multicast destination
SLOW_PROTOCOL_MULTICAST = '01:80:c2:00:00:02'

# Slow Protocol SubType
SLOW_SUBTYPE_LACP = 0x01
SLOW_SUBTYPE_MARKER = 0x02
SLOW_SUBTYPE_OAM = 0x03
SLOW_SUBTYPE_OSSP = 0x0a


class slow(packet_base.PacketBase):
    """Slow Protocol header decoder class.
    This class has only the parser method.

    http://standards.ieee.org/getieee802/download/802.3-2012_section5.pdf

    Slow Protocols Subtypes

    +---------------+--------------------------------------------------+
    | Subtype Value | Protocol Name                                    |
    +===============+==================================================+
    | 0             | Unused - Illegal Value                           |
    +---------------+--------------------------------------------------+
    | 1             | Link Aggregation Control Protocol(LACP)          |
    +---------------+--------------------------------------------------+
    | 2             | Link Aggregation - Marker Protocol               |
    +---------------+--------------------------------------------------+
    | 3             | Operations, Administration, and Maintenance(OAM) |
    +---------------+--------------------------------------------------+
    | 4 - 9         | Reserved for future use                          |
    +---------------+--------------------------------------------------+
    | 10            | Organization Specific Slow Protocol(OSSP)        |
    +---------------+--------------------------------------------------+
    | 11 - 255      | Unused - Illegal values                          |
    +---------------+--------------------------------------------------+
    """
    _PACK_STR = '!B'

    @classmethod
    def parser(cls, buf):
        (subtype, ) = struct.unpack_from(cls._PACK_STR, buf)
        switch = {
            SLOW_SUBTYPE_LACP: lacp,
            # TODO: make parsers of other subtypes.
            SLOW_SUBTYPE_MARKER: None,
            SLOW_SUBTYPE_OAM: None,
            SLOW_SUBTYPE_OSSP: None,
        }
        cls_ = switch.get(subtype)
        if cls_:
            return cls_.parser(buf)
        else:
            return None, None, buf


class lacp(packet_base.PacketBase):
    """Link Aggregation Control Protocol(LACP, IEEE 802.1AX)
    header encoder/decoder class.

    http://standards.ieee.org/getieee802/download/802.1AX-2008.pdf

    LACPDU format

    +------------------------------------------------+--------+
    | LACPDU structure                               | Octets |
    +================================================+========+
    | Subtype = LACP                                 | 1      |
    +------------------------------------------------+--------+
    | Version Number                                 | 1      |
    +------------+-----------------------------------+--------+
    | TLV        | TLV_type = Actor Information      | 1      |
    | Actor      |                                   |        |
    +------------+-----------------------------------+--------+
    |            | Actor_Information_Length = 20     | 1      |
    +------------+-----------------------------------+--------+
    |            | Actor_System_Priority             | 2      |
    +------------+-----------------------------------+--------+
    |            | Actor_System                      | 6      |
    +------------+-----------------------------------+--------+
    |            | Actor_Key                         | 2      |
    +------------+-----------------------------------+--------+
    |            | Actor_Port_Priority               | 2      |
    +------------+-----------------------------------+--------+
    |            | Actor_Port                        | 2      |
    +------------+-----------------------------------+--------+
    |            | Actor_State                       | 1      |
    +------------+-----------------------------------+--------+
    |            | Reserved                          | 3      |
    +------------+-----------------------------------+--------+
    | TLV        | TLV_type = Partner Information    | 1      |
    | Partner    |                                   |        |
    +------------+-----------------------------------+--------+
    |            | Partner_Information_Length = 20   | 1      |
    +------------+-----------------------------------+--------+
    |            | Partner_System_Priority           | 2      |
    +------------+-----------------------------------+--------+
    |            | Partner_System                    | 6      |
    +------------+-----------------------------------+--------+
    |            | Partner_Key                       | 2      |
    +------------+-----------------------------------+--------+
    |            | Partner_Port_Priority             | 2      |
    +------------+-----------------------------------+--------+
    |            | Partner_Port                      | 2      |
    +------------+-----------------------------------+--------+
    |            | Partner_State                     | 1      |
    +------------+-----------------------------------+--------+
    |            | Reserved                          | 3      |
    +------------+-----------------------------------+--------+
    | TLV        | TLV_type = Collector Information  | 1      |
    | Collector  |                                   |        |
    +------------+-----------------------------------+--------+
    |            | Collector_Information_Length = 16 | 1      |
    +------------+-----------------------------------+--------+
    |            | Collector_Max_Delay               | 2      |
    +------------+-----------------------------------+--------+
    |            | Reserved                          | 12     |
    +------------+-----------------------------------+--------+
    | TLV        | TLV_type = Terminator             | 1      |
    | Terminator |                                   |        |
    +------------+-----------------------------------+--------+
    |            | Terminator_Length = 0             | 1      |
    +------------+-----------------------------------+--------+
    |            | Reserved                          | 50     |
    +------------+-----------------------------------+--------+


    Terminator information uses a length value of 0 (0x00).

    NOTE--The use of a Terminator_Length of 0 is intentional.
          In TLV encoding schemes it is common practice
          for the terminator encoding to be 0 both
          for the type and the length.

    Actor_State and Partner_State encoded as individual bits within
    a single octet as follows:

    +------+------+------+------+------+------+------+------+
    | 7    | 6    | 5    | 4    | 3    | 2    | 1    | 0    |
    +======+======+======+======+======+======+======+======+
    | EXPR | DFLT | DIST | CLCT | SYNC | AGGR | TMO  | ACT  |
    +------+------+------+------+------+------+------+------+

    ACT
        bit 0.
        about the activity control value with regard to this link.
    TMO
        bit 1.
        about the timeout control value with regard to this link.
    AGGR
        bit 2.
        about how the system regards this link from the point of view
        of the aggregation.
    SYNC
        bit 3.
        about how the system regards this link from the point of view
        of the synchronization.
    CLCT
        bit 4.
        about collecting of incoming frames.
    DIST
        bit 5.
        about distributing of outgoing frames.
    DFLT
        bit 6.
        about the opposite system information which the system use.
    EXPR
        bit 7.
        about the expire state of the system.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte
    order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============================== ====================================
    Attribute                       Description
    =============================== ====================================
    version                         LACP version. This parameter must be
                                    set to LACP_VERSION_NUMBER(i.e. 1).

    actor_system_priority           The priority assigned to this
                                    System.

    actor_system                    The Actor's System ID, encoded as
                                    a MAC address.

    actor_key                       The operational Key value assigned
                                    to the port by the Actor.

    actor_port_priority             The priority assigned to this port.

    actor_port                      The port number assigned to the
                                    port by the Actor.

    actor_state_activity            .. _lacp_activity:

                                    about the activity control value
                                    with regard to this link.

                                    LACP_STATE_ACTIVE(1)

                                    LACP_STATE_PASSIVE(0)

    actor_state_timeout             .. _lacp_timeout:

                                    about the timeout control value
                                    with regard to this link.

                                    LACP_STATE_SHORT_TIMEOUT(1)

                                    LACP_STATE_LONG_TIMEOUT(0)

    actor_state_aggregation         .. _lacp_aggregation:

                                    about how the system regards this
                                    link from the point of view of the
                                    aggregation.

                                    LACP_STATE_AGGREGATEABLE(1)

                                    LACP_STATE_INDIVIDUAL(0)

    actor_state_synchronization     .. _lacp_synchronization:

                                    about how the system regards this
                                    link from the point of view of the
                                    synchronization.

                                    LACP_STATE_IN_SYNC(1)

                                    LACP_STATE_OUT_OF_SYNC(0)

    actor_state_collecting          .. _lacp_collecting:

                                    about collecting of incoming frames.

                                    LACP_STATE_COLLECTING_ENABLED(1)

                                    LACP_STATE_COLLECTING_DISABLED(0)

    actor_state_distributing        .. _lacp_distributing:

                                    about distributing of outgoing frames.

                                    LACP_STATE_DISTRIBUTING_ENABLED(1)

                                    LACP_STATE_DISTRIBUTING_DISABLED(0)

    actor_state_defaulted           .. _lacp_defaulted:

                                    about the Partner information
                                    which the the Actor use.

                                    LACP_STATE_DEFAULTED_PARTNER(1)

                                    LACP_STATE_OPERATIONAL_PARTNER(0)

    actor_state_expired             .. _lacp_expired:

                                    about the state of the Actor.

                                    LACP_STATE_EXPIRED(1)

                                    LACP_STATE_NOT_EXPIRED(0)

    partner_system_priority         The priority assigned to the
                                    Partner System.

    partner_system                  The Partner's System ID, encoded
                                    as a MAC address.

    partner_key                     The operational Key value assigned
                                    to the port by the Partner.

    partner_port_priority           The priority assigned to this port
                                    by the Partner.

    partner_port                    The port number assigned to the
                                    port by the Partner.

    partner_state_activity          See :ref:`actor_state_activity\
                                    <lacp_activity>`.

    partner_state_timeout           See :ref:`actor_state_timeout\
                                    <lacp_timeout>`.

    partner_state_aggregation       See :ref:`actor_state_aggregation\
                                    <lacp_aggregation>`.

    partner_state_synchronization   See
                                    :ref:`actor_state_synchronization\
                                    <lacp_synchronization>`.

    partner_state_collecting        See :ref:`actor_state_collecting\
                                    <lacp_collecting>`.

    partner_state_distributing      See :ref:`actor_state_distributing\
                                    <lacp_distributing>`.

    partner_state_defaulted         See :ref:`actor_state_defaulted\
                                    <lacp_defaulted>`.

    partner_state_expired           See :ref:`actor_state_expired\
                                    <lacp_expired>`.

    collector_max_delay             the maximum time that the Frame
                                    Collector may delay.
    =============================== ====================================

    """
    LACP_VERSION_NUMBER = 1

    # LACP TLV type
    LACP_TLV_TYPE_ACTOR = 1
    LACP_TLV_TYPE_PARTNER = 2
    LACP_TLV_TYPE_COLLECTOR = 3
    LACP_TLV_TYPE_TERMINATOR = 0

    # LACP state(LACP_Activity)
    LACP_STATE_ACTIVE = 1
    LACP_STATE_PASSIVE = 0
    # LACP state(LACP_Timeout)
    LACP_STATE_SHORT_TIMEOUT = 1
    LACP_STATE_LONG_TIMEOUT = 0
    # LACP state(Aggregation)
    LACP_STATE_AGGREGATEABLE = 1
    LACP_STATE_INDIVIDUAL = 0
    # LACP state(Synchronization)
    LACP_STATE_IN_SYNC = 1
    LACP_STATE_OUT_OF_SYNC = 0
    # LACP state(Collecting)
    LACP_STATE_COLLECTING_ENABLED = 1
    LACP_STATE_COLELCTING_DISABLED = 0
    # LACP state(Distributing)
    LACP_STATE_DISTRIBUTING_ENABLED = 1
    LACP_STATE_DISTRIBUTING_DISABLED = 0
    # LACP state(Defaulted)
    LACP_STATE_DEFAULED_PARTNER = 1
    LACP_STATE_OPERATIONAL_PARTNER = 0
    # LACP state(Expired)
    LACP_STATE_EXPIRED = 1
    LACP_STATE_NOT_EXPIRED = 0

    # The number of seconds between periodic transmissions using
    # Short Timeouts.
    FAST_PERIODIC_TIME = 1
    # The number of seconds between periodic transmissions using
    # Long Timeouts.
    SLOW_PERIODIC_TIME = 30
    # The number of seconds before invalidating received LACPDU
    # information when using Short Timeouts(3 x Fast_Periodic_Time).
    SHORT_TIMEOUT_TIME = 3 * FAST_PERIODIC_TIME
    # The number of seconds before invalidating received LACPDU
    # information when using Long Timeouts (3 x Slow_Periodic_Time).
    LONG_TIMEOUT_TIME = 3 * SLOW_PERIODIC_TIME

    _HLEN_PACK_STR = '!BB'
    _HLEN_PACK_LEN = struct.calcsize(_HLEN_PACK_STR)
    _ACTPRT_INFO_PACK_STR = '!BBH6sHHHB3x'
    _ACTPRT_INFO_PACK_LEN = struct.calcsize(_ACTPRT_INFO_PACK_STR)
    _COL_INFO_PACK_STR = '!BBH12x'
    _COL_INFO_PACK_LEN = struct.calcsize(_COL_INFO_PACK_STR)
    _TRM_PACK_STR = '!BB50x'
    _TRM_PACK_LEN = struct.calcsize(_TRM_PACK_STR)
    _ALL_PACK_LEN = _HLEN_PACK_LEN + _ACTPRT_INFO_PACK_LEN * 2 + \
        _COL_INFO_PACK_LEN + _TRM_PACK_LEN

    _MIN_LEN = _ALL_PACK_LEN

    _TYPE = {
        'ascii': [
            'actor_system', 'partner_system'
        ]
    }

    def __init__(self, version=LACP_VERSION_NUMBER,
                 actor_system_priority=0,
                 actor_system='00:00:00:00:00:00',
                 actor_key=0, actor_port_priority=0, actor_port=0,
                 actor_state_activity=0, actor_state_timeout=0,
                 actor_state_aggregation=0,
                 actor_state_synchronization=0,
                 actor_state_collecting=0, actor_state_distributing=0,
                 actor_state_defaulted=0, actor_state_expired=0,
                 partner_system_priority=0,
                 partner_system='00:00:00:00:00:00',
                 partner_key=0, partner_port_priority=0, partner_port=0,
                 partner_state_activity=0, partner_state_timeout=0,
                 partner_state_aggregation=0,
                 partner_state_synchronization=0,
                 partner_state_collecting=0,
                 partner_state_distributing=0,
                 partner_state_defaulted=0, partner_state_expired=0,
                 collector_max_delay=0):
        super(lacp, self).__init__()
        # parameter check
        assert (1 == actor_state_activity | 1)
        assert (1 == actor_state_timeout | 1)
        assert (1 == actor_state_aggregation | 1)
        assert (1 == actor_state_synchronization | 1)
        assert (1 == actor_state_collecting | 1)
        assert (1 == actor_state_distributing | 1)
        assert (1 == actor_state_defaulted | 1)
        assert (1 == actor_state_expired | 1)
        assert (1 == partner_state_activity | 1)
        assert (1 == partner_state_timeout | 1)
        assert (1 == partner_state_aggregation | 1)
        assert (1 == partner_state_synchronization | 1)
        assert (1 == partner_state_collecting | 1)
        assert (1 == partner_state_distributing | 1)
        assert (1 == partner_state_defaulted | 1)
        assert (1 == partner_state_expired | 1)
        # ------------------------------
        # Header
        # ------------------------------
        self._subtype = SLOW_SUBTYPE_LACP
        self.version = version
        # ------------------------------
        # Actor Information
        # ------------------------------
        self._actor_tag = self.LACP_TLV_TYPE_ACTOR
        self._actor_length = self._ACTPRT_INFO_PACK_LEN
        self.actor_system_priority = actor_system_priority
        self.actor_system = actor_system
        self.actor_key = actor_key
        self.actor_port_priority = actor_port_priority
        self.actor_port = actor_port
        self.actor_state_activity = actor_state_activity
        self.actor_state_timeout = actor_state_timeout
        self.actor_state_aggregation = actor_state_aggregation
        self.actor_state_synchronization = actor_state_synchronization
        self.actor_state_collecting = actor_state_collecting
        self.actor_state_distributing = actor_state_distributing
        self.actor_state_defaulted = actor_state_defaulted
        self.actor_state_expired = actor_state_expired
        self._actor_state = (
            (self.actor_state_activity << 0) |
            (self.actor_state_timeout << 1) |
            (self.actor_state_aggregation << 2) |
            (self.actor_state_synchronization << 3) |
            (self.actor_state_collecting << 4) |
            (self.actor_state_distributing << 5) |
            (self.actor_state_defaulted << 6) |
            (self.actor_state_expired << 7))
        # ------------------------------
        # Partner Information
        # ------------------------------
        self._partner_tag = self.LACP_TLV_TYPE_PARTNER
        self._partner_length = self._ACTPRT_INFO_PACK_LEN
        self.partner_system_priority = partner_system_priority
        self.partner_system = partner_system
        self.partner_key = partner_key
        self.partner_port_priority = partner_port_priority
        self.partner_port = partner_port
        self.partner_state_activity = partner_state_activity
        self.partner_state_timeout = partner_state_timeout
        self.partner_state_aggregation = partner_state_aggregation
        self.partner_state_synchronization = \
            partner_state_synchronization
        self.partner_state_collecting = partner_state_collecting
        self.partner_state_distributing = partner_state_distributing
        self.partner_state_defaulted = partner_state_defaulted
        self.partner_state_expired = partner_state_expired
        self._partner_state = (
            (self.partner_state_activity << 0) |
            (self.partner_state_timeout << 1) |
            (self.partner_state_aggregation << 2) |
            (self.partner_state_synchronization << 3) |
            (self.partner_state_collecting << 4) |
            (self.partner_state_distributing << 5) |
            (self.partner_state_defaulted << 6) |
            (self.partner_state_expired << 7))
        # ------------------------------
        # Collector Information
        # ------------------------------
        self._collector_tag = self.LACP_TLV_TYPE_COLLECTOR
        self._collector_length = self._COL_INFO_PACK_LEN
        self.collector_max_delay = collector_max_delay
        # ------------------------------
        # Terminator
        # ------------------------------
        self._terminator_tag = self.LACP_TLV_TYPE_TERMINATOR
        self._terminator_length = 0

    @classmethod
    def parser(cls, buf):
        assert cls._ALL_PACK_LEN == len(buf)
        offset = 0
        # ------------------------------
        # Header
        # ------------------------------
        (subtype, version
         ) = struct.unpack_from(cls._HLEN_PACK_STR, buf, offset)
        assert SLOW_SUBTYPE_LACP == subtype
        assert cls.LACP_VERSION_NUMBER == version
        offset += cls._HLEN_PACK_LEN
        # ------------------------------
        # Actor Information
        # ------------------------------
        (actor_tag, actor_length, actor_system_priority, actor_system,
         actor_key, actor_port_priority, actor_port, actor_state
         ) = struct.unpack_from(cls._ACTPRT_INFO_PACK_STR, buf, offset)
        assert cls.LACP_TLV_TYPE_ACTOR == actor_tag
        assert cls._ACTPRT_INFO_PACK_LEN == actor_length
        offset += cls._ACTPRT_INFO_PACK_LEN
        actor_state_activity = (actor_state >> 0) & 1
        actor_state_timeout = (actor_state >> 1) & 1
        actor_state_aggregation = (actor_state >> 2) & 1
        actor_state_synchronization = (actor_state >> 3) & 1
        actor_state_collecting = (actor_state >> 4) & 1
        actor_state_distributing = (actor_state >> 5) & 1
        actor_state_defaulted = (actor_state >> 6) & 1
        actor_state_expired = (actor_state >> 7) & 1
        # ------------------------------
        # Partner Information
        # ------------------------------
        (partner_tag, partner_length, partner_system_priority,
         partner_system, partner_key, partner_port_priority,
         partner_port, partner_state
         ) = struct.unpack_from(cls._ACTPRT_INFO_PACK_STR, buf, offset)
        assert cls.LACP_TLV_TYPE_PARTNER == partner_tag
        assert cls._ACTPRT_INFO_PACK_LEN == partner_length
        offset += cls._ACTPRT_INFO_PACK_LEN
        partner_state_activity = (partner_state >> 0) & 1
        partner_state_timeout = (partner_state >> 1) & 1
        partner_state_aggregation = (partner_state >> 2) & 1
        partner_state_synchronization = (partner_state >> 3) & 1
        partner_state_collecting = (partner_state >> 4) & 1
        partner_state_distributing = (partner_state >> 5) & 1
        partner_state_defaulted = (partner_state >> 6) & 1
        partner_state_expired = (partner_state >> 7) & 1
        # ------------------------------
        # Collector Information
        # ------------------------------
        (collector_tag, collector_length, collector_max_delay
         ) = struct.unpack_from(cls._COL_INFO_PACK_STR, buf, offset)
        assert cls.LACP_TLV_TYPE_COLLECTOR == collector_tag
        assert cls._COL_INFO_PACK_LEN == collector_length
        offset += cls._COL_INFO_PACK_LEN
        # ------------------------------
        # Terminator Information
        # ------------------------------
        (terminator_tag, terminator_length
         ) = struct.unpack_from(cls._TRM_PACK_STR, buf, offset)
        assert cls.LACP_TLV_TYPE_TERMINATOR == terminator_tag
        assert 0 == terminator_length
        return cls(version,
                   actor_system_priority,
                   addrconv.mac.bin_to_text(actor_system),
                   actor_key, actor_port_priority,
                   actor_port, actor_state_activity,
                   actor_state_timeout, actor_state_aggregation,
                   actor_state_synchronization, actor_state_collecting,
                   actor_state_distributing, actor_state_defaulted,
                   actor_state_expired, partner_system_priority,
                   addrconv.mac.bin_to_text(partner_system),
                   partner_key, partner_port_priority,
                   partner_port, partner_state_activity,
                   partner_state_timeout, partner_state_aggregation,
                   partner_state_synchronization,
                   partner_state_collecting, partner_state_distributing,
                   partner_state_defaulted, partner_state_expired,
                   collector_max_delay), None, buf[lacp._ALL_PACK_LEN:]

    def serialize(self, payload, prev):
        header = struct.pack(self._HLEN_PACK_STR, self._subtype,
                             self.version)
        actor = struct.pack(self._ACTPRT_INFO_PACK_STR,
                            self._actor_tag, self._actor_length,
                            self.actor_system_priority,
                            addrconv.mac.text_to_bin(self.actor_system),
                            self.actor_key,
                            self.actor_port_priority, self.actor_port,
                            self._actor_state)
        partner = struct.pack(self._ACTPRT_INFO_PACK_STR,
                              self._partner_tag, self._partner_length,
                              self.partner_system_priority,
                              addrconv.mac.text_to_bin(self.partner_system),
                              self.partner_key,
                              self.partner_port_priority,
                              self.partner_port, self._partner_state)
        collector = struct.pack(self._COL_INFO_PACK_STR,
                                self._collector_tag,
                                self._collector_length,
                                self.collector_max_delay)
        terminator = struct.pack(self._TRM_PACK_STR,
                                 self._terminator_tag,
                                 self._terminator_length)
        return header + actor + partner + collector + terminator
