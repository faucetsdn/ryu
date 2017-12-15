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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import copy
import logging
from struct import pack, unpack_from
import unittest

from nose.tools import ok_, eq_, raises
from ryu.ofproto import ether
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.lib import addrconv
from ryu.lib.packet.slow import slow, lacp
from ryu.lib.packet.slow import SLOW_PROTOCOL_MULTICAST
from ryu.lib.packet.slow import SLOW_SUBTYPE_LACP
from ryu.lib.packet.slow import SLOW_SUBTYPE_MARKER

LOG = logging.getLogger(__name__)


class Test_slow(unittest.TestCase):
    """ Test case for Slow Protocol
    """

    def setUp(self):
        self.subtype = SLOW_SUBTYPE_LACP
        self.version = lacp.LACP_VERSION_NUMBER
        self.actor_tag = lacp.LACP_TLV_TYPE_ACTOR
        self.actor_length = 20
        self.actor_system_priority = 65534
        self.actor_system = '00:07:0d:af:f4:54'
        self.actor_key = 1
        self.actor_port_priority = 65535
        self.actor_port = 1
        self.actor_state_activity = lacp.LACP_STATE_ACTIVE
        self.actor_state_timeout = lacp.LACP_STATE_LONG_TIMEOUT
        self.actor_state_aggregation = lacp.LACP_STATE_AGGREGATEABLE
        self.actor_state_synchronization = lacp.LACP_STATE_IN_SYNC
        self.actor_state_collecting = lacp.LACP_STATE_COLLECTING_ENABLED
        self.actor_state_distributing = lacp.LACP_STATE_DISTRIBUTING_ENABLED
        self.actor_state_defaulted = lacp.LACP_STATE_OPERATIONAL_PARTNER
        self.actor_state_expired = lacp.LACP_STATE_EXPIRED
        self.actor_state = (
            (self.actor_state_activity << 0) |
            (self.actor_state_timeout << 1) |
            (self.actor_state_aggregation << 2) |
            (self.actor_state_synchronization << 3) |
            (self.actor_state_collecting << 4) |
            (self.actor_state_distributing << 5) |
            (self.actor_state_defaulted << 6) |
            (self.actor_state_expired << 7))
        self.partner_tag = lacp.LACP_TLV_TYPE_PARTNER
        self.partner_length = 20
        self.partner_system_priority = 0
        self.partner_system = '00:00:00:00:00:00'
        self.partner_key = 0
        self.partner_port_priority = 0
        self.partner_port = 0
        self.partner_state_activity = 0
        self.partner_state_timeout = lacp.LACP_STATE_SHORT_TIMEOUT
        self.partner_state_aggregation = 0
        self.partner_state_synchronization = 0
        self.partner_state_collecting = 0
        self.partner_state_distributing = 0
        self.partner_state_defaulted = 0
        self.partner_state_expired = 0
        self.partner_state = (
            (self.partner_state_activity << 0) |
            (self.partner_state_timeout << 1) |
            (self.partner_state_aggregation << 2) |
            (self.partner_state_synchronization << 3) |
            (self.partner_state_collecting << 4) |
            (self.partner_state_distributing << 5) |
            (self.partner_state_defaulted << 6) |
            (self.partner_state_expired << 7))
        self.collector_tag = lacp.LACP_TLV_TYPE_COLLECTOR
        self.collector_length = 16
        self.collector_max_delay = 0
        self.terminator_tag = lacp.LACP_TLV_TYPE_TERMINATOR
        self.terminator_length = 0

        self.head_fmt = lacp._HLEN_PACK_STR
        self.head_len = lacp._HLEN_PACK_LEN
        self.act_fmt = lacp._ACTPRT_INFO_PACK_STR
        self.act_len = lacp._ACTPRT_INFO_PACK_LEN
        self.prt_fmt = lacp._ACTPRT_INFO_PACK_STR
        self.prt_len = lacp._ACTPRT_INFO_PACK_LEN
        self.col_fmt = lacp._COL_INFO_PACK_STR
        self.col_len = lacp._COL_INFO_PACK_LEN
        self.trm_fmt = lacp._TRM_PACK_STR
        self.trm_len = lacp._TRM_PACK_LEN
        self.length = lacp._ALL_PACK_LEN

        self.head_buf = pack(self.head_fmt,
                             self.subtype,
                             self.version)
        self.act_buf = pack(self.act_fmt,
                            self.actor_tag,
                            self.actor_length,
                            self.actor_system_priority,
                            addrconv.mac.text_to_bin(self.actor_system),
                            self.actor_key,
                            self.actor_port_priority,
                            self.actor_port,
                            self.actor_state)
        self.prt_buf = pack(self.prt_fmt,
                            self.partner_tag,
                            self.partner_length,
                            self.partner_system_priority,
                            addrconv.mac.text_to_bin(self.partner_system),
                            self.partner_key,
                            self.partner_port_priority,
                            self.partner_port,
                            self.partner_state)
        self.col_buf = pack(self.col_fmt,
                            self.collector_tag,
                            self.collector_length,
                            self.collector_max_delay)
        self.trm_buf = pack(self.trm_fmt,
                            self.terminator_tag,
                            self.terminator_length)

        self.buf = self.head_buf + self.act_buf + self.prt_buf + \
            self.col_buf + self.trm_buf

    def tearDown(self):
        pass

    def test_parser(self):
        slow.parser(self.buf)

    def test_not_implemented_subtype(self):
        not_implemented_buf = pack(
            slow._PACK_STR, SLOW_SUBTYPE_MARKER) + self.buf[1:]
        (instance, nexttype, last) = slow.parser(not_implemented_buf)
        assert instance is None
        assert nexttype is None
        assert last is not None

    def test_invalid_subtype(self):
        invalid_buf = b'\xff' + self.buf[1:]
        (instance, nexttype, last) = slow.parser(invalid_buf)
        assert instance is None
        assert nexttype is None
        assert last is not None


class Test_lacp(unittest.TestCase):
    """ Test case for lacp
    """

    def setUp(self):
        self.subtype = SLOW_SUBTYPE_LACP
        self.version = lacp.LACP_VERSION_NUMBER
        self.actor_tag = lacp.LACP_TLV_TYPE_ACTOR
        self.actor_length = 20
        self.actor_system_priority = 65534
        self.actor_system = '00:07:0d:af:f4:54'
        self.actor_key = 1
        self.actor_port_priority = 65535
        self.actor_port = 1
        self.actor_state_activity = lacp.LACP_STATE_ACTIVE
        self.actor_state_timeout = lacp.LACP_STATE_LONG_TIMEOUT
        self.actor_state_aggregation = lacp.LACP_STATE_AGGREGATEABLE
        self.actor_state_synchronization = lacp.LACP_STATE_IN_SYNC
        self.actor_state_collecting = lacp.LACP_STATE_COLLECTING_ENABLED
        self.actor_state_distributing = lacp.LACP_STATE_DISTRIBUTING_ENABLED
        self.actor_state_defaulted = lacp.LACP_STATE_OPERATIONAL_PARTNER
        self.actor_state_expired = lacp.LACP_STATE_EXPIRED
        self.actor_state = (
            (self.actor_state_activity << 0) |
            (self.actor_state_timeout << 1) |
            (self.actor_state_aggregation << 2) |
            (self.actor_state_synchronization << 3) |
            (self.actor_state_collecting << 4) |
            (self.actor_state_distributing << 5) |
            (self.actor_state_defaulted << 6) |
            (self.actor_state_expired << 7))
        self.partner_tag = lacp.LACP_TLV_TYPE_PARTNER
        self.partner_length = 20
        self.partner_system_priority = 0
        self.partner_system = '00:00:00:00:00:00'
        self.partner_key = 0
        self.partner_port_priority = 0
        self.partner_port = 0
        self.partner_state_activity = 0
        self.partner_state_timeout = lacp.LACP_STATE_SHORT_TIMEOUT
        self.partner_state_aggregation = 0
        self.partner_state_synchronization = 0
        self.partner_state_collecting = 0
        self.partner_state_distributing = 0
        self.partner_state_defaulted = 0
        self.partner_state_expired = 0
        self.partner_state = (
            (self.partner_state_activity << 0) |
            (self.partner_state_timeout << 1) |
            (self.partner_state_aggregation << 2) |
            (self.partner_state_synchronization << 3) |
            (self.partner_state_collecting << 4) |
            (self.partner_state_distributing << 5) |
            (self.partner_state_defaulted << 6) |
            (self.partner_state_expired << 7))
        self.collector_tag = lacp.LACP_TLV_TYPE_COLLECTOR
        self.collector_length = 16
        self.collector_max_delay = 0
        self.terminator_tag = lacp.LACP_TLV_TYPE_TERMINATOR
        self.terminator_length = 0

        self.head_fmt = lacp._HLEN_PACK_STR
        self.head_len = lacp._HLEN_PACK_LEN
        self.act_fmt = lacp._ACTPRT_INFO_PACK_STR
        self.act_len = lacp._ACTPRT_INFO_PACK_LEN
        self.prt_fmt = lacp._ACTPRT_INFO_PACK_STR
        self.prt_len = lacp._ACTPRT_INFO_PACK_LEN
        self.col_fmt = lacp._COL_INFO_PACK_STR
        self.col_len = lacp._COL_INFO_PACK_LEN
        self.trm_fmt = lacp._TRM_PACK_STR
        self.trm_len = lacp._TRM_PACK_LEN
        self.length = lacp._ALL_PACK_LEN

        self.head_buf = pack(self.head_fmt,
                             self.subtype,
                             self.version)
        self.act_buf = pack(self.act_fmt,
                            self.actor_tag,
                            self.actor_length,
                            self.actor_system_priority,
                            addrconv.mac.text_to_bin(self.actor_system),
                            self.actor_key,
                            self.actor_port_priority,
                            self.actor_port,
                            self.actor_state)
        self.prt_buf = pack(self.prt_fmt,
                            self.partner_tag,
                            self.partner_length,
                            self.partner_system_priority,
                            addrconv.mac.text_to_bin(self.partner_system),
                            self.partner_key,
                            self.partner_port_priority,
                            self.partner_port,
                            self.partner_state)
        self.col_buf = pack(self.col_fmt,
                            self.collector_tag,
                            self.collector_length,
                            self.collector_max_delay)
        self.trm_buf = pack(self.trm_fmt,
                            self.terminator_tag,
                            self.terminator_length)

        self.buf = self.head_buf + self.act_buf + self.prt_buf + \
            self.col_buf + self.trm_buf

        self.l = lacp(self.version,
                      self.actor_system_priority,
                      self.actor_system,
                      self.actor_key,
                      self.actor_port_priority,
                      self.actor_port,
                      self.actor_state_activity,
                      self.actor_state_timeout,
                      self.actor_state_aggregation,
                      self.actor_state_synchronization,
                      self.actor_state_collecting,
                      self.actor_state_distributing,
                      self.actor_state_defaulted,
                      self.actor_state_expired,
                      self.partner_system_priority,
                      self.partner_system,
                      self.partner_key,
                      self.partner_port_priority,
                      self.partner_port,
                      self.partner_state_activity,
                      self.partner_state_timeout,
                      self.partner_state_aggregation,
                      self.partner_state_synchronization,
                      self.partner_state_collecting,
                      self.partner_state_distributing,
                      self.partner_state_defaulted,
                      self.partner_state_expired,
                      self.collector_max_delay)

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        eq_(self.subtype, self.l._subtype)
        eq_(self.version, self.l.version)
        eq_(self.actor_tag, self.l._actor_tag)
        eq_(self.actor_length, self.l._actor_length)
        eq_(self.actor_system_priority, self.l.actor_system_priority)
        eq_(self.actor_system, self.l.actor_system)
        eq_(self.actor_key, self.l.actor_key)
        eq_(self.actor_port_priority, self.l.actor_port_priority)
        eq_(self.actor_port, self.l.actor_port)
        eq_(self.actor_state_activity, self.l.actor_state_activity)
        eq_(self.actor_state_timeout, self.l.actor_state_timeout)
        eq_(self.actor_state_aggregation,
            self.l.actor_state_aggregation)
        eq_(self.actor_state_synchronization,
            self.l.actor_state_synchronization)
        eq_(self.actor_state_collecting,
            self.l.actor_state_collecting)
        eq_(self.actor_state_distributing,
            self.l.actor_state_distributing)
        eq_(self.actor_state_defaulted, self.l.actor_state_defaulted)
        eq_(self.actor_state_expired, self.l.actor_state_expired)
        eq_(self.actor_state, self.l._actor_state)
        eq_(self.partner_tag, self.l._partner_tag)
        eq_(self.partner_length, self.l._partner_length)
        eq_(self.partner_system_priority,
            self.l.partner_system_priority)
        eq_(self.partner_system, self.l.partner_system)
        eq_(self.partner_key, self.l.partner_key)
        eq_(self.partner_port_priority, self.l.partner_port_priority)
        eq_(self.partner_port, self.l.partner_port)
        eq_(self.partner_state_activity, self.l.partner_state_activity)
        eq_(self.partner_state_timeout, self.l.partner_state_timeout)
        eq_(self.partner_state_aggregation,
            self.l.partner_state_aggregation)
        eq_(self.partner_state_synchronization,
            self.l.partner_state_synchronization)
        eq_(self.partner_state_collecting,
            self.l.partner_state_collecting)
        eq_(self.partner_state_distributing,
            self.l.partner_state_distributing)
        eq_(self.partner_state_defaulted,
            self.l.partner_state_defaulted)
        eq_(self.partner_state_expired, self.l.partner_state_expired)
        eq_(self.partner_state, self.l._partner_state)
        eq_(self.collector_tag, self.l._collector_tag)
        eq_(self.collector_length, self.l._collector_length)
        eq_(self.collector_max_delay, self.l.collector_max_delay)
        eq_(self.terminator_tag, self.l._terminator_tag)
        eq_(self.terminator_length, self.l._terminator_length)

    def test_parser(self):
        _res = self.l.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        eq_(res._subtype, self.subtype)
        eq_(res.version, self.version)
        eq_(res._actor_tag, self.actor_tag)
        eq_(res._actor_length, self.actor_length)
        eq_(res.actor_system_priority, self.actor_system_priority)
        eq_(res.actor_system, self.actor_system)
        eq_(res.actor_key, self.actor_key)
        eq_(res.actor_port_priority, self.actor_port_priority)
        eq_(res.actor_port, self.actor_port)
        eq_(res.actor_state_activity, self.actor_state_activity)
        eq_(res.actor_state_timeout, self.actor_state_timeout)
        eq_(res.actor_state_aggregation, self.actor_state_aggregation)
        eq_(res.actor_state_synchronization,
            self.actor_state_synchronization)
        eq_(res.actor_state_collecting, self.actor_state_collecting)
        eq_(res.actor_state_distributing, self.actor_state_distributing)
        eq_(res.actor_state_defaulted, self.actor_state_defaulted)
        eq_(res.actor_state_expired, self.actor_state_expired)
        eq_(res._actor_state, self.actor_state)
        eq_(res._partner_tag, self.partner_tag)
        eq_(res._partner_length, self.partner_length)
        eq_(res.partner_system_priority, self.partner_system_priority)
        eq_(res.partner_system, self.partner_system)
        eq_(res.partner_key, self.partner_key)
        eq_(res.partner_port_priority, self.partner_port_priority)
        eq_(res.partner_port, self.partner_port)
        eq_(res.partner_state_activity, self.partner_state_activity)
        eq_(res.partner_state_timeout, self.partner_state_timeout)
        eq_(res.partner_state_aggregation,
            self.partner_state_aggregation)
        eq_(res.partner_state_synchronization,
            self.partner_state_synchronization)
        eq_(res.partner_state_collecting, self.partner_state_collecting)
        eq_(res.partner_state_distributing,
            self.partner_state_distributing)
        eq_(res.partner_state_defaulted, self.partner_state_defaulted)
        eq_(res.partner_state_expired, self.partner_state_expired)
        eq_(res._partner_state, self.partner_state)
        eq_(res._collector_tag, self.collector_tag)
        eq_(res._collector_length, self.collector_length)
        eq_(res.collector_max_delay, self.collector_max_delay)
        eq_(res._terminator_tag, self.terminator_tag)
        eq_(res._terminator_length, self.terminator_length)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.l.serialize(data, prev)

        offset = 0
        head_res = unpack_from(self.head_fmt, buf, offset)
        offset += self.head_len
        act_res = unpack_from(self.act_fmt, buf, offset)
        offset += self.act_len
        prt_res = unpack_from(self.prt_fmt, buf, offset)
        offset += self.prt_len
        col_res = unpack_from(self.col_fmt, buf, offset)
        offset += self.col_len
        trm_res = unpack_from(self.trm_fmt, buf, offset)

        eq_(head_res[0], self.subtype)
        eq_(head_res[1], self.version)

        eq_(act_res[0], self.actor_tag)
        eq_(act_res[1], self.actor_length)
        eq_(act_res[2], self.actor_system_priority)
        eq_(act_res[3], addrconv.mac.text_to_bin(self.actor_system))
        eq_(act_res[4], self.actor_key)
        eq_(act_res[5], self.actor_port_priority)
        eq_(act_res[6], self.actor_port)
        eq_(act_res[7], self.actor_state)

        eq_(prt_res[0], self.partner_tag)
        eq_(prt_res[1], self.partner_length)
        eq_(prt_res[2], self.partner_system_priority)
        eq_(prt_res[3], addrconv.mac.text_to_bin(self.partner_system))
        eq_(prt_res[4], self.partner_key)
        eq_(prt_res[5], self.partner_port_priority)
        eq_(prt_res[6], self.partner_port)
        eq_(prt_res[7], self.partner_state)

        eq_(col_res[0], self.collector_tag)
        eq_(col_res[1], self.collector_length)
        eq_(col_res[2], self.collector_max_delay)

        eq_(trm_res[0], self.terminator_tag)
        eq_(trm_res[1], self.terminator_length)

    def _build_lacp(self):
        ethertype = ether.ETH_TYPE_SLOW
        dst = SLOW_PROTOCOL_MULTICAST
        e = ethernet(dst, self.actor_system, ethertype)
        p = Packet()

        p.add_protocol(e)
        p.add_protocol(self.l)
        p.serialize()
        return p

    def test_build_lacp(self):
        p = self._build_lacp()

        e = self.find_protocol(p, "ethernet")
        ok_(e)
        eq_(e.ethertype, ether.ETH_TYPE_SLOW)

        l = self.find_protocol(p, "lacp")
        ok_(l)

        eq_(l._subtype, self.subtype)
        eq_(l.version, self.version)
        eq_(l._actor_tag, self.actor_tag)
        eq_(l._actor_length, self.actor_length)
        eq_(l.actor_system_priority, self.actor_system_priority)
        eq_(l.actor_system, self.actor_system)
        eq_(l.actor_key, self.actor_key)
        eq_(l.actor_port_priority, self.actor_port_priority)
        eq_(l.actor_port, self.actor_port)
        eq_(l.actor_state_activity, self.actor_state_activity)
        eq_(l.actor_state_timeout, self.actor_state_timeout)
        eq_(l.actor_state_aggregation, self.actor_state_aggregation)
        eq_(l.actor_state_synchronization,
            self.actor_state_synchronization)
        eq_(l.actor_state_collecting, self.actor_state_collecting)
        eq_(l.actor_state_distributing, self.actor_state_distributing)
        eq_(l.actor_state_defaulted, self.actor_state_defaulted)
        eq_(l.actor_state_expired, self.actor_state_expired)
        eq_(l._actor_state, self.actor_state)
        eq_(l._partner_tag, self.partner_tag)
        eq_(l._partner_length, self.partner_length)
        eq_(l.partner_system_priority, self.partner_system_priority)
        eq_(l.partner_system, self.partner_system)
        eq_(l.partner_key, self.partner_key)
        eq_(l.partner_port_priority, self.partner_port_priority)
        eq_(l.partner_port, self.partner_port)
        eq_(l.partner_state_activity, self.partner_state_activity)
        eq_(l.partner_state_timeout, self.partner_state_timeout)
        eq_(l.partner_state_aggregation, self.partner_state_aggregation)
        eq_(l.partner_state_synchronization,
            self.partner_state_synchronization)
        eq_(l.partner_state_collecting, self.partner_state_collecting)
        eq_(l.partner_state_distributing,
            self.partner_state_distributing)
        eq_(l.partner_state_defaulted, self.partner_state_defaulted)
        eq_(l.partner_state_expired, self.partner_state_expired)
        eq_(l._partner_state, self.partner_state)
        eq_(l._collector_tag, self.collector_tag)
        eq_(l._collector_length, self.collector_length)
        eq_(l.collector_max_delay, self.collector_max_delay)
        eq_(l._terminator_tag, self.terminator_tag)
        eq_(l._terminator_length, self.terminator_length)

    @raises(Exception)
    def test_malformed_lacp(self):
        m_short_buf = self.buf[1:self.length]
        slow.parser(m_short_buf)

    @raises(Exception)
    def test_invalid_subtype(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.subtype = 0xff
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_version(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.version = 0xff
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_actor_tag(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.actor_tag = 0x04
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_actor_length(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.actor_length = 50
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_partner_tag(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.partner_tag = 0x01
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_partner_length(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.partner_length = 0
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_collector_tag(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.collector_tag = 0x00
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_collector_length(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.collector_length = 20
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_terminator_tag(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.terminator_tag = 0x04
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_terminator_length(self):
        invalid_lacv = copy.deepcopy(self.l)
        invalid_lacv.terminator_length = self.trm_len
        invalid_buf = invalid_lacv.serialize()
        slow.parser(invalid_buf)

    @raises(Exception)
    def test_invalid_actor_state_activity(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 2,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_actor_state_timeout(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 2,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_actor_state_aggregation(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 2,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_actor_state_synchronization(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 2,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_actor_state_collecting(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 2,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_actor_state_distributing(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 2,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_actor_state_defaulted(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 2,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_actor_state_expired(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 2,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_activity(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 -1,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_timeout(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 -1,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_aggregation(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 -1,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_synchronization(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 -1,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_collecting(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 -1,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_distributing(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 -1,
                 self.partner_state_defaulted,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_defaulted(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 -1,
                 self.partner_state_expired,
                 self.collector_max_delay)
        l.serialize()

    @raises(Exception)
    def test_invalid_partner_state_expired(self):
        l = lacp(self.version,
                 self.actor_system_priority,
                 self.actor_system,
                 self.actor_key,
                 self.actor_port_priority,
                 self.actor_port,
                 self.actor_state_activity,
                 self.actor_state_timeout,
                 self.actor_state_aggregation,
                 self.actor_state_synchronization,
                 self.actor_state_collecting,
                 self.actor_state_distributing,
                 self.actor_state_defaulted,
                 self.actor_state_expired,
                 self.partner_system_priority,
                 self.partner_system,
                 self.partner_key,
                 self.partner_port_priority,
                 self.partner_port,
                 self.partner_state_activity,
                 self.partner_state_timeout,
                 self.partner_state_aggregation,
                 self.partner_state_synchronization,
                 self.partner_state_collecting,
                 self.partner_state_distributing,
                 self.partner_state_defaulted,
                 -1,
                 self.collector_max_delay)
        l.serialize()

    def test_json(self):
        jsondict = self.l.to_jsondict()
        l = lacp.from_jsondict(jsondict['lacp'])
        eq_(str(self.l), str(l))
