# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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

import unittest
import logging
import six
import struct
import inspect

from nose.tools import eq_, ok_
from nose.tools import raises

from ryu.ofproto import inet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.lib.packet import packet_utils
from ryu.lib.packet import vrrp
from ryu.lib import addrconv


LOG = logging.getLogger(__name__)


class Test_vrrpv2(unittest.TestCase):
    """ Test case for vrrp v2
    """
    version = vrrp.VRRP_VERSION_V2
    type_ = vrrp.VRRP_TYPE_ADVERTISEMENT
    vrid = 128
    priority = 100
    count_ip = 1
    auth_type = vrrp.VRRP_AUTH_NO_AUTH
    max_adver_int = 100
    checksum = 0
    ip_address = '192.168.0.1'
    auth_data = (0, 0)
    vrrpv2 = vrrp.vrrpv2.create(type_, vrid, priority, max_adver_int,
                                [ip_address])
    buf = struct.pack(vrrp.vrrpv2._PACK_STR + '4sII',
                      vrrp.vrrp_to_version_type(vrrp.VRRP_VERSION_V2, type_),
                      vrid, priority, count_ip,
                      auth_type, max_adver_int, checksum,
                      addrconv.ipv4.text_to_bin(ip_address),
                      auth_data[0], auth_data[1])

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_, self.vrrpv2.type)
        eq_(self.vrid, self.vrrpv2.vrid)
        eq_(self.priority, self.vrrpv2.priority)
        eq_(self.count_ip, self.vrrpv2.count_ip)
        eq_(self.auth_type, self.vrrpv2.auth_type)
        eq_(1, len(self.vrrpv2.ip_addresses))
        eq_(self.ip_address, self.vrrpv2.ip_addresses[0])
        eq_(self.auth_data, self.vrrpv2.auth_data)

    def test_parser(self):
        vrrpv2, _cls, _ = self.vrrpv2.parser(self.buf)

        eq_(self.version, vrrpv2.version)
        eq_(self.type_, vrrpv2.type)
        eq_(self.vrid, vrrpv2.vrid)
        eq_(self.priority, vrrpv2.priority)
        eq_(self.count_ip, vrrpv2.count_ip)
        eq_(self.auth_type, vrrpv2.auth_type)
        eq_(self.max_adver_int, vrrpv2.max_adver_int)
        eq_(self.checksum, vrrpv2.checksum)
        eq_(1, len(vrrpv2.ip_addresses))
        eq_(str, type(vrrpv2.ip_addresses[0]))
        eq_(self.ip_address, vrrpv2.ip_addresses[0])
        eq_(self.auth_data, vrrpv2.auth_data)

    def test_serialize(self):
        src_ip = '192.168.0.1'
        dst_ip = vrrp.VRRP_IPV4_DST_ADDRESS
        prev = ipv4.ipv4(4, 5, 0, 0, 0, 0, 0, vrrp.VRRP_IPV4_TTL,
                         inet.IPPROTO_VRRP, 0, src_ip, dst_ip)

        type_ = vrrp.VRRP_TYPE_ADVERTISEMENT
        vrid = 5
        priority = 10
        max_adver_int = 30
        ip_address = '192.168.0.2'
        ip_addresses = [ip_address]

        vrrp_ = vrrp.vrrpv2.create(
            type_, vrid, priority, max_adver_int, ip_addresses)

        buf = vrrp_.serialize(bytearray(), prev)
        pack_str = vrrp.vrrpv2._PACK_STR + '4sII'
        pack_len = struct.calcsize(pack_str)
        res = struct.unpack(pack_str, six.binary_type(buf))
        eq_(res[0], vrrp.vrrp_to_version_type(vrrp.VRRP_VERSION_V2, type_))
        eq_(res[1], vrid)
        eq_(res[2], priority)
        eq_(res[3], len(ip_addresses))
        eq_(res[4], vrrp.VRRP_AUTH_NO_AUTH)
        eq_(res[5], max_adver_int)
        # res[6] is checksum
        eq_(res[7], addrconv.ipv4.text_to_bin(ip_address))
        eq_(res[8], 0)
        eq_(res[9], 0)
        eq_(len(buf), pack_len)

        # checksum
        s = packet_utils.checksum(buf)
        eq_(0, s)

    @raises(Exception)
    def test_malformed_vrrpv2(self):
        m_short_buf = self.buf[1:vrrp.vrrpv2._MIN_LEN]
        vrrp.vrrp.parser(m_short_buf)

    def test_create_packet(self):
        primary_ip = '192.168.0.2'
        p0 = self.vrrpv2.create_packet(primary_ip)
        p0.serialize()
        p1 = packet.Packet(six.binary_type(p0.data))
        p1.serialize()
        eq_(p0.data, p1.data)

    def _test_is_valid(self, type_=None, vrid=None, priority=None,
                       max_adver_int=None):
        if type_ is None:
            type_ = self.type_
        if vrid is None:
            vrid = self.vrid
        if priority is None:
            priority = self.priority
        if max_adver_int is None:
            max_adver_int = self.max_adver_int

        vrrp_ = vrrp.vrrpv2.create(type_, vrid, priority, max_adver_int,
                                   [self.ip_address])
        return vrrp_.is_valid()

    def test_is_valid_ok(self):
        ok_(self._test_is_valid())

    def test_is_valid_ng_type(self):
        ok_(not self._test_is_valid(type_=15))

    def test_is_valid_ng_vrid_min(self):
        vrid = vrrp.VRRP_VRID_MIN - 1
        ok_(not self._test_is_valid(vrid=vrid))

    def test_is_valid_ng_vrid_max(self):
        vrid = vrrp.VRRP_VRID_MAX + 1
        ok_(not self._test_is_valid(vrid=vrid))

    def test_is_valid_ng_priority_min(self):
        priority = vrrp.VRRP_PRIORITY_MIN - 1
        ok_(not self._test_is_valid(priority=priority))

    def test_is_valid_ng_priority_max(self):
        priority = vrrp.VRRP_PRIORITY_MAX + 1
        ok_(not self._test_is_valid(priority=priority))

    def test_is_valid_ng_adver_min(self):
        max_adver_int = vrrp.VRRP_V2_MAX_ADVER_INT_MIN - 1
        ok_(not self._test_is_valid(max_adver_int=max_adver_int))

    def test_is_valid_ng_adver_max(self):
        max_adver_int = vrrp.VRRP_V2_MAX_ADVER_INT_MAX + 1
        ok_(not self._test_is_valid(max_adver_int=max_adver_int))

    def test_to_string(self):
        vrrpv2_values = {'version': self.version,
                         'type': self.type_,
                         'vrid': self.vrid,
                         'priority': self.priority,
                         'count_ip': self.count_ip,
                         'max_adver_int': self.max_adver_int,
                         'checksum': self.vrrpv2.checksum,
                         'ip_addresses': [self.ip_address],
                         'auth_type': self.auth_type,
                         'auth_data': self.auth_data,
                         'identification': self.vrrpv2.identification}
        _vrrpv2_str = ','.join(['%s=%s' % (k, repr(vrrpv2_values[k]))
                                for k, v in inspect.getmembers(self.vrrpv2)
                                if k in vrrpv2_values])
        vrrpv2_str = '%s(%s)' % (vrrp.vrrpv2.__name__, _vrrpv2_str)

        eq_(str(self.vrrpv2), vrrpv2_str)
        eq_(repr(self.vrrpv2), vrrpv2_str)


class Test_vrrpv3_ipv4(unittest.TestCase):
    """ Test case for vrrp v3 IPv4
    """
    version = vrrp.VRRP_VERSION_V3
    type_ = vrrp.VRRP_TYPE_ADVERTISEMENT
    vrid = 128
    priority = 99
    count_ip = 1
    max_adver_int = 111
    checksum = 0
    ip_address = '192.168.0.1'
    vrrpv3 = vrrp.vrrpv3.create(type_, vrid, priority, max_adver_int,
                                [ip_address])
    buf = struct.pack(vrrp.vrrpv3._PACK_STR + '4s',
                      vrrp.vrrp_to_version_type(vrrp.VRRP_VERSION_V3, type_),
                      vrid, priority, count_ip,
                      max_adver_int, checksum,
                      addrconv.ipv4.text_to_bin(ip_address))

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_, self.vrrpv3.type)
        eq_(self.vrid, self.vrrpv3.vrid)
        eq_(self.priority, self.vrrpv3.priority)
        eq_(self.count_ip, self.vrrpv3.count_ip)
        eq_(1, len(self.vrrpv3.ip_addresses))
        eq_(self.ip_address, self.vrrpv3.ip_addresses[0])

    def test_parser(self):
        vrrpv3, _cls, _ = self.vrrpv3.parser(self.buf)

        eq_(self.version, vrrpv3.version)
        eq_(self.type_, vrrpv3.type)
        eq_(self.vrid, vrrpv3.vrid)
        eq_(self.priority, vrrpv3.priority)
        eq_(self.count_ip, vrrpv3.count_ip)
        eq_(self.max_adver_int, vrrpv3.max_adver_int)
        eq_(self.checksum, vrrpv3.checksum)
        eq_(1, len(vrrpv3.ip_addresses))
        eq_(str, type(vrrpv3.ip_addresses[0]))
        eq_(self.ip_address, vrrpv3.ip_addresses[0])

    def test_serialize(self):
        src_ip = '192.168.0.1'
        dst_ip = vrrp.VRRP_IPV4_DST_ADDRESS
        prev = ipv4.ipv4(4, 5, 0, 0, 0, 0, 0, vrrp.VRRP_IPV4_TTL,
                         inet.IPPROTO_VRRP, 0, src_ip, dst_ip)

        type_ = vrrp.VRRP_TYPE_ADVERTISEMENT
        vrid = 5
        priority = 10
        max_adver_int = 30
        ip_address = '192.168.0.2'
        ip_addresses = [ip_address]

        vrrp_ = vrrp.vrrpv3.create(
            type_, vrid, priority, max_adver_int, ip_addresses)

        buf = vrrp_.serialize(bytearray(), prev)
        print(len(buf), type(buf), buf)
        pack_str = vrrp.vrrpv3._PACK_STR + '4s'
        pack_len = struct.calcsize(pack_str)
        res = struct.unpack(pack_str, six.binary_type(buf))
        eq_(res[0], vrrp.vrrp_to_version_type(vrrp.VRRP_VERSION_V3, type_))
        eq_(res[1], vrid)
        eq_(res[2], priority)
        eq_(res[3], len(ip_addresses))
        eq_(res[4], max_adver_int)
        # res[5] is checksum
        eq_(res[6], addrconv.ipv4.text_to_bin(ip_address))
        eq_(len(buf), pack_len)
        print(res)

        # checksum
        ph = struct.pack('!4s4sxBH',
                         addrconv.ipv4.text_to_bin(src_ip),
                         addrconv.ipv4.text_to_bin(dst_ip),
                         inet.IPPROTO_VRRP, pack_len)
        s = packet_utils.checksum(ph + buf)
        eq_(0, s)

    @raises(Exception)
    def test_malformed_vrrpv3(self):
        m_short_buf = self.buf[1:vrrp.vrrpv3._MIN_LEN]
        vrrp.vrrp.parser(m_short_buf)

    def test_create_packet(self):
        primary_ip = '192.168.0.2'
        p0 = self.vrrpv3.create_packet(primary_ip)
        p0.serialize()
        p1 = packet.Packet(six.binary_type(p0.data))
        p1.serialize()
        eq_(p0.data, p1.data)

    def _test_is_valid(self, type_=None, vrid=None, priority=None,
                       max_adver_int=None):
        if type_ is None:
            type_ = self.type_
        if vrid is None:
            vrid = self.vrid
        if priority is None:
            priority = self.priority
        if max_adver_int is None:
            max_adver_int = self.max_adver_int

        vrrp_ = vrrp.vrrpv3.create(type_, vrid, priority, max_adver_int,
                                   [self.ip_address])
        return vrrp_.is_valid()

    def test_is_valid_ok(self):
        ok_(self._test_is_valid())

    def test_is_valid_ng_type(self):
        ok_(not self._test_is_valid(type_=15))

    def test_is_valid_ng_vrid_min(self):
        vrid = vrrp.VRRP_VRID_MIN - 1
        ok_(not self._test_is_valid(vrid=vrid))

    def test_is_valid_ng_vrid_max(self):
        vrid = vrrp.VRRP_VRID_MAX + 1
        ok_(not self._test_is_valid(vrid=vrid))

    def test_is_valid_ng_priority_min(self):
        priority = vrrp.VRRP_PRIORITY_MIN - 1
        ok_(not self._test_is_valid(priority=priority))

    def test_is_valid_ng_priority_max(self):
        priority = vrrp.VRRP_PRIORITY_MAX + 1
        ok_(not self._test_is_valid(priority=priority))

    def test_is_valid_ng_adver_min(self):
        max_adver_int = vrrp.VRRP_V3_MAX_ADVER_INT_MIN - 1
        ok_(not self._test_is_valid(max_adver_int=max_adver_int))

    def test_is_valid_ng_adver_max(self):
        max_adver_int = vrrp.VRRP_V3_MAX_ADVER_INT_MAX + 1
        ok_(not self._test_is_valid(max_adver_int=max_adver_int))

    def test_to_string(self):
        vrrpv3_values = {'version': self.version,
                         'type': self.type_,
                         'vrid': self.vrid,
                         'priority': self.priority,
                         'count_ip': self.count_ip,
                         'max_adver_int': self.max_adver_int,
                         'checksum': self.vrrpv3.checksum,
                         'ip_addresses': [self.ip_address],
                         'auth_type': None,
                         'auth_data': None,
                         'identification': self.vrrpv3.identification}
        _vrrpv3_str = ','.join(['%s=%s' % (k, repr(vrrpv3_values[k]))
                                for k, v in inspect.getmembers(self.vrrpv3)
                                if k in vrrpv3_values])
        vrrpv3_str = '%s(%s)' % (vrrp.vrrpv3.__name__, _vrrpv3_str)

        eq_(str(self.vrrpv3), vrrpv3_str)
        eq_(repr(self.vrrpv3), vrrpv3_str)


class Test_vrrpv3_ipv6(unittest.TestCase):
    """ Test case for vrrp v3 IPv6
    """
    version = vrrp.VRRP_VERSION_V3
    type_ = vrrp.VRRP_TYPE_ADVERTISEMENT
    vrid = 128
    priority = 99
    count_ip = 1
    max_adver_int = 111
    checksum = 0
    ip_address = '2001:db8:2000::1'
    vrrpv3 = vrrp.vrrpv3.create(type_, vrid, priority, max_adver_int,
                                [ip_address])
    buf = struct.pack(vrrp.vrrpv3._PACK_STR + '16s',
                      vrrp.vrrp_to_version_type(vrrp.VRRP_VERSION_V3, type_),
                      vrid, priority, count_ip,
                      max_adver_int, checksum,
                      addrconv.ipv6.text_to_bin(ip_address))

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_, self.vrrpv3.type)
        eq_(self.vrid, self.vrrpv3.vrid)
        eq_(self.priority, self.vrrpv3.priority)
        eq_(self.count_ip, self.vrrpv3.count_ip)
        eq_(1, len(self.vrrpv3.ip_addresses))
        eq_(self.ip_address, self.vrrpv3.ip_addresses[0])

    def test_parser(self):
        vrrpv3, _cls, _ = self.vrrpv3.parser(self.buf)

        eq_(self.version, vrrpv3.version)
        eq_(self.type_, vrrpv3.type)
        eq_(self.vrid, vrrpv3.vrid)
        eq_(self.priority, vrrpv3.priority)
        eq_(self.count_ip, vrrpv3.count_ip)
        eq_(self.max_adver_int, vrrpv3.max_adver_int)
        eq_(self.checksum, vrrpv3.checksum)
        eq_(1, len(vrrpv3.ip_addresses))
        eq_(str, type(vrrpv3.ip_addresses[0]))
        eq_(self.ip_address, vrrpv3.ip_addresses[0])

    def test_serialize(self):
        src_ip = '2001:db8:2000::1'
        dst_ip = vrrp.VRRP_IPV6_DST_ADDRESS
        prev = ipv6.ipv6(6, 0, 0, 0, inet.IPPROTO_VRRP,
                         vrrp.VRRP_IPV6_HOP_LIMIT, src_ip, dst_ip)

        type_ = vrrp.VRRP_TYPE_ADVERTISEMENT
        vrid = 5
        priority = 10
        max_adver_int = 30
        ip_address = '2001:db8:2000::2'
        ip_addresses = [ip_address]

        vrrp_ = vrrp.vrrpv3.create(
            type_, vrid, priority, max_adver_int, ip_addresses)

        buf = vrrp_.serialize(bytearray(), prev)
        print(len(buf), type(buf), buf)
        pack_str = vrrp.vrrpv3._PACK_STR + '16s'
        pack_len = struct.calcsize(pack_str)
        res = struct.unpack(pack_str, six.binary_type(buf))
        eq_(res[0], vrrp.vrrp_to_version_type(vrrp.VRRP_VERSION_V3, type_))
        eq_(res[1], vrid)
        eq_(res[2], priority)
        eq_(res[3], len(ip_addresses))
        eq_(res[4], max_adver_int)
        # res[5] is checksum
        eq_(res[6], addrconv.ipv6.text_to_bin(ip_address))
        eq_(len(buf), pack_len)
        print(res)

        # checksum
        ph = struct.pack('!16s16sI3xB',
                         addrconv.ipv6.text_to_bin(src_ip),
                         addrconv.ipv6.text_to_bin(dst_ip),
                         pack_len, inet.IPPROTO_VRRP)
        s = packet_utils.checksum(ph + buf)
        eq_(0, s)

    @raises(Exception)
    def test_malformed_vrrpv3(self):
        m_short_buf = self.buf[1:vrrp.vrrpv3._MIN_LEN]
        vrrp.vrrp.parser(m_short_buf)

    def test_create_packet(self):
        primary_ip = '2001:db8:2000::3'
        p0 = self.vrrpv3.create_packet(primary_ip)
        p0.serialize()
        print(len(p0.data), p0.data)
        p1 = packet.Packet(six.binary_type(p0.data))
        p1.serialize()
        print(len(p0.data), p0.data)
        print(len(p1.data), p1.data)
        eq_(p0.data, p1.data)

    def test_to_string(self):
        vrrpv3_values = {'version': self.version,
                         'type': self.type_,
                         'vrid': self.vrid,
                         'priority': self.priority,
                         'count_ip': self.count_ip,
                         'max_adver_int': self.max_adver_int,
                         'checksum': self.vrrpv3.checksum,
                         'ip_addresses': [self.ip_address],
                         'auth_type': None,
                         'auth_data': None,
                         'identification': self.vrrpv3.identification}
        _vrrpv3_str = ','.join(['%s=%s' % (k, repr(vrrpv3_values[k]))
                                for k, v in inspect.getmembers(self.vrrpv3)
                                if k in vrrpv3_values])
        vrrpv3_str = '%s(%s)' % (vrrp.vrrpv3.__name__, _vrrpv3_str)

        eq_(str(self.vrrpv3), vrrpv3_str)
        eq_(repr(self.vrrpv3), vrrpv3_str)
