# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

import logging
import unittest

from nose.tools import eq_, ok_

from ryu.services.protocols.bgp.utils import validation


LOG = logging.getLogger(__name__)


class Test_Utils_Validation(unittest.TestCase):
    """
    Test case for ryu.services.protocols.bgp.utils.validation
    """

    def test_is_valid_mac(self):
        ok_(validation.is_valid_mac('aa:bb:cc:dd:ee:ff'))

    def test_is_valid_mac_hyphenation(self):
        ok_(validation.is_valid_mac('aa-bb-cc-dd-ee-ff'))

    def test_is_valid_mac_short(self):
        eq_(False, validation.is_valid_mac('aa:bb:cc:dd:ee'))

    def test_is_valid_ip_prefix(self):
        ok_(validation.is_valid_ip_prefix(24, 32))

    def test_is_valid_ip_prefix_str(self):
        ok_(validation.is_valid_ip_prefix('24', 32))

    def test_is_valid_ip_prefix_not_digit(self):
        eq_(False, validation.is_valid_ip_prefix('foo', 32))

    def test_is_valid_ip_prefix_over(self):
        eq_(False, validation.is_valid_ip_prefix(100, 32))

    def test_is_valid_ipv4(self):
        ok_(validation.is_valid_ipv4('10.0.0.1'))

    def test_is_valid_ipv4_not_dot(self):
        eq_(False, validation.is_valid_ipv4('192:168:0:1'))

    def test_is_valid_ipv4_prefix(self):
        ok_(validation.is_valid_ipv4_prefix('10.0.0.1/24'))

    def test_is_valid_ipv4_prefix_not_str(self):
        eq_(False, validation.is_valid_ipv4_prefix(1234))

    def test_is_valid_ipv4_prefix_without_prefix(self):
        eq_(False, validation.is_valid_ipv4_prefix('10.0.0.1'))

    def test_is_valid_ipv4_prefix_invalid_addr(self):
        eq_(False, validation.is_valid_ipv4_prefix('xxx.xxx.xxx.xxx/24'))

    def test_is_valid_ipv6(self):
        ok_(validation.is_valid_ipv6('fe80::0011:aabb:ccdd:eeff'))

    def test_is_valid_ipv6_not_colon(self):
        eq_(False, validation.is_valid_ipv6('fe80--0011-aabb-ccdd-eeff'))

    def test_is_valid_ipv6_prefix(self):
        ok_(validation.is_valid_ipv6_prefix('fe80::0011:aabb:ccdd:eeff/64'))

    def test_is_valid_ipv6_prefix_not_str(self):
        eq_(False, validation.is_valid_ipv6_prefix(1234))

    def test_is_valid_ipv6_prefix_without_prefix(self):
        eq_(False,
            validation.is_valid_ipv6_prefix('fe80::0011:aabb:ccdd:eeff'))

    def test_is_valid_ipv6_prefix_invalid_addr(self):
        eq_(False, validation.is_valid_ipv6_prefix('xxxx::xxxx/64'))

    def test_is_valid_old_asn(self):
        ok_(validation.is_valid_old_asn(65000))

    def test_is_valid_old_asn_negative(self):
        eq_(False, validation.is_valid_old_asn(-1))

    def test_is_valid_old_asn_over(self):
        eq_(False, validation.is_valid_old_asn(0xffff + 1))

    def test_is_valid_asn(self):
        ok_(validation.is_valid_asn(6553800))

    def test_is_valid_asn_old(self):
        ok_(validation.is_valid_asn(65000))

    def test_is_valid_asn_negative(self):
        eq_(False, validation.is_valid_asn(-1))

    def test_is_valid_asn_over(self):
        eq_(False, validation.is_valid_asn(0xffffffff + 1))

    def test_is_valid_vpnv4_prefix(self):
        ok_(validation.is_valid_vpnv4_prefix('100:200:10.0.0.1/24'))

    def test_is_valid_vpnv4_prefix_not_str(self):
        eq_(False, validation.is_valid_vpnv4_prefix(1234))

    def test_is_valid_vpnv4_prefix_short_rd(self):
        eq_(False, validation.is_valid_vpnv4_prefix('100:10.0.0.1/24'))

    def test_is_valid_vpnv4_prefix_invalid_rd(self):
        eq_(False, validation.is_valid_vpnv4_prefix('foo:bar:10.0.0.1/24'))

    def test_is_valid_vpnv6_prefix(self):
        ok_(validation.is_valid_vpnv6_prefix(
            '100:200:fe80::0011:aabb:ccdd:eeff/64'))

    def test_is_valid_vpnv6_prefix_not_str(self):
        eq_(False, validation.is_valid_vpnv6_prefix(1234))

    def test_is_valid_vpnv6_prefix_short_rd(self):
        eq_(False, validation.is_valid_vpnv6_prefix('100:eeff/64'))

    def test_is_valid_vpnv6_prefix_invalid_rd(self):
        eq_(False, validation.is_valid_vpnv6_prefix('foo:bar:10.0.0.1/24'))

    def test_is_valid_med(self):
        ok_(validation.is_valid_med(100))

    def test_is_valid_med_not_num(self):
        eq_(False, validation.is_valid_med('foo'))

    def test_is_valid_med_negative(self):
        eq_(False, validation.is_valid_med(-1))

    def test_is_valid_med_over(self):
        eq_(False, validation.is_valid_med(0xffffffff + 1))

    def test_is_valid_mpls_label(self):
        ok_(validation.is_valid_mpls_label(100))

    def test_is_valid_mpls_label_reserved(self):
        eq_(False, validation.is_valid_mpls_label(4))

    def test_is_valid_mpls_label_not_num(self):
        eq_(False, validation.is_valid_mpls_label('foo'))

    def test_is_valid_mpls_label_negative(self):
        eq_(False, validation.is_valid_mpls_label(-1))

    def test_is_valid_mpls_label_over(self):
        eq_(False, validation.is_valid_mpls_label(0x100000 + 1))

    def test_is_valid_mpls_labels(self):
        ok_(validation.is_valid_mpls_labels([100, 200]))

    def test_is_valid_mpls_labels_not_list(self):
        eq_(False, validation.is_valid_mpls_labels(100))

    def test_is_valid_mpls_labels_with_invalid_label(self):
        eq_(False, validation.is_valid_mpls_labels(['foo', 200]))

    def test_is_valid_route_dist(self):
        ok_(validation.is_valid_route_dist('65000:222'))

    def test_is_valid_route_dist_ipv4_based(self):
        ok_(validation.is_valid_route_dist('10.0.0.1:333'))

    def test_is_valid_route_not_str(self):
        eq_(False, validation.is_valid_route_dist(65000))

    def test_is_valid_route_dist_short(self):
        eq_(False, validation.is_valid_route_dist('65000'))

    def test_is_valid_route_dist_invalid_ipv4_addr(self):
        eq_(False, validation.is_valid_route_dist('xxx.xxx.xxx.xxx:333'))

    def test_is_valid_esi(self):
        ok_(validation.is_valid_esi(100))

    def test_is_valid_esi_not_int(self):
        eq_(False, validation.is_valid_esi('foo'))

    def test_is_valid_ethernet_tag_id(self):
        ok_(validation.is_valid_ethernet_tag_id(100))

    def test_is_valid_ethernet_tag_id_not_int(self):
        eq_(False, validation.is_valid_ethernet_tag_id('foo'))

    def test_is_valid_ethernet_tag_id_negative(self):
        eq_(False, validation.is_valid_ethernet_tag_id(-1))

    def test_is_valid_ethernet_tag_id_over(self):
        eq_(False, validation.is_valid_ethernet_tag_id(0xffffffff + 1))

    def test_is_valid_vni(self):
        ok_(validation.is_valid_vni(100))

    def test_is_valid_vni_not_int(self):
        eq_(False, validation.is_valid_vni('foo'))

    def test_is_valid_vni_negative(self):
        eq_(False, validation.is_valid_vni(-1))

    def test_is_valid_vni_over(self):
        eq_(False, validation.is_valid_vni(0xffffff + 1))
