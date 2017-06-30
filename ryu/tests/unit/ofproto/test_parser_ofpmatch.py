# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from __future__ import print_function

try:
    # Python 3
    from functools import reduce
except ImportError:
    # Python 2
    pass

import six
import unittest
from nose.tools import eq_
from nose.tools import ok_

from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_4_parser
from ryu.ofproto import ofproto_v1_5_parser
from ryu.tests import test_lib


class Test_Parser_OFPMatch(unittest.TestCase):
    _ofp = {ofproto_v1_2_parser: ofproto_v1_2,
            ofproto_v1_3_parser: ofproto_v1_3,
            ofproto_v1_4_parser: ofproto_v1_4,
            ofproto_v1_5_parser: ofproto_v1_5}

    def __init__(self, methodName):
        print('init %s' % methodName)
        super(Test_Parser_OFPMatch, self).__init__(methodName)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _test(self, name, ofpp, d, domask):
        if domask:
            d = dict(self._ofp[ofpp].oxm_normalize_user(k, uv)
                     for (k, uv)
                     in d.items())
        match = ofpp.OFPMatch(**d)
        b = bytearray()
        match.serialize(b, 0)
        match2 = match.parser(six.binary_type(b), 0)
        for k, v in d.items():
            ok_(k in match)
            ok_(k in match2)
            eq_(match[k], v)
            eq_(match2[k], v)
        for k, v in match.iteritems():
            ok_(k in d)
            eq_(d[k], v)
        for k, v in match2.iteritems():
            ok_(k in d)
            eq_(d[k], v)


def _add_tests():
    import functools
    import itertools

    class Field(object):
        @classmethod
        def generate_mask(cls):
            return list(cls.generate())[1]

    class Int1(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0xff

    class Int2(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x1234
            yield 0xffff

    class Int3(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x123456
            yield 0xffffff

    class Int4(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x12345678
            yield 0xffffffff

    class Int8(Field):
        @staticmethod
        def generate():
            yield 0
            yield 0x123456789abcdef0
            yield 0xffffffffffffffff

    class Mac(Field):
        @staticmethod
        def generate():
            yield '00:00:00:00:00:00'
            yield 'f2:0b:a4:7d:f8:ea'
            yield 'ff:ff:ff:ff:ff:ff'

    class IPv4(Field):
        @staticmethod
        def generate():
            yield '0.0.0.0'
            yield '192.0.2.1'
            yield '255.255.255.255'

    class IPv6(Field):
        @staticmethod
        def generate():
            yield '::'
            yield 'fe80::f00b:a4ff:fed0:3f70'
            yield 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'

    class B64(Field):
        @staticmethod
        def generate():
            yield 'aG9nZWhvZ2U='
            yield 'ZnVnYWZ1Z2E='

    ofpps = [ofproto_v1_2_parser, ofproto_v1_3_parser,
             ofproto_v1_4_parser, ofproto_v1_5_parser]
    common = [
        # OpenFlow Basic
        ('in_port', Int4),
        ('in_phy_port', Int4),
        ('metadata', Int8),
        ('eth_dst', Mac),
        ('eth_src', Mac),
        ('eth_type', Int2),
        ('vlan_vid', Int2),
        ('vlan_pcp', Int1),
        ('ip_dscp', Int1),
        ('ip_ecn', Int1),
        ('ip_proto', Int1),
        ('ipv4_src', IPv4),
        ('ipv4_dst', IPv4),
        ('tcp_src', Int2),
        ('tcp_dst', Int2),
        ('udp_src', Int2),
        ('udp_dst', Int2),
        ('sctp_src', Int2),
        ('sctp_dst', Int2),
        ('icmpv4_type', Int1),
        ('icmpv4_code', Int1),
        ('arp_op', Int2),
        ('arp_spa', IPv4),
        ('arp_tpa', IPv4),
        ('arp_sha', Mac),
        ('arp_tha', Mac),
        ('ipv6_src', IPv6),
        ('ipv6_dst', IPv6),
        ('ipv6_flabel', Int4),
        ('icmpv6_type', Int1),
        ('icmpv6_code', Int1),
        ('ipv6_nd_target', IPv6),
        ('ipv6_nd_sll', Mac),
        ('ipv6_nd_tll', Mac),
        ('mpls_label', Int4),
        ('mpls_tc', Int1),
        # Old ONF Experimenter --> OpenFlow Basic (OF1.4+)
        ('pbb_uca', Int1),
        # ONF Experimenter --> OpenFlow Basic (OF1.5+)
        ('tcp_flags', Int2),
        ('actset_output', Int4),
        # Nicira Experimenter
        ('eth_dst_nxm', Mac),
        ('eth_src_nxm', Mac),
        ('tunnel_id_nxm', Int8),
        ('tun_ipv4_src', IPv4),
        ('tun_ipv4_dst', IPv4),
        ('pkt_mark', Int4),
        ('conj_id', Int4),
        ('tun_ipv6_src', IPv6),
        ('tun_ipv6_dst', IPv6),
        ('_dp_hash', Int4),
        ('reg0', Int4),
        ('reg1', Int4),
        ('reg2', Int4),
        ('reg3', Int4),
        ('reg4', Int4),
        ('reg5', Int4),
        ('reg6', Int4),
        ('reg7', Int4),
        # Common Experimenter
        ('field_100', B64),
    ]
    L = {}
    L[ofproto_v1_2_parser] = common + [
        # OF1.2 doesn't have OXM_OF_PBB_ISID.
        #    OFPXMC_OPENFLOW_BASIC = 0x8000
        #    OXM_OF_PBB_ISID = 37
        #    (OFPXMC_OPENFLOW_BASIC << 7) + OXM_OF_PBB_ISID == 4194341
        ('field_4194341', B64),
    ]
    L[ofproto_v1_3_parser] = common + [
        # OpenFlow Basic (OF1.3+)
        ('mpls_bos', Int1),
        ('pbb_isid', Int3),
        ('tunnel_id', Int8),
        ('ipv6_exthdr', Int2),
    ]
    L[ofproto_v1_4_parser] = L[ofproto_v1_3_parser]
    L[ofproto_v1_5_parser] = L[ofproto_v1_4_parser] + [
        # OpenFlow Basic (OF1.5+)
        ('packet_type', Int4),
    ]

    def flatten_one(l, i):
        if isinstance(i, tuple):
            return l + flatten(i)
        else:
            return l + [i]
    flatten = lambda l: reduce(flatten_one, l, [])

    for ofpp in ofpps:
        for n in range(1, 3):
            for C in itertools.combinations(L[ofpp], n):
                l = [1]
                keys = []
                clss = []
                for (k, cls) in C:
                    l = itertools.product(l, cls.generate())
                    keys.append(k)
                    clss.append(cls)
                l = [flatten(x)[1:] for x in l]
                for domask in [True, False]:
                    for values in l:
                        if domask:
                            values = [(value, cls.generate_mask())
                                      for (cls, value)
                                      in zip(clss, values)]
                        d = dict(zip(keys, values))
                        mod = ofpp.__name__.split('.')[-1]
                        method_name = 'test_' + mod
                        if domask:
                            method_name += '_mask'
                        for k in sorted(dict(d).keys()):
                            method_name += '_' + str(k)
                            method_name += '_' + str(d[k])
                        method_name = method_name.replace(':', '_')
                        method_name = method_name.replace('.', '_')
                        method_name = method_name.replace('(', '_')
                        method_name = method_name.replace(')', '_')
                        method_name = method_name.replace(',', '_')
                        method_name = method_name.replace("'", '_')
                        method_name = method_name.replace(' ', '_')

                        def _run(self, name, ofpp, d, domask):
                            print('processing %s ...' % name)
                            if six.PY3:
                                self._test(self, name, ofpp, d, domask)
                            else:
                                self._test(name, ofpp, d, domask)
                        print('adding %s ...' % method_name)
                        f = functools.partial(_run, name=method_name,
                                              ofpp=ofpp, d=d, domask=domask)
                        test_lib.add_method(Test_Parser_OFPMatch,
                                            method_name, f)

_add_tests()
