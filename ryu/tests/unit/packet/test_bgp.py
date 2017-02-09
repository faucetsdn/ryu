# Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import logging
import os
import sys

import unittest
from nose.tools import eq_
from nose.tools import ok_

from ryu.utils import binary_str
from ryu.lib import pcaplib
from ryu.lib.packet import packet
from ryu.lib.packet import bgp
from ryu.lib.packet import afi
from ryu.lib.packet import safi


LOG = logging.getLogger(__name__)

BGP4_PACKET_DATA_DIR = os.path.join(
    os.path.dirname(sys.modules[__name__].__file__), '../../packet_data/bgp4/')

PMSI_TYPE_NO_TUNNEL_INFORMATION_PRESENT = (
    bgp.BGPPathAttributePmsiTunnel.TYPE_NO_TUNNEL_INFORMATION_PRESENT
)
PMSI_TYPE_INGRESS_REPLICATION = (
    bgp.BGPPathAttributePmsiTunnel.TYPE_INGRESS_REPLICATION
)


class Test_bgp(unittest.TestCase):
    """ Test case for ryu.lib.packet.bgp
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_open1(self):
        msg = bgp.BGPOpen(my_as=30000, bgp_identifier='192.0.2.1')
        binmsg = msg.serialize()
        msg2, _, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 29)
        eq_(rest, b'')

    def test_open2(self):
        opt_param = [bgp.BGPOptParamCapabilityUnknown(cap_code=200,
                                                      cap_value=b'hoge'),
                     bgp.BGPOptParamCapabilityGracefulRestart(flags=0,
                                                              time=120,
                                                              tuples=[]),
                     bgp.BGPOptParamCapabilityRouteRefresh(),
                     bgp.BGPOptParamCapabilityCiscoRouteRefresh(),
                     bgp.BGPOptParamCapabilityMultiprotocol(
                         afi=afi.IP, safi=safi.MPLS_VPN),
                     bgp.BGPOptParamCapabilityCarryingLabelInfo(),
                     bgp.BGPOptParamCapabilityFourOctetAsNumber(
                         as_number=1234567),
                     bgp.BGPOptParamUnknown(type_=99, value=b'fuga')]
        msg = bgp.BGPOpen(my_as=30000, bgp_identifier='192.0.2.2',
                          opt_param=opt_param)
        binmsg = msg.serialize()
        msg2, _, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        ok_(len(msg) > 29)
        eq_(rest, b'')

    def test_update1(self):
        msg = bgp.BGPUpdate()
        binmsg = msg.serialize()
        msg2, _, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 23)
        eq_(rest, b'')

    def test_update2(self):
        withdrawn_routes = [bgp.BGPWithdrawnRoute(length=0,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=1,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=3,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=7,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=32,
                                                  addr='192.0.2.13')]
        mp_nlri = [
            bgp.LabelledVPNIPAddrPrefix(24, '192.0.9.0',
                                        route_dist='100:100',
                                        labels=[1, 2, 3]),
            bgp.LabelledVPNIPAddrPrefix(26, '192.0.10.192',
                                        route_dist='10.0.0.1:10000',
                                        labels=[5, 6, 7, 8]),
        ]
        mp_nlri2 = [
            bgp.LabelledIPAddrPrefix(24, '192.168.0.0', labels=[1, 2, 3])
        ]
        mp_nlri_v6 = [
            bgp.LabelledVPNIP6AddrPrefix(64, '2001:db8:1111::',
                                         route_dist='200:200',
                                         labels=[1, 2, 3]),
            bgp.LabelledVPNIP6AddrPrefix(64, '2001:db8:2222::',
                                         route_dist='10.0.0.1:10000',
                                         labels=[5, 6, 7, 8]),
        ]
        mp_nlri2_v6 = [
            bgp.LabelledIP6AddrPrefix(64, '2001:db8:3333::', labels=[1, 2, 3])
        ]
        communities = [
            bgp.BGP_COMMUNITY_NO_EXPORT,
            bgp.BGP_COMMUNITY_NO_ADVERTISE,
        ]
        ecommunities = [
            bgp.BGPTwoOctetAsSpecificExtendedCommunity(
                subtype=1, as_number=65500, local_administrator=3908876543),
            bgp.BGPFourOctetAsSpecificExtendedCommunity(
                subtype=2, as_number=10000000, local_administrator=59876),
            bgp.BGPIPv4AddressSpecificExtendedCommunity(
                subtype=3, ipv4_address='192.0.2.1',
                local_administrator=65432),
            bgp.BGPOpaqueExtendedCommunity(subtype=13, opaque=b'abcdef'),
            bgp.BGPEncapsulationExtendedCommunity(
                subtype=0x0c, tunnel_type=10),
            bgp.BGPEvpnMacMobilityExtendedCommunity(
                subtype=0, flags=0xff, sequence_number=0x11223344),
            bgp.BGPEvpnEsiLabelExtendedCommunity(
                subtype=1, flags=0xff, label=b'\xFF\xFF\xFF'),
            bgp.BGPEvpnEsiLabelExtendedCommunity(
                subtype=1, flags=0xff, mpls_label=0xfffff),
            bgp.BGPEvpnEsiLabelExtendedCommunity(
                subtype=1, flags=0xff, vni=0xffffff),
            bgp.BGPEvpnEsImportRTExtendedCommunity(
                subtype=2, es_import="aa:bb:cc:dd:ee:ff"),
            bgp.BGPUnknownExtendedCommunity(type_=99, value=b'abcdefg'),
        ]
        path_attributes = [
            bgp.BGPPathAttributeOrigin(value=1),
            bgp.BGPPathAttributeAsPath(value=[[1000], {1001, 1002},
                                              [1003, 1004]]),
            bgp.BGPPathAttributeNextHop(value='192.0.2.199'),
            bgp.BGPPathAttributeMultiExitDisc(value=2000000000),
            bgp.BGPPathAttributeLocalPref(value=1000000000),
            bgp.BGPPathAttributeAtomicAggregate(),
            bgp.BGPPathAttributeAggregator(as_number=40000,
                                           addr='192.0.2.99'),
            bgp.BGPPathAttributeCommunities(communities=communities),
            bgp.BGPPathAttributeOriginatorId(value='10.1.1.1'),
            bgp.BGPPathAttributeClusterList(value=['1.1.1.1', '2.2.2.2']),
            bgp.BGPPathAttributeExtendedCommunities(communities=ecommunities),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_NO_TUNNEL_INFORMATION_PRESENT,
                label=b'\xFF\xFF\xFF'),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_NO_TUNNEL_INFORMATION_PRESENT,
                tunnel_id=None),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_INGRESS_REPLICATION,
                mpls_label=0xfffff,
                tunnel_id=bgp.PmsiTunnelIdIngressReplication(
                    tunnel_endpoint_ip="1.1.1.1")),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_INGRESS_REPLICATION,
                vni=0xffffff,
                tunnel_id=bgp.PmsiTunnelIdIngressReplication(
                    tunnel_endpoint_ip="aa:bb:cc::dd:ee:ff")),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=2,
                label=b'\xFF\xFF\xFF',
                tunnel_id=bgp.PmsiTunnelIdUnknown(value=b'test')),
            bgp.BGPPathAttributeAs4Path(value=[[1000000], {1000001, 1002},
                                               [1003, 1000004]]),
            bgp.BGPPathAttributeAs4Aggregator(as_number=100040000,
                                              addr='192.0.2.99'),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP, safi=safi.MPLS_VPN,
                                            next_hop='1.1.1.1',
                                            nlri=mp_nlri),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP, safi=safi.MPLS_LABEL,
                                            next_hop='1.1.1.1',
                                            nlri=mp_nlri2),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP6, safi=safi.MPLS_VPN,
                                            next_hop=['2001:db8::1'],
                                            nlri=mp_nlri_v6),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP6, safi=safi.MPLS_LABEL,
                                            next_hop=['2001:db8::1',
                                                      'fe80::1'],
                                            nlri=mp_nlri2_v6),
            bgp.BGPPathAttributeMpUnreachNLRI(afi=afi.IP, safi=safi.MPLS_VPN,
                                              withdrawn_routes=mp_nlri),
            bgp.BGPPathAttributeUnknown(flags=0, type_=100, value=300 * b'bar')
        ]
        nlri = [
            bgp.BGPNLRI(length=24, addr='203.0.113.1'),
            bgp.BGPNLRI(length=16, addr='203.0.113.0')
        ]
        msg = bgp.BGPUpdate(withdrawn_routes=withdrawn_routes,
                            path_attributes=path_attributes,
                            nlri=nlri)
        binmsg = msg.serialize()
        msg2, _, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        ok_(len(msg) > 23)
        eq_(rest, b'')

    def test_keepalive(self):
        msg = bgp.BGPKeepAlive()
        binmsg = msg.serialize()
        msg2, _, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 19)
        eq_(rest, b'')

    def test_notification(self):
        data = b'hoge'
        msg = bgp.BGPNotification(error_code=1, error_subcode=2, data=data)
        binmsg = msg.serialize()
        msg2, _, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 21 + len(data))
        eq_(rest, b'')

    def test_route_refresh(self):
        msg = bgp.BGPRouteRefresh(afi=afi.IP, safi=safi.MPLS_VPN)
        binmsg = msg.serialize()
        msg2, _, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 23)
        eq_(rest, b'')

    def test_stream_parser(self):
        msgs = [
            bgp.BGPNotification(error_code=1, error_subcode=2, data=b'foo'),
            bgp.BGPNotification(error_code=3, error_subcode=4, data=b'bar'),
            bgp.BGPNotification(error_code=5, error_subcode=6, data=b'baz'),
        ]
        binmsgs = b''.join([bytes(msg.serialize()) for msg in msgs])
        sp = bgp.StreamParser()
        results = []
        for b in binmsgs:
            for m in sp.parse(b):
                results.append(m)
        eq_(str(results), str(msgs))

    def test_parser(self):
        files = [
            'bgp4-open',
            'bgp4-update',
            'bgp4-update_ipv6',
            'bgp4-update_vpnv6',
            'bgp4-keepalive',
            'evpn_esi_arbitrary',
            'evpn_esi_lacp',
            'evpn_esi_l2_bridge',
            'evpn_esi_mac_base',
            'evpn_esi_router_id',
            'evpn_esi_as_based',
            'evpn_nlri_eth_a-d',
            'evpn_nlri_mac_ip_ad',
            'evpn_nlri_inc_multi_eth_tag',
            'evpn_nlri_eth_seg',
            'evpn_nlri_ip_prefix',
            'flowspec_nlri_ipv4',
            'flowspec_nlri_vpn4',
            'flowspec_action_traffic_rate',
            'flowspec_action_traffic_action',
            'flowspec_action_redirect',
            'flowspec_action_traffic_marking',
        ]

        for f in files:
            LOG.debug('*** testing %s ...', f)
            for _, buf in pcaplib.Reader(
                    open(BGP4_PACKET_DATA_DIR + f + '.pcap', 'rb')):
                # Checks if BGP message can be parsed as expected.
                pkt = packet.Packet(buf)
                ok_(isinstance(pkt.protocols[-1], bgp.BGPMessage),
                    'Failed to parse BGP message: %s' % pkt)

                # Checks if BGP message can be serialized as expected.
                pkt.serialize()
                eq_(buf, pkt.data,
                    "b'%s' != b'%s'" % (binary_str(buf), binary_str(pkt.data)))

    def test_json1(self):
        opt_param = [bgp.BGPOptParamCapabilityUnknown(cap_code=200,
                                                      cap_value=b'hoge'),
                     bgp.BGPOptParamCapabilityRouteRefresh(),
                     bgp.BGPOptParamCapabilityMultiprotocol(
                         afi=afi.IP, safi=safi.MPLS_VPN),
                     bgp.BGPOptParamCapabilityFourOctetAsNumber(
                         as_number=1234567),
                     bgp.BGPOptParamUnknown(type_=99, value=b'fuga')]
        msg1 = bgp.BGPOpen(my_as=30000, bgp_identifier='192.0.2.2',
                           opt_param=opt_param)
        jsondict = msg1.to_jsondict()
        msg2 = bgp.BGPOpen.from_jsondict(jsondict['BGPOpen'])
        eq_(str(msg1), str(msg2))

    def test_json2(self):
        withdrawn_routes = [bgp.BGPWithdrawnRoute(length=0,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=1,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=3,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=7,
                                                  addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=32,
                                                  addr='192.0.2.13')]
        mp_nlri = [
            bgp.LabelledVPNIPAddrPrefix(24, '192.0.9.0',
                                        route_dist='100:100',
                                        labels=[1, 2, 3]),
            bgp.LabelledVPNIPAddrPrefix(26, '192.0.10.192',
                                        route_dist='10.0.0.1:10000',
                                        labels=[5, 6, 7, 8]),
        ]
        mp_nlri2 = [
            bgp.LabelledIPAddrPrefix(24, '192.168.0.0', labels=[1, 2, 3])
        ]
        mp_nlri_v6 = [
            bgp.LabelledVPNIP6AddrPrefix(64, '2001:db8:1111::',
                                         route_dist='200:200',
                                         labels=[1, 2, 3]),
            bgp.LabelledVPNIP6AddrPrefix(64, '2001:db8:2222::',
                                         route_dist='10.0.0.1:10000',
                                         labels=[5, 6, 7, 8]),
        ]
        mp_nlri2_v6 = [
            bgp.LabelledIP6AddrPrefix(64, '2001:db8:3333::', labels=[1, 2, 3])
        ]
        communities = [
            bgp.BGP_COMMUNITY_NO_EXPORT,
            bgp.BGP_COMMUNITY_NO_ADVERTISE,
        ]
        ecommunities = [
            bgp.BGPTwoOctetAsSpecificExtendedCommunity(
                subtype=1, as_number=65500, local_administrator=3908876543),
            bgp.BGPFourOctetAsSpecificExtendedCommunity(
                subtype=2, as_number=10000000, local_administrator=59876),
            bgp.BGPIPv4AddressSpecificExtendedCommunity(
                subtype=3, ipv4_address='192.0.2.1',
                local_administrator=65432),
            bgp.BGPOpaqueExtendedCommunity(subtype=13, opaque=b'abcdef'),
            bgp.BGPEncapsulationExtendedCommunity(
                subtype=0x0c, tunnel_type=10),
            bgp.BGPEvpnMacMobilityExtendedCommunity(
                subtype=0, flags=0xff, sequence_number=0x11223344),
            bgp.BGPEvpnEsiLabelExtendedCommunity(
                subtype=1, flags=0xff, label=b'\xFF\xFF\xFF'),
            bgp.BGPEvpnEsiLabelExtendedCommunity(
                subtype=1, flags=0xff, mpls_label=0xfffff),
            bgp.BGPEvpnEsiLabelExtendedCommunity(
                subtype=1, flags=0xff, vni=0xffffff),
            bgp.BGPEvpnEsImportRTExtendedCommunity(
                subtype=2, es_import="aa:bb:cc:dd:ee:ff"),
            bgp.BGPUnknownExtendedCommunity(type_=99, value=b'abcdefg'),
        ]
        path_attributes = [
            bgp.BGPPathAttributeOrigin(value=1),
            bgp.BGPPathAttributeAsPath(value=[[1000], {1001, 1002},
                                              [1003, 1004]]),
            bgp.BGPPathAttributeNextHop(value='192.0.2.199'),
            bgp.BGPPathAttributeMultiExitDisc(value=2000000000),
            bgp.BGPPathAttributeLocalPref(value=1000000000),
            bgp.BGPPathAttributeAtomicAggregate(),
            bgp.BGPPathAttributeAggregator(as_number=40000,
                                           addr='192.0.2.99'),
            bgp.BGPPathAttributeCommunities(communities=communities),
            bgp.BGPPathAttributeExtendedCommunities(communities=ecommunities),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_NO_TUNNEL_INFORMATION_PRESENT,
                label=b'\xFF\xFF\xFF'),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_NO_TUNNEL_INFORMATION_PRESENT,
                tunnel_id=None),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_INGRESS_REPLICATION,
                mpls_label=0xfffff,
                tunnel_id=bgp.PmsiTunnelIdIngressReplication(
                    tunnel_endpoint_ip="1.1.1.1")),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=PMSI_TYPE_INGRESS_REPLICATION,
                vni=0xffffff,
                tunnel_id=bgp.PmsiTunnelIdIngressReplication(
                    tunnel_endpoint_ip="aa:bb:cc::dd:ee:ff")),
            bgp.BGPPathAttributePmsiTunnel(
                pmsi_flags=1,
                tunnel_type=2,
                label=b'\xFF\xFF\xFF',
                tunnel_id=bgp.PmsiTunnelIdUnknown(value=b'test')),
            bgp.BGPPathAttributeAs4Path(value=[[1000000], {1000001, 1002},
                                               [1003, 1000004]]),
            bgp.BGPPathAttributeAs4Aggregator(as_number=100040000,
                                              addr='192.0.2.99'),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP, safi=safi.MPLS_VPN,
                                            next_hop='1.1.1.1',
                                            nlri=mp_nlri),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP, safi=safi.MPLS_LABEL,
                                            next_hop='1.1.1.1',
                                            nlri=mp_nlri2),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP6, safi=safi.MPLS_VPN,
                                            next_hop=['2001:db8::1'],
                                            nlri=mp_nlri_v6),
            bgp.BGPPathAttributeMpReachNLRI(afi=afi.IP6, safi=safi.MPLS_LABEL,
                                            next_hop=['2001:db8::1',
                                                      'fe80::1'],
                                            nlri=mp_nlri2_v6),
            bgp.BGPPathAttributeMpUnreachNLRI(afi=afi.IP, safi=safi.MPLS_VPN,
                                              withdrawn_routes=mp_nlri),
            bgp.BGPPathAttributeUnknown(flags=0, type_=100, value=300 * b'bar')
        ]
        nlri = [
            bgp.BGPNLRI(length=24, addr='203.0.113.1'),
            bgp.BGPNLRI(length=16, addr='203.0.113.0')
        ]
        msg1 = bgp.BGPUpdate(withdrawn_routes=withdrawn_routes,
                             path_attributes=path_attributes,
                             nlri=nlri)
        jsondict = msg1.to_jsondict()
        msg2 = bgp.BGPUpdate.from_jsondict(jsondict['BGPUpdate'])
        eq_(str(msg1), str(msg2))
