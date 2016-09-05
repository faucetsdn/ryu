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

import unittest
import logging
try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3

from nose.tools import raises

from ryu.services.protocols.bgp import bgpspeaker


LOG = logging.getLogger(__name__)


class Test_BGPSpeaker(unittest.TestCase):
    """
    Test case for bgp.bgpspeaker.BGPSpeaker
    """

    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_add_mac_ip_adv(self, mock_call):
        # Prepare test data
        route_type = bgpspeaker.EVPN_MAC_IP_ADV_ROUTE
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'
        next_hop = '10.0.0.1'
        expected_kwargs = {
            'route_type': route_type,
            'route_dist': route_dist,
            'esi': esi,
            'ethernet_tag_id': ethernet_tag_id,
            'mac_addr': mac_addr,
            'ip_addr': ip_addr,
            'next_hop': next_hop,
        }

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_add(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
            next_hop=next_hop,
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.add_local', **expected_kwargs)

    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_add_mac_ip_adv_vni(self, mock_call):
        # Prepare test data
        route_type = bgpspeaker.EVPN_MAC_IP_ADV_ROUTE
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'
        vni = 500
        next_hop = '10.0.0.1'
        tunnel_type = bgpspeaker.TUNNEL_TYPE_VXLAN
        expected_kwargs = {
            'route_type': route_type,
            'route_dist': route_dist,
            'esi': esi,
            'ethernet_tag_id': ethernet_tag_id,
            'mac_addr': mac_addr,
            'ip_addr': ip_addr,
            'vni': vni,
            'next_hop': next_hop,
            'tunnel_type': tunnel_type,
        }

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_add(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
            vni=vni,
            next_hop=next_hop,
            tunnel_type=tunnel_type,
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.add_local', **expected_kwargs)

    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_add_multicast_etag(self, mock_call):
        # Prepare test data
        route_type = bgpspeaker.EVPN_MULTICAST_ETAG_ROUTE
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'
        next_hop = '10.0.0.1'
        expected_kwargs = {
            'route_type': route_type,
            'route_dist': route_dist,
            # 'esi': esi,  # should be ignored
            'ethernet_tag_id': ethernet_tag_id,
            # 'mac_addr': mac_addr,  # should be ignored
            'ip_addr': ip_addr,
            'next_hop': next_hop,
        }

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_add(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
            next_hop=next_hop,
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.add_local', **expected_kwargs)

    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_add_multicast_etag_no_next_hop(self, mock_call):
        # Prepare test data
        route_type = bgpspeaker.EVPN_MULTICAST_ETAG_ROUTE
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'
        next_hop = '0.0.0.0'  # the default value
        expected_kwargs = {
            'route_type': route_type,
            'route_dist': route_dist,
            # 'esi': esi,  # should be ignored
            'ethernet_tag_id': ethernet_tag_id,
            # 'mac_addr': mac_addr,  # should be ignored
            'ip_addr': ip_addr,
            'next_hop': next_hop,
        }

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_add(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
            # next_hop=next_hop,  # omitted
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.add_local', **expected_kwargs)

    @raises(ValueError)
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_add_invalid_route_type(self, mock_call):
        # Prepare test data
        route_type = 'foobar'  # Invalid EVPN route type
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'
        next_hop = '10.0.0.1'

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_add(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
            next_hop=next_hop,
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.add_local', 'Invalid arguments detected')

    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_del_mac_ip_adv(self, mock_call):
        # Prepare test data
        route_type = bgpspeaker.EVPN_MAC_IP_ADV_ROUTE
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'
        expected_kwargs = {
            'route_type': route_type,
            'route_dist': route_dist,
            'esi': esi,
            'ethernet_tag_id': ethernet_tag_id,
            'mac_addr': mac_addr,
            'ip_addr': ip_addr,
        }

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_del(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.delete_local', **expected_kwargs)

    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_del_multicast_etag(self, mock_call):
        # Prepare test data
        route_type = bgpspeaker.EVPN_MULTICAST_ETAG_ROUTE
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'
        expected_kwargs = {
            'route_type': route_type,
            'route_dist': route_dist,
            # 'esi': esi,  # should be ignored
            'ethernet_tag_id': ethernet_tag_id,
            # 'mac_addr': mac_addr,  # should be ignored
            'ip_addr': ip_addr,
        }

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_del(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.delete_local', **expected_kwargs)

    @raises(ValueError)
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker.__init__',
                mock.MagicMock(return_value=None))
    @mock.patch('ryu.services.protocols.bgp.bgpspeaker.call')
    def test_evpn_prefix_del_invalid_route_type(self, mock_call):
        # Prepare test data
        route_type = 'foobar'  # Invalid EVPN route type
        route_dist = '65000:100'
        esi = 0  # denotes single-homed
        ethernet_tag_id = 200
        mac_addr = 'aa:bb:cc:dd:ee:ff'
        ip_addr = '192.168.0.1'

        # Test
        speaker = bgpspeaker.BGPSpeaker(65000, '10.0.0.1')
        speaker.evpn_prefix_del(
            route_type=route_type,
            route_dist=route_dist,
            esi=esi,
            ethernet_tag_id=ethernet_tag_id,
            mac_addr=mac_addr,
            ip_addr=ip_addr,
        )

        # Check
        mock_call.assert_called_with(
            'evpn_prefix.delete_local', 'Invalid arguments detected')
