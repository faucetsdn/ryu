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

from collections import OrderedDict
import unittest
import logging
try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3

from nose.tools import ok_, eq_, raises

from ryu.lib.packet.bgp import BGPPathAttributeOrigin
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_IGP
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import IPAddrPrefix
from ryu.lib.packet.bgp import IP6AddrPrefix
from ryu.lib.packet.bgp import EvpnArbitraryEsi
from ryu.lib.packet.bgp import EvpnLACPEsi
from ryu.lib.packet.bgp import EvpnEthernetAutoDiscoveryNLRI
from ryu.lib.packet.bgp import EvpnMacIPAdvertisementNLRI
from ryu.lib.packet.bgp import EvpnInclusiveMulticastEthernetTagNLRI
from ryu.services.protocols.bgp.bgpspeaker import EVPN_MAX_ET
from ryu.services.protocols.bgp.bgpspeaker import ESI_TYPE_LACP
from ryu.services.protocols.bgp.core import BgpCoreError
from ryu.services.protocols.bgp.core_managers import table_manager
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV6
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_L2_EVPN


LOG = logging.getLogger(__name__)


class Test_TableCoreManager(unittest.TestCase):
    """
    Test case for bgp.core_managers.table_manager.TableCoreManager
    """

    @mock.patch(
        'ryu.services.protocols.bgp.core_managers.TableCoreManager.__init__',
        mock.MagicMock(return_value=None))
    def _test_update_vrf_table(self, prefix_inst, route_dist, prefix_str,
                               next_hop, route_family, route_type,
                               is_withdraw=False, **kwargs):
        # Instantiate TableCoreManager
        tbl_mng = table_manager.TableCoreManager(None, None)
        vrf_table_mock = mock.MagicMock()
        tbl_mng._tables = {(route_dist, route_family): vrf_table_mock}

        # Test
        tbl_mng.update_vrf_table(
            route_dist=route_dist,
            prefix=prefix_str,
            next_hop=next_hop,
            route_family=route_family,
            route_type=route_type,
            is_withdraw=is_withdraw,
            **kwargs)

        # Check
        call_args_list = vrf_table_mock.insert_vrf_path.call_args_list
        ok_(len(call_args_list) == 1)  # insert_vrf_path should be called once
        args, kwargs = call_args_list[0]
        ok_(len(args) == 0)  # no positional argument
        eq_(str(prefix_inst), str(kwargs['nlri']))
        eq_(is_withdraw, kwargs['is_withdraw'])
        if is_withdraw:
            eq_(None, kwargs['next_hop'])
            eq_(False, kwargs['gen_lbl'])
        else:
            eq_(next_hop, kwargs['next_hop'])
            eq_(True, kwargs['gen_lbl'])

    def test_update_vrf_table_ipv4(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = '192.168.0.0'
        ip_prefix_len = 24
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        prefix_inst = IPAddrPrefix(ip_prefix_len, ip_network)
        next_hop = '10.0.0.1'
        route_family = VRF_RF_IPV4
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    def test_update_vrf_table_ipv6(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = 'fe80::'
        ip_prefix_len = 64
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        prefix_inst = IP6AddrPrefix(ip_prefix_len, ip_network)
        next_hop = 'fe80::0011:aabb:ccdd:eeff'
        route_family = VRF_RF_IPV6
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    def test_update_vrf_table_l2_evpn_with_esi_int(self):
        # Prepare test data
        route_dist = '65000:100'
        prefix_str = None  # should be ignored
        kwargs = {
            'ethernet_tag_id': 100,
            'mac_addr': 'aa:bb:cc:dd:ee:ff',
            'ip_addr': '192.168.0.1',
            'mpls_labels': [],  # not be used
        }
        esi = EvpnArbitraryEsi(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        prefix_inst = EvpnMacIPAdvertisementNLRI(
            route_dist=route_dist,
            esi=esi,
            **kwargs)
        next_hop = '10.0.0.1'
        route_family = VRF_RF_L2_EVPN
        route_type = EvpnMacIPAdvertisementNLRI.ROUTE_TYPE_NAME
        kwargs['esi'] = 0

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    def test_update_vrf_table_l2_evpn_with_esi_dict(self):
        # Prepare test data
        route_dist = '65000:100'
        prefix_str = None  # should be ignored
        kwargs = {
            'ethernet_tag_id': EVPN_MAX_ET,
        }
        esi = EvpnLACPEsi(mac_addr='aa:bb:cc:dd:ee:ff', port_key=100)
        prefix_inst = EvpnEthernetAutoDiscoveryNLRI(
            route_dist=route_dist,
            esi=esi,
            **kwargs)
        next_hop = '0.0.0.0'
        route_family = VRF_RF_L2_EVPN
        route_type = EvpnEthernetAutoDiscoveryNLRI.ROUTE_TYPE_NAME
        kwargs['esi'] = {
            'type': ESI_TYPE_LACP,
            'mac_addr': 'aa:bb:cc:dd:ee:ff',
            'port_key': 100,
        }

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    def test_update_vrf_table_l2_evpn_without_esi(self):
        # Prepare test data
        route_dist = '65000:100'
        prefix_str = None  # should be ignored
        kwargs = {
            'ethernet_tag_id': 100,
            'ip_addr': '192.168.0.1',
        }
        prefix_inst = EvpnInclusiveMulticastEthernetTagNLRI(
            route_dist=route_dist, **kwargs)
        next_hop = '10.0.0.1'
        route_family = VRF_RF_L2_EVPN
        route_type = EvpnInclusiveMulticastEthernetTagNLRI.ROUTE_TYPE_NAME

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    @mock.patch(
        'ryu.services.protocols.bgp.core_managers.TableCoreManager.__init__',
        mock.MagicMock(return_value=None))
    def test_update_vrf_table_l2_evpn_with_vni(self):
        # Prepare test data
        route_dist = '65000:100'
        prefix_str = None  # should be ignored
        kwargs = {
            'ethernet_tag_id': 100,
            'mac_addr': 'aa:bb:cc:dd:ee:ff',
            'ip_addr': '192.168.0.1',
            'vni': 500,
        }
        esi = EvpnArbitraryEsi(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        prefix_inst = EvpnMacIPAdvertisementNLRI(
            route_dist=route_dist,
            esi=esi,
            **kwargs)
        next_hop = '10.0.0.1'
        route_family = VRF_RF_L2_EVPN
        route_type = EvpnMacIPAdvertisementNLRI.ROUTE_TYPE_NAME
        tunnel_type = 'vxlan'
        kwargs['esi'] = 0

        # Instantiate TableCoreManager
        tbl_mng = table_manager.TableCoreManager(None, None)
        vrf_table_mock = mock.MagicMock()
        tbl_mng._tables = {(route_dist, route_family): vrf_table_mock}

        # Test
        tbl_mng.update_vrf_table(
            route_dist=route_dist,
            prefix=prefix_str,
            next_hop=next_hop,
            route_family=route_family,
            route_type=route_type,
            tunnel_type=tunnel_type,
            **kwargs)

        # Check
        call_args_list = vrf_table_mock.insert_vrf_path.call_args_list
        ok_(len(call_args_list) == 1)  # insert_vrf_path should be called once
        args, kwargs = call_args_list[0]
        ok_(len(args) == 0)  # no positional argument
        eq_(str(prefix_inst), str(kwargs['nlri']))
        eq_(next_hop, kwargs['next_hop'])
        eq_(False, kwargs['gen_lbl'])  # should not generate MPLS labels
        eq_(tunnel_type, kwargs['tunnel_type'])

    def test_update_vrf_table_ipv4_withdraw(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = '192.168.0.0'
        ip_prefix_len = 24
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        prefix_inst = IPAddrPrefix(ip_prefix_len, ip_network)
        next_hop = '10.0.0.1'
        route_family = VRF_RF_IPV4
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    is_withdraw=True, **kwargs)

    @raises(BgpCoreError)
    @mock.patch(
        'ryu.services.protocols.bgp.core_managers.TableCoreManager.__init__',
        mock.MagicMock(return_value=None))
    def test_update_vrf_table_no_vrf(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = '192.168.0.0'
        ip_prefix_len = 24
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        next_hop = '10.0.0.1'
        route_family = VRF_RF_IPV4
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        # Instantiate TableCoreManager
        tbl_mng = table_manager.TableCoreManager(None, None)
        tbl_mng._tables = {}  # no table

        # Test
        tbl_mng.update_vrf_table(
            route_dist=route_dist,
            prefix=prefix_str,
            next_hop=next_hop,
            route_family=route_family,
            route_type=route_type,
            **kwargs)

    @raises(BgpCoreError)
    def test_update_vrf_table_invalid_next_hop(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = '192.168.0.0'
        ip_prefix_len = 24
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        prefix_inst = IPAddrPrefix(ip_prefix_len, ip_network)
        next_hop = 'xxx.xxx.xxx.xxx'  # invalid
        route_family = VRF_RF_IPV4
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    @raises(BgpCoreError)
    def test_update_vrf_table_invalid_ipv4_prefix(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = 'xxx.xxx.xxx.xxx'  # invalid
        ip_prefix_len = 24
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        prefix_inst = IPAddrPrefix(ip_prefix_len, ip_network)
        next_hop = '10.0.0.1'
        route_family = VRF_RF_IPV4
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    @raises(BgpCoreError)
    def test_update_vrf_table_invalid_ipv6_prefix(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = 'xxxx::'  # invalid
        ip_prefix_len = 64
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        prefix_inst = IP6AddrPrefix(ip_prefix_len, ip_network)
        next_hop = 'fe80::0011:aabb:ccdd:eeff'
        route_family = VRF_RF_IPV6
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    @raises(BgpCoreError)
    def test_update_vrf_table_invalid_route_family(self):
        # Prepare test data
        route_dist = '65000:100'
        ip_network = '192.168.0.0'
        ip_prefix_len = 24
        prefix_str = '%s/%d' % (ip_network, ip_prefix_len)
        prefix_inst = IPAddrPrefix(ip_prefix_len, ip_network)
        next_hop = '10.0.0.1'
        route_family = 'foobar'  # invalid
        route_type = None  # should be ignored
        kwargs = {}  # should be ignored

        self._test_update_vrf_table(prefix_inst, route_dist, prefix_str,
                                    next_hop, route_family, route_type,
                                    **kwargs)

    @mock.patch(
        'ryu.services.protocols.bgp.core_managers.TableCoreManager.__init__',
        mock.MagicMock(return_value=None))
    @mock.patch(
        'ryu.services.protocols.bgp.core_managers.TableCoreManager.learn_path')
    def _test_update_global_table(self, learn_path_mock, prefix, next_hop,
                                  is_withdraw, expected_next_hop):
        # Prepare test data
        origin = BGPPathAttributeOrigin(BGP_ATTR_ORIGIN_IGP)
        aspath = BGPPathAttributeAsPath([[]])
        pathattrs = OrderedDict()
        pathattrs[BGP_ATTR_TYPE_ORIGIN] = origin
        pathattrs[BGP_ATTR_TYPE_AS_PATH] = aspath
        pathattrs = str(pathattrs)

        # Instantiate TableCoreManager
        tbl_mng = table_manager.TableCoreManager(None, None)

        # Test
        tbl_mng.update_global_table(
            prefix=prefix,
            next_hop=next_hop,
            is_withdraw=is_withdraw,
        )

        # Check
        call_args_list = learn_path_mock.call_args_list
        ok_(len(call_args_list) == 1)  # learn_path should be called once
        args, kwargs = call_args_list[0]
        ok_(len(kwargs) == 0)  # no keyword argument
        output_path = args[0]
        eq_(None, output_path.source)
        eq_(prefix, output_path.nlri.prefix)
        eq_(pathattrs, str(output_path.pathattr_map))
        eq_(expected_next_hop, output_path.nexthop)
        eq_(is_withdraw, output_path.is_withdraw)

    def test_update_global_table_ipv4(self):
        self._test_update_global_table(
            prefix='192.168.0.0/24',
            next_hop='10.0.0.1',
            is_withdraw=False,
            expected_next_hop='10.0.0.1',
        )

    def test_update_global_table_ipv4_withdraw(self):
        self._test_update_global_table(
            prefix='192.168.0.0/24',
            next_hop='10.0.0.1',
            is_withdraw=True,
            expected_next_hop='10.0.0.1',
        )

    def test_update_global_table_ipv4_no_next_hop(self):
        self._test_update_global_table(
            prefix='192.168.0.0/24',
            next_hop=None,
            is_withdraw=True,
            expected_next_hop='0.0.0.0',
        )

    def test_update_global_table_ipv6(self):
        self._test_update_global_table(
            prefix='fe80::/64',
            next_hop='fe80::0011:aabb:ccdd:eeff',
            is_withdraw=False,
            expected_next_hop='fe80::0011:aabb:ccdd:eeff',
        )

    def test_update_global_table_ipv6_withdraw(self):
        self._test_update_global_table(
            prefix='fe80::/64',
            next_hop='fe80::0011:aabb:ccdd:eeff',
            is_withdraw=True,
            expected_next_hop='fe80::0011:aabb:ccdd:eeff',
        )

    def test_update_global_table_ipv6_no_next_hop(self):
        self._test_update_global_table(
            prefix='fe80::/64',
            next_hop=None,
            is_withdraw=True,
            expected_next_hop='::',
        )
