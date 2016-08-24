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

from nose.tools import eq_

from ryu.lib.packet import bgp
from ryu.services.protocols.bgp import peer


LOG = logging.getLogger(__name__)


class Test_Peer(unittest.TestCase):
    """
    Test case for peer.Peer
    """

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def _test_construct_as_path_attr(
            self, input_as_path, input_as4_path, expected_as_path):
        # Prepare input data
        input_as_path_attr = bgp.BGPPathAttributeAsPath(input_as_path)
        input_as4_path_attr = bgp.BGPPathAttributeAs4Path(input_as4_path)
        _peer = peer.Peer(None, None, None, None, None)

        # TEST
        output_as_path_attr = _peer._construct_as_path_attr(
            input_as_path_attr, input_as4_path_attr)

        eq_(bgp.BGP_ATTR_TYPE_AS_PATH, output_as_path_attr.type)
        eq_(expected_as_path, output_as_path_attr.path_seg_list)

    def test_construct_as_path_attr_sequence_only(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 23456, 23456, 40001]]
        input_as4_path = [[400000, 300000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000, 400000, 300000, 40001]]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    def test_construct_as_path_attr_aggregated_as_path_1(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000], {10, 20, 30}, [23456, 23456, 40001]]
        input_as4_path = [[400000, 300000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000], {10, 20, 30}, [400000, 300000, 40001]]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    def test_construct_as_path_attr_aggregated_as_path_2(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000], {10, 20, 30}, [23456, 23456, 40001]]
        input_as4_path = [[3000, 400000, 300000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000, 3000, 400000, 300000, 40001]]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    def test_construct_as_path_attr_aggregated_path_3(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 23456, 23456, 40001]]
        input_as4_path = [[400000, 300000, 40001], {10, 20, 30}]
        # Expected:
        expected_as_path = [[65000, 400000, 300000, 40001], {10, 20, 30}]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    def test_construct_as_path_attr_aggregated_as4_path(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 23456, 23456, 40001]]
        input_as4_path = [{10, 20, 30}, [400000, 300000, 40001]]
        # Expected:
        expected_as_path = [[65000], {10, 20, 30}, [400000, 300000, 40001]]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    def test_construct_as_path_attr_too_short_as_path(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 23456, 23456, 40001]]
        input_as4_path = [[100000, 65000, 4000, 400000, 300000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000, 23456, 23456, 40001]]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    def test_construct_as_path_attr_too_short_as4_path(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 23456, 23456, 40001]]
        input_as4_path = [[300000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000, 23456, 300000, 40001]]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    def test_construct_as_path_attr_empty_as4_path(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 23456, 23456, 40001]]
        input_as4_path = [[]]
        # Expected:
        expected_as_path = [[65000, 4000, 23456, 23456, 40001]]

        self._test_construct_as_path_attr(
            input_as_path, input_as4_path, expected_as_path)

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def test_construct_as_path_attr_as4_path_None(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 23456, 23456, 40001]]
        # input_as4_path = None
        # Expected:
        expected_as_path = [[65000, 4000, 23456, 23456, 40001]]

        # Prepare input data
        input_as_path_attr = bgp.BGPPathAttributeAsPath(input_as_path)
        input_as4_path_attr = None
        _peer = peer.Peer(None, None, None, None, None)

        # TEST
        output_as_path_attr = _peer._construct_as_path_attr(
            input_as_path_attr, input_as4_path_attr)

        eq_(bgp.BGP_ATTR_TYPE_AS_PATH, output_as_path_attr.type)
        eq_(expected_as_path, output_as_path_attr.path_seg_list)

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def _test_trans_as_path(
            self, input_as_path, expected_as_path, expected_as4_path):
        # Prepare input data
        _peer = peer.Peer(None, None, None, None, None)

        # TEST
        output_as_path, output_as4_path = _peer._trans_as_path(input_as_path)

        eq_(expected_as_path, output_as_path)
        eq_(expected_as4_path, output_as4_path)

    @mock.patch.object(
        peer.Peer, 'is_four_octet_as_number_cap_valid',
        mock.MagicMock(return_value=True))
    def test_trans_as_path_as4_path_is_supported(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 400000, 300000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000, 400000, 300000, 40001]]
        expected_as4_path = None

        self._test_trans_as_path(
            input_as_path, expected_as_path, expected_as4_path)

    @mock.patch.object(
        peer.Peer, 'is_four_octet_as_number_cap_valid',
        mock.MagicMock(return_value=False))
    def test_trans_as_path_sequence_only(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 400000, 300000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000, 23456, 23456, 40001]]
        expected_as4_path = [[65000, 4000, 400000, 300000, 40001]]

        self._test_trans_as_path(
            input_as_path, expected_as_path, expected_as4_path)

    @mock.patch.object(
        peer.Peer, 'is_four_octet_as_number_cap_valid',
        mock.MagicMock(return_value=False))
    def test_trans_as_path_no_trans(self):
        # Test Data
        # Input:
        input_as_path = [[65000, 4000, 40000, 30000, 40001]]
        # Expected:
        expected_as_path = [[65000, 4000, 40000, 30000, 40001]]
        expected_as4_path = None

        self._test_trans_as_path(
            input_as_path, expected_as_path, expected_as4_path)

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def _test_extract_and_reconstruct_as_path(
            self, path_attributes, ex_as_path_value,
            ex_aggregator_as_number, ex_aggregator_addr):
        # Prepare test data
        update_msg = bgp.BGPUpdate(path_attributes=path_attributes)
        _peer = peer.Peer(None, None, None, None, None)

        # Test
        _peer._extract_and_reconstruct_as_path(update_msg)

        umsg_pattrs = update_msg.pathattr_map
        as_path_attr = umsg_pattrs.get(
            bgp.BGP_ATTR_TYPE_AS_PATH, None)
        as4_path_attr = umsg_pattrs.get(
            bgp.BGP_ATTR_TYPE_AS4_PATH, None)
        aggregator_attr = umsg_pattrs.get(
            bgp.BGP_ATTR_TYPE_AGGREGATOR, None)
        as4_aggregator_attr = umsg_pattrs.get(
            bgp.BGP_ATTR_TYPE_AS4_AGGREGATOR, None)

        eq_(ex_as_path_value, as_path_attr.value)
        eq_(None, as4_path_attr)
        eq_(ex_aggregator_as_number, aggregator_attr.as_number)
        eq_(ex_aggregator_addr, aggregator_attr.addr)
        eq_(None, as4_aggregator_attr)

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def test_extract_and_reconstruct_as_path_with_no_as4_attr(self):
        # Input values
        in_as_path_value = [[1000, 2000, 3000]]
        # in_as4_path_value
        in_aggregator_as_number = 4000
        in_aggregator_addr = '10.0.0.1'
        # in_as4_aggregator_as_number
        # in_as4_aggregator_addr

        # Expected values
        ex_as_path_value = [[1000, 2000, 3000]]
        ex_aggregator_as_number = 4000
        ex_aggregator_addr = '10.0.0.1'

        # Prepare test data
        path_attributes = [
            bgp.BGPPathAttributeAsPath(
                value=in_as_path_value),
            bgp.BGPPathAttributeAggregator(
                as_number=in_aggregator_as_number, addr=in_aggregator_addr),
        ]

        # Test
        self._test_extract_and_reconstruct_as_path(
            path_attributes, ex_as_path_value,
            ex_aggregator_as_number, ex_aggregator_addr)

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def test_extract_and_reconstruct_as_path_with_as4_attr(self):
        # Input values
        in_as_path_value = [[1000, 23456, 3000]]
        in_as4_path_value = [[2000, 3000]]
        in_aggregator_as_number = 23456
        in_aggregator_addr = '10.0.0.1'
        in_as4_aggregator_as_number = 4000
        in_as4_aggregator_addr = '10.0.0.1'

        # Expected values
        ex_as_path_value = [[1000, 2000, 3000]]
        ex_aggregator_as_number = 4000
        ex_aggregator_addr = '10.0.0.1'

        # Prepare test data
        path_attributes = [
            bgp.BGPPathAttributeAsPath(
                value=in_as_path_value),
            bgp.BGPPathAttributeAs4Path(
                value=in_as4_path_value),
            bgp.BGPPathAttributeAggregator(
                as_number=in_aggregator_as_number,
                addr=in_aggregator_addr),
            bgp.BGPPathAttributeAs4Aggregator(
                as_number=in_as4_aggregator_as_number,
                addr=in_as4_aggregator_addr),
        ]

        # Test
        self._test_extract_and_reconstruct_as_path(
            path_attributes, ex_as_path_value,
            ex_aggregator_as_number, ex_aggregator_addr)

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def test_extract_and_reconstruct_as_path_with_not_trans_as_aggr(self):
        # Input values
        in_as_path_value = [[1000, 23456, 3000]]
        in_as4_path_value = [[2000, 3000]]
        in_aggregator_as_number = 4000  # not AS_TRANS
        in_aggregator_addr = '10.0.0.1'
        in_as4_aggregator_as_number = 4000
        in_as4_aggregator_addr = '10.0.0.1'

        # Expected values
        ex_as_path_value = [[1000, 23456, 3000]]
        ex_aggregator_as_number = 4000
        ex_aggregator_addr = '10.0.0.1'

        # Prepare test data
        path_attributes = [
            bgp.BGPPathAttributeAsPath(
                value=in_as_path_value),
            bgp.BGPPathAttributeAs4Path(
                value=in_as4_path_value),
            bgp.BGPPathAttributeAggregator(
                as_number=in_aggregator_as_number,
                addr=in_aggregator_addr),
            bgp.BGPPathAttributeAs4Aggregator(
                as_number=in_as4_aggregator_as_number,
                addr=in_as4_aggregator_addr),
        ]

        # Test
        self._test_extract_and_reconstruct_as_path(
            path_attributes, ex_as_path_value,
            ex_aggregator_as_number, ex_aggregator_addr)

    @mock.patch.object(
        peer.Peer, '__init__', mock.MagicMock(return_value=None))
    def test_extract_and_reconstruct_as_path_with_short_as_path(self):
        # Input values
        in_as_path_value = [[1000, 23456, 3000]]
        in_as4_path_value = [[2000, 3000, 4000, 5000]]  # longer than AS_PATH
        in_aggregator_as_number = 4000
        in_aggregator_addr = '10.0.0.1'
        # in_as4_aggregator_as_number
        # in_as4_aggregator_addr

        # Expected values
        ex_as_path_value = [[1000, 23456, 3000]]
        ex_aggregator_as_number = 4000
        ex_aggregator_addr = '10.0.0.1'

        # Prepare test data
        path_attributes = [
            bgp.BGPPathAttributeAsPath(
                value=in_as_path_value),
            bgp.BGPPathAttributeAs4Path(
                value=in_as4_path_value),
            bgp.BGPPathAttributeAggregator(
                as_number=in_aggregator_as_number,
                addr=in_aggregator_addr),
        ]

        # Test
        self._test_extract_and_reconstruct_as_path(
            path_attributes, ex_as_path_value,
            ex_aggregator_as_number, ex_aggregator_addr)
