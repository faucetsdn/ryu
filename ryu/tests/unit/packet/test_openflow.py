# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

from ryu.lib import pcaplib
from ryu.lib.packet import openflow
from ryu.lib.packet import packet
from ryu.utils import binary_str


LOG = logging.getLogger(__name__)

OPENFLOW_DATA_DIR = os.path.join(
    os.path.dirname(sys.modules[__name__].__file__),
    '../../packet_data/pcap/')


class Test_openflow(unittest.TestCase):
    """
    Test case for ryu.lib.packet.openflow.
    """

    def test_pcap(self):
        files = [
            'openflow_flowmod',
            'openflow_flowstats_req',
            'openflow_invalid_version',
        ]

        for f in files:
            # print('*** testing %s ...' % f)
            for _, buf in pcaplib.Reader(
                    open(OPENFLOW_DATA_DIR + f + '.pcap', 'rb')):
                # Checks if message can be parsed as expected.
                pkt = packet.Packet(buf)
                openflow_pkt = pkt.get_protocol(openflow.openflow)
                ok_(isinstance(openflow_pkt, openflow.openflow),
                    'Failed to parse OpenFlow message: %s' % pkt)

                # Checks if message can be serialized as expected.
                pkt.serialize()
                eq_(buf, pkt.data,
                    "b'%s' != b'%s'" % (binary_str(buf), binary_str(pkt.data)))
