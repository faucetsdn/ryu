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

import os
import sys
import unittest

from nose.tools import eq_
from nose.tools import ok_
import six

from ryu.lib import pcaplib
from ryu.lib.packet import packet
from ryu.lib.packet import zebra
from ryu.utils import binary_str


PCAP_DATA_DIR = os.path.join(
    os.path.dirname(sys.modules[__name__].__file__),
    '../../packet_data/pcap/')


class Test_zebra(unittest.TestCase):
    """
    Test case for ryu.lib.packet.zebra.
    """

    def test_pcap(self):
        files = [
            'zebra_v2',
            'zebra_v3',
        ]

        for f in files:
            zebra_pcap_file = os.path.join(PCAP_DATA_DIR, f + '.pcap')
            # print('*** testing %s' % zebra_pcap_file)

            for _, buf in pcaplib.Reader(open(zebra_pcap_file, 'rb')):
                # Checks if Zebra message can be parsed as expected.
                pkt = packet.Packet(buf)
                zebra_pkts = pkt.get_protocols(zebra.ZebraMessage)
                for zebra_pkt in zebra_pkts:
                    ok_(isinstance(zebra_pkt, zebra.ZebraMessage),
                        'Failed to parse Zebra message: %s' % pkt)
                ok_(not isinstance(pkt.protocols[-1],
                                   (six.binary_type, bytearray)),
                    'Some messages could not be parsed: %s' % pkt)

                # Checks if Zebra message can be serialized as expected.
                pkt.serialize()
                eq_(buf, pkt.data,
                    "b'%s' != b'%s'" % (binary_str(buf), binary_str(pkt.data)))
