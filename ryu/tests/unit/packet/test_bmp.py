# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
from nose.tools import eq_
from nose.tools import ok_
from time import time

from ryu.lib.packet import bmp
from ryu.lib.packet import bgp
from ryu.lib.packet import afi
from ryu.lib.packet import safi


class Test_bmp(unittest.TestCase):
    """ Test case for ryu.lib.packet.bmp
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _time(self):
        # time() can give sub-microsecond precision, which results
        # in an assertion failure
        return round(time(), 6)

    def test_route_monitoring(self):
        update = bgp.BGPUpdate()
        msg = bmp.BMPRouteMonitoring(bgp_update=update,
                                     peer_type=bmp.BMP_PEER_TYPE_GLOBAL,
                                     is_post_policy=True,
                                     peer_distinguisher=0,
                                     peer_address='192.0.2.1',
                                     peer_as=30000,
                                     peer_bgp_id='192.0.2.1',
                                     timestamp=self._time())
        binmsg = msg.serialize()
        msg2, rest = bmp.BMPMessage.parser(binmsg)
        eq_(msg.to_jsondict(), msg2.to_jsondict())
        eq_(rest, b'')

    def test_statistics_report(self):
        stats = [{'type': bmp.BMP_STAT_TYPE_REJECTED, 'value': 100},
                 {'type': bmp.BMP_STAT_TYPE_DUPLICATE_PREFIX, 'value': 200},
                 {'type': bmp.BMP_STAT_TYPE_DUPLICATE_WITHDRAW, 'value': 300},
                 {'type': bmp.BMP_STAT_TYPE_ADJ_RIB_IN, 'value': 100000},
                 {'type': bmp.BMP_STAT_TYPE_LOC_RIB, 'value': 500000}]
        msg = bmp.BMPStatisticsReport(stats=stats,
                                      peer_type=bmp.BMP_PEER_TYPE_GLOBAL,
                                      is_post_policy=True,
                                      peer_distinguisher=0,
                                      peer_address='192.0.2.1',
                                      peer_as=30000,
                                      peer_bgp_id='192.0.2.1',
                                      timestamp=self._time())
        binmsg = msg.serialize()
        msg2, rest = bmp.BMPMessage.parser(binmsg)
        eq_(msg.to_jsondict(), msg2.to_jsondict())
        eq_(rest, b'')

    def test_peer_down_notification(self):
        reason = bmp.BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION
        data = b'hoge'
        data = bgp.BGPNotification(error_code=1, error_subcode=2, data=data)
        msg = bmp.BMPPeerDownNotification(reason=reason, data=data,
                                          peer_type=bmp.BMP_PEER_TYPE_GLOBAL,
                                          is_post_policy=True,
                                          peer_distinguisher=0,
                                          peer_address='192.0.2.1',
                                          peer_as=30000,
                                          peer_bgp_id='192.0.2.1',
                                          timestamp=self._time())
        binmsg = msg.serialize()
        msg2, rest = bmp.BMPMessage.parser(binmsg)
        eq_(msg.to_jsondict(), msg2.to_jsondict())
        eq_(rest, b'')

    def test_peer_up_notification(self):
        opt_param = [bgp.BGPOptParamCapabilityUnknown(cap_code=200,
                                                      cap_value=b'hoge'),
                     bgp.BGPOptParamCapabilityRouteRefresh(),
                     bgp.BGPOptParamCapabilityMultiprotocol(
                         afi=afi.IP, safi=safi.MPLS_VPN)]
        open_message = bgp.BGPOpen(my_as=40000, bgp_identifier='192.0.2.2',
                                   opt_param=opt_param)
        msg = bmp.BMPPeerUpNotification(local_address='192.0.2.2',
                                        local_port=179,
                                        remote_port=11089,
                                        sent_open_message=open_message,
                                        received_open_message=open_message,
                                        peer_type=bmp.BMP_PEER_TYPE_GLOBAL,
                                        is_post_policy=True,
                                        peer_distinguisher=0,
                                        peer_address='192.0.2.1',
                                        peer_as=30000,
                                        peer_bgp_id='192.0.2.1',
                                        timestamp=self._time())
        binmsg = msg.serialize()
        msg2, rest = bmp.BMPMessage.parser(binmsg)
        eq_(msg.to_jsondict(), msg2.to_jsondict())
        eq_(rest, b'')

    def test_initiation(self):
        initiation_info = [{'type': bmp.BMP_INIT_TYPE_STRING,
                            'value': u'This is Ryu BGP BMP message'}]
        msg = bmp.BMPInitiation(info=initiation_info)
        binmsg = msg.serialize()
        msg2, rest = bmp.BMPMessage.parser(binmsg)
        eq_(msg.to_jsondict(lambda v: v), msg2.to_jsondict(lambda v: v))
        eq_(rest, b'')

    def test_termination(self):
        termination_info = [{'type': bmp.BMP_TERM_TYPE_STRING,
                             'value': u'Session administatively closed'},
                            {'type': bmp.BMP_TERM_TYPE_REASON,
                             'value': bmp.BMP_TERM_REASON_ADMIN}]
        msg = bmp.BMPTermination(info=termination_info)
        binmsg = msg.serialize()
        msg2, rest = bmp.BMPMessage.parser(binmsg)
        eq_(msg.to_jsondict(lambda v: v), msg2.to_jsondict(lambda v: v))
        eq_(rest, b'')
