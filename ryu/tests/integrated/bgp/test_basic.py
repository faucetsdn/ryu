# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2016 Fumihiko Kakuma <kakuma at valinux co jp>
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

from __future__ import absolute_import

import time

from ryu.tests.integrated.common import docker_base as ctn_base
from . import base


class BgpSpeakerBasicTest(base.BgpSpeakerTestBase):
    def setUp(self):
        super(BgpSpeakerBasicTest, self).setUp()
        self.r1.stop_ryubgp(retry=True)
        self.r1.start_ryubgp(retry=True)

    def test_check_neighbor_established(self):
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for _ in range(0, self.checktime):
            neighbor_state = self.q1.get_neighbor_state(self.r1)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)

    def test_check_rib_nexthop(self):
        neighbor_state = ctn_base.BGP_FSM_IDLE
        for _ in range(0, self.checktime):
            neighbor_state = self.q1.get_neighbor_state(self.r1)
            if neighbor_state == ctn_base.BGP_FSM_ESTABLISHED:
                break
            time.sleep(1)
        self.assertEqual(neighbor_state, ctn_base.BGP_FSM_ESTABLISHED)
        rib = self.q1.get_global_rib(prefix='10.10.0.0/28')
        self.assertEqual(self.r1_ip, rib[0]['nexthop'])
