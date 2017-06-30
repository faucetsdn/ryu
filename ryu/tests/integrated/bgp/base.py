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

import logging
import sys
import unittest

from ryu.tests.integrated.common import docker_base as ctn_base
from ryu.tests.integrated.common import ryubgp
from ryu.tests.integrated.common import quagga


LOG = logging.getLogger(__name__)


class BgpSpeakerTestBase(unittest.TestCase):
    images = []
    containers = []
    bridges = []
    checktime = 120

    @classmethod
    def setUpClass(cls):
        cls.brdc1 = ctn_base.Bridge(name='brdc1',
                                    subnet='192.168.10.0/24')
        cls.bridges.append(cls.brdc1)

        cls.dockerimg = ctn_base.DockerImage()
        image = 'python:%d.%d' % (
            sys.version_info.major, sys.version_info.minor)
        cls.r_img = cls.dockerimg.create_ryu(image=image, check_exist=True)
        cls.images.append(cls.r_img)
        cls.q_img = 'osrg/quagga'
        cls.images.append(cls.q_img)

        cls.r1 = ryubgp.RyuBGPContainer(name='r1', asn=64512,
                                        router_id='192.168.0.1',
                                        ctn_image_name=cls.r_img)
        cls.containers.append(cls.r1)
        cls.r1.add_route('10.10.0.0/28')
        cls.r1.run(wait=True)
        cls.r1_ip_cidr = cls.brdc1.addif(cls.r1)
        cls.r1_ip = cls.r1_ip_cidr.split('/')[0]

        cls.q1 = quagga.QuaggaBGPContainer(name='q1', asn=64522,
                                           router_id='192.168.0.2',
                                           ctn_image_name=cls.q_img)
        cls.containers.append(cls.q1)
        cls.q1.add_route('192.168.160.0/24')
        cls.q1.run(wait=True)
        cls.q1_ip_cidr = cls.brdc1.addif(cls.q1)
        cls.q1_ip = cls.q1_ip_cidr.split('/')[0]

        cls.r1.add_peer(cls.q1, bridge=cls.brdc1.name)
        cls.q1.add_peer(cls.r1, bridge=cls.brdc1.name)

        super(BgpSpeakerTestBase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        for ctn in cls.containers:
            try:
                ctn.stop()
            except ctn_base.CommandError as e:
                LOG.exception('Exception when stopping containers: %s', e)
            ctn.remove()
        for br in cls.bridges:
            br.delete()
        super(BgpSpeakerTestBase, cls).tearDownClass()
