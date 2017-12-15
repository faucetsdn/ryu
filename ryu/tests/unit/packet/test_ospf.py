# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

from ryu.lib.packet import ospf


class Test_ospf(unittest.TestCase):
    """ Test case for ryu.lib.packet.ospf
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_router_lsa(self):
        link1 = ospf.RouterLSA.Link(id_='10.0.0.1', data='255.255.255.0',
                                    type_=ospf.LSA_LINK_TYPE_STUB, metric=10)
        msg = ospf.RouterLSA(id_='192.168.0.1', adv_router='192.168.0.2',
                             links=[link1])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.LSA.parser(binmsg)
        eq_(msg.header.checksum, msg2.header.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')

    def test_network_lsa(self):
        msg = ospf.NetworkLSA(id_='192.168.0.1', adv_router='192.168.0.2',
                              mask='255.255.255.0', routers=['192.168.0.2'])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.LSA.parser(binmsg)
        eq_(msg.header.checksum, msg2.header.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')

    def test_as_external_lsa(self):
        extnw1 = ospf.ASExternalLSA.ExternalNetwork(mask='255.255.255.0',
                                                    metric=20,
                                                    fwd_addr='10.0.0.1')
        msg = ospf.ASExternalLSA(id_='192.168.0.1', adv_router='192.168.0.2',
                                 extnws=[extnw1])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.LSA.parser(binmsg)
        eq_(msg.header.checksum, msg2.header.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')

    def test_hello(self):
        msg = ospf.OSPFHello(router_id='192.168.0.1',
                             neighbors=['192.168.0.2'])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.OSPFMessage.parser(binmsg)
        eq_(msg.checksum, msg2.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')

    def test_dbdesc(self):
        link1 = ospf.RouterLSA.Link(id_='10.0.0.1', data='255.255.255.0',
                                    type_=ospf.LSA_LINK_TYPE_STUB, metric=10)
        lsa1 = ospf.RouterLSA(id_='192.168.0.1', adv_router='192.168.0.2',
                              links=[link1])
        msg = ospf.OSPFDBDesc(router_id='192.168.0.1',
                              lsa_headers=[lsa1.header])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.OSPFMessage.parser(binmsg)
        eq_(msg.checksum, msg2.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')

    def test_lsreq(self):
        req = ospf.OSPFLSReq.Request(type_=ospf.OSPF_ROUTER_LSA,
                                     id_='192.168.0.1',
                                     adv_router='192.168.0.2')
        msg = ospf.OSPFLSReq(router_id='192.168.0.1', lsa_requests=[req])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.OSPFMessage.parser(binmsg)
        eq_(msg.checksum, msg2.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')

    def test_lsupd(self):
        link1 = ospf.RouterLSA.Link(id_='10.0.0.1', data='255.255.255.0',
                                    type_=ospf.LSA_LINK_TYPE_STUB, metric=10)
        lsa1 = ospf.RouterLSA(id_='192.168.0.1', adv_router='192.168.0.2',
                              links=[link1])
        msg = ospf.OSPFLSUpd(router_id='192.168.0.1', lsas=[lsa1])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.OSPFMessage.parser(binmsg)
        eq_(msg.checksum, msg2.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')

    def test_lsack(self):
        link1 = ospf.RouterLSA.Link(id_='10.0.0.1', data='255.255.255.0',
                                    type_=ospf.LSA_LINK_TYPE_STUB, metric=10)
        lsa1 = ospf.RouterLSA(id_='192.168.0.1', adv_router='192.168.0.2',
                              links=[link1])
        msg = ospf.OSPFLSAck(router_id='192.168.0.1',
                             lsa_headers=[lsa1.header])
        binmsg = msg.serialize()
        msg2, cls, rest = ospf.OSPFMessage.parser(binmsg)
        eq_(msg.checksum, msg2.checksum)
        eq_(str(msg), str(msg2))
        eq_(rest, b'')
