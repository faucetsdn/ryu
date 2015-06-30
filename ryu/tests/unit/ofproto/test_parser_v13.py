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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import six
import socket
from struct import *
from nose.tools import *
from ryu.ofproto.ofproto_v1_3_parser import *
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ether
from ryu.ofproto.ofproto_parser import MsgBase
from ryu import utils
from ryu.lib import addrconv

LOG = logging.getLogger('test_ofproto_v13')


_Datapath = ofproto_protocol.ProtocolDesc(version=ofproto_v1_3.OFP_VERSION)


class TestOFPMatch(unittest.TestCase):

    """ Test case for ofproto_v1_3_parser.OFPMatch
    """

    def test_init(self):
        res = OFPMatch()

        # wc check
        eq_(res._wc.vlan_vid_mask, 0)

        # flow check
        eq_(res._flow.vlan_vid, 0)

    def _test_serialize_and_parser(self, match, header, value, mask=None):
        cls_ = OFPMatchField._FIELDS_HEADERS.get(header)
        pack_str = cls_.pack_str.replace('!', '')
        fmt = '!HHI' + pack_str

        # serialize
        buf = bytearray()
        length = match.serialize(buf, 0)
        eq_(length, len(buf))
        if mask and len(buf) > calcsize(fmt):
            fmt += pack_str

        res = list(unpack_from(fmt, six.binary_type(buf), 0)[3:])
        if type(value) is list:
            res_value = res[:calcsize(pack_str) // 2]
            eq_(res_value, value)
            if mask:
                res_mask = res[calcsize(pack_str) // 2:]
                eq_(res_mask, mask)
        else:
            res_value = res.pop(0)
            if cls_.__name__ == 'MTVlanVid':
                eq_(res_value, value | ofproto.OFPVID_PRESENT)
            else:
                eq_(res_value, value)
            if mask and res and res[0]:
                res_mask = res[0]
                eq_(res_mask, mask)

        # parser
        res = match.parser(six.binary_type(buf), 0)
        eq_(res.type, ofproto.OFPMT_OXM)
        eq_(res.fields[0].header, header)
        eq_(res.fields[0].value, value)
        if mask and res.fields[0].mask is not None:
            eq_(res.fields[0].mask, mask)

        # to_jsondict
        jsondict = match.to_jsondict()

        # from_jsondict
        match2 = match.from_jsondict(jsondict["OFPMatch"])
        buf2 = bytearray()
        match2.serialize(buf2, 0)
        eq_(str(match), str(match2))
        eq_(buf, buf2)

    # set_vlan_vid
    def _test_set_vlan_vid(self, vid, mask=None):
        header = ofproto.OXM_OF_VLAN_VID
        match = OFPMatch()
        if mask is None:
            match.set_vlan_vid(vid)
        else:
            header = ofproto.OXM_OF_VLAN_VID_W
            match.set_vlan_vid_masked(vid, mask)
        self._test_serialize_and_parser(match, header, vid, mask)

    def _test_set_vlan_vid_none(self):
        header = ofproto.OXM_OF_VLAN_VID
        match = OFPMatch()
        match.set_vlan_vid_none()
        value = ofproto.OFPVID_NONE
        cls_ = OFPMatchField._FIELDS_HEADERS.get(header)
        pack_str = cls_.pack_str.replace('!', '')
        fmt = '!HHI' + pack_str

        # serialize
        buf = bytearray()
        length = match.serialize(buf, 0)
        eq_(length, len(buf))

        res = list(unpack_from(fmt, six.binary_type(buf), 0)[3:])
        res_value = res.pop(0)
        eq_(res_value, value)

        # parser
        res = match.parser(six.binary_type(buf), 0)
        eq_(res.type, ofproto.OFPMT_OXM)
        eq_(res.fields[0].header, header)
        eq_(res.fields[0].value, value)

        # to_jsondict
        jsondict = match.to_jsondict()

        # from_jsondict
        match2 = match.from_jsondict(jsondict["OFPMatch"])
        buf2 = bytearray()
        match2.serialize(buf2, 0)
        eq_(str(match), str(match2))
        eq_(buf, buf2)

    def test_set_vlan_vid_mid(self):
        self._test_set_vlan_vid(2047)

    def test_set_vlan_vid_max(self):
        self._test_set_vlan_vid(0xfff)

    def test_set_vlan_vid_min(self):
        self._test_set_vlan_vid(0)

    def test_set_vlan_vid_masked_mid(self):
        self._test_set_vlan_vid(2047, 0xf0f)

    def test_set_vlan_vid_masked_max(self):
        self._test_set_vlan_vid(2047, 0xfff)

    def test_set_vlan_vid_masked_min(self):
        self._test_set_vlan_vid(2047, 0)

    def test_set_vlan_vid_none(self):
        self._test_set_vlan_vid_none()
