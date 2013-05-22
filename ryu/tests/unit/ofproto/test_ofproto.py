# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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
from nose.tools import eq_


LOG = logging.getLogger('test_ofproto')


class TestOfprotCommon(unittest.TestCase):
    """ Test case for ofproto
    """

    def test_ofp_event(self):
        import ryu.ofproto
        reload(ryu.ofproto)
        import ryu.controller.ofp_event
        reload(ryu.controller.ofp_event)

    def test_ofproto(self):
        # When new version of OFP support is added,
        # this test must be updated.
        import ryu.ofproto
        reload(ryu.ofproto)
        ofp_modules = ryu.ofproto.get_ofp_modules()

        import ryu.ofproto.ofproto_v1_0
        import ryu.ofproto.ofproto_v1_2
        import ryu.ofproto.ofproto_v1_3
        eq_(set(ofp_modules.keys()), set([ryu.ofproto.ofproto_v1_0.OFP_VERSION,
                                          ryu.ofproto.ofproto_v1_2.OFP_VERSION,
                                          ryu.ofproto.ofproto_v1_3.OFP_VERSION,
                                          ]))
        consts_mods = set([ofp_mod[0] for ofp_mod in ofp_modules.values()])
        eq_(consts_mods, set([ryu.ofproto.ofproto_v1_0,
                              ryu.ofproto.ofproto_v1_2,
                              ryu.ofproto.ofproto_v1_3,
                              ]))

        parser_mods = set([ofp_mod[1] for ofp_mod in ofp_modules.values()])
        import ryu.ofproto.ofproto_v1_0_parser
        import ryu.ofproto.ofproto_v1_2_parser
        import ryu.ofproto.ofproto_v1_3_parser
        eq_(parser_mods, set([ryu.ofproto.ofproto_v1_0_parser,
                              ryu.ofproto.ofproto_v1_2_parser,
                              ryu.ofproto.ofproto_v1_3_parser,
                              ]))
