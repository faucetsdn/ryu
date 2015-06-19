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
from nose.tools import *

import binascii
import inspect
import json
import logging
import math
import netaddr
import os
import signal
import sys
import time
import traceback
from random import randint

from ryu import cfg

# import all packet libraries.
PKT_LIB_PATH = 'ryu.lib.packet'
for modname, moddef in sys.modules.items():
    if not modname.startswith(PKT_LIB_PATH) or not moddef:
        continue
    for (clsname, clsdef, ) in inspect.getmembers(moddef):
        if not inspect.isclass(clsdef):
            continue
        exec('from %s import %s' % (modname, clsname))

from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import stringify
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_4

from ryu.tests.switch.tester import TestPatterns
from ryu.tests.switch.tester import TestFile
from ryu.tests.switch.tester import OfTester

CONF = cfg.CONF

LOG = logging.getLogger('test_tester')

SAMPLE_DESC = "action: 00_OUTPUT"


class Test_tester(unittest.TestCase):

    """ Test case for tester
    """

    # action/00_OUTPUT.json

    test_json_1 = {
        "description": "ethernet/ipv4/tcp-->'actions=output:2'",
        "prerequisite": [
            {
                "OFPFlowMod": {
                    "table_id": 0,
                    "instructions": [
                        {
                            "OFPInstructionActions": {
                                "actions": [
                                    {
                                        "OFPActionOutput": {
                                            "port": "target_send_port_1"
                                        }
                                    }
                                ],
                                "type": 4
                            }
                        }
                    ]
                }
            }
        ],
        "tests": [
            {
                "ingress": [
                    "ethernet(dst='22:22:22:22:22:22', \
                    src='12:11:11:11:11:11', ethertype=2048)",
                    "ipv4(tos=32, proto=6, src='192.168.10.10', \
                    dst='192.168.20.20', ttl=64)",
                    "tcp(dst_port=2222, option=str('\\x00' * 4), \
                    src_port=11111)",
                    "'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x0\
                    8\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x1\
                    2\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1\
                    b\\x1c\\x1d\\x1e\\x1f'"
                ],
                "egress":[
                    "ethernet(dst='22:22:22:22:22:22', \
                    src='12:11:11:11:11:11', ethertype=2048)",
                    "ipv4(tos=32, proto=6, src='192.168.10.10', \
                    dst='192.168.20.20', ttl=64)",
                    "tcp(dst_port=2222, option=str('\\x00' * 4), \
                    src_port=11111)",
                    "'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x0\
                    8\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x1\
                    2\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1\
                    b\\x1c\\x1d\\x1e\\x1f'"
                ]

            }
        ]
    }

    # group/00_ALL.json

    test_json_2 = {
        "description": "2Mbps(ethernet/ipv4/tcp)-->'in_port=1,\
            actions=group:all(actions=output:2/actions=output:3)'",
        "prerequisite": [
            {
                "OFPGroupMod": {
                    "group_id": 0,
                    "buckets": [
                        {
                            "OFPBucket": {
                                "actions": [
                                    {
                                        "OFPActionOutput": {
                                            "port": "target_send_port_1"
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "OFPBucket": {
                                "actions": [
                                    {
                                        "OFPActionOutput": {
                                            "port": "target_send_port_2"
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            },
            {
                "OFPFlowMod": {
                    "match": {
                        "OFPMatch": {
                            "oxm_fields": [
                                {
                                    "OXMTlv": {
                                        "field": "in_port",
                                        "value": "target_recv_port"
                                    }
                                }
                            ]
                        }
                    },
                    "instructions": [
                        {
                            "OFPInstructionActions": {
                                "actions": [
                                    {
                                        "OFPActionGroup": {
                                            "group_id": 0
                                        }
                                    }
                                ],
                                "type": 4
                            }
                        }
                    ]
                }
            }
        ],
        "tests": [
            {
                "ingress": {
                    "packets": {
                        "data": [
                            "ethernet(dst='22:22:22:22:22:22', \
                            src='12:11:11:11:11:11', ethertype=2048)",
                            "ipv4(proto=6)",
                            "tcp()",
                            "str('\\x11' * (1500 - 54))"
                        ],
                        "pktps":175,
                        "duration_time":30
                    }
                },
                "egress":{
                    "throughput": [
                        {
                            "OFPMatch": {
                                "oxm_fields": [
                                    {
                                        "OXMTlv": {
                                            "field": "in_port",
                                            "value": "tester_recv_port_1"
                                        }
                                    }
                                ]
                            },
                            "kbps": 2000
                        },
                        {
                            "OFPMatch": {
                                "oxm_fields": [
                                    {
                                        "OXMTlv": {
                                            "field": "in_port",
                                            "value": "tester_recv_port_2"
                                        }
                                    }
                                ]
                            },
                            "kbps": 2000
                        }
                    ]
                }
            }
        ]
    }

    # match/00_IN_PORT.json

    test_json_3 = {
        "description": "ethernet/ipv4/tcp-->'in_port=1,actions=output:2'",
        "prerequisite": [
            {
                "OFPFlowMod": {
                    "table_id": 0,
                    "match": {
                        "OFPMatch": {
                            "oxm_fields": [
                                {
                                    "OXMTlv": {
                                        "field": "in_port",
                                        "value": "target_recv_port"
                                    }
                                }
                            ]
                        }
                    },
                    "instructions": [
                        {
                            "OFPInstructionActions": {
                                "actions": [
                                    {
                                        "OFPActionOutput": {
                                            "port": "target_send_port_1"
                                        }
                                    }
                                ],
                                "type": 4
                            }
                        }
                    ]
                }
            }
        ],
        "tests": [
            {
                "ingress": [
                    "ethernet(dst='22:22:22:22:22:22', \
                    src='12:11:11:11:11:11', ethertype=2048)",
                    "ipv4(tos=32, proto=6, src='192.168.10.10', \
                    dst='192.168.20.20', ttl=64)",
                    "tcp(dst_port=2222, option=str('\\x00' * 4), \
                    src_port=11111)",
                    "'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x0\
                    8\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x1\
                    2\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1\
                    b\\x1c\\x1d\\x1e\\x1f'"
                ],
                "egress":[
                    "ethernet(dst='22:22:22:22:22:22', \
                    src='12:11:11:11:11:11', ethertype=2048)",
                    "ipv4(tos=32, proto=6, src='192.168.10.10',\
                     dst='192.168.20.20', ttl=64)",
                    "tcp(dst_port=2222, option=str('\\x00' * 4), \
                    src_port=11111)",
                    "'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x0\
                    8\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x1\
                    2\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1\
                    b\\x1c\\x1d\\x1e\\x1f'"
                ]
            }
        ]
    }

    # meter/01_DROP_00_KBPS_00_1M.json

    test_json_4 = {
        "description": "2Mbps(ethernet/ipv4/tcp)-->'in_port=1,\
        actions=meter:1Mbps(drop),output:2'",
        "prerequisite": [
            {
                "OFPMeterMod": {
                    "meter_id": 1,
                    "bands": [
                        {
                            "OFPMeterBandDrop": {
                                "rate": 1000
                            }
                        }
                    ]
                }
            },
            {
                "OFPFlowMod": {
                    "match": {
                        "OFPMatch": {
                            "oxm_fields": [
                                {
                                    "OXMTlv": {
                                        "field": "in_port",
                                        "value": "target_recv_port"
                                    }
                                }
                            ]
                        }
                    },
                    "instructions": [
                        {
                            "OFPInstructionMeter": {
                                "meter_id": 1
                            }
                        },
                        {
                            "OFPInstructionActions": {
                                "actions": [
                                    {
                                        "OFPActionOutput": {
                                            "port": "target_send_port_1"
                                        }
                                    }
                                ],
                                "type": 4
                            }
                        }
                    ]
                }
            }
        ],
        "tests": [
            {
                "ingress": {
                    "packets": {
                        "data": [
                            "ethernet(dst='22:22:22:22:22:22', \
                            src='12:11:11:11:11:11', ethertype=2048)",
                            "ipv4(proto=6)",
                            "tcp()",
                            "str('\\x11' * (1500 - 54))"
                        ],
                        "pktps":175,
                        "duration_time":30
                    }
                },
                "egress":{
                    "throughput": [
                        {
                            "OFPMatch": {
                                "oxm_fields": [
                                    {
                                        "OXMTlv": {
                                            "field": "in_port",
                                            "value": "tester_recv_port_1"
                                        }

                                    }
                                ]
                            },
                            "kbps": 1000
                        }
                    ]
                }
            }
        ]
    }

    def setUp(self):
        OfTester.tester_ver = ofproto_v1_3.OFP_VERSION
        OfTester.target_ver = ofproto_v1_3.OFP_VERSION

    def tearDown(self):
        pass

    def test__normalize_test_json(self):
        self.tests = TestPatterns(
            "../switch/of13/action/00_OUTPUT.json",
            logging.getLogger("test_tester"))

        self.tests[SAMPLE_DESC]._normalize_test_json(Test_tester.test_json_1)
        self.tests[SAMPLE_DESC]._normalize_test_json(Test_tester.test_json_2)
        self.tests[SAMPLE_DESC]._normalize_test_json(Test_tester.test_json_3)
        self.tests[SAMPLE_DESC]._normalize_test_json(Test_tester.test_json_4)

        # action/00_OUTPUT.json
        eq_(Test_tester.test_json_1["prerequisite"][0]["OFPFlowMod"][
            "instructions"][0]["OFPInstructionActions"][
            "actions"][0]["OFPActionOutput"]["port"],
            CONF['test-switch']['target_send_port_1'])

        # group/00_ALL.json
        eq_(Test_tester.test_json_2["prerequisite"][1]["OFPFlowMod"][
            "match"]["OFPMatch"]["oxm_fields"][0]["OXMTlv"]["value"],
            CONF['test-switch']['target_recv_port'])
        eq_(Test_tester.test_json_2["prerequisite"][0]["OFPGroupMod"][
            "buckets"][0]["OFPBucket"]["actions"][0]["OFPActionOutput"][
            "port"], CONF['test-switch']['target_send_port_1'])
        eq_(Test_tester.test_json_2["prerequisite"][0]["OFPGroupMod"][
            "buckets"][1]["OFPBucket"]["actions"][0]["OFPActionOutput"][
            "port"], CONF['test-switch']['target_send_port_2'])
        eq_(Test_tester.test_json_2["tests"][0]["egress"]["throughput"][
            0]["OFPMatch"]["oxm_fields"][0]["OXMTlv"]["value"],
            CONF['test-switch']['tester_recv_port_1'])
        eq_(Test_tester.test_json_2["tests"][0]["egress"]["throughput"][
            1]["OFPMatch"]["oxm_fields"][0]["OXMTlv"]["value"],
            CONF['test-switch']['tester_recv_port_2'])

        # match/00_IN_PORT.json
        eq_(Test_tester.test_json_3["prerequisite"][0]["OFPFlowMod"][
            "match"]["OFPMatch"]["oxm_fields"][0]["OXMTlv"]["value"],
            CONF['test-switch']['target_recv_port'])
        eq_(Test_tester.test_json_3["prerequisite"][0]["OFPFlowMod"][
            "instructions"][0]["OFPInstructionActions"]["actions"][0][
            "OFPActionOutput"]["port"], CONF['test-switch'][
            'target_send_port_1'])

        # meter/01_DROP_00_KBPS_00_1M.json
        eq_(Test_tester.test_json_4["prerequisite"][1]["OFPFlowMod"][
            "match"]["OFPMatch"]["oxm_fields"][0]["OXMTlv"]["value"],
            CONF['test-switch']['target_recv_port'])
        eq_(Test_tester.test_json_4["prerequisite"][1]["OFPFlowMod"][
            "instructions"][1]["OFPInstructionActions"]["actions"][0][
            "OFPActionOutput"]["port"],
            CONF['test-switch']['target_send_port_1'])
        eq_(Test_tester.test_json_4["tests"][0]["egress"]["throughput"][
            0]["OFPMatch"]["oxm_fields"][0]["OXMTlv"]["value"],
            CONF['test-switch']['tester_recv_port_1'])
