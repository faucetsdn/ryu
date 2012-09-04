# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

import logging

from ryu.base import app_manager
from ryu.controller import dispatcher
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER

LOG = logging.getLogger('ryu.controller.ofp_handler')

# The state transition: HANDSHAKE -> CONFIG -> MAIN
#
# HANDSHAKE: if it receives HELLO message with the valid OFP version,
# sends Features Request message, and moves to CONFIG.
#
# CONFIG: it receives Features Reply message and moves to MAIN
#
# MAIN: it does nothing. Applications are expected to register their
# own handlers.
#
# Note that at any state, when we receive Echo Request message, send
# back Echo Reply message.


class OFPHandler(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(OFPHandler, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        LOG.debug('hello ev %s', ev)
        msg = ev.msg
        datapath = msg.datapath

        # TODO: check if received version is supported.
        #       pre 1.0 is not supported
        if msg.version not in datapath.supported_ofp_version:
            # send the error
            error_msg = datapath.ofproto_parser.OFPErrorMsg(datapath)
            error_msg.type = datapath.ofproto.OFPET_HELLO_FAILED
            error_msg.code = datapath.ofproto.OFPHFC_INCOMPATIBLE
            error_msg.data = 'unsupported version 0x%x' % msg.version
            datapath.send_msg(error_msg)
            return

        # should we again send HELLO with the version that the switch
        # supports?
        # msg.version != datapath.ofproto.OFP_VERSION:

        datapath.set_version(msg.version)

        # now send feature
        features_reqeust = datapath.ofproto_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(features_reqeust)

        # now move on to config state
        LOG.debug('move onto config mode')
        datapath.ev_q.set_dispatcher(CONFIG_DISPATCHER)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        LOG.debug('switch features ev %s', msg)

        datapath.id = msg.datapath_id
        datapath.ports = msg.ports

        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        set_config = ofproto_parser.OFPSetConfig(
            datapath, ofproto.OFPC_FRAG_NORMAL,
            128  # TODO:XXX
        )
        datapath.send_msg(set_config)

        LOG.debug('move onto main mode')
        ev.msg.datapath.ev_q.set_dispatcher(MAIN_DISPATCHER)

    @set_ev_cls(ofp_event.EventOFPEchoRequest,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_request_handler(self, ev):
        msg = ev.msg
        # LOG.debug('echo request msg %s %s', msg, str(msg.data))
        datapath = msg.datapath
        echo_reply = datapath.ofproto_parser.OFPEchoReply(datapath)
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        datapath.send_msg(echo_reply)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        LOG.debug('error msg ev %s type 0x%x code 0x%x %s',
                  msg, msg.type, msg.code, str(msg.data))
