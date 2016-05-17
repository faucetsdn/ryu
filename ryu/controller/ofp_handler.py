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

"""
Basic OpenFlow handling including negotiation.
"""

import itertools
import logging
import warnings

import ryu.base.app_manager

from ryu.lib import hub
from ryu import utils
from ryu.controller import ofp_event
from ryu.controller.controller import OpenFlowController
from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER
from ryu.ofproto import ofproto_parser


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


class OFPHandler(ryu.base.app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(OFPHandler, self).__init__(*args, **kwargs)
        self.name = 'ofp_event'

    def start(self):
        super(OFPHandler, self).start()
        return hub.spawn(OpenFlowController())

    def _hello_failed(self, datapath, error_desc):
        self.logger.error(error_desc)
        error_msg = datapath.ofproto_parser.OFPErrorMsg(datapath)
        error_msg.type = datapath.ofproto.OFPET_HELLO_FAILED
        error_msg.code = datapath.ofproto.OFPHFC_INCOMPATIBLE
        error_msg.data = error_desc
        datapath.send_msg(error_msg)

    @set_ev_handler(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        self.logger.debug('hello ev %s', ev)
        msg = ev.msg
        datapath = msg.datapath

        # check if received version is supported.
        # pre 1.0 is not supported
        elements = getattr(msg, 'elements', None)
        if elements:
            switch_versions = set()
            for version in itertools.chain.from_iterable(
                    element.versions for element in elements):
                switch_versions.add(version)
            usable_versions = switch_versions & set(
                datapath.supported_ofp_version)

            # We didn't send our supported versions for interoperability as
            # most switches would not understand elements at the moment.
            # So the switch would think that the negotiated version would
            # be max(negotiated_versions), but actual usable version is
            # max(usable_versions).
            negotiated_versions = set(
                version for version in switch_versions
                if version <= max(datapath.supported_ofp_version))
            if negotiated_versions and not usable_versions:
                # e.g.
                # versions of OF 1.0 and 1.1 from switch
                # max of OF 1.2 from Ryu and supported_ofp_version = (1.2, )
                # negotiated version = 1.1
                # usable version = None
                error_desc = (
                    'no compatible version found: '
                    'switch versions %s controller version 0x%x, '
                    'the negotiated version is 0x%x, '
                    'but no usable version found. '
                    'If possible, set the switch to use one of OF version %s'
                    % (switch_versions, max(datapath.supported_ofp_version),
                       max(negotiated_versions),
                       sorted(datapath.supported_ofp_version)))
                self._hello_failed(datapath, error_desc)
                return
            if (negotiated_versions and usable_versions and
                    max(negotiated_versions) != max(usable_versions)):
                # e.g.
                # versions of OF 1.0 and 1.1 from switch
                # max of OF 1.2 from Ryu and supported_ofp_version = (1.0, 1.2)
                # negotiated version = 1.1
                # usable version = 1.0
                #
                # TODO: In order to get the version 1.0, Ryu need to send
                # supported verions.
                error_desc = (
                    'no compatible version found: '
                    'switch versions 0x%x controller version 0x%x, '
                    'the negotiated version is %s but found usable %s. '
                    'If possible, '
                    'set the switch to use one of OF version %s' % (
                        max(switch_versions),
                        max(datapath.supported_ofp_version),
                        sorted(negotiated_versions),
                        sorted(usable_versions), sorted(usable_versions)))
                self._hello_failed(datapath, error_desc)
                return
        else:
            usable_versions = set(version for version
                                  in datapath.supported_ofp_version
                                  if version <= msg.version)
            if (usable_versions and
                max(usable_versions) != min(msg.version,
                                            datapath.ofproto.OFP_VERSION)):
                # The version of min(msg.version, datapath.ofproto.OFP_VERSION)
                # should be used according to the spec. But we can't.
                # So log it and use max(usable_versions) with the hope that
                # the switch is able to understand lower version.
                # e.g.
                # OF 1.1 from switch
                # OF 1.2 from Ryu and supported_ofp_version = (1.0, 1.2)
                # In this case, 1.1 should be used according to the spec,
                # but 1.1 can't be used.
                #
                # OF1.3.1 6.3.1
                # Upon receipt of this message, the recipient must
                # calculate the OpenFlow protocol version to be used. If
                # both the Hello message sent and the Hello message
                # received contained a OFPHET_VERSIONBITMAP hello element,
                # and if those bitmaps have some common bits set, the
                # negotiated version must be the highest version set in
                # both bitmaps. Otherwise, the negotiated version must be
                # the smaller of the version number that was sent and the
                # one that was received in the version fields.  If the
                # negotiated version is supported by the recipient, then
                # the connection proceeds. Otherwise, the recipient must
                # reply with an OFPT_ERROR message with a type field of
                # OFPET_HELLO_FAILED, a code field of OFPHFC_INCOMPATIBLE,
                # and optionally an ASCII string explaining the situation
                # in data, and then terminate the connection.
                version = max(usable_versions)
                error_desc = (
                    'no compatible version found: '
                    'switch 0x%x controller 0x%x, but found usable 0x%x. '
                    'If possible, set the switch to use OF version 0x%x' % (
                        msg.version, datapath.ofproto.OFP_VERSION,
                        version, version))
                self._hello_failed(datapath, error_desc)
                return

        if not usable_versions:
            error_desc = (
                'unsupported version 0x%x. '
                'If possible, set the switch to use one of the versions %s' % (
                    msg.version, sorted(datapath.supported_ofp_version)))
            self._hello_failed(datapath, error_desc)
            return
        datapath.set_version(max(usable_versions))

        # Move on to config state
        self.logger.debug('move onto config mode')
        datapath.set_state(CONFIG_DISPATCHER)

        # Finally, send feature request
        features_request = datapath.ofproto_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(features_request)

    @set_ev_handler(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        self.logger.debug('switch features ev %s', msg)

        datapath.id = msg.datapath_id

        # hacky workaround, will be removed. OF1.3 doesn't have
        # ports. An application should not depend on them. But there
        # might be such bad applications so keep this workaround for
        # while.
        if datapath.ofproto.OFP_VERSION < 0x04:
            datapath.ports = msg.ports
        else:
            datapath.ports = {}

        if datapath.ofproto.OFP_VERSION < 0x04:
            self.logger.debug('move onto main mode')
            ev.msg.datapath.set_state(MAIN_DISPATCHER)
        else:
            port_desc = datapath.ofproto_parser.OFPPortDescStatsRequest(
                datapath, 0)
            datapath.send_msg(port_desc)

    @set_ev_handler(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def multipart_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            for port in msg.body:
                datapath.ports[port.port_no] = port

        if msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        self.logger.debug('move onto main mode')
        ev.msg.datapath.set_state(MAIN_DISPATCHER)

    @set_ev_handler(ofp_event.EventOFPEchoRequest,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_request_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        echo_reply = datapath.ofproto_parser.OFPEchoReply(datapath)
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        datapath.send_msg(echo_reply)

    @set_ev_handler(ofp_event.EventOFPEchoReply,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        datapath.acknowledge_echo_reply(msg.xid)

    @set_ev_handler(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if msg.reason in [ofproto.OFPPR_ADD, ofproto.OFPPR_MODIFY]:
            datapath.ports[msg.desc.port_no] = msg.desc
        elif msg.reason == ofproto.OFPPR_DELETE:
            datapath.ports.pop(msg.desc.port_no, None)
        else:
            return

        self.send_event_to_observers(
            ofp_event.EventOFPPortStateChange(
                datapath, msg.reason, msg.desc.port_no),
            datapath.state)

    @set_ev_handler(ofp_event.EventOFPErrorMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        self.logger.debug(
            "EventOFPErrorMsg received.\n"
            "version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
            " `-- msg_type: %s\n"
            "OFPErrorMsg(type=%s, code=%s, data=b'%s')\n"
            " |-- type: %s\n"
            " |-- code: %s",
            hex(msg.version), hex(msg.msg_type), hex(msg.msg_len),
            hex(msg.xid), ofp.ofp_msg_type_to_str(msg.msg_type),
            hex(msg.type), hex(msg.code), utils.binary_str(msg.data),
            ofp.ofp_error_type_to_str(msg.type),
            ofp.ofp_error_code_to_str(msg.type, msg.code))
        if len(msg.data) >= ofp.OFP_HEADER_SIZE:
            (version, msg_type, msg_len, xid) = ofproto_parser.header(msg.data)
            self.logger.debug(
                " `-- data: version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
                "     `-- msg_type: %s",
                hex(version), hex(msg_type), hex(msg_len), hex(xid),
                ofp.ofp_msg_type_to_str(msg_type))
        else:
            self.logger.warning(
                "The data field sent from the switch is too short: "
                "len(msg.data) < OFP_HEADER_SIZE\n"
                "The OpenFlow Spec says that the data field should contain "
                "at least 64 bytes of the failed request.\n"
                "Please check the settings or implementation of your switch.")
