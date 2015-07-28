"""
This file define the handler of OXP.
Author:www.muzixing.com
"""


"""
Basic OpenExchange handling including negotiation.
"""

import itertools
import logging

import ryu.base.app_manager

from ryu.lib import hub
from ryu import utils
from ryu.controller import ofp_event
from ryu.openexchange.oxp_domain import Domain_Controller
from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER


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


class OXP_Client_Handler(ryu.base.app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(OXP_Client_Handler, self).__init__(*args, **kwargs)
        self.name = 'oxp_event'

    def start(self):
        super(OXP_Client_Handler, self).start()
        return hub.spawn(Domain_Controller())

    def _hello_failed(self, domain, error_desc):
        self.logger.error(error_desc)
        error_msg = domain.oxproto_parser.OXPErrorMsg(domain)
        error_msg.type = domain.oxproto.OXPET_HELLO_FAILED
        error_msg.code = domain.oxproto.OXPHFC_INCOMPATIBLE
        error_msg.data = error_desc
        domain.send_msg(error_msg)

    @set_ev_handler(oxp_event.EventOXPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        self.logger.debug('hello ev %s', ev)
        msg = ev.msg
        domain = msg.domain

        # check if received version is supported.
        # pre 1.0 is not supported
        elements = getattr(msg, 'elements', None)
        if elements:
            domain_versions = set()
            for version in itertools.chain.from_iterable(
                    element.versions for element in elements):
                domain_versions.add(version)
            usable_versions = domain_versions & set(
                domain.supported_oxp_version)

            negotiated_versions = set(
                version for version in domain_versions
                if version <= max(domain.supported_oxp_version))
            if negotiated_versions and not usable_versions:
                # Ref:ryu.controller.ofp_handler
                error_desc = (
                    'no compatible version found: '
                    'domain versions %s super version 0x%x, '
                    'the negotiated version is 0x%x, '
                    'but no usable version found. '
                    'If possible, set the domain to use one of OX version %s'
                    % (domain_versions, max(domain.supported_oxp_version),
                       max(negotiated_versions),
                       sorted(domain.supported_oxp_version)))
                self._hello_failed(domain, error_desc)
                return
            if (negotiated_versions and usable_versions and
                    max(negotiated_versions) != max(usable_versions)):
                # Ref:ryu.controller.ofp_handler
                error_desc = (
                    'no compatible version found: '
                    'domain versions 0x%x super version 0x%x, '
                    'the negotiated version is %s but found usable %s. '
                    'If possible, '
                    'set the domain to use one of OX version %s' % (
                        max(domain_versions),
                        max(domain.supported_oxp_version),
                        sorted(negotiated_versions),
                        sorted(usable_versions), sorted(usable_versions)))
                self._hello_failed(domain, error_desc)
                return
        else:
            usable_versions = set(version for version
                                  in domain.supported_oxp_version
                                  if version <= msg.version)
            if (usable_versions and
                max(usable_versions) != min(msg.version,
                                            domain.oxproto.OXP_VERSION)):
                # Ref:ryu.controller.ofp_handler
                version = max(usable_versions)
                error_desc = (
                    'no compatible version found: '
                    'domain 0x%x super 0x%x, but found usable 0x%x. '
                    'If possible, set the domain to use OX version 0x%x' % (
                        msg.version, domain.oxproto.OXP_VERSION,
                        version, version))
                self._hello_failed(domain, error_desc)
                return

        if not usable_versions:
            error_desc = (
                'unsupported version 0x%x. '
                'If possible, set the domain to use one of the versions %s' % (
                    msg.version, sorted(domain.supported_oxp_version)))
            self._hello_failed(domain, error_desc)
            return
        domain.set_version(max(usable_versions))

        # now move on to config state
        self.logger.debug('move onto config mode')
        domain.set_state(CONFIG_DISPATCHER)

    @set_ev_handler(oxp_event.EventOXPDomainFeatures, CONFIG_DISPATCHER)
    def domain_features_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        self.logger.debug('switch features ev %s', msg)

        domain.id = msg.domain_id

        oxproto = domain.oxproto
        oxproto_parser = domain.oxproto_parser
        set_config = oxproto_parser.OXPSetConfig(
            domain, oxproto.OXPC_MODEL_DEFAULT, 20, 128
        )
        domain.send_msg(set_config)

        ev.msg.domain.set_state(MAIN_DISPATCHER)

    @set_ev_handler(oxp_event.EventOXPEchoRequest,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_request_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        echo_reply = domain.oxproto_parser.OXPEchoReply(domain)
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        domain.send_msg(echo_reply)

    @set_ev_handler(oxp_event.EventOXPErrorMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('error msg ev %s type 0x%x code 0x%x %s',
                         msg, msg.type, msg.code, utils.hex_array(msg.data))

    @set_ev_handler(oxp_event.EventOXPGetConfigReply,
                    [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def config_reply_handler(self, ev):
        msg = ev.msg
        domain = msg.domain

        domain.flags = msg.flags
        domain.period = msg.period  # domain should upload the new data
                                    # every period seconds whatever the data
                                    # change or not.If data is not changed,
                                    # domain will return no body but header.
                                    # which indicate domain respone to super
                                    # super doesn't need to do anything.

        domain.miss_send_lend = msg.miss_send_lend

    @set_ev_handler(oxp_event.EventOXPStateChange,
                    [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        #collet the domain.
        domain = ev.domain
        assert domain is not None
        LOG.debug(domain)

        if ev.state == MAIN_DISPATCHER:
            if domain.id not in self.topo.domains:
                self.topo.domains.append(domain.id)
                self.domain[domain.id] = domain
        elif ev.state == DEAD_DISPATCHER:
            self.topo.domains.remove(domain.id)
            del self.domain[domain.id]
        else:
            pass

    @set_ev_handler(oxp_event.EventOXPTopoReply, MAIN_DISPATCHER)
    def topo_reply_handler(self, ev):
        # parser the msg and save the topo data.
        msg = ev.msg
        domain = msg.domain
        domain_id = msg.domain_id

        oxproto = domain.oxproto
        oxproto_parser = domain.oxproto_parser

        self.links.domain_id = domain_id
        # link: (src_vport:1, dst_vport=2, capacities=123)
        self.links.update(msg.links)

    @set_ev_handler(oxp_event.EventOXPHostReply, MAIN_DISPATCHER)
    def host_reply_handler(self, ev):
        # parser the msg and save the host data.
        msg = ev.msg
        domain = msg.domain
        domain_id = msg.domain_id

        oxproto = domain.oxproto
        oxproto_parser = domain.oxproto_parser

        self.location.update(domain_id, msg.hosts)

    @set_ev_handler(oxp_event.EventOXPHostUpdate, MAIN_DISPATCHER)
    def host_update_handler(self, ev):
        # parser the msg and save the host data.
        msg = ev.msg
        domain = msg.domain
        domain_id = msg.domain_id

        oxproto = domain.oxproto
        oxproto_parser = domain.oxproto_parser

        self.location.update(domain_id, msg.hosts)

    @set_ev_handler(oxp_event.EventOXPSBP, MAIN_DISPATCHER)
    def SBP_handler(self, ev):
        # parser the msg and handle the SBP message.
        # raise the event.
        # finish it in service or app.
        pass
