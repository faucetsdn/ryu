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
from ryu.openexchange import oxp_event
from ryu.openexchange.oxp_super import Super_Controller
from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER, DEAD_DISPATCHER

from ryu.openexchange import topology_data as _topo
from ryu.openexchange import host_data

from ryu.openexchange.domain import config
from ryu import cfg


# The state transition: HANDSHAKE -> CONFIG -> MAIN
#
# HANDSHAKE: if it receives HELLO message with the valid OXP version,
# sends Features Request message, and moves to CONFIG.
#
# CONFIG: it receives Features Reply message and moves to MAIN
#
# MAIN: it does nothing. Applications are expected to register their
# own handlers.
#
# Note that at any state, when we receive Echo Request message, send
# back Echo Reply message.

CONF = cfg.CONF


class OXP_Server_Handler(ryu.base.app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(OXP_Server_Handler, self).__init__(*args, **kwargs)
        self.name = 'oxp_event'
        self.topo = _topo.Super_Topo()
        self.domain = {}

        self.location = host_data.Location()

    def start(self):
        super(OXP_Server_Handler, self).start()
        return hub.spawn(Super_Controller())

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

        # now send feature
        features_reqeust = domain.oxproto_parser.OXPFeaturesRequest(domain)
        # print "features_reqeust:", features_reqeust.__class__
        domain.send_msg(features_reqeust)

        # now move on to config state
        self.logger.debug('move onto config mode')
        domain.set_state(CONFIG_DISPATCHER)

    @set_ev_handler(oxp_event.EventOXPDomainFeatures, CONFIG_DISPATCHER)
    def domain_features_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        self.logger.debug('domain features ev %s', msg)

        domain.id = msg.domain_id

        oxproto_parser = domain.oxproto_parser

        set_config = oxproto_parser.OXPSetConfig(
            domain, CONF.oxp_flags, CONF.oxp_period,
            CONF.oxp_miss_send_len)

        domain.send_msg(set_config)

        get_config_request = oxproto_parser.OXPGetConfigRequest(domain)
        domain.send_msg(get_config_request)

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

        domain.miss_send_len = msg.miss_send_len

    @set_ev_cls(oxp_event.EventOXPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        #collet the domain.
        domain = ev.domain
        assert domain is not None
        self.logger.debug(domain)

        if ev.state == MAIN_DISPATCHER:
            if domain.id not in self.topo.domains:
                self.topo.domains.add(domain.id)
                self.domain[domain.id] = _topo.Domain(domain_id=domain.id)
                self.location.locations.setdefault(domain.id, set())

        elif ev.state == DEAD_DISPATCHER:
            self.topo.domains.remove(domain.id)
            del self.domain[domain.id]
        else:
            pass

    @set_ev_handler(oxp_event.EventOXPVportStatus, MAIN_DISPATCHER)
    def vport_status_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        self.domain[domain.id].update_port(msg)
        self.topo.update_link(msg)

    @set_ev_handler(oxp_event.EventOXPTopoReply, MAIN_DISPATCHER)
    def topo_reply_handler(self, ev):
        # parser the msg and save the topo data.
        msg = ev.msg
        domain = msg.domain
        self.domain[domain.id].update_link(domain, msg.links)

    @set_ev_handler(oxp_event.EventOXPHostReply, MAIN_DISPATCHER)
    def host_reply_handler(self, ev):
        # parser the msg and save the host data.
        msg = ev.msg
        domain = msg.domain

        oxproto = domain.oxproto
        oxproto_parser = domain.oxproto_parser

        self.location.update(domain.id, msg.hosts)

    @set_ev_handler(oxp_event.EventOXPHostUpdate, MAIN_DISPATCHER)
    def host_update_handler(self, ev):
        # parser the msg and save the host data.
        msg = ev.msg
        domain = msg.domain

        oxproto = domain.oxproto
        oxproto_parser = domain.oxproto_parser

        self.location.update(domain.id, msg.hosts)
        topo_request = domain.oxproto_parser.OXPTopoRequest(domain)
        domain.send_msg(topo_request)

    @set_ev_handler(oxp_event.EventOXPSBP, MAIN_DISPATCHER)
    def SBP_handler(self, ev):
        # parser the msg and handle the SBP message.
        # raise the event.
        # finish it in service or app.
        pass
