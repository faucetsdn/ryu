'''
Define SBP handler for SBP events.

Author:www.muzixing.com
Date                Work
2015/7/29           new this file

Plan to be replaced by CONF.

'''

import itertools
import logging
import ryu.base.app_manager
from ryu.lib import hub
from ryu import utils

from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.ofproto import ofproto_common, ofproto_parser
from ryu.topology import switches

from ryu.openexchange.oxproto_common import OXP_DEFAULT_FLAGS
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange.domain import config
from ryu.openexchange.event import oxp_event
from ryu.openexchange.super import oxp_server_handler
from ryu.openexchange.super import topology
from ryu.openexchange.super.oxp_super import Super_Controller

from ryu import cfg
CONF = cfg.CONF


class OXP_SBP_Handler(ryu.base.app_manager.RyuApp):

    _CONTEXTS = {"topology": topology.Topology}

    def __init__(self, *args, **kwargs):
        super(OXP_SBP_Handler, self).__init__(*args, **kwargs)
        self.name = 'oxp_sbp_handler'
        self.topology = kwargs["topology"]
        self.topo = self.topology.topo

    @set_ev_cls(oxp_event.EventOXPSBPPacketIn, MAIN_DISPATCHER)
    def sbp_packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match['in_port']
        domain = ev.domain
        data = msg.data

        try:
            src_domain_id, src_vport_no = switches.LLDPPacket.lldp_parse(data)
            if OXP_DEFAULT_FLAGS == CONF.oxp_flags & OXP_DEFAULT_FLAGS:
                link = {(domain.id, in_port, src_domain_id, src_vport_no): 1}
                self.topo.update_link(link)

        except switches.LLDPPacket.LLDPUnknownFormat as e:
            return
        # Todo other packet in handler. routing request.
