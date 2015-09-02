"""
This is Topology module for OXP.
Author:www.muzixing.com

Date                Work
2015/8/27           new this file

"""

import itertools
import logging

import ryu.base.app_manager

from ryu.lib import hub
from ryu import utils
from ryu.openexchange.event import oxp_event
from ryu.openexchange.super.oxp_super import Super_Controller
from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER, DEAD_DISPATCHER

from ryu.openexchange.database import topology_data
from ryu.openexchange.database import host_data
from ryu.openexchange import oxproto_v1_0
from ryu.ofproto import ofproto_common, ofproto_parser

from ryu.openexchange.domain import config
from ryu import cfg

CONF = cfg.CONF


class Topology(ryu.base.app_manager.RyuApp):
    '''
        Collect topology data include host data and topo data.
    '''
    def __init__(self, *args, **kwargs):
        super(Topology, self).__init__(*args, **kwargs)
        self.name = 'oxp_topology'
        self.topo = topology_data.Super_Topo()
        self.location = host_data.Location()
        self.domains = {}

    @set_ev_cls(oxp_event.EventOXPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        domain = ev.domain
        if ev.state == MAIN_DISPATCHER:
            if domain.id not in self.topo.domains.keys():
                self.topo.domains.setdefault(domain.id, None)

                domain_topo = topology_data.Domain(domain_id=domain.id)
                self.topo.domains[domain.id] = domain_topo
                self.location.locations.setdefault(domain.id, set())

                topo_request = domain.oxproto_parser.OXPTopoRequest(domain)
                domain.send_msg(topo_request)
                self.logger.info("Domain[%s] connected." % domain.id)
            else:
                self.logger.info("same domain id ocurred: %s" % domain.id)
        if ev.state == DEAD_DISPATCHER:
            del self.topo.domains[domain.id]
            del self.location.locations[domain.id]
            self.logger.info("Domain[%s] leave." % domain.id)

    @set_ev_cls(oxp_event.EventOXPVportStatus, MAIN_DISPATCHER)
    def vport_status_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        self.topo.update_port(msg)

    @set_ev_cls(oxp_event.EventOXPTopoReply, MAIN_DISPATCHER)
    def topo_reply_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        self.topo.domains[domain.id].update_link(domain, msg.links)

    @set_ev_cls(oxp_event.EventOXPHostReply, MAIN_DISPATCHER)
    def host_reply_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        self.location.update(domain.id, msg.hosts)

    @set_ev_cls(oxp_event.EventOXPHostUpdate, MAIN_DISPATCHER)
    def host_update_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        self.location.update(domain.id, msg.hosts)
        self.logger.info("Host reply: ", self.location.locations)
