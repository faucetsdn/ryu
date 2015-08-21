"""
Reply Topo data to super periodically.
Author:www.muzixing.com

Date                Work
2015/8/3            define topo reply

"""
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_0
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import set_ev_handler
from ryu.lib.ip import ipv4_to_bin
from ryu.lib.ip import ipv4_to_str
from ryu.lib.mac import haddr_to_bin

from ryu.openexchange.network import network_aware
from ryu.openexchange.network import network_monitor
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER

from ryu.openexchange import oxp_event
from ryu.openexchange.oxproto_common import OXP_MAX_PERIOD
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxproto_v1_0_parser
from ryu.openexchange.oxproto_v1_0 import OXPP_ACTIVE
from ryu.openexchange.oxproto_v1_0 import OXPPS_LIVE
from ryu.openexchange import topology_data
from ryu.openexchange.routing_algorithm.routing_algorithm import get_paths
from ryu import cfg
from ryu.lib import hub

CONF = cfg.CONF


class TopoReply(app_manager.RyuApp):
    """TopoReply achieve the periodical topo reply."""

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "Network_Aware": network_aware.Network_Aware,
        "Network_Monitor": network_monitor.Network_Monitor,
    }

    def __init__(self, *args, **kwargs):
        super(TopoReply, self).__init__(*args, **kwargs)
        self.name = 'oxp_toporeply'
        self.args = args
        self.network = kwargs["Network_Aware"]
        self.monitor = kwargs["Network_Monitor"]
        self.domain = None
        self.oxparser = oxproto_v1_0_parser
        self.oxproto = oxproto_v1_0
        self.topology = topology_data.Domain()
        self.monitor_thread = hub.spawn(self._monitor)
        self.links = []

    def _monitor(self):
        while True:
            self.topo_reply()
            hub.sleep(CONF.oxp_period)

    @set_ev_cls(oxp_event.EventOXPFeaturesRequest, CONFIG_DISPATCHER)
    def features_request_handler(self, ev):
        self.logger.debug('hello ev %s', ev)
        msg = ev.msg
        # Only to get domain.
        self.domain = msg.domain
        self.topology.domain_id = self.domain.id

        self.oxproto = self.domain.oxproto
        self.oxparser = self.domain.oxproto_parser

    def create_links(self, vport=[], capabilities={}):
        links = []
        for src in vport:
            for dst in vport:
                src_dpid, src_port_no = self.network.vport[src]
                dst_dpid, dst_port_no = self.network.vport[dst]

                if src_dpid != dst_dpid and src_dpid > dst_dpid:
                    if src_dpid in capabilities:
                        if dst_dpid in capabilities[src_dpid]:
                            cap = capabilities[src_dpid][dst_dpid]
                        else:
                            continue
                    else:
                        continue

                    link = self.oxparser.OXPInternallink(src_vport=int(src),
                                                         dst_vport=int(dst),
                                                         capability=str(cap))
                    links.append(link)
        return links

    def get_capabilities(self):
        self.topology.ports = self.network.vport.keys()
        if len(self.topology.ports):
            capabilities, paths = get_paths(self.network.graph, CONF.oxp_flags)

            self.topology.capabilities = capabilities
            self.topology.paths = paths

            return self.create_links(self.topology.ports, capabilities)
        return None

    def topo_reply(self):
        links = self.get_capabilities()
        if links == self.links:
            if CONF.oxp_period < OXP_MAX_PERIOD:
                CONF.oxp_period += 1
            else:
                CONF.oxp_period = OXP_MAX_PERIOD
        else:
            self.links = links
            if self.domain:
                topo_reply = self.oxparser.OXPTopoReply(self.domain,
                                                        links=links)
                self.domain.send_msg(topo_reply)
