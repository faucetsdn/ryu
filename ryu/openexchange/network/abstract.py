"""
Define the community machanism.
Author:www.muzixing.com

Date                Work
2015/7/30           define abstract

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

from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxproto_v1_0_parser


class Abstract(app_manager.RyuApp):
    """Abstract complete the network abstract
    and handle the network information update."""

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "Network_Aware": network_aware.Network_Aware,
        "Network_Monitor": network_monitor.Network_Monitor,
    }

    def __init__(self, *args, **kwargs):
        super(Abstract, self).__init__(*args, **kwargs)
        self.name = 'oxp_abstract'
        self.args = args
        self.network = kwargs["Network_Aware"]
        self.monitor = kwargs["Network_Monitor"]
        self.domain = None
        self.oxparser = oxproto_v1_0_parser
        self.oxproto = oxproto_v1_0

    @set_ev_cls(oxp_event.EventOXPFeaturesRequest, CONFIG_DISPATCHER)
    def features_request_handler(self, ev):
        self.logger.debug('hello ev %s', ev)
        msg = ev.msg
        # Only to get domain.
        self.domain = msg.domain
        self.oxproto = self.domain.oxproto
        self.oxparser = self.domain.oxproto_parser

    @set_ev_cls(oxp_event.EventOXPVportStateChange, MAIN_DISPATCHER)
    def _vport_handler(self, ev):
        vport_no = ev.vport_no
        state = ev.state

        vport = self.oxparser.OXPVPort(vport_no=vport_no, state=state)
        vport_state_change = self.oxparser.OXPVportStatus(
            self.domain, vport=vport, reason=self.oxproto.OXPPR_ADD)

        self.domain.send_msg(vport_state_change)

    @set_ev_cls(oxp_event.EventOXPHostStateChange, MAIN_DISPATCHER)
    def _host_update_handler(self, ev):
        hosts = []
        for host in ev.hosts:
            h = self.oxparser.OXPHost(ip=ipv4_to_bin(host[0]),
                                      mac=haddr_to_bin(host[1]),
                                      mask=255, state=host[2])
            hosts.append(h)

        host_update = self.oxparser.OXPHostUpdate(self.domain, hosts)

        self.domain.send_msg(host_update)
