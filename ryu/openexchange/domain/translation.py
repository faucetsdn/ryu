"""
Translate Packet_out and Flow_mod.
Author:www.muzixing.com

Date                Work
2015/9/1            new Translation.
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

from ryu.topology import event, switches

from ryu.openexchange.event import oxp_event
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxproto_v1_0_parser
from ryu.openexchange.oxproto_v1_0 import OXPP_ACTIVE
from ryu.openexchange.oxproto_v1_0 import OXPPS_LIVE
from ryu.openexchange import topology_data
from ryu.openexchange.routing_algorithm.routing_algorithm import get_paths
from ryu import cfg
from ryu.lib import hub

CONF = cfg.CONF


class Translation(app_manager.RyuApp):
    """Translation module translate the Packet_out and Flow_mod from super."""

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Translation, self).__init__(*args, **kwargs)
        self.name = 'oxp_translation'

        self.args = args
        self.network = app_manager.lookup_service_brick("Network_Aware")

        self.domain = None
        self.oxparser = oxproto_v1_0_parser
        self.oxproto = oxproto_v1_0

    @set_ev_cls(oxp_event.EventOXPSBPPacketOut, MAIN_DISPATCHER)
    def sbp_packet_in_handler(self, ev):
        msg = ev.msg
        print msg.__dict__
        # translate and packet out.
        #sbp_pkt = self.oxparser.OXPSBP(self.domain, data=msg.buf)
        #self.domain.send_msg(sbp_pkt)
        return
