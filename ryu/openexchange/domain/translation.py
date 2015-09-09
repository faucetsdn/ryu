"""
Translate Packet_out and Flow_mod.
Author:www.muzixing.com

Date                Work
2015/9/1            new Translation.
"""

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.openexchange.event import oxp_event
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxproto_v1_0_parser
from ryu.openexchange.utils import utils

from ryu import cfg

CONF = cfg.CONF


class Translation(app_manager.RyuApp):
    """Translation module translate the Packet_out and Flow_mod from super."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Translation, self).__init__(*args, **kwargs)
        self.name = 'oxp_translation'

        self.args = args
        self.network = app_manager.lookup_service_brick("Network_Aware")
        self.router = app_manager.lookup_service_brick('shortest_forwarding')
        self.domain = None
        self.oxparser = oxproto_v1_0_parser
        self.oxproto = oxproto_v1_0
        self.buffer = {}
        self.buffer_id = 0

    @set_ev_cls(oxp_event.EventOXPSBPPacketOut, MAIN_DISPATCHER)
    def sbp_packet_out_handler(self, ev):
        msg = ev.msg
        domain = ev.domain

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype

        if msg.actions[0].port == ofproto_v1_3.OFPP_LOCAL:
            if isinstance(arp_pkt, arp.arp):
                self.router.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)
            #save msg.data for flow_mod.
            elif isinstance(ip_pkt, ipv4.ipv4):
                self.buffer[(eth_type, ip_pkt.src, ip_pkt.dst)] = msg.data
        else:
            # packet_out to datapath:port.
            vport = msg.actions[0].port
            dpid, port = self.network.vport[vport]
            datapath = self.router.datapaths[dpid]
            ofproto = datapath.ofproto
            out = utils._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                          ofproto.OFPP_CONTROLLER,
                                          port, msg.data)
            #save msg.data for flow_mod.
            if isinstance(ip_pkt, ipv4.ipv4):
                self.buffer[(eth_type, ip_pkt.src, ip_pkt.dst)] = msg.data
            datapath.send_msg(out)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        src_sw = dst_sw = outer_port = data = None
        in_port = msg.match['in_port']

        src_location = self.router.get_host_location(ip_src)
        dst_location = self.router.get_host_location(ip_dst)
        if src_location:
            src_sw, in_port = src_location
        else:
            src_sw, in_port = self.network.vport[in_port]

        if dst_location:
            dst_sw = dst_location[0]
        else:
            for i in msg.instructions:
                if isinstance(i, parser.OFPInstructionActions):
                    for action in i.actions:
                        if isinstance(action, parser.OFPActionOutput):
                            vport = action.port
                            dst_sw, outer_port = self.network.vport[vport]
                            break

        path_dict = self.router.get_path(self.router.graph, src_sw)
        if path_dict:
            if dst_sw:
                path = path_dict[src_sw][dst_sw]
                path.insert(0, src_sw)
                self.logger.debug(
                    " PATH[%s --> %s]:%s" % (ip_src, ip_dst, path))

                flow_info = (eth_type, ip_src, ip_dst, in_port)
                if (eth_type, ip_src, ip_dst) in self.buffer:
                    data = self.buffer[(eth_type, ip_src, ip_dst)]
                    del self.buffer[(eth_type, ip_src, ip_dst)]
                utils.install_flow(self.router.datapaths,
                                   self.router.link_to_port,
                                   self.router.access_table, path, flow_info,
                                   ofproto.OFP_NO_BUFFER, data,
                                   outer_port=outer_port)
                # we should save pakact_out data by buffer.id.
        else:
            self.network.get_topology(None)

    @set_ev_cls(oxp_event.EventOXPSBPFlowMod, MAIN_DISPATCHER)
    def sbp_flow_mod_handler(self, ev):
        msg = ev.msg
        domain = ev.domain

        ip_src = msg.match['ipv4_src']
        ip_dst = msg.match['ipv4_dst']
        eth_type = msg.match['eth_type']

        self.shortest_forwarding(msg, eth_type, ip_src, ip_dst)
