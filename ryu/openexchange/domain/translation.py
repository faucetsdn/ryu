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

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.openexchange.network import network_aware
from ryu.openexchange.network import network_monitor
from ryu.openexchange.network import shortest_forwarding

from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER

from ryu.topology import event, switches

from ryu.openexchange.database import buffer_data
from ryu.openexchange.event import oxp_event
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxproto_v1_0_parser
from ryu.openexchange.oxproto_v1_0 import OXPP_ACTIVE
from ryu.openexchange.oxproto_v1_0 import OXPPS_LIVE
from ryu.openexchange import topology_data
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
        self.router = app_manager.lookup_service_brick('shortest_forwarding')
        self.domain = None
        self.oxparser = oxproto_v1_0_parser
        self.oxproto = oxproto_v1_0
        self.buffer = buffer_data.Buffer_Data()
        self.buffer_id = 0

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    actions = [parser.OFPActionOutput(port)]
                    datapath = self.datapaths[dpid]
                    out = parser.OFPPacketOut(
                        datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=msg.data)
                    datapath.send_msg(out)

    def arp_forwarding(self, msg, arp_pkt):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        arp_src_ip = arp_pkt.src_ip
        arp_dst_ip = arp_pkt.dst_ip

        result = self.get_host_location(arp_dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapaths[datapath_dst]

            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                actions=actions, in_port=ofproto.OFPP_CONTROLLER,
                data=msg.data)
            datapath.send_msg(out)
        else:
            self.flood(msg)
            # we can not send arp to super every time.
            if isinstance(msg, parser.OFPPacketIn):
                self.network_aware.raise_sbp_packet_in_event(
                    msg, ofproto_v1_3.OFPP_LOCAL, msg.data)

    @set_ev_cls(oxp_event.EventOXPSBPPacketOut, MAIN_DISPATCHER)
    def sbp_packet_out_handler(self, ev):
        msg = ev.msg
        domain = ev.domain

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        # Flood.
        if msg.actions[0].port == ofproto_v1_3.OFPP_LOCAL:
            if isinstance(arp_pkt, arp.arp):
                self.router.arp_forwarding(msg, arp_pkt)
            print "outer_hosts: ", self.router.outer_hosts
            #if isinstance(ip_pkt, ipv4.ipv4):
            #    self.shortest_forwarding(msg, eth_type, ip_pkt)

            #self.buffer.setdefault(self.buffer_id, None)
            #self.buffer[self.buffer_id]
            # print msg.__dict__
            # translate and packet out.
            #sbp_pkt = self.oxparser.OXPSBP(self.domain, data=msg.buf)
            #self.domain.send_msg(sbp_pkt)
            return
