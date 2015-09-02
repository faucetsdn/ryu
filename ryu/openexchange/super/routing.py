# conding=utf-8
import logging
import struct
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import controller
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_0_parser

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from ryu.openexchange.network import network_aware
from ryu.openexchange.network import network_monitor

from ryu.openexchange import oxproto_v1_0
from ryu.openexchange.routing_algorithm.routing_algorithm import dijkstra
from ryu.openexchange.utils import utils
from ryu.openexchange.event import oxp_event


class Route(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(Route, self).__init__(*args, **kwargs)
        self.module_topo = app_manager.lookup_service_brick('oxp_topology')
        self.topology = self.module_topo.topo
        self.location = self.module_topo.location
        self.domains = {}
        self.fake_datapath = None

        self.mac_to_port = {}
        # links   :(src_dpid,dst_dpid)->(src_port,dst_port)
        # self.link_to_port = self.network_aware.link_to_port

        # {sw :[host1_ip,host2_ip,host3_ip,host4_ip]}
        # self.access_table = self.network_aware.access_table

        # dpid->port_num (ports without link)
        # self.access_ports = self.network_aware.access_ports
        # self.outer_ports = self.network_aware.outer_ports

        # self.graph = self.network_aware.graph

    @set_ev_cls(oxp_event.EventOXPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        domain = ev.domain
        if ev.state == MAIN_DISPATCHER:
            if domain.id not in self.domains.keys():
                self.domains.setdefault(domain.id, None)
                self.domains[domain.id] = domain
        if ev.state == DEAD_DISPATCHER:
            del self.domains[domain.id]
        '''
        if self.fake_datapath is None:
            self.fake_datapath = controller.Datapath(
                domain.socket, domain.address)
            if domain.sbp_proto_type == oxproto_v1_0.OXPS_OPENFLOW:
                if domain.sbp_proto_version == 4:
                    self.fake_datapath.ofproto = ofproto_v1_3
                    self.fake_datapath.ofproto_parser = ofproto_v1_3_parser
                elif domain.sbp_proto_version == 1:
                    self.fake_datapath.ofproto = ofproto_v1_0
                    self.fake_datapath.ofproto_parser = ofproto_v1_0_parser
        '''
    def get_host_location(self, host_ip):
        for domain_id in self.location.locations:
            if host_ip in self.location.locations[domain_id]:
                return domain_id
        self.logger.debug("%s location is not found." % host_ip)
        return None

    def get_path(self, graph, src):
        result = dijkstra(graph, src)
        if result:
            path = result[1]
            return path
        self.logger.debug("Path is not found.")
        return None

    def arp_forwarding(self, domain, msg, arp_pkt):
        # datapath = self.fake_datapath
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        arp_src_ip = arp_pkt.src_ip
        arp_dst_ip = arp_pkt.dst_ip
        self.logger.info("src_ip: %s, dst_ip: %s " % (arp_src_ip, arp_dst_ip))

        domain_id = self.get_host_location(arp_dst_ip)
        if domain_id:
            # build packet_out pkt and put it into sbp, send to domain
            domain = self.domains[domain_id]

            actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                actions=actions, in_port=ofproto.OFPP_CONTROLLER,
                data=msg.data)
            out.serialize()

            sbp_pkt = domain.oxproto_parser.OXPSBP(domain, data=out.buf)
            domain.send_msg(sbp_pkt)
        else:   # access info is not existed. send to all UNknow access port
            for domain in self.domains.values():
                actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions, data=msg.data)
                out.serialize()

                sbp_pkt = domain.oxproto_parser.OXPSBP(domain, data=out.buf)
                domain.send_msg(sbp_pkt)

    def shortest_forwarding(self, domain, msg, eth_type, ip_pkt):
        ip_src = ip_pkt.src
        ip_dst = ip_pkt.dst
        result = src_sw = dst_sw = None

        src_domain = self.get_host_location(ip_src)
        dst_domain = self.get_host_location(ip_dst)
        # calculate the path.
        result = dijkstra(self.graph, src_sw)
        if result:
            path = result[1][src_sw][dst_sw]
            path.insert(0, src_sw)
            #self.logger.info(
            #    " PATH[%s --> %s]:%s\n" % (ip_src, ip_dst, path))

            flow_info = (eth_type, ip_src, ip_dst, msg.match['in_port'])
            utils.install_flow(self.datapaths, self.link_to_port,
                               self.access_table, path, flow_info,
                               msg.buffer_id, msg.data)
        else:
            # Reflesh the topology database.
            self.network_aware.get_topology(None)

    @set_ev_cls(oxp_event.EventOXPSBPPacketIn, MAIN_DISPATCHER)
    def _sbp_packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match['in_port']
        domain = ev.domain
        data = msg.data

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype

        # We implemente oxp in a big network,
        # so we shouldn't care about the subnet and router.

        if isinstance(arp_pkt, arp.arp):
            self.arp_forwarding(domain, msg, arp_pkt)

        if isinstance(ip_pkt, ipv4.ipv4):
            # self.shortest_forwarding(domain, msg, eth_type, ip_pkt)
            pass
