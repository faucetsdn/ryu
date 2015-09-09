# conding=utf-8
import logging
import struct
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from ryu.openexchange.network import network_aware
from ryu.openexchange.network import network_monitor
from ryu.openexchange.routing_algorithm.routing_algorithm import dijkstra
from ryu.openexchange.utils import utils


class Shortest_forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Aware": network_aware.Network_Aware,
        "Network_Monitor": network_monitor.Network_Monitor,
    }

    def __init__(self, *args, **kwargs):
        super(Shortest_forwarding, self).__init__(*args, **kwargs)
        self.name = 'shortest_forwarding'
        self.network_aware = kwargs["Network_Aware"]
        self.network_monitor = kwargs["Network_Monitor"]
        self.mac_to_port = {}
        self.datapaths = {}

        # links   :(src_dpid,dst_dpid)->(src_port,dst_port)
        self.link_to_port = self.network_aware.link_to_port

        # {sw :[host1_ip,host2_ip,host3_ip,host4_ip]}
        self.access_table = self.network_aware.access_table

        # dpid->port_num (ports without link)
        self.access_ports = self.network_aware.access_ports

        self.outer_ports = self.network_aware.outer_ports
        self.outer_hosts = set()

        self.graph = self.network_aware.graph

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def get_host_location(self, host_ip):
        for key in self.access_table:
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.debug("%s location is not found." % host_ip)
        return None

    def get_path(self, graph, src):
        result = dijkstra(graph, src)
        if result:
            path = result[1]
            return path
        self.logger.debug("Path is not found.")
        return None

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = utils._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)

    def arp_forwarding(self, msg, src_ip, dst_ip):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # dst in other domain, send to super and return.
        if dst_ip in self.outer_hosts:
            if isinstance(msg, parser.OFPPacketIn):
                self.network_aware.raise_sbp_packet_in_event(
                    msg, ofproto_v1_3.OFPP_LOCAL, msg.data)
                return
        # host in domain.
        result = self.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = utils._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                          ofproto.OFPP_CONTROLLER,
                                          out_port, msg.data)
            datapath.send_msg(out)
        else:
            self.flood(msg)
            # we can not send arp to super every time.
            if isinstance(msg, parser.OFPPacketIn):
                self.network_aware.raise_sbp_packet_in_event(
                    msg, ofproto_v1_3.OFPP_LOCAL, msg.data)
        # packet_out from super, record src.
        if isinstance(msg, parser.OFPPacketOut):
            for sw in self.access_table:
                if src_ip in self.access_table[sw]:
                    return
            self.outer_hosts.add(src_ip)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        src_sw = dst_sw = None

        src_location = self.get_host_location(ip_src)
        dst_location = self.get_host_location(ip_dst)
        if src_location:
            src_sw = src_location[0]
        if dst_location:
            dst_sw = dst_location[0]

        path_dict = self.get_path(self.graph, src_sw)
        if path_dict:
            if dst_sw:
                path = path_dict[src_sw][dst_sw]
                path.insert(0, src_sw)

                flow_info = (eth_type, ip_src, ip_dst, msg.match['in_port'])
                utils.install_flow(self.datapaths, self.link_to_port,
                                   self.access_table, path, flow_info,
                                   msg.buffer_id, msg.data)
            else:
                if isinstance(msg, parser.OFPPacketIn):
                    self.network_aware.raise_sbp_packet_in_event(
                        msg, ofproto_v1_3.OFPP_LOCAL, msg.data)
        else:
            # Reflesh the topology database.
            self.network_aware.get_topology(None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            In packet_in handler, we need to learn access_table by ARP.
            Therefore, the first packet from UNKOWN host MUST be ARP.
        '''
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype

        if datapath.id in self.outer_ports:
            if in_port in self.outer_ports[datapath.id]:
                # The packet from other domain, ignore it.
                return
        # We implemente oxp in a big network,
        # so we shouldn't care about the subnet and router.
        if isinstance(arp_pkt, arp.arp):
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)
