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

import network_aware
import network_monitor


class Shortest_Route(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Aware": network_aware.Network_Aware,
        "Network_Monitor": network_monitor.Network_Monitor,
    }

    def __init__(self, *args, **kwargs):
        super(Shortest_Route, self).__init__(*args, **kwargs)
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

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def install_flow(self, path, flow_info, buffer_id, data):
        '''
            path=[dpid1, dpid2, dpid3...]
            flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        # first flow entry
        in_port = flow_info[3]
        assert path
        datapath_first = self.datapaths[path[0]]
        ofproto = datapath_first.ofproto
        parser = datapath_first.ofproto_parser
        out_port = ofproto.OFPP_LOCAL

        # inter_link
        if len(path) > 2:
            for i in xrange(1, len(path) - 1):
                port = self.get_link2port(path[i - 1], path[i])
                port_next = self.get_link2port(path[i], path[i + 1])
                if port:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = self.datapaths[path[i]]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    actions = []

                    actions.append(parser.OFPActionOutput(dst_port))
                    match = parser.OFPMatch(
                        in_port=src_port,
                        eth_type=flow_info[0],
                        ipv4_src=flow_info[1],
                        ipv4_dst=flow_info[2])
                    self.add_flow(
                        datapath, 1, match, actions,
                        idle_timeout=10, hard_timeout=30)

                    # inter links pkt_out
                    msg_data = None
                    if buffer_id == ofproto.OFP_NO_BUFFER:
                        msg_data = data

                    out = parser.OFPPacketOut(
                        datapath=datapath, buffer_id=buffer_id,
                        data=msg_data, in_port=src_port, actions=actions)

                    datapath.send_msg(out)

        if len(path) > 1:
            # the  first flow entry
            port_pair = self.get_link2port(path[0], path[1])
            out_port = port_pair[0]

            actions = []
            actions.append(parser.OFPActionOutput(out_port))
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=flow_info[0],
                ipv4_src=flow_info[1],
                ipv4_dst=flow_info[2])
            self.add_flow(datapath_first,
                          1, match, actions, idle_timeout=10, hard_timeout=30)

            # the last hop: tor -> host
            datapath = self.datapaths[path[-1]]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = []
            src_port = self.get_link2port(path[-2], path[-1])[1]
            dst_port = None

            for key in self.access_table.keys():
                if flow_info[2] == self.access_table[key]:
                    dst_port = key[1]
                    break
            actions.append(parser.OFPActionOutput(dst_port))
            match = parser.OFPMatch(
                in_port=src_port,
                eth_type=flow_info[0],
                ipv4_src=flow_info[1],
                ipv4_dst=flow_info[2])

            self.add_flow(
                datapath, 1, match, actions, idle_timeout=10, hard_timeout=30)

            # first pkt_out
            actions = []

            actions.append(parser.OFPActionOutput(out_port))
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(
                datapath=datapath_first, buffer_id=buffer_id,
                data=msg_data, in_port=in_port, actions=actions)

            datapath_first.send_msg(out)

            # last pkt_out
            actions = []
            actions.append(parser.OFPActionOutput(dst_port))
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=buffer_id,
                data=msg_data, in_port=src_port, actions=actions)

            datapath.send_msg(out)

        else:  # src and dst on the same
            out_port = None
            actions = []
            for key in self.access_table.keys():
                if flow_info[2] == self.access_table[key]:
                    out_port = key[1]
                    break

            actions.append(parser.OFPActionOutput(out_port))
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=flow_info[0],
                ipv4_src=flow_info[1],
                ipv4_dst=flow_info[2])
            self.add_flow(
                datapath_first, 1, match, actions,
                idle_timeout=10, hard_timeout=30)

            # pkt_out
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(
                datapath=datapath_first, buffer_id=buffer_id,
                data=msg_data, in_port=in_port, actions=actions)

            datapath_first.send_msg(out)

    def get_host_location(self, host_ip):
        for key in self.access_table:
            if self.access_table[key] == host_ip:
                return key
        self.logger.debug("%s location is not found." % host_ip)
        return None

    def get_path(self, graph, src):
        result = self.dijkstra(graph, src)
        if result:
            path = result[1]
            return path
        self.logger.debug("Path is not found.")
        return None

    def get_link2port(self, src_dpid, dst_dpid):
        if (src_dpid, dst_dpid) in self.link_to_port:
            return self.link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.debug("Link to port is not found.")
            return None

    def dijkstra(self, graph, src):
        if graph is None:
            self.logger.debug("Graph is empty.")
            return None
        length = len(graph)
        type_ = type(graph)

        # Initiation
        if type_ == list:
            nodes = [i for i in xrange(length)]
        elif type_ == dict:
            nodes = graph.keys()
        visited = [src]
        path = {src: {src: []}}
        if src not in nodes:
            self.logger.debug("Src is not in nodes.")
            return None
        else:
            nodes.remove(src)
        distance_graph = {src: 0}
        pre = next = src
        no_link_value = 100000

        while nodes:
            distance = no_link_value
            for v in visited:
                for d in nodes:
                    new_dist = graph[src][v] + graph[v][d]
                    if new_dist <= distance:
                        distance = new_dist
                        next = d
                        pre = v
                        graph[src][d] = new_dist

            if distance < no_link_value:
                path[src][next] = [i for i in path[src][pre]]
                path[src][next].append(next)
                distance_graph[next] = distance
                visited.append(next)
                nodes.remove(next)
            else:
                self.logger.debug("Next node is not found.")
                return None

        return distance_graph, path

    '''
    In packet_in handler, we need to learn access_table by ARP.
    Therefore, the first packet from UNKOWN host MUST be ARP.
    '''

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            # record the access info
            if in_port in self.access_ports[datapath.id]:
                self.access_table[(datapath.id, in_port)] = arp_src_ip

            result = self.get_host_location(arp_dst_ip)
            if result:  # host record in access table.
                datapath_dst, out_port = result[0], result[1]
                actions = [parser.OFPActionOutput(out_port)]
                datapath = self.datapaths[datapath_dst]

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions, data=msg.data)
                datapath.send_msg(out)
            else:       # access info is not existed. send to all host.
                for dpid in self.access_ports:
                    for port in self.access_ports[dpid]:
                        if (dpid, port) not in self.access_table.keys():
                            actions = [parser.OFPActionOutput(port)]
                            datapath = self.datapaths[dpid]
                            out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions, data=msg.data)
                            datapath.send_msg(out)

        if isinstance(ip_pkt, ipv4.ipv4):

            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst

            result = None
            src_sw = None
            dst_sw = None

            src_location = self.get_host_location(ip_src)
            dst_location = self.get_host_location(ip_dst)

            if src_location:
                src_sw = src_location[0]

            if dst_location:
                dst_sw = dst_location[0]
            result = self.dijkstra(self.graph, src_sw)

            if result:
                path = result[1][src_sw][dst_sw]
                path.insert(0, src_sw)
                self.logger.info(
                    " PATH[%s --> %s]:%s\n" % (ip_src, ip_dst, path))

                flow_info = (eth_type, ip_src, ip_dst, in_port)
                self.install_flow(path, flow_info, msg.buffer_id, msg.data)
            else:
                # Reflesh the topology database.
                self.network_aware.get_topology(None)
