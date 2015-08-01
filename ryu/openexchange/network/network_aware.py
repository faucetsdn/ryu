# conding=utf-8
import logging
import struct
import time
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
import ryu.base.app_manager as app_manager

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from ryu.openexchange.oxp_event import EventOXPVportStatus
from ryu.openexchange.oxproto_v1_0 import OXPPS_LINK_DOWN, OXPPS_BLOCKED
from ryu.openexchange.oxproto_v1_0 import OXPPS_LIVE
from ryu.openexchange.oxproto_v1_0 import OXPP_ACTIVE
from ryu.openexchange import oxp_event

IS_UPDATE = True


class Network_Aware(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _NAME = 'network_aware'

    _EVENT = [oxp_event.EventOXPVportStateChange,
              oxp_event.EventOXPHostStateChange]

    def __init__(self, *args, **kwargs):
        super(Network_Aware, self).__init__(*args, **kwargs)
        self.name = "Network_Aware"
        self.topology_api_app = self

        # links   :(src_dpid,dst_dpid)->(src_port,dst_port)
        self.link_to_port = {}

        # {(sw,port) :[host1_ip,host2_ip,host3_ip,host4_ip]}
        # Todo: handle the leave host.
        self.access_table = {}

        # cache access_table if for reduce the number of
        # event and oxphost update msg.
        # self.cache_access_table = {}
        # self.hosts = []

        self.switch_port_table = {}  # dpid->port_num

        # dpid->port_num (access ports)
        self.access_ports = {}

        # dpid->port_num(interior ports)
        self.interior_ports = {}

        self.outer_ports = {}
        self.outer_port_no = 1
        self.vport = {}

        self.graph = {}

        self.pre_link_to_port = {}
        self.pre_graph = {}
        self.pre_access_table = {}
        self.oxp_brick = None
        # self.sync_thread = hub.spawn(self._synchoronous(3))

    # synchoronous the host data with super controller per Xs.
    #def _synchoronous(self, seconds=5):
    #    start = time.time()
    #    while True:
    #        now = time.time()
    #        if now - start > 3:
    #            if self.oxp_brick is not None:
    #                self.synchronous()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

    def get_switches(self):
        return self.switches

    def get_links(self):
        return self.link_to_port

    # get Adjacency matrix from link_to_port
    def get_graph(self, link_list):
        for src in self.switches:
            for dst in self.switches:
                self.graph.setdefault(src, {dst: float('inf')})
                if src == dst:
                    self.graph[src][src] = 0
                elif (src, dst) in link_list:
                    self.graph[src][dst] = 1
                else:
                    self.graph[src][dst] = float('inf')
        return self.graph

        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.outer_ports.setdefault(dpip, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_port_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    # get links`srouce port to dst port  from link_list,
    # link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
    def create_interior_links(self, link_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        for sw in self.switch_port_table:
            self.access_ports[sw] = self.switch_port_table[
                sw] - self.interior_ports[sw]
                # we send the arp to the outer port too
                # stop it by - self.outer_ports[sw]

    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    @set_ev_cls(events, [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER])
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self.topology_api_app, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.get_graph(self.link_to_port.keys())
        # self.show_topology()
        if self.oxp_brick is None:
            self.oxp_brick = app_manager.lookup_service_brick('oxp_event')

    def register_access_info(self, dpid, in_port, ip, mac):
        if in_port in self.access_ports[dpid]:
            self.access_table[(dpid, in_port)] = ip
            ev = oxp_event.EventOXPHostStateChange(
                self, hosts=[(ip, mac, OXPP_ACTIVE)])
            self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)
            # self.cache_access_table[(dpid, in_port)] = ip
            # self.hosts.append((ip, mac, OXPP_ACTIVE))

    #def synchronous(self):
    #    if self.hosts is not None:
    #        ev = oxp_event.EventOXPHostStateChange(self, hosts=self.hosts)
    #        self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)
    #        self.cache_access_table = {}
    #        self.hosts = []

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        data = msg.data
        pkt = packet.Packet(data)

        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if isinstance(arp_pkt, arp.arp):
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            src_mac = arp_pkt.src_mac
            self.register_access_info(
                datapath.id, in_port, arp_src_ip, src_mac)

            '''
            Test , should be deleted.
            '''
            ev = oxp_event.EventOXPVportStateChange(
                self, vport_no=self.outer_port_no, state=OXPPS_LIVE)
            self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)

            return
        else:
            try:
                src_dpid, src_port_no = switches.LLDPPacket.lldp_parse(data)
            except switches.LLDPPacket.LLDPUnknownFormat as e:
                # This handler can receive all the packtes which can be
                # not-LLDP packet. Ignore it silently
                return

            # if src dpip not in self.dps, then, the port is an outer port.
            if src_dpid not in self.switches:
                dst_dpid = datapath.id
                dst_port_no = None

                if datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                    dst_port_no = msg.in_port
                elif datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
                    dst_port_no = msg.match['in_port']
                else:
                    LOG.error('cannot accept LLDP. unsupported version. %x',
                              msg.datapath.ofproto.OFP_VERSION)
                    return

                self.outer_ports[dst_dpid].add(dst_port_no)
                self.vport[self.outer_port_no] = (dst_dpid, dst_port_no)

                # raise event and send to handler.
                ev = oxp_event.EventOXPVportStateChange(
                    vport_no=self.outer_port_no, state=OXPPS_LIVE)
                self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)

                print "self.outer_ports:", self.outer_ports
                self.outer_port_no += 1

    # show topo
    def show_topology(self):
        switch_num = len(self.graph)
        if self.pre_graph != self.graph or IS_UPDATE:
            print "---------------------Topo Link---------------------"
            print '%10s' % ("switch"),
            for i in xrange(1, switch_num + 1):
                print '%10d' % i,
            print ""
            for i in self.graph.keys():
                print '%10d' % i,
                for j in self.graph[i].values():
                    print '%10.0f' % j,
                print ""
            self.pre_graph = self.graph
        # show link
        if self.pre_link_to_port != self.link_to_port or IS_UPDATE:
            print "---------------------Link Port---------------------"
            print '%10s' % ("switch"),
            for i in xrange(1, switch_num + 1):
                print '%10d' % i,
            print ""
            for i in xrange(1, switch_num + 1):
                print '%10d' % i,
                for j in xrange(1, switch_num + 1):
                    if (i, j) in self.link_to_port.keys():
                        print '%10s' % str(self.link_to_port[(i, j)]),
                    else:
                        print '%10s' % "No-link",
                print ""
            self.pre_link_to_port = self.link_to_port

        # each dp access host
        # {(sw,port) :[host1_ip,host2_ip,host3_ip,host4_ip]}
        if self.pre_access_table != self.access_table or IS_UPDATE:
            print "----------------Access Host-------------------"
            print '%10s' % ("switch"), '%12s' % "Host"
            if not self.access_table.keys():
                print "    NO found host"
            else:
                for tup in self.access_table:
                    print '%10d:    ' % tup[0], self.access_table[tup]
            self.pre_access_table = self.access_table
