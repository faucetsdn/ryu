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
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0, ofproto_v1_2
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import lldp
from ryu.lib.mac import DONTCARE_STR
from ryu.lib import hub
import ryu.base.app_manager as app_manager

from ryu.topology import event, switches
from ryu.topology.switches import Switches
from ryu.topology.api import get_switch, get_link

from ryu.openexchange.event.oxp_event import EventOXPVportStatus
from ryu.openexchange.oxproto_v1_0 import OXPPS_LINK_DOWN, OXPPS_BLOCKED
from ryu.openexchange.oxproto_v1_0 import OXPPS_LIVE
from ryu.openexchange.oxproto_v1_0 import OXPP_ACTIVE
from ryu.openexchange.oxproto_v1_0 import OXPP_INACTIVE
from ryu.openexchange.event import oxp_event
from ryu import cfg

CONF = cfg.CONF
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
        self.period = CONF.oxp_period
        # use for hiding infomation to super.
        self.fake_datapath = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        if self.fake_datapath is None:
            self.fake_datapath = datapath

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
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_port_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            # self.outer_ports.setdefault(dpid, set())
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

        # If the topo change, reset the CONF.oxp_period.
        # So, topo_reply module can reply in time.
        CONF.oxp_period = self.period

    @set_ev_cls(event.EventSwitchLeave,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER])
    def delete_sw(self, ev):
        for key in self.access_table:
            if ev.switch.dp.id == key[0]:
                event = oxp_event.EventOXPHostStateChange(
                    self, hosts=[(self.access_table[key][0],
                                  self.access_table[key][1], OXPP_INACTIVE)])
                self.oxp_brick.send_event_to_observers(event, MAIN_DISPATCHER)

    @set_ev_cls(event.EventPortDelete, MAIN_DISPATCHER)
    def delete_host(self, ev):
        if (ev.port.dpid, ev.port.port_no) in self.access_table:
            event = oxp_event.EventOXPHostStateChange(
                self, hosts=[(self.access_table[key][0],
                              self.access_table[key][1], OXPP_INACTIVE)])
            self.oxp_brick.send_event_to_observers(event, MAIN_DISPATCHER)

    def register_access_info(self, dpid, in_port, ip, mac):
        # Todo:reduce the duplicate host update.
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    ev = oxp_event.EventOXPHostStateChange(
                        self, hosts=[(ip, mac, OXPP_ACTIVE)])
                    self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                ev = oxp_event.EventOXPHostStateChange(
                    self, hosts=[(ip, mac, OXPP_ACTIVE)])
                self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)
                return
        # in case the error recode of other domain's host.
        if dpid in self.outer_ports:
            if in_port in self.outer_ports[dpid]:
                if (dpid, in_port) in self.access_table:
                    ip, mac = self.access_table[(dpid, in_port)]

                    ev = oxp_event.EventOXPHostStateChange(
                        self, hosts=[(ip, mac, OXPP_INACTIVE)])
                    self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)

                    del self.access_table[(dpid, in_port)]

    def _send_lldp(self, datapath, in_port, vport_no):
        lldp_pkt = switches.LLDPPacket.lldp_packet(datapath.id, in_port,
                                                   DONTCARE_STR,
                                                   Switches.DEFAULT_TTL,
                                                   vport_no=vport_no)
        dp = datapath
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
            dp.send_packet_out(actions=actions, data=lldp_pkt)
        elif dp.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
            out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp, in_port=dp.ofproto.OFPP_CONTROLLER,
                buffer_id=dp.ofproto.OFP_NO_BUFFER, actions=actions,
                data=lldp_pkt)
            dp.send_msg(out)
        else:
            LOG.error('cannot send lldp packet. unsupported version. %x',
                      dp.ofproto.OFP_VERSION)

    def raise_sbp_packet_in_event(self, msg, vport_no, data):
        msg.match.set_in_port(vport_no)
        pkt_in = ofproto_v1_3_parser.OFPPacketIn(
            self.fake_datapath, buffer_id=msg.buffer_id,
            total_len=msg.total_len, reason=msg.reason, table_id=msg.table_id,
            cookie=msg.cookie, match=msg.match, data=data)

        ev = oxp_event.sbp_to_oxp_msg_to_ev(pkt_in)
        self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)
        return

    def register_outer_port(self, msg, in_port, src_domain_id, src_vport_no):
        if src_domain_id != CONF.oxp_domain_id:
            dst_dpid = msg.datapath.id
            dst_port_no = in_port

            # register out_port.
            if dst_dpid not in self.outer_ports:
                self.outer_ports.setdefault(dst_dpid, set())
            if dst_port_no not in self.outer_ports[dst_dpid]:
                self.outer_ports[dst_dpid].add(dst_port_no)
                self.vport[self.outer_port_no] = (dst_dpid, dst_port_no)

                self.access_ports[dst_dpid].remove(dst_port_no)

                # raise event and send to handler.
                ev = oxp_event.EventOXPVportStateChange(
                    domain=self, vport_no=self.outer_port_no, state=OXPPS_LIVE)
                self.oxp_brick.send_event_to_observers(ev, MAIN_DISPATCHER)

                # send lldp to neighbor domain.
                self._send_lldp(msg.datapath, in_port, self.outer_port_no)

                # raise event of packet_in to send lldp to super.
                if src_vport_no != ofproto_v1_0.OFPP_NONE:
                    dst_vport_no = None
                    for key in self.vport:
                        if (dst_dpid, dst_port_no) == self.vport[key]:
                            dst_vport_no = key
                            break

                    lldp_pkt = switches.LLDPPacket.lldp_packet(
                        src_domain_id, src_vport_no,
                        DONTCARE_STR, Switches.DEFAULT_TTL)
                    self.raise_sbp_packet_in_event(msg, dst_vport_no, lldp_pkt)

                self.outer_port_no += 1

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        if datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            in_port = msg.in_port
        elif datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            in_port = msg.match['in_port']

        data = msg.data
        pkt = packet.Packet(data)

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # Dirty code. Try other way to trigger.
        if isinstance(arp_pkt, arp.arp):
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            src_mac = arp_pkt.src_mac
            self.register_access_info(
                datapath.id, in_port, arp_src_ip, src_mac)
            return
        else:
            try:
                src_dpid, src_port_no, src_domain_id, src_vport_no = \
                    switches.LLDPPacket.oxp_lldp_parse(data)
            except switches.LLDPPacket.LLDPUnknownFormat as e:
                # If non-LLDP, Ignore it silently
                return
            self.register_outer_port(msg, in_port, src_domain_id, src_vport_no)

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
