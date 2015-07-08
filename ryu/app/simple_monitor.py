from __future__ import division
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.topology.tracker import Tracker
from ryu.lib.pce.path_computing import all_feasible_path

TOR_LAYER = 3000
AGGREGATION_LAYER = 2000
CORE_LAYER = 1000


class SimpleMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _NAME = 'monitor'
    _CONTEXTS = {
        "tracker": Tracker
    }

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.access_table = {}
        self.sleep = 5
        self.tracker = kwargs["tracker"]
        self.tor_level = TOR_LAYER
        self.agg_level = AGGREGATION_LAYER
        self.core_level = CORE_LAYER
        self.tor_list = []
        self.UPT = {}   # Up path table.
        self.link_dist = {}
        self.ARP_table = {}

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

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=0, hard_timeout=30,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _save_stats(self, dist, key, value, length):
        if key not in dist:
                dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
<<<<<<< HEAD
        if period:
            return (now-pre)/(period * 8)
        else:
            return 0
=======
        return (now-pre)/period
>>>>>>> 5058a3bf4f998d4b00a99491b7a76d188797d0db

    def _get_time(self, sec, nsec):
        return sec + nsec/(10**9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def create_up_path(self, tor, graph_cap, tor_list):
        up_path = {}  # up_path={tor:{[agg1,agg2]:[core1,core2]}}
        agg_list = []
        up_path.setdefault(tor, [])  # up_path[tor]=[[agg],[core]]
        if tor in graph_cap:
            for key in graph_cap[tor].keys():
                agg_list.append(key)  # collect the aggregation switches.
            up_path[tor].append(agg_list)

            # up_path[tor] =[[aggregation],[core]]
            for agg in agg_list:
                core_list = []
                if agg in graph_cap:
                    for key in graph_cap[agg].keys():
                    # collect the aggregation switches.
                        if key not in tor_list:
                            core_list.append(key)
                    up_path[tor].append(core_list)

            return up_path

    # according to tor dpid to find up path.
    def findUppath(self, start, end, UPT):
        path = []
        if start in UPT:
            if end in UPT[start][0]:
                path.append((start, end))
                return path
            elif end in UPT[start][1]:
                path.append((start, UPT[start][0][0]))
                path.append((UPT[start][0][0], end))
                return path
            elif end in UPT[start][2]:
                path.append((start, UPT[start][0][1]))
                path.append((UPT[start][0][1], end))
                return path
            else:
                return None

    def find_top_sw(self, src, dst):
        if src in self.UPT and dst in self.UPT:
            consw = list(
                set(self.UPT[src][0]).intersection(set(self.UPT[dst][0])))
            if consw:
                return self.UPT[src][0]
            else:
                return self.UPT[src][1], self.UPT[src][2]

    # get reverse path
    def path_reverse(self, path):
        r_path = []
        if path:
            for p in path:
                src, dst = p
                r_path.append((dst, src))
            return r_path[::-1]

    def get_link2port(self, src_dpid, dst_dpid):
        if (src_dpid, dst_dpid) in self.link_dist:
            return self.link_dist[(src_dpid, dst_dpid)]
        else:
            return None

    def get_UPT(self):
        graph_cap, graph_port = self.tracker.get_capacity_graph()
        if self.tracker.dps.keys():
            for dpid in self.tracker.dps.keys():
                if dpid > self.tor_level and graph_cap and self.tor_list:
                    table = self.create_up_path(dpid, graph_cap, self.tor_list)
                    if table:
                        self.UPT.update(table)
        return self.UPT

    def get_link_dist(self):
        '''
        return link_dist = (dpid1,dpid2):(port1,port2,bw)
        graph_cap = {dpid:{dpid:cap, dpid, cap}}
        graph_port = {dpid:{dpid:src_port}}
        '''

        graph_cap, graph_port = self.tracker.get_capacity_graph()
        set_cap = [100, 1000]

        for src_dpid in graph_cap:
            for dst_dpid in graph_cap[src_dpid]:
                capacity = set_cap[int((src_dpid+dst_dpid)/4000)]
                src_port = graph_port[src_dpid][dst_dpid]
                if dst_dpid in graph_port:
                    if src_dpid in graph_port[dst_dpid]:
                        dst_port = graph_port[dst_dpid][src_dpid]
                    else:
                        dst_port = None
                else:
                    dst_port = None

                if (src_dpid, src_port) in self.port_speed:
                    current_speed = self.port_speed[(src_dpid, src_port)][-1]
                else:
                    current_speed = 0
                bw = capacity - current_speed/1000
                graph_cap[src_dpid][dst_dpid] = bw
                self.link_dist[(src_dpid, dst_dpid)] = (src_port, dst_port, bw)

        return self.link_dist

    def get_tor_list(self):
        for dpid in self.tracker.dps.keys():    # we find tor here. dirty code.
            if dpid > self.tor_level:
                self.tor_list.append(dpid)
        return self.tor_list

    def get_access_table(self):
        '''
        # use tracker module to learn access_table.
        for h in self.tracker.hosts_route:
            if self.tracker.hosts_route[h].keys():
                for host in self.tracker.hosts_route[h].keys():
                    ip_addr = host.ip_addr
                    key = self.tracker.hosts_route[h][host]
                    self.access_table[key] = ip_addr
        '''

        self._create_access_table(8, 4)
        return self.access_table

    def _create_access_table(self, k, density):
        ip_list = []
        mac_list = []
        tor_number = int(k*k/2)
        for i in range(1, tor_number*density+1):
            temp_ip = [10, 0, 0, i]
            ipadd = '.'.join(map(lambda x: "%d" % x, temp_ip))
            ip_list.append(ipadd)

            temp_mac = [0x00, 0x00, 0x00, 0x00, 0x00, i]
            macadd = ':'.join(map(lambda x: "%02x" % x, temp_mac))
            mac_list.append(macadd)

        for i in range(0, len(ip_list)):
            self.ARP_table[ip_list[i]] = mac_list[i]

        for dp in xrange(1, tor_number+1):
            for i in xrange(density):
                host = (dp - 1) * density + i
                self.access_table[(dp+3000, k/2+1+i)] = ip_list[host]

    def convert(self, UPT):
        """
        link_dsit {(dpid1,dpid2):(p1,p2, bw)}
        UPT=  {TOR:[[a1, a2],[c11, c22], [c21, c22]]}
        self.AGGREGATION_Table = {(agg_dpid,agg_port):(tor_dpid,tor_port)}
        self.CORE_Table = {(core_dpid,core_port):(agg_dpid,agg_port)}
        you can get your table info from self.convert.
        """
        agg2tor = {}
        core2agg = {}
        if UPT:
            for tor in UPT.keys():
                i = 0
                for a in UPT[tor][0]:
                    port = self.get_link2port(a, tor)
                    if port:
                        agg2tor[a, port[0]] = (tor, port[1])
                        i += 1
                        for c in UPT[tor][i]:
                            port = self.get_link2port(c, a)
                            if port:
                                core2agg[c, port[0]] = (a, port[1])
        return agg2tor, core2agg

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
        actions = []
        out_port = ofproto.OFPP_LOCAL

        if len(path) > 1:
            # the  first flow entry
            port_pair = self.get_link2port(path[0], path[1])
            out_port = port_pair[0]
            actions.append(parser.OFPActionOutput(out_port))
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=flow_info[0],
                ipv4_src=flow_info[1],
                ipv4_dst=flow_info[2])
            self.add_flow(datapath_first, 1, match, actions)

            # inter_link
            if len(path) > 2:
                for i in xrange(1, len(path)-1):
                    port = self.get_link2port(path[i-1], path[i])
                    port_next = self.get_link2port(path[i], path[i+1])
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
                        self.add_flow(datapath, 1, match, actions)

            # the last hop: tor -> host
            datapath = self.datapaths[path[-1]]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = []
            src_port = self.get_link2port(path[-2], path[-1])[1]

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
            self.add_flow(datapath, 1, match, actions)
            print "last flow install"

            # pkt_out
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(
                datapath=datapath_first, buffer_id=buffer_id,
                data=msg_data, in_port=in_port, actions=actions)

            datapath_first.send_msg(out)
        else:
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
            self.add_flow(datapath_first, 1, match, actions)

            #pkt_out
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(
                datapath=datapath_first, buffer_id=buffer_id,
                data=msg_data, in_port=in_port, actions=actions)

            datapath_first.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_type'],
                                             flow.match['ipv4_dst'])):
            key = (
                stat.match['in_port'], stat.match['ipv4_dst'],
                stat.instructions[0].actions[0].port,)
            value = (
                stat.packet_count, stat.byte_count,
                stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats, key, value, 5)

            # Get flow's speed.
            pre = 0
            period = self.sleep
            tmp = self.flow_stats[key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(
                    tmp[-1][2], tmp[-1][3],
                    tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(
                self.flow_stats[key][-1][1], pre, period)

            self._save_stats(self.flow_speed, key, speed, 5)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (ev.msg.datapath.id, stat.port_no)
                value = (
                    stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                    stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = self.sleep
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(
                        tmp[-1][3], tmp[-1][4],
                        tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0]+self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)
