import logging
import struct
import math
from operator import attrgetter
from ryu.app.simple_monitor import SimpleMonitor
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.topology.tracker import Tracker
from ryu.controller import pktin_filter
#from ryu.topology.api import get_switch,get_link

TOR_LAYER = 0
AGGREGATION_LAYER = 1
CORE_LAYER = 2


class DynamicLoadSBalance(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {
    #    "monitor": SimpleMonitor
        # 'switches': switches.Switches, we can get many info from switches.
    #}
    _CONTEXTS = {"monitor": SimpleMonitor, "tracker": Tracker}

    def __init__(self, *args, **kwargs):
        super(DynamicLoadSBalance, self).__init__(*args, **kwargs)
        self.monitor = kwargs["monitor"]
        self.tracker = kwargs["tracker"]

        self.UPT = {}  # UPT=  {TOR:[[a1, a2],[c11, c12], [c21, c22]]}
        self.TOR_Table = {}  # {tor_dpid,in_port):host_ip}
        self.AGGREGATION_Table = {}
        # {(agg_dpid,agg_port):(tor_dpid,tor_port)}
        self.CORE_Table = {}  # {(core_dpid,core_port):(agg_dpid,agg_port)}

        self.paths = {}  # the set of path
        self.pathlinks = {}
        # pathlinks : {(dpid1,dpid2):(port_no1,port_no2,bandwidth)}

        self.is_active = True
        self.threads = []
        self.threads.extend([hub.spawn(self._get_stat)])
        # self.up_path_list = []
        # self.down_path_list = []
        # self.global_path_list = []
        # self.path = []  # the list of chosen path

    def _get_stat(self):
        while(self.is_active):
            self.pathlinks = self.monitor.get_link_dist()
            self.tor_list = self.monitor.get_tor_list()
            self.TOR_Table = self.monitor.get_access_table()
            self.UPT = self.monitor.get_UPT()
            self.AGGREGATION_Table, self.CORE_Table = self.monitor.convert(self.UPT)
            hub.sleep(1)

    def close(self):
        self.is_active = False
        hub.joinall(self.threads)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    #  decide which layer need to access
    def setAccessLayer(self, srcEdgeSW, dstEdgeSW):
        if srcEdgeSW == dstEdgeSW:
            return TOR_LAYER
        elif set(self.findAggregationSwitch(srcEdgeSW)).intersection(self.findAggregationSwitch(dstEdgeSW)):
            return AGGREGATION_LAYER
        else:
            return CORE_LAYER

###############################findSwitch#####################################
    def findTorSwitch(self, host_ip):  # get tor_dpid
        for key in self.TOR_Table.keys():
            if self.TOR_Table[key] == host_ip:
                return key[0]

    #get agg_dpid
    def findAggregationSwitch(self,sw): 
        #UPT=  {TOR:[[a1, a2],[c11, c12], [c21, c22]]}
        agg_dpid = None
        if sw in self.UPT:
            while agg_dpid is None:     # dangerous design. may be block forever.
                agg_dpid = self.UPT[sw][0]
        return agg_dpid
    '''
    def findAggregationSwitch(self, sw):
        # UPT=  {TOR:[[a1, a2],[c11, c12], [c21, c22]]}
        agg_dpid = self.UPT[sw][0]
        return agg_dpid
    '''
    #get core_dpid
    def findCoreSwitch(self, sw):
        core_dpid = []

        for key in self.CORE_Table.keys():
            if sw == self.CORE_Table[key][0]:
                core_dpid.append(key[0])
        return core_dpid

##############################searchPath###########################
    def findLinkbyDSLB(self, srcEdgeSW, dstEdgeSW):

        if srcEdgeSW == dstEdgeSW:
            return [srcEdgeSW]

        if (srcEdgeSW, dstEdgeSW) in self.paths:
            up_paths = self.paths[(srcEdgeSW, dstEdgeSW)][0]
            down_paths = self.paths[(srcEdgeSW, dstEdgeSW)][1]
        else:
            self.paths.setdefault((srcEdgeSW, dstEdgeSW), [])
            up_paths = self.getUpPath(srcEdgeSW, dstEdgeSW)
            down_paths = self.getDownPath(srcEdgeSW, dstEdgeSW, up_paths)
            self.paths[(srcEdgeSW, dstEdgeSW)] = [up_paths, down_paths]

        bu = self.getMinBandWidth(up_paths)
        bd = self.getMinBandWidth(down_paths)

        CV = []
        ab = []
        delta = []

        for i in range(0, len(bu)):
            ab.append(float((bd[i]+bu[i])/2))
            delta.append(float(math.sqrt((((bu[i]-ab[i])**2)+((bd[i]-ab[i])**2))/2)))
            CV.append(float(delta[i]/ab[i]))

        for i in range(0, len(CV)):
            if len(up_paths) == len(down_paths):
                path = list(up_paths[i]+down_paths[i])
                if CV[i] == min(CV):
                    return path

    def getMinBandWidth(self, links):
        min_bw = []
        for i in links:
            bw = []
            path = []

            path.append((i[0], i[1]))
            if len(i) == 3:
                path.append((i[1], i[2]))

            for t in path:
                bw.append((self.pathlinks[t][2]))  # bw=[bw1, bw2, bw3,...]
            min_bw.append(min(bw))

        return min_bw

    def getUpPath(self, srcEdgeSW, dstEdgeSW):
        up_path_list = []
        layer = self.setAccessLayer(srcEdgeSW, dstEdgeSW)
        if layer == 1:
            sw_set = list(set(self.findAggregationSwitch(srcEdgeSW)).intersection(self.findAggregationSwitch(dstEdgeSW)))
            for t in sw_set:
                up_path_list.append((srcEdgeSW, t))
        if layer == 2:
            for i in self.findAggregationSwitch(srcEdgeSW):
                for key in self.findCoreSwitch(i):
                    up_path_list.append((srcEdgeSW, i, key))

        return up_path_list

    def getDownPath(self, srcEdgeSW, dstEdgeSW, up_path_list):
        down_path_list = []
        accesslayer = self.setAccessLayer(srcEdgeSW, dstEdgeSW)
        if accesslayer == 2:
            for key in up_path_list:
                for t in self.findAggregationSwitch(dstEdgeSW):
                    for i in self.findCoreSwitch(t):
                        if i == key[-1]:
                            down_path_list.append((key[-1], t, dstEdgeSW))

        if accesslayer == 1:
            for key in up_path_list:
                for j in self.findAggregationSwitch(dstEdgeSW):
                    if j == key[-1]:
                        down_path_list.append((key[-1], dstEdgeSW))
        return down_path_list

    def getGlobalPath(self):
        return self.paths

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        ip = pkt.get_protocols(ipv4.ipv4)
        if ip:
            ip_src = ip[0].src
            ip_dst = ip[0].dst
            srcEdgeSW = self.findTorSwitch(ip_src)
            dstEdgeSW = self.findTorSwitch(ip_dst)
            layer = self.setAccessLayer(srcEdgeSW, dstEdgeSW)
            cur_layer = 0

            path = self.findLinkbyDSLB(srcEdgeSW, dstEdgeSW)
            path = sorted(set(path), key=path.index)
            # print path
            flow_info = (eth_type, ip_src, ip_dst, in_port)
            self.monitor.install_flow(path, flow_info, msg.buffer_id, msg.data)
