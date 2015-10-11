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


class DynamicLoadBalance(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {"monitor": SimpleMonitor,
                "tracker": Tracker}

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalance, self).__init__(*args, **kwargs)
        self.monitor = kwargs["monitor"]
        self.tracker = kwargs["tracker"]
        self.UPT = {} #UPT=  {TOR:[[a1, a2],[c11, c12], [c21, c22]]}
        self.TOR_Table = {} #{tor_dpid,in_port):host_ip}
        self.AGGREGATION_Table = {}#{(agg_dpid,agg_port):(tor_dpid,tor_port)}
        self.CORE_Table = {} #{(core_dpid,core_port):(agg_dpid,agg_port)}
        self.paths = [] # the set of path 
        self.path = [] # the list of chosen path
        self.pathlinks = {}   # pathlinks : {(dpid1,dpid2):(port_no1,port_no2,bandwidth)}
        self.is_active = True
        self.threads = []
        self.threads.extend([hub.spawn(self._get_stat)])
        self.up_path_list = []
        self.down_path_list = []
        self.global_path_list = []
    def  _get_stat(self):
        while(self.is_active):
            
            self.pathlinks = self.monitor.get_link_dist()
            self.tor_list = self.monitor.get_tor_list()
            self.TOR_Table = self.monitor.get_access_table()
            self.UPT = self.monitor.get_UPT()
            self.AGGREGATION_Table,self.CORE_Table = self.monitor.convert(self.UPT)
            hub.sleep(2)
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
                                    instructions=inst, hard_timeout=100)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=100)
        datapath.send_msg(mod)
    #  decide which layer need to access   
    def setAccessLayer(self,srcEdgeSW,dstEdgeSW):
        
        if srcEdgeSW == dstEdgeSW:
            return TOR_LAYER
        src_agg = self.findAggregationSwitch(srcEdgeSW)
        dst_agg = self.findAggregationSwitch(dstEdgeSW)
        if src_agg and dst_agg and set(src_agg).intersection(dst_agg):
            return AGGREGATION_LAYER
        else:
            return CORE_LAYER
    
###############################findSwitch#######################################
    def findTorSwitch(self,host_ip):#get tor_dpid
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

    #get core_dpid
    def findCoreSwitch(self,sw): 
        core_dpid = []

        for key in self.CORE_Table.keys():   
            if sw == self.CORE_Table[key][0]:
                core_dpid.append(key[0])
        return core_dpid

    def findNextSwitch(self,link):
        nextSW = link[1]
        return nextSW

##############################searchPath###########################
    def searchUpPath(self,curSW,cur_layer,accesslayer,sw_path_list):
        sw_path_list.append(curSW)
        if cur_layer == accesslayer:
            return sw_path_list 
        links = self.findLinks(curSW,cur_layer)#links: {((sw1,port_no1),(sw2,port_no2)):100K)}
        link  = self.findWorstFitLink(links) #link
        cur_sw = self.findNextSwitch(link)
        cur_layer = cur_layer + 1
        return self.searchUpPath(cur_sw,cur_layer,accesslayer,sw_path_list)
    
    def searchDownPath(self,curSW,dpid,accesslayer,sw_path_list):
        if accesslayer == 2:
            for key in self.findAggregationSwitch(curSW):
                for i in self.findCoreSwitch(key):
                    if i == dpid:
                        sw_path_list.append(key)
                        sw_path_list.append(curSW)
                        return sw_path_list
        if accesslayer == 1:
            sw_path_list.append(curSW)
            return sw_path_list   
        else:
            return sw_path_list

    def findLinks(self,curSW,layer): #return [(dpid1,dpid2)]
        paths = []
        if layer == 0:#TOR
            agg_dpids= self.findAggregationSwitch(curSW)
            for key in agg_dpids:
                paths.append((curSW,key))
            return paths 
        elif layer == 1:#Aggregation
            core_dpids = self.findCoreSwitch(curSW)
            for key in core_dpids:
                paths.append((curSW,key))
            return paths

    def findWorstFitLink(self,link):   #input list[(dpid1,dpid2)],return 
        band = []
        for t in link:
            if t[0]>t[1]:
                band.append(self.pathlinks[t][2])
                
                worst_bandwidth = max(band)
                # print worst_bandwidth
                result = []
                for key in self.pathlinks.keys():
                    if key in link:
                        if self.pathlinks[key][2] == worst_bandwidth:
                            #  return {key:pathlinks[key]}
                            self.path.append(key)
                            return key

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #print "PKT IN"
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
            layer = self.setAccessLayer(srcEdgeSW,dstEdgeSW)
            cur_layer = 0
            up_path = self.searchUpPath(srcEdgeSW,cur_layer,layer,[])
            all_path = self.searchDownPath(dstEdgeSW,up_path[-1],layer,up_path)

            flow_info = (eth_type, ip_src, ip_dst, in_port)
            self.monitor.install_flow(all_path, flow_info, msg.buffer_id, msg.data)
