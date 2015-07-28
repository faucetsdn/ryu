import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4

from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches


class TopoLearning(app_manager.RyuApp):
	
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopoLearning, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.switches = []
        self.topo_list = []
        self.datapaths = {}
        self.link_to_port = {}
        self.access_table = {} #{sw :[host1_ip,host2_ip,host3_ip,host4_ip]}
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



    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)   
        self.switches=[switch.dp.id for switch in switch_list]
        #print "switches"
        #print self.switches
        
        links_list = get_link(self.topology_api_app, None)
        #print "links_list"
        #print links_list
        links={(link.src.dpid,link.dst.dpid):(link.src.port_no,link.dst.port_no) for link in links_list}
        #print "links"
        #print links
        self.link_to_port = links
        #print "get_link2port"
        #print self.link_to_port
        
        #print links
        
        for link in links.keys():
            if link[0] > link[1]:
                if link not in self.topo_list:
                    self.topo_list.append(link)
        #print "####################topo_list############"
        #print self.topo_list

    def get_link2port(self, src_dpid, dst_dpid):
        if (src_dpid, dst_dpid) in self.link_to_port:
            return self.link_to_port[(src_dpid, dst_dpid)]
        else:
            return None

    def get_access_table(self, switch_list):
        ip_list = []
        mac_list = []
        for i in range(1,len(switch_list) + 1):
            temp_ip = [10, 0, 0, i]
            ipadd = '.'.join(map(lambda x: "%d" % x, temp_ip))
            ip_list.append(ipadd)

            temp_mac = [0x00, 0x00, 0x00, 0x00, 0x00, i]
            macadd = ':'.join(map(lambda x: "%02x" % x, temp_mac))
            mac_list.append(macadd)

        for i in range(0, len(ip_list)):
            self.ARP_table[ip_list[i]] = mac_list[i]
        for sw in switch_list:
            self.access_table[(sw, 1)] = ip_list[sw - 1]
        return self.access_table

 
###########################################################################
    def add_flow(self, datapath, priority, match, actions,buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=30)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=30)
        datapath.send_msg(mod)
      
        
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

            
#########################################################################
    #get topo_graph
    def get_graph(self, p_topo):
        length = len(self.switches)
        graph = [[ -1 for col in range(length)] for row in range(length)]
        for i in range(0,length):
            for j in range(0,length):
                if i == j:
                    graph[i][j] = 0

                elif (i+1,j+1) in p_topo or (j+1,i+1) in p_topo:
                    graph[i][j] = 1
                    graph[j][i] = 1
                else:
                    graph[i][j] = 1000
        return graph

    def floyd(self,graph): 
        num= len(graph)
        nextnode=[]
        for i in range(0,num): 
            temp=[None]*num
            for j in range(0,num):
                if graph[i][j]!=1000 :
                    temp[j]=j
                else :
                    temp[j]=-1
            nextnode.append(temp)
        for i in range(0,num):
            for j in range(0,num):
                for k in range(0,num):
                    if(graph[j][k] > graph[j][i]+graph[i][k]):
                        graph[j][k] = graph[j][i]+graph[i][k]
                        nextnode[j][k]=nextnode[j][i]
        return nextnode

    def cal_shorest_path(self,i,j,nextnode):
        path =[]
        path.append(i+1)
        t=nextnode[i][j]
        while t!=j:
            path.append(t+1)
            t=nextnode[t][j]
        path.append(j+1)
        return path

    def findEdgeSwitch(self,host_ip):#get tor_dpid
        for key in self.access_table.keys():
            if self.access_table[key] == host_ip:
                return key[0]
#####################################################################
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)    
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        #print pkt
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        ip = pkt.get_protocols(ipv4.ipv4)
        #print "ip", ip
        #print "##########################link_to_port######################"
        #print self.link_to_port
        #print "##########################topo_list#########################"
        #print self.topo_list
        access_table = self.get_access_table(self.switches)
        #print "access_table"
        #print access_table
        maps = self.get_graph(self.topo_list)
        #print "maps:"
        #print maps
        self.nextnode = self.floyd(maps)
        #print "nextnode",self.nextnode
        #sw1 = 
        #path = self.cal_shorest_path(sw1 - 1,sw2-1,self.nextnode)
        if ip:
            ip_src = ip[0].src
            ip_dst = ip[0].dst
            srcEdgeSW = self.findEdgeSwitch(ip_src)
            dstEdgeSW = self.findEdgeSwitch(ip_dst)
            path = self.cal_shorest_path(srcEdgeSW - 1,dstEdgeSW - 1,self.nextnode)
            print "########################path########################"
            print path
            flow_info = (eth_type, ip_src, ip_dst, in_port)
            #print "flow_info"
            #print flow_info
            self.install_flow(path, flow_info, msg.buffer_id, msg.data)
        
	