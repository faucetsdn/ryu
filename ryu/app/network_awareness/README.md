## Network Awareness

Network Awareness is a set of Ryu applications to collecting the basic network information including the topology, link delay, and link free bandwidth. Also, the Shortest\_forwarding.py application can achieve the shortest path forwarding based on HOP, DELAY and BANDWIDTH. You can set model of computing shortest path when starting Ryu by adding "weight" argument. Moreover, you can set "k-paths" argument to support K-Shortest paths computing. Fortunately, our application supports load balance based on dynamic traffic information. 

The detail information of modules shows below.

* Network Aware is a module for collecting network information.

* Network Monitor is a module for collecting network traffic information.

* Network Delay is a module for collecting link delay information.

* Shortest\_forwarding is a simple application to achieve shortest forwarding based on hop or delay.

* Setting is the common setting module.



In this version, we take networkx's data structure to store topology. Meanwhile, we also use networkx's function to calculate shortest path.


### Download File

Download files, and add them to ryu directory, for instance, app/network_awareness

### Make some changes

To register parsing parameter, you NEED to add code into flags.py, which is in the topo directory of ryu project.

    CONF.register_cli_opts([
        # k_shortest_forwarding
        cfg.IntOpt('k-paths', default=1, help='number for k shortest paths'),
        cfg.StrOpt('weight', default='hop',
                   help='weight type of computing shortest path.')])


For using delay detector module, we should make some changes in topology/switches.py.

* Add self.delay for PortData in topology/switches.py module.


		class PortData(object):
		    def __init__(self, is_down, lldp_data):
		        super(PortData, self).__init__()
		        self.is_down = is_down
		        self.lldp_data = lldp_data
		        self.timestamp = None
		        self.sent = 0
		        self.delay = 0


* Also, add delay calculation code in Class Switches in topology/switches.py module.


	    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	    def packet_in_handler(self, ev):
	    	# add code for getting LLDP packet receiving timestamp
	        recv_timestamp = time.time()
	        if not self.link_discovery:
	            return

	        msg = ev.msg
	        try:
	            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
	        except LLDPPacket.LLDPUnknownFormat as e:
	            # This handler can receive all the packtes which can be
	            # not-LLDP packet. Ignore it silently
	            return

	        dst_dpid = msg.datapath.id
	        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
	            dst_port_no = msg.in_port
	        elif msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
	            dst_port_no = msg.match['in_port']
	        else:
	            LOG.error('cannot accept LLDP. unsupported version. %x',
	                      msg.datapath.ofproto.OFP_VERSION)

	        # get the lldp delay, and save it into port_data.
	        for port in self.ports.keys():
	            if src_dpid == port.dpid and src_port_no == port.port_no:
	                send_timestamp = self.ports[port].timestamp
	                if send_timestamp:
	                    self.ports[port].delay = recv_timestamp - send_timestamp



### Reinstall Ryu

You have to reinstall Ryu, so that you can run the new code. In the top derectory of ryu project.

    sudo python setup.py install 


### Start

Go into the directory, and run applications. You are suggested to add arguments when starting Ryu. The example shows below.

    ryu-manager shortest_forwarding.py --observe-links --k-paths=2  --weight=bw

The last step is to set up a network and connect to Ryu.

If you need to show collected information, you can set the parameter in setting.py. Also, you can define your personal setting, such as topology discovery period, You will find out the information shown in terninal.

Enjoy it! Good Luck!

If you have any question, you can email me. Don't forget to STAR this repository!
