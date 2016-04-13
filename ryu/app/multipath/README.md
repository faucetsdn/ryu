# Multipath

This module is a simple demo for multipath forwarding based on OpenFlow group table.

## Usage

* Download the multipath.py, and add it to a suitable location like ryu/app/multipath.py. Also, download the topo file and useful scripts.

* Reinstall Ryu by commond below.

		ryu/$ sudo python setup.py install

* Start multipath application.
	
For example:

	ryu-manager ryu/app/multipath.py

* Start up Mininet

		sudo mn --controller=remote --custom=yourpath/loop.py --topo=mytopo --mac 

* Set queue at ports

		sudo ./set_queue.sh

* View the info of queue
 
		sudo ./dump_queue.sh

* Pingall test and Iperf Test.

In mininet, use pingall of iperf commond to test

* View the info of flow table.

		sudo ./dump_s1_s4.sh

Good Luck!


