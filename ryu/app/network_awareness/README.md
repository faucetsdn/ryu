##Network Awareness

Network Awareness is a set of Ryu applications to collecting the basic network information including the topology, link delay, and link free bandwidth. Also, the Shortest\_forwarding.py application can achieve the shortest path forwarding based on hop or delay. Actually, it can based on bandwidth easily if you make a little bit change of code. The detail information of modules shows below.

* NetworkAwareness is a module for collecting network information.

* NetworkMonitor is a module for collecting network traffic information.

* NetworkDelayDetector is a module for collecting link delay information. [Coming soon]

* ShortestForwarding is a simple application to achieve shortest forwarding based on hop or delay.


In this version, we take networkx's data structure to store topology. Meanwhile, we also use networkx's function to calculate shortest path.


###Download File

Download files, and add them to ryu directory, for instance, app/network_awareness

### Reinstall Ryu

You have to reinstall Ryu, so that you can run the new code. In the top derectory of ryu project.

    sudo python setup.py install 


###Start

Go into the directory, and run applications.

    ryu-manager shortest_forwarding.py --observe-links

The last step is to set up a network and connect to Ryu.

You will find out the information shown in terninal.

Good Luck!
