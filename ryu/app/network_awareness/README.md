##Network Awareness

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
