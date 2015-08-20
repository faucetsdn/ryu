******************
Snort Intergration
******************

This document describes how to integrate Ryu with Snort.

Overview
========

There are two options can send alert to Ryu controller. The Option 1 is easier if you just want to demonstrate or test. Since Snort need very large computation power for analyzing packets you can choose Option 2 to separate them.  

**[Option 1] Ryu and Snort are on the same machine**
::

          +---------------------+
          |      unixsock       |
          |    Ryu  ==  snort   |
          +----eth0-----eth1----+
                 |       |
    +-------+   +----------+   +-------+
    | HostA |---| OFSwitch |---| HostB |
    +-------+   +----------+   +-------+


The above depicts Ryu and Snort architecture. Ryu receives Snort alert packet via **Unix Domain Socket** . To monitor packets between HostA and HostB, installing a flow that mirrors packets to Snort.


**[Option 2] Ryu and Snort are on the different machines**
::

              +---------------+
              |    Snort     eth0--|
              |   Sniffer     |    |
              +-----eth1------+    |
                     |             |
    +-------+   +----------+   +-----------+
    | HostA |---| OFSwitch |---| LAN (*CP) |
    +-------+   +----------+   +-----------+
                     |             |
                +----------+   +----------+
                |  HostB   |   |   Ryu    |
                +----------+   +----------+


**\*CP: Control Plane**

The above depicts Ryu and Snort architecture. Ryu receives Snort alert packet via **Network Socket** . To monitor packets between HostA and HostB, installing a flow that mirrors packets to Snort.



Installation Snort
==================
Snort is an open source network intrusion prevention and detectionsystem developed by Sourcefire. If you are not familiar with installing/setting up Snort, please referto snort setup guides.

http://www.snort.org/documents



Configure Snort
===============
The configuration example is below:

- Add a snort rules file into ``/etc/snort/rules`` named ``Myrules.rules`` ::

      alert icmp any any -> any any (msg:"Pinging...";sid:1000004;)
      alert tcp any any -> any 80 (msg:"Port 80 is accessing"; sid:1000003;)

- Add the custom rules in ``/etc/snort/snort.conf`` ::

      include $RULE_PATH/Myrules.rules

Configure NIC as a promiscuous mode. ::

    $ sudo ifconfig eth1 promisc


Usage
=====
**[Option 1]**

1. Modify the ``simple_switch_snort.py``: ::

    socket_config = {'unixsock': True}
    # True: Unix Domain Socket Server [Option1]
    # False: Network Socket Server [Option2]


2. Run Ryu with sample application: ::

    $ sudo ./bin/ryu-manager ryu/app/simple_switch_snort.py

The incoming packets will all mirror to **port 3** which should be connect to Snort network interface. You can modify the mirror port by assign a new value in the ``self.snort_port = 3`` of ``simple_switch_snort.py``

3. Run Snort: ::

    $ sudo -i
    $ snort -i eth1 -A unsock -l /tmp -c /etc/snort/snort.conf

4. Send an ICMP packet from HostA (192.168.8.40) to HostB (192.168.8.50): ::

    $ ping 192.168.8.50

5. You can see the result under next section.


**[Option 2]**

1. Modify the ``simple_switch_snort.py``: ::

    socket_config = {'unixsock': False}
    # True: Unix Domain Socket Server [Option1]
    # False: Network Socket Server [Option2]


2. Run Ryu with sample application (On the Controller): ::

    $ ./bin/ryu-manager ryu/app/simple_switch_snort.py

3. Run Snort (On the Snort machine): ::

    $ sudo -i
    $ snort -i eth1 -A unsock -l /tmp -c /etc/snort/snort.conf

4. Run ``pigrelay.py`` (On the Snort machine): ::

    $ sudo python pigrelay.py

This program listening snort alert messages from unix domain socket and sending it to Ryu using network socket.

You can clone the source code from this repo. https://github.com/John-Lin/pigrelay


5. Send an ICMP packet from HostA (192.168.8.40) to HostB (192.168.8.50): ::

    $ ping 192.168.8.50


6. You can see the alert message below: ::


    alertmsg: Pinging...
    icmp(code=0,csum=19725,data=echo(data=array('B', [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 97, 98, 99, 100, 101, 102, 103, 104, 105]),id=1,seq=78),type=8)

    ipv4(csum=42562,dst='192.168.8.50',flags=0,header_length=5,identification=724,offset=0,option=None,proto=1,src='192.168.8.40',tos=0,total_length=60,ttl=128,version=4)

    ethernet(dst='00:23:54:5a:05:14',ethertype=2048,src='00:23:54:6c:1d:17')


    alertmsg: Pinging...
    icmp(code=0,csum=21773,data=echo(data=array('B', [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 97, 98, 99, 100, 101, 102, 103, 104, 105]),id=1,seq=78),type=0)

    ipv4(csum=52095,dst='192.168.8.40',flags=0,header_length=5,identification=7575,offset=0,option=None,proto=1,src='192.168.8.50',tos=0,total_length=60,ttl=64,version=4)
