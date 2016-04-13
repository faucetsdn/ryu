"""Custom loop topo example

   There are two paths between host1 and host2.

                |--------switch2 --------|
   host1 --- switch1        |            switch4 ----host2
                |           |            |  |______host3
                -------- switch3 ---------
                            |
                          host4

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo


class MyTopo(Topo):
    "Simple loop topology example."

    def __init__(self):
        "Create custom loop topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')
        host5 = self.addHost('h5')
        host6 = self.addHost('h6')
        switch1 = self.addSwitch("s1")
        switch2 = self.addSwitch("s2")
        switch3 = self.addSwitch("s3")
        switch4 = self.addSwitch("s4")
        switch5 = self.addSwitch("s5")

        # Add links
        self.addLink(switch1, host1, 1)
        self.addLink(switch1, switch2, 2, 1)
        self.addLink(switch1, switch3, 3, 1)
        self.addLink(switch2, switch4, 2, 1)
        self.addLink(switch3, switch4, 2, 2)
        self.addLink(switch2, switch3, 3, 4)
        self.addLink(switch5, switch1, 1, 4)
        self.addLink(switch5, switch2, 2, 4)

        self.addLink(switch4, host2, 3)
        self.addLink(switch4, host3, 4)
        self.addLink(switch5, switch4, 3, 5)
        self.addLink(switch3, host4, 3)
        self.addLink(switch5, switch3, 4, 5)
        self.addLink(switch2, host5, 5)
        self.addLink(switch4, host6, 6)

topos = {'mytopo': (lambda: MyTopo())}
