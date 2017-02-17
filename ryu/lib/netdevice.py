# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Constants defined in netdevice(7)

# Interface flags
# from net/if.h
IFF_UP = 1 << 0           # Interface is running.
IFF_BROADCAST = 1 << 1    # Valid broadcast address set.
IFF_DEBUG = 1 << 2        # Internal debugging flag.
IFF_LOOPBACK = 1 << 3     # Interface is a loopback interface.
IFF_POINTOPOINT = 1 << 4  # Interface is a point-to-point link.
IFF_NOTRAILERS = 1 << 5   # Avoid use of trailers.
IFF_RUNNING = 1 << 6      # Resources allocated.
IFF_NOARP = 1 << 7        # No arp protocol, L2 destination address not set.
IFF_PROMISC = 1 << 8      # Interface is in promiscuous mode.
IFF_ALLMULTI = 1 << 9     # Receive all multicast packets.
IFF_MASTER = 1 << 10      # Master of a load balancing bundle.
IFF_SLAVE = 1 << 11       # Slave of a load balancing bundle.
IFF_MULTICAST = 1 << 12   # Supports multicast.
IFF_PORTSEL = 1 << 13     # Is able to select media type via ifmap.
IFF_AUTOMEDIA = 1 << 14   # Auto media selection active.
IFF_DYNAMIC = 1 << 15     # The addresses are lost when the interface goes down.
# from linux/if.h
IFF_LOWER_UP = 1 << 16    # Driver signals L1 up. (since Linux 2.6.17)
IFF_DORMANT = 1 << 17     # Driver signals dormant. (since Linux 2.6.17)
IFF_ECHO = 1 << 18        # Echo sent packets. (since Linux 2.6.25)

# Private interface flags
# from linux/netdevice.h
IFF_802_1Q_VLAN = 1 << 0             # 802.1Q VLAN device.
IFF_EBRIDGE = 1 << 1                 # Ethernet bridging device.
IFF_BONDING = 1 << 2                 # bonding master or slave.
IFF_ISATAP = 1 << 3                  # ISATAP interface (RFC4214).
IFF_WAN_HDLC = 1 << 4                # WAN HDLC device.
IFF_XMIT_DST_RELEASE = 1 << 5        # dev_hard_start_xmit() is allowed to release skb->dst.
IFF_DONT_BRIDGE = 1 << 6             # disallow bridging this ether dev.
IFF_DISABLE_NETPOLL = 1 << 7         # disable netpoll at run-time.
IFF_MACVLAN_PORT = 1 << 8            # device used as macvlan port.
IFF_BRIDGE_PORT = 1 << 9             # device used as bridge port.
IFF_OVS_DATAPATH = 1 << 10           # device used as Open vSwitch datapath port.
IFF_TX_SKB_SHARING = 1 << 11         # The interface supports sharing skbs on transmit.
IFF_UNICAST_FLT = 1 << 12            # Supports unicast filtering.
IFF_TEAM_PORT = 1 << 13              # device used as team port.
IFF_SUPP_NOFCS = 1 << 14             # device supports sending custom FCS.
IFF_LIVE_ADDR_CHANGE = 1 << 15       # device supports hardware address change when it's running.
IFF_MACVLAN = 1 << 16                # Macvlan device.
IFF_XMIT_DST_RELEASE_PERM = 1 << 17  # IFF_XMIT_DST_RELEASE not taking into account underlying stacked devices.
IFF_IPVLAN_MASTER = 1 << 18          # IPvlan master device.
IFF_IPVLAN_SLAVE = 1 << 19           # IPvlan slave device.
IFF_L3MDEV_MASTER = 1 << 20          # device is an L3 master device.
IFF_NO_QUEUE = 1 << 21               # device can run without qdisc attached.
IFF_OPENVSWITCH = 1 << 22            # device is a Open vSwitch master.
IFF_L3MDEV_SLAVE = 1 << 23           # device is enslaved to an L3 master device.
IFF_TEAM = 1 << 24                   # device is a team device.
IFF_RXFH_CONFIGURED = 1 << 25        # device has had Rx Flow indirection table configured.
IFF_PHONY_HEADROOM = 1 << 26         # the headroom value is controlled by an external entity. (i.e. the master device for bridged veth)
IFF_MACSEC = 1 << 27                 # device is a MACsec device.
