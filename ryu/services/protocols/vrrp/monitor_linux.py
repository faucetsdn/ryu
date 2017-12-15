# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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

import contextlib
import socket
import struct

from ryu.controller import handler
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import addrconv
from ryu.lib import hub
from ryu.lib.packet import arp
from ryu.lib.packet import vrrp
from ryu.services.protocols.vrrp import monitor
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import utils


# Those are not defined in socket module
SS_MAXSIZE = 128
MCAST_JOIN_GROUP = 42
MCAST_LEAVE_GROUP = 45
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_MR_MULTICAST = 0
SOL_PACKET = 263


def if_nametoindex(ifname):
    filename = '/sys/class/net/' + ifname + '/ifindex'
    with contextlib.closing(open(filename)) as f:
        for line in f:
            return int(line)


@monitor.VRRPInterfaceMonitor.register(vrrp_event.VRRPInterfaceNetworkDevice)
class VRRPInterfaceMonitorNetworkDevice(monitor.VRRPInterfaceMonitor):
    """
    This module uses raw socket so that privilege(CAP_NET_ADMIN capability)
    is required.
    """

    def __init__(self, *args, **kwargs):
        super(VRRPInterfaceMonitorNetworkDevice, self).__init__(*args,
                                                                **kwargs)
        self.__is_active = True
        config = self.config
        if config.is_ipv6:
            family = socket.AF_INET6
            ether_type = ether.ETH_TYPE_IPV6
            mac_address = vrrp.vrrp_ipv6_src_mac_address(config.vrid)
        else:
            family = socket.AF_INET
            ether_type = ether.ETH_TYPE_IP
            mac_address = vrrp.vrrp_ipv4_src_mac_address(config.vrid)
        # socket module doesn't define IPPROTO_VRRP
        self.ip_socket = socket.socket(family, socket.SOCK_RAW,
                                       inet.IPPROTO_VRRP)

        self.packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                           socket.htons(ether_type))
        self.packet_socket.bind((self.interface.device_name, ether_type,
                                 socket.PACKET_MULTICAST,
                                 arp.ARP_HW_TYPE_ETHERNET,
                                 addrconv.mac.text_to_bin(mac_address)))

        self.ifindex = if_nametoindex(self.interface.device_name)

    def start(self):
        # discard received packets before joining multicast membership
        packet_socket = self.packet_socket
        packet_socket.setblocking(0)
        with hub.Timeout(0.1, False):
            while True:
                try:
                    packet_socket.recv(1500)
                except socket.error:
                    break
        packet_socket.setblocking(1)

        self._join_multicast_membership(True)
        self._join_vrrp_group(True)
        super(VRRPInterfaceMonitorNetworkDevice, self).start()
        self.threads.append(hub.spawn(self._recv_loop))

    def stop(self):
        self.__is_active = False
        super(VRRPInterfaceMonitorNetworkDevice, self).stop()

    # we assume that the structures in the following two functions for
    # multicast are aligned in the same way on all the archtectures.
    def _join_multicast_membership(self, join_leave):
        config = self.config
        if config.is_ipv6:
            mac_address = vrrp.vrrp_ipv6_src_mac_address(config.vrid)
        else:
            mac_address = vrrp.vrrp_ipv4_src_mac_address(config.vrid)
        if join_leave:
            add_drop = PACKET_ADD_MEMBERSHIP
        else:
            add_drop = PACKET_DROP_MEMBERSHIP
        # struct packet_mreq {
        #     int mr_ifindex;
        #     unsigned short mr_type;
        #     unsigned short mr_alen;
        #     unsigned char  mr_mr_address[8];
        # };
        packet_mreq = struct.pack('IHH8s', self.ifindex,
                                  PACKET_MR_MULTICAST, 6,
                                  addrconv.mac.text_to_bin(mac_address))
        self.packet_socket.setsockopt(SOL_PACKET, add_drop, packet_mreq)

    def _join_vrrp_group(self, join_leave):
        if join_leave:
            join_leave = MCAST_JOIN_GROUP
        else:
            join_leave = MCAST_LEAVE_GROUP

        # struct group_req {
        #     __u32 gr_interface;  /* interface index */
        #     struct __kernel_sockaddr_storage gr_group; /* group address */
        # };
        group_req = struct.pack('I', self.ifindex)
        # padding to gr_group. This is environment dependent
        group_req += b'\x00' * (struct.calcsize('P') - struct.calcsize('I'))
        if self.config.is_ipv6:
            # struct sockaddr_in6 {
            #     sa_family_t     sin6_family;   /* AF_INET6 */
            #     in_port_t       sin6_port;     /* port number */
            #     uint32_t        sin6_flowinfo; /* IPv6 flow information */
            #     struct in6_addr sin6_addr;     /* IPv6 address */
            #     uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
            # };
            # struct in6_addr {
            #     unsigned char   s6_addr[16];   /* IPv6 address */
            # };
            family = socket.IPPROTO_IPV6
            sockaddr = struct.pack('H', socket.AF_INET6)
            sockaddr += struct.pack('!H', 0)
            sockaddr += struct.pack('!I', 0)
            sockaddr += addrconv.ipv6.text_to_bin(vrrp.VRRP_IPV6_DST_ADDRESS)
            sockaddr += struct.pack('I', 0)
        else:
            # #define __SOCK_SIZE__   16 /* sizeof(struct sockaddr) */
            # struct sockaddr_in {
            #   __kernel_sa_family_t  sin_family;     /* Address family */
            #   __be16                sin_port;       /* Port number */
            #   struct in_addr        sin_addr;       /* Internet address */
            #   /* Pad to size of `struct sockaddr'. */
            #   unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
            #           sizeof(unsigned short int) - sizeof(struct in_addr)];
            # };
            # struct in_addr {
            #     __be32  s_addr;
            # };
            family = socket.IPPROTO_IP
            sockaddr = struct.pack('H', socket.AF_INET)
            sockaddr += struct.pack('!H', 0)
            sockaddr += addrconv.ipv4.text_to_bin(vrrp.VRRP_IPV4_DST_ADDRESS)

        sockaddr += b'\x00' * (SS_MAXSIZE - len(sockaddr))
        group_req += sockaddr

        self.ip_socket.setsockopt(family, join_leave, group_req)
        return

    def _recv_loop(self):
        packet_socket = self.packet_socket
        packet_socket.settimeout(1.3)       # to check activeness periodically
        try:
            while self.__is_active:
                try:
                    buf = packet_socket.recv(128)
                except socket.timeout:
                    self.logger.debug('timeout')
                    continue
                except:
                    self.logger.error('recv failed')
                    continue
                if len(buf) == 0:
                    self.__is_active = False
                    break

                self.logger.debug('recv buf')
                self._send_vrrp_packet_received(buf)
        finally:
            self._join_vrrp_group(False)
            self._join_multicast_membership(False)

    @handler.set_ev_handler(vrrp_event.EventVRRPTransmitRequest)
    def vrrp_transmit_request_handler(self, ev):
        self.logger.debug('send')
        try:
            self.packet_socket.sendto(ev.data,
                                      (self.interface.device_name, 0))
        except:
            self.logger.error('send failed')

    def _initialize(self):
        # nothing
        pass

    def _shutdown(self):
        self.__is_active = False
