# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import struct
import netaddr
import array
from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto import ether, inet
from ryu.lib import mac
from ryu.lib.packet import *


LOG = logging.getLogger('test_packet')


class TestPacket(unittest.TestCase):
    """ Test case for packet
    """

    dst_mac = mac.haddr_to_bin('AA:AA:AA:AA:AA:AA')
    src_mac = mac.haddr_to_bin('BB:BB:BB:BB:BB:BB')
    dst_ip = int(netaddr.IPAddress('192.168.128.10'))
    dst_ip_bin = struct.pack('!I', dst_ip)
    src_ip = int(netaddr.IPAddress('192.168.122.20'))
    src_ip_bin = struct.pack('!I', src_ip)
    payload = '\x06\x06\x47\x50\x00\x00\x00\x00' \
        + '\xcd\xc5\x00\x00\x00\x00\x00\x00' \
        + '\x10\x11\x12\x13\x14\x15\x16\x17' \
        + '\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'

    def get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_arp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_ARP)
        a = arp.arp(1, ether.ETH_TYPE_IP, 6, 4, 2,
                    self.src_mac, self.src_ip, self.dst_mac,
                    self.dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac \
            + self.src_mac \
            + '\x08\x06'

        # arp !HHBBH6sI6sI
        a_buf = '\x00\x01' \
            + '\x08\x00' \
            + '\x06' \
            + '\x04' \
            + '\x00\x02' \
            + self.src_mac \
            + self.src_ip_bin \
            + self.dst_mac \
            + self.dst_ip_bin

        buf = e_buf + a_buf
        eq_(buf, p.data)

        # parse
        pkt = packet.Packet(array.array('B', p.data))
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_arp = protocols['arp']

        # ethernet
        ok_(p_eth)
        eq_(self.dst_mac, p_eth.dst)
        eq_(self.src_mac, p_eth.src)
        eq_(ether.ETH_TYPE_ARP, p_eth.ethertype)

        # arp
        ok_(p_arp)
        eq_(1, p_arp.hwtype)
        eq_(ether.ETH_TYPE_IP, p_arp.proto)
        eq_(6, p_arp.hlen)
        eq_(4, p_arp.plen)
        eq_(2, p_arp.opcode)
        eq_(self.src_mac, p_arp.src_mac)
        eq_(self.src_ip, p_arp.src_ip)
        eq_(self.dst_mac, p_arp.dst_mac)
        eq_(self.dst_ip, p_arp.dst_ip)

    def test_vlan_arp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_8021Q)
        v = vlan.vlan(0b111, 0b1, 3, ether.ETH_TYPE_ARP)
        a = arp.arp(1, ether.ETH_TYPE_IP, 6, 4, 2,
                    self.src_mac, self.src_ip, self.dst_mac,
                    self.dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(v)
        p.add_protocol(a)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac \
            + self.src_mac \
            + '\x81\x00'

        # vlan !HH
        v_buf = '\xF0\x03' \
            + '\x08\x06'

        # arp !HHBBH6sI6sI
        a_buf = '\x00\x01' \
            + '\x08\x00' \
            + '\x06' \
            + '\x04' \
            + '\x00\x02' \
            + self.src_mac \
            + self.src_ip_bin \
            + self.dst_mac \
            + self.dst_ip_bin

        buf = e_buf + v_buf + a_buf
        eq_(buf, p.data)

        # parse
        pkt = packet.Packet(array.array('B', p.data))
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_vlan = protocols['vlan']
        p_arp = protocols['arp']

        # ethernet
        ok_(p_eth)
        eq_(self.dst_mac, p_eth.dst)
        eq_(self.src_mac, p_eth.src)
        eq_(ether.ETH_TYPE_8021Q, p_eth.ethertype)

        # vlan
        ok_(p_vlan)
        eq_(0b111, p_vlan.pcp)
        eq_(0b1, p_vlan.cfi)
        eq_(3, p_vlan.vid)
        eq_(ether.ETH_TYPE_ARP, p_vlan.ethertype)

        # arp
        ok_(p_arp)
        eq_(1, p_arp.hwtype)
        eq_(ether.ETH_TYPE_IP, p_arp.proto)
        eq_(6, p_arp.hlen)
        eq_(4, p_arp.plen)
        eq_(2, p_arp.opcode)
        eq_(self.src_mac, p_arp.src_mac)
        eq_(self.src_ip, p_arp.src_ip)
        eq_(self.dst_mac, p_arp.dst_mac)
        eq_(self.dst_ip, p_arp.dst_ip)

    def test_ipv4_udp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(4, 5, 1, 0, 3, 1, 4, 64, inet.IPPROTO_UDP, 0,
                       self.src_ip, self.dst_ip)
        u = udp.udp(0x190F, 0x1F90, 0, 0)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(u)
        p.add_protocol(self.payload)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac \
            + self.src_mac \
            + '\x08\x00'

        # ipv4 !BBHHHBBHII
        ip_buf = '\x45' \
            + '\x01' \
            + '\x00\x3C' \
            + '\x00\x03' \
            + '\x20\x04' \
            + '\x40' \
            + '\x11' \
            + '\x00\x00' \
            + self.src_ip_bin \
            + self.dst_ip_bin

        # udp !HHHH
        u_buf = '\x19\x0F' \
            + '\x1F\x90' \
            + '\x00\x28' \
            + '\x00\x00'

        buf = e_buf + ip_buf + u_buf + self.payload

        # parse
        pkt = packet.Packet(array.array('B', p.data))
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv4 = protocols['ipv4']
        p_udp = protocols['udp']

        # ethernet
        ok_(p_eth)
        eq_(self.dst_mac, p_eth.dst)
        eq_(self.src_mac, p_eth.src)
        eq_(ether.ETH_TYPE_IP, p_eth.ethertype)

        # ipv4
        ok_(p_ipv4)
        eq_(4, p_ipv4.version)
        eq_(5, p_ipv4.header_length)
        eq_(1, p_ipv4.tos)
        l = len(ip_buf) + len(u_buf) + len(self.payload)
        eq_(l, p_ipv4.total_length)
        eq_(3, p_ipv4.identification)
        eq_(1, p_ipv4.flags)
        eq_(64, p_ipv4.ttl)
        eq_(inet.IPPROTO_UDP, p_ipv4.proto)
        eq_(self.src_ip, p_ipv4.src)
        eq_(self.dst_ip, p_ipv4.dst)
        t = bytearray(ip_buf)
        struct.pack_into('!H', t, 10, p_ipv4.csum)
        eq_(packet_utils.checksum(t), 0)

        # udp
        ok_(p_udp)
        eq_(0x190f, p_udp.src_port)
        eq_(0x1F90, p_udp.dst_port)
        eq_(len(u_buf) + len(self.payload), p_udp.total_length)
        eq_(0x77b2, p_udp.csum)
        t = bytearray(u_buf)
        struct.pack_into('!H', t, 6, p_udp.csum)
        ph = struct.pack('!IIBBH', self.src_ip, self.dst_ip, 0,
                         17, len(u_buf) + len(self.payload))
        t = ph + t + self.payload
        eq_(packet_utils.checksum(t), 0)

        # payload
        ok_('payload' in protocols)
        eq_(self.payload, protocols['payload'].tostring())

    def test_ipv4_tcp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(4, 5, 0, 0, 0, 0, 0, 64, inet.IPPROTO_TCP, 0,
                       self.src_ip, self.dst_ip)
        t = tcp.tcp(0x190F, 0x1F90, 0x123, 1, 6, 0b101010, 2048, 0, 0x6f,
                    '\x01\x02')

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(t)
        p.add_protocol(self.payload)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac \
            + self.src_mac \
            + '\x08\x00'

        # ipv4 !BBHHHBBHII
        ip_buf = '\x45' \
            + '\x00' \
            + '\x00\x4C' \
            + '\x00\x00' \
            + '\x00\x00' \
            + '\x40' \
            + '\x06' \
            + '\x00\x00' \
            + self.src_ip_bin \
            + self.dst_ip_bin

        # tcp !HHIIBBHHH + option
        t_buf = '\x19\x0F' \
            + '\x1F\x90' \
            + '\x00\x00\x01\x23' \
            + '\x00\x00\x00\x01' \
            + '\x60' \
            + '\x2A' \
            + '\x08\x00' \
            + '\x00\x00' \
            + '\x00\x6F' \
            + '\x01\x02\x00\x00'

        buf = e_buf + ip_buf + t_buf + self.payload

        # parse
        pkt = packet.Packet(array.array('B', p.data))
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv4 = protocols['ipv4']
        p_tcp = protocols['tcp']

        # ethernet
        ok_(p_eth)
        eq_(self.dst_mac, p_eth.dst)
        eq_(self.src_mac, p_eth.src)
        eq_(ether.ETH_TYPE_IP, p_eth.ethertype)

        # ipv4
        ok_(p_ipv4)
        eq_(4, p_ipv4.version)
        eq_(5, p_ipv4.header_length)
        eq_(0, p_ipv4.tos)
        l = len(ip_buf) + len(t_buf) + len(self.payload)
        eq_(l, p_ipv4.total_length)
        eq_(0, p_ipv4.identification)
        eq_(0, p_ipv4.flags)
        eq_(64, p_ipv4.ttl)
        eq_(inet.IPPROTO_TCP, p_ipv4.proto)
        eq_(self.src_ip, p_ipv4.src)
        eq_(self.dst_ip, p_ipv4.dst)
        t = bytearray(ip_buf)
        struct.pack_into('!H', t, 10, p_ipv4.csum)
        eq_(packet_utils.checksum(t), 0)

        # tcp
        ok_(p_tcp)
        eq_(0x190f, p_tcp.src_port)
        eq_(0x1F90, p_tcp.dst_port)
        eq_(0x123, p_tcp.seq)
        eq_(1, p_tcp.ack)
        eq_(6, p_tcp.offset)
        eq_(0b101010, p_tcp.bits)
        eq_(2048, p_tcp.window_size)
        eq_(0x6f, p_tcp.urgent)
        eq_(len(t_buf), p_tcp.length)
        t = bytearray(t_buf)
        struct.pack_into('!H', t, 16, p_tcp.csum)
        ph = struct.pack('!IIBBH', self.src_ip, self.dst_ip, 0,
                         6, len(t_buf) + len(self.payload))
        t = ph + t + self.payload
        eq_(packet_utils.checksum(t), 0)

        # payload
        ok_('payload' in protocols)
        eq_(self.payload, protocols['payload'].tostring())
