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
import array
import inspect
from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto import ether, inet
from ryu.lib.packet import *
from ryu.lib import addrconv


LOG = logging.getLogger('test_packet')


class TestPacket(unittest.TestCase):
    """ Test case for packet
    """

    dst_mac = 'aa:aa:aa:aa:aa:aa'
    src_mac = 'bb:bb:bb:bb:bb:bb'
    dst_mac_bin = addrconv.mac.text_to_bin(dst_mac)
    src_mac_bin = addrconv.mac.text_to_bin(src_mac)
    dst_ip = '192.168.128.10'
    src_ip = '192.168.122.20'
    dst_ip_bin = addrconv.ipv4.text_to_bin(dst_ip)
    src_ip_bin = addrconv.ipv4.text_to_bin(src_ip)
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
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
            + '\x08\x06'

        # arp !HHBBH6sI6sI
        a_buf = '\x00\x01' \
            + '\x08\x00' \
            + '\x06' \
            + '\x04' \
            + '\x00\x02' \
            + self.src_mac_bin \
            + self.src_ip_bin \
            + self.dst_mac_bin \
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
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_eth.dst)
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_eth.src)
        eq_(ether.ETH_TYPE_ARP, p_eth.ethertype)

        # arp
        ok_(p_arp)
        eq_(1, p_arp.hwtype)
        eq_(ether.ETH_TYPE_IP, p_arp.proto)
        eq_(6, p_arp.hlen)
        eq_(4, p_arp.plen)
        eq_(2, p_arp.opcode)
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_arp.src_mac)
        eq_(addrconv.ipv4.text_to_bin(self.src_ip), p_arp.src_ip)
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_arp.dst_mac)
        eq_(addrconv.ipv4.text_to_bin(self.dst_ip), p_arp.dst_ip)

        # to string
        eth_values = {#'dst': self.dst_mac,
                      #'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_ARP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        arp_values = {'hwtype': 1,
                      'proto': ether.ETH_TYPE_IP,
                      'hlen': 6,
                      'plen': 4,
                      'opcode': 2,
                      #'src_mac': self.src_mac,
                      #'dst_mac': self.dst_mac,
                      #'src_ip': self.src_ip,
                      #'dst_ip': self.dst_ip
                      }
        _arp_str = ','.join(['%s=%s' % (k, repr(arp_values[k]))
                             for k, v in inspect.getmembers(p_arp)
                             if k in arp_values])
        arp_str = '%s(%s)' % (arp.arp.__name__, _arp_str)

        pkt_str = '%s, %s' % (eth_str, arp_str)

        eq_(eth_str, str(p_eth))
        eq_(eth_str, repr(p_eth))

        eq_(arp_str, str(p_arp))
        eq_(arp_str, repr(p_arp))

        eq_(pkt_str, str(pkt))
        eq_(pkt_str, repr(pkt))

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
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
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
            + self.src_mac_bin \
            + self.src_ip_bin \
            + self.dst_mac_bin \
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
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_eth.dst)
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_eth.src)
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
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_arp.src_mac)
        eq_(addrconv.ipv4.text_to_bin(self.src_ip), p_arp.src_ip)
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_arp.dst_mac)
        eq_(addrconv.ipv4.text_to_bin(self.dst_ip), p_arp.dst_ip)

        # to string
        eth_values = {#'dst': self.dst_mac,
                      #'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_8021Q}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        vlan_values = {'pcp': 0b111,
                       'cfi': 0b1,
                       'vid': 3,
                       'ethertype': ether.ETH_TYPE_ARP}
        _vlan_str = ','.join(['%s=%s' % (k, repr(vlan_values[k]))
                             for k, v in inspect.getmembers(p_vlan)
                             if k in vlan_values])
        vlan_str = '%s(%s)' % (vlan.vlan.__name__, _vlan_str)

        arp_values = {'hwtype': 1,
                      'proto': ether.ETH_TYPE_IP,
                      'hlen': 6,
                      'plen': 4,
                      'opcode': 2,
                      #'src_mac': self.src_mac,
                      #'dst_mac': self.dst_mac,
                      #'src_ip': self.src_ip,
                      #'dst_ip': self.dst_ip
                      }
        _arp_str = ','.join(['%s=%s' % (k, repr(arp_values[k]))
                             for k, v in inspect.getmembers(p_arp)
                             if k in arp_values])
        arp_str = '%s(%s)' % (arp.arp.__name__, _arp_str)

        pkt_str = '%s, %s, %s' % (eth_str, vlan_str, arp_str)

        eq_(eth_str, str(p_eth))
        eq_(eth_str, repr(p_eth))

        eq_(vlan_str, str(p_vlan))
        eq_(vlan_str, repr(p_vlan))

        eq_(arp_str, str(p_arp))
        eq_(arp_str, repr(p_arp))

        eq_(pkt_str, str(pkt))
        eq_(pkt_str, repr(pkt))

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
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
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
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_eth.dst)
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_eth.src)
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
        eq_(addrconv.ipv4.text_to_bin(self.src_ip), p_ipv4.src)
        eq_(addrconv.ipv4.text_to_bin(self.dst_ip), p_ipv4.dst)
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
        ph = struct.pack('!4s4sBBH', self.src_ip_bin, self.dst_ip_bin, 0,
                         17, len(u_buf) + len(self.payload))
        t = ph + t + self.payload
        eq_(packet_utils.checksum(t), 0)

        # payload
        ok_('payload' in protocols)
        eq_(self.payload, protocols['payload'].tostring())

        # to string
        eth_values = {#'dst': self.dst_mac,
                      #'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_IP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv4_values = {'version': 4,
                       'header_length': 5,
                       'tos': 1,
                       'total_length': l,
                       'identification': 3,
                       'flags': 1,
                       'offset': p_ipv4.offset,
                       'ttl': 64,
                       'proto': inet.IPPROTO_UDP,
                       'csum': p_ipv4.csum,
                       #'src': self.src_ip,
                       #'dst': self.dst_ip,
                       'option': None}
        _ipv4_str = ','.join(['%s=%s' % (k, repr(ipv4_values[k]))
                              for k, v in inspect.getmembers(p_ipv4)
                              if k in ipv4_values])
        ipv4_str = '%s(%s)' % (ipv4.ipv4.__name__, _ipv4_str)

        udp_values = {'src_port': 0x190f,
                      'dst_port': 0x1F90,
                      'total_length': len(u_buf) + len(self.payload),
                      'csum': 0x77b2}
        _udp_str = ','.join(['%s=%s' % (k, repr(udp_values[k]))
                             for k, v in inspect.getmembers(p_udp)
                             if k in udp_values])
        udp_str = '%s(%s)' % (udp.udp.__name__, _udp_str)

        pkt_str = '%s, %s, %s, %s' % (eth_str, ipv4_str, udp_str,
                                      repr(protocols['payload']))

        eq_(eth_str, str(p_eth))
        eq_(eth_str, repr(p_eth))

        eq_(ipv4_str, str(p_ipv4))
        eq_(ipv4_str, repr(p_ipv4))

        eq_(udp_str, str(p_udp))
        eq_(udp_str, repr(p_udp))

        eq_(pkt_str, str(pkt))
        eq_(pkt_str, repr(pkt))

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
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
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
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_eth.dst)
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_eth.src)
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
        eq_(addrconv.ipv4.text_to_bin(self.src_ip), p_ipv4.src)
        eq_(addrconv.ipv4.text_to_bin(self.dst_ip), p_ipv4.dst)
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
        eq_(len(t_buf), len(p_tcp))
        t = bytearray(t_buf)
        struct.pack_into('!H', t, 16, p_tcp.csum)
        ph = struct.pack('!4s4sBBH', self.src_ip_bin, self.dst_ip_bin, 0,
                         6, len(t_buf) + len(self.payload))
        t = ph + t + self.payload
        eq_(packet_utils.checksum(t), 0)

        # payload
        ok_('payload' in protocols)
        eq_(self.payload, protocols['payload'].tostring())

        # to string
        eth_values = {#'dst': self.dst_mac,
                      #'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_IP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv4_values = {'version': 4,
                       'header_length': 5,
                       'tos': 0,
                       'total_length': l,
                       'identification': 0,
                       'flags': 0,
                       'offset': p_ipv4.offset,
                       'ttl': 64,
                       'proto': inet.IPPROTO_TCP,
                       'csum': p_ipv4.csum,
                       #'src': self.src_ip,
                       #'dst': self.dst_ip,
                       'option': None}
        _ipv4_str = ','.join(['%s=%s' % (k, repr(ipv4_values[k]))
                              for k, v in inspect.getmembers(p_ipv4)
                              if k in ipv4_values])
        ipv4_str = '%s(%s)' % (ipv4.ipv4.__name__, _ipv4_str)

        tcp_values = {'src_port': 0x190f,
                      'dst_port': 0x1F90,
                      'seq': 0x123,
                      'ack': 1,
                      'offset': 6,
                      'bits': 0b101010,
                      'window_size': 2048,
                      'csum': p_tcp.csum,
                      'urgent': 0x6f,
                      'option': p_tcp.option}
        _tcp_str = ','.join(['%s=%s' % (k, repr(tcp_values[k]))
                             for k, v in inspect.getmembers(p_tcp)
                             if k in tcp_values])
        tcp_str = '%s(%s)' % (tcp.tcp.__name__, _tcp_str)

        pkt_str = '%s, %s, %s, %s' % (eth_str, ipv4_str, tcp_str,
                                      repr(protocols['payload']))

        eq_(eth_str, str(p_eth))
        eq_(eth_str, repr(p_eth))

        eq_(ipv4_str, str(p_ipv4))
        eq_(ipv4_str, repr(p_ipv4))

        eq_(tcp_str, str(p_tcp))
        eq_(tcp_str, repr(p_tcp))

        eq_(pkt_str, str(pkt))
        eq_(pkt_str, repr(pkt))

    def test_llc_bpdu(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_IEEE802_3)
        llc_control = llc.ControlFormatU(0, 0, 0)
        l = llc.llc(llc.SAP_BPDU, llc.SAP_BPDU, llc_control)
        b = bpdu.ConfigurationBPDUs(flags=0,
                                    root_priority=32768,
                                    root_system_id_extension=0,
                                    root_mac_address=self.src_mac,
                                    root_path_cost=0,
                                    bridge_priority=32768,
                                    bridge_system_id_extension=0,
                                    bridge_mac_address=self.dst_mac,
                                    port_priority=128,
                                    port_number=4,
                                    message_age=1,
                                    max_age=20,
                                    hello_time=2,
                                    forward_delay=15)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(l)
        p.add_protocol(b)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac + self.src_mac + '\x05\xdc'

        # llc !BBB
        l_buf = ('\x42'
                 '\x42'
                 '\x03')

        # bpdu !HBBBQIQHHHHH
        b_buf = ('\x00\x00'
                 '\x00'
                 '\x00'
                 '\x00'
                 '\x80\x64\xaa\xaa\xaa\xaa\xaa\xaa'
                 '\x00\x00\x00\x04'
                 '\x80\x64\xbb\xbb\xbb\xbb\xbb\xbb'
                 '\x80\x04'
                 '\x01\x00'
                 '\x14\x00'
                 '\x02\x00'
                 '\x0f\x00')

        buf = e_buf + l_buf + b_buf

        # parse
        pkt = packet.Packet(array.array('B', p.data))
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_llc = protocols['llc']
        p_bpdu = protocols['ConfigurationBPDUs']

        # ethernet
        ok_(p_eth)
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_eth.dst)
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_eth.src)
        eq_(ether.ETH_TYPE_IEEE802_3, p_eth.ethertype)

        # llc
        ok_(p_llc)
        eq_(llc.SAP_BPDU, p_llc.dsap_addr)
        eq_(llc.SAP_BPDU, p_llc.ssap_addr)
        eq_(0, p_llc.control.modifier_function1)
        eq_(0, p_llc.control.pf_bit)
        eq_(0, p_llc.control.modifier_function2)

        # bpdu
        ok_(p_bpdu)
        eq_(bpdu.PROTOCOL_IDENTIFIER, p_bpdu.protocol_id)
        eq_(bpdu.PROTOCOLVERSION_ID_BPDU, p_bpdu.version_id)
        eq_(bpdu.TYPE_CONFIG_BPDU, p_bpdu.bpdu_type)
        eq_(0, p_bpdu.flags)
        eq_(32768, p_bpdu.root_priority)
        eq_(0, p_bpdu.root_system_id_extension)
        eq_(addrconv.mac.text_to_bin(self.src_mac), p_bpdu.root_mac_address)
        eq_(0, p_bpdu.root_path_cost)
        eq_(32768, p_bpdu.bridge_priority)
        eq_(0, p_bpdu.bridge_system_id_extension)
        eq_(addrconv.mac.text_to_bin(self.dst_mac), p_bpdu.bridge_mac_address)
        eq_(128, p_bpdu.port_priority)
        eq_(4, p_bpdu.port_number)
        eq_(1, p_bpdu.message_age)
        eq_(20, p_bpdu.max_age)
        eq_(2, p_bpdu.hello_time)
        eq_(15, p_bpdu.forward_delay)

        # to string
        eth_values = {#'dst': self.dst_mac,
                      #'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_IEEE802_3}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ctrl_values = {'modifier_function1': 0,
                       'pf_bit': 0,
                       'modifier_function2': 0}
        _ctrl_str = ','.join(['%s=%s' % (k, repr(ctrl_values[k]))
                             for k, v in inspect.getmembers(p_llc.control)
                             if k in ctrl_values])
        ctrl_str = '%s(%s)' % (llc.ControlFormatU.__name__, _ctrl_str)

        llc_values = {'dsap_addr': repr(llc.SAP_BPDU),
                      'ssap_addr': repr(llc.SAP_BPDU),
                      'control': ctrl_str}
        _llc_str = ','.join(['%s=%s' % (k, llc_values[k])
                             for k, v in inspect.getmembers(p_llc)
                             if k in llc_values])
        llc_str = '%s(%s)' % (llc.llc.__name__, _llc_str)

        bpdu_values = {'protocol_id': bpdu.PROTOCOL_IDENTIFIER,
                       'version_id': bpdu.PROTOCOLVERSION_ID_BPDU,
                       'bpdu_type': bpdu.TYPE_CONFIG_BPDU,
                       'flags': 0,
                       'root_priority': long(32768),
                       'root_system_id_extension': long(0),
                       #'root_mac_address': self.src_mac,
                       'root_path_cost': 0,
                       'bridge_priority': long(32768),
                       'bridge_system_id_extension': long(0),
                       #'bridge_mac_address': self.dst_mac,
                       'port_priority': 128,
                       'port_number': 4,
                       'message_age': float(1),
                       'max_age': float(20),
                       'hello_time': float(2),
                       'forward_delay': float(15)}
        _bpdu_str = ','.join(['%s=%s' % (k, repr(bpdu_values[k]))
                             for k, v in inspect.getmembers(p_bpdu)
                             if k in bpdu_values])
        bpdu_str = '%s(%s)' % (bpdu.ConfigurationBPDUs.__name__, _bpdu_str)

        pkt_str = '%s, %s, %s' % (eth_str, llc_str, bpdu_str)

        eq_(eth_str, str(p_eth))
        eq_(eth_str, repr(p_eth))

        eq_(llc_str, str(p_llc))
        eq_(llc_str, repr(p_llc))

        eq_(bpdu_str, str(p_bpdu))
        eq_(bpdu_str, repr(p_bpdu))

        eq_(pkt_str, str(pkt))
        eq_(pkt_str, repr(pkt))
