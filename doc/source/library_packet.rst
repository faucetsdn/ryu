**************
Packet library
**************

Introduction
============

Ryu packet library helps you to parse and build various protocol
packets. dpkt is the popular library for the same purpose, however it
is not designed to handle protocols that are interleaved; vlan, mpls,
gre, etc. So we implemented our own packet library.

Network Addresses
=================

Unless otherwise specified, MAC/IPv4/IPv6 addresses are specified
using human readable strings for this library.
For example, '08:60:6e:7f:74:e7', '192.0.2.1', 'fe80::a60:6eff:fe7f:74e7'.

Parsing Packet
==============

First, let's look at how we can use the library to parse the received
packets in a handler for OFPPacketIn messages.

.. code-block:: python
       
    from ryu.lib.packet import packet
    
    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt = packet.Packet(array.array('B', ev.msg.data))
        for p in pkt.protocols:
            print p

You can create a Packet class instance with the received raw
data. Then the packet library parses the data and creates protocol
class instances included the data. The packet class 'protocols' has
the protocol class instances.

If a TCP packet is received, something like the following is printed::

    <ryu.lib.packet.ethernet.ethernet object at 0x107a5d790>
    <ryu.lib.packet.vlan.vlan object at 0x107a5d7d0>
    <ryu.lib.packet.ipv4.ipv4 object at 0x107a5d810>
    <ryu.lib.packet.tcp.tcp object at 0x107a5d850>

If vlan is not used, you see something like::

    <ryu.lib.packet.ethernet.ethernet object at 0x107a5d790>
    <ryu.lib.packet.ipv4.ipv4 object at 0x107a5d810>
    <ryu.lib.packet.tcp.tcp object at 0x107a5d850>

You can access to a specific protocol class instance by using the
packet class iterator.  Let's try to check VLAN id if VLAN is used:

.. code-block:: python
       
    from ryu.lib.packet import packet
    
    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt = packet.Packet(array.array('B', ev.msg.data))
        for p in pkt:
            print p.protocol_name, p
            if p.protocol_name == 'vlan':
                print 'vid = ', p.vid

You see something like::

    ethernet <ryu.lib.packet.ethernet.ethernet object at 0x107a5d790>
    vlan <ryu.lib.packet.vlan.vlan object at 0x107a5d7d0>
    vid = 10
    ipv4 <ryu.lib.packet.ipv4.ipv4 object at 0x107a5d810>
    tcp <ryu.lib.packet.tcp.tcp object at 0x107a5d850>



Building Packet
===============

You need to create protocol class instances that you want to send, add
them to a packet class instance via add_protocol method, and then call
serialize method. You have the raw data to send. The following example
is building an arp packet.

.. code-block:: python

    from ryu.ofproto import ether
    from ryu.lib.packet import ethernet, arp, packet

    e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                          src='08:60:6e:7f:74:e7',
                          ethertype=ether.ETH_TYPE_ARP)
    a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                src_mac='08:60:6e:7f:74:e7', src_ip='192.0.2.1',
                dst_mac='00:00:00:00:00:00', dst_ip='192.0.2.2')
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    print repr(p.data)  # the on-wire packet
