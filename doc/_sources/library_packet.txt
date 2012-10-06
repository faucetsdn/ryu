**************
Packet library
**************

Introduction
============

Ryu packet library helps you to parse and build various protocol
packets. dpkt is the popular library for the same purpose, however it
is not designed to handle protocols that are interleaved; vlan, mpls,
gre, etc. So we implemented our own packet library.

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
packet class find_protocol method. Let's try to check VLAN id if VLAN
is used:

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
    
    dst = 'a' * 6
    src = 'b' * 6
    e = ethernet.ethernet(dst, src, ether.ETH_TYPE_8021Q)
    a = arp.arp(1, 0x0800, 6, 4, 2, '\a' * 6, 50, '\b' * 6, 30)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
