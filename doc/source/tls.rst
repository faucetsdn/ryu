********************
Setup TLS Connection
********************

If you want to use secure channel to connect OpenFlow switches, you
need to use TLS connection. This document describes how to setup Ryu
to connect to the Open vSwitch over TLS.


Configuring a Public Key Infrastructure
========================================

If you don't have a PKI, the ovs-pki script included with Open vSwitch
can help you. This section is based on the INSTALL.SSL in the Open
vSwitch source code.

NOTE: How to install Open vSwitch isn't described in this
document. Please refer to the Open vSwitch documents.


Create a PKI by using ovs-pki script::

    % ovs-pki init
    (Default directory is /usr/local/var/lib/openvswitch/pki)

The pki directory consists of controllerca and switchca
subdirectories. Each directory contains CA files.


Create a controller private key and certificate::

    % ovs-pki req+sign ctl controller

ctl-privkey.pem and ctl-cert.pem are generated in the current
directory.


Create a switch private key and certificate::

    % ovs-pki req+sign sc switch

sc-privkey.pem and sc-cert.pem are generated in the current directory.


Testing TLS Connection
======================

Configuring ovs-vswitchd to use CA files using the ovs-vsctl "set-ssl"
command, e.g.::

    % ovs-vsctl set-ssl sc-privkey.pem sc-cert.pem /usr/local/var/lib/openvswitch/pki/controllerca/cacert.pem
    % ovs-vsctl add-br br0
    % ovs-vsctl set-controller br0 ssl:127.0.0.1:6633


Run Ryu with CA files::

    % ryu-manager --ctl_privkey ctl-privkey.pem \
                  --ctl_cert ctl-cert.pem \
                  --ca_cert /usr/local/var/lib/openvswitch/pki/switchca/cacert.pem \
                  --verbose

You can see something like::

    loading app ryu.controller.ofp_handler
    instantiating app ryu.controller.ofp_handler
    connected socket:<SSLSocket fileno=4 sock=127.0.0.1:6633 peer=127.0.0.1:56493> address:('127.0.0.1', 56493)
    unhandled event <ryu.controller.dispatcher.EventQueueCreate object at 0x2fdcd90>
    hello ev <ryu.controller.ofp_event.EventOFPHello object at 0x2fdce90>
    move onto config mode
    unhandled event <ryu.controller.dispatcher.EventDispatcherChange object at 0x2fdcfd0>
    switch features ev version: 0x1 msg_type 0x6 xid 0xc23353f2 port OFPPhyPort(port_no=65534, hw_addr='\x16\xd8u\xe7[C', name='br0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', config=1, state=1, curr=0, advertised=0, supported=0, peer=0)
    move onto main mode
    unhandled event <ryu.controller.dispatcher.EventDispatcherChange object at 0x2fdcfd0>

