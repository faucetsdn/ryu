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

    % ovs-vsctl set-ssl /etc/openvswitch/sc-privkey.pem \
      /etc/openvswitch/sc-cert.pem \
      /usr/local/var/lib/openvswitch/pki/controllerca/cacert.pem
    % ovs-vsctl add-br br0
    % ovs-vsctl set-controller br0 ssl:127.0.0.1:6633

Substitute the correct file names, if they differ from the ones used
above. You should use absolute file names.


Run Ryu with CA files::

    % ryu-manager --ctl-privkey ctl-privkey.pem \
                  --ctl-cert ctl-cert.pem \
                  --ca-certs /usr/local/var/lib/openvswitch/pki/switchca/cacert.pem \
                  --verbose \
                  ryu.app.simple_switch

You can see something like::

    loading app ryu.app.simple_switch
    loading app ryu.controller.ofp_handler
    instantiating app ryu.app.simple_switch
    instantiating app ryu.controller.ofp_handler
    BRICK SimpleSwitch
      CONSUMES EventOFPPacketIn
      CONSUMES EventOFPPortStatus
    BRICK ofp_event
      PROVIDES EventOFPPacketIn TO {'SimpleSwitch': set(['main'])}
      PROVIDES EventOFPPortStatus TO {'SimpleSwitch': set(['main'])}
      CONSUMES EventOFPSwitchFeatures
      CONSUMES EventOFPHello
      CONSUMES EventOFPEchoRequest
      CONSUMES EventOFPErrorMsg
      CONSUMES EventOFPPortDescStatsReply
    connected socket:<eventlet.green.ssl.GreenSSLSocket object at 0x7f7ff37f5410> address:('127.0.0.1', 60805)
    hello ev <ryu.controller.ofp_event.EventOFPHello object at 0x7f7ff37f1a50>
    move onto config mode
    switch features ev version: 0x1 msg_type 0x6 xid 0x83678173 OFPSwitchFeatures(actions=4095,capabilities=199,datapath_id=2551895560512,n_buffers=256,n_tables=254,ports={65534: OFPPhyPort(port_no=65534,hw_addr='02:52:28:d4:11:40',name='of13',config=0,state=0,curr=0,advertised=0,supported=0,peer=0)})
    move onto main mode
