.. _getting_started:

***************
Getting Started
***************

Overview/What's Ryu the Network Operating System
================================================
Ryu is an open-sourced Network Operating System which is licensed under GPL v3.
It supports openflow protocol.

If you are not familiar with Software Defined Network(SDN) and
OpenFlow/openflow controller,
please refer to `openflow org <http://www.openflow.org/>`_ .

The mailing list is available at
`ryu-devel ML <https://lists.sourceforge.net/lists/listinfo/ryu-devel>`_


Installing Ryu Network Operating System
=======================================
Extract source code and just type::

   % python ./setup.py install

Then, run ryu-manager.
It listens to ip address 0.0.0.0 and port 6633 by default.
Then have your openflow switch (hardware or openvswitch OVS) to connect to
ryu-manager.

For OVS case, you can done it by

  % ovs-vsctl set-controller <your bridge>  tcp:<ip addr>[:<port: default 6633>]

At the moment, ryu-manager supports only tcp method.
If you want to use it with openstack nova and quantum OVS plugin,
Please refer to :ref:`using_with_openstack`.

Configuration
=============
It can be configured by passing configuration file like::

  ryu-manager [--flagfile <path to configuration file>]
