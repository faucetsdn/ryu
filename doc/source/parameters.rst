:orphan:

.. _getting_started:

***************
Getting Started
***************

Overview/What's Ryu the Network Operating System
================================================
Ryu is an open-sourced Network Operating System which is licensed under Apache v2.0.
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

invoking application and Configuration
======================================
It can be configured by passing configuration file like::

  ryu-manager [--flagfile <path to configuration file>] [generic/application specific options...]

At the moment the following applications are available
(And more to come as Ryu evolves.)

  * ryu.app.simple_isolation.SimpleIsolation
  * ryu.app.rest.restapi
  * ryu.app.simple_bridge.SimpleSwitch
  * ryu.app.event_dumper.EventDumper

The generic available is as follows::

  --app_lists: application module name to run;
    repeat this option to specify a list of values
    (default: "['ryu.app.simple_isolation.SimpleIsolation',
                'ryu.app.rest.restapi']")
  -?,--[no]help: show this help
  --[no]helpshort: show usage only for this module
  --[no]helpxml: like --help, but generates XML output

The options for REST server::

  --wsapi_host: webapp listen host
    (default: '')
  --wsapi_port: webapp listen port
    (default: '8080')
    (an integer)

The options for openflow controller::

  --ofp_listen_host: openflow listen host
    (default: '')
  --ofp_tcp_listen_port: openflow tcp listen port
    (default: '6633')
    (an integer)

The options for log::

  --default_log_level: default log level
    (an integer)
  --log_dir: log file directory
  --log_file: log file name
  --log_file_mode: default log file permission
    (default: '0644')
  --[no]use_stderr: log to standard error
    (default: 'true')
  --use_syslog: output to syslog
    (default: 'False')
  --[no]verbose: show debug output
    (default: 'false')

The option for gflags::

  --flagfile: Insert flag definitions from the given file into the command line.
    (default: '')
  --undefok: comma-separated list of flag names that it is okay to specify on
    the command line even if the program does not define a flag with that name.
    IMPORTANT: flags in this list that have arguments MUST use the --flag=value
    format.
    (default: '')

The options for event dumper::

  --dump_queue: list of dispatcher name to dump event: default any
    (default: [])
  --dump_dispatcher: list of dispatcher name to dump event: default any
    (default: [])


Invoking Example
================
The exmaple is as follows::

  $ ./bin/ryu-manager --wsapi_port 8081 --verbose --app_lists ryu.app.simple_isolation.SimpleIsolation,ryu.app.rest.restapi,ryu.app.event_dumper.EventDumper
  unhandled event <ryu.controller.dispatcher.EventQueueCreate object at 0x22ec690>
  loading app ryu.app.simple_isolation.SimpleIsolation
  loading app ryu.app.rest.restapi
  ryu.app.event_dumper: registering q datapath dispatcher dpset
  loading app ryu.app.event_dumper.EventDumper
  connected socket:<socket fileno=8 sock=172.16.3.33:6633 peer=172.17.107.1:41888> address:('172.17.107.1', 41888)
  ryu.app.event_dumper: queue created ofp_msg
  ryu.app.event_dumper: event <ryu.controller.dispatcher.EventQueueCreate object at 0x23bf3d0>
  ryu.app.event_dumper: event <ryu.controller.ofp_event.EventOFPHello object at 0x23bf4d0>
  hello ev <ryu.controller.ofp_event.EventOFPHello object at 0x23bf4d0>
  move onto config mode
  dispatcher change q ofp_msg dispatcher ofp_config
  ryu.app.event_dumper: dispatcher change q ofp_msg dispatcher ofp_handshake -> ofp_config
  ryu.app.event_dumper: event <ryu.controller.dispatcher.EventDispatcherChange object at 0x23bf950>
  ryu.app.event_dumper: event <ryu.controller.ofp_event.EventOFPSwitchFeatures object at 0x23bf450>
  switch features ev version: 0x1 msg_type 0x6 xid 0xd1bf86d2 port OFPPhyPort(port_no=8, hw_addr='b\x9d\xf4\x03\xab\xaf', name='tap5d7657d4-cb\x00\x00', config=0, state=1, curr=130, advertised=0, supported=0, peer=0) OFPPhyPort(port_no=1, hw_addr='\x00\x02\xb3\x13\xea\xd6', name='eth0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', config=0, state=0, curr=520, advertised=1679, supported=655, peer=0) OFPPhyPort(port_no=18, hw_addr='\xce\x12\xa2\x8a\xe5\x1c', name='tapa37f47e1-25\x00\x00', config=0, state=1, curr=130, advertised=0, supported=0, peer=0) OFPPhyPort(port_no=19, hw_addr='\x12\xba1\x7f\xe4\xde', name='tap927b77c7-8f\x00\x00', config=0, state=1, curr=130, advertised=0, supported=0, peer=0) OFPPhyPort(port_no=65534, hw_addr='\x00\x02\xb3\x13\xea\xd6', name='br-int\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', config=1, state=1, curr=0, advertised=0, supported=0, peer=0)
  dpid_add: 0x00000002b313ead6
  ryu.app.event_dumper: event <ryu.controller.ofp_event.EventOFPBarrierReply object at 0x23bf4d0>
  barrier reply ev <ryu.controller.ofp_event.EventOFPBarrierReply object at 0x23bf4d0> msg version: 0x1 msg_type 0x13 xid 0xd1bf86d5
  move onto main mode
  dispatcher change q ofp_msg dispatcher ofp_main
  DPSET: register datapath <ryu.controller.controller.Datapath object at 0x23def10>
  ryu.app.event_dumper: event <ryu.controller.dpset.EventDP object at 0x23bf990>
  unhandled event <ryu.controller.dpset.EventDP object at 0x23bf990>
  ryu.app.event_dumper: dispatcher change q ofp_msg dispatcher ofp_config -> ofp_main
  ryu.app.event_dumper: event <ryu.controller.dispatcher.EventDispatcherChange object at 0x23bf590>
