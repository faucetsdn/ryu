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

  ryu-manager [generic/application specific options...]

At the moment applications including the following ones are available
(And more to come as Ryu evolves.)

  * ryu.app.simple_isolation.SimpleIsolation
  * ryu.app.rest.RestAPI
  * ryu.app.simple_bridge.SimpleSwitch

The generic available is as follows::

  --app-lists: application module name to run;
    repeat this option to specify a list of values
  --help: show help

The options for REST server::

  --wsapi-host: webapp listen host
    (default: '')
  --wsapi-port: webapp listen port
    (default: '8080')
    (an integer)

The options for openflow controller::

  --ofp-listen-host: openflow listen host
    (default: '')
  --ofp-tcp-listen-port: openflow tcp listen port
    (default: '6633')
    (an integer)

The options for log::

  --default-log-level: default log level
    (an integer)
  --log-dir: log file directory
  --log-file: log file name
  --log-file-mode: default log file permission
    (default: '0644')
  --[no]use-stderr: log to standard error
    (default: 'true')
  --use-syslog: output to syslog
    (default: 'False')
  --[no]verbose: show debug output
    (default: 'false')

The option for oslo.config.cfg::

  --config-file: Path to a config file to use. Multiple config files
    can be specified, with values in later files taking precedence.
    (default: [])
  --config-dir: Path to a config directory to pull *.conf files from.
    This file set is sorted, so as to provide a predictable parse order if
    individual options are over-ridden. The set is parsed after the file(s),
    if any, specified via --config-file, hence over-ridden options in the
    directory take precedence.


Invoking Example
================
The exmaple is as follows::

% PYTHONPATH=. ./bin/ryu-manager --wsapi-port 8081 --verbose --app-lists ryu.app.simple_isolation,ryu.app.rest
loading app ryu.app.simple_isolation
loading app ryu.app.rest
loading app ryu.controller.ofp_handler
creating context dpset
creating context wsgi
creating context network
instantiating app ryu.app.simple_isolation
instantiating app ryu.app.rest
instantiating app ryu.controller.ofp_handler
BRICK dpset
  CONSUMES EventOFPStateChange
  CONSUMES EventOFPPortStatus
  CONSUMES EventOFPSwitchFeatures
BRICK ofp_event
  PROVIDES EventOFPStateChange TO ['dpset']
  PROVIDES EventOFPPortStatus TO ['dpset', 'SimpleIsolation']
  PROVIDES EventOFPPacketIn TO ['SimpleIsolation']
  PROVIDES EventOFPSwitchFeatures TO ['dpset', 'SimpleIsolation']
  CONSUMES EventOFPEchoRequest
  CONSUMES EventOFPErrorMsg
  CONSUMES EventOFPSwitchFeatures
  CONSUMES EventOFPHello
BRICK network
BRICK RestAPI
BRICK SimpleIsolation
  CONSUMES EventOFPPacketIn
  CONSUMES EventOFPPortStatus
  CONSUMES EventOFPSwitchFeatures
