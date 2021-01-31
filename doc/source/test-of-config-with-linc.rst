===================================
Testing OF-config support with LINC
===================================

This page describes how to setup LINC and test Ryu OF-config with it.

The procedure is as follows.
Although all the procedure is written for reader's convenience,
please refer to LINC document for latest informations of LINC.

    https://github.com/FlowForwarding/LINC-Switch

The test procedure

* install Erlang environment
* build LINC
* configure LINC switch
* setup for LINC
* run LINC switch
* run Ryu test_of_config app

For getting/installing Ryu itself, please refer to https://ryu-sdn.org/


Install Erlang environment
==========================

Since LINC is written in Erlang, you need to install Erlang execution
environment. Required version is R15B+.

The easiest way is to use binary package from
https://www.erlang-solutions.com/downloads/download-erlang-otp

The distribution may also provide Erlang package.


build LINC
==========

install necessary packages for build
------------------------------------

install necessary build tools
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On Ubuntu::

    # apt-get install git-core bridge-utils libpcap0.8 libpcap-dev libcap2-bin uml-utilities

On RedHat/CentOS::

    # yum install git sudo bridge-utils libpcap libpcap-devel libcap tunctl

Note that on RedHat/CentOS 5.x you need a newer version of libpcap::

    # yum erase libpcap libpcap-devel
    # yum install flex byacc
    # wget http://www.tcpdump.org/release/libpcap-1.2.1.tar.gz
    # tar xzf libpcap-1.2.1.tar.gz
    # cd libpcap-1.2.1
    # ./configure
    # make && make install

get LINC repo and built
^^^^^^^^^^^^^^^^^^^^^^^

Clone LINC repo::

    % git clone git://github.com/FlowForwarding/LINC-Switch.git

Then compile everything::

    % cd LINC-Switch
    % make

.. NOTE::
    At the time of this writing, test_of_config fails due to a bug of LINC. You can try this test with LINC which is built by the following methods.

    ::

        % cd LINC-Switch
        % make
        % cd deps/of_config
        % git reset --hard f772af4b765984381ad024ca8e5b5b8c54362638
        % cd ../..
        % make offline


Setup LINC
==========

edit LINC switch configuration file. ``rel/linc/releases/0.1/sys.config``
Here is the sample sys.config for test_of_config.py to run.

::

    [{linc,
         [{of_config,enabled},
          {capable_switch_ports,
              [{port,1,[{interface,"linc-port"}]},
               {port,2,[{interface,"linc-port2"}]},
               {port,3,[{interface,"linc-port3"}]},
               {port,4,[{interface,"linc-port4"}]}]},
          {capable_switch_queues,
              [
                {queue,991,[{min_rate,10},{max_rate,120}]},
                {queue,992,[{min_rate,10},{max_rate,130}]},
                {queue,993,[{min_rate,200},{max_rate,300}]},
                {queue,994,[{min_rate,400},{max_rate,900}]}
                ]},
          {logical_switches,
              [{switch,0,
                   [{backend,linc_us4},
                    {controllers,[{"Switch0-Default-Controller","127.0.0.1",6633,tcp}]},
                    {controllers_listener,{"127.0.0.1",9998,tcp}},
                    {queues_status,enabled},
                    {ports,[{port,1,{queues,[]}},{port,2,{queues,[991,992]}}]}]}
                    ,
               {switch,7,
                   [{backend,linc_us3},
                    {controllers,[{"Switch7-Controller","127.0.0.1",6633,tcp}]},
                    {controllers_listener,disabled},
                    {queues_status,enabled},
                    {ports,[{port,4,{queues,[]}},{port,3,{queues,[993,994]}}]}]}
            ]}]},
     {enetconf,
         [{capabilities,
              [{base,{1,0}},
               {base,{1,1}},
               {startup,{1,0}},
               {'writable-running',{1,0}}]},
          {callback_module,linc_ofconfig},
          {sshd_ip,{127,0,0,1}},
          {sshd_port,1830},
          {sshd_user_passwords,[{"linc","linc"}]}]},
     {lager,
         [{handlers,
              [{lager_console_backend,debug},
               {lager_file_backend,
                   [{"log/error.log",error,10485760,"$D0",5},
                    {"log/console.log",info,10485760,"$D0",5}]}]}]},
     {sasl,
         [{sasl_error_logger,{file,"log/sasl-error.log"}},
          {errlog_type,error},
          {error_logger_mf_dir,"log/sasl"},
          {error_logger_mf_maxbytes,10485760},
          {error_logger_mf_maxfiles,5}]},
     {sync,[{excluded_modules,[procket]}]}].


setup for LINC
==============

As the above sys.config requires some network interface, create them::

    # ip link add linc-port type veth peer name linc-port-peer
    # ip link set linc-port up
    # ip link add linc-port2 type veth peer name linc-port-peer2
    # ip link set linc-port2 up
    # ip link add linc-port3 type veth peer name linc-port-peer3
    # ip link set linc-port3 up
    # ip link add linc-port4 type veth peer name linc-port-peer4
    # ip link set linc-port4 up

After stopping LINC, those created interfaces can be deleted::

    # ip link delete linc-port
    # ip link delete linc-port2
    # ip link delete linc-port3
    # ip link delete linc-port4


Starting LINC OpenFlow switch
=============================

Then run LINC::

    # rel/linc/bin/linc console


Run Ryu test_of_config app
==========================

Run test_of_config app::

    # ryu-manager --verbose ryu.tests.integrated.test_of_config ryu.app.rest

If you don't install ryu and are working in the git repo directly::

    # PYTHONPATH=. ./bin/ryu-manager --verbose ryu.tests.integrated.test_of_config ryu.app.rest
