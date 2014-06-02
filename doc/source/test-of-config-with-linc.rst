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

For getting/installing Ryu itself, please refer to http://osrg.github.io/ryu/


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
	
Here is the sample output

::

    kuma% PYTHONPATH=. ./bin/ryu-manager --verbose ryu.tests.integrated.test_of_config ryu.app.rest
    loading app ryu.tests.integrated.test_of_config
    loading app ryu.app.rest
    creating context wsgi
    instantiating app None of Network
    creating context network
    instantiating app ryu.app.rest of RestAPI
    instantiating app ryu.tests.integrated.test_of_config of OFConfigClient
    <SSHSession(session, initial daemon)> created: client_capabilities=['urn:ie
    tf:params:netconf:capability:writable-running:1.0','urn:ietf:params:netconf
    :capability:rollback-on-error:1.0', 'urn:ietf:params:netconf:capability:val
    idate:1.0', 'urn:ietf:params:netconf:capability:confirmed-commit:1.0', 'urn
    :ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file,https,sftp', '
    urn:ietf:params:netconf:base:1.0', 'urn:liberouter:params:netconf:capabilit
    y:power-control:1.0', 'urn:ietf:params:netconf:capability:candidate:1.0', '
    urn:ietf:params:netconf:capability:xpath:1.0', 'urn:ietf:params:netconf:cap
    ability:startup:1.0', 'urn:ietf:params:netconf:capability:interleave:1.0']
    Unable to handle key of type ecdsa-sha2-nistp256
    Unable to handle key of type ecdsa-sha2-nistp256
    Unable to handle key of type ecdsa-sha2-nistp256
    Unable to handle key of type ecdsa-sha2-nistp256
    Unable to handle key of type ecdsa-sha2-nistp256
    Unable to handle key of type ecdsa-sha2-nistp521
    Unable to handle key of type ecdsa-sha2-nistp256
    Unable to handle key of type ecdsa-sha2-nistp521
    Unable to handle key of type ecdsa-sha2-nistp256
    Unable to handle key of type ecdsa-sha2-nistp256
    starting thread (client mode): 0xf0d2f890L
    Connected (version 2.0, client Erlang)
    kex algos:['diffie-hellman-group1-sha1'] server key:['ssh-rsa', 'ssh-dss'] 
    client encrypt:['aes128-cbc', '3des-cbc'] server encrypt:['aes128-cbc', '3d
    es-cbc'] client mac:['hmac-sha1'] server mac:['hmac-sha1'] client compress:
    ['none', 'zlib'] server compress:['none', 'zlib'] client lang:[''] server l
    ang:[''] kex follows?False
    Ciphers agreed: local=aes128-cbc, remote=aes128-cbc
    using kex diffie-hellman-group1-sha1; server key type ssh-rsa; cipher: loca
    l aes128-cbc, remote aes128-cbc; mac: local hmac-sha1, remote hmac-sha1; co
    mpression: local none, remote none
    Switch to new keys ...
    Not a valid RSA private key file (bad ber encoding)
    userauth is OK
    Authentication (password) successful!
    [chan 1] Max packet in: 34816 bytes
    [chan 1] Max packet out: 32768 bytes
    Secsh channel 1 opened.
    [chan netconf] Sesch channel 1 request ok
    installing listener <ncclient.transport.session.HelloHandler object at 0x7f
    7ff0d3a4d0>
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:hello xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><nc:capabiliti
    es><nc:capability>urn:ietf:params:netconf:capability:writable-running:1.0</
    nc:capability><nc:capability>urn:ietf:params:netconf:capability:rollback-on
    -error:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability
    :validate:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capabil
    ity:confirmed-commit:1.0</nc:capability><nc:capability>urn:ietf:params:netc
    onf:capability:url:1.0?scheme=http,ftp,file,https,sftp</nc:capability><nc:c
    apability>urn:ietf:params:netconf:base:1.0</nc:capability><nc:capability>ur
    n:liberouter:params:netconf:capability:power-control:1.0</nc:capability><nc
    :capability>urn:ietf:params:netconf:capability:candidate:1.0</nc:capability
    ><nc:capability>urn:ietf:params:netconf:capability:xpath:1.0</nc:capability
    ><nc:capability>urn:ietf:params:netconf:capability:startup:1.0</nc:capabili
    ty><nc:capability>urn:ietf:params:netconf:capability:interleave:1.0</nc:cap
    ability></nc:capabilities></nc:hello>
    starting main loop
    Sending message
    parsed new message
    dispatching message to <ncclient.transport.session.HelloHandler object at 0
    x7f7ff0d3a4d0>: <?xml version="1.0" encoding="UTF-8"?><hello xmlns="urn:iet
    f:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params
    :netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1<
    /capability><capability>urn:ietf:params:netconf:capability:startup:1.0</cap
    ability><capability>urn:ietf:params:netconf:capability:writable-running:1.0
    </capability></capabilities><session-id>1</session-id></hello>
    discarding listener <ncclient.transport.session.HelloHandler object at 0x7f
    7ff0d3a4d0>
    initialized: session-id=1 | server_capabilities=['urn:ietf:params:netconf:c
    apability:startup:1.0', 'urn:ietf:params:netconf:capability:writable-runnin
    g:1.0', 'urn:ietf:params:netconf:base:1.0', 'urn:ietf:params:netconf:base:1
    .1']
    BRICK RestAPI
    BRICK OFConfigClient
    BRICK network
    installing listener <ncclient.operations.rpc.RPCReplyListener object at 0x7
    f7ff0d3a5d0>
    Requesting 'Get'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:
    uuid:d2bb3d51-e664-11e3-860a-0d6c265e373f"><nc:get /></nc:rpc>
    Sync request, will wait for timeout=30
    (8836) wsgi starting up on http://0.0.0.0:8080/
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d2bb3d51-e664-11e3-860a-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><data><capable-switch xmlns="urn:onf:of111:config:ya
    ng"><id>CapableSwitch0</id><resources><port><resource-id>LogicalSwitch0-Por
    t2</resource-id><number>2</number><name>Port2</name><current-rate>5000</cur
    rent-rate><max-rate>5000</max-rate><configuration><admin-state>up</admin-st
    ate><no-receive>false</no-receive><no-forward>false</no-forward><no-packet-
    in>false</no-packet-in></configuration><state><oper-state>up</oper-state><b
    locked>false</blocked><live>true</live></state><features><current><rate>100
    Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><pa
    use>unsupported</pause></current><advertised><rate>other</rate><auto-negoti
    ate>true</auto-negotiate><medium>copper</medium><pause>unsupported</pause><
    /advertised><supported><rate>100Mb-FD</rate><auto-negotiate>true</auto-nego
    tiate><medium>copper</medium><pause>unsupported</pause></supported><adverti
    sed-peer><rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>
    copper</medium><pause>unsupported</pause></advertised-peer></features></por
    t><port><resource-id>LogicalSwitch0-Port1</resource-id><number>1</number><n
    ame>Port1</name><current-rate>5000</current-rate><max-rate>5000</max-rate><
    configuration><admin-state>up</admin-state><no-receive>false</no-receive><n
    o-forward>false</no-forward><no-packet-in>false</no-packet-in></configurati
    on><state><oper-state>up</oper-state><blocked>false</blocked><live>true</li
    ve></state><features><current><rate>100Mb-FD</rate><auto-negotiate>true</au
    to-negotiate><medium>copper</medium><pause>unsupported</pause></current><ad
    vertised><rate>other</rate><auto-negotiate>true</auto-negotiate><medium>cop
    per</medium><pause>unsupported</pause></advertised><supported><rate>100Mb-F
    D</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><pause>
    unsupported</pause></supported><advertised-peer><rate>100Mb-FD</rate><auto-
    negotiate>true</auto-negotiate><medium>copper</medium><pause>unsupported</p
    ause></advertised-peer></features></port><port><resource-id>LogicalSwitch7-
    Port4</resource-id><number>4</number><name>Port4</name><current-rate>5000</
    current-rate><max-rate>5000</max-rate><configuration><admin-state>up</admin
    -state><no-receive>false</no-receive><no-forward>false</no-forward><no-pack
    et-in>false</no-packet-in></configuration><state><oper-state>up</oper-state
    ><blocked>false</blocked><live>true</live></state><features><current><rate>
    100Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium>
    <pause>unsupported</pause></current><advertised><rate>other</rate><auto-neg
    otiate>true</auto-negotiate><medium>copper</medium><pause>unsupported</paus
    e></advertised><supported><rate>100Mb-FD</rate><auto-negotiate>true</auto-n
    egotiate><medium>copper</medium><pause>unsupported</pause></supported><adve
    rtised-peer><rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><medi
    um>copper</medium><pause>unsupported</pause></advertised-peer></features></
    port><port><resource-id>LogicalSwitch7-Port3</resource-id><number>3</number
    ><name>Port3</name><current-rate>5000</current-rate><max-rate>5000</max-rat
    e><configuration><admin-state>up</admin-state><no-receive>false</no-receive
    ><no-forward>false</no-forward><no-packet-in>false</no-packet-in></configur
    ation><state><oper-state>up</oper-state><blocked>false</blocked><live>true<
    /live></state><features><current><rate>100Mb-FD</rate><auto-negotiate>true<
    /auto-negotiate><medium>copper</medium><pause>unsupported</pause></current>
    <advertised><rate>other</rate><auto-negotiate>true</auto-negotiate><medium>
    copper</medium><pause>unsupported</pause></advertised><supported><rate>100M
    b-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><pau
    se>unsupported</pause></supported><advertised-peer><rate>100Mb-FD</rate><au
    to-negotiate>true</auto-negotiate><medium>copper</medium><pause>unsupported
    </pause></advertised-peer></features></port><queue><resource-id>LogicalSwit
    ch0-Port2-Queue991</resource-id><id>991</id><port>2</port><properties><min-
    rate>10</min-rate><max-rate>120</max-rate></properties></queue><queue><reso
    urce-id>LogicalSwitch0-Port2-Queue992</resource-id><id>992</id><port>2</por
    t><properties><min-rate>10</min-rate><max-rate>130</max-rate></properties><
    /queue><queue><resource-id>LogicalSwitch7-Port3-Queue993</resource-id><id>9
    93</id><port>3</port><properties><min-rate>200</min-rate><max-rate>300</max
    -rate></properties></queue><queue><resource-id>LogicalSwitch7-Port3-Queue99
    4</resource-id><id>994</id><port>3</port><properties><min-rate>400</min-rat
    e><max-rate>900</max-rate></properties></queue></resources><logical-switche
    s><switch><id>LogicalSwitch0</id><capabilities><max-buffered-packets>0</max
    -buffered-packets><max-tables>255</max-tables><max-ports>16777216</max-port
    s><flow-statistics>true</flow-statistics><table-statistics>true</table-stat
    istics><port-statistics>true</port-statistics><group-statistics>true</group
    -statistics><queue-statistics>true</queue-statistics><reassemble-ip-fragmen
    ts>false</reassemble-ip-fragments><block-looping-ports>false</block-looping
    -ports><reserved-port-types><type>all</type><type>controller</type><type>ta
    ble</type><type>inport</type><type>any</type></reserved-port-types><group-t
    ypes><type>all</type><type>select</type><type>indirect</type><type>fast-fai
    lover</type></group-types><group-capabilities><capability>select-weight</ca
    pability><capability>select-liveness</capability><capability>chaining</capa
    bility></group-capabilities><action-types><type>output</type><type>group</t
    ype><type>set-queue</type><type>set-mpls-ttl</type><type>dec-mpls-ttl</type
    ><type>set-nw-ttl</type><type>dec-nw-ttl</type><type>copy-ttl-out</type><ty
    pe>copy-ttl-in</type><type>push-vlan</type><type>pop-vlan</type><type>push-
    mpls</type><type>pop-mpls</type><type>push-pbb</type><type>pop-pbb</type><t
    ype>set-field</type></action-types><instruction-types><type>goto-table</typ
    e><type>write-metadata</type><type>write-actions</type><type>apply-actions<
    /type><type>clear-actions</type><type>meter</type></instruction-types></cap
    abilities><datapath-id>08:60:6E:7F:74:E7:00:00</datapath-id><enabled>true</
    enabled><check-controller-certificate>false</check-controller-certificate><
    lost-connection-behavior>failSecureMode</lost-connection-behavior><controll
    ers><controller><id>Switch0-Default-Controller</id><role>equal</role><ip-ad
    dress>127.0.0.1</ip-address><port>6633</port><protocol>tcp</protocol><state
    ><connection-state>down</connection-state><supported-versions>1.3</supporte
    d-versions></state></controller></controllers><resources><port>LogicalSwitc
    h0-Port2</port><port>LogicalSwitch0-Port1</port><queue>LogicalSwitch0-Port2
    -Queue991</queue><queue>LogicalSwitch0-Port2-Queue992</queue></resources></
    switch><switch><id>LogicalSwitch7</id><capabilities><max-buffered-packets>0
    </max-buffered-packets><max-tables>255</max-tables><max-ports>16777216</max
    -ports><flow-statistics>true</flow-statistics><table-statistics>true</table
    -statistics><port-statistics>true</port-statistics><group-statistics>true</
    group-statistics><queue-statistics>true</queue-statistics><reassemble-ip-fr
    agments>false</reassemble-ip-fragments><block-looping-ports>false</block-lo
    oping-ports><reserved-port-types><type>all</type><type>controller</type><ty
    pe>table</type><type>inport</type><type>any</type></reserved-port-types><gr
    oup-types><type>all</type><type>select</type><type>indirect</type><type>fas
    t-failover</type></group-types><group-capabilities><capability>select-weigh
    t</capability><capability>select-liveness</capability><capability>chaining<
    /capability></group-capabilities><action-types><type>output</type><type>gro
    up</type><type>set-queue</type><type>set-mpls-ttl</type><type>dec-mpls-ttl<
    /type><type>set-nw-ttl</type><type>dec-nw-ttl</type><type>copy-ttl-out</typ
    e><type>copy-ttl-in</type><type>push-vlan</type><type>pop-vlan</type><type>
    push-mpls</type><type>pop-mpls</type><type>set-field</type></action-types><
    instruction-types><type>goto-table</type><type>write-metadata</type><type>w
    rite-actions</type><type>apply-actions</type><type>clear-actions</type></in
    struction-types></capabilities><datapath-id>08:60:6E:7F:74:E7:00:07</datapa
    th-id><enabled>true</enabled><check-controller-certificate>false</check-con
    troller-certificate><lost-connection-behavior>failSecureMode</lost-connecti
    on-behavior><controllers><controller><id>Switch7-Controller</id><role>equal
    </role><ip-address>127.0.0.1</ip-address><port>6633</port><protocol>tcp</pr
    otocol><state><connection-state>down</connection-state><supported-versions>
    1.2</supported-versions></state></controller></controllers><resources><port
    >LogicalSwitch7-Port4</port><port>LogicalSwitch7-Port3</port><queue>Logical
    Switch7-Port3-Queue993</queue><queue>LogicalSwitch7-Port3-Queue994</queue><
    /resources></switch></logical-switches></capable-switch></data></rpc-reply>
    Delivering to <ncclient.operations.retrieve.Get object at 0x7f7ff0d3a150>
    Traceback (most recent call last):
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/tests/integrated/test_of_config.py"
    , line 226, in _validate
        xmlschema.assertValid(tree)
      File "lxml.etree.pyx", line 3303, in lxml.etree._Validator.assertValid (s
    rc/lxml/lxml.etree.c:159771)
    DocumentInvalid: Element '{urn:onf:of111:config:yang}type': [facet 'enumera
    tion'] The value 'push-pbb' is not an element of the set {'output', 'copy-t
    tl-out', 'copy-ttl-in', 'set-mpls-ttl', 'dec-mpls-ttl', 'push-vlan', 'pop-v
    lan', 'push-mpls', 'pop-mpls', 'set-queue', 'group', 'set-nw-ttl', 'dec-nw-
    ttl', 'set-field'}., line 2
    set(['urn:onf:of111:config:yang'])
    source = running
    Requesting 'GetConfig'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:
    uuid:d2f15087-e664-11e3-b7fa-0d6c265e373f"><nc:get-config><nc:source><nc:ru
    nning /></nc:source></nc:get-config></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d2f15087-e664-11e3-b7fa-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><data><capable-switch xmlns="urn:onf:of111:config:ya
    ng"><id>CapableSwitch0</id><resources><port><resource-id>LogicalSwitch0-Por
    t2</resource-id><configuration><admin-state>up</admin-state><no-receive>fal
    se</no-receive><no-forward>false</no-forward><no-packet-in>false</no-packet
    -in></configuration><features><advertised><rate>other</rate><auto-negotiate
    >true</auto-negotiate><medium>copper</medium><pause>unsupported</pause></ad
    vertised></features></port><port><resource-id>LogicalSwitch0-Port1</resourc
    e-id><configuration><admin-state>up</admin-state><no-receive>false</no-rece
    ive><no-forward>false</no-forward><no-packet-in>false</no-packet-in></confi
    guration><features><advertised><rate>other</rate><auto-negotiate>true</auto
    -negotiate><medium>copper</medium><pause>unsupported</pause></advertised></
    features></port><port><resource-id>LogicalSwitch7-Port4</resource-id><confi
    guration><admin-state>up</admin-state><no-receive>false</no-receive><no-for
    ward>false</no-forward><no-packet-in>false</no-packet-in></configuration><f
    eatures><advertised><rate>other</rate><auto-negotiate>true</auto-negotiate>
    <medium>copper</medium><pause>unsupported</pause></advertised></features></
    port><port><resource-id>LogicalSwitch7-Port3</resource-id><configuration><a
    dmin-state>up</admin-state><no-receive>false</no-receive><no-forward>false<
    /no-forward><no-packet-in>false</no-packet-in></configuration><features><ad
    vertised><rate>other</rate><auto-negotiate>true</auto-negotiate><medium>cop
    per</medium><pause>unsupported</pause></advertised></features></port><queue
    ><resource-id>LogicalSwitch0-Port2-Queue991</resource-id><properties><min-r
    ate>10</min-rate><max-rate>120</max-rate></properties></queue><queue><resou
    rce-id>LogicalSwitch0-Port2-Queue992</resource-id><properties><min-rate>10<
    /min-rate><max-rate>130</max-rate></properties></queue><queue><resource-id>
    LogicalSwitch7-Port3-Queue993</resource-id><properties><min-rate>200</min-r
    ate><max-rate>300</max-rate></properties></queue><queue><resource-id>Logica
    lSwitch7-Port3-Queue994</resource-id><properties><min-rate>400</min-rate><m
    ax-rate>900</max-rate></properties></queue></resources><logical-switches><s
    itch><id>LogicalSwitch0</id><datapath-id>08:60:6E:7F:74:E7:00:00</datapath-
    id><controllers><controller><id>Switch0-Default-Controller</id><role>equal<
    /role><ip-address>127.0.0.1</ip-address><port>6633</port><protocol>tcp</pro
    tocol><state><connection-state>down</connection-state><supported-versions>1
    .3</supported-versions></state></controller></controllers><resources><port>
    LogicalSwitch0-Port2</port><port>LogicalSwitch0-Port1</port><queue>LogicalS
    witch0-Port2-Queue991</queue><queue>LogicalSwitch0-Port2-Queue992</queue></
    resources></switch><switch><id>LogicalSwitch7</id><datapath-id>08:60:6E:7F:
    74:E7:00:07</datapath-id><controllers><controller><id>Switch7-Controller</i
    d><role>equal</role><ip-address>127.0.0.1</ip-address><port>6633</port><pro
    tocol>tcp</protocol><state><connection-state>down</connection-state><suppor
    ted-versions>1.2</supported-versions></state></controller></controllers><re
    sources><port>LogicalSwitch7-Port4</port><port>LogicalSwitch7-Port3</port><
    queue>LogicalSwitch7-Port3-Queue993</queue><queue>LogicalSwitch7-Port3-Queu
    e994</queue></resources></switch></logical-switches></capable-switch></data
    ></rpc-reply>
    Delivering to <ncclient.operations.retrieve.GetConfig object at 0x7f7ff0901
    d10>
    source = startup
    Requesting 'GetConfig'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:
    uuid:d30c8470-e664-11e3-a182-0d6c265e373f"><nc:get-config><nc:source><nc:st
    artup /></nc:source></nc:get-config></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d30c8470-e664-11e3-a182-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><data><capable-switch xmlns="urn:onf:of111:config:ya
    ng"><id>CapableSwitch0</id><resources><port><resource-id>LogicalSwitch7-Por
    t4</resource-id><configuration><admin-state>up</admin-state><no-receive>fal
    se</no-receive><no-forward>false</no-forward><no-packet-in>false</no-packet
    -in></configuration><features><advertised><rate>100Mb-FD</rate><auto-negoti
    ate>true</auto-negotiate><medium>copper</medium><pause>unsupported</pause><
    /advertised></features></port><port><resource-id>LogicalSwitch7-Port3</reso
    urce-id><configuration><admin-state>up</admin-state><no-receive>false</no-r
    eceive><no-forward>false</no-forward><no-packet-in>false</no-packet-in></co
    nfiguration><features><advertised><rate>100Mb-FD</rate><auto-negotiate>true
    </auto-negotiate><medium>copper</medium><pause>unsupported</pause></adverti
    sed></features></port><port><resource-id>LogicalSwitch0-Port1</resource-id>
    <configuration><admin-state>up</admin-state><no-receive>false</no-receive><
    no-forward>false</no-forward><no-packet-in>false</no-packet-in></configurat
    ion><features><advertised><rate>100Mb-FD</rate><auto-negotiate>true</auto-n
    egotiate><medium>copper</medium><pause>unsupported</pause></advertised></fe
    atures></port><port><resource-id>LogicalSwitch0-Port2</resource-id><configu
    ration><admin-state>up</admin-state><no-receive>false</no-receive><no-forwa
    rd>false</no-forward><no-packet-in>false</no-packet-in></configuration><fea
    tures><advertised><rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate
    ><medium>copper</medium><pause>unsupported</pause></advertised></features><
    /port><queue><resource-id>LogicalSwitch7-Port3-Queue994</resource-id><prope
    rties><min-rate>400</min-rate><max-rate>900</max-rate></properties></queue>
    <queue><resource-id>LogicalSwitch7-Port3-Queue993</resource-id><properties>
    <min-rate>200</min-rate><max-rate>300</max-rate></properties></queue><queue
    ><resource-id>LogicalSwitch0-Port2-Queue992</resource-id><properties><min-r
    ate>10</min-rate><max-rate>130</max-rate></properties></queue><queue><resou
    rce-id>LogicalSwitch0-Port2-Queue991</resource-id><properties><min-rate>10<
    /min-rate><max-rate>120</max-rate></properties></queue></resources><logical
    -switches><switch><id>LogicalSwitch7</id><datapath-id>08:60:6E:7F:74:E7:00:
    07</datapath-id><controllers/><resources><port>LogicalSwitch7-Port4</port><
    port>LogicalSwitch7-Port3</port><queue>LogicalSwitch7-Port3-Queue994</queue
    ><queue>LogicalSwitch7-Port3-Queue993</queue></resources></switch><switch><
    id>LogicalSwitch0</id><datapath-id>08:60:6E:7F:74:E7:00:00</datapath-id><co
    ntrollers/><resources><port>LogicalSwitch0-Port1</port><port>LogicalSwitch0
    -Port2</port><queue>LogicalSwitch0-Port2-Queue992</queue><queue>LogicalSwit
    ch0-Port2-Queue991</queue></resources></switch></logical-switches></capable
    -switch></data></rpc-reply>
    Delivering to <ncclient.operations.retrieve.GetConfig object at 0x7f7ff0d3a
    cd0>
    Traceback (most recent call last):
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/tests/integrated/test_of_config.py"
    , line 226, in _validate
        xmlschema.assertValid(tree)
      File "lxml.etree.pyx", line 3303, in lxml.etree._Validator.assertValid (s
    rc/lxml/lxml.etree.c:159771)
    DocumentInvalid: Element '{urn:onf:of111:config:yang}controllers': Missing 
    child element(s). Expected is ( {urn:onf:of111:config:yang}controller )., l
    ine 2
    source = candidate
    Requesting 'GetConfig'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:
    uuid:d33e9ce3-e664-11e3-83f2-0d6c265e373f"><nc:get-config><nc:source><nc:ca
    ndidate /></nc:source></nc:get-config></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d33e9ce3-e664-11e3-83f2-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><rpc-error><error-tag>invalid-value</error-tag><erro
    r-type>application</error-type><error-severity>error</error-severity></rpc-
    error></rpc-reply>
    Delivering to <ncclient.operations.retrieve.GetConfig object at 0x7f7ff0d3a
    cd0>
    Traceback (most recent call last):
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/tests/integrated/test_of_config.py"
    , line 315, in _do_of_config
        self._do_get_config('candidate')
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/tests/integrated/test_of_config.py"
    , line 246, in _do_get_config
        config_xml = self.switch.raw_get_config(source)
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/lib/of_config/capable_switch.py", l
    ine 102, in raw_get_config
        reply = self.netconf.get_config(source, filter)
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/contrib/ncclient/manager.py", line 
    78, in wrapper
        return self.execute(op_cls, *args, **kwds)
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/contrib/ncclient/manager.py", line 
    132, in execute
        raise_mode=self._raise_mode).request(*args, **kwds)
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/contrib/ncclient/operations/retriev
    e.py", line 87, in request
        return self._request(node)
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/contrib/ncclient/operations/rpc.py"
    , line 289, in _request
        raise self._reply.error
    RPCError: {'info': None, 'severity': 'error', 'tag': 'invalid-value', 'path
    ': None, 'message': None, 'type': 'application'}
    Requesting 'EditConfig'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ns1="urn:o
    nf:of111:config:yang" message-id="urn:uuid:d359ee23-e664-11e3-a8fd-0d6c265e
    373f"><nc:edit-config><nc:target><nc:running /></nc:target><nc:config>
      <ns1:capable-switch>
        <ns1:id>CapableSwitch0</ns1:id>
        <ns1:resources>
          <ns1:port>
            <ns1:resource-id>LogicalSwitch0-Port2</ns1:resource-id>
            <ns1:configuration operation="merge">
              <ns1:admin-state>down</ns1:admin-state>
              <ns1:no-receive>false</ns1:no-receive>
              <ns1:no-forward>false</ns1:no-forward>
              <ns1:no-packet-in>false</ns1:no-packet-in>
            </ns1:configuration>
          </ns1:port>
        </ns1:resources>
      </ns1:capable-switch>
    </nc:config></nc:edit-config></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d359ee23-e664-11e3-a8fd-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><ok/></rpc-reply>
    Delivering to <ncclient.operations.edit.EditConfig object at 0x7f7ff0915290
    >
    Requesting 'EditConfig'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ns1="urn:o
    nf:of111:config:yang" message-id="urn:uuid:d384a4dc-e664-11e3-b1ed-0d6c265e
    373f"><nc:edit-config><nc:target><nc:running /></nc:target><nc:config>
      <ns1:capable-switch>
        <ns1:id>CapableSwitch0</ns1:id>
        <ns1:resources>
          <ns1:port>
            <ns1:resource-id>LogicalSwitch0-Port2</ns1:resource-id>
            <ns1:features>
              <ns1:advertised operation="merge">
                <ns1:rate>10Mb-FD</ns1:rate>
                <ns1:auto-negotiate>true</ns1:auto-negotiate>
                <ns1:medium>copper</ns1:medium>
                <ns1:pause>unsupported</ns1:pause>
              </ns1:advertised>
            </ns1:features>
          </ns1:port>
        </ns1:resources>
      </ns1:capable-switch>
    </nc:config></nc:edit-config></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d384a4dc-e664-11e3-b1ed-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><ok/></rpc-reply>
    Delivering to <ncclient.operations.edit.EditConfig object at 0x7f7ff0d3a950
    >
    Requesting 'EditConfig'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ns1="urn:o
    nf:of111:config:yang" message-id="urn:uuid:d39f537d-e664-11e3-84c3-0d6c265e
    373f"><nc:edit-config><nc:target><nc:running /></nc:target><nc:config>
      <ns1:capable-switch>
        <ns1:id>CapableSwitch0</ns1:id>
        <ns1:logical-switches>
          <ns1:switch>
            <ns1:id>LogicalSwitch0</ns1:id>
              <ns1:controllers>
                <ns1:controller operation="merge">
                  <ns1:id>Switch0-DefaultController</ns1:id>
                  <ns1:role>master</ns1:role>
                  <ns1:ip-address>127.0.0.1</ns1:ip-address>
                  <ns1:port>6633</ns1:port>
                  <ns1:protocol>tcp</ns1:protocol>
                </ns1:controller>
              </ns1:controllers>
          </ns1:switch>
        </ns1:logical-switches>
      </ns1:capable-switch>
    </nc:config></nc:edit-config></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d39f537d-e664-11e3-84c3-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><ok/></rpc-reply>
    Delivering to <ncclient.operations.edit.EditConfig object at 0x7f7ff0d3a950
    >
    Requesting 'Get'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:
    uuid:d3c8cb1c-e664-11e3-897f-0d6c265e373f"><nc:get /></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d3c8cb1c-e664-11e3-897f-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><data><capable-switch xmlns="urn:onf:of111:config:ya
    ng"><id>CapableSwitch0</id><resources><port><resource-id>LogicalSwitch0-Por
    t2</resource-id><number>2</number><name>Port2</name><current-rate>5000</cur
    rent-rate><max-rate>5000</max-rate><configuration><admin-state>down</admin-
    state><no-receive>false</no-receive><no-forward>false</no-forward><no-packe
    t-in>false</no-packet-in></configuration><state><oper-state>up</oper-state>
    <blocked>false</blocked><live>true</live></state><features><current><rate>1
    00Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><
    pause>unsupported</pause></current><advertised><rate>other</rate><auto-nego
    tiate>true</auto-negotiate><medium>copper</medium><pause>unsupported</pause
    ></advertised><supported><rate>100Mb-FD</rate><auto-negotiate>true</auto-ne
    gotiate><medium>copper</medium><pause>unsupported</pause></supported><adver
    tised-peer><rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><mediu
    m>copper</medium><pause>unsupported</pause></advertised-peer></features></p
    ort><port><resource-id>LogicalSwitch0-Port1</resource-id><number>1</number>
    <name>Port1</name><current-rate>5000</current-rate><max-rate>5000</max-rate
    ><configuration><admin-state>up</admin-state><no-receive>false</no-receive>
    <no-forward>false</no-forward><no-packet-in>false</no-packet-in></configura
    tion><state><oper-state>up</oper-state><blocked>false</blocked><live>true</
    live></state><features><current><rate>100Mb-FD</rate><auto-negotiate>true</
    auto-negotiate><medium>copper</medium><pause>unsupported</pause></current><
    advertised><rate>other</rate><auto-negotiate>true</auto-negotiate><medium>c
    opper</medium><pause>unsupported</pause></advertised><supported><rate>100Mb
    -FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><paus
    e>unsupported</pause></supported><advertised-peer><rate>100Mb-FD</rate><aut
    o-negotiate>true</auto-negotiate><medium>copper</medium><pause>unsupported<
    /pause></advertised-peer></features></port><port><resource-id>LogicalSwitch
    7-Port4</resource-id><number>4</number><name>Port4</name><current-rate>5000
    </current-rate><max-rate>5000</max-rate><configuration><admin-state>up</adm
    in-state><no-receive>false</no-receive><no-forward>false</no-forward><no-pa
    cket-in>false</no-packet-in></configuration><state><oper-state>up</oper-sta
    te><blocked>false</blocked><live>true</live></state><features><current><rat
    e>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</mediu
    m><pause>unsupported</pause></current><advertised><rate>other</rate><auto-n
    egotiate>true</auto-negotiate><medium>copper</medium><pause>unsupported</pa
    use></advertised><supported><rate>100Mb-FD</rate><auto-negotiate>true</auto
    -negotiate><medium>copper</medium><pause>unsupported</pause></supported><ad
    vertised-peer><rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><me
    dium>copper</medium><pause>unsupported</pause></advertised-peer></features>
    </port><port><resource-id>LogicalSwitch7-Port3</resource-id><number>3</numb
    er><name>Port3</name><current-rate>5000</current-rate><max-rate>5000</max-r
    ate><configuration><admin-state>up</admin-state><no-receive>false</no-recei
    ve><no-forward>false</no-forward><no-packet-in>false</no-packet-in></config
    uration><state><oper-state>up</oper-state><blocked>false</blocked><live>tru
    e</live></state><features><current><rate>100Mb-FD</rate><auto-negotiate>tru
    e</auto-negotiate><medium>copper</medium><pause>unsupported</pause></curren
    t><advertised><rate>other</rate><auto-negotiate>true</auto-negotiate><mediu
    m>copper</medium><pause>unsupported</pause></advertised><supported><rate>10
    0Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><p
    ause>unsupported</pause></supported><advertised-peer><rate>100Mb-FD</rate><
    auto-negotiate>true</auto-negotiate><medium>copper</medium><pause>unsupport
    ed</pause></advertised-peer></features></port><queue><resource-id>LogicalSw
    itch0-Port2-Queue991</resource-id><id>991</id><port>2</port><properties><mi
    n-rate>10</min-rate><max-rate>120</max-rate></properties></queue><queue><re
    source-id>LogicalSwitch0-Port2-Queue992</resource-id><id>992</id><port>2</p
    ort><properties><min-rate>10</min-rate><max-rate>130</max-rate></properties
    ></queue><queue><resource-id>LogicalSwitch7-Port3-Queue993</resource-id><id
    >993</id><port>3</port><properties><min-rate>200</min-rate><max-rate>300</m
    ax-rate></properties></queue><queue><resource-id>LogicalSwitch7-Port3-Queue
    994</resource-id><id>994</id><port>3</port><properties><min-rate>400</min-r
    ate><max-rate>900</max-rate></properties></queue></resources><logical-switc
    hes><switch><id>LogicalSwitch0</id><capabilities><max-buffered-packets>0</m
    ax-buffered-packets><max-tables>255</max-tables><max-ports>16777216</max-po
    rts><flow-statistics>true</flow-statistics><table-statistics>true</table-st
    atistics><port-statistics>true</port-statistics><group-statistics>true</gro
    up-statistics><queue-statistics>true</queue-statistics><reassemble-ip-fragm
    ents>false</reassemble-ip-fragments><block-looping-ports>false</block-loopi
    ng-ports><reserved-port-types><type>all</type><type>controller</type><type>
    able</type><type>inport</type><type>any</type></reserved-port-types><group-
    types><type>all</type><type>select</type><type>indirect</type><type>fast-fa
    ilover</type></group-types><group-capabilities><capability>select-weight</c
    apability><capability>select-liveness</capability><capability>chaining</cap
    ability></group-capabilities><action-types><type>output</type><type>group</
    type><type>set-queue</type><type>set-mpls-ttl</type><type>dec-mpls-ttl</typ
    e><type>set-nw-ttl</type><type>dec-nw-ttl</type><type>copy-ttl-out</type><t
    ype>copy-ttl-in</type><type>push-vlan</type><type>pop-vlan</type><type>push
    -mpls</type><type>pop-mpls</type><type>push-pbb</type><type>pop-pbb</type><
    type>set-field</type></action-types><instruction-types><type>goto-table</ty
    pe><type>write-metadata</type><type>write-actions</type><type>apply-actions
    </type><type>clear-actions</type><type>meter</type></instruction-types></ca
    pabilities><datapath-id>08:60:6E:7F:74:E7:00:00</datapath-id><enabled>true<
    /enabled><check-controller-certificate>false</check-controller-certificate>
    <lost-connection-behavior>failSecureMode</lost-connection-behavior><control
    lers><controller><id>Switch0-DefaultController</id><role>equal</role><ip-ad
    dress>127.0.0.1</ip-address><port>6633</port><protocol>tcp</protocol><state
    ><connection-state>down</connection-state><supported-versions>1.3</supporte
    d-versions></state></controller><controller><id>Switch0-Default-Controller<
    /id><role>equal</role><ip-address>127.0.0.1</ip-address><port>6633</port><p
    rotocol>tcp</protocol><state><connection-state>down</connection-state><supp
    orted-versions>1.3</supported-versions></state></controller></controllers><
    resources><port>LogicalSwitch0-Port2</port><port>LogicalSwitch0-Port1</port
    ><queue>LogicalSwitch0-Port2-Queue991</queue><queue>LogicalSwitch0-Port2-Qu
    eue992</queue></resources></switch><switch><id>LogicalSwitch7</id><capabili
    ties><max-buffered-packets>0</max-buffered-packets><max-tables>255</max-tab
    les><max-ports>16777216</max-ports><flow-statistics>true</flow-statistics><
    table-statistics>true</table-statistics><port-statistics>true</port-statist
    ics><group-statistics>true</group-statistics><queue-statistics>true</queue-
    statistics><reassemble-ip-fragments>false</reassemble-ip-fragments><block-l
    ooping-ports>false</block-looping-ports><reserved-port-types><type>all</typ
    e><type>controller</type><type>table</type><type>inport</type><type>any</ty
    pe></reserved-port-types><group-types><type>all</type><type>select</type><t
    ype>indirect</type><type>fast-failover</type></group-types><group-capabilit
    ies><capability>select-weight</capability><capability>select-liveness</capa
    bility><capability>chaining</capability></group-capabilities><action-types>
    <type>output</type><type>group</type><type>set-queue</type><type>set-mpls-t
    tl</type><type>dec-mpls-ttl</type><type>set-nw-ttl</type><type>dec-nw-ttl</
    type><type>copy-ttl-out</type><type>copy-ttl-in</type><type>push-vlan</type
    ><type>pop-vlan</type><type>push-mpls</type><type>pop-mpls</type><type>set-
    field</type></action-types><instruction-types><type>goto-table</type><type>
    write-metadata</type><type>write-actions</type><type>apply-actions</type><t
    ype>clear-actions</type></instruction-types></capabilities><datapath-id>08:
    60:6E:7F:74:E7:00:07</datapath-id><enabled>true</enabled><check-controller-
    certificate>false</check-controller-certificate><lost-connection-behavior>f
    ailSecureMode</lost-connection-behavior><controllers><controller><id>Switch
    7-Controller</id><role>equal</role><ip-address>127.0.0.1</ip-address><port>
    6633</port><protocol>tcp</protocol><state><connection-state>down</connectio
    n-state><supported-versions>1.2</supported-versions></state></controller></
    controllers><resources><port>LogicalSwitch7-Port4</port><port>LogicalSwitch
    7-Port3</port><queue>LogicalSwitch7-Port3-Queue993</queue><queue>LogicalSwi
    tch7-Port3-Queue994</queue></resources></switch></logical-switches></capabl
    e-switch></data></rpc-reply>
    Delivering to <ncclient.operations.retrieve.Get object at 0x7f7ff0d3a950>
    Traceback (most recent call last):
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/tests/integrated/test_of_config.py"
    , line 226, in _validate
        xmlschema.assertValid(tree)
      File "lxml.etree.pyx", line 3303, in lxml.etree._Validator.assertValid (s
    rc/lxml/lxml.etree.c:159771)
    DocumentInvalid: Element '{urn:onf:of111:config:yang}type': [facet 'enumera
    tion'] The value 'push-pbb' is not an element of the set {'output', 'copy-t
    tl-out', 'copy-ttl-in', 'set-mpls-ttl', 'dec-mpls-ttl', 'push-vlan', 'pop-v
    lan', 'push-mpls', 'pop-mpls', 'set-queue', 'group', 'set-nw-ttl', 'dec-nw-
    ttl', 'set-field'}., line 2
    set(['urn:onf:of111:config:yang'])
    <ns0:capable-switch xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:id>CapableSwitch0</ns0:id>
      <ns0:resources>
        <ns0:port>
          <ns0:resource-id>LogicalSwitch0-Port2</ns0:resource-id>
          <ns0:number>2</ns0:number>
          <ns0:name>Port2</ns0:name>
          <ns0:current-rate>5000</ns0:current-rate>
          <ns0:max-rate>5000</ns0:max-rate>
          <ns0:configuration>
            <ns0:admin-state>down</ns0:admin-state>
            <ns0:no-receive>false</ns0:no-receive>
            <ns0:no-forward>false</ns0:no-forward>
            <ns0:no-packet-in>false</ns0:no-packet-in>
          </ns0:configuration>
          <ns0:state>
            <ns0:oper-state>up</ns0:oper-state>
            <ns0:blocked>false</ns0:blocked>
            <ns0:live>true</ns0:live>
          </ns0:state>
          <ns0:features>
            <ns0:current>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:current>
            <ns0:advertised>
              <ns0:rate>other</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised>
            <ns0:supported>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:supported>
            <ns0:advertised-peer>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised-peer>
          </ns0:features>
        </ns0:port>
        <ns0:port>
          <ns0:resource-id>LogicalSwitch0-Port1</ns0:resource-id>
          <ns0:number>1</ns0:number>
          <ns0:name>Port1</ns0:name>
          <ns0:current-rate>5000</ns0:current-rate>
          <ns0:max-rate>5000</ns0:max-rate>
          <ns0:configuration>
            <ns0:admin-state>up</ns0:admin-state>
            <ns0:no-receive>false</ns0:no-receive>
            <ns0:no-forward>false</ns0:no-forward>
            <ns0:no-packet-in>false</ns0:no-packet-in>
          </ns0:configuration>
          <ns0:state>
            <ns0:oper-state>up</ns0:oper-state>
            <ns0:blocked>false</ns0:blocked>
            <ns0:live>true</ns0:live>
          </ns0:state>
          <ns0:features>
            <ns0:current>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:current>
            <ns0:advertised>
              <ns0:rate>other</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised>
            <ns0:supported>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:supported>
            <ns0:advertised-peer>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised-peer>
          </ns0:features>
        </ns0:port>
        <ns0:port>
          <ns0:resource-id>LogicalSwitch7-Port4</ns0:resource-id>
          <ns0:number>4</ns0:number>
          <ns0:name>Port4</ns0:name>
          <ns0:current-rate>5000</ns0:current-rate>
          <ns0:max-rate>5000</ns0:max-rate>
          <ns0:configuration>
            <ns0:admin-state>up</ns0:admin-state>
            <ns0:no-receive>false</ns0:no-receive>
            <ns0:no-forward>false</ns0:no-forward>
            <ns0:no-packet-in>false</ns0:no-packet-in>
          </ns0:configuration>
          <ns0:state>
            <ns0:oper-state>up</ns0:oper-state>
            <ns0:blocked>false</ns0:blocked>
            <ns0:live>true</ns0:live>
          </ns0:state>
          <ns0:features>
            <ns0:current>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:current>
            <ns0:advertised>
              <ns0:rate>other</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised>
            <ns0:supported>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:supported>
            <ns0:advertised-peer>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised-peer>
          </ns0:features>
        </ns0:port>
        <ns0:port>
          <ns0:resource-id>LogicalSwitch7-Port3</ns0:resource-id>
          <ns0:number>3</ns0:number>
          <ns0:name>Port3</ns0:name>
          <ns0:current-rate>5000</ns0:current-rate>
          <ns0:max-rate>5000</ns0:max-rate>
          <ns0:configuration>
            <ns0:admin-state>up</ns0:admin-state>
            <ns0:no-receive>false</ns0:no-receive>
            <ns0:no-forward>false</ns0:no-forward>
            <ns0:no-packet-in>false</ns0:no-packet-in>
          </ns0:configuration>
          <ns0:state>
            <ns0:oper-state>up</ns0:oper-state>
            <ns0:blocked>false</ns0:blocked>
            <ns0:live>true</ns0:live>
          </ns0:state>
          <ns0:features>
            <ns0:current>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:current>
            <ns0:advertised>
              <ns0:rate>other</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised>
            <ns0:supported>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:supported>
            <ns0:advertised-peer>
              <ns0:rate>100Mb-FD</ns0:rate>
              <ns0:auto-negotiate>true</ns0:auto-negotiate>
              <ns0:medium>copper</ns0:medium>
              <ns0:pause>unsupported</ns0:pause>
            </ns0:advertised-peer>
          </ns0:features>
        </ns0:port>
        <ns0:queue>
          <ns0:resource-id>LogicalSwitch0-Port2-Queue991</ns0:resource-id>
          <ns0:id>991</ns0:id>
          <ns0:port>2</ns0:port>
          <ns0:properties>
            <ns0:min-rate>10</ns0:min-rate>
            <ns0:max-rate>120</ns0:max-rate>
          </ns0:properties>
        </ns0:queue>
        <ns0:queue>
          <ns0:resource-id>LogicalSwitch0-Port2-Queue992</ns0:resource-id>
          <ns0:id>992</ns0:id>
          <ns0:port>2</ns0:port>
          <ns0:properties>
            <ns0:min-rate>10</ns0:min-rate>
            <ns0:max-rate>130</ns0:max-rate>
          </ns0:properties>
        </ns0:queue>
        <ns0:queue>
          <ns0:resource-id>LogicalSwitch7-Port3-Queue993</ns0:resource-id>
          <ns0:id>993</ns0:id>
          <ns0:port>3</ns0:port>
          <ns0:properties>
            <ns0:min-rate>200</ns0:min-rate>
            <ns0:max-rate>300</ns0:max-rate>
          </ns0:properties>
        </ns0:queue>
        <ns0:queue>
          <ns0:resource-id>LogicalSwitch7-Port3-Queue994</ns0:resource-id>
          <ns0:id>994</ns0:id>
          <ns0:port>3</ns0:port>
          <ns0:properties>
            <ns0:min-rate>400</ns0:min-rate>
            <ns0:max-rate>900</ns0:max-rate>
          </ns0:properties>
        </ns0:queue>
      </ns0:resources>
      <ns0:logical-switches>
        <ns0:switch>
          <ns0:id>LogicalSwitch0</ns0:id>
          <ns0:capabilities>
            <ns0:max-buffered-packets>0</ns0:max-buffered-packets>
            <ns0:max-tables>255</ns0:max-tables>
            <ns0:max-ports>16777216</ns0:max-ports>
            <ns0:flow-statistics>true</ns0:flow-statistics>
            <ns0:table-statistics>true</ns0:table-statistics>
            <ns0:port-statistics>true</ns0:port-statistics>
            <ns0:group-statistics>true</ns0:group-statistics>
            <ns0:queue-statistics>true</ns0:queue-statistics>
            <ns0:reassemble-ip-fragments>false</ns0:reassemble-ip-fragments>
            <ns0:block-looping-ports>false</ns0:block-looping-ports>
            <ns0:reserved-port-types>
              <ns0:type>all</ns0:type>
              <ns0:type>controller</ns0:type>
              <ns0:type>table</ns0:type>
              <ns0:type>inport</ns0:type>
              <ns0:type>any</ns0:type>
            </ns0:reserved-port-types>
            <ns0:group-types>
              <ns0:type>all</ns0:type>
              <ns0:type>select</ns0:type>
              <ns0:type>indirect</ns0:type>
              <ns0:type>fast-failover</ns0:type>
            </ns0:group-types>
            <ns0:group-capabilities>
              <ns0:capability>select-weight</ns0:capability>
              <ns0:capability>select-liveness</ns0:capability>
              <ns0:capability>chaining</ns0:capability>
            </ns0:group-capabilities>
            <ns0:action-types>
              <ns0:type>output</ns0:type>
              <ns0:type>group</ns0:type>
              <ns0:type>set-queue</ns0:type>
              <ns0:type>set-mpls-ttl</ns0:type>
              <ns0:type>dec-mpls-ttl</ns0:type>
              <ns0:type>set-nw-ttl</ns0:type>
              <ns0:type>dec-nw-ttl</ns0:type>
              <ns0:type>copy-ttl-out</ns0:type>
              <ns0:type>copy-ttl-in</ns0:type>
              <ns0:type>push-vlan</ns0:type>
              <ns0:type>pop-vlan</ns0:type>
              <ns0:type>push-mpls</ns0:type>
              <ns0:type>pop-mpls</ns0:type>
              <ns0:type>push-pbb</ns0:type>
              <ns0:type>pop-pbb</ns0:type>
              <ns0:type>set-field</ns0:type>
            </ns0:action-types>
            <ns0:instruction-types>
              <ns0:type>goto-table</ns0:type>
              <ns0:type>write-metadata</ns0:type>
              <ns0:type>write-actions</ns0:type>
              <ns0:type>apply-actions</ns0:type>
              <ns0:type>clear-actions</ns0:type>
              <ns0:type>meter</ns0:type>
            </ns0:instruction-types>
          </ns0:capabilities>
          <ns0:datapath-id>08:60:6E:7F:74:E7:00:00</ns0:datapath-id>
          <ns0:enabled>true</ns0:enabled>
          <ns0:check-controller-certificate>false</ns0:check-controller-certifi
    cate>
          <ns0:lost-connection-behavior>failSecureMode</ns0:lost-connection-beh
    avior>
          <ns0:controllers>
            <ns0:controller>
              <ns0:id>Switch0-DefaultController</ns0:id>
              <ns0:role>equal</ns0:role>
              <ns0:ip-address>127.0.0.1</ns0:ip-address>
              <ns0:port>6633</ns0:port>
              <ns0:protocol>tcp</ns0:protocol>
              <ns0:state>
                <ns0:connection-state>down</ns0:connection-state>
                <ns0:supported-versions>1.3</ns0:supported-versions>
              </ns0:state>
            </ns0:controller>
            <ns0:controller>
              <ns0:id>Switch0-Default-Controller</ns0:id>
              <ns0:role>equal</ns0:role>
              <ns0:ip-address>127.0.0.1</ns0:ip-address>
              <ns0:port>6633</ns0:port>
              <ns0:protocol>tcp</ns0:protocol>
              <ns0:state>
                <ns0:connection-state>down</ns0:connection-state>
                <ns0:supported-versions>1.3</ns0:supported-versions>
              </ns0:state>
            </ns0:controller>
          </ns0:controllers>
          <ns0:resources>
            <ns0:port>LogicalSwitch0-Port2</ns0:port>
            <ns0:port>LogicalSwitch0-Port1</ns0:port>
            <ns0:queue>LogicalSwitch0-Port2-Queue991</ns0:queue>
            <ns0:queue>LogicalSwitch0-Port2-Queue992</ns0:queue>
          </ns0:resources>
        </ns0:switch>
        <ns0:switch>
          <ns0:id>LogicalSwitch7</ns0:id>
          <ns0:capabilities>
            <ns0:max-buffered-packets>0</ns0:max-buffered-packets>
            <ns0:max-tables>255</ns0:max-tables>
            <ns0:max-ports>16777216</ns0:max-ports>
            <ns0:flow-statistics>true</ns0:flow-statistics>
            <ns0:table-statistics>true</ns0:table-statistics>
            <ns0:port-statistics>true</ns0:port-statistics>
            <ns0:group-statistics>true</ns0:group-statistics>
            <ns0:queue-statistics>true</ns0:queue-statistics>
            <ns0:reassemble-ip-fragments>false</ns0:reassemble-ip-fragments>
            <ns0:block-looping-ports>false</ns0:block-looping-ports>
            <ns0:reserved-port-types>
              <ns0:type>all</ns0:type>
              <ns0:type>controller</ns0:type>
              <ns0:type>table</ns0:type>
              <ns0:type>inport</ns0:type>
              <ns0:type>any</ns0:type>
            </ns0:reserved-port-types>
            <ns0:group-types>
              <ns0:type>all</ns0:type>
              <ns0:type>select</ns0:type>
              <ns0:type>indirect</ns0:type>
              <ns0:type>fast-failover</ns0:type>
            </ns0:group-types>
            <ns0:group-capabilities>
              <ns0:capability>select-weight</ns0:capability>
              <ns0:capability>select-liveness</ns0:capability>
              <ns0:capability>chaining</ns0:capability>
            </ns0:group-capabilities>
            <ns0:action-types>
              <ns0:type>output</ns0:type>
              <ns0:type>group</ns0:type>
              <ns0:type>set-queue</ns0:type>
              <ns0:type>set-mpls-ttl</ns0:type>
              <ns0:type>dec-mpls-ttl</ns0:type>
              <ns0:type>set-nw-ttl</ns0:type>
              <ns0:type>dec-nw-ttl</ns0:type>
              <ns0:type>copy-ttl-out</ns0:type>
              <ns0:type>copy-ttl-in</ns0:type>
              <ns0:type>push-vlan</ns0:type>
              <ns0:type>pop-vlan</ns0:type>
              <ns0:type>push-mpls</ns0:type>
              <ns0:type>pop-mpls</ns0:type>
              <ns0:type>set-field</ns0:type>
            </ns0:action-types>
            <ns0:instruction-types>
              <ns0:type>goto-table</ns0:type>
              <ns0:type>write-metadata</ns0:type>
              <ns0:type>write-actions</ns0:type>
              <ns0:type>apply-actions</ns0:type>
              <ns0:type>clear-actions</ns0:type>
            </ns0:instruction-types>
          </ns0:capabilities>
          <ns0:datapath-id>08:60:6E:7F:74:E7:00:07</ns0:datapath-id>
          <ns0:enabled>true</ns0:enabled>
          <ns0:check-controller-certificate>false</ns0:check-controller-certifi
    cate>
          <ns0:lost-connection-behavior>failSecureMode</ns0:lost-connection-beh
    avior>
          <ns0:controllers>
            <ns0:controller>
              <ns0:id>Switch7-Controller</ns0:id>
              <ns0:role>equal</ns0:role>
              <ns0:ip-address>127.0.0.1</ns0:ip-address>
              <ns0:port>6633</ns0:port>
              <ns0:protocol>tcp</ns0:protocol>
              <ns0:state>
                <ns0:connection-state>down</ns0:connection-state>
                <ns0:supported-versions>1.2</ns0:supported-versions>
              </ns0:state>
            </ns0:controller>
          </ns0:controllers>
          <ns0:resources>
            <ns0:port>LogicalSwitch7-Port4</ns0:port>
            <ns0:port>LogicalSwitch7-Port3</ns0:port>
            <ns0:queue>LogicalSwitch7-Port3-Queue993</ns0:queue>
            <ns0:queue>LogicalSwitch7-Port3-Queue994</ns0:queue>
          </ns0:resources>
        </ns0:switch>
      </ns0:logical-switches>
    </ns0:capable-switch>
    
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch0-Port2</ns0:resource-id>
      <ns0:number>2</ns0:number>
      <ns0:name>Port2</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>down</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch0-Port1</ns0:resource-id>
      <ns0:number>1</ns0:number>
      <ns0:name>Port1</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>up</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch7-Port4</ns0:resource-id>
      <ns0:number>4</ns0:number>
      <ns0:name>Port4</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>up</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch7-Port3</ns0:resource-id>
      <ns0:number>3</ns0:number>
      <ns0:name>Port3</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>up</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    Requesting 'EditConfig'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ns1="urn:o
    nf:of111:config:yang" message-id="urn:uuid:d3ddc2b8-e664-11e3-a8e7-0d6c265e
    373f"><nc:edit-config><nc:target><nc:running /></nc:target><nc:config>
      <ns1:capable-switch>
        <ns1:id>CapableSwitch0</ns1:id>
        <ns1:resources>
          <ns1:port>
            <ns1:resource-id>LogicalSwitch0-Port2</ns1:resource-id>
            <ns1:configuration operation="merge">
              <ns1:admin-state>down</ns1:admin-state>
            </ns1:configuration>
          </ns1:port>
          <ns1:port>
            <ns1:resource-id>LogicalSwitch0-Port1</ns1:resource-id>
            <ns1:configuration operation="merge">
              <ns1:admin-state>down</ns1:admin-state>
            </ns1:configuration>
          </ns1:port>
          <ns1:port>
            <ns1:resource-id>LogicalSwitch7-Port4</ns1:resource-id>
            <ns1:configuration operation="merge">
              <ns1:admin-state>down</ns1:admin-state>
            </ns1:configuration>
          </ns1:port>
          <ns1:port>
            <ns1:resource-id>LogicalSwitch7-Port3</ns1:resource-id>
            <ns1:configuration operation="merge">
              <ns1:admin-state>down</ns1:admin-state>
            </ns1:configuration>
          </ns1:port>
        </ns1:resources>
      </ns1:capable-switch>
    </nc:config></nc:edit-config></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d3ddc2b8-e664-11e3-a8e7-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><ok/></rpc-reply>
    Delivering to <ncclient.operations.edit.EditConfig object at 0x7f7ff0901e50
    >
    Requesting 'Get'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:
    uuid:d3f7c0f0-e664-11e3-ba3b-0d6c265e373f"><nc:get /></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d3f7c0f0-e664-11e3-ba3b-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><data><capable-switch xmlns="urn:onf:of111:config:ya
    ng"><id>CapableSwitch0</id><resources><port><resource-id>LogicalSwitch0-Por
    t2</resource-id><number>2</number><name>Port2</name><current-rate>5000</cur
    rent-rate><max-rate>5000</max-rate><configuration><admin-state>down</admin-
    state><no-receive>false</no-receive><no-forward>false</no-forward><no-packe
    t-in>false</no-packet-in></configuration><state><oper-state>up</oper-state>
    <blocked>false</blocked><live>true</live></state><features><current><rate>1
    00Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><
    pause>unsupported</pause></current><advertised><rate>other</rate><auto-nego
    tiate>true</auto-negotiate><medium>copper</medium><pause>unsupported</pause
    ></advertised><supported><rate>100Mb-FD</rate><auto-negotiate>true</auto-ne
    gotiate><medium>copper</medium><pause>unsupported</pause></supported><adver
    tised-peer><rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><mediu
    m>copper</medium><pause>unsupported</pause></advertised-peer></features></p
    ort><port><resource-id>LogicalSwitch0-Port1</resource-id><number>1</number>
    <name>Port1</name><current-rate>5000</current-rate><max-rate>5000</max-rate
    ><configuration><admin-state>down</admin-state><no-receive>false</no-receiv
    e><no-forward>false</no-forward><no-packet-in>false</no-packet-in></configu
    ration><state><oper-state>up</oper-state><blocked>false</blocked><live>true
    </live></state><features><current><rate>100Mb-FD</rate><auto-negotiate>true
    </auto-negotiate><medium>copper</medium><pause>unsupported</pause></current
    ><advertised><rate>other</rate><auto-negotiate>true</auto-negotiate><medium
    >copper</medium><pause>unsupported</pause></advertised><supported><rate>100
    Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><pa
    use>unsupported</pause></supported><advertised-peer><rate>100Mb-FD</rate><a
    uto-negotiate>true</auto-negotiate><medium>copper</medium><pause>unsupporte
    d</pause></advertised-peer></features></port><port><resource-id>LogicalSwit
    ch7-Port4</resource-id><number>4</number><name>Port4</name><current-rate>50
    00</current-rate><max-rate>5000</max-rate><configuration><admin-state>down<
    /admin-state><no-receive>false</no-receive><no-forward>false</no-forward><n
    o-packet-in>false</no-packet-in></configuration><state><oper-state>up</oper
    -state><blocked>false</blocked><live>true</live></state><features><current>
    <rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</m
    edium><pause>unsupported</pause></current><advertised><rate>other</rate><au
    to-negotiate>true</auto-negotiate><medium>copper</medium><pause>unsupported
    </pause></advertised><supported><rate>100Mb-FD</rate><auto-negotiate>true</
    auto-negotiate><medium>copper</medium><pause>unsupported</pause></supported
    ><advertised-peer><rate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate
    ><medium>copper</medium><pause>unsupported</pause></advertised-peer></featu
    res></port><port><resource-id>LogicalSwitch7-Port3</resource-id><number>3</
    number><name>Port3</name><current-rate>5000</current-rate><max-rate>5000</m
    ax-rate><configuration><admin-state>down</admin-state><no-receive>false</no
    -receive><no-forward>false</no-forward><no-packet-in>false</no-packet-in></
    configuration><state><oper-state>up</oper-state><blocked>false</blocked><li
    ve>true</live></state><features><current><rate>100Mb-FD</rate><auto-negotia
    te>true</auto-negotiate><medium>copper</medium><pause>unsupported</pause></
    current><advertised><rate>other</rate><auto-negotiate>true</auto-negotiate>
    <medium>copper</medium><pause>unsupported</pause></advertised><supported><r
    ate>100Mb-FD</rate><auto-negotiate>true</auto-negotiate><medium>copper</med
    ium><pause>unsupported</pause></supported><advertised-peer><rate>100Mb-FD</
    rate><auto-negotiate>true</auto-negotiate><medium>copper</medium><pause>uns
    upported</pause></advertised-peer></features></port><queue><resource-id>Log
    icalSwitch0-Port2-Queue991</resource-id><id>991</id><port>2</port><properti
    es><min-rate>10</min-rate><max-rate>120</max-rate></properties></queue><que
    ue><resource-id>LogicalSwitch0-Port2-Queue992</resource-id><id>992</id><por
    t>2</port><properties><min-rate>10</min-rate><max-rate>130</max-rate></prop
    erties></queue><queue><resource-id>LogicalSwitch7-Port3-Queue993</resource-
    id><id>993</id><port>3</port><properties><min-rate>200</min-rate><max-rate>
    300</max-rate></properties></queue><queue><resource-id>LogicalSwitch7-Port3
    -Queue994</resource-id><id>994</id><port>3</port><properties><min-rate>400<
    /min-rate><max-rate>900</max-rate></properties></queue></resources><logical
    -switches><switch><id>LogicalSwitch0</id><capabilities><max-buffered-packet
    s>0</max-buffered-packets><max-tables>255</max-tables><max-ports>16777216</
    max-ports><flow-statistics>true</flow-statistics><table-statistics>true</ta
    ble-statistics><port-statistics>true</port-statistics><group-statistics>tru
    e</group-statistics><queue-statistics>true</queue-statistics><reassemble-ip
    -fragments>false</reassemble-ip-fragments><block-looping-ports>false</block
    -looping-ports><reserved-port-types><type>all</type><type>controller</type>
    <type>table</type><type>inport</type><type>any</type></reserved-port-types>
    <group-types><type>all</type><type>select</type><type>indirect</type><type>
    fast-failover</type></group-types><group-capabilities><capability>select-we
    ight</capability><capability>select-liveness</capability><capability>chaini
    ng</capability></group-capabilities><action-types><type>output</type><type>
    group</type><type>set-queue</type><type>set-mpls-ttl</type><type>dec-mpls-t
    tl</type><type>set-nw-ttl</type><type>dec-nw-ttl</type><type>copy-ttl-out</
    type><type>copy-ttl-in</type><type>push-vlan</type><type>pop-vlan</type><ty
    pe>push-mpls</type><type>pop-mpls</type><type>push-pbb</type><type>pop-pbb<
    /type><type>set-field</type></action-types><instruction-types><type>goto-ta
    ble</type><type>write-metadata</type><type>write-actions</type><type>apply-
    actions</type><type>clear-actions</type><type>meter</type></instruction-typ
    es></capabilities><datapath-id>08:60:6E:7F:74:E7:00:00</datapath-id><enable
    d>true</enabled><check-controller-certificate>false</check-controller-certi
    ficate><lost-connection-behavior>failSecureMode</lost-connection-behavior><
    controllers><controller><id>Switch0-DefaultController</id><role>equal</role
    ><ip-address>127.0.0.1</ip-address><port>6633</port><protocol>tcp</protocol
    ><state><connection-state>down</connection-state><supported-versions>1.3</s
    upported-versions></state></controller><controller><id>Switch0-Default-Cont
    roller</id><role>equal</role><ip-address>127.0.0.1</ip-address><port>6633</
    port><protocol>tcp</protocol><state><connection-state>down</connection-stat
    e><supported-versions>1.3</supported-versions></state></controller></contro
    llers><resources><port>LogicalSwitch0-Port2</port><port>LogicalSwitch0-Port
    1</port><queue>LogicalSwitch0-Port2-Queue991</queue><queue>LogicalSwitch0-P
    ort2-Queue992</queue></resources></switch><switch><id>LogicalSwitch7</id><c
    apabilities><max-buffered-packets>0</max-buffered-packets><max-tables>255</
    max-tables><max-ports>16777216</max-ports><flow-statistics>true</flow-stati
    stics><table-statistics>true</table-statistics><port-statistics>true</port-
    statistics><group-statistics>true</group-statistics><queue-statistics>true<
    /queue-statistics><reassemble-ip-fragments>false</reassemble-ip-fragments><
    block-looping-ports>false</block-looping-ports><reserved-port-types><type>a
    ll</type><type>controller</type><type>table</type><type>inport</type><type>
    any</type></reserved-port-types><group-types><type>all</type><type>select</
    type><type>indirect</type><type>fast-failover</type></group-types><group-ca
    pabilities><capability>select-weight</capability><capability>select-livenes
    s</capability><capability>chaining</capability></group-capabilities><action
    -types><type>output</type><type>group</type><type>set-queue</type><type>set
    -mpls-ttl</type><type>dec-mpls-ttl</type><type>set-nw-ttl</type><type>dec-n
    w-ttl</type><type>copy-ttl-out</type><type>copy-ttl-in</type><type>push-vla
    n</type><type>pop-vlan</type><type>push-mpls</type><type>pop-mpls</type><ty
    pe>set-field</type></action-types><instruction-types><type>goto-table</type
    ><type>write-metadata</type><type>write-actions</type><type>apply-actions</
    type><type>clear-actions</type></instruction-types></capabilities><datapath
    -id>08:60:6E:7F:74:E7:00:07</datapath-id><enabled>true</enabled><check-cont
    roller-certificate>false</check-controller-certificate><lost-connection-beh
    avior>failSecureMode</lost-connection-behavior><controllers><controller><id
    >Switch7-Controller</id><role>equal</role><ip-address>127.0.0.1</ip-address
    ><port>6633</port><protocol>tcp</protocol><state><connection-state>down</co
    nnection-state><supported-versions>1.2</supported-versions></state></contro
    ller></controllers><resources><port>LogicalSwitch7-Port4</port><port>Logica
    lSwitch7-Port3</port><queue>LogicalSwitch7-Port3-Queue993</queue><queue>Log
    icalSwitch7-Port3-Queue994</queue></resources></switch></logical-switches><
    /capable-switch></data></rpc-reply>
    Delivering to <ncclient.operations.retrieve.Get object at 0x7f7ff0901e50>
    Traceback (most recent call last):
      File "/nfs/eos-fs.nfskuro/git/ryu/ryu/tests/integrated/test_of_config.py"
    , line 226, in _validate
        xmlschema.assertValid(tree)
      File "lxml.etree.pyx", line 3303, in lxml.etree._Validator.assertValid (s
    rc/lxml/lxml.etree.c:159771)
    DocumentInvalid: Element '{urn:onf:of111:config:yang}type': [facet 'enumera
    tion'] The value 'push-pbb' is not an element of the set {'output', 'copy-t
    tl-out', 'copy-ttl-in', 'set-mpls-ttl', 'dec-mpls-ttl', 'push-vlan', 'pop-v
    lan', 'push-mpls', 'pop-mpls', 'set-queue', 'group', 'set-nw-ttl', 'dec-nw-
    ttl', 'set-field'}., line 2
    set(['urn:onf:of111:config:yang'])
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch0-Port2</ns0:resource-id>
      <ns0:number>2</ns0:number>
      <ns0:name>Port2</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>down</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch0-Port1</ns0:resource-id>
      <ns0:number>1</ns0:number>
      <ns0:name>Port1</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>down</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch7-Port4</ns0:resource-id>
      <ns0:number>4</ns0:number>
      <ns0:name>Port4</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>down</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    <ns0:port xmlns:ns0="urn:onf:of111:config:yang">
      <ns0:resource-id>LogicalSwitch7-Port3</ns0:resource-id>
      <ns0:number>3</ns0:number>
      <ns0:name>Port3</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>down</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    
    Requesting 'CloseSession'
    queueing <?xml version='1.0' encoding='UTF-8'?>
    <nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:
    uuid:d422b4d7-e664-11e3-9f26-0d6c265e373f"><nc:close-session /></nc:rpc>
    Sync request, will wait for timeout=30
    Sending message
    parsed new message
    dispatching message to <ncclient.operations.rpc.RPCReplyListener object at 
    0x7f7ff0d3a5d0>: <?xml version="1.0" encoding="UTF-8"?><rpc-reply message-i
    d="urn:uuid:d422b4d7-e664-11e3-9f26-0d6c265e373f" xmlns="urn:ietf:params:xm
    l:ns:netconf:base:1.0"><ok/></rpc-reply>
    Delivering to <ncclient.operations.session.CloseSession object at 0x7f7ff09
    01e50>
    EOF in transport thread
    Broke out of main loop, error=SessionCloseError('Unexpected session close',
    )
    dispatching error to <ncclient.operations.rpc.RPCReplyListener object at 0x
    7f7ff0d3a5d0>
