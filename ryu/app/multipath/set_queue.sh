ovs-vsctl -- set Port s1-eth2 qos=@newqos \
	 -- --id=@newqos create QoS type=linux-htb other-config:max-rate=250000000 queues=0=@q0\
	 -- --id=@q0 create Queue other-config:min-rate=8000000 other-config:max-rate=150000000\

ovs-vsctl -- set Port s1-eth3 qos=@defaultqos\
	-- --id=@defaultqos create QoS type=linux-htb other-config:max-rate=300000000 queues=1=@q1\
	 -- --id=@q1 create Queue other-config:min-rate=5000000 other-config:max-rate=200000000

ovs-vsctl list queue
