.. step_by_step_example

***************************************************
Step-by-step example for testing ryu with OpenStack
***************************************************

Overview
========
Here is the step-by-step to test if ryu plugin/segregation works with openstack.
In this example,

#. create one user account as an admin and an user
#. create two projects and create a network tenant for each project
#. run VM instances for each projects
#. open vga console via virt-manager
#. try to ping to each VMs

Note: in this section, nova/quantum/ryu installation isn't explained.
If you don't have any experience with openstack nova, it is strongly
recommended to try plain nova and quantum with ovs plugin.

Conventions
===========
The following variable is used to show values which depends on the
configuration.

* $username: nova user account name which is used as admin and user
            Probably you man want to create two account to separate admin
            and user. In this example, only single account is used for
            simplicity.

            e.g. yamahata

* $tenant0: nova project name and tenant name.
            This name is used as both nova project name and nova network
            tenant name.
            Here we abuse nova project name as network tenant name for
            simplicity. If you'd like to more complex setting, please refer
            to nova documentation.

            e.g. yamahata-project-0

* $iprange0: IP ranges which is used for $tenant0
             e.g. 172.17.220.0/25
  
* $tenant1: another project name
            e.g. yamahata-project-1

* $iprange1: another IP ranges for $tenant1
             e.g. 172.17.221.0/25


step-by-step testing
====================
In this example, euca2ools is used because it's handy.
The more openstack way is possible, though.

#. setup nova data base

   Run the following on a nova node::

   $ sudo nova-manage db sync

#. setup quantum data base

   Use mysql command to connect mysql server::

   $ mysql -u <admin user name> -p

   Then create the quantum db and allow the agents to access it::

       mysql> CREATE DATABASE ovs_quantum;
       mysql> GRANT USAGE ON *.* to <user name>@'yourremotehost' IDENTIFIED BY 'newpassword';
       mysql> FLUSH PRIVILEGES;

   Where the database name, ovs_quantum, the user name, <user name>, and
   its password, newpassword, are the one defined in the ryu plugin
   configuration file, ryu.ini.

   If you are using multiple compute nodes, the GRANT sentence needs to
   be repeated. Or wildcard, %, can be used like::

       mysql> GRANT USAGE ON *.* to <user name>@'%' IDENTIFIED BY 'newpassword';

#. Make sure all nova, quantum, ryu and other openstack components are
   installed and running

   Especially

   * On nova compute/network node

     * Ryu must be installed
     * ryu quantum agent(ryu_quantum_agent.py) is put somewhere and
       it must be running
     * ovs bridge is configured

   * on machine quantum-server is running

     * Ryu must be installed

   * the db server is accessible from all related servers

#. create a user on a nova node

   Run the following on a nova node::

   $ sudo nova-manage --flagfile=/etc/nova/nova.conf user admin $username


#. Create project, get the zipfile for the project, unextract it and create

   ssh key for $tenant0
   Run the following::

   $ sudo nova-manage --flagfile /etc/nova/nova.conf project create $tenant0 --user=$username
   $ sudo nova-manage --flagfile=/etc/nova/nova.conf project create $tenant0 $username ./$tenant0.zip
   $ sudo unzip ./$tenant0.zip -d $tenant0
   $ source ./$tenant0/novarc
   $ euca-add-keypair mykey-$tenant0 > mykey-$tenant0.priv

#. do the same of the above step for $tenant1

#. create networks for each projects

   Run the followings::

   $ sudo nova-manage --flagfile=/etc/nova/nova.conf network create --label=$tenant0 --fixed_range_v4=$iprange0 --project_id=$tenant0
   $ sudo nova-manage --flagfile=/etc/nova/nova.conf network create --label=$tenant1 --fixed_range_v4=$iprange1 --project_id=$tenant1

#. register image file

   Get the vm image from somewhere (or create it by yourself) and register it.
   The easiest way is to get the image someone has already created. You can find
   links from the below.

   * `Getting Images that Work with OpenStack <http://wiki.openstack.org/GettingImages>`_.

   * `ttylinux by Scott Moser <http://smoser.brickies.net/ubuntu/ttylinux-uec/>`_.

   In this example we use the ttylinux image just because its size is small::

   $ wget http://smoser.brickies.net/ubuntu/ttylinux-uec/ttylinux-uec-i686-12.1_2.6.35-22_1.tar.gz
   $ cloud-publish-tarball ttylinux-uec-i686-12.1_2.6.35-22_1.tar.gz <bucket-name>
   $ euca-register <bucket-name>/ttylinux-uec-amd64-12.1_2.6.35-22_1.img.manifest.xml

   Now you get the image id, ari-xxx, aki-xxx and ami-xxx, where xxx is 
   replaced with some id number.
   Depending on which distribution you use, you need to use other command like
   uec-publish-tarball.
   If you customize images, you may have to use commands like euca-bundle-image,
   euca-upload-image, euca-register.

   Or you want to go for more openstack way, glance command is your friend
   to create/register image.

#. run instances

   boot instances for each projects.
   In order to test network segregation, 2 or more VM instances need to
   be created:

::

   $ source ./$tenant0/novarc
   $ euca-run-instances ami-<id which you get above> -k mykey-$tenant0 -t m1.tiny
   # repeat euca-run-instances for some times.
   $ source ./$tenant1/novarc
   $ euca-run-instances ami-<id which you get above> -k mykey-$tenant1 -t m1.tiny


#. check if VM instances are created

   Get the list of VM instances you've created and their assigned IP address::

    $ euca-describe-instances

#. login VM instances and try ping/traceroute

   In plain nova case, you can login the VM instances by ssh like
   "ssh -i mykey-$tenant0.priv root@$ipaddress"
   However, the VM instances are segregated from the management network. So the
   story differs. the easiest way to login the VM is to use virt-manager
   (or virsh) on each compute nodes.
   Identify on which compute node the VM is running by euca-describe-instances,
   and run virt-manager on the compute node. Show the vga console by
   virt-manager GUI, then you can login the VM instances.

   Then try "ping <other VM IP or gateway>" or "traceroute <ip address>"
   on each consoles.

#. packet capture (optional)

   You can run wireshark or similar tools in order to observe what packets
   are sent.


When something goes wrong
=========================
Something can go wrong sometimes unfortunately.
Database tables used by openstack nova/quantum seems very fragile.
Db can result in broken state easily. If you hit it, the easiest way is

#. stop all the related daemons
#. drop related DB and re-create them.
#. clean up OVS related stuff

   OVS uses its own data base which is persistent. So reboot doesn't fix it.
   The leaked resources must be released explicitly by hand.
   The following command would help.::

   # ip link delete <tapxxx>
   # tunctl -d <tapxxx>
   # ovs-vsctl del-port <br-int> <gw-xxx>
   # ovs-vsctl del-port <br-int> <tapxxx>

#. restart the daemons
#. set up from the scratch.

Although you can fix it by issuing SQL manually, you have to know what you're
doing with db tables.

Appendix
========
configuration file examples
---------------------------
This section includes sample configuration files I use for convenience.
Some values need to be changed depending on your setup. For example
IP addresses/port numbers.

* /etc/nova/nova.conf for api, compute, network, volume, object-store and scheduler node

Here is the nova.conf on which all nova servers are running::

    --verbose
	# For debugging

    --logdir=/var/log/nova
    --state_path=/var/lib/nova
    --lock_path=/var/lock/nova
	# I set those three above for my preference.
	# You don't have to set them if the default works for you

    --use_deprecated-auth=true
	# This depends on which authentication method you use.

    --sql_connection=mysql://nova:nova@localhost/nova
	# Change this depending on how MySQL(or other db?) is setup

    --dhcpbridge_flagfile=/etc/nova/nova.conf
    --dhcpbridge=/usr/local/bin/nova-dhcpbridge
	# This path depends on where you install nova.

    --fixed_range=172.17.220.0/16
	# You have to change this parameter depending on which IPs you uses

    --network_size=128
	# This depends on which IPs you uses for one tenant

    --network_manager=nova.network.quantum.manager.QuantumManager
    --quantum_connection_host=127.0.0.1 # <IP on which quantume server runs>
	# Change this according to your set up

    --connection_type=libvirt
    --libvirt_type=kvm
    --firewall_driver=quantum.plugins.ryu.nova.firewall.NopFirewallDriver
    --libvirt_ovs_integration_bridge=br-int
    --libvirt_vif_type=ethernet
    --libvirt_vif_driver=quantum.plugins.ryu.nova.vif.LibvirtOpenVswitchOFPRyuDriver
    --libvirt_ovs_ryu_api_host=<ip address on which ryu is running>:<port>
	# default 172.0.0.1:8080

    --linuxnet_interface_driver=quantum.plugins.ryu.nova.linux_net.LinuxOVSRyuInterfaceDriver
    --linuxnet_ovs_ryu_api_host=<ip address on which ryu is running>:<port>
	# default 172.0.0.1:8080
	# usually same to libvirt_ovs_ryu_api_host

    --quantum_use_dhcp


* /etc/nova/nova.conf on compute nodes

I copied the above to compute node and modified it.
So it includes unnecessary values for network node. Since they don't harm,
I didn't scrub them.::

    --verbose

    --logdir=/var/log/nova
    --state_path=/var/lib/nova
    --lock_path=/var/lock/nova

    --use_deprecated_auth

    --sql_connection=mysql://nova:nova@<IP address>/nova

    --dhcpbridge_flagfile=/etc/nova/nova.conf
    --dhcpbridge=/usr/bin/nova-dhcpbridge

    --fixed_range=172.17.220.0/16
    --network_size=128

    --network_manager=nova.network.quantum.manager.QuantumManager
    --quantum_connection_host=<IP address on which quantum server is runniung>
    --connection_type=libvirt
    --libvirt_type=kvm
    --libvirt_ovs_integration_bridge=br-int
    --libvirt_vif_type=ethernet
    --libvirt_vif_driver=quantum.plugins.ryu.nova.vif.LibvirtOpenVswitchOFPRyuDriver
    --libvirt_ovs_ryu_api_host=<ip address on which ryu is running>:<port>
    --linuxnet_interface_driver=quantum.plugins.ryu.nova.linux_net.LinuxOVSRyuInterfaceDriver
    --linuxnet_ovs_ryu_api_host=<ip address on which ryu is running>:<port>
    --firewall_driver=quantum.plugins.ryu.nova.firewall.NopFirewallDriver
    --quantum_use_dhcp

    --rabbit_host=<IP address on which rabbit mq is running>
    --glance_api_servers=<IP address on which glance api server is running>:<port>
    --ec2_host=<IP address on which ec2 api server is running>
    --osapi_host=<IP address on which OpenStack api server is running>
    --s3_host=<IP address on which S3 host is running>
    --metadata_host=<IP address on which ec2 meta data sever is running>


* /etc/quantum/plugins.ini

This file needs to be installed on which quantum-server is running.
This file defines which quantum plugin is used::

  [PLUGIN]
  # Quantum plugin provider module
  provider = quantum.plugins.ryu.ryu_quantum_plugin.RyuQuantumPlugin


* /etc/quantum/quantum.conf

This file needs to be installed on which quantum-server is running.
A configuration file for quantum server. I use this file as is.

* /etc/quantum/plugins/ryu/ryu.ini

This files needs to be installed on nova-compute node, nova-network node
and quantum-server node.
This file defines several setting ryu quantum plugin/agent uses::

  [DATABASE]
  # This line MUST be changed to actually run the plugin.
  # Example: sql_connection = mysql://root:nova@127.0.0.1:3306/ovs_quantum
  #sql_connection = mysql://<user>:<pass>@<IP>:<port>/<dbname>
  sql_connection = mysql://quantum:quantum@172.0.0.1:3306/ovs_quantum

  [OVS]
  integration-bridge = br-int

  # openflow-controller = <host IP address of ofp controller>:<port: 6633>
  # openflow-rest-api = <host IP address of ofp rest api service>:<port: 8080>
  openflow-controller = <IP address on which ryu-manager is running>:<port>
	# default 127.0.0.1:6633
	# This corresponds to <ofp_listen_host>:<ofp_listen_port> in ryu.conf

  openflow-rest-api = <IP address on which ryu-manager is running>:<port>
	# default 127.0.0.1:8080
	# This corresponds to <wsapi_host>:<wsapi_port> in ryu.conf

* /etc/ryu/ryu.conf

This file needs to be installed on which ryu-manager is running.
If you use default configurations, you don't have to modify it.
Just leave it blank::

    # Sample configuration file
    [DEFAULT]
    #wsapi_host=<hostip>
    #wsapi_port=<port:8080>
    #ofp_listen_host=<hostip>
    #ofp_listen_port=<port:6633>
