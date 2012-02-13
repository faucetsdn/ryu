.. _step_by_step_example

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
   be created::

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
