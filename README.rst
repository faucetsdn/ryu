****************************
Ryu Network Operating System
****************************

For details, please see the documentation under doc/ directory and
make html (or make <format you prefer>). If you have any
questions, suggestions, and patches, the mailing list is available at
`ryu-devel ML
<https://lists.sourceforge.net/lists/listinfo/ryu-devel>`_.

Ryu Official site is `<http://www.osrg.net/ryu/>`_.


Overview
========
Ryu is an open-sourced Network Operating System (NOS) licensed under
Apache v2.0. It's fully written in Python.

Ryu aims to provide a logically centralized control and well defined
API that make it easy for operators to create new network management
and control applications. Currently, Ryu supports OpenFlow protocol to
modify the behavior of network devices.

We aim at the de facto OSS NOS implementation and NOS API.

Currently, Ryu is shipped with one control application for `OpenStack
<http://openstack.org/.>`_ network management L2 segregation of
tenants without using VLAN. The application is included in OpenStack
mainline as of Essex release.

The project goal is to develop an OSS Network Operating System that
has high quality enough for use in large production environment in
code quality/functionality/usability.


TODO
====
* OpenFlow Protocol version 1.2 (right after the spec release)
* The better API for control applications
* Cluster support
* ...too many for here.


Quick Start
===========
Get source code::

   % git clone git://github.com/osrg/ryu.git

Then just type::

   % cd ryu; python ./setup.py install

and run ryu-manager command which is installed.
Then set up your openflow switch (hardware switch or OVS) to connect the ip
address and port to which ryu-manager is listening.
If you want to use it with Openstack (nova and quantum with ovs plugin),
please refer detailed documents under doc/ directory.


Requirement
===========
* python-setuptools
* python-gevent >= 0.13
* python-gflags
* python-sphinx


Project Members
===============
* OHMURA Kei <ohmura.kei at lab.ntt.co.jp>
* MORITA Kazutaka <morita.kazutaka at lab.ntt.co.jp>
* Isaku Yamahata <yamahata at valinux co jp>
* FUJITA Tomonori <fujita.tomonori@lab.ntt.co.jp> 

