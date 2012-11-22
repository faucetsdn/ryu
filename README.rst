What's Ryu
==========
Ryu is an Operating System for Software Defined Networking.
            
Ryu aims to provide a logically centralized control and well defined
API that make it easy for operators to create new network management
and control applications. Currently, Ryu manages network devices by
using OpenFlow. You can say that Ryu is an OpenFlow Controller, which
support OpenFlow v1.0, v1.2, v1.3, and Nicira Extensions.

All of the code is freely available under the Apache 2.0 license. Ryu
is fully written in Python.


Quick Start
===========
Installing Ryu is quite easy::

   % pip install ryu

If you prefer to install Ryu from the source code::

   % git clone git://github.com/osrg/ryu.git
   % cd ryu; python ./setup.py install

If you want to use Ryu with `OpenStack <http://openstack.org/>`_,
please refer `detailed documents <http://osrg.github.com/ryu/doc/using_with_openstack.html>`_.
You can create tens of thousands of isolated virtual networks without
using VLAN.  The Ryu application is included in OpenStack mainline as
of Essex release.

If you want to write your Ryu application, have a look at
`Writing ryu application <http://osrg.github.com/ryu/doc/writing_ryu_app.html>`_ document.
After writing your application, just type::

   % ryu-manager yourapp.py


Support
=======
Ryu Official site is `<http://osrg.github.com/ryu/>`_.

If you have any
questions, suggestions, and patches, the mailing list is available at
`ryu-devel ML
<https://lists.sourceforge.net/lists/listinfo/ryu-devel>`_.
`The ML archive at Gmane <http://dir.gmane.org/gmane.network.ryu.devel>`_
is also available.
