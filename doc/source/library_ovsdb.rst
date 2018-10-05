*************
OVSDB library
*************

Path: ``ryu.lib.ovs``

Similar to the :doc:`library_ovsdb_manager`, this library enables your
application to speak the OVSDB protocol (RFC7047_), but differ from the
:doc:`library_ovsdb_manager`, this library will initiate connections from
controller side as ovs-vsctl_ command does.
Please make sure that your devices are listening on either the Unix domain
socket or TCP/SSL port before calling the APIs of this library.

.. code-block:: bash

    # Show current configuration
    $ ovs-vsctl get-manager

    # Set TCP listen address
    $ ovs-vsctl set-manager "ptcp:6640"

See manpage of ovs-vsctl_ command for more details.

.. _RFC7047: https://tools.ietf.org/html/rfc7047
.. _ovs-vsctl: http://openvswitch.org/support/dist-docs/ovs-vsctl.8.txt

Basic Usage
===========

1. Instantiate :py:mod:`ryu.lib.ovs.vsctl.VSCtl`.

2. Construct commands with :py:mod:`ryu.lib.ovs.vsctl.VSCtlCommand`.
   The syntax is almost the same as ovs-vsctl_ command.

3. Execute commands via :py:mod:`ryu.lib.ovs.vsctl.VSCtl.run_command`.

Example
-------

.. code-block:: python

    from ryu.lib.ovs import vsctl

    OVSDB_ADDR = 'tcp:127.0.0.1:6640'
    ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)

    # Equivalent to
    # $ ovs-vsctl show
    command = vsctl.VSCtlCommand('show')
    ovs_vsctl.run_command([command])
    print(command)
    # >>> VSCtlCommand(args=[],command='show',options=[],result='830d781f-c3c8-4b4f-837e-106e1b33d058\n    ovs_version: "2.8.90"\n')

    # Equivalent to
    # $ ovs-vsctl list Port s1-eth1
    command = vsctl.VSCtlCommand('list', ('Port', 's1-eth1'))
    ovs_vsctl.run_command([command])
    print(command)
    # >>> VSCtlCommand(args=('Port', 's1-eth1'),command='list',options=[],result=[<ovs.db.idl.Row object at 0x7f525fb682e8>])
    print(command.result[0].name)
    # >>> s1-eth1

API Reference
=============

ryu.lib.ovs.vsctl
-----------------

.. automodule:: ryu.lib.ovs.vsctl
    :members:

ryu.lib.ovs.bridge
------------------

.. automodule:: ryu.lib.ovs.bridge
    :members:
