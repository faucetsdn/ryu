*********************
OVSDB Manager library
*********************

Path: ``ryu.services.protocols.ovsdb``

Introduction
============

Ryu OVSDB Manager library allows your code to interact with devices
speaking the OVSDB protocol. This enables your code to perform remote
management of the devices and react to topology changes on them.

Please note this library will spawn a server listening on the port 6640 (the
IANA registered for OVSDB protocol), but does not initiate connections from
controller side.
Then, to make your devices connect to Ryu, you need to tell the controller IP
address and port to your devices.

.. code-block:: bash

    # Show current configuration
    $ ovs-vsctl get-manager

    # Set manager (controller) address
    $ ovs-vsctl set-manager "tcp:127.0.0.1:6640"

    # If you want to specify IPv6 address, wrap ip with brackets
    $ ovs-vsctl set-manager "tcp:[::1]:6640"

Also this library identifies the devices by "system-id" which should be unique,
persistent identifier among all devices connecting to a single controller.
Please make sure "system-id" is configured before connecting.

.. code-block:: bash

    # Show current configuration
    $ ovs-vsctl get Open_vSwitch . external_ids:system-id

    # Set system-id manually
    $ ovs-vsctl set Open_vSwitch . external_ids:system-id=<SYSTEM-ID>

Example
=======

The following logs all new OVSDB connections in "handle_new_ovsdb_connection"
and also provides the API "create_port" for creating a port on a bridge.

.. code-block:: python

    import uuid

    from ryu.base import app_manager
    from ryu.controller.handler import set_ev_cls
    from ryu.services.protocols.ovsdb import api as ovsdb
    from ryu.services.protocols.ovsdb import event as ovsdb_event


    class MyApp(app_manager.RyuApp):
        @set_ev_cls(ovsdb_event.EventNewOVSDBConnection)
        def handle_new_ovsdb_connection(self, ev):
            system_id = ev.system_id
            address = ev.client.address
            self.logger.info(
                'New OVSDB connection from system-id=%s, address=%s',
                system_id, address)

            # Example: If device has bridge "s1", add port "s1-eth99"
            if ovsdb.bridge_exists(self, system_id, "s1"):
                self.create_port(system_id, "s1", "s1-eth99")

        def create_port(self, system_id, bridge_name, name):
            new_iface_uuid = uuid.uuid4()
            new_port_uuid = uuid.uuid4()

            bridge = ovsdb.row_by_name(self, system_id, bridge_name)

            def _create_port(tables, insert):
                iface = insert(tables['Interface'], new_iface_uuid)
                iface.name = name
                iface.type = 'internal'

                port = insert(tables['Port'], new_port_uuid)
                port.name = name
                port.interfaces = [iface]

                bridge.ports = bridge.ports + [port]

                return new_port_uuid, new_iface_uuid

            req = ovsdb_event.EventModifyRequest(system_id, _create_port)
            rep = self.send_request(req)

            if rep.status != 'success':
                self.logger.error('Error creating port %s on bridge %s: %s',
                                  name, bridge, rep.status)
                return None

            return rep.insert_uuids[new_port_uuid]
