*********************
OVSDB Manager library
*********************

Introduction
============

Ryu OVSDB Manager library allows your code to interact with devices
speaking the OVSDB protocol. This enables your code to perform remote
management of the devices and react to topology changes on them.

Example
=======

The following logs all new OVSDB connections and allows creating a port
on a bridge.

.. code-block:: python

    import uuid

    from ryu.base import app_manager
    from ryu.services.protocols.ovsdb import api as ovsdb
    from ryu.services.protocols.ovsdb import event as ovsdb_event


    class MyApp(app_manager.RyuApp):
        @set_ev_cls(ovsdb_event.EventNewOVSDBConnection)
        def handle_new_ovsdb_connection(self, ev):
            system_id = ev.system_id
            self.logger.info('New OVSDB connection from system id %s',
                             systemd_id)

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

                return (new_port_uuid, new_iface_uuid)

            req = ovsdb_event.EventModifyRequest(system_id, _create_port)
            rep = self.send_request(req)

            if rep.status != 'success':
                self.logger.error('Error creating port %s on bridge %s: %s',
                                  name, bridge, rep.status)
                return None

            return rep.insert_uuids[new_port_uuid]
