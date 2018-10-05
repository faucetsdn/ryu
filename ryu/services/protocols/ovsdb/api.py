# Copyright (c) 2014 Rackspace Hosting
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid

from ryu.lib import dpid as dpidlib
from ryu.services.protocols.ovsdb import event as ovsdb_event


def _get_table_row(table, attr_name, attr_value, tables):
    sentinel = object()

    for row in tables[table].rows.values():
        if getattr(row, attr_name, sentinel) == attr_value:
            return row


def _get_controller(tables, attr_val, attr_name='target'):
    return _get_table_row('Controller', attr_name, attr_val, tables=tables)


def _get_bridge(tables, attr_val, attr_name='name'):
    return _get_table_row('Bridge', attr_name, attr_val, tables=tables)


def _get_port(tables, attr_val, attr_name='name'):
    return _get_table_row('Port', attr_name, attr_val, tables=tables)


def _get_iface(tables, attr_val, attr_name='name'):
    return _get_table_row('Interface', attr_name, attr_val, tables=tables)


def match_row(manager, system_id, table, fn):
    def _match_row(tables):
        return next((r for r in tables[table].rows.values()
                     if fn(r)), None)

    request_to_get_tables = ovsdb_event.EventReadRequest(system_id,
                                                         _match_row)
    reply_to_get_tables = manager.send_request(request_to_get_tables)
    return reply_to_get_tables.result


def match_rows(manager, system_id, table, fn):
    def _match_rows(tables):
        return (r for r in tables[table].rows.values() if fn(r))

    request = ovsdb_event.EventReadRequest(system_id, _match_rows)
    reply = manager.send_request(request)
    return reply.result


def row_by_name(manager, system_id, name, table='Bridge', fn=None):
    matched_row = match_row(manager, system_id, table,
                            lambda row: row.name == name)

    if fn is not None:
        return fn(matched_row)

    return matched_row


def rows_by_external_id(manager, system_id, key, value,
                        table='Bridge', fn=None):
    matched_rows = match_rows(manager, system_id, table,
                              lambda r: (key in r.external_ids and
                                         r.external_ids.get(key) == value))

    if matched_rows and fn is not None:
        return [fn(row) for row in matched_rows]

    return matched_rows


def rows_by_other_config(manager, system_id, key, value,
                         table='Bridge', fn=None):
    matched_rows = match_rows(manager, system_id, table,
                              lambda r: (key in r.other_config and
                                         r.other_config.get(key) == value))

    if matched_rows and fn is not None:
        return [fn(row) for row in matched_rows]

    return matched_rows


def get_column_value(manager, table, record, column):
    """
    Example : To get datapath_id from Bridge table
    get_column_value('Bridge', <bridge name>, 'datapath_id').strip('"')
    """
    row = row_by_name(manager, record, table)
    value = getattr(row, column, "")

    if isinstance(value, list) and len(value) == 1:
        value = value[0]

    return str(value)


def get_iface_by_name(manager, system_id, name, fn=None):
    iface = row_by_name(manager, system_id, name, 'Interface')

    if fn is not None:
        return fn(iface)

    return iface


def get_ifaces_by_external_id(manager, system_id, key, value, fn=None):
    return rows_by_external_id(manager, system_id, key, value,
                               'Interface', fn)


def get_ifaces_by_other_config(manager, system_id, key, value, fn=None):
    return rows_by_other_config(manager, system_id, key, value,
                                'Interface', fn)


def get_port_by_name(manager, system_id, name, fn=None):
    port = row_by_name(manager, system_id, name, 'Port')

    if fn is not None:
        return fn(port)

    return port


def get_bridge_for_iface_name(manager, system_id, iface_name, fn=None):
    iface = row_by_name(manager, system_id, iface_name, 'Interface')
    port = match_row(manager, system_id, 'Port',
                     lambda x: iface in x.interfaces)
    bridge = match_row(manager, system_id, 'Bridge',
                       lambda x: port in x.ports)

    if fn is not None:
        return fn(bridge)

    return bridge


def get_table(manager, system_id, name):
    def _get_table(tables):
        return tables[name]

    request_to_get_tables = ovsdb_event.EventReadRequest(system_id,
                                                         _get_table)
    reply_to_get_tables = manager.send_request(request_to_get_tables)
    return reply_to_get_tables.result


def get_bridge_by_datapath_id(manager, system_id, datapath_id, fn=None):
    def _match_fn(row):
        row_dpid = dpidlib.str_to_dpid(str(row.datapath_id[0]))
        return row_dpid == datapath_id

    bridge = match_row(manager, system_id, 'Bridge', _match_fn)

    if fn is not None:
        return fn(bridge)

    return bridge


def get_datapath_ids_for_systemd_id(manager, system_id):
    def _get_dp_ids(tables):
        dp_ids = []

        bridges = tables.get('Bridge')

        if not bridges:
            return dp_ids

        for bridge in bridges.rows.values():
            datapath_ids = bridge.datapath_id
            dp_ids.extend(dpidlib.str_to_dpid(dp_id) for dp_id in datapath_ids)

        return dp_ids

    request = ovsdb_event.EventReadRequest(system_id, _get_dp_ids)
    reply = manager.send_request(request)
    return reply.result


def get_system_id_for_datapath_id(manager, datapath_id):
    def _get_dp_ids(tables):
        bridges = tables.get('Bridge')

        if not bridges:
            return None

        for bridge in bridges.rows.values():
            datapath_ids = [dpidlib.str_to_dpid(dp_id)
                            for dp_id in bridge.datapath_id]

            if datapath_id in datapath_ids:
                openvswitch = tables['Open_vSwitch'].rows

                if openvswitch:
                    row = openvswitch.get(list(openvswitch.keys())[0])
                    return row.external_ids.get('system-id')

        return None

    request = ovsdb_event.EventReadRequest(None, _get_dp_ids)
    reply = manager.send_request(request)

    # NOTE(jkoelker) Bulk reads return a tuple of (system_id, result)
    for result in reply.result:
        if result[1]:
            return result[0]

    return None


def get_bridges_by_system_id(manager, system_id, fn=None):
    bridges = get_table(manager, system_id, 'Bridge').rows.values()

    if fn is not None:
        return fn(bridges)

    return bridges


def bridge_exists(manager, system_id, bridge_name):
    return bool(row_by_name(manager, system_id, bridge_name))


def port_exists(manager, system_id, port_name):
    return bool(row_by_name(manager, system_id, port_name, 'Port'))


def set_external_id(manager, system_id, key, val, fn):
    val = str(val)

    def _set_iface_external_id(tables, *_):
        row = fn(tables)

        if not row:
            return None

        external_ids = row.external_ids
        external_ids[key] = val
        row.external_ids = external_ids

    req = ovsdb_event.EventModifyRequest(system_id, _set_iface_external_id)
    return manager.send_request(req)


def set_iface_external_id(manager, system_id, iface_name, key, val):
    return set_external_id(manager, system_id, key, val,
                           lambda tables: _get_iface(tables, iface_name))


def set_other_config(manager, system_id, key, val, fn):
    val = str(val)

    def _set_iface_other_config(tables, *_):
        row = fn(tables)

        if not row:
            return None

        other_config = row.other_config
        other_config[key] = val
        row.other_config = other_config

    req = ovsdb_event.EventModifyRequest(system_id, _set_iface_other_config)
    return manager.send_request(req)


def set_iface_other_config(manager, system_id, iface_name, key, val):
    return set_other_config(manager, system_id, key, val,
                            lambda tables: _get_iface(tables, iface_name))


def del_external_id(manager, system_id, key, fn):
    def _del_iface_external_id(tables, *_):
        row = fn(tables)

        if not row:
            return None

        external_ids = row.external_ids
        if key in external_ids:
            external_ids.pop(key)
            row.external_ids = external_ids

    req = ovsdb_event.EventModifyRequest(system_id, _del_iface_external_id)
    return manager.send_request(req)


def del_iface_external_id(manager, system_id, iface_name, key):
    return del_external_id(manager, system_id, key,
                           lambda tables: _get_iface(tables, iface_name))


def del_other_config(manager, system_id, key, fn):
    def _del_iface_other_config(tables, *_):
        row = fn(tables)

        if not row:
            return None

        other_config = row.other_config
        if key in other_config:
            other_config.pop(key)
            row.other_config = other_config

    req = ovsdb_event.EventModifyRequest(system_id, _del_iface_other_config)
    return manager.send_request(req)


def del_iface_other_config(manager, system_id, iface_name, key):
    return del_other_config(manager, system_id, key,
                            lambda tables: _get_iface(tables, iface_name))


def del_port(manager, system_id, bridge_name, fn):
    def _delete_port(tables, *_):
        bridge = _get_bridge(tables, bridge_name)

        if not bridge:
            return

        port = fn(tables)

        if not port:
            return

        ports = bridge.ports
        ports.remove(port)
        bridge.ports = ports

    req = ovsdb_event.EventModifyRequest(system_id, _delete_port)

    return manager.send_request(req)


def del_port_by_uuid(manager, system_id, bridge_name, port_uuid):
    return del_port(manager, system_id, bridge_name,
                    lambda tables: _get_port(tables, port_uuid,
                                             attr_name='uuid'))


def del_port_by_name(manager, system_id, bridge_name, port_name):
    return del_port(manager, system_id, bridge_name,
                    lambda tables: _get_port(tables, port_name))


def set_controller(manager, system_id, bridge_name,
                   target, controller_info=None):
    controller_info = controller_info or {}

    def _set_controller(tables, insert):
        bridge = _get_bridge(tables, bridge_name)

        controller = _get_controller(tables, target)
        _uuid = None
        if not controller:
            _uuid = controller_info.get('uuid', uuid.uuid4())
            controller = insert(tables['Controller'], _uuid)
            controller.target = target
            controller.connection_mode = ['out-of-band']

        elif 'out-of-band' not in controller.connection_mode:
            controller.connection_mode = ['out-of-band']

        if controller_info:
            for key, val in controller_info.items():
                setattr(controller, key, val)

        bridge.controller = [controller]

        return _uuid

    req = ovsdb_event.EventModifyRequest(system_id, _set_controller)
    return manager.send_request(req)


def create_port(manager, system_id, bridge_name, port_info, iface_info=None,
                port_insert_uuid=None, iface_insert_uuid=None):
    if iface_info is None:
        iface_info = {}

    if not port_insert_uuid:
        port_insert_uuid = uuid.uuid4()

    if not iface_insert_uuid:
        iface_insert_uuid = uuid.uuid4()

    def _create_port(tables, insert):
        bridge = _get_bridge(tables, bridge_name)

        if not bridge:
            return

        default_port_name = 'port' + str(port_insert_uuid)

        if 'name' not in iface_info:
            iface_info['name'] = port_info.get('name', default_port_name)

        if 'type' not in iface_info:
            iface_info['type'] = 'internal'

        if 'name' not in port_info:
            port_info['name'] = default_port_name

        iface = insert(tables['Interface'], iface_insert_uuid)
        for key, val in iface_info.items():
            setattr(iface, key, val)

        port = insert(tables['Port'], port_insert_uuid)
        for key, val in port_info.items():
            setattr(port, key, val)

        port.interfaces = [iface]

        bridge.ports = bridge.ports + [port]

        return port_insert_uuid, iface_insert_uuid

    req = ovsdb_event.EventModifyRequest(system_id, _create_port)

    return manager.send_request(req)
