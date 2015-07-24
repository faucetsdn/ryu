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
from ryu.lib import dpid as dpidlib
from ryu.services.protocols.ovsdb import event as ovsdb_event


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


def get_bridges_by_system_id(manager, system_id):
    return get_table(manager, system_id, 'Bridge').rows.values()


def bridge_exists(manager, system_id, bridge_name):
    return bool(row_by_name(manager, system_id, bridge_name))


def port_exists(manager, system_id, port_name):
    return bool(row_by_name(manager, system_id, port_name, 'Port'))
