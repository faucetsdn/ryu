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

import collections
import logging
import uuid

# NOTE(jkoelker) Patch Vlog so that is uses standard logging
from ovs import vlog


class Vlog(vlog.Vlog):
    def __init__(self, name):
        self.log = logging.getLogger('ovs.%s' % name)

    def __log(self, level, message, **kwargs):
        level = vlog.LEVELS.get(level, logging.DEBUG)
        self.log.log(level, message, **kwargs)

vlog.Vlog = Vlog


from ovs import jsonrpc
from ovs import reconnect
from ovs import stream
from ovs import timeval
from ovs.db import idl

from ryu.base import app_manager
from ryu.lib import hub
from ryu.services.protocols.ovsdb import event
from ryu.services.protocols.ovsdb import model


now = timeval.msec


def _uuid_to_row(atom, base):
    if base.ref_table:
        value = base.ref_table.rows.get(atom)
    else:
        value = atom

    if isinstance(value, idl.Row):
        value = str(value.uuid)

    return value


def dictify(row):
    if row is None:
        return

    return dict([(k, v.to_python(_uuid_to_row))
                 for k, v in row._data.items()])


def discover_schemas(connection):
    # NOTE(jkoelker) currently only the Open_vSwitch schema
    #                is supported.
    # TODO(jkoelker) support arbitrary schemas
    req = jsonrpc.Message.create_request('list_dbs', [])
    error, reply = connection.transact_block(req)

    if error or reply.error:
        return

    schemas = []
    for db in reply.result:
        if db != 'Open_vSwitch':
            continue

        req = jsonrpc.Message.create_request('get_schema', [db])
        error, reply = connection.transact_block(req)

        if error or reply.error:
            # TODO(jkoelker) Error handling
            continue

        schemas.append(reply.result)

    return schemas


def discover_system_id(idl):
    system_id = None

    while system_id is None and idl._session.is_connected():
        idl.run()
        openvswitch = idl.tables['Open_vSwitch'].rows

        if openvswitch:
            row = openvswitch.get(list(openvswitch.keys())[0])
            system_id = row.external_ids.get('system-id')

    return system_id


# NOTE(jkoelker) Wrap ovs's Idl to accept an existing session, and
#                trigger callbacks on changes
class Idl(idl.Idl):
    def __init__(self, session, schema):
        if not isinstance(schema, idl.SchemaHelper):
            schema = idl.SchemaHelper(schema_json=schema)
            schema.register_all()

        schema = schema.get_idl_schema()

        # NOTE(jkoelker) event buffer
        self._events = []

        self.tables = schema.tables
        self._db = schema
        self._session = session
        self._monitor_request_id = None
        self._last_seqno = None
        self.change_seqno = 0

        # Database locking.
        self.lock_name = None          # Name of lock we need, None if none.
        self.has_lock = False          # Has db server said we have the lock?
        self.is_lock_contended = False  # Has db server said we can't get lock?
        self._lock_request_id = None   # JSON-RPC ID of in-flight lock request.

        # Transaction support.
        self.txn = None
        self._outstanding_txns = {}

        for table in schema.tables.values():
            for column in table.columns.values():
                if not hasattr(column, 'alert'):
                    column.alert = True
            table.need_table = False
            table.rows = {}
            table.idl = self

    @property
    def events(self):
        events = self._events
        self._events = []
        return events

    def __process_update(self, table, uuid, old, new):
        old_row = table.rows.get(uuid)
        if old_row is not None:
            old_row = model.Row(dictify(old_row))
            old_row['_uuid'] = uuid

        changed = idl.Idl.__process_update(self, table, uuid, old, new)

        if changed:
            if not new:
                ev = (event.EventRowDelete, (table.name, old_row))

            elif not old:
                new_row = model.Row(dictify(table.rows.get(uuid)))
                new_row['_uuid'] = uuid
                ev = (event.EventRowInsert, (table.name, new_row))

            else:
                new_row = model.Row(dictify(table.rows.get(uuid)))
                new_row['_uuid'] = uuid

                ev = (event.EventRowUpdate, (table.name, old_row, new_row))

            self._events.append(ev)

        return changed


class RemoteOvsdb(app_manager.RyuApp):
    _EVENTS = [event.EventRowUpdate,
               event.EventRowDelete,
               event.EventRowInsert,
               event.EventInterfaceDeleted,
               event.EventInterfaceInserted,
               event.EventInterfaceUpdated,
               event.EventPortDeleted,
               event.EventPortInserted,
               event.EventPortUpdated]

    @classmethod
    def factory(cls, sock, address, *args, **kwargs):
        ovs_stream = stream.Stream(sock, None, None)
        connection = jsonrpc.Connection(ovs_stream)
        schemas = discover_schemas(connection)

        if not schemas:
            return

        fsm = reconnect.Reconnect(now())
        fsm.set_name('%s:%s' % address)
        fsm.enable(now())
        fsm.set_passive(True, now())
        fsm.set_max_tries(-1)
        fsm.connected(now())

        session = jsonrpc.Session(fsm, connection)
        idl = Idl(session, schemas[0])

        system_id = discover_system_id(idl)

        if not system_id:
            return None

        name = cls.instance_name(system_id)
        ovs_stream.name = name
        connection.name = name
        fsm.set_name(name)

        kwargs = kwargs.copy()
        kwargs['address'] = address
        kwargs['idl'] = idl
        kwargs['name'] = name
        kwargs['system_id'] = system_id

        app_mgr = app_manager.AppManager.get_instance()

        old_app = app_manager.lookup_service_brick(name)
        old_events = None
        if old_app:
            old_events = old_app.events
            app_mgr.uninstantiate(name)

        app = app_mgr.instantiate(cls, *args, **kwargs)

        if old_events:
            app.events = old_events

        return app

    @classmethod
    def instance_name(cls, system_id):
        return '%s-%s' % (cls.__name__, system_id)

    def __init__(self, *args, **kwargs):
        super(RemoteOvsdb, self).__init__(*args, **kwargs)
        self.address = kwargs['address']
        self._idl = kwargs['idl']
        self.system_id = kwargs['system_id']
        self.name = kwargs['name']
        self._txn_q = collections.deque()

    def _event_proxy_loop(self):
        while self.is_active:
            events = self._idl.events

            if not events:
                hub.sleep(0.1)
                continue

            for event in events:
                ev = event[0]
                args = event[1]
                self._submit_event(ev(self.system_id, *args))

            hub.sleep(0)

    def _submit_event(self, ev):
        self.send_event_to_observers(ev)
        try:
            ev_cls_name = 'Event' + ev.table + ev.event_type
            proxy_ev_cls = getattr(event, ev_cls_name, None)
            if proxy_ev_cls:
                self.send_event_to_observers(proxy_ev_cls(ev))
        except Exception:
            self.logger.exception('Error submitting specific event for OVSDB',
                                  self.system_id)

    def _idl_loop(self):
        while self.is_active:
            try:
                self._idl.run()
                self._transactions()
            except Exception:
                self.logger.exception('Error running IDL for system_id %s' %
                                      self.system_id)
                break

            hub.sleep(0)

    def _run_thread(self, func, *args, **kwargs):
        try:
            func(*args, **kwargs)

        finally:
            self.stop()

    def _transactions(self):
        if not self._txn_q:
            return

        # NOTE(jkoelker) possibly run multiple transactions per loop?
        self._transaction()

    def _transaction(self):
        req = self._txn_q.popleft()
        txn = idl.Transaction(self._idl)

        uuids = req.func(self._idl.tables, txn.insert)
        status = txn.commit_block()

        insert_uuids = {}
        err_msg = None

        if status in (idl.Transaction.SUCCESS,
                      idl.Transaction.UNCHANGED):
            if uuids:
                if isinstance(uuids, uuid.UUID):
                    insert_uuids[uuids] = txn.get_insert_uuid(uuids)

                else:
                    insert_uuids = dict((uuid, txn.get_insert_uuid(uuid))
                                        for uuid in uuids)
        else:
            err_msg = txn.get_error()

        rep = event.EventModifyReply(self.system_id, status, insert_uuids,
                                     err_msg)
        self.reply_to_request(req, rep)

    def modify_request_handler(self, ev):
        self._txn_q.append(ev)

    def read_request_handler(self, ev):
        result = ev.func(self._idl.tables)
        rep = event.EventReadReply(self.system_id, result)
        self.reply_to_request(ev, rep)

    def start(self):
        super(RemoteOvsdb, self).start()
        t = hub.spawn(self._run_thread, self._idl_loop)
        self.threads.append(t)

        t = hub.spawn(self._run_thread, self._event_proxy_loop)
        self.threads.append(t)

    def stop(self):
        super(RemoteOvsdb, self).stop()
        self._idl.close()
