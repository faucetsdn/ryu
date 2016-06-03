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

from ryu.controller import event as ryu_event
from ryu.controller import handler


class EventRowBase(ryu_event.EventBase):
    def __init__(self, system_id, table, row, event_type):
        super(EventRowBase, self).__init__()
        self.system_id = system_id
        self.table = table
        self.row = row
        self.event_type = event_type

    def __str__(self):
        return '%s<system_id=%s table=%s, uuid=%s>' % (self.__class__.__name__,
                                                       self.system_id,
                                                       self.table,
                                                       self.row['_uuid'])


class EventRowDelete(EventRowBase):
    def __init__(self, system_id, table, row):
        super(EventRowDelete, self).__init__(system_id, table, row, 'Deleted')


class EventRowInsert(EventRowBase):
    def __init__(self, system_id, table, row):
        super(EventRowInsert, self).__init__(system_id, table, row, 'Inserted')


class EventRowUpdate(ryu_event.EventBase):
    def __init__(self, system_id, table, old, new):
        super(EventRowUpdate, self).__init__()
        self.system_id = system_id
        self.table = table
        self.old = old
        self.new = new
        self.event_type = 'Updated'

    def __str__(self):
        return '%s<system_id=%s table=%s, uuid=%s>' % (self.__class__.__name__,
                                                       self.system_id,
                                                       self.table,
                                                       self.old['_uuid'])


class EventModifyRequest(ryu_event.EventRequestBase):
    """ Dispatch a modify function to OVSDB

    `func` must be a callable that accepts an insert fucntion and the
    IDL.tables object. It can then modify the tables as needed. For inserts,
    specify a UUID for each insert, and return a tuple of the temporary
    UUID's. The execution of `func` will be wrapped in a single transaction
    and the reply will include a dict of temporary UUID to real UUID mappings.

    e.g.

        new_port_uuid = uuid.uuid4()

        def modify(tables, insert):
            bridges = tables['Bridge'].rows
            bridge = None
            for b in bridges:
                if b.name == 'my-bridge':
                    bridge = b

            if not bridge:
                return

            port = insert('Port', new_port_uuid)

            bridge.ports = bridge.ports + [port]

            return (new_port_uuid, )

        request = EventModifyRequest(system_id, modify)
        reply = send_request(request)

        port_uuid = reply.insert_uuids[new_port_uuid]
    """
    def __init__(self, system_id, func):
        super(EventModifyRequest, self).__init__()
        self.dst = 'OVSDB'
        self.system_id = system_id
        self.func = func

    def __str__(self):
        return '%s<system_id=%s>' % (self.__class__.__name__, self.system_id)


class EventModifyReply(ryu_event.EventReplyBase):
    def __init__(self, system_id, status, insert_uuids, err_msg):
        self.system_id = system_id
        self.status = status
        self.insert_uuids = insert_uuids
        self.err_msg = err_msg

    def __str__(self):
        return ('%s<system_id=%s, status=%s, insert_uuids=%s, error_msg=%s>'
                % (self.__class__.__name__,
                   self.system_id,
                   self.status,
                   self.insert_uuids,
                   self.err_msg))


class EventNewOVSDBConnection(ryu_event.EventBase):
    def __init__(self, system_id):
        super(EventNewOVSDBConnection, self).__init__()
        self.system_id = system_id

    def __str__(self):
        return '%s<system_id=%s>' % (self.__class__.__name__,
                                     self.system_id)


class EventReadRequest(ryu_event.EventRequestBase):
    def __init__(self, system_id, func):
        self.system_id = system_id
        self.func = func
        self.dst = 'OVSDB'


class EventReadReply(ryu_event.EventReplyBase):
    def __init__(self, system_id, result, err_msg=''):
        self.system_id = system_id
        self.result = result
        self.err_msg = err_msg


class EventRowInsertedBase(EventRowInsert):
    def __init__(self, ev):
        super(EventRowInsertedBase, self).__init__(ev.system_id,
                                                   ev.table,
                                                   ev.row)


class EventRowDeletedBase(EventRowDelete):
    def __init__(self, ev):
        super(EventRowDeletedBase, self).__init__(ev.system_id,
                                                  ev.table,
                                                  ev.row)


class EventRowUpdatedBase(EventRowUpdate):
    def __init__(self, ev):
        super(EventRowUpdatedBase, self).__init__(ev.system_id,
                                                  ev.table,
                                                  ev.old,
                                                  ev.new)


class EventPortInserted(EventRowInsertedBase):
    pass


class EventPortDeleted(EventRowDeletedBase):
    pass


class EventPortUpdated(EventRowUpdatedBase):
    pass


class EventInterfaceInserted(EventRowInsertedBase):
    pass


class EventInterfaceDeleted(EventRowDeletedBase):
    pass


class EventInterfaceUpdated(EventRowUpdatedBase):
    pass


handler.register_service('ryu.services.protocols.ovsdb.manager')
