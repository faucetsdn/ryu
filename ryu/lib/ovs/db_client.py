# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import logging
import os

import ryu.contrib
ryu.contrib.update_module_path()

from ovs import (jsonrpc,
                 stream)
from ovs import util as ovs_util
from ovs.db import schema

LOG = logging.getLogger(__name__)


class DBClient(object):
    def __init__(self, remote):
        super(DBClient, self).__init__()
        self.remote = remote

    def run_command(self, args):
        _COMMANDS = {
            'list-dbs': self._list_dbs,
            'get-schema': self._get_schema,
            'get-schema-version': self._get_schema_version,
            'list-tables': self._list_tables,
            'list-columns': self._list_columns,
            'transact': self._transact,
            'monitor': self._monitor,
            'dump': self._dump,
        }

        command = args[0]
        args = args[1:]

        error, stream_ = stream.Stream.open_block(
            stream.Stream.open(self.remote))
        if error:
            RuntimeError('can not open socket to %s: %s' %
                         (self.remote, os.strerror(error)))
            raise
        rpc = jsonrpc.Connection(stream_)

        ret = _COMMANDS[command](rpc, *args)
        LOG.info('ret %s', ret)
        rpc.close()

    def _check_txn(self, error, reply):
        if error:
            ovs_util.ovs_fatal(error, os.strerror(error))
        elif reply.error:
            ovs_util.ovs_fatal(reply.error, 'error %s' % reply.error)

    def _fetch_dbs(self, rpc):
        request = jsonrpc.Message.create_request('list_dbs', [])
        error, reply = rpc.transact_block(request)
        self._check_txn(error, reply)

        dbs = set()
        for name in reply.result:
            dbs.add(name)

        return dbs

    def _fetch_schema_json(self, rpc, database):
        request = jsonrpc.Message.create_request('get_schema', [database])
        error, reply = rpc.transact_block(request)
        self._check_txn(error, reply)
        return reply.result

    def _fetch_schema(self, rpc, database):
        return schema.DbSchema.from_json(self._fetch_schema_json(rpc,
                                                                 database))

    # commands
    def _list_dbs(self, rpc, *_args):
        return self._fetch_dbs(rpc)

    def _get_schema(self, rpc, *args):
        database = args[0]
        return self._fetch_schema(rpc, database).to_json()

    def _get_schema_version(self, rpc, *_args):
        database = _args[0]
        schema_ = self._fetch_schema(rpc, database)
        return schema_.version

    def _list_tables(self, rpc, *args):
        database = args[0]
        schema_ = self._fetch_schema(rpc, database)
        return [table.to_json() for table in schema_.tables.values()]

    def _list_columns(self, rpc, *args):
        database = args[0]
        table_name = None
        if len(args) > 1:
            table_name = args[1]

        schema_ = self._fetch_schema(rpc, database)
        if table_name is None:
            tables = [table for table in schema_.tables.values()]
        else:
            tables = [table for table in schema_.tables.values()
                      if table.name == table_name]

        columns = []
        for table in tables:
            columns.extend(table.columns.values())
        return [column.to_json() for column in columns]

    def _transact(self, rpc, *args):
        raise NotImplementedError()

    def _monitor(self, rpc, *args):
        raise NotImplementedError()

    def _dump(self, rpc, *args):
        raise NotImplementedError()
