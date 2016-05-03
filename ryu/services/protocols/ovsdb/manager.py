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

import ssl
import socket

from ryu import cfg
from ryu.base import app_manager
from ryu.lib import hub
from ryu.services.protocols.ovsdb import client
from ryu.services.protocols.ovsdb import event
from ryu.controller import handler


opts = (cfg.StrOpt('address', default='0.0.0.0', help='OVSDB address'),
        cfg.IntOpt('port', default=6640, help='OVSDB port'),
        cfg.IntOpt('probe-interval', help='OVSDB reconnect probe interval'),
        cfg.IntOpt('min-backoff',
                   help=('OVSDB reconnect minimum milliseconds between '
                         'connection attemps')),
        cfg.IntOpt('max-backoff',
                   help=('OVSDB reconnect maximum milliseconds between '
                         'connection attemps')),
        cfg.StrOpt('mngr-privkey', default=None, help='manager private key'),
        cfg.StrOpt('mngr-cert', default=None, help='manager certificate'),
        cfg.ListOpt('whitelist', default=[],
                    help='Whitelist of address to allow to connect'),
        cfg.ListOpt('schema-tables', default=[],
                    help='Tables in the OVSDB schema to configure'),
        cfg.ListOpt('schema-exclude-columns', default=[],
                    help='Table columns in the OVSDB schema to filter out.  '
                         'Values should be in the format: <table>.<column>.'
                         'Ex: Bridge.netflow,Interface.statistics')
        )

cfg.CONF.register_opts(opts, 'ovsdb')


class OVSDB(app_manager.RyuApp):
    _EVENTS = [event.EventNewOVSDBConnection,
               event.EventModifyRequest,
               event.EventReadRequest]

    def __init__(self, *args, **kwargs):
        super(OVSDB, self).__init__(*args, **kwargs)
        self._address = self.CONF.ovsdb.address
        self._port = self.CONF.ovsdb.port
        self._probe_interval = self.CONF.ovsdb.probe_interval
        self._min_backoff = self.CONF.ovsdb.min_backoff
        self._max_backoff = self.CONF.ovsdb.max_backoff
        self._clients = {}

    def _accept(self, server):
        if self.CONF.ovsdb.whitelist:
            def check(address):
                if address in self.CONF.ovsdb.whitelist:
                    return True

                self.logger.debug('Connection from non-whitelist client '
                                  '(%s:%s)' % address)
                return False

        else:
            def check(address):
                return True

        while self.is_active:
            try:
                # TODO(jkoelker) SSL Certificate Fingerprint check
                sock, client_address = server.accept()

            except:
                if self.is_active:
                    self.logger.exception('Error accepting connection')
                    continue

            if not check(client_address[0]):
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                continue

            self.logger.debug('New connection from %s:%s' % client_address)
            t = hub.spawn(self._start_remote, sock, client_address)
            self.threads.append(t)

    def _bulk_read_handler(self, ev):
        results = []

        def done(gt, *args, **kwargs):
            if gt in self.threads:
                self.threads.remove(gt)

            results.append(gt.wait())

        threads = []
        for c in self._clients.values():
            gt = hub.spawn(c.read_request_handler, ev, bulk=True)
            threads.append(gt)
            self.threads.append(gt)
            gt.link(done)

        hub.joinall(threads)
        rep = event.EventReadReply(None, results)
        self.reply_to_request(ev, rep)

    def _proxy_event(self, ev):
        system_id = ev.system_id
        client_name = client.RemoteOvsdb.instance_name(system_id)

        if client_name not in self._clients:
            self.logger.info('Unknown remote system_id %s' % system_id)
            return

        return self.send_event(client_name, ev)

    def _start_remote(self, sock, client_address):
        schema_tables = cfg.CONF.ovsdb.schema_tables
        schema_ex_col = {}
        if cfg.CONF.ovsdb.schema_exclude_columns:
            for c in cfg.CONF.ovsdb.schema_exclude_columns:
                tbl, col = c.split('.')
                if tbl in schema_ex_col:
                    schema_ex_col[tbl].append(col)
                else:
                    schema_ex_col[tbl] = [col]

        app = client.RemoteOvsdb.factory(sock, client_address,
                                         probe_interval=self._probe_interval,
                                         min_backoff=self._min_backoff,
                                         max_backoff=self._max_backoff,
                                         schema_tables=schema_tables,
                                         schema_exclude_columns=schema_ex_col)

        if app:
            self._clients[app.name] = app
            app.start()
            ev = event.EventNewOVSDBConnection(app.system_id)
            self.send_event_to_observers(ev)

        else:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass

            sock.close()

    def start(self):
        server = hub.listen((self._address, self._port))
        key = self.CONF.ovsdb.mngr_privkey or self.CONF.ctl_privkey
        cert = self.CONF.ovsdb.mngr_cert or self.CONF.ctl_cert

        if key is not None and cert is not None:
            ssl_kwargs = dict(keyfile=key, certfile=cert, server_side=True)

            if self.CONF.ca_certs is not None:
                ssl_kwargs['cert_reqs'] = ssl.CERT_REQUIRED
                ssl_kwargs['ca_certs'] = self.CONF.ca_certs

            server = ssl.wrap_socket(server, **ssl_kwargs)

        self._server = server

        self.logger.info('Listening on %s:%s for clients' % (self._address,
                                                             self._port))
        t = hub.spawn(self._accept, self._server)
        super(OVSDB, self).start()
        return t

    def stop(self):
        # NOTE(jkoelker) Attempt to gracefully stop the accept loop
        self.is_active = False

        # NOTE(jkoelker) Forceably kill the loop and clear the main_thread
        if self.main_thread:
            hub.kill(self.main_thread)
            self.main_thread = None

        # NOTE(jkoelker) Stop all the clients
        for c in self._clients.values():
            c.stop()

        # NOTE(jkoelker) super will only take care of the event and joining now
        super(OVSDB, self).stop()

    @handler.set_ev_cls(event.EventModifyRequest)
    def modify_request_handler(self, ev):

        system_id = ev.system_id
        client_name = client.RemoteOvsdb.instance_name(system_id)
        remote = self._clients.get(client_name)

        if not remote:
            msg = 'Unknown remote system_id %s' % system_id
            self.logger.info(msg)
            rep = event.EventModifyReply(system_id, None, None, msg)
            return self.reply_to_request(ev, rep)

        return remote.modify_request_handler(ev)

    @handler.set_ev_cls(event.EventReadRequest)
    def read_request_handler(self, ev):
        system_id = ev.system_id

        if system_id is None:
            def done(gt, *args, **kwargs):
                if gt in self.threads:
                    self.threads.remove(gt)

            thread = hub.spawn(self._bulk_read_handler, ev)
            self.threads.append(thread)
            return thread.link(done)

        client_name = client.RemoteOvsdb.instance_name(system_id)
        remote = self._clients.get(client_name)

        if not remote:
            msg = 'Unknown remote system_id %s' % system_id
            self.logger.info(msg)
            rep = event.EventReadReply(system_id, None, msg)
            return self.reply_to_request(ev, rep)

        return remote.read_request_handler(ev)
