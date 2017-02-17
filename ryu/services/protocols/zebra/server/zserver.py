# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

"""
Zebra Server corresponding to 'zserv' structure.
"""

import contextlib
import logging
import os
import socket
import struct

import netaddr

from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import RyuApp
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import zebra

from ryu.services.protocols.zebra import db
from ryu.services.protocols.zebra import event
from ryu.services.protocols.zebra.server import event as zserver_event


LOG = logging.getLogger(__name__)

CONF = cfg.CONF['zapi']
GLOBAL_CONF = cfg.CONF

# Session to database of Zebra protocol service
SESSION = db.Session()


class ZClient(object):
    """
    Zebra client class.
    """

    def __init__(self, server, sock, addr):
        self.server = server
        self.sock = sock
        self.addr = addr
        self.logger = server.logger
        self.is_active = False
        self._threads = []
        self.send_q = hub.Queue(16)

        # Zebra protocol version
        self.zserv_ver = CONF.server_version

        # Zebra route type distributed by client (not initialized yet)
        self.route_type = None

    def start(self):
        self.is_active = True
        self.sock.settimeout(GLOBAL_CONF.socket_timeout)

        self._threads.append(hub.spawn(self._send_loop))
        self._threads.append(hub.spawn(self._recv_loop))

        self.server.send_event_to_observers(
            zserver_event.EventZClientConnected(self))

        hub.joinall(self._threads)

        self.server.send_event_to_observers(
            zserver_event.EventZClientDisconnected(self))

    def stop(self):
        self.is_active = False

    def _send_loop(self):
        try:
            while self.is_active:
                buf = self.send_q.get()
                self.sock.sendall(buf)
        except socket.error as e:
            self.logger.exception(
                'Error while sending message to Zebra client%s: %s',
                self.addr, e)

        self.stop()

    def _recv_loop(self):
        buf = b''
        min_len = recv_len = zebra.ZebraMessage.get_header_size(
            self.zserv_ver)
        try:
            while self.is_active:
                try:
                    recv_buf = self.sock.recv(recv_len)
                except socket.timeout:
                    continue

                if len(recv_buf) == 0:
                    break

                buf += recv_buf
                while len(buf) >= min_len:
                    (length,) = struct.unpack_from('!H', buf)
                    if (length - len(buf)) > 0:
                        # Need to receive remaining data
                        recv_len = length - len(buf)
                        break

                    msg, _, buf = zebra.ZebraMessage.parser(buf)

                    ev = event.message_to_event(self, msg)
                    if ev:
                        self.logger.debug('Notify event: %s', ev)
                        self.server.send_event_to_observers(ev)

        except socket.error as e:
            self.logger.exception(
                'Error while sending message to Zebra client%s: %s',
                self.addr, e)

        self.stop()

    def send_msg(self, msg):
        """
        Sends Zebra message.

        :param msg: Instance of py:class: `ryu.lib.packet.zebra.ZebraMessage`.
        :return: Serialized msg if succeeded, otherwise None.
        """
        if not self.is_active:
            self.logger.debug(
                'Cannot send message: Already deactivated: msg=%s', msg)
            return
        elif not self.send_q:
            self.logger.debug(
                'Cannot send message: Send queue does not exist: msg=%s', msg)
            return
        elif self.zserv_ver != msg.version:
            self.logger.debug(
                'Zebra protocol version mismatch:'
                'server_version=%d, msg.version=%d',
                self.zserv_ver, msg.version)
            msg.version = self.zserv_ver  # fixup

        self.send_q.put(msg.serialize())


def zclient_connection_factory(sock, addr):
    LOG.debug('Connected from client: %s: %s', addr, sock)
    zserv = app_manager.lookup_service_brick(ZServer.__name__)
    with contextlib.closing(ZClient(zserv, sock, addr)) as zclient:
        try:
            zclient.start()
        except Exception as e:
            LOG.error('Error in client%s: %s', addr, e)
            raise e


def detect_address_family(host):
    if netaddr.valid_ipv4(host):
        return socket.AF_INET
    elif netaddr.valid_ipv6(host):
        return socket.AF_INET6
    elif os.path.isdir(os.path.dirname(host)):
        return socket.AF_UNIX
    else:
        return None


class ZServer(RyuApp):
    """
    The base class for Zebra server application.
    """
    _EVENTS = event.ZEBRA_EVENTS + [
        zserver_event.EventZClientConnected,
        zserver_event.EventZClientDisconnected,
    ]

    def __init__(self, *args, **kwargs):
        super(ZServer, self).__init__(*args, **kwargs)
        self.zserv = None
        self.zserv_addr = (CONF.server_host, CONF.server_port)
        self.zapi_connection_family = detect_address_family(CONF.server_host)

        # Initial Router ID for Zebra server
        self.router_id = CONF.router_id

    def start(self):
        super(ZServer, self).start()

        if self.zapi_connection_family == socket.AF_UNIX:
            unix_sock_dir = os.path.dirname(CONF.server_host)
            # Makes sure the unix socket does not already exist
            if os.path.exists(CONF.server_host):
                os.remove(CONF.server_host)
            if not os.path.isdir(unix_sock_dir):
                os.mkdir(unix_sock_dir)
                os.chmod(unix_sock_dir, 0o777)

        try:
            self.zserv = hub.StreamServer(
                self.zserv_addr, zclient_connection_factory)
        except OSError as e:
            self.logger.error(
                'Cannot start Zebra server%s: %s', self.zserv_addr, e)
            raise e

        if self.zapi_connection_family == socket.AF_UNIX:
            os.chmod(CONF.server_host, 0o777)

        self._add_lo_interface()

        return hub.spawn(self.zserv.serve_forever)

    def _add_lo_interface(self):
        intf = db.interface.ip_link_add(SESSION, 'lo')
        if intf:
            self.logger.debug('Added interface "%s": %s', intf.ifname, intf)

        route = db.route.ip_route_add(
            SESSION,
            destination='127.0.0.0/8',
            device='lo',
            source='127.0.0.1/8',
            route_type=zebra.ZEBRA_ROUTE_CONNECT)
        if route:
            self.logger.debug(
                'Added route to "%s": %s', route.destination, route)

    @set_ev_cls(event.EventZebraHello)
    def _hello_handler(self, ev):
        if ev.body is None:
            self.logger.debug('Client %s says hello.', ev.zclient)
            return

        # Set distributed route_type to ZClient
        ev.zclient.route_type = ev.body.route_type
        self.logger.debug(
            'Client %s says hello and bids fair to announce only %s routes',
            ev.zclient, ev.body.route_type)

    @set_ev_cls(event.EventZebraRouterIDAdd)
    def _router_id_add_handler(self, ev):
        self.logger.debug(
            'Client %s requests router_id, server will response: router_id=%s',
            ev.zclient, self.router_id)

        # Send ZEBRA_ROUTER_ID_UPDATE for response
        msg = zebra.ZebraMessage(
            body=zebra.ZebraRouterIDUpdate(
                family=socket.AF_INET,
                prefix='%s/32' % self.router_id))
        ev.zclient.send_msg(msg)

    @set_ev_cls(event.EventZebraInterfaceAdd)
    def _interface_add_handler(self, ev):
        self.logger.debug('Client %s requested all interfaces', ev.zclient)

        interfaces = db.interface.ip_address_show_all(SESSION)
        self.logger.debug('Server will response interfaces: %s', interfaces)
        for intf in interfaces:
            msg = zebra.ZebraMessage(
                body=zebra.ZebraInterfaceAdd(
                    ifname=intf.ifname,
                    ifindex=intf.ifindex,
                    status=intf.status,
                    if_flags=intf.flags,
                    metric=intf.metric,
                    ifmtu=intf.ifmtu,
                    ifmtu6=intf.ifmtu6,
                    bandwidth=intf.bandwidth,
                    ll_type=intf.ll_type,
                    hw_addr=intf.hw_addr))
            ev.zclient.send_msg(msg)

            routes = db.route.ip_route_show_all(
                SESSION, ifindex=intf.ifindex, is_selected=True)
            self.logger.debug('Server will response routes: %s', routes)
            for route in routes:
                dest, _ = route.destination.split('/')
                msg = zebra.ZebraMessage(
                    body=zebra.ZebraInterfaceAddressAdd(
                        ifindex=intf.ifindex,
                        ifc_flags=0,
                        family=None,
                        prefix=route.source,
                        dest=dest))
                ev.zclient.send_msg(msg)

    @set_ev_cls([event.EventZebraIPv4RouteAdd,
                 event.EventZebraIPv6RouteAdd])
    def _ip_route_add_handler(self, ev):
        self.logger.debug(
            'Client %s advertised IP route: %s', ev.zclient, ev.body)

        for nexthop in ev.body.nexthops:
            route = db.route.ip_route_add(
                SESSION,
                destination=ev.body.prefix,
                gateway=nexthop.addr,
                ifindex=nexthop.ifindex or 0,
                route_type=ev.body.route_type)
            if route:
                self.logger.debug(
                    'Added route to "%s": %s', route.destination, route)

    @set_ev_cls([event.EventZebraIPv4RouteDelete,
                 event.EventZebraIPv6RouteDelete])
    def _ip_route_delete_handler(self, ev):
        self.logger.debug(
            'Client %s withdrew IP route: %s', ev.zclient, ev.body)

        for nexthop in ev.body.nexthops:
            routes = db.route.ip_route_delete(
                SESSION,
                destination=ev.body.prefix,
                gateway=nexthop.addr,
                route_type=ev.body.route_type)
            if routes:
                self.logger.debug(
                    'Deleted routes to "%s": %s', ev.body.prefix, routes)
