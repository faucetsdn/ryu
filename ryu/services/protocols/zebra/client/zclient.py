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
Zebra Client corresponding to 'zclient' structure.
"""

import os
import socket
import struct

import netaddr

from ryu import cfg
from ryu.base.app_manager import RyuApp
from ryu.lib import hub
from ryu.lib import ip
from ryu.lib.packet import zebra
from ryu.lib.packet import safi as packet_safi
from ryu.services.protocols.zebra import event
from ryu.services.protocols.zebra.client import event as zclient_event


CONF = cfg.CONF['zapi']
GLOBAL_CONF = cfg.CONF


def create_connection(address):
    """
    Wrapper for socket.create_connection() function.

    If *address* (a 2-tuple ``(host, port)``) contains a valid IPv4/v6
    address, passes *address* to socket.create_connection().
    If *host* is valid path to Unix Domain socket, tries to connect to
    the server listening on the given socket.

    :param address: IP address or path to Unix Domain socket.
    :return: Socket instance.
    """
    host, _port = address

    if (netaddr.valid_ipv4(host)
            or netaddr.valid_ipv6(host)):
        return socket.create_connection(address)
    elif os.path.exists(host):
        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(host)
        except socket.error as e:
            if sock is not None:
                sock.close()
            raise e
        return sock
    else:
        raise ValueError('Invalid IP address or Unix Socket: %s' % host)


def get_zebra_route_type_by_name(route_type='BGP'):
    """
    Returns the constant value for Zebra route type named "ZEBRA_ROUTE_*"
    from its name.

    See "ZEBRA_ROUTE_*" constants in "ryu.lib.packet.zebra" module.

    :param route_type: Route type name (e.g., Kernel, BGP).
    :return: Constant value for Zebra route type.
    """
    return getattr(zebra, "ZEBRA_ROUTE_%s" % route_type.upper())


class ZServer(object):
    """
    Zebra server class.
    """

    def __init__(self, client):
        self.client = client
        self.logger = client.logger
        self.is_active = False
        self.sock = None  # Client socket connecting to Zebra server
        self.threads = []

    def start(self):
        self.is_active = True
        try:
            self.sock = create_connection(self.client.zserv_addr)
        except socket.error as e:
            self.logger.exception(
                'Cannot connect to Zebra server%s: %s',
                self.client.zserv_addr, e)
            self.stop()
            return None

        self.sock.settimeout(GLOBAL_CONF.socket_timeout)

        self.threads.append(hub.spawn(self._send_loop))
        self.threads.append(hub.spawn(self._recv_loop))

        # Send the following messages at starting connection.
        # - ZEBRA_HELLO to register route_type
        # - ZEBRA_ROUTER_ID_ADD to get router_id
        # - ZEBRA_INTERFACE_ADD to get info for interfaces
        self.client.send_msg(
            zebra.ZebraMessage(
                version=self.client.zserv_ver,
                body=zebra.ZebraHello(self.client.route_type)))
        self.client.send_msg(
            zebra.ZebraMessage(
                version=self.client.zserv_ver,
                command=zebra.ZEBRA_ROUTER_ID_ADD))
        self.client.send_msg(
            zebra.ZebraMessage(
                version=self.client.zserv_ver,
                command=zebra.ZEBRA_INTERFACE_ADD))

        self.client.send_event_to_observers(
            zclient_event.EventZServConnected(self))

        hub.joinall(self.threads)

        self.client.send_event_to_observers(
            zclient_event.EventZServDisconnected(self))

    def stop(self):
        self.is_active = False

    def _send_loop(self):
        try:
            while self.is_active:
                buf = self.client.send_q.get()
                self.sock.sendall(buf)
        except socket.error as e:
            self.logger.exception(
                'Error while sending message to Zebra server%s: %s',
                self.client.zserv_addr, e)

        self.stop()

    def _recv_loop(self):
        buf = b''
        min_len = recv_len = zebra.ZebraMessage.get_header_size(
            self.client.zserv_ver)
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

                    ev = event.message_to_event(self.client, msg)
                    if ev:
                        self.client.send_event_to_observers(ev)

        except socket.error as e:
            self.logger.exception(
                'Error while sending message to Zebra server%s: %s',
                self.client.zserv_addr, e)

        self.stop()


class ZClient(RyuApp):
    """
    The base class for Zebra client application.
    """
    _EVENTS = event.ZEBRA_EVENTS + [
        zclient_event.EventZServConnected,
        zclient_event.EventZServDisconnected,
    ]

    def __init__(self, *args, **kwargs):
        super(ZClient, self).__init__(*args, **kwargs)
        self.zserv = None  # ZServer instance
        self.zserv_addr = (CONF.server_host, CONF.server_port)
        self.zserv_ver = CONF.server_version
        self.send_q = hub.Queue(16)
        self.route_type = get_zebra_route_type_by_name(
            CONF.client_route_type)

    def start(self):
        super(ZClient, self).start()

        return hub.spawn(self._service_loop)

    def _service_loop(self):
        while self.is_active:
            self.zserv = ZServer(self)
            self.zserv.start()

            hub.sleep(CONF.retry_interval)

        self.close()

    def close(self):
        self.is_active = False
        self._send_event(self._event_stop, None)
        self.zserv.stop()

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

    def _send_ip_route_impl(
            self, prefix, nexthops=None,
            safi=packet_safi.UNICAST, flags=zebra.ZEBRA_FLAG_INTERNAL,
            distance=None, metric=None, mtu=None, tag=None,
            is_withdraw=False):
        if ip.valid_ipv4(prefix):
            if is_withdraw:
                msg_cls = zebra.ZebraIPv4RouteDelete
            else:
                msg_cls = zebra.ZebraIPv4RouteAdd
        elif ip.valid_ipv6(prefix):
            if is_withdraw:
                msg_cls = zebra.ZebraIPv6RouteDelete
            else:
                msg_cls = zebra.ZebraIPv6RouteAdd
        else:
            raise ValueError('Invalid prefix: %s' % prefix)

        nexthop_list = []
        for nexthop in nexthops:
            if netaddr.valid_ipv4(nexthop):
                nexthop_list.append(zebra.NextHopIPv4(addr=nexthop))
            elif netaddr.valid_ipv6(nexthop):
                nexthop_list.append(zebra.NextHopIPv6(addr=nexthop))
            else:
                raise ValueError('Invalid nexthop: %s' % nexthop)

        msg = zebra.ZebraMessage(
            version=self.zserv_ver,
            body=msg_cls(
                route_type=self.route_type,
                flags=flags,
                message=0,
                safi=safi,
                prefix=prefix,
                nexthops=nexthop_list,
                distance=distance,
                metric=metric,
                mtu=mtu,
                tag=tag))
        self.send_msg(msg)

        return msg

    def send_ip_route_add(
            self, prefix, nexthops=None,
            safi=packet_safi.UNICAST, flags=zebra.ZEBRA_FLAG_INTERNAL,
            distance=None, metric=None, mtu=None, tag=None):
        """
        Sends ZEBRA_IPV4/v6_ROUTE_ADD message to Zebra daemon.

        :param prefix: IPv4/v6 Prefix to advertise.
        :param nexthops: List of nexthop addresses.
        :param safi: SAFI to advertise.
        :param flags: Message flags to advertise. See "ZEBRA_FLAG_*".
        :param distance: (Optional) Distance to advertise.
        :param metric: (Optional) Metric to advertise.
        :param mtu: (Optional) MTU size to advertise.
        :param tag: (Optional) TAG information to advertise.
        :return: Zebra message instance to be sent. None if failed.
        """
        try:
            return self._send_ip_route_impl(
                prefix=prefix, nexthops=nexthops, safi=safi, flags=flags,
                distance=distance, metric=metric, mtu=mtu, tag=tag,
                is_withdraw=False)
        except ValueError as e:
            self.logger.exception(
                'Cannot send IP route add message: %s', e)
            return None

    def send_ip_route_delete(
            self, prefix, nexthops=None,
            safi=packet_safi.UNICAST, flags=zebra.ZEBRA_FLAG_INTERNAL,
            distance=None, metric=None, mtu=None, tag=None):
        """
        Sends ZEBRA_IPV4/v6_ROUTE_DELETE message to Zebra daemon.

        :param prefix: IPv4/v6 Prefix to advertise.
        :param nexthops: List of nexthop addresses.
        :param safi: SAFI to advertise.
        :param flags: Message flags to advertise. See "ZEBRA_FLAG_*".
        :param distance: (Optional) Distance to advertise.
        :param metric: (Optional) Metric to advertise.
        :param mtu: (Optional) MTU size to advertise.
        :param tag: (Optional) TAG information to advertise.
        :return: Zebra message instance to be sent. None if failed.
        """
        try:
            return self._send_ip_route_impl(
                prefix=prefix, nexthops=nexthops, safi=safi, flags=flags,
                distance=distance, metric=metric, mtu=mtu, tag=tag,
                is_withdraw=True)
        except ValueError as e:
            self.logger.exception(
                'Cannot send IP route delete message: %s', e)
            return None
