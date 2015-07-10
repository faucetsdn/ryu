"""
This file define the super in OXP communication.
Author:www.muzixing.com

The main component of OXP role.
    - Handle connection with Domain Controller as a server socket.
    - Gerenrate and route event to appropriate entitlies like ryu applications.

"""

import contextlib
from ryu import cfg
import logging
import ssl
import random

from ryu.lib import hub
from ryu.lib.hub import StreamServer
import eventlet

from ryu.controller import handler
from ryu.openexchange import oxproto
from ryu.openexchange import oxproto_parser
from ryu.openexchange import oxproto_common
from ryu.openexchange import oxproto_protocol
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxp_event

from socket import IPPROTO_TCP, TCP_NODELAY

import ryu.base.app_manager
#from eventlet.green import socket


LOG = logging.getLogger('ryu.openexchange.oxp_super')

CONF = cfg.CONF

#TODO: judge of controller role.


class OXP_Controller(object):
    def __init__(self):
        super(OXP_Controller, self).__init__()
        role = CONF.oxp_role
        if role == 'super':
            Controller = Super_Controller()
        else:
            Controller = Domain_Controller()


class Super_Controller(object):
    def __init__(self):
        super(Super_Controller, self).__init__()
        # role
        role = CONF.oxp_role

    # entry point
    def __call__(self):
        # LOG.info('call')
        self.server_loop()

    def server_loop(self):
        if CONF.oxp_ctl_privkey is not None and CONF.oxp_ctl_cert is not None:
            if CONF.oxp_ca_certs is not None:
                server = StreamServer((CONF.oxp_listen_host,
                                       CONF.oxp_ssl_listen_port),
                                      domain_connection_factory,
                                      # change into the real handler
                                      keyfile=CONF.oxp_ctl_privkey,
                                      certfile=CONF.oxp_ctl_cert,
                                      cert_reqs=ssl.CERT_REQUIRED,
                                      ca_certs=CONF.oxp_ca_certs,
                                      ssl_version=ssl.PROTOCOL_TLSv1)
            else:
                server = StreamServer((CONF.oxp_listen_host,
                                       CONF.oxp_ssl_listen_port),
                                      domain_connection_factory,  # to change
                                      keyfile=CONF.oxp_ctl_privkey,
                                      certfile=CONF.oxp_ctl_cert,
                                      ssl_version=ssl.PROTOCOL_TLSv1)
            LOG.info('oxp super controller set up at:%s:%s ' % (
                CONF.oxp_listen_host, CONF.oxp_ssl_listen_port))
        else:
            server = StreamServer((CONF.oxp_listen_host,
                                   CONF.oxp_tcp_listen_port),
                                  domain_connection_factory)  # to change
            LOG.info('oxp super controller set up at:%s:%s ' % (
                CONF.oxp_listen_host, CONF.oxp_tcp_listen_port))

        # LOG.debug('loop')
        server.serve_forever()


def _deactivate(method):
    def deactivate(self):
        try:
            method(self)
        finally:
            self.is_active = False
    return deactivate


class Domain_network(oxproto_protocol.ProtocolDesc):
    # TODO: descirpt a domain controller which used by super controller.
    def __init__(self, socket, address):
        super(Domain_network, self).__init__()
        self.oxp_proto = 1
        self.oxp_parser = 1
        self.socket = socket
        self.socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self.address = address
        self.is_active = True

        # The limit is arbitrary. We need to limit queue size to
        # prevent it from eating memory up
        self.send_q = hub.Queue(16)

        self.xid = random.randint(0, self.oxproto.MAX_XID)
        self.id = None  # controller_id is unknown yet
        self.ports = None
        # TODO: What is this ?
        # self.flow_format = oxproto_v1_0.NXFF_OPENFLOW10  # ?

        # TODO we still need event mechanism.
        self.oxp_brick = ryu.base.app_manager.lookup_service_brick('oxp_event')
        self.set_state(handler.HANDSHAKE_DISPATCHER)

    def close(self):
        self.set_state(handler.DEAD_DISPATCHER)

    def set_state(self, state):  # Use to create event.
        self.state = state
        ev = oxp_event.EventOXPStateChange(self)  # OXP event
        ev.state = state
        self.oxp_brick.send_event_to_observers(ev, state)

    # Low level socket handling layer
    @_deactivate
    def _recv_loop(self):
        buf = bytearray()
        required_len = oxproto_common.OXP_HEADER_SIZE

        count = 0
        while self.is_active:
            ret = self.socket.recv(required_len)
            if len(ret) == 0:
                self.is_active = False
                break
            buf += ret
            LOG.info("msg: %s " % buf)

            while len(buf) >= required_len:
                # Parser.
                (version, msg_type, msg_len, xid) = oxproto_parser.header(buf)
                required_len = msg_len
                if len(buf) < required_len:
                    break
                print "msg:", msg
                '''
                #Wait for parsing
                msg = ofproto_parser.msg(self,
                                         version, msg_type, msg_len, xid, buf)
                # LOG.debug('queue msg %s cls %s', msg, msg.__class__)
                if msg:
                    ev = ofp_event.ofp_msg_to_ev(msg)
                    self.ofp_brick.send_event_to_observers(ev, self.state)

                    dispatchers = lambda x: x.callers[ev.__class__].dispatchers
                    handlers = [handler for handler in
                                self.ofp_brick.get_handlers(ev) if
                                self.state in dispatchers(handler)]
                    for handler in handlers:
                        handler(ev)

                buf = buf[required_len:]
                required_len = ofproto_common.OFP_HEADER_SIZE

                # We need to schedule other greenlets. Otherwise, ryu
                # can't accept new switches or handle the existing
                # switches. The limit is arbitrary. We need the better
                # approach in the future.
                '''
                count += 1
                if count > 2048:
                    count = 0
                    hub.sleep(0)

    def send(self, buf):
        if self.send_q:
            self.send_q.put(buf)

    def send_msg(self, msg):
        #assert isinstance(msg, self.ofproto_parser.MsgBase)
        if msg.xid is None:
            self.set_xid(msg)
        msg.serialize()
        # LOG.debug('send_msg %s', msg)
        self.send(msg.buf)

    def set_xid(self, msg):
        self.xid += 1
        self.xid &= self.ofproto.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    @_deactivate
    def _send_loop(self):
        try:
            while self.is_active:
                buf = self.send_q.get()
                # Todo
                buf = "_Server"
                self.socket.sendall(buf)
                LOG.info("sendall")
        finally:
            q = self.send_q
            # first, clear self.send_q to prevent new references.
            self.send_q = None
            # there might be threads currently blocking in send_q.put().
            # unblock them by draining the queue.
            try:
                while q.get(block=False):
                    pass
            except hub.QueueEmpty:
                pass

    def serve(self):
        # TODO: entry point
        send_thr = hub.spawn(self._send_loop)

        # send hello message immediately
        #hello = self.ofproto_parser.OFPHello(self)
        #self.send_msg(hello)
        buf = "Server"
        self.socket.sendall(buf)

        try:
            self._recv_loop()
        finally:
            hub.kill(send_thr)
            hub.joinall([send_thr])


def domain_connection_factory(socket, address):
    # TODO: receive domain connections
    LOG.info('connected domain:%s address:%s', socket, address)
    with contextlib.closing(Domain_network(socket, address)) as domain:
        try:
            domain.serve()
        except:
            # Something went wrong.
            # Especially malicious switch can send malformed packet,
            # the parser raise exception.
            # Can we do anything more graceful?

            # TODO: class domain and did_to_str
            if domain.id is None:
                domain_str = "%s" % domain.id
            else:
                domain_str = did_to_str(domain.id)
            LOG.error("Error in the domain %s from %s", domain_str, address)
            raise
