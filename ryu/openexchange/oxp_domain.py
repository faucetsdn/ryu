"""
This file define the domain in OXP communication.
Author:www.muzixing.com

The main component of OXP role.
    - Handle connection with Super Controller as a client socket
    - Gerenrate and route event to appropriate entitlies like ryu applications.

"""


from ryu import cfg
import logging
import ssl

from ryu.lib import hub
from ryu.lib.hub import StreamServer
import eventlet
from eventlet.green import socket

from ryu.openexchange import oxproto
from ryu.openexchange import oxproto_common
from ryu.openexchange import oxproto_parser
from ryu.openexchange import oxproto_protocol
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxp_event


LOG = logging.getLogger('ryu.lib.openexchange.oxp_domain')

CONF = cfg.CONF


def _deactivate(method):
    def deactivate(self):
        try:
            method(self)
        finally:
            self.is_active = False
    return deactivate


class Domain_Controller(object):
    def __init__(self):
        super(Domain_Controller, self).__init__()
        # role
        self.role = CONF.oxp_role
        self.server = CONF.oxp_server_ip
        self.port = CONF.oxp_server_port
        self.socket = None
        self.is_active = True

    # entry point
    def __call__(self):
        self._connect()

    def _connect(self, ):
        # TODO: Set up a socket to connet super.
        self.socket = eventlet.connect((self.server, self.port))

        LOG.info("connect to: %s : %s" % (self.server, self.port))
        self.socket.send("client")  # oxp_hello
        self._recv_loop()

    def _rw_loop(self):
      # TODO client socket r/w loop.
        pass

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
                buf = "I am buf"
                self.socket.sendall(buf)
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

        try:
            self._recv_loop()
        finally:
            hub.kill(send_thr)
            hub.joinall([send_thr])


class Super_network(object):
    # TODO: descript a super controller which used by domain controller.
    pass
