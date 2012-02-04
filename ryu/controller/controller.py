# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import gflags
import logging
import gevent
import random
import weakref
from gevent.server import StreamServer
from gevent.queue import Queue

from ryu.ofproto import ofproto
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_0_parser

from ryu.controller import dispatcher
from ryu.controller import handler
from ryu.controller import ofp_event

LOG = logging.getLogger('ryu.controller.controller')

FLAGS = gflags.FLAGS
gflags.DEFINE_string('ofp_listen_host', '', 'openflow listen host')
gflags.DEFINE_integer('ofp_tcp_listen_port', ofproto.OFP_TCP_PORT,
                      'openflow tcp listen port')


class OpenFlowController(object):
    def __init__(self):
        super(OpenFlowController, self).__init__()

    # entry point
    def __call__(self):
        #LOG.debug('call')
        self.server_loop()

    def server_loop(self):
        server = StreamServer((FLAGS.ofp_listen_host,
                               FLAGS.ofp_tcp_listen_port),
                              datapath_connection_factory)
        #LOG.debug('loop')
        server.serve_forever()


def _deactivate(method):
    def deactivate(self):
        try:
            method(self)
        finally:
            self.is_active = False
    return deactivate


class Datapath(object):
    supported_ofp_version = {
        ofproto_v1_0.OFP_VERSION: (ofproto_v1_0,
                                   ofproto_v1_0_parser),
        }

    def __init__(self, socket, address):
        super(Datapath, self).__init__()

        self.socket = socket
        self.address = address
        self.is_active = True

        # XIX limit queue size somehow to prevent it from eating memory up
        self.recv_q = Queue()
        self.send_q = Queue()

        # weakref: qv_q.aux refers to aux = self
        # self.ev_q.aux == weakref.ref(self)
        self.ev_q = dispatcher.EventQueue(handler.QUEUE_NAME_OFP_MSG,
                                          handler.HANDSHAKE_DISPATCHER,
                                          weakref.ref(self))

        self.set_version(max(self.supported_ofp_version))
        self.xid = random.randint(0, self.ofproto.MAX_XID)
        self.id = None  # datapath_id is unknown yet
        self.ports = None

    def set_version(self, version):
        assert version in self.supported_ofp_version
        self.ofproto, self.ofproto_parser = self.supported_ofp_version[version]

    # Low level socket handling layer
    @_deactivate
    def _recv_loop(self):
        buf = bytearray()
        required_len = ofproto.OFP_HEADER_SIZE

        while self.is_active:
            ret = self.socket.recv(ofproto.OFP_MSG_SIZE_MAX)
            if len(ret) == 0:
                self.is_active = False
                break
            buf += ret
            while len(buf) >= required_len:
                (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)
                required_len = msg_len
                if len(buf) < required_len:
                    break

                msg = ofproto_parser.msg(self,
                                         version, msg_type, msg_len, xid, buf)
                #LOG.debug('queue msg %s cls %s', msg, msg.__class__)
                self.recv_q.put(msg)

                buf = buf[required_len:]
                required_len = ofproto.OFP_HEADER_SIZE

    @_deactivate
    def _send_loop(self):
        while self.is_active:
            buf = self.send_q.get()
            self.socket.sendall(buf)

    def send(self, buf):
        self.send_q.put(buf)

    def set_xid(self, msg):
        self.xid += 1
        self.xid &= self.ofproto.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    def send_msg(self, msg):
        assert isinstance(msg, self.ofproto_parser.MsgBase)
        if msg.xid is None:
            self.set_xid(msg)
        msg.serialize()
        # LOG.debug('send_msg %s', msg)
        self.send(msg.buf)

    def serve(self):
        send_thr = gevent.spawn(self._send_loop)
        ev_thr = gevent.spawn(self._event_loop)

        # send hello message immediately
        hello = self.ofproto_parser.OFPHello(self)
        self.send_msg(hello)

        self._recv_loop()
        gevent.kill(ev_thr)
        gevent.kill(send_thr)
        gevent.joinall([ev_thr, send_thr])

    @_deactivate
    def _event_loop(self):
        while self.is_active:
            msg = self.recv_q.get()
            #LOG.debug('_event_loop ev %s cls %s', msg, msg.__class__)
            self.ev_q.queue(ofp_event.ofp_msg_to_ev(msg))

    def send_ev(self, ev):
        #LOG.debug('send_ev %s', ev)
        self.ev_q.queue(ev)

    #
    # Utility methods for convenience
    #
    def send_packet_out(self, buffer_id=0xffffffff, in_port=None,
                        actions=None, data=None):
        if in_port is None:
            in_port = self.ofproto.OFPP_NONE
        packet_out = self.ofproto_parser.OFPPacketOut(
            self, buffer_id, in_port, actions, data)
        self.send_msg(packet_out)

    def send_flow_mod(self, match, cookie, command, idle_timeout, hard_timeout,
                      priority, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None):
        if out_port is None:
            out_port = self.ofproto.OFPP_NONE
        flow_mod = self.ofproto_parser.OFPFlowMod(
            self, match, cookie, command, idle_timeout, hard_timeout,
            priority, buffer_id, out_port, flags, actions)
        self.send_msg(flow_mod)

    def send_delete_all_flows(self):
        match = self.ofproto_parser.OFPMatch(self.ofproto.OFPFW_ALL,
                                             0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0)
        self.send_flow_mod(
            match=match, cookie=0, command=self.ofproto.OFPFC_DELETE,
            idle_timeout=0, hard_timeout=0, priority=0, buffer_id=0,
            out_port=self.ofproto.OFPP_NONE, flags=0, actions=None)

    def send_barrier(self):
        barrier_request = self.ofproto_parser.OFPBarrierRequest(self)
        self.send_msg(barrier_request)


def datapath_connection_factory(socket, address):
    LOG.debug('connected socket:%s address:%s', socket, address)

    datapath = Datapath(socket, address)
    try:
        datapath.serve()
    finally:
        # tell this datapath is dead
        datapath.ev_q.set_dispatcher(handler.DEAD_DISPATCHER)
