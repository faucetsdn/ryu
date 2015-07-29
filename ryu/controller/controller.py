# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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
The main component of OpenFlow controller.

- Handle connections from switches
- Generate and route events to appropriate entities like Ryu applications

"""

import contextlib
from ryu import cfg
import logging
from ryu.lib import hub
from ryu.lib.hub import StreamServer
import traceback
import random
import ssl
from socket import IPPROTO_TCP, TCP_NODELAY
import warnings

import ryu.base.app_manager

from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import nx_match

from ryu.controller import handler
from ryu.controller import ofp_event

from ryu.lib.dpid import dpid_to_str

LOG = logging.getLogger('ryu.controller.controller')

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt('ofp-listen-host', default='', help='openflow listen host'),
    cfg.IntOpt('ofp-tcp-listen-port', default=ofproto_common.OFP_TCP_PORT,
               help='openflow tcp listen port'),
    cfg.IntOpt('ofp-ssl-listen-port', default=ofproto_common.OFP_SSL_PORT,
               help='openflow ssl listen port'),
    cfg.StrOpt('ctl-privkey', default=None, help='controller private key'),
    cfg.StrOpt('ctl-cert', default=None, help='controller certificate'),
    cfg.StrOpt('ca-certs', default=None, help='CA certificates')
])


class OpenFlowController(object):
    def __init__(self):
        super(OpenFlowController, self).__init__()

    # entry point
    def __call__(self):
        # LOG.debug('call')
        self.server_loop()

    def server_loop(self):
        if CONF.ctl_privkey is not None and CONF.ctl_cert is not None:
            if CONF.ca_certs is not None:
                server = StreamServer((CONF.ofp_listen_host,
                                       CONF.ofp_ssl_listen_port),
                                      datapath_connection_factory,
                                      keyfile=CONF.ctl_privkey,
                                      certfile=CONF.ctl_cert,
                                      cert_reqs=ssl.CERT_REQUIRED,
                                      ca_certs=CONF.ca_certs,
                                      ssl_version=ssl.PROTOCOL_TLSv1)
            else:
                server = StreamServer((CONF.ofp_listen_host,
                                       CONF.ofp_ssl_listen_port),
                                      datapath_connection_factory,
                                      keyfile=CONF.ctl_privkey,
                                      certfile=CONF.ctl_cert,
                                      ssl_version=ssl.PROTOCOL_TLSv1)
        else:
            server = StreamServer((CONF.ofp_listen_host,
                                   CONF.ofp_tcp_listen_port),
                                  datapath_connection_factory)

        # LOG.debug('loop')
        server.serve_forever()


def _deactivate(method):
    def deactivate(self):
        try:
            method(self)
        finally:
            self.is_active = False
    return deactivate


class Datapath(ofproto_protocol.ProtocolDesc):
    def __init__(self, socket, address):
        super(Datapath, self).__init__()

        self.socket = socket
        self.socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self.address = address
        self.is_active = True

        # The limit is arbitrary. We need to limit queue size to
        # prevent it from eating memory up
        self.send_q = hub.Queue(16)

        self.xid = random.randint(0, self.ofproto.MAX_XID)
        self.id = None  # datapath_id is unknown yet
        self._ports = None
        self.flow_format = ofproto_v1_0.NXFF_OPENFLOW10
        self.ofp_brick = ryu.base.app_manager.lookup_service_brick('ofp_event')
        self.set_state(handler.HANDSHAKE_DISPATCHER)

    def _get_ports(self):
        if (self.ofproto_parser is not None and
                self.ofproto_parser.ofproto.OFP_VERSION >= 0x04):
            message = (
                'Datapath#ports is kept for compatibility with the previous '
                'openflow versions (< 1.3). '
                'This not be updated by EventOFPPortStatus message. '
                'If you want to be updated, you can use '
                '\'ryu.controller.dpset\' or \'ryu.topology.switches\'.'
            )
            warnings.warn(message, stacklevel=2)
        return self._ports

    def _set_ports(self, ports):
        self._ports = ports

    # To show warning when Datapath#ports is read
    ports = property(_get_ports, _set_ports)

    def close(self):
        self.set_state(handler.DEAD_DISPATCHER)

    def set_state(self, state):
        self.state = state
        ev = ofp_event.EventOFPStateChange(self)
        ev.state = state
        self.ofp_brick.send_event_to_observers(ev, state)

    # Low level socket handling layer
    @_deactivate
    def _recv_loop(self):
        buf = bytearray()
        required_len = ofproto_common.OFP_HEADER_SIZE

        count = 0
        while self.is_active:
            ret = self.socket.recv(required_len)
            if len(ret) == 0:
                self.is_active = False
                self.socket.close()
                break
            buf += ret
            while len(buf) >= required_len:
                (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)
                required_len = msg_len
                if len(buf) < required_len:
                    break

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
                count += 1
                if count > 2048:
                    count = 0
                    hub.sleep(0)

    @_deactivate
    def _send_loop(self):
        try:
            while self.is_active:
                buf = self.send_q.get()
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

    def send(self, buf):
        if self.send_q:
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
        send_thr = hub.spawn(self._send_loop)

        # send hello message immediately
        hello = self.ofproto_parser.OFPHello(self)
        self.send_msg(hello)

        try:
            self._recv_loop()
        finally:
            hub.kill(send_thr)
            hub.joinall([send_thr])

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

    def send_flow_mod(self, rule, cookie, command, idle_timeout, hard_timeout,
                      priority=None, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None):
        if priority is None:
            priority = self.ofproto.OFP_DEFAULT_PRIORITY
        if out_port is None:
            out_port = self.ofproto.OFPP_NONE
        flow_format = rule.flow_format()
        assert (flow_format == ofproto_v1_0.NXFF_OPENFLOW10 or
                flow_format == ofproto_v1_0.NXFF_NXM)
        if self.flow_format < flow_format:
            self.send_nxt_set_flow_format(flow_format)
        if flow_format == ofproto_v1_0.NXFF_OPENFLOW10:
            match_tuple = rule.match_tuple()
            match = self.ofproto_parser.OFPMatch(*match_tuple)
            flow_mod = self.ofproto_parser.OFPFlowMod(
                self, match, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, actions)
        else:
            flow_mod = self.ofproto_parser.NXTFlowMod(
                self, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, rule, actions)
        self.send_msg(flow_mod)

    def send_flow_del(self, rule, cookie, out_port=None):
        self.send_flow_mod(rule=rule, cookie=cookie,
                           command=self.ofproto.OFPFC_DELETE,
                           idle_timeout=0, hard_timeout=0, priority=0,
                           out_port=out_port)

    def send_delete_all_flows(self):
        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=self.ofproto.OFPFC_DELETE,
            idle_timeout=0, hard_timeout=0, priority=0, buffer_id=0,
            out_port=self.ofproto.OFPP_NONE, flags=0, actions=None)

    def send_barrier(self):
        barrier_request = self.ofproto_parser.OFPBarrierRequest(self)
        self.send_msg(barrier_request)

    def send_nxt_set_flow_format(self, flow_format):
        assert (flow_format == ofproto_v1_0.NXFF_OPENFLOW10 or
                flow_format == ofproto_v1_0.NXFF_NXM)
        if self.flow_format == flow_format:
            # Nothing to do
            return
        self.flow_format = flow_format
        set_format = self.ofproto_parser.NXTSetFlowFormat(self, flow_format)
        # FIXME: If NXT_SET_FLOW_FORMAT or NXFF_NXM is not supported by
        # the switch then an error message will be received. It may be
        # handled by setting self.flow_format to
        # ofproto_v1_0.NXFF_OPENFLOW10 but currently isn't.
        self.send_msg(set_format)
        self.send_barrier()

    def is_reserved_port(self, port_no):
        return port_no > self.ofproto.OFPP_MAX


def datapath_connection_factory(socket, address):
    LOG.debug('connected socket:%s address:%s', socket, address)
    with contextlib.closing(Datapath(socket, address)) as datapath:
        try:
            datapath.serve()
        except:
            # Something went wrong.
            # Especially malicious switch can send malformed packet,
            # the parser raise exception.
            # Can we do anything more graceful?
            if datapath.id is None:
                dpid_str = "%s" % datapath.id
            else:
                dpid_str = dpid_to_str(datapath.id)
            LOG.error("Error in the datapath %s from %s", dpid_str, address)
            raise
