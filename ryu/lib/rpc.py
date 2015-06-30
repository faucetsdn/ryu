#!/usr/bin/env python
#
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# msgpack-rpc
# http://wiki.msgpack.org/display/MSGPACK/RPC+specification

import msgpack
import six


class MessageType(object):
    REQUEST = 0
    RESPONSE = 1
    NOTIFY = 2


class MessageEncoder(object):
    """msgpack-rpc encoder/decoder.
    intended to be transport-agnostic.
    """
    def __init__(self):
        super(MessageEncoder, self).__init__()
        # note: on-wire msgpack has no notion of encoding.
        # the msgpack-python library implicitly converts unicode to
        # utf-8 encoded bytes by default.  we don't want to rely on
        # the behaviour though because it seems to be going to change.
        # cf. https://gist.github.com/methane/5022403
        self._packer = msgpack.Packer(encoding=None)
        self._unpacker = msgpack.Unpacker(encoding=None)
        self._next_msgid = 0

    def _create_msgid(self):
        this_id = self._next_msgid
        self._next_msgid = (self._next_msgid + 1) % 0xffffffff
        return this_id

    def create_request(self, method, params):
        assert isinstance(method, six.binary_type)
        assert isinstance(params, list)
        msgid = self._create_msgid()
        return (self._packer.pack([MessageType.REQUEST, msgid, method,
                                  params]), msgid)

    def create_response(self, msgid, error=None, result=None):
        assert isinstance(msgid, int)
        assert 0 <= msgid and msgid <= 0xffffffff
        assert error is None or result is None
        return self._packer.pack([MessageType.RESPONSE, msgid, error, result])

    def create_notification(self, method, params):
        assert isinstance(method, six.binary_type)
        assert isinstance(params, list)
        return self._packer.pack([MessageType.NOTIFY, method, params])

    def get_and_dispatch_messages(self, data, disp_table):
        """dissect messages from a raw stream data.
        disp_table[type] should be a callable for the corresponding
        MessageType.
        """
        self._unpacker.feed(data)
        for m in self._unpacker:
            self._dispatch_message(m, disp_table)

    def _dispatch_message(self, m, disp_table):
        # XXX validation
        type = m[0]
        try:
            f = disp_table[type]
        except KeyError:
            # ignore messages with unknown type
            return
        f(m[1:])


from collections import deque
import select


class EndPoint(object):
    """An endpoint
    *sock* is a socket-like.  it can be either blocking or non-blocking.
    """
    def __init__(self, sock, encoder=None, disp_table=None):
        if encoder is None:
            encoder = MessageEncoder()
        self._encoder = encoder
        self._sock = sock
        if disp_table is None:
            self._table = {
                MessageType.REQUEST: self._enqueue_incoming_request,
                MessageType.RESPONSE: self._enqueue_incoming_response,
                MessageType.NOTIFY: self._enqueue_incoming_notification
            }
        else:
            self._table = disp_table
        self._send_buffer = bytearray()
        # msgids for which we sent a request but have not received a response
        self._pending_requests = set()
        # queues for incoming messages
        self._requests = deque()
        self._notifications = deque()
        self._responses = {}
        self._incoming = 0  # number of incoming messages in our queues
        self._closed_by_peer = False

    def selectable(self):
        rlist = [self._sock]
        wlist = []
        if self._send_buffer:
            wlist.append(self._sock)
        return rlist, wlist

    def process_outgoing(self):
        try:
            sent_bytes = self._sock.send(self._send_buffer)
        except IOError:
            sent_bytes = 0
        del self._send_buffer[:sent_bytes]

    def process_incoming(self):
        self.receive_messages(all=True)

    def process(self):
        self.process_outgoing()
        self.process_incoming()

    def block(self):
        rlist, wlist = self.selectable()
        select.select(rlist, wlist, rlist + wlist)

    def serve(self):
        while not self._closed_by_peer:
            self.block()
            self.process()

    def _send_message(self, msg):
        self._send_buffer += msg
        self.process_outgoing()

    def send_request(self, method, params):
        """Send a request
        """
        msg, msgid = self._encoder.create_request(method, params)
        self._send_message(msg)
        self._pending_requests.add(msgid)
        return msgid

    def send_response(self, msgid, error=None, result=None):
        """Send a response
        """
        msg = self._encoder.create_response(msgid, error, result)
        self._send_message(msg)

    def send_notification(self, method, params):
        """Send a notification
        """
        msg = self._encoder.create_notification(method, params)
        self._send_message(msg)

    def receive_messages(self, all=False):
        """Try to receive some messages.
        Received messages are put on the internal queues.
        They can be retrieved using get_xxx() methods.
        Returns True if there's something queued for get_xxx() methods.
        """
        while all or self._incoming == 0:
            try:
                packet = self._sock.recv(4096)  # XXX the size is arbitrary
            except IOError:
                packet = None
            if not packet:
                if packet is not None:
                    # socket closed by peer
                    self._closed_by_peer = True
                break
            self._encoder.get_and_dispatch_messages(packet, self._table)
        return self._incoming > 0

    def _enqueue_incoming_request(self, m):
        self._requests.append(m)
        self._incoming += 1

    def _enqueue_incoming_response(self, m):
        msgid, error, result = m
        try:
            self._pending_requests.remove(msgid)
        except KeyError:
            # bogus msgid
            # XXXwarn
            return
        assert msgid not in self._responses
        self._responses[msgid] = (error, result)
        self._incoming += 1

    def _enqueue_incoming_notification(self, m):
        self._notifications.append(m)
        self._incoming += 1

    def _get_message(self, q):
        try:
            m = q.popleft()
            assert self._incoming > 0
            self._incoming -= 1
            return m
        except IndexError:
            return None

    def get_request(self):
        return self._get_message(self._requests)

    def get_response(self, msgid):
        try:
            m = self._responses.pop(msgid)
            assert self._incoming > 0
            self._incoming -= 1
        except KeyError:
            return None
        error, result = m
        return (result, error)

    def get_notification(self):
        return self._get_message(self._notifications)


class RPCError(Exception):
    """an error from server
    """
    def __init__(self, error):
        self._error = error

    def get_value(self):
        return self._error

    def __str__(self):
        return str(self._error)


class Client(object):
    """a convenient class for a pure rpc client
    *sock* is a socket-like.  it should be blocking.
    """
    def __init__(self, sock, encoder=None, notification_callback=None):
        self._endpoint = EndPoint(sock, encoder)
        if notification_callback is None:
            # ignore notifications by default
            self._notification_callback = lambda n: None
        else:
            self._notification_callback = notification_callback

    def _process_input_notification(self):
        n = self._endpoint.get_notification()
        if n:
            self._notification_callback(n)

    def _process_input_request(self):
        # ignore requests as we are a pure client
        # XXXwarn
        self._endpoint.get_request()

    def call(self, method, params):
        """synchronous call.
        send a request and wait for a response.
        return a result.  or raise RPCError exception if the peer
        sends us an error.
        """
        msgid = self._endpoint.send_request(method, params)
        while True:
            if not self._endpoint.receive_messages():
                raise EOFError("EOF")
            res = self._endpoint.get_response(msgid)
            if res:
                result, error = res
                if error is None:
                    return result
                raise RPCError(error)
            self._process_input_notification()
            self._process_input_request()

    def send_notification(self, method, params):
        """send a notification to the peer.
        """
        self._endpoint.send_notification(method, params)

    def receive_notification(self):
        """wait for the next incoming message.
        intended to be used when we have nothing to send but want to receive
        notifications.
        """
        if not self._endpoint.receive_messages():
            raise EOFError("EOF")
        self._process_input_notification()
        self._process_input_request()

    def peek_notification(self):
        while True:
            rlist, _wlist = self._endpoint.selectable()
            rlist, _wlist, _xlist = select.select(rlist, [], [], 0)
            if not rlist:
                break
            self.receive_notification()
