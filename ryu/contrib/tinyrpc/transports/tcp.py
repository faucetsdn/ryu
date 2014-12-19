#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Queue import Queue
import struct
import threading

from SocketServer import TCPServer, BaseRequestHandler, ThreadingMixIn

from . import RPCRequestResponseServer


def _read_length_prefixed_msg(sock, prefix_format='!I'):
    prefix_bytes = struct.calcsize(prefix_format)

    sock.recv(prefix_bytes)

def _read_n_bytes(sock, n):
    buf = []
    while n > 0:
        data = sock.recv(n)
        n -= len(data)
        buf.append(data)

    return ''.join(buf)


def create_length_prefixed_tcp_handler():
    queue = Queue()
    class LengthPrefixedTcpHandler(BaseRequestHandler):
        def handle(self):
            #msg = _read_length_prefixed_msg(self.request)
            # this will run inside a new thread
            self.request.send("hello\n")
            while True:
                b = _read_n_bytes(self.request, 10)
                self.request.send("you sent: %s" % b)
                queue.put(b)

    return queue, LengthPrefixedTcpHandler


def tcp_test_main():
    class Server(ThreadingMixIn, TCPServer):
        pass

    queue, Handler = create_length_prefixed_tcp_handler()

    server = Server(('localhost', 12345), Handler)
    server.allow_reuse_address = True

    server.serve_forever()
