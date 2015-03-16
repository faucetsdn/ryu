#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gevent
import zmq.green as zmq
from logbook import Logger

from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.dispatch import RPCDispatcher
from tinyrpc import RPCError, ServerError, MethodNotFoundError


class Server(object):
    def __init__(transport, protocol, dispatcher):
        self.transport = transport
        self.protocol = protocol
        self.dispatcher = dispatcher

    def run(self):
        while True:
            try:
                context, message = self.transport.receive_message()
            except Exception as e:
                self.exception(e)
                continue

            # assuming protocol is threadsafe and dispatcher is theadsafe, as long
            # as its immutable

            self.handle_client(context, message)

    def handle_client(self, context, message):
        try:
            request = self.protocol.parse_request(message)
        except RPCError as e:
            self.exception(e)
            response = e.error_respond()
        else:
            response = dispatcher.dispatch(request)

        # send reply
        reply = response.serialize()
        self.transport.send_reply(context, reply)


class ConcurrentServerMixin(object):
    def handle_client(self, context, message):
        self.spawn(
            super(ConcurrentServer, self).handle_client, context, message
        )


class ZmqRouterTransport(object):
    def __init__(self, socket):
        self.socket = socket

    def receive_message(self):
        msg = socket.recv_multipart()
        return msg[:-1], [-1]

    def send_reply(self, context, reply):
        self.send_multipart(context + [reply])


class GeventConcurrencyMixin(ConcurrentServerMixin):
    def spawn(self, func, *args, **kwargs):
        gevent.spawn(func, *args, **kwargs)


def rpc_server(socket, protocol, dispatcher):
    log = Logger('rpc_server')
    log.debug('starting up...')
    while True:
        try:
            message = socket.recv_multipart()
        except Exception as e:
            log.warning('Failed to receive message from client, ignoring...')
            log.exception(e)
            continue

        log.debug('Received message %s from %r', message[-1], message[0])

        # assuming protocol is threadsafe and dispatcher is theadsafe, as long
        # as its immutable

        def handle_client(message):
            try:
                request = protocol.parse_request(message[-1])
            except RPCError as e:
                log.exception(e)
                response = e.error_respond()
            else:
                response = dispatcher.dispatch(request)
                log.debug('Response okay: %r', response)

            # send reply
            message[-1] = response.serialize()
            log.debug('Replying %s to %r', message[-1], message[0])
            socket.send_multipart(message)

        gevent.spawn(handle_client, message)


context = zmq.Context()
socket = context.socket(zmq.ROUTER)
socket.bind("tcp://127.0.0.1:12345")

dispatcher = RPCDispatcher()

@dispatcher.public
def throw_up():
    return 'asad'
    raise Exception('BLARGH')

rpc_server(socket, JSONRPCProtocol(), dispatcher)
