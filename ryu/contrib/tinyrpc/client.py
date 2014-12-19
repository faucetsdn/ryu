#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .exc import RPCError


class RPCClient(object):
    """Client for making RPC calls to connected servers.

    :param protocol: An :py:class:`~tinyrpc.RPCProtocol` instance.
    :param transport: A :py:class:`~tinyrpc.transports.ClientTransport`
                      instance.
    """

    def __init__(self, protocol, transport):
        self.protocol = protocol
        self.transport = transport

    def _send_and_handle_reply(self, req):
        # sends and waits for reply
        reply = self.transport.send_message(req.serialize())

        response = self.protocol.parse_reply(reply)

        if hasattr(response, 'error'):
            raise RPCError('Error calling remote procedure: %s' %\
                           response.error)

        return response

    def call(self, method, args, kwargs, one_way=False):
        """Calls the requested method and returns the result.

        If an error occured, an :py:class:`~tinyrpc.exc.RPCError` instance
        is raised.

        :param method: Name of the method to call.
        :param args: Arguments to pass to the method.
        :param kwargs: Keyword arguments to pass to the method.
        :param one_way: Whether or not a reply is desired.
        """
        req = self.protocol.create_request(method, args, kwargs, one_way)

        return self._send_and_handle_reply(req).result

    def get_proxy(self, prefix='', one_way=False):
        """Convenience method for creating a proxy.

        :param prefix: Passed on to :py:class:`~tinyrpc.client.RPCProxy`.
        :param one_way: Passed on to :py:class:`~tinyrpc.client.RPCProxy`.
        :return: :py:class:`~tinyrpc.client.RPCProxy` instance."""
        return RPCProxy(self, prefix, one_way)

    def batch_call(self, calls):
        """Experimental, use at your own peril."""
        req = self.protocol.create_batch_request()

        for call_args in calls:
            req.append(self.protocol.create_request(*call_args))

        return self._send_and_handle_reply(req)


class RPCProxy(object):
    """Create a new remote proxy object.

    Proxies allow calling of methods through a simpler interface. See the
    documentation for an example.

    :param client: An :py:class:`~tinyrpc.client.RPCClient` instance.
    :param prefix: Prefix to prepend to every method name.
    :param one_way: Passed to every call of
                    :py:func:`~tinyrpc.client.call`.
    """

    def __init__(self, client, prefix='', one_way=False):
        self.client = client
        self.prefix = prefix
        self.one_way = one_way

    def __getattr__(self, name):
        """Returns a proxy function that, when called, will call a function
        name ``name`` on the client associated with the proxy.
        """
        proxy_func = lambda *args, **kwargs: self.client.call(
                         self.prefix + name,
                         args,
                         kwargs,
                         one_way=self.one_way
                     )
        return proxy_func
