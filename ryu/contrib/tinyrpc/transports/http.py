#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Queue import Queue
import threading
import requests

from . import ServerTransport, ClientTransport


class HttpPostClientTransport(ClientTransport):
    """HTTP POST based client transport.

    Requires :py:mod:`requests`. Submits messages to a server using the body of
    an ``HTTP`` ``POST`` request. Replies are taken from the responses body.

    :param endpoint: The URL to send ``POST`` data to.
    :param kwargs: Additional parameters for :py:func:`requests.post`.
    """
    def __init__(self, endpoint, **kwargs):
        self.endpoint = endpoint
        self.request_kwargs = kwargs

    def send_message(self, message, expect_reply=True):
        if not isinstance(message, str):
            raise TypeError('str expected')

        r = requests.post(self.endpoint, data=message, **self.request_kwargs)

        if expect_reply:
            return r.content
