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

import logging
import os


# we don't bother to use cfg.py because monkey patch needs to be
# called very early.  instead, we use an environment variable to
# select the type of hub.
HUB_TYPE = os.getenv('RYU_HUB_TYPE', 'eventlet')

LOG = logging.getLogger('ryu.lib.hub')

if HUB_TYPE == 'eventlet':
    import eventlet
    import eventlet.event
    import eventlet.queue
    import eventlet.timeout
    import eventlet.wsgi
    import greenlet
    import ssl
    import socket
    import traceback

    getcurrent = eventlet.getcurrent
    patch = eventlet.monkey_patch
    sleep = eventlet.sleep

    def spawn(*args, **kwargs):
        def _launch(func, *args, **kwargs):
            # mimic gevent's default raise_error=False behaviour
            # by not propergating an exception to the joiner.
            try:
                func(*args, **kwargs)
            except greenlet.GreenletExit:
                pass
            except:
                # log uncaught exception.
                # note: this is an intentional divergence from gevent
                # behaviour.  gevent silently ignores such exceptions.
                LOG.error('hub: uncaught exception: %s',
                          traceback.format_exc())

        return eventlet.spawn(_launch, *args, **kwargs)

    def kill(thread):
        thread.kill()

    def joinall(threads):
        for t in threads:
            # this try-except is necessary when killing an inactive
            # greenthread
            try:
                t.wait()
            except greenlet.GreenletExit:
                pass

    Queue = eventlet.queue.Queue
    QueueEmpty = eventlet.queue.Empty

    class StreamServer(object):
        def __init__(self, listen_info, handle=None, backlog=None,
                     spawn='default', **ssl_args):
            assert backlog is None
            assert spawn == 'default'

            if ':' in listen_info[0]:
                self.server = eventlet.listen(listen_info,
                                              family=socket.AF_INET6)
            else:
                self.server = eventlet.listen(listen_info)
            if ssl_args:
                def wrap_and_handle(sock, addr):
                    ssl_args.setdefault('server_side', True)
                    handle(ssl.wrap_socket(sock, **ssl_args), addr)

                self.handle = wrap_and_handle
            else:
                self.handle = handle

        def serve_forever(self):
            while True:
                sock, addr = self.server.accept()
                spawn(self.handle, sock, addr)

    class WSGIServer(StreamServer):
        def serve_forever(self):
            eventlet.wsgi.server(self.server, self.handle)

    Timeout = eventlet.timeout.Timeout

    class Event(object):
        def __init__(self):
            self._ev = eventlet.event.Event()
            self._cond = False

        def _wait(self, timeout=None):
            while not self._cond:
                self._ev.wait()

        def _broadcast(self):
            self._ev.send()
            # because eventlet Event doesn't allow mutiple send() on an event,
            # re-create the underlying event.
            # note: _ev.reset() is obsolete.
            self._ev = eventlet.event.Event()

        def set(self):
            self._cond = True
            self._broadcast()

        def clear(self):
            self._cond = False

        def wait(self, timeout=None):
            if timeout is None:
                self._wait()
            else:
                try:
                    with Timeout(timeout):
                        self._wait()
                except Timeout:
                    pass

            return self._cond
