# Copyright (C) 2013-2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013-2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import numbers
import time
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
from nose.tools import raises
import six

from ryu.lib import hub
hub.patch()
from ryu.lib import rpc


class MyException(BaseException):
    pass


class Test_rpc(unittest.TestCase):
    """ Test case for ryu.lib.rpc
    """

    def _handle_request(self, m):
        e = self._server_endpoint
        msgid, method, params = m
        if method == b'resp':
            e.send_response(msgid, result=params[0])
        elif method == b'err':
            e.send_response(msgid, error=params[0])
        elif method == b'callback':
            n, cb, v = params
            assert n > 0
            self._requests.add(e.send_request(cb, [msgid, n, cb, v]))
        elif method == b'notify1':
            e.send_notification(params[1], params[2])
            e.send_response(msgid, result=params[0])
        elif method == b'shutdown':
            import socket
            # Though six.text_type is not needed in python2, it is
            # unconditionally applied for code simplicityp
            how = getattr(socket, six.text_type(params[0], 'utf-8'))
            self._server_sock.shutdown(how)
            e.send_response(msgid, result=method)
        else:
            raise Exception("unknown method %s" % method)

    def _handle_notification(self, m):
        e = self._server_endpoint
        method, params = m
        if method == b'notify2':
            e.send_notification(params[0], params[1])

    def _handle_response(self, m):
        e = self._server_endpoint
        msgid, error, result = m
        assert error is None
        self._requests.remove(msgid)
        omsgid, n, cb, v = result
        assert n >= 0
        if n == 0:
            e.send_response(omsgid, result=v)
        else:
            self._requests.add(e.send_request(cb, [omsgid, n, cb, v]))

    def setUp(self):
        import socket

        self._server_sock, self._client_sock = socket.socketpair()
        table = {
            rpc.MessageType.REQUEST: self._handle_request,
            rpc.MessageType.RESPONSE: self._handle_response,
            rpc.MessageType.NOTIFY: self._handle_notification
        }
        self._requests = set()
        self._server_sock.setblocking(0)
        self._server_endpoint = rpc.EndPoint(self._server_sock,
                                             disp_table=table)
        self._server_thread = hub.spawn(self._server_endpoint.serve)

    def tearDown(self):
        hub.kill(self._server_thread)
        hub.joinall([self._server_thread])

    def test_0_call_str(self):
        c = rpc.Client(self._client_sock)
        obj = b'hoge'
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, bytes)

    def test_0_call_int(self):
        c = rpc.Client(self._client_sock)
        obj = 12345
        assert isinstance(obj, int)
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, type(obj))

    def test_0_call_int2(self):
        c = rpc.Client(self._client_sock)
        obj = six.MAXSIZE
        assert isinstance(obj, int)
        result = c.call(b'resp', [obj])
        assert result == obj
        import sys
        # note: on PyPy, result will be a long type value.
        sv = getattr(sys, 'subversion', None)
        if sv is not None and sv[0] == 'PyPy':
            assert isinstance(result, long)
        else:
            assert isinstance(result, type(obj))

    def test_0_call_int3(self):
        c = rpc.Client(self._client_sock)
        obj = - six.MAXSIZE - 1
        assert isinstance(obj, int)
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, type(obj))

    def test_0_call_long(self):
        c = rpc.Client(self._client_sock)
        obj = 0xffffffffffffffff  # max value for msgpack
        _long = int if six.PY3 else long
        assert isinstance(obj, _long)
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, type(obj))

    def test_0_call_long2(self):
        c = rpc.Client(self._client_sock)
        # NOTE: the python type of this value is int for 64-bit arch
        obj = -0x8000000000000000  # min value for msgpack
        assert isinstance(obj, numbers.Integral)
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, type(obj))

    @raises(TypeError)
    def test_0_call_bytearray(self):
        c = rpc.Client(self._client_sock)
        obj = bytearray(b'foo')
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, bytes)

    def test_1_shutdown_wr(self):
        # test if the server shutdown on disconnect
        import socket
        self._client_sock.shutdown(socket.SHUT_WR)
        hub.joinall([self._server_thread])

    @raises(EOFError)
    def test_1_client_shutdown_wr(self):
        c = rpc.Client(self._client_sock)
        c.call(b'shutdown', [b'SHUT_WR'])

    def test_1_call_True(self):
        c = rpc.Client(self._client_sock)
        obj = True
        assert c.call(b'resp', [obj]) == obj

    def test_2_call_None(self):
        c = rpc.Client(self._client_sock)
        obj = None
        assert c.call(b'resp', [obj]) is None

    def test_2_call_False(self):
        c = rpc.Client(self._client_sock)
        obj = False
        assert c.call(b'resp', [obj]) == obj

    def test_2_call_dict(self):
        c = rpc.Client(self._client_sock)
        obj = {b'hoge': 1, b'fuga': 2}
        assert c.call(b'resp', [obj]) == obj

    def test_2_call_empty_dict(self):
        c = rpc.Client(self._client_sock)
        obj = {}
        assert c.call(b'resp', [obj]) == obj

    def test_2_call_array(self):
        c = rpc.Client(self._client_sock)
        obj = [1, 2, 3, 4]
        assert c.call(b'resp', [obj]) == obj

    def test_2_call_empty_array(self):
        c = rpc.Client(self._client_sock)
        obj = []
        assert c.call(b'resp', [obj]) == obj

    def test_2_call_tuple(self):
        c = rpc.Client(self._client_sock)
        # note: msgpack library implicitly convert a tuple into a list
        obj = (1, 2, 3)
        assert c.call(b'resp', [obj]) == list(obj)

    @raises(TypeError)
    def test_2_call_unicode(self):
        c = rpc.Client(self._client_sock)
        # note: on-wire msgpack has no notion of encoding.
        # the msgpack library implicitly converts unicode to
        # utf-8 encoded bytes by default.
        # we don't want to rely on the behaviour though because
        # it seems to be going to change.
        # https://gist.github.com/methane/5022403
        obj = u"hoge"
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, bytes)

    def test_2_call_small_binary(self):
        import struct
        c = rpc.Client(self._client_sock)
        obj = struct.pack("100x")
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, bytes)

    def test_3_call_complex(self):
        c = rpc.Client(self._client_sock)
        obj = [1, b'hoge', {b'foo': 1, 3: b'bar'}]
        assert c.call(b'resp', [obj]) == list(obj)

    @unittest.skip("doesn't work with eventlet 0.18 and later")
    def test_4_call_large_binary(self):
        import struct
        import sys
        # note: on PyPy, this test case may hang up.
        sv = getattr(sys, 'subversion', None)
        if sv is not None and sv[0] == 'PyPy':
            return

        c = rpc.Client(self._client_sock)
        obj = struct.pack("10000000x")
        result = c.call(b'resp', [obj])
        assert result == obj
        assert isinstance(result, bytes)

    def test_0_notification1(self):
        l = []

        def callback(n):
            l.append(n)
        c = rpc.Client(self._client_sock, notification_callback=callback)
        obj = b'hogehoge'
        robj = b'fugafuga'
        assert c.call(b'notify1', [robj, b'notify_hoge', [obj]]) == robj
        c.receive_notification()
        assert len(l) == 1
        n = l.pop(0)
        assert n is not None
        method, params = n
        assert method == b'notify_hoge'
        assert params[0] == obj

    def test_0_notification2(self):
        l = []

        def callback(n):
            l.append(n)
        c = rpc.Client(self._client_sock, notification_callback=callback)
        obj = b'hogehogehoge'
        c.send_notification(b'notify2', [b'notify_hoge', [obj]])
        c.receive_notification()
        assert len(l) == 1
        n = l.pop(0)
        assert n is not None
        method, params = n
        assert method == b'notify_hoge'
        assert params[0] == obj

    def test_0_call_error(self):
        c = rpc.Client(self._client_sock)
        obj = b'hoge'
        try:
            c.call(b'err', [obj])
            raise Exception("unexpected")
        except rpc.RPCError as e:
            assert e.get_value() == obj

    def test_0_call_error_notification(self):
        l = []

        def callback(n):
            l.append(n)
        c = rpc.Client(self._client_sock, notification_callback=callback)
        c.send_notification(b'notify2', [b'notify_foo', []])
        hub.sleep(0.5)  # give the peer a chance to run
        obj = b'hoge'
        try:
            c.call(b'err', [obj])
            raise Exception("unexpected")
        except rpc.RPCError as e:
            assert e.get_value() == obj
        assert len(l) == 1
        n = l.pop(0)
        method, params = n
        assert method == b'notify_foo'
        assert params == []

    def test_4_async_call(self):
        """send a bunch of requests and then wait for responses
        """
        num_calls = 9999
        old_blocking = self._client_sock.setblocking(0)
        try:
            e = rpc.EndPoint(self._client_sock)
            s = set()
            for i in range(1, num_calls + 1):
                s.add(e.send_request(b'resp', [i]))
            sum = 0
            while s:
                e.block()
                e.process()
                done = set()
                for x in s:
                    r = e.get_response(x)
                    if r is None:
                        continue
                    res, error = r
                    assert error is None
                    sum += res
                    done.add(x)
                assert done.issubset(s)
                s -= done
            assert sum == (1 + num_calls) * num_calls / 2
        finally:
            self._client_sock.setblocking(old_blocking)

    def test_4_async_call2(self):
        """both sides act as rpc client and server
        """
        assert not self._requests
        num_calls = 100
        old_blocking = self._client_sock.setblocking(0)
        try:
            e = rpc.EndPoint(self._client_sock)
            s = set()
            for i in range(1, num_calls + 1):
                s.add(e.send_request(b'callback', [i, b'ourcallback', 0]))
            sum = 0
            while s:
                e.block()
                e.process()
                done = set()
                for x in s:
                    r = e.get_response(x)
                    if r is None:
                        continue
                    res, error = r
                    assert error is None
                    sum += res
                    done.add(x)
                assert done.issubset(s)
                s -= done
                r = e.get_request()
                if r is not None:
                    msgid, method, params = r
                    assert method == b'ourcallback'
                    omsgid, n, cb, v = params
                    assert omsgid in s
                    assert cb == b'ourcallback'
                    assert n > 0
                    e.send_response(msgid, result=[omsgid, n - 1, cb, v + 1])
            assert sum == (1 + num_calls) * num_calls / 2
        finally:
            self._client_sock.setblocking(old_blocking)
        assert not self._requests
