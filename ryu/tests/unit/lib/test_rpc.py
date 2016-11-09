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
import socket
import struct
import unittest

from nose.tools import raises
import six

from ryu.lib import hub
from ryu.lib import rpc


class MyException(BaseException):
    pass


class Test_rpc(unittest.TestCase):
    """ Test case for ryu.lib.rpc
    """

    def _handle_request(self, m):
        e = self._server_endpoint
        msgid, method, params = m
        if method == 'resp':
            e.send_response(msgid, result=params[0])
        elif method == 'err':
            e.send_response(msgid, error=params[0])
        elif method == 'callback':
            n, cb, v = params
            assert n > 0
            self._requests.add(e.send_request(cb, [msgid, n, cb, v]))
        elif method == 'notify1':
            e.send_notification(params[1], params[2])
            e.send_response(msgid, result=params[0])
        elif method == 'shutdown':
            how = getattr(socket, params[0])
            self._server_sock.shutdown(how)
            e.send_response(msgid, result=method)
        else:
            raise Exception("unknown method %s" % method)

    def _handle_notification(self, m):
        e = self._server_endpoint
        method, params = m
        if method == 'notify2':
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
        obj = 'hoge'
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, str)

    def test_0_call_int(self):
        c = rpc.Client(self._client_sock)
        obj = 12345
        assert isinstance(obj, int)
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, numbers.Integral)

    def test_0_call_int2(self):
        c = rpc.Client(self._client_sock)
        obj = six.MAXSIZE
        assert isinstance(obj, int)
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, numbers.Integral)

    def test_0_call_int3(self):
        c = rpc.Client(self._client_sock)
        obj = - six.MAXSIZE - 1
        assert isinstance(obj, int)
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, numbers.Integral)

    def test_0_call_long(self):
        c = rpc.Client(self._client_sock)
        obj = 0xffffffffffffffff  # max value for msgpack
        assert isinstance(obj, numbers.Integral)
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, numbers.Integral)

    def test_0_call_long2(self):
        c = rpc.Client(self._client_sock)
        # Note: the python type of this value is int for 64-bit arch
        obj = -0x8000000000000000  # min value for msgpack
        assert isinstance(obj, numbers.Integral)
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, numbers.Integral)

    @raises(TypeError)
    def test_0_call_bytearray(self):
        c = rpc.Client(self._client_sock)
        obj = bytearray(b'foo')
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, str)

    def test_1_shutdown_wr(self):
        # test if the server shutdown on disconnect
        self._client_sock.shutdown(socket.SHUT_WR)
        hub.joinall([self._server_thread])

    @raises(EOFError)
    def test_1_client_shutdown_wr(self):
        c = rpc.Client(self._client_sock)
        c.call('shutdown', ['SHUT_WR'])

    def test_1_call_True(self):
        c = rpc.Client(self._client_sock)
        obj = True
        assert c.call('resp', [obj]) == obj

    def test_2_call_None(self):
        c = rpc.Client(self._client_sock)
        obj = None
        assert c.call('resp', [obj]) is None

    def test_2_call_False(self):
        c = rpc.Client(self._client_sock)
        obj = False
        assert c.call('resp', [obj]) == obj

    def test_2_call_dict(self):
        c = rpc.Client(self._client_sock)
        obj = {'hoge': 1, 'fuga': 2}
        assert c.call('resp', [obj]) == obj

    def test_2_call_empty_dict(self):
        c = rpc.Client(self._client_sock)
        obj = {}
        assert c.call('resp', [obj]) == obj

    def test_2_call_array(self):
        c = rpc.Client(self._client_sock)
        obj = [1, 2, 3, 4]
        assert c.call('resp', [obj]) == obj

    def test_2_call_empty_array(self):
        c = rpc.Client(self._client_sock)
        obj = []
        assert c.call('resp', [obj]) == obj

    def test_2_call_tuple(self):
        c = rpc.Client(self._client_sock)
        # Note: msgpack library implicitly convert a tuple into a list
        obj = (1, 2, 3)
        assert c.call('resp', [obj]) == list(obj)

    def test_2_call_unicode(self):
        c = rpc.Client(self._client_sock)
        # Note: We use encoding='utf-8' option in msgpack.Packer/Unpacker
        # in order to support Python 3.
        # With this option, utf-8 encoded bytes will be decoded into unicode
        # type in Python 2 and str type in Python 3.
        obj = u"hoge"
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, six.text_type)

    def test_2_call_small_binary(self):
        c = rpc.Client(self._client_sock)
        obj = struct.pack("100x")
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, six.binary_type)

    def test_3_call_complex(self):
        c = rpc.Client(self._client_sock)
        obj = [1, 'hoge', {'foo': 1, 3: 'bar'}]
        assert c.call('resp', [obj]) == obj

    @unittest.skip("doesn't work with eventlet 0.18 and later")
    def test_4_call_large_binary(self):
        c = rpc.Client(self._client_sock)
        obj = struct.pack("10000000x")
        result = c.call('resp', [obj])
        assert result == obj
        assert isinstance(result, six.binary_type)

    def test_0_notification1(self):
        l = []

        def callback(n):
            l.append(n)
        c = rpc.Client(self._client_sock, notification_callback=callback)
        obj = 'hogehoge'
        robj = 'fugafuga'
        assert c.call('notify1', [robj, 'notify_hoge', [obj]]) == robj
        c.receive_notification()
        assert len(l) == 1
        n = l.pop(0)
        assert n is not None
        method, params = n
        assert method == 'notify_hoge'
        assert params[0] == obj

    def test_0_notification2(self):
        l = []

        def callback(n):
            l.append(n)
        c = rpc.Client(self._client_sock, notification_callback=callback)
        obj = 'hogehogehoge'
        c.send_notification('notify2', ['notify_hoge', [obj]])
        c.receive_notification()
        assert len(l) == 1
        n = l.pop(0)
        assert n is not None
        method, params = n
        assert method == 'notify_hoge'
        assert params[0] == obj

    def test_0_call_error(self):
        c = rpc.Client(self._client_sock)
        obj = 'hoge'
        try:
            c.call('err', [obj])
            raise Exception("unexpected")
        except rpc.RPCError as e:
            assert e.get_value() == obj

    def test_0_call_error_notification(self):
        l = []

        def callback(n):
            l.append(n)
        c = rpc.Client(self._client_sock, notification_callback=callback)
        c.send_notification('notify2', ['notify_foo', []])
        hub.sleep(0.5)  # give the peer a chance to run
        obj = 'hoge'
        try:
            c.call('err', [obj])
            raise Exception("unexpected")
        except rpc.RPCError as e:
            assert e.get_value() == obj
        assert len(l) == 1
        n = l.pop(0)
        method, params = n
        assert method == 'notify_foo'
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
                s.add(e.send_request('resp', [i]))
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
                s.add(e.send_request('callback', [i, 'ourcallback', 0]))
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
                    assert method == 'ourcallback'
                    omsgid, n, cb, v = params
                    assert omsgid in s
                    assert cb == 'ourcallback'
                    assert n > 0
                    e.send_response(msgid, result=[omsgid, n - 1, cb, v + 1])
            assert sum == (1 + num_calls) * num_calls / 2
        finally:
            self._client_sock.setblocking(old_blocking)
        assert not self._requests
