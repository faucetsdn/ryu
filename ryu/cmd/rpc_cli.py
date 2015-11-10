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

# a simple command line msgpack-rpc client
#
# a usage example:
#     % PYTHONPATH=. ./bin/rpc-cli \
#      --peers=echo-server=localhost:9999,hoge=localhost:9998
#     (Cmd) request echo-server echo ["hoge"]
#     RESULT hoge
#     (Cmd) request echo-server notify ["notify-method", ["param1","param2"]]
#     RESULT notify-method
#     (Cmd)
#     NOTIFICATION from echo-server ['notify-method', ['param1', 'param2']]
#     (Cmd)

from __future__ import print_function

import ryu.contrib
ryu.contrib.update_module_path()

from ryu import cfg

import cmd
import signal
import socket
import sys
import termios

from ryu.lib import rpc


CONF = cfg.CONF
CONF.register_cli_opts([
    # eg. rpc-cli --peers=hoge=localhost:9998,fuga=localhost:9999
    cfg.ListOpt('peers', default=[], help='list of peers')
])


class Peer(object):
    def __init__(self, name, addr):
        self._name = name
        self._addr = addr
        self.client = None
        try:
            self.connect()
        except:
            pass

    def connect(self):
        self.client = None
        s = socket.create_connection(self._addr)
        self.client = rpc.Client(s, notification_callback=self.notification)

    def try_to_connect(self, verbose=False):
        if self.client:
            return
        try:
            self.connect()
            assert self.client
        except Exception as e:
            if verbose:
                print("connection failure %s" % e)
            raise EOFError

    def notification(self, n):
        print("NOTIFICATION from %s %s" % (self._name, n))

    def call(self, method, params):
        return self._do(lambda: self.client.call(method, params))

    def send_notification(self, method, params):
        self._do(lambda: self.client.send_notification(method, params))

    def _do(self, f):
        def g():
            try:
                return f()
            except EOFError:
                self.client = None
                raise

        self.try_to_connect(verbose=True)
        try:
            return g()
        except EOFError:
            print("disconnected.  trying to connect...")
            self.try_to_connect(verbose=True)
            print("connected.  retrying the request...")
            return g()


peers = {}


def add_peer(name, host, port):
    peers[name] = Peer(name, (host, port))


class Cmd(cmd.Cmd):
    def __init__(self, *args, **kwargs):
        self._in_onecmd = False
        self._notification_check_interval = 1  # worth to be configurable?
        self._saved_termios = None
        cmd.Cmd.__init__(self, *args, **kwargs)

    def _request(self, line, f):
        args = line.split(None, 2)
        try:
            peer = args[0]
            method = args[1]
            params = eval(args[2])
        except:
            print("argument error")
            return
        try:
            p = peers[peer]
        except KeyError:
            print("unknown peer %s" % peer)
            return
        try:
            f(p, method, params)
        except rpc.RPCError as e:
            print("RPC ERROR %s" % e)
        except EOFError:
            print("disconnected")

    def _complete_peer(self, text, line, _begidx, _endidx):
        if len((line + 'x').split()) >= 3:
            return []
        return [name for name in peers if name.startswith(text)]

    def do_request(self, line):
        """request <peer> <method> <params>
        send a msgpack-rpc request and print a response.
        <params> is a python code snippet, it should be eval'ed to a list.
        """

        def f(p, method, params):
            result = p.call(method, params)
            print("RESULT %s" % result)

        self._request(line, f)

    def do_notify(self, line):
        """notify <peer> <method> <params>
        send a msgpack-rpc notification.
        <params> is a python code snippet, it should be eval'ed to a list.
        """

        def f(p, method, params):
            p.send_notification(method, params)

        self._request(line, f)

    def complete_request(self, text, line, begidx, endidx):
        return self._complete_peer(text, line, begidx, endidx)

    def complete_notify(self, text, line, begidx, endidx):
        return self._complete_peer(text, line, begidx, endidx)

    def do_EOF(self, _line):
        sys.exit(0)

    def emptyline(self):
        self._peek_notification()

    def postcmd(self, _stop, _line):
        self._peek_notification()

    def _peek_notification(self):
        for k, p in peers.items():
            if p.client:
                try:
                    p.client.peek_notification()
                except EOFError:
                    p.client = None
                    print("disconnected %s" % k)

    @staticmethod
    def _save_termios():
        return termios.tcgetattr(sys.stdin.fileno())

    @staticmethod
    def _restore_termios(t):
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, t)

    def preloop(self):
        self._saved_termios = self._save_termios()
        signal.signal(signal.SIGALRM, self._timeout)
        signal.alarm(1)

    def onecmd(self, string):
        self._in_onecmd = True
        try:
            return cmd.Cmd.onecmd(self, string)
        finally:
            self._in_onecmd = False

    def _timeout(self, _sig, _frame):
        if not self._in_onecmd:
            # restore terminal settings. (cooked/raw, ...)
            # required for pypy at least.
            # this doesn't seem to be needed for cpython readline
            # module but i'm not sure if it's by spec or luck.
            o = self._save_termios()
            self._restore_termios(self._saved_termios)
            self._peek_notification()
            self._restore_termios(o)
        signal.alarm(self._notification_check_interval)


def main(args=None, prog=None):
    CONF(args=args, prog=prog, project='rpc-cli', version='rpc-cli')

    for p_str in CONF.peers:
        name, addr = p_str.split('=')
        host, port = addr.rsplit(':', 1)
        add_peer(name, host, port)

    Cmd().cmdloop()


if __name__ == "__main__":
    main()
