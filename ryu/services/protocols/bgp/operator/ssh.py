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

"""
 CLI application for SSH management.
"""

from copy import copy
import logging
import os.path
import sys

import paramiko

from ryu import version
from ryu.lib import hub
from ryu.services.protocols.bgp.base import Activity
from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.commands.root import RootCmd
from ryu.services.protocols.bgp.operator.internal_api import InternalApi

SSH_PORT = "ssh_port"
SSH_HOST = "ssh_host"
SSH_HOST_KEY = "ssh_host_key"
SSH_USERNAME = "ssh_username"
SSH_PASSWORD = "ssh_password"

DEFAULT_SSH_PORT = 4990
DEFAULT_SSH_HOST = "localhost"
DEFAULT_SSH_HOST_KEY = None
DEFAULT_SSH_USERNAME = "ryu"
DEFAULT_SSH_PASSWORD = "ryu"

CONF = {
    SSH_PORT: DEFAULT_SSH_PORT,
    SSH_HOST: DEFAULT_SSH_HOST,
    SSH_HOST_KEY: DEFAULT_SSH_HOST_KEY,
    SSH_USERNAME: DEFAULT_SSH_USERNAME,
    SSH_PASSWORD: DEFAULT_SSH_PASSWORD,
}

LOG = logging.getLogger('bgpspeaker.cli')


def find_ssh_server_key():
    if CONF[SSH_HOST_KEY]:
        return paramiko.RSAKey.from_private_key_file(CONF[SSH_HOST_KEY])
    elif os.path.exists("/etc/ssh_host_rsa_key"):
        # OSX
        return paramiko.RSAKey.from_private_key_file(
            "/etc/ssh_host_rsa_key")
    elif os.path.exists("/etc/ssh/ssh_host_rsa_key"):
        # Linux
        return paramiko.RSAKey.from_private_key_file(
            "/etc/ssh/ssh_host_rsa_key")
    else:
        return paramiko.RSAKey.generate(1024)


class SshServer(paramiko.ServerInterface):
    TERM = "ansi"
    PROMPT = "bgpd> "
    WELCOME = "\n\rHello, this is Ryu BGP speaker (version %s).\n\r" % version

    class HelpCmd(Command):
        help_msg = 'show this help'
        command = 'help'

        def action(self, params):
            return self.parent_cmd.question_mark()[0]

    class QuitCmd(Command):
        help_msg = 'exit this session'
        command = 'quit'

        def action(self, params):
            self.api.sshserver.end_session()
            return CommandsResponse(STATUS_OK, True)

    def __init__(self, sock, addr):
        super(SshServer, self).__init__()
        self.sock = sock
        self.addr = addr
        self.is_connected = True

        # For pylint
        self.buf = None
        self.chan = None
        self.curpos = None
        self.histindex = None
        self.history = None
        self.prompted = None
        self.promptlen = None

        # tweak InternalApi and RootCmd for non-bgp related commands
        self.api = InternalApi(log_handler=logging.StreamHandler(sys.stderr))
        setattr(self.api, 'sshserver', self)
        self.root = RootCmd(self.api)
        self.root.subcommands['help'] = self.HelpCmd
        self.root.subcommands['quit'] = self.QuitCmd

        self.transport = paramiko.Transport(self.sock)
        self.transport.load_server_moduli()
        host_key = find_ssh_server_key()
        self.transport.add_server_key(host_key)
        self.transport.start_server(server=self)

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        if (username == CONF[SSH_USERNAME]
                and password == CONF[SSH_PASSWORD]):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        hub.spawn(self._handle_shell_request)
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        self.TERM = term
        return True

    def check_channel_window_change_request(self, channel, width, height,
                                            pixelwidth, pixelheight):
        return True

    @staticmethod
    def _is_echoable(c):
        return not (c < chr(0x20) or c == chr(0x7F))

    @staticmethod
    def _is_enter(c):
        return c == chr(0x0d)

    @staticmethod
    def _is_eof(c):
        return c == chr(0x03)

    @staticmethod
    def _is_esc(c):
        return c == chr(0x1b)

    @staticmethod
    def _is_hist(c):
        return c == chr(0x10) or c == chr(0x0e)

    @staticmethod
    def _is_del(c):
        return (c == chr(0x04) or c == chr(0x08) or c == chr(0x15)
                or c == chr(0x17) or c == chr(0x0c) or c == chr(0x7f))

    @staticmethod
    def _is_curmov(c):
        return c == chr(0x01) or c == chr(0x02) or c == chr(0x05) \
            or c == chr(0x06)

    @staticmethod
    def _is_cmpl(c):
        return c == chr(0x09)

    def _handle_csi_seq(self):
        c = self.chan.recv(1)
        c = c.decode()  # For Python3 compatibility
        if c == 'A':
            self._lookup_hist_up()
        elif c == 'B':
            self._lookup_hist_down()
        elif c == 'C':
            self._movcursor(self.curpos + 1)
        elif c == 'D':
            self._movcursor(self.curpos - 1)
        else:
            LOG.error("unknown CSI sequence. do nothing: %c", c)

    def _handle_esc_seq(self):
        c = self.chan.recv(1)
        c = c.decode()  # For Python3 compatibility
        if c == '[':
            self._handle_csi_seq()
        else:
            LOG.error("non CSI sequence. do nothing")

    def _send_csi_seq(self, cmd):
        self.chan.send('\x1b[' + cmd)

    def _movcursor(self, curpos):
        if self.prompted and curpos < len(self.PROMPT):
            self.curpos = len(self.PROMPT)
        elif self.prompted and curpos > (len(self.PROMPT) + len(self.buf)):
            self.curpos = len(self.PROMPT) + len(self.buf)
        else:
            self._send_csi_seq('%dG' % (curpos + 1))
            self.curpos = curpos

    def _clearscreen(self, prompt=None):
        if not prompt and self.prompted:
            prompt = self.PROMPT
        # clear screen
        self._send_csi_seq('2J')
        # move cursor to the top
        self._send_csi_seq('d')
        # redraw prompt and buf
        self._refreshline(prompt=prompt)

    def _clearline(self, prompt=None):
        if not prompt and self.prompted:
            prompt = self.PROMPT
        self.prompted = False
        self._movcursor(0)
        self._send_csi_seq('2K')
        if prompt:
            self.prompted = True
            self.chan.send(prompt)
            self._movcursor(len(prompt))
        self.buf = []

    def _refreshline(self, prompt=None):
        if not prompt and self.prompted:
            prompt = self.PROMPT
        buf = copy(self.buf)
        curpos = copy(self.curpos)
        self._clearline(prompt=prompt)
        self.chan.send(''.join(buf))
        self.buf = buf
        self.curpos = curpos
        self._movcursor(curpos)

    def _refreshnewline(self, prompt=None):
        if not prompt and self.prompted:
            prompt = self.PROMPT
        buf = copy(self.buf)
        curpos = copy(self.curpos)
        self._startnewline(prompt)
        self.chan.send(''.join(buf))
        self.buf = buf
        self.curpos = curpos
        self._movcursor(curpos)

    def _startnewline(self, prompt=None, buf=None):
        buf = buf or []
        if not prompt and self.prompted:
            prompt = self.PROMPT
        if isinstance(buf, str):
            buf = list(buf)
        if self.chan:
            self.buf = buf
            if prompt:
                self.chan.send('\n\r' + prompt + ''.join(buf))
                self.curpos = len(prompt) + len(buf)
                self.prompted = True
            else:
                self.chan.send('\n\r' + ''.join(buf))
                self.curpos = len(buf)
                self.prompted = False

    def _lookup_hist_up(self):
        if len(self.history) == 0:
            return
        self.buf = self.history[self.histindex]
        self.curpos = self.promptlen + len(self.buf)
        self._refreshline()
        if self.histindex + 1 < len(self.history):
            self.histindex += 1

    def _lookup_hist_down(self):
        if self.histindex > 0:
            self.histindex -= 1
            self.buf = self.history[self.histindex]
            self.curpos = self.promptlen + len(self.buf)
            self._refreshline()
        else:
            self._clearline()

    def _do_cmpl(self, buf, is_exec=False):
        cmpleter = self.root
        is_spaced = buf[-1] == ' ' if len(buf) > 0 else False
        cmds = [tkn.strip() for tkn in ''.join(buf).split()]
        ret = []

        for i, cmd in enumerate(cmds):
            subcmds = cmpleter.subcommands
            matches = [x for x in subcmds.keys() if x.startswith(cmd)]

            if len(matches) == 1:
                cmpled_cmd = matches[0]
                cmpleter = subcmds[cmpled_cmd](self.api)

                if is_exec:
                    ret.append(cmpled_cmd)
                    continue

                if (i + 1) == len(cmds):
                    if is_spaced:
                        result, cmd = cmpleter('?')
                        result = result.value.replace('\n', '\n\r').rstrip()
                        self.prompted = False
                        buf = copy(buf)
                        self._startnewline(buf=result)
                        self.prompted = True
                        self._startnewline(buf=buf)
                    else:
                        self.buf = buf[:(-1 * len(cmd))] + \
                            list(cmpled_cmd + ' ')
                        self.curpos += len(cmpled_cmd) - len(cmd) + 1
                        self._refreshline()
            else:
                self.prompted = False
                buf = copy(self.buf)
                if len(matches) == 0:
                    if cmpleter.param_help_msg:
                        self.prompted = True
                        ret.append(cmd)
                        continue
                    else:
                        self._startnewline(buf='Error: Not implemented')
                else:
                    if (i + 1) < len(cmds):
                        self._startnewline(buf='Error: Ambiguous command')
                    else:
                        self._startnewline(buf=', '.join(matches))
                ret = []
                self.prompted = True
                if not is_exec:
                    self._startnewline(buf=buf)
                break

        return ret

    def _execute_cmd(self, cmds):
        result, _ = self.root(cmds)
        LOG.debug("result: %s", result)
        if cmds[0] == 'quit':
            self.is_connected = False
            return result.status
        self.prompted = False
        self._startnewline()
        output = result.value.replace('\n', '\n\r').rstrip()
        self.chan.send(output)
        self.prompted = True
        self._startnewline()
        return result.status

    def end_session(self):
        self._startnewline(prompt=False, buf='bye.\n\r')
        self.chan.close()

    def _handle_shell_request(self):
        LOG.info("session start")
        chan = self.transport.accept(20)
        if not chan:
            LOG.info("transport.accept timed out")
            return

        self.chan = chan
        self.buf = []
        self.curpos = 0
        self.history = []
        self.histindex = 0
        self.prompted = True
        self.chan.send(self.WELCOME)
        self._startnewline()

        while self.is_connected:
            c = self.chan.recv(1)
            c = c.decode()  # For Python3 compatibility

            if len(c) == 0:
                break

            LOG.debug("ord:%d, hex:0x%x", ord(c), ord(c))
            self.promptlen = len(self.PROMPT) if self.prompted else 0
            if c == '?':
                cmpleter = self.root
                cmds = [tkn.strip() for tkn in ''.join(self.buf).split()]

                for i, cmd in enumerate(cmds):
                    subcmds = cmpleter.subcommands
                    matches = [x for x in subcmds.keys() if x.startswith(cmd)]
                    if len(matches) == 1:
                        cmpled_cmd = matches[0]
                        cmpleter = subcmds[cmpled_cmd](self.api)

                result, cmd = cmpleter('?')
                result = result.value.replace('\n', '\n\r').rstrip()
                self.prompted = False
                buf = copy(self.buf)
                self._startnewline(buf=result)
                self.prompted = True
                self._startnewline(buf=buf)
            elif self._is_echoable(c):
                self.buf.insert(self.curpos - self.promptlen, c)
                self.curpos += 1
                self._refreshline()
            elif self._is_esc(c):
                self._handle_esc_seq()
            elif self._is_eof(c):
                self.end_session()
            elif self._is_curmov(c):
                # <C-a>
                if c == chr(0x01):
                    self._movcursor(self.promptlen)
                # <C-b>
                elif c == chr(0x02):
                    self._movcursor(self.curpos - 1)
                # <C-e>
                elif c == chr(0x05):
                    self._movcursor(self.promptlen + len(self.buf))
                # <C-f>
                elif c == chr(0x06):
                    self._movcursor(self.curpos + 1)
                else:
                    LOG.error("unknown cursor move cmd.")
                    continue
            elif self._is_hist(c):
                # <C-p>
                if c == chr(0x10):
                    self._lookup_hist_up()
                # <C-n>
                elif c == chr(0x0e):
                    self._lookup_hist_down()
            elif self._is_del(c):
                # <C-d>
                if c == chr(0x04):
                    if self.curpos < (self.promptlen + len(self.buf)):
                        self.buf.pop(self.curpos - self.promptlen)
                        self._refreshline()
                # <C-h> or delete
                elif c == chr(0x08) or c == chr(0x7f):
                    if self.curpos > self.promptlen:
                        self.buf.pop(self.curpos - self.promptlen - 1)
                        self.curpos -= 1
                        self._refreshline()
                # <C-u>
                elif c == chr(0x15):
                    self._clearline()
                # <C-w>
                elif c == chr(0x17):
                    pos = self.curpos - self.promptlen
                    i = pos
                    flag = False
                    for c in reversed(self.buf[:pos]):
                        if flag and c == ' ':
                            break
                        if c != ' ':
                            flag = True
                        i -= 1
                    del self.buf[i:pos]
                    self.curpos = self.promptlen + i
                    self._refreshline()
                # <C-l>
                elif c == chr(0x0c):
                    self._clearscreen()
            elif self._is_cmpl(c):
                self._do_cmpl(self.buf)
            elif self._is_enter(c):
                if len(''.join(self.buf).strip()) != 0:
                    # cmd line interpretation
                    cmds = self._do_cmpl(self.buf, is_exec=True)
                    if cmds:
                        self.history.insert(0, self.buf)
                        self.histindex = 0
                        self._execute_cmd(cmds)
                    else:
                        LOG.debug("no command is interpreted. "
                                  "just start a new line.")
                        self._startnewline()
                else:
                    LOG.debug("blank buf is detected. "
                              "just start a new line.")
                    self._startnewline()

            LOG.debug("curpos: %d, buf: %s, prompted: %s", self.curpos,
                      self.buf, self.prompted)

        LOG.info("session end")


def ssh_server_factory(sock, addr):
    SshServer(sock, addr)


class Cli(Activity):
    def __init__(self):
        super(Cli, self).__init__()

    def _run(self, *args, **kwargs):
        for k, v in kwargs.items():
            if k in CONF:
                CONF[k] = v

        listen_info = (CONF[SSH_HOST], CONF[SSH_PORT])
        LOG.info("starting ssh server at %s:%d" % listen_info)
        server = hub.StreamServer(listen_info, ssh_server_factory)
        server.serve_forever()


SSH_CLI_CONTROLLER = Cli()
