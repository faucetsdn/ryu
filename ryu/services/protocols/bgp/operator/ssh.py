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

# a management cli application.

import logging
import paramiko
import sys
from copy import copy
import os.path

from ryu.lib import hub
from ryu import version
from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.commands.root import RootCmd
from ryu.services.protocols.bgp.operator.internal_api import InternalApi
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.base import Activity

CONF = {
    "ssh_port": 4990,
    "ssh_host": "localhost",
    "ssh_hostkey": None,
    "ssh_username": "ryu",
    "ssh_password": "ryu",
}

LOG = logging.getLogger('bgpspeaker.cli')


class SshServer(paramiko.ServerInterface):
    TERM = "ansi"
    PROMPT = "bgpd> "
    WELCOME = """
Hello, this is Ryu BGP speaker (version %s).
""" % version

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

        # tweak InternalApi and RootCmd for non-bgp related commands
        self.api = InternalApi(log_handler=logging.StreamHandler(sys.stderr))
        setattr(self.api, 'sshserver', self)
        self.root = RootCmd(self.api)
        self.root.subcommands['help'] = self.HelpCmd
        self.root.subcommands['quit'] = self.QuitCmd

        transport = paramiko.Transport(sock)
        transport.load_server_moduli()
        host_key = self._find_ssh_server_key()
        transport.add_server_key(host_key)
        self.transport = transport
        transport.start_server(server=self)

    def _find_ssh_server_key(self):
        if CONF["ssh_hostkey"]:
            return paramiko.RSAKey.from_private_key_file(CONF['ssh_hostkey'])
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

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        if username == CONF["ssh_username"] and \
                password == CONF["ssh_password"]:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, chan):
        hub.spawn(self._handle_shell_request)
        return True

    def check_channel_pty_request(self, chan, term, width, height,
                                  pixelwidth, pixelheight, modes):
        LOG.debug("termtype: %s", term)
        self.TERM = term
        return True

    def check_channel_window_change_request(self, chan, width, height, pwidth,
                                            pheight):
        LOG.info("channel window change")
        return True

    def _is_echoable(self, c):
        return not (c < chr(0x20) or c == chr(0x7F))

    def _is_enter(self, c):
        return c == chr(0x0d)

    def _is_eof(self, c):
        return c == chr(0x03)

    def _is_esc(self, c):
        return c == chr(0x1b)

    def _is_hist(self, c):
        return c == chr(0x10) or c == chr(0x0e)

    def _is_del(self, c):
        return c == chr(0x04) or c == chr(0x08) or c == chr(0x15) \
            or c == chr(0x17) or c == chr(0x0c) or c == chr(0x7f)

    def _is_curmov(self, c):
        return c == chr(0x01) or c == chr(0x02) or c == chr(0x05) \
            or c == chr(0x06)

    def _is_cmpl(self, c):
        return c == chr(0x09)

    def _handle_csi_seq(self):
        c = self.chan.recv(1)
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
        if c == '[':
            self._handle_csi_seq()
        else:
            LOG.error("non CSI sequence. do nothing")

    def _send_csi_seq(self, cmd):
        self.chan.send(b'\x1b[' + cmd)

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

    def _startnewline(self, prompt=None, buf=''):
        if not prompt and self.prompted:
            prompt = self.PROMPT
        if type(buf) == str:
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
                ret = False
                self.prompted = True
                if not is_exec:
                    self._startnewline(buf=buf)
                break

        return ret

    def _execute_cmd(self, cmds):
        result, cmd = self.root(cmds)
        LOG.debug("result: %s", result)
        self.prompted = False
        self._startnewline()
        output = result.value.replace('\n', '\n\r').rstrip()
        self.chan.send(output)
        self.prompted = True
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

        while True:
            c = self.chan.recv(1)

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
                    LOG.debug("blank buf. just start a new line.")
                self._startnewline()

            LOG.debug("curpos: %d, buf: %s, prompted: %s", self.curpos,
                      self.buf, self.prompted)

        LOG.info("session end")


class SshServerFactory(object):
    def __init__(self, *args, **kwargs):
        super(SshServerFactory, self).__init__(*args, **kwargs)

    def streamserver_handle(self, sock, addr):
        SshServer(sock, addr)


class Cli(Activity):
    def __init__(self):
        super(Cli, self).__init__()

    def _run(self, *args, **kwargs):
        for k, v in kwargs.items():
            if k in CONF:
                CONF[k] = v

        LOG.info("starting ssh server at %s:%d", CONF["ssh_host"],
                 CONF["ssh_port"])
        factory = SshServerFactory()
        server = hub.StreamServer((CONF["ssh_host"], CONF["ssh_port"]),
                                  factory.streamserver_handle)
        server.serve_forever()

SSH_CLI_CONTROLLER = Cli()
