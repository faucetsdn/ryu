# Copyright 2009 Shikhar Bhushan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import socket
import getpass
from binascii import hexlify
from cStringIO import StringIO
from select import select

import paramiko

from errors import AuthenticationError, SessionCloseError, SSHError, SSHUnknownHostError
from session import Session

import logging
logger = logging.getLogger("ncclient.transport.ssh")

BUF_SIZE = 4096
MSG_DELIM = "]]>]]>"
TICK = 0.1

def default_unknown_host_cb(host, fingerprint):
    """An unknown host callback returns `True` if it finds the key acceptable, and `False` if not.

    This default callback always returns `False`, which would lead to :meth:`connect` raising a :exc:`SSHUnknownHost` exception.
    
    Supply another valid callback if you need to verify the host key programatically.

    *host* is the hostname that needs to be verified

    *fingerprint* is a hex string representing the host key fingerprint, colon-delimited e.g. `"4b:69:6c:72:6f:79:20:77:61:73:20:68:65:72:65:21"`
    """
    return False

def _colonify(fp):
    finga = fp[:2]
    for idx  in range(2, len(fp), 2):
        finga += ":" + fp[idx:idx+2]
    return finga

class SSHSession(Session):

    "Implements a :rfc:`4742` NETCONF session over SSH."

    def __init__(self, capabilities):
        Session.__init__(self, capabilities)
        self._host_keys = paramiko.HostKeys()
        self._transport = None
        self._connected = False
        self._channel = None
        self._buffer = StringIO() # for incoming data
        # parsing-related, see _parse()
        self._parsing_state = 0
        self._parsing_pos = 0
    
    def _parse(self):
        "Messages ae delimited by MSG_DELIM. The buffer could have grown by a maximum of BUF_SIZE bytes everytime this method is called. Retains state across method calls and if a byte has been read it will not be considered again."
        delim = MSG_DELIM
        n = len(delim) - 1
        expect = self._parsing_state
        buf = self._buffer
        buf.seek(self._parsing_pos)
        while True:
            x = buf.read(1)
            if not x: # done reading
                break
            elif x == delim[expect]: # what we expected
                expect += 1 # expect the next delim char
            else:
                expect = 0
                continue
            # loop till last delim char expected, break if other char encountered
            for i in range(expect, n):
                x = buf.read(1)
                if not x: # done reading
                    break
                if x == delim[expect]: # what we expected
                    expect += 1 # expect the next delim char
                else:
                    expect = 0 # reset
                    break
            else: # if we didn't break out of the loop, full delim was parsed
                msg_till = buf.tell() - n
                buf.seek(0)
                logger.debug('parsed new message')
                self._dispatch_message(buf.read(msg_till).strip())
                buf.seek(n+1, os.SEEK_CUR)
                rest = buf.read()
                buf = StringIO()
                buf.write(rest)
                buf.seek(0)
                expect = 0
        self._buffer = buf
        self._parsing_state = expect
        self._parsing_pos = self._buffer.tell()

    def load_known_hosts(self, filename=None):
        """Load host keys from an openssh :file:`known_hosts`-style file. Can be called multiple times.

        If *filename* is not specified, looks in the default locations i.e. :file:`~/.ssh/known_hosts` and :file:`~/ssh/known_hosts` for Windows.
        """
        if filename is None:
            filename = os.path.expanduser('~/.ssh/known_hosts')
            try:
                self._host_keys.load(filename)
            except IOError:
                # for windows
                filename = os.path.expanduser('~/ssh/known_hosts')
                try:
                    self._host_keys.load(filename)
                except IOError:
                    pass
        else:
            self._host_keys.load(filename)

    def close(self):
        if self._transport.is_active():
            self._transport.close()
        self._connected = False

    # REMEMBER to update transport.rst if sig. changes, since it is hardcoded there
    def connect(self, host, port=830, timeout=None, unknown_host_cb=default_unknown_host_cb,
                username=None, password=None, key_filename=None, allow_agent=True, look_for_keys=True):
        """Connect via SSH and initialize the NETCONF session. First attempts the publickey authentication method and then password authentication.

        To disable attempting publickey authentication altogether, call with *allow_agent* and *look_for_keys* as `False`.

        *host* is the hostname or IP address to connect to

        *port* is by default 830, but some devices use the default SSH port of 22 so this may need to be specified

        *timeout* is an optional timeout for socket connect

        *unknown_host_cb* is called when the server host key is not recognized. It takes two arguments, the hostname and the fingerprint (see the signature of :func:`default_unknown_host_cb`)

        *username* is the username to use for SSH authentication

        *password* is the password used if using password authentication, or the passphrase to use for unlocking keys that require it

        *key_filename* is a filename where a the private key to be used can be found

        *allow_agent* enables querying SSH agent (if found) for keys

        *look_for_keys* enables looking in the usual locations for ssh keys (e.g. :file:`~/.ssh/id_*`)
        """
        if username is None:
            username = getpass.getuser()
        
        sock = None
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(timeout)
            except socket.error:
                continue
            try:
                sock.connect(sa)
            except socket.error:
                sock.close()
                continue
            break
        else:
            raise SSHError("Could not open socket to %s:%s" % (host, port))

        t = self._transport = paramiko.Transport(sock)
        t.set_log_channel(logger.name)

        try:
            t.start_client()
        except paramiko.SSHException:
            raise SSHError('Negotiation failed')

        # host key verification
        server_key = t.get_remote_server_key()
        known_host = self._host_keys.check(host, server_key)

        fingerprint = _colonify(hexlify(server_key.get_fingerprint()))

        if not known_host and not unknown_host_cb(host, fingerprint):
            raise SSHUnknownHostError(host, fingerprint)

        if key_filename is None:
            key_filenames = []
        elif isinstance(key_filename, basestring):
            key_filenames = [ key_filename ]
        else:
            key_filenames = key_filename

        self._auth(username, password, key_filenames, allow_agent, look_for_keys)

        self._connected = True # there was no error authenticating

        c = self._channel = self._transport.open_session()
        c.set_name("netconf")
        c.invoke_subsystem("netconf")

        self._post_connect()
    
    # on the lines of paramiko.SSHClient._auth()
    def _auth(self, username, password, key_filenames, allow_agent,
              look_for_keys):
        saved_exception = None

        for key_filename in key_filenames:
            for cls in (paramiko.RSAKey, paramiko.DSSKey):
                try:
                    key = cls.from_private_key_file(key_filename, password)
                    logger.debug("Trying key %s from %s",
                              hexlify(key.get_fingerprint()), key_filename)
                    self._transport.auth_publickey(username, key)
                    return
                except Exception as e:
                    saved_exception = e
                    logger.debug(e)

        if allow_agent:
            for key in paramiko.Agent().get_keys():
                try:
                    logger.debug("Trying SSH agent key %s",
                                 hexlify(key.get_fingerprint()))
                    self._transport.auth_publickey(username, key)
                    return
                except Exception as e:
                    saved_exception = e
                    logger.debug(e)

        keyfiles = []
        if look_for_keys:
            rsa_key = os.path.expanduser("~/.ssh/id_rsa")
            dsa_key = os.path.expanduser("~/.ssh/id_dsa")
            if os.path.isfile(rsa_key):
                keyfiles.append((paramiko.RSAKey, rsa_key))
            if os.path.isfile(dsa_key):
                keyfiles.append((paramiko.DSSKey, dsa_key))
            # look in ~/ssh/ for windows users:
            rsa_key = os.path.expanduser("~/ssh/id_rsa")
            dsa_key = os.path.expanduser("~/ssh/id_dsa")
            if os.path.isfile(rsa_key):
                keyfiles.append((paramiko.RSAKey, rsa_key))
            if os.path.isfile(dsa_key):
                keyfiles.append((paramiko.DSSKey, dsa_key))

        for cls, filename in keyfiles:
            try:
                key = cls.from_private_key_file(filename, password)
                logger.debug("Trying discovered key %s in %s",
                          hexlify(key.get_fingerprint()), filename)
                self._transport.auth_publickey(username, key)
                return
            except Exception as e:
                saved_exception = e
                logger.debug(e)

        if password is not None:
            try:
                self._transport.auth_password(username, password)
                return
            except Exception as e:
                saved_exception = e
                logger.debug(e)

        if saved_exception is not None:
            # need pep-3134 to do this right
            raise AuthenticationError(repr(saved_exception))

        raise AuthenticationError("No authentication methods available")

    def run(self):
        chan = self._channel
        q = self._q
        try:
            while True:
                # select on a paramiko ssh channel object does not ever return it in the writable list, so channels don't exactly emulate the socket api
                r, w, e = select([chan], [], [], TICK)
                # will wakeup evey TICK seconds to check if something to send, more if something to read (due to select returning chan in readable list)
                if r:
                    data = chan.recv(BUF_SIZE)
                    if data:
                        self._buffer.write(data)
                        self._parse()
                    else:
                        raise SessionCloseError(self._buffer.getvalue())
                if not q.empty() and chan.send_ready():
                    logger.debug("Sending message")
                    data = q.get() + MSG_DELIM
                    while data:
                        n = chan.send(data)
                        if n <= 0:
                            raise SessionCloseError(self._buffer.getvalue(), data)
                        data = data[n:]
        except Exception as e:
            logger.debug("Broke out of main loop, error=%r", e)
            self.close()
            self._dispatch_error(e)

    @property
    def transport(self):
        "Underlying `paramiko.Transport <http://www.lag.net/paramiko/docs/paramiko.Transport-class.html>`_ object. This makes it possible to call methods like :meth:`~paramiko.Transport.set_keepalive` on it."
        return self._transport
