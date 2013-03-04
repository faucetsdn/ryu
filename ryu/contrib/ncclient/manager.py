# Copyright 2009 Shikhar Bhushan
# Copyright 2011 Leonidas Poulopoulos
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

"""This module is a thin layer of abstraction around the library. It exposes all core functionality."""

import capabilities
import operations
import transport

import logging

logger = logging.getLogger('ncclient.manager')

CAPABILITIES = [
    "urn:ietf:params:netconf:base:1.0",
    "urn:ietf:params:netconf:capability:writable-running:1.0",
    "urn:ietf:params:netconf:capability:candidate:1.0",
    "urn:ietf:params:netconf:capability:confirmed-commit:1.0",
    "urn:ietf:params:netconf:capability:rollback-on-error:1.0",
    "urn:ietf:params:netconf:capability:startup:1.0",
    "urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file,https,sftp",
    "urn:ietf:params:netconf:capability:validate:1.0",
    "urn:ietf:params:netconf:capability:xpath:1.0",
    "urn:liberouter:params:netconf:capability:power-control:1.0",
    "urn:ietf:params:netconf:capability:interleave:1.0"
]
"""A list of URI's representing the client's capabilities. This is used during the initial capability exchange. Modify this if you need to announce some capability not already included."""

OPERATIONS = {
    "get": operations.Get,
    "get_config": operations.GetConfig,
    "dispatch": operations.Dispatch,
    "edit_config": operations.EditConfig,
    "copy_config": operations.CopyConfig,
    "validate": operations.Validate,
    "commit": operations.Commit,
    "discard_changes": operations.DiscardChanges,
    "delete_config": operations.DeleteConfig,
    "lock": operations.Lock,
    "unlock": operations.Unlock,
    "close_session": operations.CloseSession,
    "kill_session": operations.KillSession,
    "poweroff_machine": operations.PoweroffMachine,
    "reboot_machine": operations.RebootMachine
}
"""Dictionary of method names and corresponding :class:`~ncclient.operations.RPC` subclasses. It is used to lookup operations, e.g. `get_config` is mapped to :class:`~ncclient.operations.GetConfig`. It is thus possible to add additional operations to the :class:`Manager` API."""

def connect_ssh(*args, **kwds):
    """Initialize a :class:`Manager` over the SSH transport. For documentation of arguments see :meth:`ncclient.transport.SSHSession.connect`.

    The underlying :class:`ncclient.transport.SSHSession` is created with :data:`CAPABILITIES`. It is first instructed to :meth:`~ncclient.transport.SSHSession.load_known_hosts` and then  all the provided arguments are passed directly to its implementation of :meth:`~ncclient.transport.SSHSession.connect`.
    """
    session = transport.SSHSession(capabilities.Capabilities(CAPABILITIES))
    session.load_known_hosts()
    session.connect(*args, **kwds)
    return Manager(session)

connect = connect_ssh
"Same as :func:`connect_ssh`, since SSH is the default (and currently, the only) transport."

class OpExecutor(type):

    def __new__(cls, name, bases, attrs):
        def make_wrapper(op_cls):
            def wrapper(self, *args, **kwds):
                return self.execute(op_cls, *args, **kwds)
            wrapper.func_doc = op_cls.request.func_doc
            return wrapper
        for op_name, op_cls in OPERATIONS.iteritems():
            attrs[op_name] = make_wrapper(op_cls)
        return super(OpExecutor, cls).__new__(cls, name, bases, attrs)

class Manager(object):

    """For details on the expected behavior of the operations and their parameters refer to :rfc:`4741`.

    Manager instances are also context managers so you can use it like this::

        with manager.connect("host") as m:
            # do your stuff

    ... or like this::

        m = manager.connect("host")
        try:
            # do your stuff
        finally:
            m.close_session()
    """

    __metaclass__ = OpExecutor

    def __init__(self, session, timeout=30):
        self._session = session
        self._async_mode = False
        self._timeout = timeout
        self._raise_mode = operations.RaiseMode.ALL

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close_session()
        return False

    def __set_timeout(self, timeout):
        self._timeout = timeout

    def __set_async_mode(self, mode):
        self._async_mode = mode

    def __set_raise_mode(self, mode):
        assert(mode in (operations.RaiseMode.NONE, operations.RaiseMode.ERRORS, operations.RaiseMode.ALL))
        self._raise_mode = mode

    def execute(self, cls, *args, **kwds):
        return cls(self._session,
                   async=self._async_mode,
                   timeout=self._timeout,
                   raise_mode=self._raise_mode).request(*args, **kwds)

    def locked(self, target):
        """Returns a context manager for a lock on a datastore, where *target* is the name of the configuration datastore to lock, e.g.::

            with m.locked("running"):
                # do your stuff

        ... instead of::

            m.lock("running")
            try:
                # do your stuff
            finally:
                m.unlock("running")
        """
        return operations.LockContext(self._session, target)

    @property
    def client_capabilities(self):
        ":class:`~ncclient.capabilities.Capabilities` object representing the client's capabilities."
        return self._session._client_capabilities

    @property
    def server_capabilities(self):
        ":class:`~ncclient.capabilities.Capabilities` object representing the server's capabilities."
        return self._session._server_capabilities

    @property
    def session_id(self):
        "`session-id` assigned by the NETCONF server."
        return self._session.id

    @property
    def connected(self):
        "Whether currently connected to the NETCONF server."
        return self._session.connected

    async_mode = property(fget=lambda self: self._async_mode, fset=__set_async_mode)
    "Specify whether operations are executed asynchronously (`True`) or synchronously (`False`) (the default)."

    timeout = property(fget=lambda self: self._timeout, fset=__set_timeout)
    "Specify the timeout for synchronous RPC requests."

    raise_mode = property(fget=lambda self: self._raise_mode, fset=__set_raise_mode)
    "Specify which errors are raised as :exc:`~ncclient.operations.RPCError` exceptions. Valid values are the constants defined in :class:`~ncclient.operations.RaiseMode`. The default value is :attr:`~ncclient.operations.RaiseMode.ALL`."
