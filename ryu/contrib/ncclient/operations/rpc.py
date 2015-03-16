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

from threading import Event, Lock
from uuid import uuid1

from ncclient.xml_ import *
from ncclient.transport import SessionListener

from errors import OperationError, TimeoutExpiredError, MissingCapabilityError

import logging
logger = logging.getLogger("ncclient.operations.rpc")


class RPCError(OperationError):

    "Represents an `rpc-error`. It is a type of :exc:`OperationError` and can be raised as such."
    
    tag_to_attr = {
        qualify("error-type"): "_type",
        qualify("error-tag"): "_tag",
        qualify("error-severity"): "_severity",
        qualify("error-info"): "_info",
        qualify("error-path"): "_path",
        qualify("error-message"): "_message"
    }
    
    def __init__(self, raw):
        self._raw = raw
        for attr in RPCError.tag_to_attr.values():
            setattr(self, attr, None)
        for subele in raw:
            attr = RPCError.tag_to_attr.get(subele.tag, None)
            if attr is not None:
                setattr(self, attr, subele.text if attr != "_info" else to_xml(subele) )
        if self.message is not None:
            OperationError.__init__(self, self.message)
        else:
            OperationError.__init__(self, self.to_dict())
    
    def to_dict(self):
        return dict([ (attr[1:], getattr(self, attr)) for attr in RPCError.tag_to_attr.values() ])
    
    @property
    def xml(self):
        "The `rpc-error` element as returned in XML."
        return self._raw
    
    @property
    def type(self):
        "The contents of the `error-type` element."
        return self._type
    
    @property
    def tag(self):
        "The contents of the `error-tag` element."
        return self._tag
    
    @property
    def severity(self):
        "The contents of the `error-severity` element."
        return self._severity
    
    @property
    def path(self):
        "The contents of the `error-path` element if present or `None`."
        return self._path
    
    @property
    def message(self):
        "The contents of the `error-message` element if present or `None`."
        return self._message
    
    @property
    def info(self):
        "XML string or `None`; representing the `error-info` element."
        return self._info


class RPCReply:

    """Represents an *rpc-reply*. Only concerns itself with whether the operation was successful.

    .. note::
        If the reply has not yet been parsed there is an implicit, one-time parsing overhead to
        accessing some of the attributes defined by this class.
    """
    
    ERROR_CLS = RPCError
    "Subclasses can specify a different error class, but it should be a subclass of `RPCError`."
    
    def __init__(self, raw):
        self._raw = raw
        self._parsed = False
        self._root = None
        self._errors = []

    def __repr__(self):
        return self._raw
    
    def parse(self):
        "Parses the *rpc-reply*."
        if self._parsed: return
        root = self._root = to_ele(self._raw) # The <rpc-reply> element
        # Per RFC 4741 an <ok/> tag is sent when there are no errors or warnings
        ok = root.find(qualify("ok"))
        if ok is None:
            # Create RPCError objects from <rpc-error> elements
            error = root.find(qualify("rpc-error"))
            if error is not None:
                for err in root.getiterator(error.tag):
                    # Process a particular <rpc-error>
                    self._errors.append(self.ERROR_CLS(err))
        self._parsing_hook(root)
        self._parsed = True

    def _parsing_hook(self, root):
        "No-op by default. Gets passed the *root* element for the reply."
        pass
    
    @property
    def xml(self):
        "*rpc-reply* element as returned."
        return self._raw
    
    @property
    def ok(self):
        "Boolean value indicating if there were no errors."
        return not self.errors # empty list => false
    
    @property
    def error(self):
        "Returns the first :class:`RPCError` and `None` if there were no errors."
        self.parse()
        if self._errors:
            return self._errors[0]
        else:
            return None
    
    @property
    def errors(self):
        "List of `RPCError` objects. Will be empty if there were no *rpc-error* elements in reply."
        self.parse()
        return self._errors


class RPCReplyListener(SessionListener): # internal use
    
    creation_lock = Lock()
    
    # one instance per session -- maybe there is a better way??
    def __new__(cls, session):
        with RPCReplyListener.creation_lock:
            instance = session.get_listener_instance(cls)
            if instance is None:
                instance = object.__new__(cls)
                instance._lock = Lock()
                instance._id2rpc = {}
                #instance._pipelined = session.can_pipeline
                session.add_listener(instance)
            return instance

    def register(self, id, rpc):
        with self._lock:
            self._id2rpc[id] = rpc

    def callback(self, root, raw):
        tag, attrs = root
        if tag != qualify("rpc-reply"):
            return
        for key in attrs: # in the <rpc-reply> attributes
            if key == "message-id": # if we found msgid attr
                id = attrs[key] # get the msgid
                with self._lock:
                    try:
                        rpc = self._id2rpc[id] # the corresponding rpc
                        logger.debug("Delivering to %r", rpc)
                        rpc.deliver_reply(raw)
                    except KeyError:
                        raise OperationError("Unknown 'message-id': %s", id)
                    # no catching other exceptions, fail loudly if must
                    else:
                        # if no error delivering, can del the reference to the RPC
                        del self._id2rpc[id]
                        break
        else:
            raise OperationError("Could not find 'message-id' attribute in <rpc-reply>")
    
    def errback(self, err):
        try:
            for rpc in self._id2rpc.values():
                rpc.deliver_error(err)
        finally:
            self._id2rpc.clear()


class RaiseMode(object):

    NONE = 0
    "Don't attempt to raise any type of `rpc-error` as :exc:`RPCError`."

    ERRORS = 1
    "Raise only when the `error-type` indicates it is an honest-to-god error."

    ALL = 2
    "Don't look at the `error-type`, always raise."


class RPC(object):
    
    """Base class for all operations, directly corresponding to *rpc* requests. Handles making the request, and taking delivery of the reply."""

    DEPENDS = []
    """Subclasses can specify their dependencies on capabilities as a list of URI's or abbreviated names, e.g. ':writable-running'. These are verified at the time of instantiation. If the capability is not available, :exc:`MissingCapabilityError` is raised."""
    
    REPLY_CLS = RPCReply
    "By default :class:`RPCReply`. Subclasses can specify a :class:`RPCReply` subclass."
    
    def __init__(self, session, async=False, timeout=30, raise_mode=RaiseMode.NONE):
        """
        *session* is the :class:`~ncclient.transport.Session` instance

        *async* specifies whether the request is to be made asynchronously, see :attr:`is_async`

        *timeout* is the timeout for a synchronous request, see :attr:`timeout`

        *raise_mode* specifies the exception raising mode, see :attr:`raise_mode`
        """
        self._session = session
        try:
            for cap in self.DEPENDS:
                self._assert(cap)
        except AttributeError:
            pass
        self._async = async
        self._timeout = timeout
        self._raise_mode = raise_mode
        self._id = uuid1().urn # Keeps things simple instead of having a class attr with running ID that has to be locked
        self._listener = RPCReplyListener(session)
        self._listener.register(self._id, self)
        self._reply = None
        self._error = None
        self._event = Event()
    
    def _wrap(self, subele):
        # internal use
        ele = new_ele("rpc", {"message-id": self._id})
        ele.append(subele)
        return to_xml(ele)

    def _request(self, op):
        """Implementations of :meth:`request` call this method to send the request and process the reply.
        
        In synchronous mode, blocks until the reply is received and returns :class:`RPCReply`. Depending on the :attr:`raise_mode` a `rpc-error` element in the reply may lead to an :exc:`RPCError` exception.
        
        In asynchronous mode, returns immediately, returning `self`. The :attr:`event` attribute will be set when the reply has been received (see :attr:`reply`) or an error occured (see :attr:`error`).
        
        *op* is the operation to be requested as an :class:`~xml.etree.ElementTree.Element`
        """
        logger.info('Requesting %r', self.__class__.__name__)
        req = self._wrap(op)
        self._session.send(req)
        if self._async:
            logger.debug('Async request, returning %r', self)
            return self
        else:
            logger.debug('Sync request, will wait for timeout=%r', self._timeout)
            self._event.wait(self._timeout)
            if self._event.isSet():
                if self._error:
                    # Error that prevented reply delivery
                    raise self._error
                self._reply.parse()
                if self._reply.error is not None:
                    # <rpc-error>'s [ RPCError ]
                    if self._raise_mode == RaiseMode.ALL:
                        raise self._reply.error
                    elif (self._raise_mode == RaiseMode.ERRORS and self._reply.error.type == "error"):
                        raise self._reply.error
                return self._reply
            else:
                raise TimeoutExpiredError

    def request(self):
        """Subclasses must implement this method. Typically only the request needs to be built as an
        :class:`~xml.etree.ElementTree.Element` and everything else can be handed off to
        :meth:`_request`."""
        pass
    
    def _assert(self, capability):
        """Subclasses can use this method to verify that a capability is available with the NETCONF
        server, before making a request that requires it. A :exc:`MissingCapabilityError` will be
        raised if the capability is not available."""
        if capability not in self._session.server_capabilities:
            raise MissingCapabilityError('Server does not support [%s]' % capability)
    
    def deliver_reply(self, raw):
        # internal use
        self._reply = self.REPLY_CLS(raw)
        self._event.set()

    def deliver_error(self, err):
        # internal use
        self._error = err
        self._event.set()
    
    @property
    def reply(self):
        ":class:`RPCReply` element if reply has been received or `None`"
        return self._reply
    
    @property
    def error(self):
        """:exc:`Exception` type if an error occured or `None`.
        
        .. note::
            This represents an error which prevented a reply from being received. An *rpc-error*
            does not fall in that category -- see `RPCReply` for that.
        """
        return self._error
    
    @property
    def id(self):
        "The *message-id* for this RPC."
        return self._id
    
    @property
    def session(self):
        "The `~ncclient.transport.Session` object associated with this RPC."
        return self._session

    @property
    def event(self):
        """:class:`~threading.Event` that is set when reply has been received or when an error preventing
        delivery of the reply occurs.
        """
        return self._event

    def __set_async(self, async=True):
        self._async = async
        if async and not session.can_pipeline:
            raise UserWarning('Asynchronous mode not supported for this device/session')

    def __set_raise_mode(self, mode):
        assert(choice in ("all", "errors", "none"))
        self._raise_mode = mode

    def __set_timeout(self, timeout):
        self._timeout = timeout

    raise_mode = property(fget=lambda self: self._raise_mode, fset=__set_raise_mode)
    """Depending on this exception raising mode, an `rpc-error` in the reply may be raised as an :exc:`RPCError` exception. Valid values are the constants defined in :class:`RaiseMode`. """
    
    is_async = property(fget=lambda self: self._async, fset=__set_async)
    """Specifies whether this RPC will be / was requested asynchronously. By default RPC's are synchronous."""
    
    timeout = property(fget=lambda self: self._timeout, fset=__set_timeout)
    """Timeout in seconds for synchronous waiting defining how long the RPC request will block on a reply before raising :exc:`TimeoutExpiredError`.
    
    Irrelevant for asynchronous usage.
    """
