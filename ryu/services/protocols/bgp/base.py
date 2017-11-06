# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
  Defines some base class related to managing green threads.
"""
from __future__ import absolute_import

import abc
from collections import OrderedDict
import logging
import socket
import time
import traceback
import weakref

import netaddr
import six

from ryu.lib import hub
from ryu.lib import sockopt
from ryu.lib import ip
from ryu.lib.hub import Timeout
from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import RF_L2_EVPN
from ryu.lib.packet.bgp import RF_IPv4_FLOWSPEC
from ryu.lib.packet.bgp import RF_IPv6_FLOWSPEC
from ryu.lib.packet.bgp import RF_VPNv4_FLOWSPEC
from ryu.lib.packet.bgp import RF_VPNv6_FLOWSPEC
from ryu.lib.packet.bgp import RF_L2VPN_FLOWSPEC
from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.services.protocols.bgp.utils.circlist import CircularListType
from ryu.services.protocols.bgp.utils.evtlet import LoopingCall


# Logger instance for this module.
LOG = logging.getLogger('bgpspeaker.base')

# Pointer to active/available OrderedDict.
OrderedDict = OrderedDict


# Currently supported address families.
SUPPORTED_GLOBAL_RF = {
    RF_IPv4_UC,
    RF_IPv6_UC,
    RF_IPv4_VPN,
    RF_RTC_UC,
    RF_IPv6_VPN,
    RF_L2_EVPN,
    RF_IPv4_FLOWSPEC,
    RF_IPv6_FLOWSPEC,
    RF_VPNv4_FLOWSPEC,
    RF_VPNv6_FLOWSPEC,
    RF_L2VPN_FLOWSPEC,
}


# Various error codes
ACTIVITY_ERROR_CODE = 100
RUNTIME_CONF_ERROR_CODE = 200
BIN_ERROR = 300
NET_CTRL_ERROR_CODE = 400
API_ERROR_CODE = 500
PREFIX_ERROR_CODE = 600
BGP_PROCESSOR_ERROR_CODE = 700
CORE_ERROR_CODE = 800

# Registry of custom exceptions
# Key: code:sub-code
# Value: exception class
_EXCEPTION_REGISTRY = {}


class BGPSException(Exception):
    """Base exception class for all BGPS related exceptions.
    """

    CODE = 1
    SUB_CODE = 1
    DEF_DESC = 'Unknown exception.'

    def __init__(self, desc=None):
        super(BGPSException, self).__init__()
        if not desc:
            desc = self.__class__.DEF_DESC
        kls = self.__class__
        self.message = '%d.%d - %s' % (kls.CODE, kls.SUB_CODE, desc)

    def __repr__(self):
        kls = self.__class__
        return '<%s(desc=%s)>' % (kls, self.message)

    def __str__(self, *args, **kwargs):
        return self.message


def add_bgp_error_metadata(code, sub_code, def_desc='unknown'):
    """Decorator for all exceptions that want to set exception class meta-data.
    """
    # Check registry if we already have an exception with same code/sub-code
    if _EXCEPTION_REGISTRY.get((code, sub_code)) is not None:
        raise ValueError('BGPSException with code %d and sub-code %d '
                         'already defined.' % (code, sub_code))

    def decorator(subclass):
        """Sets class constants for exception code and sub-code.

        If given class is sub-class of BGPSException we sets class constants.
        """
        if issubclass(subclass, BGPSException):
            _EXCEPTION_REGISTRY[(code, sub_code)] = subclass
            subclass.CODE = code
            subclass.SUB_CODE = sub_code
            subclass.DEF_DESC = def_desc
        return subclass
    return decorator


@add_bgp_error_metadata(code=ACTIVITY_ERROR_CODE,
                        sub_code=1,
                        def_desc='Unknown activity exception.')
class ActivityException(BGPSException):
    """Base class for exceptions related to Activity.
    """
    pass


@six.add_metaclass(abc.ABCMeta)
class Activity(object):
    """Base class for a thread of execution that provides some custom settings.

    Activity is also a container of other activities or threads that it has
    started. Inside a Activity you should always use one of the spawn method
    to start another activity or greenthread. Activity is also holds pointers
    to sockets that it or its child activities of threads have create.
    """

    def __init__(self, name=None):
        self._name = name
        if self._name is None:
            self._name = 'UnknownActivity: ' + str(time.time())
        self._child_thread_map = weakref.WeakValueDictionary()
        self._child_activity_map = weakref.WeakValueDictionary()
        self._asso_socket_map = weakref.WeakValueDictionary()
        self._timers = weakref.WeakValueDictionary()
        self._started = False

    @property
    def name(self):
        return self._name

    @property
    def started(self):
        return self._started

    def _validate_activity(self, activity):
        """Checks the validity of the given activity before it can be started.
        """
        if not self._started:
            raise ActivityException(desc='Tried to spawn a child activity'
                                    ' before Activity was started.')

        if activity.started:
            raise ActivityException(desc='Tried to start an Activity that was '
                                    'already started.')

    def _spawn_activity(self, activity, *args, **kwargs):
        """Starts *activity* in a new thread and passes *args* and *kwargs*.

        Maintains pointer to this activity and stops *activity* when this
        activity is stopped.
        """
        self._validate_activity(activity)

        # Spawn a new greenthread for given activity
        greenthread = hub.spawn(activity.start, *args, **kwargs)
        self._child_thread_map[activity.name] = greenthread
        self._child_activity_map[activity.name] = activity
        return greenthread

    def _spawn_activity_after(self, seconds, activity, *args, **kwargs):
        self._validate_activity(activity)

        # Schedule to spawn a new greenthread after requested delay
        greenthread = hub.spawn_after(seconds, activity.start, *args,
                                      **kwargs)
        self._child_thread_map[activity.name] = greenthread
        self._child_activity_map[activity.name] = activity
        return greenthread

    def _validate_callable(self, callable_):
        if callable_ is None:
            raise ActivityException(desc='Callable cannot be None')

        if not hasattr(callable_, '__call__'):
            raise ActivityException(desc='Currently only supports instances'
                                    ' that have __call__ as callable which'
                                    ' is missing in given arg.')
        if not self._started:
            raise ActivityException(desc='Tried to spawn a child thread '
                                    'before this Activity was started.')

    def _spawn(self, name, callable_, *args, **kwargs):
        self._validate_callable(callable_)
        greenthread = hub.spawn(callable_, *args, **kwargs)
        self._child_thread_map[name] = greenthread
        return greenthread

    def _spawn_after(self, name, seconds, callable_, *args, **kwargs):
        self._validate_callable(callable_)
        greenthread = hub.spawn_after(seconds, callable_, *args, **kwargs)
        self._child_thread_map[name] = greenthread
        return greenthread

    def _create_timer(self, name, func, *arg, **kwarg):
        timer = LoopingCall(func, *arg, **kwarg)
        self._timers[name] = timer
        return timer

    @abc.abstractmethod
    def _run(self, *args, **kwargs):
        """Main activity of this class.

        Can launch other activity/callables here.
        Sub-classes should override this method.
        """
        raise NotImplementedError()

    def start(self, *args, **kwargs):
        """Starts the main activity of this class.

        Calls *_run* and calls *stop* when *_run* is finished.
        This method should be run in a new greenthread as it may not return
        immediately.
        """
        if self.started:
            raise ActivityException(desc='Activity already started')

        self._started = True
        try:
            self._run(*args, **kwargs)
        except BGPSException:
            LOG.error(traceback.format_exc())
        finally:
            if self.started:  # could have been stopped somewhere else
                self.stop()

    def pause(self, seconds=0):
        """Relinquishes hub for given number of seconds.

        In other words is puts to sleep to give other greenthread a chance to
        run.
        """
        hub.sleep(seconds)

    def _stop_child_activities(self, name=None):
        """Stop all child activities spawn by this activity.
        """
        # Makes a list copy of items() to avoid dictionary size changed
        # during iteration
        for child_name, child in list(self._child_activity_map.items()):
            if name is not None and name != child_name:
                continue
            LOG.debug('%s: Stopping child activity %s ', self.name, child_name)
            if child.started:
                child.stop()
            self._child_activity_map.pop(child_name, None)

    def _stop_child_threads(self, name=None):
        """Stops all threads spawn by this activity.
        """
        for thread_name, thread in list(self._child_thread_map.items()):
            if name is not None and thread_name is name:
                LOG.debug('%s: Stopping child thread %s',
                          self.name, thread_name)
                thread.kill()
                self._child_thread_map.pop(thread_name, None)

    def _close_asso_sockets(self):
        """Closes all the sockets linked to this activity.
        """
        for sock_name, sock in list(self._asso_socket_map.items()):
            LOG.debug('%s: Closing socket %s - %s', self.name, sock_name, sock)
            sock.close()

    def _stop_timers(self):
        for timer_name, timer in list(self._timers.items()):
            LOG.debug('%s: Stopping timer %s', self.name, timer_name)
            timer.stop()

    def stop(self):
        """Stops all child threads and activities and closes associated
        sockets.

        Re-initializes this activity to be able to start again.
        Raise `ActivityException` if activity is not currently started.
        """
        if not self.started:
            raise ActivityException(desc='Cannot call stop when activity is '
                                    'not started or has been stopped already.')

        LOG.debug('Stopping activity %s.', self.name)
        self._stop_timers()
        self._stop_child_activities()
        self._stop_child_threads()
        self._close_asso_sockets()

        # Setup activity for start again.
        self._started = False
        self._asso_socket_map = weakref.WeakValueDictionary()
        self._child_activity_map = weakref.WeakValueDictionary()
        self._child_thread_map = weakref.WeakValueDictionary()
        self._timers = weakref.WeakValueDictionary()
        LOG.debug('Stopping activity %s finished.', self.name)

    def _canonicalize_ip(self, ip):
        addr = netaddr.IPAddress(ip)
        if addr.is_ipv4_mapped():
            ip = str(addr.ipv4())
        return ip

    def get_remotename(self, sock):
        addr, port = sock.getpeername()[:2]
        return self._canonicalize_ip(addr), str(port)

    def get_localname(self, sock):
        addr, port = sock.getsockname()[:2]
        return self._canonicalize_ip(addr), str(port)

    def _create_listen_socket(self, family, loc_addr):
        s = socket.socket(family)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(loc_addr)
        s.listen(1)
        return s

    def _listen_socket_loop(self, s, conn_handle):
        while True:
            sock, client_address = s.accept()
            client_address, port = self.get_remotename(sock)
            LOG.debug('Connect request received from client for port'
                      ' %s:%s', client_address, port)
            client_name = self.name + '_client@' + client_address
            self._asso_socket_map[client_name] = sock
            self._spawn(client_name, conn_handle, sock)

    def _listen_tcp(self, loc_addr, conn_handle):
        """Creates a TCP server socket which listens on `port` number.

        For each connection `server_factory` starts a new protocol.
        """
        info = socket.getaddrinfo(loc_addr[0], loc_addr[1], socket.AF_UNSPEC,
                                  socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
        listen_sockets = {}
        for res in info:
            af, socktype, proto, _, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if af == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

                sock.bind(sa)
                sock.listen(50)
                listen_sockets[sa] = sock
            except socket.error as e:
                LOG.error('Error creating socket: %s', e)

                if sock:
                    sock.close()

        count = 0
        server = None
        for sa in listen_sockets:
            name = self.name + '_server@' + str(sa[0])
            self._asso_socket_map[name] = listen_sockets[sa]
            if count == 0:
                import eventlet
                server = eventlet.spawn(self._listen_socket_loop,
                                        listen_sockets[sa], conn_handle)

                self._child_thread_map[name] = server
                count += 1
            else:
                server = self._spawn(name, self._listen_socket_loop,
                                     listen_sockets[sa], conn_handle)
        return server, listen_sockets

    def _connect_tcp(self, peer_addr, conn_handler, time_out=None,
                     bind_address=None, password=None):
        """Creates a TCP connection to given peer address.

        Tries to create a socket for `timeout` number of seconds. If
        successful, uses the socket instance to start `client_factory`.
        The socket is bound to `bind_address` if specified.
        """
        LOG.debug('Connect TCP called for %s:%s', peer_addr[0], peer_addr[1])
        if ip.valid_ipv4(peer_addr[0]):
            family = socket.AF_INET
        else:
            family = socket.AF_INET6
        with Timeout(time_out, socket.error):
            sock = socket.socket(family)
            if bind_address:
                sock.bind(bind_address)
            if password:
                sockopt.set_tcp_md5sig(sock, peer_addr[0], password)
            sock.connect(peer_addr)
            # socket.error exception is raised in case of timeout and
            # the following code is executed only when the connection
            # is established.

        # Connection name for pro-active connection is made up of
        # local end address + remote end address
        local = self.get_localname(sock)[0]
        remote = self.get_remotename(sock)[0]
        conn_name = ('L: ' + local + ', R: ' + remote)
        self._asso_socket_map[conn_name] = sock
        # If connection is established, we call connection handler
        # in a new thread.
        self._spawn(conn_name, conn_handler, sock)
        return sock


#
# Sink
#
class Sink(object):
    """An entity to which we send out messages (eg. BGP routes)."""

    #
    # OutgoingMsgList
    #
    # A circular list type in which objects are linked to each
    # other using the 'next_sink_out_route' and 'prev_sink_out_route'
    # attributes.
    #
    OutgoingMsgList = CircularListType(next_attr_name='next_sink_out_route',
                                       prev_attr_name='prev_sink_out_route')

    # Next available index that can identify an instance uniquely.
    idx = 0

    @staticmethod
    def next_index():
        """Increments the sink index and returns the value."""
        Sink.idx += 1
        return Sink.idx

    def __init__(self):
        # A small integer that represents this sink.
        self.index = Sink.next_index()

        # Create an event for signal enqueuing.
        from .utils.evtlet import EventletIOFactory
        self.outgoing_msg_event = EventletIOFactory.create_custom_event()

        self.messages_queued = 0
        # List of msgs. that are to be sent to this peer. Each item
        # in the list is an instance of OutgoingRoute.
        self.outgoing_msg_list = Sink.OutgoingMsgList()

    def clear_outgoing_msg_list(self):
        self.outgoing_msg_list = Sink.OutgoingMsgList()

    def enque_outgoing_msg(self, msg):
        self.outgoing_msg_list.append(msg)
        self.outgoing_msg_event.set()

        self.messages_queued += 1

    def enque_first_outgoing_msg(self, msg):
        self.outgoing_msg_list.prepend(msg)
        self.outgoing_msg_event.set()

    def __iter__(self):
        return self

    def next(self):
        """Pops and returns the first outgoing message from the list.

        If message list currently has no messages, the calling thread will
        be put to sleep until we have at-least one message in the list that
        can be popped and returned.
        """
        # We pick the first outgoing available and send it.
        outgoing_msg = self.outgoing_msg_list.pop_first()
        # If we do not have any outgoing msg., we wait.
        if outgoing_msg is None:
            self.outgoing_msg_event.clear()
            self.outgoing_msg_event.wait()
            outgoing_msg = self.outgoing_msg_list.pop_first()

        return outgoing_msg

    # For Python 3 compatibility
    __next__ = next


#
# Source
#
class Source(object):
    """An entity that gives us BGP routes. A BGP peer, for example."""

    def __init__(self, version_num):
        # Number that is currently being used to stamp information
        # received from this source. We will bump this number up when
        # the information that is now expected from the source belongs
        # to a different logical batch. This mechanism can be used to
        # identify stale information.
        self.version_num = version_num


class FlexinetPeer(Source, Sink):
    def __init__(self):
        # Initialize source and sink
        Source.__init__(self, 1)
        Sink.__init__(self)


# Registry of validators for configuration/settings.
_VALIDATORS = {}


def validate(**kwargs):
    """Defines a decorator to register a validator with a name for look-up.

    If name is not provided we use function name as name of the validator.
    """
    def decorator(func):
        _VALIDATORS[kwargs.pop('name', func.__name__)] = func
        return func

    return decorator


def get_validator(name):
    """Returns a validator registered for given name.
    """
    return _VALIDATORS.get(name)
