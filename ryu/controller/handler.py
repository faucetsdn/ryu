# Copyright (C) 2011-2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

import inspect
import logging
import sys

LOG = logging.getLogger('ryu.controller.handler')

# just represent OF datapath state. datapath specific so should be moved.
HANDSHAKE_DISPATCHER = "handshake"
CONFIG_DISPATCHER = "config"
MAIN_DISPATCHER = "main"
DEAD_DISPATCHER = "dead"


class _Caller(object):
    """Describe how to handle an event class.
    """

    def __init__(self, dispatchers, ev_source):
        """Initialize _Caller.

        :param dispatchers: A list of states or a state, in which this
                            is in effect.
                            None and [] mean all states.
        :param ev_source: The module which generates the event.
                          ev_cls.__module__ for set_ev_cls.
                          None for set_ev_handler.
        """
        self.dispatchers = dispatchers
        self.ev_source = ev_source


# should be named something like 'observe_event'
def set_ev_cls(ev_cls, dispatchers=None):
    """
    A decorator for Ryu application to declare an event handler.

    Decorated method will become an event handler.
    ev_cls is an event class whose instances this RyuApp wants to receive.
    dispatchers argument specifies one of the following negotiation phases
    (or a list of them) for which events should be generated for this handler.
    Note that, in case an event changes the phase, the phase before the change
    is used to check the interest.

    .. tabularcolumns:: |l|L|

    =========================================== ===============================
    Negotiation phase                           Description
    =========================================== ===============================
    ryu.controller.handler.HANDSHAKE_DISPATCHER Sending and waiting for hello
                                                message
    ryu.controller.handler.CONFIG_DISPATCHER    Version negotiated and sent
                                                features-request message
    ryu.controller.handler.MAIN_DISPATCHER      Switch-features message
                                                received and sent set-config
                                                message
    ryu.controller.handler.DEAD_DISPATCHER      Disconnect from the peer.  Or
                                                disconnecting due to some
                                                unrecoverable errors.
    =========================================== ===============================
    """
    def _set_ev_cls_dec(handler):
        if 'callers' not in dir(handler):
            handler.callers = {}
        for e in _listify(ev_cls):
            handler.callers[e] = _Caller(_listify(dispatchers), e.__module__)
        return handler
    return _set_ev_cls_dec


def set_ev_handler(ev_cls, dispatchers=None):
    def _set_ev_cls_dec(handler):
        if 'callers' not in dir(handler):
            handler.callers = {}
        for e in _listify(ev_cls):
            handler.callers[e] = _Caller(_listify(dispatchers), None)
        return handler
    return _set_ev_cls_dec


def _has_caller(meth):
    return hasattr(meth, 'callers')


def _listify(may_list):
    if may_list is None:
        may_list = []
    if not isinstance(may_list, list):
        may_list = [may_list]
    return may_list


def register_instance(i):
    for _k, m in inspect.getmembers(i, inspect.ismethod):
        # LOG.debug('instance %s k %s m %s', i, _k, m)
        if _has_caller(m):
            for ev_cls, c in m.callers.items():
                i.register_handler(ev_cls, m)


def _is_method(f):
    return inspect.isfunction(f) or inspect.ismethod(f)


def get_dependent_services(cls):
    services = []
    for _k, m in inspect.getmembers(cls, _is_method):
        if _has_caller(m):
            for ev_cls, c in m.callers.items():
                service = getattr(sys.modules[ev_cls.__module__],
                                  '_SERVICE_NAME', None)
                if service:
                    # avoid cls that registers the own events (like
                    # ofp_handler)
                    if cls.__module__ != service:
                        services.append(service)

    m = sys.modules[cls.__module__]
    services.extend(getattr(m, '_REQUIRED_APP', []))
    services = list(set(services))
    return services


def register_service(service):
    """
    Register the ryu application specified by 'service' as
    a provider of events defined in the calling module.

    If an application being loaded consumes events (in the sense of
    set_ev_cls) provided by the 'service' application, the latter
    application will be automatically loaded.

    This mechanism is used to e.g. automatically start ofp_handler if
    there are applications consuming OFP events.
    """
    frame = inspect.currentframe()
    m_name = frame.f_back.f_globals['__name__']
    m = sys.modules[m_name]
    m._SERVICE_NAME = service
