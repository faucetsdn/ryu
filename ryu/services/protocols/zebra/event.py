# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
Events for Zebra protocol service.
"""

import inspect
import logging

from ryu import utils
from ryu.controller import event
from ryu.lib.packet import zebra


LOG = logging.getLogger(__name__)
MOD = utils.import_module(__name__)

ZEBRA_EVENTS = []


class EventZebraBase(event.EventBase):
    """
    The base class for Zebra protocol service event class.

    The subclasses have at least ``zclient`` and the same attributes with
    :py:class: `ryu.lib.packet.zebra.ZebraMessage`.
    ``zclient`` is an instance of Zebra client class. See
    :py:class: `ryu.services.protocols.zebra.client.zclient.ZClient` or
    :py:class: `ryu.services.protocols.zebra.server.zserver.ZClient`.

    The subclasses are named as::

        ``"Event" + <Zebra message body class name>``

    For Example, if the service received ZEBRA_INTERFACE_ADD message,
    the body class should be
    :py:class: `ryu.lib.packet.zebra.ZebraInterfaceAdd`, then the event
    class will be named as::

        "Event" + "ZebraInterfaceAdd" = "EventZebraInterfaceAdd"

    ``msg`` argument must be an instance of
    :py:class: `ryu.lib.packet.zebra.ZebraMessage` and used to extract the
    attributes for the event classes.
    """

    def __init__(self, zclient, msg):
        super(EventZebraBase, self).__init__()
        assert isinstance(msg, zebra.ZebraMessage)
        self.__dict__ = msg.__dict__
        self.zclient = zclient

    def __repr__(self):
        m = ', '.join(
            ['%s=%r' % (k, v)
             for k, v in self.__dict__.items() if not k.startswith('_')])
        return "%s(%s)" % (self.__class__.__name__, m)

    __str__ = __repr__


def _event_name(body_cls):
    return 'Event%s' % body_cls.__name__


def message_to_event(zclient, msg):
    """
    Converts Zebra protocol message instance to Zebra protocol service
    event instance.

    If corresponding event class is not defined, returns None.

    :param zclient: Zebra client instance.
    :param msg: Zebra protocol message.
    :return: Zebra protocol service event.
    """
    if not isinstance(msg, zebra.ZebraMessage):
        return None

    body_cls = msg.get_body_class(msg.version, msg.command)
    ev_cls = getattr(MOD, _event_name(body_cls), None)
    if ev_cls is None:
        return None

    return ev_cls(zclient, msg)


def _define_event_class(body_cls):
    name = _event_name(body_cls)

    event_cls = type(name, (EventZebraBase,), {})
    globals()[name] = event_cls

    return event_cls


def _generate_event_classes():
    for zebra_cls in zebra.__dict__.values():
        if (not inspect.isclass(zebra_cls)
                or not issubclass(zebra_cls, zebra._ZebraMessageBody)
                or zebra_cls.__name__.startswith('_')):
            continue

        ev = _define_event_class(zebra_cls)
        # LOG.debug('Generated Zebra event: %s' % ev)
        ZEBRA_EVENTS.append(ev)


_generate_event_classes()
