*******************
Ryu application API
*******************

Ryu application programming model
=================================

Threads, events, and event queues
---------------------------------

Ryu applications are single-threaded entities which implement
various functionalities in Ryu.  Events are messages between them.

Ryu applications send asynchronous events each other.
Besides that, there are some Ryu-internal event sources which
are not Ryu applications.  One of examples of such event sources
is OpenFlow controller.
While an event can currently contain arbitrary python objects,
it's discouraged to pass complex objects (eg. unpickleable objects)
between Ryu applications.

Each Ryu application has a receive queue for events.
The queue is FIFO and preserves the order of events.
Each Ryu application has a thread for event processing.
The thread keep draining the receive queue by dequeueing an event
and calling the appropritate event handler for the event type.
Because the event handler is called in the context of
the event processing thread, it should be careful for blocking.
I.e. while an event handler is blocked, no further events for
the Ryu application will be processed.

There are kinds of events which are used to implement synchronous
inter-application calls between Ryu applications.
While such requests uses the same machinary as ordinary
events, their replies are put on a queue dedicated to the transaction
to avoid deadlock.

While threads and queues is currently implemented with eventlet/greenlet,
a direct use of them in a Ryu application is strongly discouraged.

Contexts
--------
Contexts are ordinary python objects shared among Ryu applications.
The use of contexts are discouraged for new code.

Create a Ryu application
========================
A Ryu application is a python module which defines a subclass of
ryu.base.app_manager.RyuApp.
If two or more such classes are defined in a module, the first one
(by name order) will be picked by app_manager.
Ryu application is singleton: only single instance of a given Ryu
application is supported.

Observe events
==============
A Ryu application can register itself to listen for specific events
using ryu.controller.handler.set_ev_cls decorator.

Generate events
===============
A Ryu application can raise events by calling appropriate
ryu.base.app_manager.RyuApp's methods like send_event or
send_event_to_observers.

Event classes
=============
An event class describes a Ryu event generated in the system.
By convention, event class names are prefixed by "Event".
Events are generated either by the core part of Ryu or Ryu applications.
A Ryu application can register its interest for a specific type of
event by providing a handler method using
ryu.controller.handler.set_ev_cls decorator.

OpenFlow event classes
----------------------
ryu.controller.ofp_event module exports event classes which describe
receptions of OpenFlow messages from connected switches.
By convention, they are named as ryu.controller.ofp_event.EventOFPxxxx
where xxxx is the name of the corresponding OpenFlow message.
For example, EventOFPPacketIn for packet-in message.
The OpenFlow controller part of Ryu automatically decodes OpenFlow messages
received from switches and send these events to Ryu applications which
expressed an interest using ryu.controller.handler.set_ev_cls.
OpenFlow event classes are subclass of the following class.

.. autoclass:: ryu.controller.ofp_event.EventOFPMsgBase

See :ref:`ofproto_ref` for more info about OpenFlow messages.

ryu.base.app_manager.RyuApp
===========================

See :ref:`api_ref`.

ryu.controller.handler.set_ev_cls
=================================

.. autofunction:: ryu.controller.handler.set_ev_cls

ryu.controller.controller.Datapath
==================================

.. autoclass:: ryu.controller.controller.Datapath

ryu.controller.event.EventBase
==============================

.. autoclass:: ryu.controller.event.EventBase

ryu.controller.event.EventRequestBase
=====================================

.. autoclass:: ryu.controller.event.EventRequestBase

ryu.controller.event.EventReplyBase
===================================

.. autoclass:: ryu.controller.event.EventReplyBase

ryu.controller.ofp_event.EventOFPStateChange
============================================

.. autoclass:: ryu.controller.ofp_event.EventOFPStateChange

ryu.controller.ofp_event.EventOFPPortStateChange
================================================

.. autoclass:: ryu.controller.ofp_event.EventOFPPortStateChange

ryu.controller.dpset.EventDP
============================

.. autoclass:: ryu.controller.dpset.EventDP

ryu.controller.dpset.EventPortAdd
=================================

.. autoclass:: ryu.controller.dpset.EventPortAdd

ryu.controller.dpset.EventPortDelete
====================================

.. autoclass:: ryu.controller.dpset.EventPortDelete

ryu.controller.dpset.EventPortModify
====================================

.. autoclass:: ryu.controller.dpset.EventPortModify

ryu.controller.network.EventNetworkPort
=======================================

.. autoclass:: ryu.controller.network.EventNetworkPort

ryu.controller.network.EventNetworkDel
======================================

.. autoclass:: ryu.controller.network.EventNetworkDel

ryu.controller.network.EventMacAddress
======================================

.. autoclass:: ryu.controller.network.EventMacAddress

ryu.controller.tunnels.EventTunnelKeyAdd
========================================

.. autoclass:: ryu.controller.tunnels.EventTunnelKeyAdd

ryu.controller.tunnels.EventTunnelKeyDel
========================================

.. autoclass:: ryu.controller.tunnels.EventTunnelKeyDel

ryu.controller.tunnels.EventTunnelPort
======================================

.. autoclass:: ryu.controller.tunnels.EventTunnelPort
