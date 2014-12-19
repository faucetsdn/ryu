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
OpenFlow event classes have at least the following attributes.

.. tabularcolumns:: |l|L|

============ =============================================================
Attribute    Description
============ =============================================================
msg          An object which describes the corresponding OpenFlow message.
msg.datapath A ryu.controller.controller.Datapath instance which describes
             an OpenFlow switch from which we received this OpenFlow message.
============ =============================================================

The msg object has some more additional members whose values are extracted
from the original OpenFlow message.
See :ref:`ofproto_ref` for more info about OpenFlow messages.

ryu.base.app_manager.RyuApp
===========================

See :ref:`api_ref`.

ryu.controller.handler.set_ev_cls(ev_cls, dispatchers=None)
===========================================================

A decorator for Ryu application to declare an event handler.
Decorated method will become an event handler.
ev_cls is an event class whose instances this RyuApp wants to receive.
dispatchers argument specifies one of the following negotiation phases
(or a list of them) for which events should be generated for this handler.
Note that, in case an event changes the phase, the phase before the change
is used to check the interest.

.. tabularcolumns:: |l|L|

=========================================== ==================================
Negotiation phase                           Description
=========================================== ==================================
ryu.controller.handler.HANDSHAKE_DISPATCHER Sending and waiting for hello
                                            message
ryu.controller.handler.CONFIG_DISPATCHER    Version negotiated and sent
                                            features-request message
ryu.controller.handler.MAIN_DISPATCHER      Switch-features message received
                                            and sent set-config message
ryu.controller.handler.DEAD_DISPATCHER      Disconnect from the peer.  Or
                                            disconnecting due to some
                                            unrecoverable errors.
=========================================== ==================================

ryu.controller.controller.Datapath
==================================

A class to describe an OpenFlow switch connected to this controller.
An instance has the following attributes.

.. tabularcolumns:: |l|L|

====================================== =======================================
Attribute                              Description
====================================== =======================================
id                                     64-bit OpenFlow Datapath ID.
                                       Only available for
                                       ryu.controller.handler.MAIN_DISPATCHER
                                       phase.
ofproto                                A module which exports OpenFlow
                                       definitions, mainly constants appeared
                                       in the specification, for the
                                       negotiated OpenFlow version.  For
                                       example, ryu.ofproto.ofproto_v1_0 for
                                       OpenFlow 1.0.
ofproto_parser                         A module which exports OpenFlow wire
                                       message encoder and decoder for the
                                       negotiated OpenFlow version.  For
                                       example, ryu.ofproto.ofproto_v1_0_parser
                                       for OpenFlow 1.0.
ofproto_parser.OFPxxxx(datapath, ....) A callable to prepare an OpenFlow
                                       message for the given switch.  It can
                                       be sent with Datapath.send_msg later.
                                       xxxx is a name of the message.  For
                                       example OFPFlowMod for flow-mod
                                       message.  Arguemnts depend on the
                                       message.
set_xid(self, msg)                     Generate an OpenFlow XID and put it
                                       in msg.xid.
send_msg(self, msg)                    Queue an OpenFlow message to send to
                                       the corresponding switch.  If msg.xid
                                       is None, set_xid is automatically
                                       called on the message before queueing.
send_packet_out                        deprecated
send_flow_mod                          deprecated
send_flow_del                          deprecated
send_delete_all_flows                  deprecated
send_barrier                           Queue an OpenFlow barrier message to
                                       send to the switch.
send_nxt_set_flow_format               deprecated
is_reserved_port                       deprecated
====================================== =======================================

ryu.controller.event.EventBase
==============================

The base of all event classes.
A Ryu application can define its own event type by creating a subclass.

ryu.controller.event.EventRequestBase
=====================================

The base class for synchronous request for RyuApp.send_request.

ryu.controller.event.EventReplyBase
===================================

The base class for synchronous request reply for RyuApp.send_reply.

ryu.controller.ofp_event.EventOFPStateChange
============================================

An event class for negotiation phase change notification.
An instance of this class is sent to observer after changing
the negotiation phase.
An instance has at least the following attributes.

========= ====================================================================
Attribute Description
========= ====================================================================
datapath  ryu.controller.controller.Datapath instance of the switch
========= ====================================================================

ryu.controller.dpset.EventDP
============================

An event class to notify connect/disconnect of a switch.
For OpenFlow switches, one can get the same notification by observing
ryu.controller.ofp_event.EventOFPStateChange.
An instance has at least the following attributes.

========= ====================================================================
Attribute Description
========= ====================================================================
dp        A ryu.controller.controller.Datapath instance of the switch
enter     True when the switch connected to our controller.  False for
          disconnect.
========= ====================================================================

ryu.controller.dpset.EventPortAdd
=================================

An event class for switch port status notification.
This event is generated when a new port is added to a switch.
For OpenFlow switches, one can get the same notification by observing
ryu.controller.ofp_event.EventOFPPortStatus.
An instance has at least the following attributes.

========= ====================================================================
Attribute Description
========= ====================================================================
dp        A ryu.controller.controller.Datapath instance of the switch
port      port number
========= ====================================================================

ryu.controller.dpset.EventPortDelete
====================================

An event class for switch port status notification.
This event is generated when a port is removed from a switch.
For OpenFlow switches, one can get the same notification by observing
ryu.controller.ofp_event.EventOFPPortStatus.
An instance has at least the following attributes.

========= ====================================================================
Attribute Description
========= ====================================================================
dp        A ryu.controller.controller.Datapath instance of the switch
port      port number
========= ====================================================================

ryu.controller.dpset.EventPortModify
====================================

An event class for switch port status notification.
This event is generated when some attribute of a port is changed.
For OpenFlow switches, one can get the same notification by observing
ryu.controller.ofp_event.EventOFPPortStatus.
An instance has at least the following attributes.

========= ====================================================================
Attribute Description
========= ====================================================================
dp        A ryu.controller.controller.Datapath instance of the switch
port      port number
========= ====================================================================

ryu.controller.network.EventNetworkPort
=======================================

An event class for notification of port arrival and deperture.
This event is generated when a port is introduced to or removed from a network
by the REST API.
An instance has at least the following attributes.

========== ===================================================================
Attribute  Description
========== ===================================================================
network_id Network ID
dpid       OpenFlow Datapath ID of the switch to which the port belongs.
port_no    OpenFlow port number of the port
add_del    True for adding a port.  False for removing a port.
========== ===================================================================

ryu.controller.network.EventNetworkDel
======================================

An event class for network deletion.
This event is generated when a network is deleted by the REST API.
An instance has at least the following attributes.

========== ===================================================================
Attribute  Description
========== ===================================================================
network_id Network ID
========== ===================================================================

ryu.controller.network.EventMacAddress
======================================

An event class for end-point MAC address registration.
This event is generated when a end-point MAC address is updated
by the REST API.
An instance has at least the following attributes.

=========== ==================================================================
Attribute   Description
=========== ==================================================================
network_id  Network ID
dpid        OpenFlow Datapath ID of the switch to which the port belongs.
port_no     OpenFlow port number of the port
mac_address The old MAC address of the port if add_del is False.  Otherwise
            the new MAC address.
add_del     False if this event is a result of a port removal.  Otherwise
            True.
=========== ==================================================================

ryu.controller.tunnels.EventTunnelKeyAdd
========================================

An event class for tunnel key registration.
This event is generated when a tunnel key is registered or updated
by the REST API.
An instance has at least the following attributes.

=========== ==================================================================
Attribute   Description
=========== ==================================================================
network_id  Network ID
tunnel_key  Tunnel Key
=========== ==================================================================

ryu.controller.tunnels.EventTunnelKeyDel
========================================

An event class for tunnel key registration.
This event is generated when a tunnel key is removed by the REST API.
An instance has at least the following attributes.

=========== ==================================================================
Attribute   Description
=========== ==================================================================
network_id  Network ID
tunnel_key  Tunnel Key
=========== ==================================================================

ryu.controller.tunnels.EventTunnelPort
======================================

An event class for tunnel port registration.
This event is generated when a tunnel port is added or removed by the REST API.
An instance has at least the following attributes.

=========== ==================================================================
Attribute   Description
=========== ==================================================================
dpid        OpenFlow Datapath ID
port_no     OpenFlow port number
remote_dpid OpenFlow port number of the tunnel peer
add_del     True for adding a tunnel.  False for removal.
=========== ==================================================================
