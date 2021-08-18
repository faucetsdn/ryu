*********************
The First Application
*********************

Whetting Your Appetite
======================

If you want to manage network gear (switches, routers, etc) your
own way, you just need to write your own Ryu application. Your application
tells Ryu how you want to manage the gear. Then Ryu configures the
gear by using OpenFlow protocol, etc.

Writing Ryu applications is easy. They're just Python scripts.


Start Writing
=============

Here we show a Ryu application that makes an OpenFlow switch work as a dumb
layer 2 switch.

Open a text editor and create a new file with the following content:

.. code-block:: python
   
   from ryu.base import app_manager
   
   class L2Switch(app_manager.RyuApp):
       def __init__(self, *args, **kwargs):
           super(L2Switch, self).__init__(*args, **kwargs)

Ryu applications are just Python scripts so you can save the file with
any name, any extension, and any place you want. Let's name the file
'l2.py' in your home directory.

This application does nothing useful yet, however it's a complete Ryu
application. In fact, you can run this Ryu application::
   
   % ryu-manager ~/l2.py
   loading app /Users/fujita/l2.py
   instantiating app /Users/fujita/l2.py


All you have to do is define a new subclass of RyuApp to run
your Python script as a Ryu application.

Next let's add some functionality that sends a received packet to all
the ports.

.. code-block:: python
   
   from ryu.base import app_manager
   from ryu.controller import ofp_event
   from ryu.controller.handler import MAIN_DISPATCHER
   from ryu.controller.handler import set_ev_cls
   from ryu.ofproto import ofproto_v1_0
   
   class L2Switch(app_manager.RyuApp):
       OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

       def __init__(self, *args, **kwargs):
           super(L2Switch, self).__init__(*args, **kwargs)
   
       @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
       def packet_in_handler(self, ev):
           msg = ev.msg
           dp = msg.datapath
           ofp = dp.ofproto
           ofp_parser = dp.ofproto_parser

           actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

           data = None
           if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data

           out = ofp_parser.OFPPacketOut(
               datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
               actions=actions, data = data)
           dp.send_msg(out)


A new method 'packet_in_handler' is added to the L2Switch class. This is
called when Ryu receives an OpenFlow packet_in message. The trick is the
'set_ev_cls' decorator. This decorator tells Ryu when the decorated
function should be called.

The first argument of the decorator indicates which type of event this
function should be called for. As you might expect, every time Ryu gets a
packet_in message, this function is called.

The second argument indicates the state of the switch. You probably
want to ignore packet_in messages before the negotiation between Ryu
and the switch is finished. Using 'MAIN_DISPATCHER' as the second
argument means this function is called only after the negotiation
completes.

Next let's look at the first half of the 'packet_in_handler' function.

* ev.msg is an object that represents a packet_in data structure.

* msg.dp is an object that represents a datapath (switch).

* dp.ofproto and dp.ofproto_parser are objects that represent the
  OpenFlow protocol that Ryu and the switch negotiated.

Ready for the second half.

* OFPActionOutput class is used with a packet_out message to specify a
  switch port that you want to send the packet out of. This
  application uses the OFPP_FLOOD flag to indicate that the packet should
  be sent out on all ports.

* OFPPacketOut class is used to build a packet_out message.

* If you call Datapath class's send_msg method with a OpenFlow message
  class object, Ryu builds and sends the on-wire data format to the switch.


There, you finished implementing your first Ryu application. You are ready to
run a Ryu application that does something useful.


Is a dumb L2 switch is too dumb? You want to implement a learning L2
switch? Move to `the next step
<https://github.com/faucetsdn/ryu/blob/master/ryu/app/simple_switch.py>`_. You
can learn from the existing Ryu applications at `ryu/app
<https://github.com/faucetsdn/ryu/blob/master/ryu/app/>`_ directory and
`integrated tests
<https://github.com/faucetsdn/ryu/blob/master/ryu/tests/integrated/>`_
directory.
