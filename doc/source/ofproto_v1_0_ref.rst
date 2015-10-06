*************************************
OpenFlow v1.0 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_0_parser

Controller-to-Switch Messages
=============================

Handshake
---------

.. autoclass:: OFPFeaturesRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-5-features_request.packet.json

.. autoclass:: OFPSwitchFeatures

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-6-ofp_switch_features.packet.json

Switch Configuration
--------------------

.. autoclass:: OFPSetConfig

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-7-ofp_set_config.packet.json

.. autoclass:: OFPGetConfigRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-8-ofp_get_config_request.packet.json

.. autoclass:: OFPGetConfigReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-9-ofp_get_config_reply.packet.json

Modify State Messages
---------------------

.. autoclass:: OFPFlowMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-2-ofp_flow_mod.packet.json
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-3-ofp_flow_mod.packet.json

.. autoclass:: OFPPortMod

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-22-ofp_port_mod.packet.json

Queue Configuration Messages
----------------------------

.. autoclass:: OFPQueueGetConfigRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-35-ofp_queue_get_config_request.packet.json

.. autoclass:: OFPQueueGetConfigReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-36-ofp_queue_get_config_reply.packet.json

Read State Messages
-------------------

.. autoclass:: OFPDescStatsRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-24-ofp_desc_stats_request.packet.json

.. autoclass:: OFPDescStatsReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-0-ofp_desc_stats_reply.packet.json

.. autoclass:: OFPFlowStatsRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-11-ofp_flow_stats_request.packet.json

.. autoclass:: OFPFlowStatsReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-12-ofp_flow_stats_reply.packet.json

.. autoclass:: OFPAggregateStatsRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-25-ofp_aggregate_stats_request.packet.json

.. autoclass:: OFPAggregateStatsReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-26-ofp_aggregate_stats_reply.packet.json

.. autoclass:: OFPTableStatsRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-27-ofp_table_stats_request.packet.json

.. autoclass:: OFPTableStatsReply

..    XXX commented out because it's too long
..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-28-ofp_table_stats_reply.packet.json

.. autoclass:: OFPPortStatsRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-29-ofp_port_stats_request.packet.json

.. autoclass:: OFPPortStatsReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-30-ofp_port_stats_reply.packet.json

.. autoclass:: OFPQueueStatsRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-37-ofp_queue_stats_request.packet.json

.. autoclass:: OFPQueueStatsReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-38-ofp_queue_stats_reply.packet.json

.. autoclass:: OFPVendorStatsRequest
.. autoclass:: OFPVendorStatsReply

Send Packet Message
-------------------

.. autoclass:: OFPPacketOut

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-1-ofp_packet_out.packet.json

Barrier Message
---------------

.. autoclass:: OFPBarrierRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-17-ofp_barrier_request.packet.json

.. autoclass:: OFPBarrierReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-18-ofp_barrier_reply.packet.json


Asynchronous Messages
=====================

Packet-In Message
-----------------

.. autoclass:: OFPPacketIn

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-4-ofp_packet_in.packet.json

Flow Removed Message
--------------------

.. autoclass:: OFPFlowRemoved

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-40-ofp_flow_removed.packet.json

Port Status Message
-------------------

.. autoclass:: OFPPortStatus

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-39-ofp_port_status.packet.json

Error Message
-------------

.. autoclass:: OFPErrorMsg

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-15-ofp_error_msg.packet.json
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-41-ofp_error_msg_vendor.packet.json

Symmetric Messages
==================

Hello
-----

.. autoclass:: OFPHello

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-10-ofp_hello.packet.json

Echo Request
------------

.. autoclass:: OFPEchoRequest

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-13-ofp_echo_request.packet.json


Echo Reply
----------

.. autoclass:: OFPEchoReply

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-14-ofp_echo_reply.packet.json


Vendor
------------

.. autoclass:: OFPVendor

..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of10/1-16-ofp_vendor.packet.json

Port Structures
===============

.. autoclass:: OFPPhyPort


Flow Match Structure
====================

.. autoclass:: OFPMatch


Action Structures
=================

.. autoclass:: OFPActionHeader
.. autoclass:: OFPAction
.. autoclass:: OFPActionOutput
.. autoclass:: OFPActionVlanVid
.. autoclass:: OFPActionVlanPcp
.. autoclass:: OFPActionStripVlan
.. autoclass:: OFPActionDlAddr
.. autoclass:: OFPActionSetDlSrc
.. autoclass:: OFPActionSetDlDst
.. autoclass:: OFPActionNwAddr
.. autoclass:: OFPActionSetNwSrc
.. autoclass:: OFPActionSetNwDst
.. autoclass:: OFPActionSetNwTos
.. autoclass:: OFPActionTpPort
.. autoclass:: OFPActionSetTpSrc
.. autoclass:: OFPActionSetTpDst
.. autoclass:: OFPActionEnqueue
.. autoclass:: OFPActionVendor
