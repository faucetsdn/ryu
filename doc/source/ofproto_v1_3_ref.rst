*************************************
OpenFlow v1.3 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_3_parser

Controller-to-Switch Messages
=============================

Handshake
---------

.. autoclass:: OFPFeaturesRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-5-ofp_features_request.packet.json

.. autoclass:: OFPSwitchFeatures

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-6-ofp_features_reply.packet.json

Switch Configuration
--------------------

.. autoclass:: OFPSetConfig

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-7-ofp_set_config.packet.json

.. autoclass:: OFPGetConfigRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-8-ofp_get_config_request.packet.json

.. autoclass:: OFPGetConfigReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-9-ofp_get_config_reply.packet.json

Flow Table Configuration
------------------------

.. autoclass:: OFPTableMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-23-ofp_table_mod.packet.json

Modify State Messages
---------------------

.. autoclass:: OFPFlowMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-2-ofp_flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-3-ofp_flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-46-ofp_flow_mod.packet.json

.. autoclass:: OFPGroupMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-21-ofp_group_mod.packet.json

.. autoclass:: OFPPortMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-22-ofp_port_mod.packet.json

.. autoclass:: OFPMeterMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-45-ofp_meter_mod.packet.json

Multipart Messages
------------------

.. autoclass:: OFPDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-24-ofp_desc_request.packet.json

.. autoclass:: OFPDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-0-ofp_desc_reply.packet.json

.. autoclass:: OFPFlowStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-11-ofp_flow_stats_request.packet.json

.. autoclass:: OFPFlowStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-12-ofp_flow_stats_reply.packet.json

.. autoclass:: OFPAggregateStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-25-ofp_aggregate_stats_request.packet.json

.. autoclass:: OFPAggregateStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-26-ofp_aggregate_stats_reply.packet.json

.. autoclass:: OFPTableStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-27-ofp_table_stats_request.packet.json

.. autoclass:: OFPTableStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-28-ofp_table_stats_reply.packet.json

.. autoclass:: OFPPortStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-29-ofp_port_stats_request.packet.json

.. autoclass:: OFPPortStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-30-ofp_port_stats_reply.packet.json

.. autoclass:: OFPPortDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-53-ofp_port_desc_request.packet.json

.. autoclass:: OFPPortDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-54-ofp_port_desc_reply.packet.json

.. autoclass:: OFPQueueStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-37-ofp_queue_stats_request.packet.json

.. autoclass:: OFPQueueStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-38-ofp_queue_stats_reply.packet.json

.. autoclass:: OFPGroupStatsRequest
.. autoclass:: OFPGroupStatsReply
.. autoclass:: OFPGroupDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-33-ofp_group_desc_request.packet.json

.. autoclass:: OFPGroupDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-34-ofp_group_desc_reply.packet.json

.. autoclass:: OFPGroupFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-31-ofp_group_features_request.packet.json

.. autoclass:: OFPGroupFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-32-ofp_group_features_reply.packet.json

.. autoclass:: OFPMeterStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-49-ofp_meter_stats_request.packet.json

.. autoclass:: OFPMeterStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-50-ofp_meter_stats_reply.packet.json

.. autoclass:: OFPMeterConfigStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-47-ofp_meter_config_request.packet.json

.. autoclass:: OFPMeterConfigStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-48-ofp_meter_config_reply.packet.json

.. autoclass:: OFPMeterFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-51-ofp_meter_features_request.packet.json

.. autoclass:: OFPMeterFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-52-ofp_meter_features_reply.packet.json

.. autoclass:: OFPTableFeaturesStatsRequest
.. autoclass:: OFPTableFeaturesStatsReply

    JSON Example:

       See an example in:

       ``ryu/tests/unit/ofproto/json/of13/4-56-ofp_table_features_reply.packet.json``

Queue Configuration Messages
----------------------------

.. autoclass:: OFPQueueGetConfigRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-35-ofp_queue_get_config_request.packet.json

.. autoclass:: OFPQueueGetConfigReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-36-ofp_queue_get_config_reply.packet.json

Packet-Out Message
------------------

.. autoclass:: OFPPacketOut

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-1-ofp_packet_out.packet.json

Barrier Message
---------------

.. autoclass:: OFPBarrierRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-17-ofp_barrier_request.packet.json

.. autoclass:: OFPBarrierReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-18-ofp_barrier_reply.packet.json

Role Request Message
--------------------

.. autoclass:: OFPRoleRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-19-ofp_role_request.packet.json

.. autoclass:: OFPRoleReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-20-ofp_role_reply.packet.json

Set Asynchronous Configuration Message
--------------------------------------

.. autoclass:: OFPSetAsync

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-44-ofp_set_async.packet.json

.. autoclass:: OFPGetAsyncRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-42-ofp_get_async_request.packet.json

.. autoclass:: OFPGetAsyncReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-43-ofp_get_async_reply.packet.json


Asynchronous Messages
=====================

Packet-In Message
-----------------

.. autoclass:: OFPPacketIn

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-4-ofp_packet_in.packet.json

Flow Removed Message
--------------------

.. autoclass:: OFPFlowRemoved

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-40-ofp_flow_removed.packet.json

Port Status Message
-------------------

.. autoclass:: OFPPortStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-39-ofp_port_status.packet.json

Error Message
-------------

.. autoclass:: OFPErrorMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-15-ofp_error_msg.packet.json


Symmetric Messages
==================

Hello
-----

.. autoclass:: OFPHello

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-10-ofp_hello.packet.json

.. autoclass:: OFPHelloElemVersionBitmap

Echo Request
------------

.. autoclass:: OFPEchoRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-13-ofp_echo_request.packet.json

Echo Reply
----------

.. autoclass:: OFPEchoReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-14-ofp_echo_reply.packet.json

Experimenter
------------

.. autoclass:: OFPExperimenter

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of13/4-16-ofp_experimenter.packet.json

Port Structures
===============

.. autoclass:: OFPPort


Flow Match Structure
====================

.. autoclass:: OFPMatch


Flow Instruction Structures
===========================

.. autoclass:: OFPInstructionGotoTable
.. autoclass:: OFPInstructionWriteMetadata
.. autoclass:: OFPInstructionActions
.. autoclass:: OFPInstructionMeter


Action Structures
=================

.. autoclass:: OFPActionOutput
.. autoclass:: OFPActionGroup
.. autoclass:: OFPActionSetQueue
.. autoclass:: OFPActionSetMplsTtl
.. autoclass:: OFPActionDecMplsTtl
.. autoclass:: OFPActionSetNwTtl
.. autoclass:: OFPActionDecNwTtl
.. autoclass:: OFPActionCopyTtlOut
.. autoclass:: OFPActionCopyTtlIn
.. autoclass:: OFPActionPushVlan
.. autoclass:: OFPActionPushMpls
.. autoclass:: OFPActionPopVlan
.. autoclass:: OFPActionPopMpls
.. autoclass:: OFPActionSetField
.. autoclass:: OFPActionExperimenter
