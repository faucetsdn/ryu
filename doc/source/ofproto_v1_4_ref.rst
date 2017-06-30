*************************************
OpenFlow v1.4 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_4_parser

Controller-to-Switch Messages
=============================

Handshake
---------

.. autoclass:: OFPFeaturesRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-5-ofp_features_request.packet.json

.. autoclass:: OFPSwitchFeatures

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-6-ofp_features_reply.packet.json

Switch Configuration
--------------------

.. autoclass:: OFPSetConfig

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-7-ofp_set_config.packet.json

.. autoclass:: OFPGetConfigRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-8-ofp_get_config_request.packet.json

.. autoclass:: OFPGetConfigReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-9-ofp_get_config_reply.packet.json

Modify State Messages
---------------------

.. autoclass:: OFPTableMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-23-ofp_table_mod.packet.json

.. autoclass:: OFPFlowMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-2-ofp_flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-3-ofp_flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-44-ofp_flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-58-ofp_flow_mod.packet.json

.. autoclass:: OFPGroupMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-21-ofp_group_mod.packet.json

.. autoclass:: OFPPortMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-22-ofp_port_mod.packet.json

.. autoclass:: OFPMeterMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-43-ofp_meter_mod.packet.json

Multipart Messages
------------------

.. autoclass:: OFPDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-24-ofp_desc_request.packet.json

.. autoclass:: OFPDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-0-ofp_desc_reply.packet.json

.. autoclass:: OFPFlowStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-11-ofp_flow_stats_request.packet.json

.. autoclass:: OFPFlowStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-12-ofp_flow_stats_reply.packet.json

.. autoclass:: OFPAggregateStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-25-ofp_aggregate_stats_request.packet.json

.. autoclass:: OFPAggregateStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-26-ofp_aggregate_stats_reply.packet.json

.. autoclass:: OFPTableStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-27-ofp_table_stats_request.packet.json

.. autoclass:: OFPTableStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-28-ofp_table_stats_reply.packet.json

.. autoclass:: OFPTableDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-61-ofp_table_desc_request.packet.json

.. autoclass:: OFPTableDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-62-ofp_table_desc_reply.packet.json

.. autoclass:: OFPTableFeaturesStatsRequest

    JSON Example:

       See an example in:

       ``ryu/tests/unit/ofproto/json/of14/5-53-ofp_table_features_request.packet.json``

.. autoclass:: OFPTableFeaturesStatsReply

    JSON Example:

       See an example in:

       ``ryu/tests/unit/ofproto/json/of14/5-54-ofp_table_features_reply.packet.json``

.. autoclass:: OFPPortStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-29-ofp_port_stats_request.packet.json

.. autoclass:: OFPPortStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-30-ofp_port_stats_reply.packet.json

.. autoclass:: OFPPortDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-51-ofp_port_desc_request.packet.json

.. autoclass:: OFPPortDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-52-ofp_port_desc_reply.packet.json

.. autoclass:: OFPQueueStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-35-ofp_queue_stats_request.packet.json

.. autoclass:: OFPQueueStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-36-ofp_queue_stats_reply.packet.json

.. autoclass:: OFPQueueDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-63-ofp_queue_desc_request.packet.json

.. autoclass:: OFPQueueDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-64-ofp_queue_desc_reply.packet.json

.. autoclass:: OFPGroupStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-55-ofp_group_stats_request.packet.json

.. autoclass:: OFPGroupStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-56-ofp_group_stats_reply.packet.json

.. autoclass:: OFPGroupDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-33-ofp_group_desc_request.packet.json

.. autoclass:: OFPGroupDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-34-ofp_group_desc_reply.packet.json

.. autoclass:: OFPGroupFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-31-ofp_group_features_request.packet.json

.. autoclass:: OFPGroupFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-32-ofp_group_features_reply.packet.json

.. autoclass:: OFPMeterStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-47-ofp_meter_stats_request.packet.json

.. autoclass:: OFPMeterStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-48-ofp_meter_stats_reply.packet.json

.. autoclass:: OFPMeterConfigStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-45-ofp_meter_config_request.packet.json

.. autoclass:: OFPMeterConfigStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-46-ofp_meter_config_reply.packet.json

.. autoclass:: OFPMeterFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-49-ofp_meter_features_request.packet.json

.. autoclass:: OFPMeterFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-50-ofp_meter_features_reply.packet.json

.. autoclass:: OFPFlowMonitorRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-66-ofp_flow_monitor_request.packet.json

.. autoclass:: OFPFlowMonitorReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-67-ofp_flow_monitor_reply.packet.json

.. autoclass:: OFPExperimenterStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-59-ofp_experimenter_request.packet.json

.. autoclass:: OFPExperimenterStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-60-ofp_experimenter_reply.packet.json

Packet-Out Message
------------------

.. autoclass:: OFPPacketOut

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-1-ofp_packet_out.packet.json

Barrier Message
---------------

.. autoclass:: OFPBarrierRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-17-ofp_barrier_request.packet.json

.. autoclass:: OFPBarrierReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-18-ofp_barrier_reply.packet.json

Role Request Message
--------------------

.. autoclass:: OFPRoleRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-19-ofp_role_request.packet.json

.. autoclass:: OFPRoleReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-20-ofp_role_reply.packet.json

Bundle Messages
---------------

.. autoclass:: OFPBundleCtrlMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-69-ofp_bundle_ctrl_msg.packet.json

.. autoclass:: OFPBundleAddMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-70-ofp_bundle_add_msg.packet.json

Set Asynchronous Configuration Message
--------------------------------------

.. autoclass:: OFPSetAsync

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-42-ofp_set_async.packet.json

.. autoclass:: OFPGetAsyncRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-40-ofp_get_async_request.packet.json

.. autoclass:: OFPGetAsyncReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-41-ofp_get_async_reply.packet.json


Asynchronous Messages
=====================

Packet-In Message
-----------------

.. autoclass:: OFPPacketIn

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-4-ofp_packet_in.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-57-ofp_packet_in.packet.json

Flow Removed Message
--------------------

.. autoclass:: OFPFlowRemoved

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-38-ofp_flow_removed.packet.json

Port Status Message
-------------------

.. autoclass:: OFPPortStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-37-ofp_port_status.packet.json

Controller Role Status Message
------------------------------

.. autoclass:: OFPRoleStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-65-ofp_role_status.packet.json

Table Status Message
--------------------

.. autoclass:: OFPTableStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-68-ofp_table_status.packet.json

Request Forward Message
-----------------------

.. autoclass:: OFPRequestForward

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-71-ofp_requestforward.packet.json


Symmetric Messages
==================

Hello
-----

.. autoclass:: OFPHello

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-10-ofp_hello.packet.json

.. autoclass:: OFPHelloElemVersionBitmap

Echo Request
------------

.. autoclass:: OFPEchoRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-13-ofp_echo_request.packet.json

Echo Reply
----------

.. autoclass:: OFPEchoReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-14-ofp_echo_reply.packet.json

Error Message
-------------

.. autoclass:: OFPErrorMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-15-ofp_error_msg.packet.json

Experimenter
------------

.. autoclass:: OFPExperimenter

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of14/5-16-ofp_experimenter.packet.json

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
.. autoclass:: OFPActionCopyTtlOut
.. autoclass:: OFPActionCopyTtlIn
.. autoclass:: OFPActionSetMplsTtl
.. autoclass:: OFPActionDecMplsTtl
.. autoclass:: OFPActionPushVlan
.. autoclass:: OFPActionPopVlan
.. autoclass:: OFPActionPushMpls
.. autoclass:: OFPActionPopMpls
.. autoclass:: OFPActionSetQueue
.. autoclass:: OFPActionGroup
.. autoclass:: OFPActionSetNwTtl
.. autoclass:: OFPActionDecNwTtl
.. autoclass:: OFPActionSetField
.. autoclass:: OFPActionPushPbb
.. autoclass:: OFPActionPopPbb
.. autoclass:: OFPActionExperimenter
