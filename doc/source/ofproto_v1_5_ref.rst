*************************************
OpenFlow v1.5 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_5_parser

Controller-to-Switch Messages
=============================

Handshake
---------

.. autoclass:: OFPFeaturesRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-features_request.packet.json

.. autoclass:: OFPSwitchFeatures

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-features_reply.packet.json

Switch Configuration
--------------------

.. autoclass:: OFPSetConfig

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-set_config.packet.json

.. autoclass:: OFPGetConfigRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-get_config_request.packet.json

.. autoclass:: OFPGetConfigReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-get_config_reply.packet.json

Modify State Messages
---------------------

.. autoclass:: OFPTableMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_mod.packet.json

.. autoclass:: OFPFlowMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_mod_conjunction.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_mod_match_conj.packet.json

.. autoclass:: OFPGroupMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_mod.packet.json

.. autoclass:: OFPPortMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-port_mod.packet.json

.. autoclass:: OFPMeterMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-meter_mod.packet.json

Multipart Messages
------------------

.. autoclass:: OFPDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-desc_request.packet.json

.. autoclass:: OFPDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-desc_reply.packet.json

.. autoclass:: OFPFlowDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_desc_request.packet.json

.. autoclass:: OFPFlowDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_desc_reply.packet.json

.. autoclass:: OFPFlowStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_stats_request.packet.json

.. autoclass:: OFPFlowStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_stats_reply.packet.json

.. autoclass:: OFPAggregateStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-aggregate_stats_request.packet.json

.. autoclass:: OFPAggregateStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-aggregate_stats_reply.packet.json

.. autoclass:: OFPPortStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-port_stats_request.packet.json

.. autoclass:: OFPPortStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-port_stats_reply.packet.json

.. autoclass:: OFPPortDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-port_desc_request.packet.json

.. autoclass:: OFPPortDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-port_desc_reply.packet.json

.. autoclass:: OFPQueueStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-queue_stats_request.packet.json

.. autoclass:: OFPQueueStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-queue_stats_reply.packet.json

.. autoclass:: OFPQueueDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-queue_desc_request.packet.json

.. autoclass:: OFPQueueDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-queue_desc_reply.packet.json

.. autoclass:: OFPGroupStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_stats_request.packet.json

.. autoclass:: OFPGroupStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_stats_reply.packet.json

.. autoclass:: OFPGroupDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_desc_request.packet.json

.. autoclass:: OFPGroupDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_desc_reply.packet.json

.. autoclass:: OFPGroupFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_features_request.packet.json

.. autoclass:: OFPGroupFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_features_reply.packet.json

.. autoclass:: OFPMeterStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-meter_stats_request.packet.json

.. autoclass:: OFPMeterStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-meter_stats_reply.packet.json

.. autoclass:: OFPMeterDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-meter_desc_request.packet.json

.. autoclass:: OFPMeterDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-meter_desc_reply.packet.json

.. autoclass:: OFPMeterFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-meter_features_request.packet.json

.. autoclass:: OFPMeterFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-meter_features_reply.packet.json

.. autoclass:: OFPControllerStatusStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-controller_status_request.packet.json

.. autoclass:: OFPControllerStatusStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-controller_status_reply.packet.json

.. autoclass:: OFPTableStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_stats_request.packet.json

.. autoclass:: OFPTableStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_stats_reply.packet.json

.. autoclass:: OFPTableDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_desc_request.packet.json

.. autoclass:: OFPTableDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_desc_reply.packet.json

.. autoclass:: OFPTableFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_features_request.packet.json

.. autoclass:: OFPTableFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_features_reply.packet.json

.. autoclass:: OFPFlowMonitorRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_monitor_request.packet.json

.. autoclass:: OFPFlowMonitorReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_monitor_reply.packet.json

.. autoclass:: OFPBundleFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-bundle_features_request.packet.json

.. autoclass:: OFPBundleFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-bundle_features_reply.packet.json

.. autoclass:: OFPExperimenterStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-experimenter_request.packet.json

.. autoclass:: OFPExperimenterStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-experimenter_reply.packet.json

Packet-Out Message
------------------

.. autoclass:: OFPPacketOut

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-packet_out.packet.json

Barrier Message
---------------

.. autoclass:: OFPBarrierRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-barrier_request.packet.json

.. autoclass:: OFPBarrierReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-barrier_reply.packet.json

Role Request Message
--------------------

.. autoclass:: OFPRoleRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-role_request.packet.json

.. autoclass:: OFPRoleReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-role_reply.packet.json

Bundle Messages
---------------

.. autoclass:: OFPBundleCtrlMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-bundle_ctrl.packet.json

.. autoclass:: OFPBundleAddMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-bundle_add.packet.json

Set Asynchronous Configuration Message
--------------------------------------

.. autoclass:: OFPSetAsync

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-set_async.packet.json

.. autoclass:: OFPGetAsyncRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-get_async_request.packet.json

.. autoclass:: OFPGetAsyncReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-get_async_reply.packet.json

Asynchronous Messages
=====================

Packet-In Message
-----------------

.. autoclass:: OFPPacketIn

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-packet_in.packet.json

Flow Removed Message
--------------------

.. autoclass:: OFPFlowRemoved

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_removed.packet.json

Port Status Message
-------------------

.. autoclass:: OFPPortStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-port_status.packet.json

Controller Role Status Message
------------------------------

.. autoclass:: OFPRoleStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-role_status.packet.json

Table Status Message
--------------------

.. autoclass:: OFPTableStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_status.packet.json

Request Forward Message
-----------------------

.. autoclass:: OFPRequestForward

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-requestforward.packet.json

Controller Status Message
-------------------------

.. autoclass:: OFPControllerStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-controller_status.packet.json

Symmetric Messages
==================

Hello
-----

.. autoclass:: OFPHello

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-hello.packet.json

.. autoclass:: OFPHelloElemVersionBitmap

Echo Request
------------

.. autoclass:: OFPEchoRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-echo_request.packet.json

Echo Reply
----------

.. autoclass:: OFPEchoReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-echo_reply.packet.json

Error Message
-------------

.. autoclass:: OFPErrorMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-error_msg.packet.json

Experimenter
------------

.. autoclass:: OFPExperimenter

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-error_msg_experimenter.packet.json

Port Structures
===============

.. autoclass:: OFPPort

Flow Match Structure
====================

.. autoclass:: OFPMatch

Flow Stats Structures
=====================

.. autoclass:: OFPStats

Flow Instruction Structures
===========================

.. autoclass:: OFPInstructionGotoTable
.. autoclass:: OFPInstructionWriteMetadata
.. autoclass:: OFPInstructionActions
.. autoclass:: OFPInstructionStatTrigger

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
.. autoclass:: OFPActionCopyField
.. autoclass:: OFPActionMeter
.. autoclass:: OFPActionExperimenter

Controller Status Structure
===========================

.. autoclass:: OFPControllerStatusStats

