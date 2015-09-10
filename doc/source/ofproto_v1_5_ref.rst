*************************************
OpenFlow v1.5 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_5_parser

Controller-to-Switch Messages
=============================

Handshake
---------

.. autoclass:: OFPFeaturesRequest

.. autoclass:: OFPSwitchFeatures

Switch Configuration
--------------------

.. autoclass:: OFPSetConfig

.. autoclass:: OFPGetConfigRequest

.. autoclass:: OFPGetConfigReply

Modify State Messages
---------------------

.. autoclass:: OFPTableMod

.. autoclass:: OFPFlowMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_mod_conjunction.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_mod_match_conj.packet.json

.. autoclass:: OFPGroupMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_mod.packet.json

.. autoclass:: OFPPortMod

.. autoclass:: OFPMeterMod

Multipart Messages
------------------

.. autoclass:: OFPDescStatsRequest

.. autoclass:: OFPDescStatsReply

.. autoclass:: OFPFlowDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_desc_request.packet.json

.. autoclass:: OFPFlowDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_desc_reply.packet.json

.. autoclass:: OFPFlowStatsRequest

.. autoclass:: OFPFlowStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-flow_stats_reply.packet.json

.. autoclass:: OFPAggregateStatsRequest

.. autoclass:: OFPAggregateStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-aggregate_stats_reply.packet.json

.. autoclass:: OFPPortStatsRequest

.. autoclass:: OFPPortStatsReply

.. autoclass:: OFPPortDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-port_desc_request.packet.json

.. autoclass:: OFPPortDescStatsReply

.. autoclass:: OFPQueueStatsRequest

.. autoclass:: OFPQueueStatsReply

.. autoclass:: OFPQueueDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-queue_desc_request.packet.json

.. autoclass:: OFPQueueDescStatsReply

.. autoclass:: OFPGroupStatsRequest

.. autoclass:: OFPGroupStatsReply

.. autoclass:: OFPGroupDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_desc_request.packet.json

.. autoclass:: OFPGroupDescStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-group_desc_reply.packet.json

.. autoclass:: OFPGroupFeaturesStatsRequest

.. autoclass:: OFPGroupFeaturesStatsReply

.. autoclass:: OFPMeterStatsRequest

.. autoclass:: OFPMeterStatsReply

.. autoclass:: OFPMeterDescStatsRequest

.. autoclass:: OFPMeterDescStatsReply

.. autoclass:: OFPMeterFeaturesStatsRequest

.. autoclass:: OFPMeterFeaturesStatsReply

.. autoclass:: OFPControllerStatusStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-controller_status_request.packet.json

.. autoclass:: OFPControllerStatusStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-controller_status_reply.packet.json

.. autoclass:: OFPTableStatsRequest

.. autoclass:: OFPTableStatsReply

.. autoclass:: OFPTableDescStatsRequest

.. autoclass:: OFPTableDescStatsReply

.. autoclass:: OFPTableFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_features_request.packet.json

.. autoclass:: OFPTableFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-table_features_reply.packet.json

.. autoclass:: OFPFlowMonitorRequest

.. autoclass:: OFPFlowMonitorReply

.. autoclass:: OFPBundleFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-bundle_features_request.packet.json

.. autoclass:: OFPBundleFeaturesStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-bundle_features_reply.packet.json

.. autoclass:: OFPExperimenterStatsRequest

.. autoclass:: OFPExperimenterStatsReply

Packet-Out Message
------------------

.. autoclass:: OFPPacketOut

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of15/libofproto-OFP15-packet_out.packet.json

Barrier Message
---------------

.. autoclass:: OFPBarrierRequest

.. autoclass:: OFPBarrierReply

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

.. autoclass:: OFPGetAsyncRequest

.. autoclass:: OFPGetAsyncReply

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

Controller Role Status Message
------------------------------

.. autoclass:: OFPRoleStatus

Table Status Message
--------------------

.. autoclass:: OFPTableStatus

Request Forward Message
-----------------------

.. autoclass:: OFPRequestForward

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

.. autoclass:: OFPHelloElemVersionBitmap

Echo Request
------------

.. autoclass:: OFPEchoRequest

Echo Reply
----------

.. autoclass:: OFPEchoReply

Error Message
-------------

.. autoclass:: OFPErrorMsg

Experimenter
------------

.. autoclass:: OFPExperimenter

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


