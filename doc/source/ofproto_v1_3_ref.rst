*************************************
OpenFlow v1.3 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_3_parser

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

Flow Table Configuration
------------------------

.. autoclass:: OFPTableMod

Modify State Messages
---------------------

.. autoclass:: OFPFlowMod
.. autoclass:: OFPGroupMod
.. autoclass:: OFPPortMod
.. autoclass:: OFPMeterMod

Multipart Messages
------------------

.. autoclass:: OFPDescStatsRequest
.. autoclass:: OFPDescStatsReply
.. autoclass:: OFPFlowStatsRequest
.. autoclass:: OFPFlowStatsReply
.. autoclass:: OFPAggregateStatsRequest
.. autoclass:: OFPAggregateStatsReply
.. autoclass:: OFPTableStatsRequest
.. autoclass:: OFPTableStatsReply
.. autoclass:: OFPPortStatsRequest
.. autoclass:: OFPPortStatsReply
.. autoclass:: OFPPortDescStatsRequest
.. autoclass:: OFPPortDescStatsReply
.. autoclass:: OFPQueueStatsRequest
.. autoclass:: OFPQueueStatsReply
.. autoclass:: OFPGroupStatsRequest
.. autoclass:: OFPGroupStatsReply
.. autoclass:: OFPGroupDescStatsRequest
.. autoclass:: OFPGroupDescStatsReply
.. autoclass:: OFPGroupFeaturesStatsRequest
.. autoclass:: OFPGroupFeaturesStatsReply
.. autoclass:: OFPMeterStatsRequest
.. autoclass:: OFPMeterStatsReply
.. autoclass:: OFPMeterConfigStatsRequest
.. autoclass:: OFPMeterConfigStatsReply
.. autoclass:: OFPMeterFeaturesStatsRequest
.. autoclass:: OFPMeterFeaturesStatsReply

Queue Configuration Messages
----------------------------

.. autoclass:: OFPQueueGetConfigRequest
.. autoclass:: OFPQueueGetConfigReply

Packet-Out Message
------------------

.. autoclass:: OFPPacketOut

Barrier Message
---------------

.. autoclass:: OFPBarrierRequest
.. autoclass:: OFPBarrierReply

Role Request Message
--------------------

.. autoclass:: OFPRoleRequest
.. autoclass:: OFPRoleReply

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

Flow Removed Message
--------------------

.. autoclass:: OFPFlowRemoved

Port Status Message
-------------------

.. autoclass:: OFPPortStatus

Error Message
-------------

.. autoclass:: OFPErrorMsg


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

Experimenter
------------

.. autoclass:: OFPExperimenter


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
