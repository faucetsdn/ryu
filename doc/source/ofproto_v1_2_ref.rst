*************************************
OpenFlow v1.2 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_2_parser

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

Read State Messages
-------------------

.. autoclass:: OFPDescStatsRequest
.. autoclass:: OFPDescStats
.. autoclass:: OFPFlowStatsRequest
.. autoclass:: OFPFlowStats
.. autoclass:: OFPAggregateStatsRequest
.. autoclass:: OFPAggregateStatsReply
.. autoclass:: OFPTableStatsRequest
.. autoclass:: OFPTableStats
.. autoclass:: OFPPortStatsRequest
.. autoclass:: OFPPortStats
.. autoclass:: OFPQueueStatsRequest
.. autoclass:: OFPQueueStats
.. autoclass:: OFPGroupStatsRequest
.. autoclass:: OFPGroupStats
.. autoclass:: OFPGroupDescStatsRequest
.. autoclass:: OFPGroupDescStats
.. autoclass:: OFPGroupFeaturesStatsRequest
.. autoclass:: OFPGroupFeaturesStats

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
