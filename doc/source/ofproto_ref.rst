*******************************
OpenFlow protocol API Reference
*******************************

| :ref:`OpenFlow v1.2 Messages and Structures <OpenFlow-v1.2>`
| :ref:`OpenFlow v1.3 Messages and Structures <OpenFlow-v1.3>`

.. _OpenFlow-v1.2:

OpenFlow v1.2 Messages and Structures
=====================================
.. py:currentmodule:: ryu.ofproto.ofproto_v1_2_parser

Controller-to-Switch Messages
-----------------------------

Handshake
^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPFeaturesRequest
   OFPSwitchFeatures

Switch Configuration
^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPSetConfig
   OFPGetConfigRequest
   OFPGetConfigReply

Flow Table Configuration
^^^^^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPTableMod

Modify State Messages
^^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPFlowMod
   OFPGroupMod
   OFPPortMod

Read State Messages
^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPDescStatsRequest
   OFPDescStats
   OFPFlowStatsRequest
   OFPFlowStats
   OFPAggregateStatsRequest
   OFPAggregateStatsReply
   OFPTableStatsRequest
   OFPTableStats
   OFPPortStatsRequest
   OFPPortStats
   OFPQueueStatsRequest
   OFPQueueStats
   OFPGroupStatsRequest
   OFPGroupStats
   OFPGroupDescStatsRequest
   OFPGroupDescStats
   OFPGroupFeaturesStatsRequest
   OFPGroupFeaturesStats

Queue Configuration Messages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPQueueGetConfigRequest
   OFPQueueGetConfigReply

Packet-Out Message
^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPPacketOut

Barrier Message
^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPBarrierRequest
   OFPBarrierReply

Role Request Message
^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPRoleRequest
   OFPRoleReply


Asynchronous Messages
---------------------

Packet-In Message
^^^^^^^^^^^^^^^^^

.. autosummary::

   OFPPacketIn

Flow Removed Message
^^^^^^^^^^^^^^^^^^^^

.. autosummary::

   OFPFlowRemoved

Port Status Message
^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPPortStatus

Error Message
^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPErrorMsg


Symmetric Messages
------------------

Hello
^^^^^

.. autosummary::
   :nosignatures:

   OFPHello

Echo Request
^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPEchoRequest

Echo Reply
^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPEchoReply

Experimenter
^^^^^^^^^^^^
.. autosummary::
   :nosignatures:

   OFPExperimenter


Flow Match Structure
--------------------

.. autosummary::
   :nosignatures:

   OFPMatch


Flow Instruction Structures
---------------------------

.. autosummary::
   :nosignatures:

   OFPInstructionGotoTable
   OFPInstructionWriteMetadata
   OFPInstructionActions


Action Structures
-----------------

.. autosummary::
   :nosignatures:

   OFPActionOutput
   OFPActionGroup
   OFPActionSetQueue
   OFPActionSetMplsTtl
   OFPActionDecMplsTtl
   OFPActionSetNwTtl
   OFPActionDecNwTtl
   OFPActionCopyTtlOut
   OFPActionCopyTtlIn
   OFPActionPushVlan
   OFPActionPushMpls
   OFPActionPopVlan
   OFPActionPopMpls
   OFPActionSetField
   OFPActionExperimenter


.. _OpenFlow-v1.3:

OpenFlow v1.3 Messages and Structures
=====================================
.. py:currentmodule:: ryu.ofproto.ofproto_v1_3_parser

Controller-to-Switch Messages
-----------------------------

Handshake
^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPFeaturesRequest
   OFPSwitchFeatures

Switch Configuration
^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPSetConfig
   OFPGetConfigRequest
   OFPGetConfigReply

Flow Table Configuration
^^^^^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPTableMod

Modify State Messages
^^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPFlowMod
   OFPGroupMod
   OFPPortMod
   OFPMeterMod

Multipart Messages
^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPDescStatsRequest
   OFPDescStatsReply
   OFPFlowStatsRequest
   OFPFlowStatsReply
   OFPAggregateStatsRequest
   OFPAggregateStatsReply
   OFPTableStatsRequest
   OFPTableStatsReply
   OFPPortStatsRequest
   OFPPortStatsReply
   OFPPortDescStatsRequest
   OFPPortDescStatsReply
   OFPQueueStatsRequest
   OFPQueueStatsReply
   OFPGroupStatsRequest
   OFPGroupStatsReply
   OFPGroupDescStatsRequest
   OFPGroupDescStatsReply
   OFPGroupFeaturesStatsRequest
   OFPGroupFeaturesStatsReply
   OFPMeterStatsRequest
   OFPMeterStatsReply
   OFPMeterConfigStatsRequest
   OFPMeterConfigStatsReply
   OFPMeterFeaturesStatsRequest
   OFPMeterFeaturesStatsReply

Queue Configuration Messages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPQueueGetConfigRequest
   OFPQueueGetConfigReply

Packet-Out Message
^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPPacketOut

Barrier Message
^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPBarrierRequest
   OFPBarrierReply

Role Request Message
^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPRoleRequest
   OFPRoleReply

Set Asynchronous Configuration Message
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPSetAsync
   OFPGetAsyncRequest
   OFPGetAsyncReply


Asynchronous Messages
---------------------

.. autosummary::
   :nosignatures:


Packet-In Message
^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPPacketIn

Flow Removed Message
^^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPFlowRemoved

Port Status Message
^^^^^^^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPPortStatus

Error Message
^^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPErrorMsg


Symmetric Messages
------------------

Hello
^^^^^

.. autosummary::
   :nosignatures:

   OFPHello
   OFPHelloElemVersionBitmap

Echo Request
^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPEchoRequest

Echo Reply
^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPEchoReply

Experimenter
^^^^^^^^^^^^

.. autosummary::
   :nosignatures:

   OFPExperimenter


Flow Match Structure
--------------------

.. autosummary::
   :nosignatures:

   OFPMatch


Flow Instruction Structures
---------------------------

.. autosummary::
   :nosignatures:

   OFPInstructionGotoTable
   OFPInstructionWriteMetadata
   OFPInstructionActions
   OFPInstructionMeter


Action Structures
-----------------

.. autosummary::
   :nosignatures:

   OFPActionOutput
   OFPActionGroup
   OFPActionSetQueue
   OFPActionSetMplsTtl
   OFPActionDecMplsTtl
   OFPActionSetNwTtl
   OFPActionDecNwTtl
   OFPActionCopyTtlOut
   OFPActionCopyTtlIn
   OFPActionPushVlan
   OFPActionPushMpls
   OFPActionPopVlan
   OFPActionPopMpls
   OFPActionSetField
   OFPActionExperimenter

