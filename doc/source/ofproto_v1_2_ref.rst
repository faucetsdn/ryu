*************************************
OpenFlow v1.2 Messages and Structures
*************************************

.. py:currentmodule:: ryu.ofproto.ofproto_v1_2_parser

Controller-to-Switch Messages
=============================

Handshake
---------

.. autoclass:: OFPFeaturesRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-5-ofp_features_request.packet.json

.. autoclass:: OFPSwitchFeatures

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-6-ofp_features_reply.packet.json

Switch Configuration
--------------------

.. autoclass:: OFPSetConfig

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-7-ofp_set_config.packet.json

.. autoclass:: OFPGetConfigRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-8-ofp_get_config_request.packet.json

.. autoclass:: OFPGetConfigReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-9-ofp_get_config_reply.packet.json

Flow Table Configuration
------------------------

.. autoclass:: OFPTableMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-23-ofp_table_mod.packet.json

Modify State Messages
---------------------

.. autoclass:: OFPFlowMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-2-ofp_flow_mod.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-3-ofp_flow_mod.packet.json

.. autoclass:: OFPGroupMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-21-ofp_group_mod.packet.json

.. autoclass:: OFPPortMod

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-22-ofp_port_mod.packet.json

Read State Messages
-------------------

.. autoclass:: OFPDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-24-ofp_desc_stats_request.packet.json

.. autoclass:: OFPDescStats

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-0-ofp_desc_stats_reply.packet.json

.. autoclass:: OFPFlowStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-11-ofp_flow_stats_request.packet.json

.. autoclass:: OFPFlowStats

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-12-ofp_flow_stats_reply.packet.json

.. autoclass:: OFPAggregateStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-25-ofp_aggregate_stats_request.packet.json

.. autoclass:: OFPAggregateStatsReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-26-ofp_aggregate_stats_reply.packet.json

.. autoclass:: OFPTableStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-27-ofp_table_stats_request.packet.json

.. autoclass:: OFPTableStats

..    XXX commented out because it's too long
..    JSON Example:
..
..    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-28-ofp_table_stats_reply.packet.json

.. autoclass:: OFPPortStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-29-ofp_port_stats_request.packet.json

.. autoclass:: OFPPortStats

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-30-ofp_port_stats_reply.packet.json

.. autoclass:: OFPQueueStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-37-ofp_queue_stats_request.packet.json

.. autoclass:: OFPQueueStats

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-38-ofp_queue_stats_reply.packet.json

.. autoclass:: OFPGroupStatsRequest
.. autoclass:: OFPGroupStats
.. autoclass:: OFPGroupDescStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-33-ofp_group_desc_stats_request.packet.json

.. autoclass:: OFPGroupDescStats

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-34-ofp_group_desc_stats_reply.packet.json

.. autoclass:: OFPGroupFeaturesStatsRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-31-ofp_group_features_stats_request.packet.json

.. autoclass:: OFPGroupFeaturesStats

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-32-ofp_group_features_stats_reply.packet.json

Queue Configuration Messages
----------------------------

.. autoclass:: OFPQueueGetConfigRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-35-ofp_queue_get_config_request.packet.json

.. autoclass:: OFPQueueGetConfigReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-36-ofp_queue_get_config_reply.packet.json

Packet-Out Message
------------------

.. autoclass:: OFPPacketOut

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-1-ofp_packet_out.packet.json

Barrier Message
---------------

.. autoclass:: OFPBarrierRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-17-ofp_barrier_request.packet.json

.. autoclass:: OFPBarrierReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-18-ofp_barrier_reply.packet.json

Role Request Message
--------------------

.. autoclass:: OFPRoleRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-19-ofp_role_request.packet.json

.. autoclass:: OFPRoleReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-20-ofp_role_reply.packet.json


Asynchronous Messages
=====================

Packet-In Message
-----------------

.. autoclass:: OFPPacketIn

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-4-ofp_packet_in.packet.json

Flow Removed Message
--------------------

.. autoclass:: OFPFlowRemoved

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-40-ofp_flow_removed.packet.json

Port Status Message
-------------------

.. autoclass:: OFPPortStatus

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-39-ofp_port_status.packet.json

Error Message
-------------

.. autoclass:: OFPErrorMsg

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-15-ofp_error_msg.packet.json
    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-41-ofp_error_msg_experimenter.packet.json

Symmetric Messages
==================

Hello
-----

.. autoclass:: OFPHello

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-10-ofp_hello.packet.json

Echo Request
------------

.. autoclass:: OFPEchoRequest

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-13-ofp_echo_request.packet.json


Echo Reply
----------

.. autoclass:: OFPEchoReply

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-14-ofp_echo_reply.packet.json


Experimenter
------------

.. autoclass:: OFPExperimenter

    JSON Example:

    .. literalinclude:: ../../ryu/tests/unit/ofproto/json/of12/3-16-ofp_experimenter.packet.json

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
