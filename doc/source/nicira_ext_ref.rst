***************************
Nicira Extension Structures
***************************

.. _nx_actions_structures:

Nicira Extension Actions Structures
===================================

The followings shows the supported NXAction classes only in OpenFlow1.0
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:currentmodule:: ryu.ofproto.ofproto_v1_0_parser

.. autoclass:: NXActionSetQueue
.. autoclass:: NXActionDecTtl
.. autoclass:: NXActionPushMpls
.. autoclass:: NXActionPopMpls
.. autoclass:: NXActionSetMplsTtl
.. autoclass:: NXActionDecMplsTtl
.. autoclass:: NXActionSetMplsLabel
.. autoclass:: NXActionSetMplsTc

The followings shows the supported NXAction classes in OpenFlow1.0 or later
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:currentmodule:: ryu.ofproto.ofproto_v1_3_parser

.. autoclass:: NXActionPopQueue
.. autoclass:: NXActionRegLoad
.. autoclass:: NXActionRegLoad2
.. autoclass:: NXActionNote
.. autoclass:: NXActionSetTunnel
.. autoclass:: NXActionSetTunnel64
.. autoclass:: NXActionRegMove
.. autoclass:: NXActionResubmit
.. autoclass:: NXActionResubmitTable
.. autoclass:: NXActionOutputReg
.. autoclass:: NXActionOutputReg2
.. autoclass:: NXActionLearn
.. autoclass:: NXActionExit
.. autoclass:: NXActionController
.. autoclass:: NXActionController2
.. autoclass:: NXActionDecTtlCntIds
.. autoclass:: NXActionStackPush
.. autoclass:: NXActionStackPop
.. autoclass:: NXActionSample
.. autoclass:: NXActionSample2
.. autoclass:: NXActionFinTimeout
.. autoclass:: NXActionConjunction
.. autoclass:: NXActionMultipath
.. autoclass:: NXActionBundle
.. autoclass:: NXActionBundleLoad
.. autoclass:: NXActionCT
.. autoclass:: NXActionNAT
.. autoclass:: NXActionOutputTrunc
.. autoclass:: NXActionDecNshTtl
.. autoclass:: NXFlowSpecMatch
.. autoclass:: NXFlowSpecLoad
.. autoclass:: NXFlowSpecOutput
.. autofunction:: ryu.ofproto.nicira_ext.ofs_nbits

.. _nx_match_structures:

Nicira Extended Match Structures
================================

.. automodule:: ryu.ofproto.nicira_ext

