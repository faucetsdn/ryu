****************
MRT file library
****************

Introduction
============

Ryu MRT file library helps you to read/write MRT
(Multi-Threaded Routing Toolkit) Routing Information Export Format
[`RFC6396`_].

.. _RFC6396: https://tools.ietf.org/html/rfc6396

Reading MRT file
================

For loading the routing information contained in MRT files, you can use
mrtlib.Reader.

.. autoclass:: ryu.lib.mrtlib.Reader

Writing MRT file
================

For dumping the routing information which your RyuApp generated, you can use
mrtlib.Writer.

.. autoclass:: ryu.lib.mrtlib.Writer
