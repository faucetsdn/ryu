*****************
PCAP file library
*****************

Introduction
============

Ryu PCAP file library helps you to read/write PCAP file which file
format are described in `The Wireshark Wiki`_.

.. _The Wireshark Wiki: https://wiki.wireshark.org/Development/LibpcapFileFormat

Reading PCAP file
=================

For loading the packet data containing in PCAP files, you can use
pcaplib.Reader.

.. autoclass:: ryu.lib.pcaplib.Reader

Writing PCAP file
=================

For dumping the packet data which your RyuApp received, you can use
pcaplib.Writer.

.. autoclass:: ryu.lib.pcaplib.Writer
