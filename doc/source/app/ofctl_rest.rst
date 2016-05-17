******************
ryu.app.ofctl_rest
******************

ryu.app.ofctl_rest provides REST APIs for retrieving the switch stats
and Updating the switch stats.
This application helps you debug your application and get various statistics.

This application supports OpenFlow version 1.0, 1.2, 1.3, 1.4 and 1.5.

.. contents::
   :depth: 3


Retrieve the switch stats
=========================

Get all switches
----------------

    Get the list of all switches which connected to the controller.

    Usage:

        ======= ================
        Method  GET
        URI     /stats/switches
        ======= ================

    Response message body:

        ========== =================== ========
        Attribute  Description         Example
        ========== =================== ========
        dpid       Datapath ID         1
        ========== =================== ========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/switches

    .. code-block:: javascript

        [
          1,
          2,
          3
        ]

    .. NOTE::

       The result of the REST command is formatted for easy viewing.


Get the desc stats
------------------

    Get the desc stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ===================
        Method  GET
        URI     /stats/desc/<dpid>
        ======= ===================

    Response message body:

        =========== ======================================= ================
        Attribute   Description                             Example
        =========== ======================================= ================
        dpid        Datapath ID                             "1"
        mfr_desc    Manufacturer description                "Nicira, Inc.",
        hw_desc     Hardware description                    "Open vSwitch",
        sw_desc     Software description                    "2.3.90",
        serial_num  Serial number                           "None",
        dp_desc     Human readable description of datapath  "None"
        =========== ======================================= ================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/desc/1

    .. code-block:: javascript

        {
          "1": {
            "mfr_desc": "Nicira, Inc.",
            "hw_desc": "Open vSwitch",
            "sw_desc": "2.3.90",
            "serial_num": "None",
            "dp_desc": "None"
          }
        }


.. _get-all-flows-stats:

Get all flows stats
-------------------

    Get all flows stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ===================
        Method  GET
        URI     /stats/flow/<dpid>
        ======= ===================

    Response message body(OpenFlow1.3 or earlier):

        ============== ============================================================ ===============
        Attribute      Description                                                  Example
        ============== ============================================================ ===============
        dpid           Datapath ID                                                  "1"
        length         Length of this entry                                         88
        table_id       Table ID                                                     0
        duration_sec   Time flow has been alive in seconds                          2
        duration_nsec  Time flow has been alive in nanoseconds beyond duration_sec  6.76e+08
        priority       Priority of the entry                                        11111
        idle_timeout   Number of seconds idle before expiration                     0
        hard_timeout   Number of seconds before expiration                          0
        flags          Bitmap of OFPFF_* flags                                      1
        cookie         Opaque controller-issued identifier                          1
        packet_count   Number of packets in flow                                    0
        byte_count     Number of bytes in flow                                      0
        match          Fields to match                                              {"in_port": 1}
        actions        Instruction set                                              ["OUTPUT:2"]
        ============== ============================================================ ===============

    Response message body(OpenFlow1.4 or later):

        ============== ============================================================ ========================================
        Attribute      Description                                                  Example
        ============== ============================================================ ========================================
        dpid           Datapath ID                                                  "1"
        length         Length of this entry                                         88
        table_id       Table ID                                                     0
        duration_sec   Time flow has been alive in seconds                          2
        duration_nsec  Time flow has been alive in nanoseconds beyond duration_sec  6.76e+08
        priority       Priority of the entry                                        11111
        idle_timeout   Number of seconds idle before expiration                     0
        hard_timeout   Number of seconds before expiration                          0
        flags          Bitmap of OFPFF_* flags                                      1
        cookie         Opaque controller-issued identifier                          1
        packet_count   Number of packets in flow                                    0
        byte_count     Number of bytes in flow                                      0
        importance     Eviction precedence                                          0
        match          Fields to match                                              {"eth_type": 2054}
        instructions   struct ofp_instruction_header                                [{"type":GOTO_TABLE", "table_id":1}]
        ============== ============================================================ ========================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/flow/1

    Response (OpenFlow1.3 or earlier):

    .. code-block:: javascript

        {
          "1": [
            {
              "length": 88,
              "table_id": 0,
              "duration_sec": 2,
              "duration_nsec": 6.76e+08,
              "priority": 11111,
              "idle_timeout": 0,
              "hard_timeout": 0,
              "flags": 1,
              "cookie": 1,
              "packet_count": 0,
              "byte_count": 0,
              "match": {
                "in_port": 1
              },
              "actions": [
                "OUTPUT:2"
              ]
            }
          ]
        }

    Response (OpenFlow1.4 or later):

    .. code-block:: javascript

        {
           "1": [
             {
               "length": 88,
               "table_id": 0,
               "duration_sec": 2,
               "duration_nsec": 6.76e+08,
               "priority": 11111,
               "idle_timeout": 0,
               "hard_timeout": 0,
               "flags": 1,
               "cookie": 1,
               "packet_count": 0,
               "byte_count": 0,
               "match": {
                 "eth_type": 2054
               },
               "importance": 0,
               "instructions": [
                 {
                   "type": "APPLY_ACTIONS",
                   "actions": [
                     {
                       "port": 2,
                       "max_len": 0,
                       "type": "OUTPUT"
                     }
                   ]
                 }
               ]
             }
           ]
       }


.. _get-flows-stats-filtered:

Get flows stats filtered by fields
----------------------------------

    Get flows stats of the switch filtered by the OFPFlowStats fields.
    This is POST method version of :ref:`get-all-flows-stats`.

    Usage:

        ======= ===================
        Method  POST
        URI     /stats/flow/<dpid>
        ======= ===================

    Request message body:

        ============ ================================================================== =============== ===============
        Attribute    Description                                                        Example         Default
        ============ ================================================================== =============== ===============
        table_id     Table ID (int)                                                     0               OFPTT_ALL
        out_port     Require matching entries to include this as an output port (int)   2               OFPP_ANY
        out_group    Require matching entries to include this as an output group (int)  1               OFPG_ANY
        cookie       Require matching entries to contain this cookie value (int)        1               0
        cookie_mask  Mask used to restrict the cookie bits that must match (int)        1               0
        match        Fields to match (dict)                                             {"in_port": 1}  {} #wildcarded
        ============ ================================================================== =============== ===============

    Response message body:
        The same as :ref:`get-all-flows-stats`

    Example of use::

        $ curl -X POST -d '{
             "table_id": 0,
             "out_port": 2,
             "cookie": 1,
             "cookie_mask": 1,
             "match":{
                 "in_port":1
             }
         }' http://localhost:8080/stats/flow/1

    Response (OpenFlow1.3 or earlier):

    .. code-block:: javascript

        {
          "1": [
            {
              "length": 88,
              "table_id": 0,
              "duration_sec": 2,
              "duration_nsec": 6.76e+08,
              "priority": 11111,
              "idle_timeout": 0,
              "hard_timeout": 0,
              "flags": 1,
              "cookie": 1,
              "packet_count": 0,
              "byte_count": 0,
              "match": {
                "in_port": 1
              },
              "actions": [
                "OUTPUT:2"
              ]
            }
          ]
        }

    Response (OpenFlow1.4 or later):

    .. code-block:: javascript

        {
           "1": [
             {
               "length": 88,
               "table_id": 0,
               "duration_sec": 2,
               "duration_nsec": 6.76e+08,
               "priority": 11111,
               "idle_timeout": 0,
               "hard_timeout": 0,
               "flags": 1,
               "cookie": 1,
               "packet_count": 0,
               "byte_count": 0,
               "match": {
                 "eth_type": 2054
               },
               "importance": 0,
               "instructions": [
                 {
                   "type": "APPLY_ACTIONS",
                   "actions": [
                     {
                       "port": 2,
                       "max_len": 0,
                       "type": "OUTPUT"
                     }
                   ]
                 }
               ]
             }
           ]
       }



.. _get-aggregate-flow-stats:

Get aggregate flow stats
------------------------

    Get aggregate flow stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ============================
        Method  GET
        URI     /stats/aggregateflow/<dpid>
        ======= ============================

    Response message body:

        ============= =========================== ========
        Attribute     Description                 Example
        ============= =========================== ========
        dpid          Datapath ID                 "1"
        packet_count  Number of packets in flows  18
        byte_count    Number of bytes in flows    756
        flow_count    Number of flows             3
        ============= =========================== ========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/aggregateflow/1

    .. code-block:: javascript

        {
          "1": [
            {
              "packet_count": 18,
              "byte_count": 756,
              "flow_count": 3
            }
          ]
        }


Get aggregate flow stats filtered by fields
-------------------------------------------

    Get aggregate flow stats of the switch filtered by the OFPAggregateStats fields.
    This is POST method version of :ref:`get-aggregate-flow-stats`.

    Usage:

        ======= ============================
        Method  POST
        URI     /stats/aggregateflow/<dpid>
        ======= ============================

    Request message body:

        ============ ================================================================== =============== ===============
        Attribute    Description                                                        Example         Default
        ============ ================================================================== =============== ===============
        table_id     Table ID (int)                                                     0               OFPTT_ALL
        out_port     Require matching entries to include this as an output port (int)   2               OFPP_ANY
        out_group    Require matching entries to include this as an output group (int)  1               OFPG_ANY
        cookie       Require matching entries to contain this cookie value (int)        1               0
        cookie_mask  Mask used to restrict the cookie bits that must match (int)        1               0
        match        Fields to match (dict)                                             {"in_port": 1}  {} #wildcarded
        ============ ================================================================== =============== ===============

    Response message body:
        The same as :ref:`get-aggregate-flow-stats`

    Example of use::

        $ curl -X POST -d '{
             "table_id": 0,
             "out_port": 2,
             "cookie": 1,
             "cookie_mask": 1,
             "match":{
                 "in_port":1
             }
         }' http://localhost:8080/stats/aggregateflow/1

    .. code-block:: javascript

        {
          "1": [
            {
              "packet_count": 18,
              "byte_count": 756,
              "flow_count": 3
            }
          ]
        }


Get table stats
---------------

    Get table stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ===================
        Method  GET
        URI     /stats/table/<dpid>
        ======= ===================

    Response message body(OpenFlow1.0):

        =============== ============================================================ ============
        Attribute       Description                                                  Example
        =============== ============================================================ ============
        dpid            Datapath ID                                                  "1"
        table_id        Table ID                                                     0
        name            Name of Table                                                "classifier"
        max_entries     Max number of entries supported                              1e+06
        wildcards       Bitmap of OFPFW_* wildcards that are supported by the table  ["IN_PORT","DL_VLAN"]
        active_count    Number of active entries                                     0
        lookup_count    Number of packets looked up in table                         8
        matched_count   Number of packets that hit table                             0
        =============== ============================================================ ============

    Response message body(OpenFlow1.2):

        =============== ============================================================ ====================
        Attribute       Description                                                  Example
        =============== ============================================================ ====================
        dpid            Datapath ID                                                  "1"
        table_id        Table ID                                                     0
        name            Name of Table                                                "classifier"
        match           Bitmap of (1 << OFPXMT_*) that indicate the                  ["OFB_IN_PORT","OFB_METADATA"]
                        fields the table can match on
        wildcards       Bitmap of (1 << OFPXMT_*) wildcards that are                 ["OFB_IN_PORT","OFB_METADATA"]
                        supported by the table
        write_actions   Bitmap of OFPAT_* that are supported                         ["OUTPUT","SET_MPLS_TTL"]
                        by the table with OFPIT_WRITE_ACTIONS
        apply_actions   Bitmap of OFPAT_* that are supported                         ["OUTPUT","SET_MPLS_TTL"]
                        by the table with OFPIT_APPLY_ACTIONS
        write_setfields Bitmap of (1 << OFPXMT_*) header fields that                 ["OFB_IN_PORT","OFB_METADATA"]
                        can be set with OFPIT_WRITE_ACTIONS
        apply_setfields Bitmap of (1 << OFPXMT_*) header fields that                 ["OFB_IN_PORT","OFB_METADATA"]
                        can be set with OFPIT_APPLY_ACTIONS
        metadata_match  Bits of metadata table can match                             18446744073709552000
        metadata_write  Bits of metadata table can write                             18446744073709552000
        instructions    Bitmap of OFPIT_* values supported                           ["GOTO_TABLE","WRITE_METADATA"]
        config          Bitmap of OFPTC_* values                                     []
        max_entries     Max number of entries supported                              1e+06
        active_count    Number of active entries                                     0
        lookup_count    Number of packets looked up in table                         0
        matched_count   Number of packets that hit table                             8
        =============== ============================================================ ====================

    Response message body(OpenFlow1.3):

        ============== ============================================================= =========
        Attribute      Description                                                   Example
        ============== ============================================================= =========
        dpid           Datapath ID                                                   "1"
        table_id       Table ID                                                      0
        active_count   Number of active entries                                      0
        lookup_count   Number of packets looked up in table                          8
        matched_count  Number of packets that hit table                              0
        ============== ============================================================= =========


    Example of use::

        $ curl -X GET http://localhost:8080/stats/table/1

    Response (OpenFlow1.0):

    .. code-block:: javascript

        {
          "1": [
            {
              "table_id": 0,
              "lookup_count": 8,
              "max_entries": 1e+06,
              "active_count": 0,
              "name": "classifier",
              "matched_count": 0,
              "wildcards": [
               "IN_PORT",
               "DL_VLAN"
              ]
            },
            ...
            {
              "table_id": 253,
              "lookup_count": 0,
              "max_entries": 1e+06,
              "active_count": 0,
              "name": "table253",
              "matched_count": 0,
              "wildcards": [
               "IN_PORT",
               "DL_VLAN"
              ]
            }
          ]
        }

    Response (OpenFlow1.2):

    .. code-block:: javascript

        {
          "1": [
            {
              "apply_setfields": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "match": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "metadata_write": 18446744073709552000,
              "config": [],
              "instructions":[
               "GOTO_TABLE",
               "WRITE_METADATA"
              ],
              "table_id": 0,
              "metadata_match": 18446744073709552000,
              "lookup_count": 8,
              "wildcards": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "write_setfields": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "write_actions": [
               "OUTPUT",
               "SET_MPLS_TTL"
              ],
              "name": "classifier",
              "matched_count": 0,
              "apply_actions": [
               "OUTPUT",
               "SET_MPLS_TTL"
              ],
              "active_count": 0,
              "max_entries": 1e+06
            },
            ...
            {
              "apply_setfields": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "match": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "metadata_write": 18446744073709552000,
              "config": [],
              "instructions": [
               "GOTO_TABLE",
               "WRITE_METADATA"
              ],
              "table_id": 253,
              "metadata_match": 18446744073709552000,
              "lookup_count": 0,
              "wildcards": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "write_setfields": [
               "OFB_IN_PORT",
               "OFB_METADATA"
              ],
              "write_actions": [
               "OUTPUT",
               "SET_MPLS_TTL"
              ],
              "name": "table253",
              "matched_count": 0,
              "apply_actions": [
               "OUTPUT",
               "SET_MPLS_TTL"
              ],
              "active_count": 0,
              "max_entries": 1e+06
            }
          ]
        }

    Response (OpenFlow1.3):

    .. code-block:: javascript

        {
          "1": [
            {
              "active_count": 0,
              "table_id": 0,
              "lookup_count": 8,
              "matched_count": 0
            },
            ...
            {
              "active_count": 0,
              "table_id": 253,
              "lookup_count": 0,
              "matched_count": 0
            }
          ]
        }


Get table features
------------------

    Get table features of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ===========================
        Method  GET
        URI     /stats/tablefeatures/<dpid>
        ======= ===========================

    Response message body:

        ============== ==================================== =======================================================
        Attribute      Description                          Example
        ============== ==================================== =======================================================
        dpid           Datapath ID                          "1"
        table_id       Table ID                             0
        name           Name of Table                        "table_0"
        metadata_match Bits of metadata table can match     18446744073709552000
        metadata_write Bits of metadata table can write     18446744073709552000
        config         Bitmap of OFPTC_* values             0
        max_entries    Max number of entries supported      4096
        properties     struct ofp_table_feature_prop_header [{"type": "INSTRUCTIONS","instruction_ids": [...]},...]
        ============== ==================================== =======================================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/tablefeatures/1

    .. code-block:: javascript

        {
          "1": [
            {
              "metadata_write": 18446744073709552000,
              "config": 0,
              "table_id": 0,
              "metadata_match": 18446744073709552000,
              "max_entries": 4096,
              "properties": [
                {
                  "type": "INSTRUCTIONS",
                  "instruction_ids": [
                   {
                   "len": 4,
                   "type": 1
                   },
                   ...
                  ]
                },
                ...
              ],
              "name": "table_0"
            },
            {
              "metadata_write": 18446744073709552000,
              "config": 0,
              "table_id": 1,
              "metadata_match": 18446744073709552000,
              "max_entries": 4096,
              "properties": [
                {
                  "type": "INSTRUCTIONS",
                  "instruction_ids": [
                   {
                   "len": 4,
                   "type": 1
                   },
                   ...
                  ]
                },
                ...
              ],
              "name": "table_1"
            },
            ...
          ]
        }


Get ports stats
---------------

    Get ports stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ===========================
        Method  GET
        URI     /stats/port/<dpid>[/<port>]
        ======= ===========================

        .. NOTE::

           Specification of port number is optional.


    Response message body(OpenFlow1.3 or earlier):

        ============== ============================================================ =========
        Attribute      Description                                                  Example
        ============== ============================================================ =========
        dpid           Datapath ID                                                  "1"
        port_no        Port number                                                  1
        rx_packets     Number of received packets                                   9
        tx_packets     Number of transmitted packets                                6
        rx_bytes       Number of received bytes                                     738
        tx_bytes       Number of transmitted bytes                                  252
        rx_dropped     Number of packets dropped by RX                              0
        tx_dropped     Number of packets dropped by TX                              0
        rx_errors      Number of receive errors                                     0
        tx_errors      Number of transmit errors                                    0
        rx_frame_err   Number of frame alignment errors                             0
        rx_over_err    Number of packets with RX overrun                            0
        rx_crc_err     Number of CRC errors                                         0
        collisions     Number of collisions                                         0
        duration_sec   Time port has been alive in seconds                          12
        duration_nsec  Time port has been alive in nanoseconds beyond duration_sec  9.76e+08
        ============== ============================================================ =========


    Response message body(OpenFlow1.4 or later):

        ============== ============================================================ =================================================================================
        Attribute      Description                                                  Example
        ============== ============================================================ =================================================================================
        dpid           Datapath ID                                                  "1"
        port_no        Port number                                                  1
        rx_packets     Number of received packets                                   9
        tx_packets     Number of transmitted packets                                6
        rx_bytes       Number of received bytes                                     738
        tx_bytes       Number of transmitted bytes                                  252
        rx_dropped     Number of packets dropped by RX                              0
        tx_dropped     Number of packets dropped by TX                              0
        rx_errors      Number of receive errors                                     0
        tx_errors      Number of transmit errors                                    0
        duration_sec   Time port has been alive in seconds                          12
        duration_nsec  Time port has been alive in nanoseconds beyond duration_sec  9.76e+08
        properties     struct ofp_port_desc_prop_header                             [{"rx_frame_err": 0, "rx_over_err": 0, "rx_crc_err": 0, "collisions": 0,...},...]
        ============== ============================================================ =================================================================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/port/1

    Response (OpenFlow1.3 or earlier):

    .. code-block:: javascript

        {
          "1": [
            {
              "port_no": 1,
              "rx_packets": 9,
              "tx_packets": 6,
              "rx_bytes": 738,
              "tx_bytes": 252,
              "rx_dropped": 0,
              "tx_dropped": 0,
              "rx_errors": 0,
              "tx_errors": 0,
              "rx_frame_err": 0,
              "rx_over_err": 0,
              "rx_crc_err": 0,
              "collisions": 0,
              "duration_sec": 12,
              "duration_nsec": 9.76e+08
            },
            {
              :
              :
            }
          ]
        }

    Response (OpenFlow1.4 or later):

    .. code-block:: javascript

        {
           "1": [
             {
               "port_no": 1,
               "rx_packets": 9,
               "tx_packets": 6,
               "rx_bytes": 738,
               "tx_bytes": 252,
               "rx_dropped": 0,
               "tx_dropped": 0,
               "rx_errors": 0,
               "tx_errors": 0,
               "duration_nsec": 12,
               "duration_sec": 9.76e+08,
               "properties": [
                 {
                   "rx_frame_err": 0,
                   "rx_over_err": 0,
                   "rx_crc_err": 0,
                   "collisions": 0,
                   "type": "ETHERNET"
                 },
                 {
                   "bias_current": 300,
                   "flags": 3,
                   "rx_freq_lmda": 1500,
                   "rx_grid_span": 500,
                   "rx_offset": 700,
                   "rx_pwr": 2000,
                   "temperature": 273,
                   "tx_freq_lmda": 1500,
                   "tx_grid_span": 500,
                   "tx_offset": 700,
                   "tx_pwr": 2000,
                   "type": "OPTICAL"
                 },
                 {
                   "data": [],
                   "exp_type": 0,
                   "experimenter": 101,
                   "type": "EXPERIMENTER"
                 },
                 {
                   :

                   :
                 }
               ]
             }
           ]
         }


.. _get-ports-description:

Get ports description
---------------------

    Get ports description of the switch which specified with Datapath ID in URI.

    Usage(OpenFlow1.4 or earlier):

        ======= =======================
        Method  GET
        URI     /stats/portdesc/<dpid>
        ======= =======================

    Usage(OpenFlow1.5 or later):

        ======= ==================================
        Method  GET
        URI     /stats/portdesc/<dpid>/[<port>]
        ======= ==================================

        .. NOTE::

           Specification of port number is optional.


    Response message body(OpenFlow1.3 or earlier):

        ============== ====================================== ====================
        Attribute      Description                            Example
        ============== ====================================== ====================
        dpid           Datapath ID                            "1"
        port_no        Port number                            1
        hw_addr        Ethernet hardware address              "0a:b6:d0:0c:e1:d7"
        name           Name of port                           "s1-eth1"
        config         Bitmap of OFPPC_* flags                0
        state          Bitmap of OFPPS_* flags                0
        curr           Current features                       2112
        advertised     Features being advertised by the port  0
        supported      Features supported by the port         0
        peer           Features advertised by peer            0
        curr_speed     Current port bitrate in kbps           1e+07
        max_speed      Max port bitrate in kbps               0
        ============== ====================================== ====================

    Response message body(OpenFlow1.4 or later):

        ============== ====================================== ======================================
        Attribute      Description                            Example
        ============== ====================================== ======================================
        dpid           Datapath ID                            "1"
        port_no        Port number                            1
        hw_addr        Ethernet hardware address              "0a:b6:d0:0c:e1:d7"
        name           Name of port                           "s1-eth1"
        config         Bitmap of OFPPC_* flags                0
        state          Bitmap of OFPPS_* flags                0
        length         Length of this entry                   168
        properties     struct ofp_port_desc_prop_header       [{"length": 32, "curr": 10248,...}...]
        ============== ====================================== ======================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/portdesc/1

    Response (OpenFlow1.3 or earlier):

    .. code-block:: javascript

        {
          "1": [
            {
              "port_no": 1,
              "hw_addr": "0a:b6:d0:0c:e1:d7",
              "name": "s1-eth1",
              "config": 0,
              "state": 0,
              "curr": 2112,
              "advertised": 0,
              "supported": 0,
              "peer": 0,
              "curr_speed": 1e+07,
              "max_speed": 0
            },
            {
              :
              :
            }
          ]
        }

    Response (OpenFlow1.4 or later):

    .. code-block:: javascript

        {
           "1": [
             {
               "port_no": 1,
               "hw_addr": "0a:b6:d0:0c:e1:d7",
               "name": "s1-eth1",
               "config": 0,
               "state": 0,
               "length": 168,
               "properties": [
                 {
                   "length": 32,
                   "curr": 10248,
                   "advertised": 10240,
                   "supported": 10248,
                   "peer": 10248,
                   "curr_speed": 5000,
                   "max_speed": 5000,
                   "type": "ETHERNET"
                 },
                 {
                   "length": 40,
                   "rx_grid_freq_lmda": 1500,
                   "tx_grid_freq_lmda": 1500,
                   "rx_max_freq_lmda": 2000,
                   "tx_max_freq_lmda": 2000,
                   "rx_min_freq_lmda": 1000,
                   "tx_min_freq_lmda": 1000,
                   "tx_pwr_max": 2000,
                   "tx_pwr_min": 1000,
                   "supported": 1,
                   "type": "OPTICAL"
                 },
                 {
                   "data": [],
                   "exp_type": 0,
                   "experimenter": 101,
                   "length": 12,
                   "type": "EXPERIMENTER"
                 },
                 {
                   :

                   :
                 }
               ]
             }
           ]
        }


Get queues stats
----------------

    Get queues stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= =========================================
        Method  GET
        URI     /stats/queue/<dpid>[/<port>[/<queue_id>]]
        ======= =========================================

        .. NOTE::

           Specification of port number and queue id are optional.

           If you want to omitting the port number and setting the queue id,
           please specify the keyword "ALL" to the port number.

           e.g. GET http://localhost:8080/stats/queue/1/ALL/1


    Response message body(OpenFlow1.3 or earlier):

        ============== ============================================================= ===========
        Attribute      Description                                                   Example
        ============== ============================================================= ===========
        dpid           Datapath ID                                                   "1"
        port_no        Port number                                                   1
        queue_id       Queue ID                                                      0
        tx_bytes       Number of transmitted bytes                                   0
        tx_packets     Number of transmitted packets                                 0
        tx_errors      Number of packets dropped due to overrun                      0
        duration_sec   Time queue has been alive in seconds                          4294963425
        duration_nsec  Time queue has been alive in nanoseconds beyond duration_sec  3912967296
        ============== ============================================================= ===========

    Response message body(OpenFlow1.4 or later):

        ============== ============================================================= ======================================
        Attribute      Description                                                   Example
        ============== ============================================================= ======================================
        dpid           Datapath ID                                                   "1"
        port_no        Port number                                                   1
        queue_id       Queue ID                                                      0
        tx_bytes       Number of transmitted bytes                                   0
        tx_packets     Number of transmitted packets                                 0
        tx_errors      Number of packets dropped due to overrun                      0
        duration_sec   Time queue has been alive in seconds                          4294963425
        duration_nsec  Time queue has been alive in nanoseconds beyond duration_sec  3912967296
        length         Length of this entry                                          104
        properties     struct ofp_queue_stats_prop_header                            [{"type": 65535,"length": 12,...},...]
        ============== ============================================================= ======================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/queue/1

    Response (OpenFlow1.3 or earlier):

    .. code-block:: javascript

        {
          "1": [
            {
              "port_no": 1,
              "queue_id": 0,
              "tx_bytes": 0,
              "tx_packets": 0,
              "tx_errors": 0,
              "duration_sec": 4294963425,
              "duration_nsec": 3912967296
            },
            {
              "port_no": 1,
              "queue_id": 1,
              "tx_bytes": 0,
              "tx_packets": 0,
              "tx_errors": 0,
              "duration_sec": 4294963425,
              "duration_nsec": 3912967296
            }
          ]
        }

    Response (OpenFlow1.4 or later):

    .. code-block:: javascript

        {
          "1": [
            {
              "port_no": 1,
              "queue_id": 0,
              "tx_bytes": 0,
              "tx_packets": 0,
              "tx_errors": 0,
              "duration_sec": 4294963425,
              "duration_nsec": 3912967296,
              "length": 104,
              "properties": [
                 {
                    "OFPQueueStatsPropExperimenter": {
                       "type": 65535,
                       "length": 16,
                       "data": [
                          1
                       ],
                       "exp_type": 1,
                       "experimenter": 101
                    }
                 },
                 {
                    :

                    :
                 }
              ]
            },
            {
              "port_no": 2,
              "queue_id": 1,
              "tx_bytes": 0,
              "tx_packets": 0,
              "tx_errors": 0,
              "duration_sec": 4294963425,
              "duration_nsec": 3912967296,
              "length": 48,
              "properties": []
            }
          ]
        }

.. _get-queues-config:

Get queues config
-----------------

    Get queues config of the switch which specified with Datapath ID and Port in URI.

    Usage:

        ======= ==================================
        Method  GET
        URI     /stats/queueconfig/<dpid>/[<port>]
        ======= ==================================

        .. NOTE::

           Specification of port number is optional.


        .. CAUTION::

           This message is deprecated in Openflow1.4.
           If OpenFlow 1.4 or later is in use, please refer to :ref:`get-queues-description` instead.

    Response message body:

        ================ ====================================================== ========================================
        Attribute        Description                                            Example
        ================ ====================================================== ========================================
        dpid             Datapath ID                                            "1"
        port             Port which was queried                                 1
        queues           struct ofp_packet_queue
        -- queue_id      ID for the specific queue                              2
        -- port          Port this queue is attached to                         0
        -- properties    struct ofp_queue_prop_header properties                [{"property": "MIN_RATE","rate": 80}]
        ================ ====================================================== ========================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/queueconfig/1/1

    .. code-block:: javascript

        {
          "1": [
            {
              "port": 1,
              "queues": [
                {
                  "properties": [
                    {
                      "property": "MIN_RATE",
                      "rate": 80
                    }
                  ],
                  "port": 0,
                  "queue_id": 1
                },
                {
                  "properties": [
                    {
                      "property": "MAX_RATE",
                      "rate": 120
                    }
                  ],
                  "port": 2,
                  "queue_id": 2
                },
                {
                  "properties": [
                    {
                      "property": "EXPERIMENTER",
                      "data": [],
                      "experimenter": 999
                    }
                  ],
                  "port": 3,
                  "queue_id": 3
                }
              ]
            }
          ]
        }

.. _get-queues-description:

Get queues description
----------------------

    Get queues description of the switch which specified with Datapath ID, Port and Queue_id in URI.

    Usage:

        ======= =============================================
        Method  GET
        URI     /stats/queuedesc/<dpid>[/<port>/[<queue_id>]]
        ======= =============================================

        .. NOTE::

           Specification of port number and queue id are optional.

           If you want to omitting the port number and setting the queue id,
           please specify the keyword "ALL" to the port number.

           e.g. GET http://localhost:8080/stats/queuedesc/1/ALL/1


        .. CAUTION::

           This message is available in OpenFlow1.4 or later.
           If Openflow1.3 or earlier is in use, please refer to :ref:`get-queues-config` instead.


    Response message body:

        ================ ====================================================== ========================================
        Attribute        Description                                            Example
        ================ ====================================================== ========================================
        dpid             Datapath ID                                            "1"
        len              Length in bytes of this queue desc                     88
        port_no          Port which was queried                                 1
        queue_id         Queue ID                                               1
        properties       struct ofp_queue_desc_prop_header                      [{"length": 8, ...},...]
        ================ ====================================================== ========================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/queuedesc/1/1/1

    .. code-block:: javascript


        {
         "1": [
             {
               "len": 88,
               "port_no": 1,
               "queue_id": 1,
               "properties": [
                 {
                   "length": 8,
                   "rate": 300,
                   "type": "MIN_RATE"
                 },
                 {
                   "length": 8,
                   "rate": 900,
                   "type": "MAX_RATE"
                 },
                 {
                   "length": 16,
                   "exp_type": 0,
                   "experimenter": 101,
                   "data": [1],
                   "type": "EXPERIMENTER"
                 },
                 {
                   :

                   :
                 }
               ]
             }
           ]
         }


Get groups stats
----------------

    Get groups stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ================================
        Method  GET
        URI     /stats/group/<dpid>[/<group_id>]
        ======= ================================

        .. NOTE::

           Specification of group id is optional.


    Response message body:

        ================ ============================================================== =========
        Attribute        Description                                                    Example
        ================ ============================================================== =========
        dpid             Datapath ID                                                    "1"
        length           Length of this entry                                           56
        group_id         Group ID                                                       1
        ref_count        Number of flows or groups that directly forward to this group  1
        packet_count     Number of packets processed by group                           0
        byte_count       Number of bytes processed by group                             0
        duration_sec     Time group has been alive in seconds                           161
        duration_nsec    Time group has been alive in nanoseconds beyond duration_sec   3.03e+08
        bucket_stats     struct ofp_bucket_counter
        -- packet_count  Number of packets processed by bucket                          0
        -- byte_count    Number of bytes processed by bucket                            0
        ================ ============================================================== =========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/group/1

    .. code-block:: javascript

        {
          "1": [
            {
              "length": 56,
              "group_id": 1,
              "ref_count": 1,
              "packet_count": 0,
              "byte_count": 0,
              "duration_sec": 161,
              "duration_nsec": 3.03e+08,
              "bucket_stats": [
                {
                  "packet_count": 0,
                  "byte_count": 0
                }
              ]
            }
          ]
        }


.. _get-group-description-stats:

Get group description stats
---------------------------

    Get group description stats of the switch which specified with Datapath ID in URI.

    Usage(Openflow1.4 or earlier):

        ======= ========================
        Method  GET
        URI     /stats/groupdesc/<dpid>
        ======= ========================

    Usage(Openflow1.5 or later):

        ======= ====================================
        Method  GET
        URI     /stats/groupdesc/<dpid>/[<group_id>]
        ======= ====================================

        .. NOTE::

           Specification of group id is optional.


    Response message body(Openflow1.3 or earlier):

        =============== ======================================================= =============
        Attribute       Description                                             Example
        =============== ======================================================= =============
        dpid            Datapath ID                                             "1"
        type            One of OFPGT_*                                          "ALL"
        group_id        Group ID                                                1
        buckets         struct ofp_bucket
        -- weight       Relative weight of bucket                               0
                        (Only defined for select groups)
        -- watch_port   Port whose state affects whether this bucket is live    4294967295
                        (Only required for fast failover groups)
        -- watch_group  Group whose state affects whether this bucket is live   4294967295
                        (Only required for fast failover groups)
        -- actions      0 or more actions associated with the bucket            ["OUTPUT:1"]
        =============== ======================================================= =============

    Response message body(Openflow1.4 or later):

        =============== ======================================================= ====================================
        Attribute       Description                                             Example
        =============== ======================================================= ====================================
        dpid            Datapath ID                                             "1"
        type            One of OFPGT_*                                          "ALL"
        group_id        Group ID                                                1
        length          Length of this entry                                    40
        buckets         struct ofp_bucket
        -- weight       Relative weight of bucket                               0
                        (Only defined for select groups)
        -- watch_port   Port whose state affects whether this bucket is live    4294967295
                        (Only required for fast failover groups)
        -- watch_group  Group whose state affects whether this bucket is live   4294967295
                        (Only required for fast failover groups)
        -- len          Length the bucket in bytes, including this header and   32
                        any adding to make it 64-bit aligned.
        -- actions      0 or more actions associated with the bucket            [{"OUTPUT:1", "max_len": 65535,...}]
        =============== ======================================================= ====================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/groupdesc/1

    Response (Openflow1.3 or earlier):

    .. code-block:: javascript

        {
          "1": [
            {
              "type": "ALL",
              "group_id": 1,
              "buckets": [
                {
                  "weight": 0,
                  "watch_port": 4294967295,
                  "watch_group": 4294967295,
                  "actions": [
                    "OUTPUT:1"
                  ]
                }
              ]
            }
          ]
        }

    Response (Openflow1.4 or later):

    .. code-block:: javascript

        {
           "1": [
             {
               "type": "ALL",
               "group_id": 1,
               "length": 40,
               "buckets": [
                 {
                   "weight": 1,
                   "watch_port": 1,
                   "watch_group": 1,
                   "len": 32,
                   "actions": [
                     {
                         "type": "OUTPUT",
                         "max_len": 65535,
                         "port": 2
                     }
                   ]
                 }
               ]
             }
           ]
        }


Get group features stats
------------------------

    Get group features stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ============================
        Method  GET
        URI     /stats/groupfeatures/<dpid>
        ======= ============================

    Response message body:

        ============== =========================================== ===============================================
        Attribute      Description                                 Example
        ============== =========================================== ===============================================
        dpid           Datapath ID                                 "1"
        types          Bitmap of (1 << OFPGT_*) values supported   []
        capabilities   Bitmap of OFPGFC_* capability supported     ["SELECT_WEIGHT","SELECT_LIVENESS","CHAINING"]
        max_groups     Maximum number of groups for each type      [{"ALL": 4294967040},...]
        actions        Bitmaps of (1 << OFPAT_*) values supported  [{"ALL": ["OUTPUT",...]},...]
        ============== =========================================== ===============================================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/groupfeatures/1

    .. code-block:: javascript

        {
          "1": [
            {
              "types": [],
              "capabilities": [
                "SELECT_WEIGHT",
                "SELECT_LIVENESS",
                "CHAINING"
              ],
              "max_groups": [
                {
                  "ALL": 4294967040
                },
                {
                  "SELECT": 4294967040
                },
                {
                  "INDIRECT": 4294967040
                },
                {
                  "FF": 4294967040
                }
              ],
              "actions": [
                {
                  "ALL": [
                    "OUTPUT",
                    "COPY_TTL_OUT",
                    "COPY_TTL_IN",
                    "SET_MPLS_TTL",
                    "DEC_MPLS_TTL",
                    "PUSH_VLAN",
                    "POP_VLAN",
                    "PUSH_MPLS",
                    "POP_MPLS",
                    "SET_QUEUE",
                    "GROUP",
                    "SET_NW_TTL",
                    "DEC_NW_TTL",
                    "SET_FIELD"
                  ]
                },
                {
                  "SELECT": []
                },
                {
                  "INDIRECT": []
                },
                {
                  "FF": []
                }
              ]
            }
          ]
        }


Get meters stats
----------------

    Get meters stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ================================
        Method  GET
        URI     /stats/meter/<dpid>[/<meter_id>]
        ======= ================================

        .. NOTE::

           Specification of meter id is optional.


    Response message body:

        ===================== ============================================================= ========
        Attribute             Description                                                   Example
        ===================== ============================================================= ========
        dpid                  Datapath ID                                                   "1"
        meter_id              Meter ID                                                      1
        len                   Length in bytes of this stats                                 56
        flow_count            Number of flows bound to meter                                0
        packet_in_count       Number of packets in input                                    0
        byte_in_count         Number of bytes in input                                      0
        duration_sec          Time meter has been alive in seconds                          37
        duration_nsec         Time meter has been alive in nanoseconds beyond duration_sec  988000
        band_stats            struct ofp_meter_band_stats
        -- packet_band_count  Number of packets in band                                     0
        -- byte_band_count    Number of bytes in band                                       0
        ===================== ============================================================= ========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/meter/1

    .. code-block:: javascript

        {
          "1": [
            {
              "meter_id": 1,
              "len": 56,
              "flow_count": 0,
              "packet_in_count": 0,
              "byte_in_count": 0,
              "duration_sec": 37,
              "duration_nsec": 988000,
              "band_stats": [
                {
                  "packet_band_count": 0,
                  "byte_band_count": 0
                }
              ]
            }
          ]
        }


.. _get-meter-config-stats:

Get meter config stats
----------------------
Get meter description stats
---------------------------

    Get meter config stats of the switch which specified with Datapath ID in URI.

        .. CAUTION::

           This message has been renamed in openflow 1.5.
           If Openflow 1.4 or earlier is in use, please used as Get meter description stats.
           If Openflow 1.5 or later is in use, please used as Get meter description stats.


    Usage(Openflow1.4 or earlier):

        ======= ======================================
        Method  GET
        URI     /stats/meterconfig/<dpid>[/<meter_id>]
        ======= ======================================

    Usage(Openflow1.5 or later):

        ======= ======================================
        Method  GET
        URI     /stats/meterdesc/<dpid>[/<meter_id>]
        ======= ======================================

        .. NOTE::

           Specification of meter id is optional.


    Response message body:

        ============== ============================================ =========
        Attribute      Description                                  Example
        ============== ============================================ =========
        dpid           Datapath ID                                  "1"
        flags          All OFPMC_* that apply                       "KBPS"
        meter_id       Meter ID                                     1
        bands          struct ofp_meter_band_header
        -- type        One of OFPMBT_*                              "DROP"
        -- rate        Rate for this band                           1000
        -- burst_size  Size of bursts                               0
        ============== ============================================ =========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/meterconfig/1

    .. code-block:: javascript

        {
          "1": [
            {
              "flags": [
                "KBPS"
              ],
              "meter_id": 1,
              "bands": [
                {
                  "type": "DROP",
                  "rate": 1000,
                  "burst_size": 0
                }
              ]
            }
          ]
        }


Get meter features stats
------------------------

    Get meter features stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ============================
        Method  GET
        URI     /stats/meterfeatures/<dpid>
        ======= ============================

    Response message body:

        ============= ============================================ ===========================
        Attribute     Description                                  Example
        ============= ============================================ ===========================
        dpid          Datapath ID                                  "1"
        max_meter     Maximum number of meters                     256
        band_types    Bitmaps of (1 << OFPMBT_*) values supported  ["DROP"]
        capabilities  Bitmaps of "ofp_meter_flags"                 ["KBPS", "BURST", "STATS"]
        max_bands     Maximum bands per meters                     16
        max_color     Maximum color value                          8
        ============= ============================================ ===========================

    Example of use::

        $ curl -X GET http://localhost:8080/stats/meterfeatures/1

    .. code-block:: javascript

        {
          "1": [
            {
              "max_meter": 256,
              "band_types": [
                "DROP"
              ],
              "capabilities": [
                "KBPS",
                "BURST",
                "STATS"
              ],
              "max_bands": 16,
              "max_color": 8
            }
          ]
        }


Update the switch stats
=======================

Add a flow entry
----------------

    Add a flow entry to the switch.

    Usage:

        ======= =====================
        Method  POST
        URI     /stats/flowentry/add
        ======= =====================

    Request message body(Openflow1.3 or earlier):

        ============= ===================================================== ============================== ===============
        Attribute     Description                                           Example                        Default
        ============= ===================================================== ============================== ===============
        dpid          Datapath ID (int)                                     1                              (Mandatory)
        cookie        Opaque controller-issued identifier (int)             1                              0
        cookie_mask   Mask used to restrict the cookie bits (int)           1                              0
        table_id      Table ID to put the flow in (int)                     0                              0
        idle_timeout  Idle time before discarding (seconds) (int)           30                             0
        hard_timeout  Max time before discarding (seconds) (int)            30                             0
        priority      Priority level of flow entry (int)                    11111                          0
        buffer_id     Buffered packet to apply to, or OFP_NO_BUFFER (int)   1                              OFP_NO_BUFFER
        flags         Bitmap of OFPFF_* flags (int)                         1                              0
        match         Fields to match (dict)                                {"in_port":1}                  {} #wildcarded
        actions       Instruction set (list of dict)                        [{"type":"OUTPUT", "port":2}]  [] #DROP
        ============= ===================================================== ============================== ===============

    Request message body(Openflow1.4 or later):

        ============= ===================================================== ================================ ===============
        Attribute     Description                                           Example                          Default
        ============= ===================================================== ================================ ===============
        dpid          Datapath ID (int)                                     1                                (Mandatory)
        cookie        Opaque controller-issued identifier (int)             1                                0
        cookie_mask   Mask used to restrict the cookie bits (int)           1                                0
        table_id      Table ID to put the flow in (int)                     0                                0
        idle_timeout  Idle time before discarding (seconds) (int)           30                               0
        hard_timeout  Max time before discarding (seconds) (int)            30                               0
        priority      Priority level of flow entry (int)                    11111                            0
        buffer_id     Buffered packet to apply to, or OFP_NO_BUFFER (int)   1                                OFP_NO_BUFFER
        flags         Bitmap of OFPFF_* flags (int)                         1                                0
        match         Fields to match (dict)                                {"in_port":1}                    {} #wildcarded
        instructions  Instruction set (list of dict)                        [{"type":"METER", "meter_id":2}] [] #DROP
        ============= ===================================================== ================================ ===============

    .. NOTE::

        For description of match and actions, please see :ref:`description-of-match-and-actions`.

    Example of use(Openflow1.3 or earlier):

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 30,
            "hard_timeout": 30,
            "priority": 11111,
            "flags": 1,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 2
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "priority": 22222,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"GOTO_TABLE",
                    "table_id": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "priority": 33333,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"WRITE_METADATA",
                    "metadata": 1,
                    "metadata_mask": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "priority": 44444,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"METER",
                    "meter_id": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    Example of use(Openflow1.4 or later):

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 30,
            "hard_timeout": 30,
            "priority": 11111,
            "flags": 1,
            "match":{
                "in_port":1
            },
            "instructions": [
                {
                    "type": "APPLY_ACTIONS",
                    "actions": [
                        {
                            "max_len": 65535,
                            "port": 2,
                            "type": "OUTPUT"
                        }
                    ]
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "priority": 22222,
            "match":{
                "in_port":1
            },
            "instructions": [
                {
                    "type":"GOTO_TABLE",
                    "table_id": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "priority": 33333,
            "match":{
                "in_port":1
            },
            "instructions": [
                {
                    "type":"WRITE_METADATA",
                    "metadata": 1,
                    "metadata_mask": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{
            "dpid": 1,
            "priority": 44444,
            "match":{
                "in_port":1
            },
            "instructions": [
                {
                    "type":"METER",
                    "meter_id": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    .. NOTE::

        To confirm flow entry registration, please see :ref:`get-all-flows-stats` or :ref:`get-flows-stats-filtered`.


Modify all matching flow entries
--------------------------------

    Modify all matching flow entries of the switch.

    Usage:

        ======= ========================
        Method  POST
        URI     /stats/flowentry/modify
        ======= ========================

    Request message body:

        ============= ===================================================== ============================== ===============
        Attribute     Description                                           Example                        Default
        ============= ===================================================== ============================== ===============
        dpid          Datapath ID (int)                                     1                              (Mandatory)
        cookie        Opaque controller-issued identifier (int)             1                              0
        cookie_mask   Mask used to restrict the cookie bits (int)           1                              0
        table_id      Table ID to put the flow in (int)                     0                              0
        idle_timeout  Idle time before discarding (seconds) (int)           30                             0
        hard_timeout  Max time before discarding (seconds) (int)            30                             0
        priority      Priority level of flow entry (int)                    11111                          0
        buffer_id     Buffered packet to apply to, or OFP_NO_BUFFER (int)   1                              OFP_NO_BUFFER
        flags         Bitmap of OFPFF_* flags (int)                         1                              0
        match         Fields to match (dict)                                {"in_port":1}                  {} #wildcarded
        actions       Instruction set (list of dict)                        [{"type":"OUTPUT", "port":2}]  [] #DROP
        ============= ===================================================== ============================== ===============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 30,
            "hard_timeout": 30,
            "priority": 11111,
            "flags": 1,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 2
                }
            ]
         }' http://localhost:8080/stats/flowentry/modify


Modify flow entry strictly
--------------------------

    Modify flow entry strictly matching wildcards and priority

    Usage:

        ======= ===============================
        Method  POST
        URI     /stats/flowentry/modify_strict
        ======= ===============================

    Request message body:

        ============= ===================================================== ============================== ===============
        Attribute     Description                                           Example                        Default
        ============= ===================================================== ============================== ===============
        dpid          Datapath ID (int)                                     1                              (Mandatory)
        cookie        Opaque controller-issued identifier (int)             1                              0
        cookie_mask   Mask used to restrict the cookie bits (int)           1                              0
        table_id      Table ID to put the flow in (int)                     0                              0
        idle_timeout  Idle time before discarding (seconds) (int)           30                             0
        hard_timeout  Max time before discarding (seconds) (int)            30                             0
        priority      Priority level of flow entry (int)                    11111                          0
        buffer_id     Buffered packet to apply to, or OFP_NO_BUFFER (int)   1                              OFP_NO_BUFFER
        flags         Bitmap of OFPFF_* flags (int)                         1                              0
        match         Fields to match (dict)                                {"in_port":1}                  {} #wildcarded
        actions       Instruction set (list of dict)                        [{"type":"OUTPUT", "port":2}]  [] #DROP
        ============= ===================================================== ============================== ===============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 30,
            "hard_timeout": 30,
            "priority": 11111,
            "flags": 1,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 2
                }
            ]
         }' http://localhost:8080/stats/flowentry/modify_strict


Delete all matching flow entries
--------------------------------

    Delete all matching flow entries of the switch.

    Usage:

        ======= ========================
        Method  POST
        URI     /stats/flowentry/delete
        ======= ========================

    Request message body:

        ============= ===================================================== ============================== ===============
        Attribute     Description                                           Example                        Default
        ============= ===================================================== ============================== ===============
        dpid          Datapath ID (int)                                     1                              (Mandatory)
        cookie        Opaque controller-issued identifier (int)             1                              0
        cookie_mask   Mask used to restrict the cookie bits (int)           1                              0
        table_id      Table ID to put the flow in (int)                     0                              0
        idle_timeout  Idle time before discarding (seconds) (int)           30                             0
        hard_timeout  Max time before discarding (seconds) (int)            30                             0
        priority      Priority level of flow entry (int)                    11111                          0
        buffer_id     Buffered packet to apply to, or OFP_NO_BUFFER (int)   1                              OFP_NO_BUFFER
        out_port      Output port (int)                                     1                              OFPP_ANY
        out_group     Output group (int)                                    1                              OFPG_ANY
        flags         Bitmap of OFPFF_* flags (int)                         1                              0
        match         Fields to match (dict)                                {"in_port":1}                  {} #wildcarded
        actions       Instruction set (list of dict)                        [{"type":"OUTPUT", "port":2}]  [] #DROP
        ============= ===================================================== ============================== ===============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 30,
            "hard_timeout": 30,
            "priority": 11111,
            "flags": 1,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 2
                }
            ]
         }' http://localhost:8080/stats/flowentry/delete


Delete flow entry strictly
--------------------------

    Delete flow entry strictly matching wildcards and priority.

    Usage:

        ======= ===============================
        Method  POST
        URI     /stats/flowentry/delete_strict
        ======= ===============================

    Request message body:

        ============= ===================================================== ============================== ===============
        Attribute     Description                                           Example                        Default
        ============= ===================================================== ============================== ===============
        dpid          Datapath ID (int)                                     1                              (Mandatory)
        cookie        Opaque controller-issued identifier (int)             1                              0
        cookie_mask   Mask used to restrict the cookie bits (int)           1                              0
        table_id      Table ID to put the flow in (int)                     0                              0
        idle_timeout  Idle time before discarding (seconds) (int)           30                             0
        hard_timeout  Max time before discarding (seconds) (int)            30                             0
        priority      Priority level of flow entry (int)                    11111                          0
        buffer_id     Buffered packet to apply to, or OFP_NO_BUFFER (int)   1                              OFP_NO_BUFFER
        out_port      Output port (int)                                     1                              OFPP_ANY
        out_group     Output group (int)                                    1                              OFPG_ANY
        flags         Bitmap of OFPFF_* flags (int)                         1                              0
        match         Fields to match (dict)                                {"in_port":1}                  {} #wildcarded
        actions       Instruction set (list of dict)                        [{"type":"OUTPUT", "port":2}]  [] #DROP
        ============= ===================================================== ============================== ===============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 30,
            "hard_timeout": 30,
            "priority": 11111,
            "flags": 1,
            "match":{
                "in_port":1
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 2
                }
            ]
         }' http://localhost:8080/stats/flowentry/delete_strict


Delete all flow entries
-----------------------

    Delete all flow entries of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ==============================
        Method  DELETE
        URI     /stats/flowentry/clear/<dpid>
        ======= ==============================

    Example of use::

        $ curl -X DELETE http://localhost:8080/stats/flowentry/clear/1


Add a group entry
-----------------

    Add a group entry to the switch.

    Usage:

        ======= ======================
        Method  POST
        URI     /stats/groupentry/add
        ======= ======================

    Request message body:

        =============== ============================================================ ================================ ============
        Attribute       Description                                                  Example                          Default
        =============== ============================================================ ================================ ============
        dpid            Datapath ID (int)                                            1                                (Mandatory)
        type            One of OFPGT_* (string)                                      "ALL"                            "ALL"
        group_id        Group ID (int)                                               1                                0
        buckets         struct ofp_bucket
        -- weight       Relative weight of bucket                                    0                                0
                        (Only defined for select groups)
        -- watch_port   Port whose state affects whether this bucket is live         4294967295                       OFPP_ANY
                        (Only required for fast failover groups)
        -- watch_group  Group whose state affects whether this bucket is live        4294967295                       OFPG_ANY
                        (Only required for fast failover groups)
        -- actions      0 or more actions associated with the bucket (list of dict)  [{"type": "OUTPUT", "port": 1}]  [] #DROP
        =============== ============================================================ ================================ ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "type": "ALL",
            "group_id": 1,
            "buckets": [
                {
                    "actions": [
                        {
                            "type": "OUTPUT",
                            "port": 1
                        }
                    ]
                }
            ]
         }' http://localhost:8080/stats/groupentry/add

    .. NOTE::

        To confirm group entry registration, please see :ref:`get-group-description-stats`.


Modify a group entry
--------------------

    Modify a group entry to the switch.

    Usage:

        ======= =========================
        Method  POST
        URI     /stats/groupentry/modify
        ======= =========================

    Request message body:

        =============== ============================================================ ================================ ============
        Attribute       Description                                                  Example                          Default
        =============== ============================================================ ================================ ============
        dpid            Datapath ID (int)                                            1                                (Mandatory)
        type            One of OFPGT_* (string)                                      "ALL"                            "ALL"
        group_id        Group ID (int)                                               1                                0
        buckets         struct ofp_bucket
        -- weight       Relative weight of bucket                                    0                                0
                        (Only defined for select groups)
        -- watch_port   Port whose state affects whether this bucket is live         4294967295                       OFPP_ANY
                        (Only required for fast failover groups)
        -- watch_group  Group whose state affects whether this bucket is live        4294967295                       OFPG_ANY
                        (Only required for fast failover groups)
        -- actions      0 or more actions associated with the bucket (list of dict)  [{"type": "OUTPUT", "port": 1}]  [] #DROP
        =============== ============================================================ ================================ ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "type": "ALL",
            "group_id": 1,
            "buckets": [
                {
                    "actions": [
                        {
                            "type": "OUTPUT",
                            "port": 1
                        }
                    ]
                }
            ]
         }' http://localhost:8080/stats/groupentry/modify


Delete a group entry
--------------------

    Delete a group entry to the switch.

    Usage:

        ======= =========================
        Method  POST
        URI     /stats/groupentry/delete
        ======= =========================

    Request message body:

        =========== ======================== ======== ============
        Attribute   Description              Example  Default
        =========== ======================== ======== ============
        dpid        Datapath ID (int)        1        (Mandatory)
        group_id    Group ID (int)           1        0
        =========== ======================== ======== ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "group_id": 1
         }' http://localhost:8080/stats/groupentry/delete


Modify the behavior of the port
-------------------------------

    Modify the behavior of the physical port.

    Usage:

        ======= =======================
        Method  POST
        URI     /stats/portdesc/modify
        ======= =======================

    Request message body:

        =========== ============================================ ======== ============
        Attribute   Description                                  Example  Default
        =========== ============================================ ======== ============
        dpid        Datapath ID (int)                            1        (Mandatory)
        port_no     Port number (int)                            1        0
        config      Bitmap of OFPPC_* flags (int)                1        0
        mask        Bitmap of OFPPC_* flags to be changed (int)  1        0
        =========== ============================================ ======== ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "port_no": 1,
            "config": 1,
            "mask": 1
            }' http://localhost:8080/stats/portdesc/modify

    .. NOTE::

        To confirm port description, please see :ref:`get-ports-description`.


Add a meter entry
-----------------

    Add a meter entry to the switch.

    Usage:

        ======= ======================
        Method  POST
        URI     /stats/meterentry/add
        ======= ======================

    Request message body:

        ============== =============================== ========= ============
        Attribute      Description                     Example   Default
        ============== =============================== ========= ============
        dpid           Datapath ID (int)               1         (Mandatory)
        flags          Bitmap of OFPMF_* flags (list)  ["KBPS"]  [] #Empty
        meter_id       Meter ID (int)                  1         0
        bands          struct ofp_meter_band_header
        -- type        One of OFPMBT_* (string)        "DROP"    None
        -- rate        Rate for this band (int)        1000      None
        -- burst_size  Size of bursts (int)            100       None
        ============== =============================== ========= ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "flags": "KBPS",
            "meter_id": 1,
            "bands": [
                {
                    "type": "DROP",
                    "rate": 1000
                }
            ]
         }' http://localhost:8080/stats/meterentry/add

    .. NOTE::

        To confirm meter entry registration, please see :ref:`get-meter-config-stats`.


Modify a meter entry
--------------------

    Modify a meter entry to the switch.

    Usage:

        ======= =========================
        Method  POST
        URI     /stats/meterentry/modify
        ======= =========================

    Request message body:

        ============== =============================== ========= ============
        Attribute      Description                     Example   Default
        ============== =============================== ========= ============
        dpid           Datapath ID (int)               1         (Mandatory)
        flags          Bitmap of OFPMF_* flags (list)  ["KBPS"]  [] #Empty
        meter_id       Meter ID (int)                  1         0
        bands          struct ofp_meter_band_header
        -- type        One of OFPMBT_* (string)        "DROP"    None
        -- rate        Rate for this band (int)        1000      None
        -- burst_size  Size of bursts (int)            100       None
        ============== =============================== ========= ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "meter_id": 1,
            "flags": "KBPS",
            "bands": [
                {
                    "type": "DROP",
                    "rate": 1000
                }
            ]
         }' http://localhost:8080/stats/meterentry/modify


Delete a meter entry
--------------------

    Delete a meter entry to the switch.

    Usage:

        ======= =========================
        Method  POST
        URI     /stats/meterentry/delete
        ======= =========================

    Request message body:

        =========== ================== ========= ============
        Attribute   Description        Example   Default
        =========== ================== ========= ============
        dpid        Datapath ID (int)  1         (Mandatory)
        meter_id    Meter ID (int)     1         0
        =========== ================== ========= ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "meter_id": 1
         }' http://localhost:8080/stats/meterentry/delete


Support for experimenter multipart
==================================

Send a experimenter message
---------------------------

    Send a experimenter message to the switch which specified with Datapath ID in URI.


    Usage:

        ======= ===========================
        Method  POST
        URI     /stats/experimenter/<dpid>
        ======= ===========================

    Request message body:

        ============= ============================================ ======== ============
        Attribute     Description                                  Example  Default
        ============= ============================================ ======== ============
        dpid          Datapath ID (int)                            1        (Mandatory)
        experimenter  Experimenter ID (int)                        1        0
        exp_type      Experimenter defined (int)                   1        0
        data_type     Data format type ("ascii" or "base64")       "ascii"  "ascii"
        data          Data to send (string)                        "data"   "" #Empty
        ============= ============================================ ======== ============

    Example of use::

        $ curl -X POST -d '{
            "dpid": 1,
            "experimenter": 1,
            "exp_type": 1,
            "data_type": "ascii",
            "data": "data"
            }' http://localhost:8080/stats/experimenter/1


.. _description-of-match-and-actions:

Reference: Description of Match and Actions
===========================================

Description of Match on request messages
----------------------------------------

    List of Match fields (OpenFlow1.0):

        =============== ================================================ ==============================================
        Match field     Description                                      Example
        =============== ================================================ ==============================================
        in_port         Input switch port (int)                          {"in_port": 7}
        dl_src          Ethernet source address (string)                 {"dl_src": "aa:bb:cc:11:22:33"}
        dl_dst          Ethernet destination address (string)            {"dl_dst": "aa:bb:cc:11:22:33"}
        dl_vlan         Input VLAN id (int)                              {"dl_vlan": 5}
        dl_vlan_pcp     Input VLAN priority (int)                        {"dl_vlan_pcp": 3, "dl_vlan": 3}
        dl_type         Ethernet frame type (int)                        {"dl_type": 123}
        nw_tos          IP ToS (int)                                     {"nw_tos": 16, "dl_type": 2048}
        nw_proto        IP protocol or lower 8 bits of ARP opcode (int)  {"nw_proto": 5, "dl_type": 2048}
        nw_src          IPv4 source address (string)                     {"nw_src": "192.168.0.1", "dl_type": 2048}
        nw_dst          IPv4 destination address (string)                {"nw_dst": "192.168.0.1/24", "dl_type": 2048}
        tp_src          TCP/UDP source port (int)                        {"tp_src": 1, "nw_proto": 6, "dl_type": 2048}
        tp_dst          TCP/UDP destination port (int)                   {"tp_dst": 2, "nw_proto": 6, "dl_type": 2048}
        =============== ================================================ ==============================================

    .. NOTE::

        IPv4 address field can be described as IP Prefix like as follows.

        IPv4 address::

            "192.168.0.1"
            "192.168.0.2/24"

    List of Match fields (OpenFlow1.2 or later):

        =============== ================================================== =======================================================================================================
        Match field     Description                                        Example
        =============== ================================================== =======================================================================================================
        in_port         Switch input port (int)                            {"in_port": 7}
        in_phy_port     Switch physical input port (int)                   {"in_phy_port": 5, "in_port": 3}
        metadata        Metadata passed between tables (int or string)     {"metadata": 12345} or {"metadata": "0x1212/0xffff"}
        eth_dst         Ethernet destination address (string)              {"eth_dst": "aa:bb:cc:11:22:33/00:00:00:00:ff:ff"}
        eth_src         Ethernet source address (string)                   {"eth_src": "aa:bb:cc:11:22:33"}
        eth_type        Ethernet frame type (int)                          {"eth_type": 2048}
        vlan_vid        VLAN id (int or string)                            See :ref:`example-of-vlan-id-match-field`
        vlan_pcp        VLAN priority (int)                                {"vlan_pcp": 3, "vlan_vid": 3}
        ip_dscp         IP DSCP (6 bits in ToS field) (int)                {"ip_dscp": 3, "eth_type": 2048}
        ip_ecn          IP ECN (2 bits in ToS field) (int)                 {"ip_ecn": 0, "eth_type": 34525}
        ip_proto        IP protocol (int)                                  {"ip_proto": 5, "eth_type": 34525}
        ipv4_src        IPv4 source address (string)                       {"ipv4_src": "192.168.0.1", "eth_type": 2048}
        ipv4_dst        IPv4 destination address (string)                  {"ipv4_dst": "192.168.10.10/255.255.255.0", "eth_type": 2048}
        tcp_src         TCP source port (int)                              {"tcp_src": 3, "ip_proto": 6, "eth_type": 2048}
        tcp_dst         TCP destination port (int)                         {"tcp_dst": 5, "ip_proto": 6, "eth_type": 2048}
        udp_src         UDP source port (int)                              {"udp_src": 2, "ip_proto": 17, "eth_type": 2048}
        udp_dst         UDP destination port (int)                         {"udp_dst": 6, "ip_proto": 17, "eth_type": 2048}
        sctp_src        SCTP source port (int)                             {"sctp_src": 99, "ip_proto": 132, "eth_type": 2048}
        sctp_dst        SCTP destination port (int)                        {"sctp_dst": 99, "ip_proto": 132, "eth_type": 2048}
        icmpv4_type     ICMP type (int)                                    {"icmpv4_type": 5, "ip_proto": 1, "eth_type": 2048}
        icmpv4_code     ICMP code (int)                                    {"icmpv4_code": 6, "ip_proto": 1, "eth_type": 2048}
        arp_op          ARP opcode (int)                                   {"arp_op": 3, "eth_type": 2054}
        arp_spa         ARP source IPv4 address (string)                   {"arp_spa": "192.168.0.11", "eth_type": 2054}
        arp_tpa         ARP target IPv4 address (string)                   {"arp_tpa": "192.168.0.44/24", "eth_type": 2054}
        arp_sha         ARP source hardware address (string)               {"arp_sha": "aa:bb:cc:11:22:33", "eth_type": 2054}
        arp_tha         ARP target hardware address (string)               {"arp_tha": "aa:bb:cc:11:22:33/00:00:00:00:ff:ff", "eth_type": 2054}
        ipv6_src        IPv6 source address (string)                       {"ipv6_src": "2001::aaaa:bbbb:cccc:1111", "eth_type": 34525}
        ipv6_dst        IPv6 destination address (string)                  {"ipv6_dst": "2001::ffff:cccc:bbbb:1111/64", "eth_type": 34525}
        ipv6_flabel     IPv6 Flow Label (int)                              {"ipv6_flabel": 2, "eth_type": 34525}
        icmpv6_type     ICMPv6 type (int)                                  {"icmpv6_type": 3, "ip_proto": 58, "eth_type": 34525}
        icmpv6_code     ICMPv6 code (int)                                  {"icmpv6_code": 4, "ip_proto": 58, "eth_type": 34525}
        ipv6_nd_target  Target address for Neighbor Discovery (string)     {"ipv6_nd_target": "2001::ffff:cccc:bbbb:1111", "icmpv6_type": 135, "ip_proto": 58, "eth_type": 34525}
        ipv6_nd_sll     Source link-layer for Neighbor Discovery (string)  {"ipv6_nd_sll": "aa:bb:cc:11:22:33", "icmpv6_type": 135, "ip_proto": 58, "eth_type": 34525}
        ipv6_nd_tll     Target link-layer for Neighbor Discovery (string)  {"ipv6_nd_tll": "aa:bb:cc:11:22:33", "icmpv6_type": 136, "ip_proto": 58, "eth_type": 34525}
        mpls_label      MPLS label (int)                                   {"mpls_label": 3, "eth_type": 34888}
        mpls_tc         MPLS Traffic Class (int)                           {"mpls_tc": 2, "eth_type": 34888}
        mpls_bos        MPLS BoS bit (int)                                 {"mpls_bos": 1, "eth_type": 34888}
                        (Openflow1.3+)
        pbb_isid        PBB I-SID (int or string)                          {"pbb_isid": 5, "eth_type": 35047} or{"pbb_isid": "0x05/0xff", "eth_type": 35047}
                        (Openflow1.3+)
        tunnel_id       Logical Port Metadata (int or string)              {"tunnel_id": 7} or {"tunnel_id": "0x07/0xff"}
                        (Openflow1.3+)
        ipv6_exthdr     IPv6 Extension Header pseudo-field (int or string) {"ipv6_exthdr": 3, "eth_type": 34525} or {"ipv6_exthdr": "0x40/0x1F0", "eth_type": 34525}
                        (Openflow1.3+)
        pbb_uca         PBB UCA hander field(int)                          {"pbb_uca": 1, "eth_type": 35047}
                        (Openflow1.4+)
        tcp_flags       TCP flags(int)                                     {"tcp_flags": 2, "ip_proto": 6, "eth_type": 2048}
                        (Openflow1.5+)
        actset_output   Output port from action set metadata(int)          {"actset_output": 3}
                        (Openflow1.5+)
        packet_type     Packet type value(int)                             {"packet_type": [1, 2048]}
                        (Openflow1.5+)
        =============== ================================================== =======================================================================================================

    .. NOTE::

        Some field can be described with mask like as follows.

        Ethernet address::

            "aa:bb:cc:11:22:33"
            "aa:bb:cc:11:22:33/00:00:00:00:ff:ff"

        IPv4 address::

            "192.168.0.11"
            "192.168.0.44/24"
            "192.168.10.10/255.255.255.0"

        IPv6 address::

            "2001::ffff:cccc:bbbb:1111"
            "2001::ffff:cccc:bbbb:2222/64"
            "2001::ffff:cccc:bbbb:2222/ffff:ffff:ffff:ffff::0"

        Metadata::

            "0x1212121212121212"
            "0x3434343434343434/0x01010101010101010"


.. _example-of-vlan-id-match-field:

Example of VLAN ID match field
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    The following is available in OpenFlow1.0 or later.

    - To match only packets with VLAN tag and VLAN ID equal value 5::

        $ curl -X POST -d '{
            "dpid": 1,
            "match":{
                "dl_vlan": 5
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    .. NOTE::
        When "dl_vlan" field is described as decimal int value, OFPVID_PRESENT(0x1000) bit is automatically applied.

    The following is available in OpenFlow1.2 or later.

    - To match only packets without a VLAN tag::

        $ curl -X POST -d '{
            "dpid": 1,
            "match":{
                "dl_vlan": "0x0000"   # Describe OFPVID_NONE(0x0000)
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    - To match only packets with a VLAN tag regardless of its value::

        $ curl -X POST -d '{
            "dpid": 1,
            "match":{
                "dl_vlan": "0x1000/0x1000"   # Describe OFPVID_PRESENT(0x1000/0x1000)
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    - To match only packets with VLAN tag and VLAN ID equal value 5::

        $ curl -X POST -d '{
            "dpid": 1,
            "match":{
                "dl_vlan": "0x1005"   # Describe sum of VLAN-ID(e.g. 5) | OFPVID_PRESENT(0x1000)
            },
            "actions":[
                {
                    "type":"OUTPUT",
                    "port": 1
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

    .. NOTE::
        When using the descriptions for OpenFlow1.2 or later, please describe "dl_vlan" field as hexadecimal string value,
        and OFPVID_PRESENT(0x1000) bit is NOT automatically applied.



Description of Actions on request messages
------------------------------------------

    List of Actions (OpenFlow1.0):

        =============== ============================================================================ ======================================================
        Actions         Description                                                                  Example
        =============== ============================================================================ ======================================================
        OUTPUT          Output packet from "port"                                                    {"type": "OUTPUT", "port": 3}
        SET_VLAN_VID    Set the 802.1Q VLAN ID using "vlan_vid"                                      {"type": "SET_VLAN_VID", "vlan_vid": 5}
        SET_VLAN_PCP    Set the 802.1Q priority using "vlan_pcp"                                     {"type": "SET_VLAN_PCP", "vlan_pcp": 3}
        STRIP_VLAN      Strip the 802.1Q header                                                      {"type": "STRIP_VLAN"}
        SET_DL_SRC      Set ethernet source address using "dl_src"                                   {"type": "SET_DL_SRC", "dl_src": "aa:bb:cc:11:22:33"}
        SET_DL_DST      Set ethernet destination address using "dl_dst"                              {"type": "SET_DL_DST", "dl_dst": "aa:bb:cc:11:22:33"}
        SET_NW_SRC      IP source address using "nw_src"                                             {"type": "SET_NW_SRC", "nw_src": "10.0.0.1"}
        SET_NW_DST      IP destination address using "nw_dst"                                        {"type": "SET_NW_DST", "nw_dst": "10.0.0.1"}
        SET_NW_TOS      Set IP ToS (DSCP field, 6 bits) using "nw_tos"                               {"type": "SET_NW_TOS", "nw_tos": 184}
        SET_TP_SRC      Set TCP/UDP source port using "tp_src"                                       {"type": "SET_TP_SRC", "tp_src": 8080}
        SET_TP_DST      Set TCP/UDP destination port using "tp_dst"                                  {"type": "SET_TP_DST", "tp_dst": 8080}
        ENQUEUE         Output to queue with "queue_id" attached to "port"                           {"type": "ENQUEUE", "queue_id": 3, "port": 1}
        =============== ============================================================================ ======================================================

    List of Actions (OpenFlow1.2 or later):

        =============== ============================================================================ ========================================================================================================================
        Actions         Description                                                                  Example
        =============== ============================================================================ ========================================================================================================================
        OUTPUT          Output packet from "port"                                                    {"type": "OUTPUT", "port": 3}
        COPY_TTL_OUT    Copy TTL outwards                                                            {"type": "COPY_TTL_OUT"}
        COPY_TTL_IN     Copy TTL inwards                                                             {"type": "COPY_TTL_IN"}
        SET_MPLS_TTL    Set MPLS TTL using "mpls_ttl"                                                {"type": "SET_MPLS_TTL", "mpls_ttl": 64}
        DEC_MPLS_TTL    Decrement MPLS TTL                                                           {"type": "DEC_MPLS_TTL"}
        PUSH_VLAN       Push a new VLAN tag with "ethertype"                                         {"type": "PUSH_VLAN", "ethertype": 33024}
        POP_VLAN        Pop the outer VLAN tag                                                       {"type": "POP_VLAN"}
        PUSH_MPLS       Push a new MPLS tag with "ethertype"                                         {"type": "PUSH_MPLS", "ethertype": 34887}
        POP_MPLS        Pop the outer MPLS tag with "ethertype"                                      {"type": "POP_MPLS", "ethertype": 2054}
        SET_QUEUE       Set queue id using "queue_id" when outputting to a port                      {"type": "SET_QUEUE", "queue_id": 7}
        GROUP           Apply group identified by "group_id"                                         {"type": "GROUP", "group_id": 5}
        SET_NW_TTL      Set IP TTL using "nw_ttl"                                                    {"type": "SET_NW_TTL", "nw_ttl": 64}
        DEC_NW_TTL      Decrement IP TTL                                                             {"type": "DEC_NW_TTL"}
        SET_FIELD       Set a "field" using "value"                                                  See :ref:`example-of-set-field-action`
                        (The set of keywords available for "field" is the same as match field)
        PUSH_PBB        Push a new PBB service tag with "ethertype"                                  {"type": "PUSH_PBB", "ethertype": 35047}
                        (Openflow1.3+)
        POP_PBB         Pop the outer PBB service tag                                                {"type": "POP_PBB"}
                        (Openflow1.3+)
        COPY_FIELD      Copy value between header and register                                       {"type": "COPY_FIELD", "n_bits": 32, "src_offset": 1, "dst_offset": 2, "src_oxm_id": "eth_src", "dst_oxm_id": "eth_dst"}
                        (Openflow1.5+)
        METER           Apply meter identified by "meter_id"                                         {"type": "METER", "meter_id": 3}
                        (Openflow1.5+)
        EXPERIMENTER    Extensible action for the experimenter                                       {"type": "EXPERIMENTER", "experimenter": 101, "data": "AAECAwQFBgc=", "data_type": "base64"}
                        (Set "base64" or "ascii" to "data_type" field)
        GOTO_TABLE      (Instruction) Setup the next table identified by "table_id"                  {"type": "GOTO_TABLE", "table_id": 8}
        WRITE_METADATA  (Instruction) Setup the metadata field using "metadata" and "metadata_mask"  {"type": "WRITE_METADATA", "metadata": 0x3, "metadata_mask": 0x3}
        METER           (Instruction) Apply meter identified by "meter_id"                           {"type": "METER", "meter_id": 3}
                        (deprecated in Openflow1.5)
        WRITE_ACTIONS   (Instruction) Write the action(s) onto the datapath action set               {"type": "WRITE_ACTIONS", actions":[{"type":"POP_VLAN",},{ "type":"OUTPUT", "port": 2}]}
        CLEAR_ACTIONS   (Instruction) Clears all actions from the datapath action set                {"type": "CLEAR_ACTIONS"}
        =============== ============================================================================ ========================================================================================================================



.. _example-of-set-field-action:

Example of set-field action
^^^^^^^^^^^^^^^^^^^^^^^^^^^

    To set VLAN ID to non-VLAN-tagged frame::

        $ curl -X POST -d '{
            "dpid": 1,
            "match":{
                "dl_type": "0x8000"
            },
            "actions":[
                {
                    "type": "PUSH_VLAN",     # Push a new VLAN tag if a input frame is non-VLAN-tagged
                    "ethertype": 33024       # Ethertype 0x8100(=33024): IEEE 802.1Q VLAN-tagged frame
                },
                {
                    "type": "SET_FIELD",
                    "field": "vlan_vid",     # Set VLAN ID
                    "value": 4102            # Describe sum of vlan_id(e.g. 6) | OFPVID_PRESENT(0x1000=4096)
                },
                {
                    "type": "OUTPUT",
                    "port": 2
                }
            ]
         }' http://localhost:8080/stats/flowentry/add

