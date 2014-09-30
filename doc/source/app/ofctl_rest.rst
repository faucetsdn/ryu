******************
ryu.app.ofctl_rest
******************

ryu.app.ofctl_rest provides REST APIs for retrieving the switch stats
and Updating the switch stats.
This application helps you debug your application and get various statistics.

This application supports OpenFlow version 1.0, 1.2 and 1.3.


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

    ::

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

    ::

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

    Response message body:

        ============== ========================================= ===============
        Attribute      Description                               Example
        ============== ========================================= ===============
        dpid           Datapath ID                               "1"
        length         Length of this entry                      88
        table_id       Table ID                                  0
        duration_sec   Time flow has been alive in seconds       2
        duration_nsec  Time flow has been alive in nanoseconds   6.76e+08
        priority       Priority of the entry                     11111
        idle_timeout   Number of seconds idle before expiration  0
        hard_timeout   Number of seconds before expiration       0
        flags          Bitmap of OFPFF_* flags                   1
        cookie         Opaque controller-issued identifier       1
        packet_count   Number of packets in flow                 0
        byte_count     Number of bytes in flow                   0
        match          Fields to match                           {"in_port": 1}
        actions        Instruction set                           ["OUTPUT:2"]
        ============== ========================================= ===============

    Example of use::

        $ curl -X GET http://localhost:8080/stats/flow/1

    ::

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

        $ curl -X POST -d '{ \
             "table_id": 0, \
             "out_port": 2, \
             "cookie": 1, \
             "cookie_mask": 1, \
             "match":{ \
                 "in_port":1 \
             } \
         }' \
         http://localhost:8080/stats/flow/1

    ::

        {
          "1": [
            {
              "table_id": 0,
              "duration_sec": 2,
              "duration_nsec": 6.76e+08,
              "priority": 11111,
              "idle_timeout": 0,
              "hard_timeout": 0,
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


Get ports stats
---------------

    Get ports stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ===================
        Method  GET
        URI     /stats/port/<dpid>
        ======= ===================

    Response message body:

        ============== ======================================== =========
        Attribute      Description                              Example
        ============== ======================================== =========
        dpid           Datapath ID                              "1"
        port_no        Port number                              1
        rx_packets     Number of received packets               9
        tx_packets     Number of transmitted packets            6
        rx_bytes       Number of received bytes                 738
        tx_bytes       Number of transmitted bytes              252
        rx_dropped     Number of packets dropped by RX          0
        tx_dropped     Number of packets dropped by TX          0
        rx_errors      Number of receive errors                 0
        tx_errors      Number of transmit errors                0
        rx_frame_err   Number of frame alignment errors         0
        rx_over_err    Number of packets with RX overrun        0
        rx_crc_err     Number of CRC errors                     0
        collisions     Number of collisions                     0
        duration_sec   Time port has been alive in seconds      12
        duration_nsec  Time port has been alive in nanoseconds  9.76e+08
        ============== ======================================== =========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/port/1

    ::

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


.. _get-ports-description:

Get ports description
---------------------

    Get ports description of the switch which specified with Datapath ID in URI.

    Usage:

        ======= =======================
        Method  GET
        URI     /stats/portdesc/<dpid>
        ======= =======================

    Response message body:

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

    Example of use::

        $ curl -X GET http://localhost:8080/stats/portdesc/1

    ::

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


Get groups stats
----------------

    Get groups stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ====================
        Method  GET
        URI     /stats/group/<dpid>
        ======= ====================

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
        duration_nsec    Time group has been alive in nanoseconds                       3.03e+08
        bucket_stats     struct ofp_bucket_counter
        -- packet_count  Number of packets processed by bucket                          0
        -- byte_count    Number of bytes processed by bucket                            0
        ================ ============================================================== =========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/group/1

    ::

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

    Usage:

        ======= ========================
        Method  GET
        URI     /stats/groupdesc/<dpid>
        ======= ========================

    Response message body:

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

    Example of use::

        $ curl -X GET http://localhost:8080/stats/groupdesc/1

    ::

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

    ::

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

        ======= =======================
        Method  GET
        URI     /stats/meter/<dpid>
        ======= =======================

    Response message body:

        ===================== ========================================= ========
        Attribute             Description                               Example
        ===================== ========================================= ========
        dpid                  Datapath ID                               "1"
        meter_id              Meter ID                                  1
        len                   Length in bytes of this stats             56
        flow_count            Number of flows bound to meter            0
        packet_in_count       Number of packets in input                0
        byte_in_count         Number of bytes in input                  0
        duration_sec          Time meter has been alive in seconds      37
        duration_nsec         Time meter has been alive in nanoseconds  988000
        band_stats            struct ofp_meter_band_stats
        -- packet_band_count  Number of packets in band                 0
        -- byte_band_count    Number of bytes in band                   0
        ===================== ========================================= ========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/meter/1

    ::

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
------------------------

    Get meter config stats of the switch which specified with Datapath ID in URI.

    Usage:

        ======= ============================
        Method  GET
        URI     /stats/meterconfig/<dpid>
        ======= ============================

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

    ::

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

        =========== ============================================ =========
        Attribute   Description                                  Example
        =========== ============================================ =========
        dpid        Datapath ID                                  "1"
        max_meter   Maximum number of meters                     256
        band_types  Bitmaps of (1 << OFPMBT_*) values supported  ['DROP']
        max_bands   Maximum bands per meters                     16
        max_color   Maximum color value                          8
        =========== ============================================ =========

    Example of use::

        $ curl -X GET http://localhost:8080/stats/meterfeatures/1

    ::

        {
          "1": [
            {
              "max_meter": 256,
              "band_types": [
                'DROP'
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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "cookie": 1, \
            "cookie_mask": 1, \
            "table_id": 0, \
            "idle_timeout": 30, \
            "hard_timeout": 30, \
            "priority": 11111, \
            "flags": 1, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"OUTPUT", \
                    "port": 2 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "priority": 22222, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"GOTO_TABLE", \
                    "table_id": 1 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "priority": 33333, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"WRITE_METADATA", \
                    "metadata": 1, \
                    "metadata_mask": 1 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/add

    ::

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "priority": 44444, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"METER", \
                    "meter_id": 1 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/add

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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "cookie": 1, \
            "cookie_mask": 1, \
            "table_id": 0, \
            "idle_timeout": 30, \
            "hard_timeout": 30, \
            "priority": 11111, \
            "flags": 1, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"OUTPUT", \
                    "port": 2 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/modify


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "cookie": 1, \
            "cookie_mask": 1, \
            "table_id": 0, \
            "idle_timeout": 30, \
            "hard_timeout": 30, \
            "priority": 11111, \
            "flags": 1, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"OUTPUT", \
                    "port": 2 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/modify_strict


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "cookie": 1, \
            "cookie_mask": 1, \
            "table_id": 0, \
            "idle_timeout": 30, \
            "hard_timeout": 30, \
            "priority": 11111, \
            "flags": 1, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"OUTPUT", \
                    "port": 2 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/delete


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "cookie": 1, \
            "cookie_mask": 1, \
            "table_id": 0, \
            "idle_timeout": 30, \
            "hard_timeout": 30, \
            "priority": 11111, \
            "flags": 1, \
            "match":{ \
                "in_port":1 \
            }, \
            "actions":[ \
                { \
                    "type":"OUTPUT", \
                    "port": 2 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/flowentry/delete_strict


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "type": "ALL", \
            "group_id": 1, \
            "buckets": [ \
                { \
                    "actions": [ \
                        { \
                            "type": "OUTPUT", \
                            "port": 1 \
                        } \
                    ] \
                } \
            ] \
         }' \
         http://localhost:8080/stats/groupentry/add

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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "type": "ALL", \
            "group_id": 1, \
            "buckets": [ \
                { \
                    "actions": [ \
                        { \
                            "type": "OUTPUT", \
                            "port": 1 \
                        } \
                    ] \
                } \
            ] \
         }' \
         http://localhost:8080/stats/groupentry/modify


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "group_id": 1 \
         }' \
         http://localhost:8080/stats/groupentry/delete


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "port_no": 1, \
            "config": 1, \
            "mask": 1 \
            }' \
         http://localhost:8080/stats/portdesc/modify

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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "flags": "KBPS", \
            "meter_id": 1, \
            "bands": [ \
                { \
                    "type": "DROP", \
                    "rate": 1000 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/meterentry/add

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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "meter_id": 1, \
            "flags": "KBPS", \
            "bands": [ \
                { \
                    "type": "DROP", \
                    "rate": 1000 \
                } \
            ] \
         }' \
         http://localhost:8080/stats/meterentry/modify


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "meter_id": 1 \
         }' \
         http://localhost:8080/stats/meterentry/delete


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

        $ curl -X POST -d '{ \
            "dpid": 1, \
            "experimenter": 1, \
            "exp_type": 1, \
            "data_type": "ascii", \
            "data": "data" \
            }' \
         http://localhost:8080/stats/experimenter/1
