__author__ = 'matemaciek'
# Based on ofproto_v1_4.py, backward compatible to previous versions.

ERRORS = {
    0: {
        'name': 'OFPET_HELLO_FAILED',
        'description': 'Hello protocol failed.',
        0: {
            'name': 'OFPHFC_INCOMPATIBLE',
            'description': 'No compatible version.'
        },
        1: {
            'name': 'OFPHFC_EPERM',
            'description': 'Permissions error.'
        }
    },
    1: {
        'name': 'OFPET_BAD_REQUEST',
        'description': 'Request was not understood.',
        0: {
            'name': 'OFPBRC_BAD_VERSION',
            'description': 'ofp_header.version not supported.'
        },
        1: {
            'name': 'OFPBRC_BAD_TYPE',
            'description': 'ofp_header.type not supported.'
        },
        2: {
            'name': 'OFPBRC_BAD_MULTIPART',
            'description': 'ofp_multipart_request.type not supported.'
        },
        3: {
            'name': 'OFPBRC_BAD_EXPERIMENTER',
            'description': 'Experimenter id not supported (in '
                           'ofp_experimenter_header or '
                           'ofp_multipart_request or ofp_multipart_reply).'
        },
        4: {
            'name': 'OFPBRC_BAD_EXP_TYPE',
            'description': 'Experimenter type not supported.'
        },
        5: {
            'name': 'OFPBRC_EPERM',
            'description': 'Permissions error.'
        },
        6: {
            'name': 'OFPBRC_BAD_LEN',
            'description': 'Wrong request length for type.'
        },
        7: {
            'name': 'OFPBRC_BUFFER_EMPTY',
            'description': 'Specified buffer has already been used.'
        },
        8: {
            'name': 'OFPBRC_BUFFER_UNKNOWN',
            'description': 'Specified buffer does not exist.'
        },
        9: {
            'name': 'OFPBRC_BAD_TABLE_ID',
            'description': 'Specified table-id invalid or does not exist.'
        },
        10: {
            'name': 'OFPBRC_IS_SLAVE',
            'description': 'Denied because controller is slave.'
        },
        11: {
            'name': 'OFPBRC_BAD_PORT',
            'description': 'Invalid port.'
        },
        12: {
            'name': 'OFPBRC_BAD_PACKET',
            'description': 'Invalid packet in packet-out'
        },
        13: {
            'name': 'OFPBRC_MULTIPART_BUFFER_OVERFLOW',
            'description': 'ofp_multipart_request overflowed the assigned buffer.'
        },
        14: {
            'name': 'OFPBRC_MULTIPART_REQUEST_TIMEOUT',
            'description': 'Timeout during multipart request.'
        },
        15: {
            'name': 'OFPBRC_MULTIPART_REPLY_TIMEOUT',
            'description': 'Timeout during multipart reply.'
        }
    },
    2: {
        'name': 'OFPET_BAD_ACTION',
        'description': 'Error in action description.',
        0: {
            'name': 'OFPBAC_BAD_TYPE',
            'description': 'Unknown action type.'
        },
        1: {
            'name': 'OFPBAC_BAD_LEN',
            'description': 'Length problem in actions.'
        },
        2: {
            'name': 'OFPBAC_BAD_EXPERIMENTER',
            'description': 'Unknown experimenter id specified.'
        },
        3: {
            'name': 'OFPBAC_BAD_EXP_TYPE',
            'description': 'Unknown action type for experimenter id.'
        },
        4: {
            'name': 'OFPBAC_BAD_OUT_PORT',
            'description': 'Problem validating output action.'
        },
        5: {
            'name': 'OFPBAC_BAD_ARGUMENT',
            'description': 'Bad action argument.'
        },
        6: {
            'name': 'OFPBAC_EPERM',
            'description': 'Permissions error.'
        },
        7: {
            'name': 'OFPBAC_TOO_MANY',
            'description': 'Can\'t handle this many actions.'
        },
        8: {
            'name': 'OFPBAC_BAD_QUEUE',
            'description': 'Problem validating output queue.'
        },
        9: {
            'name': 'OFPBAC_BAD_OUT_GROUP',
            'description': 'Invalid group id in forward action.'
        },
        10: {
            'name': 'OFPBAC_MATCH_INCONSISTENT',
            'description': 'Action can\'t apply for this match, '
                           'or Set-Field missing prerequisite.'
        },
        11: {
            'name': 'OFPBAC_UNSUPPORTED_ORDER',
            'description': 'Action order is unsupported for the '
                           'action list in an Apply-Actions instruction'
        },
        12: {
            'name': 'OFPBAC_BAD_TAG',
            'description': 'Actions uses an unsupported tag/encap.'
        },
        13: {
            'name': 'OFPBAC_BAD_SET_TYPE',
            'description': 'Unsupported type in SET_FIELD action.'
        },
        14: {
            'name': 'OFPBAC_BAD_SET_LEN',
            'description': 'Length problem in SET_FIELD action.'
        },
        15: {
            'name': 'OFPBAC_BAD_SET_ARGUMENT',
            'description': 'Bad arguement in SET_FIELD action.'
        }
    },
    3: {
        'name': 'OFPET_BAD_INSTRUCTION',
        'description': 'Error in instruction list.',
        0: {
            'name': 'OFPBIC_UNKNOWN_INST',
            'description': 'Unknown instruction.'
        },
        1: {
            'name': 'OFPBIC_UNSUP_INST',
            'description': 'Switch or table does not support the instruction.'
        },
        2: {
            'name': 'OFPBIC_BAD_TABLE_ID',
            'description': 'Invalid Table-Id specified'
        },
        3: {
            'name': 'OFPBIC_UNSUP_METADATA',
            'description': 'Metadata value unsupported by datapath.'
        },
        4: {
            'name': 'OFPBIC_UNSUP_METADATA_MASK',
            'description': 'Metadata mask value unsupported by datapath.'
        },
        5: {
            'name': 'OFPBIC_BAD_EXPERIMENTER',
            'description': 'Unknown experimenter id specified.'
        },
        6: {
            'name': 'OFPBIC_BAD_EXP_TYPE',
            'description': 'Unknown instruction for experimenter id.'
        },
        7: {
            'name': 'OFPBIC_BAD_EXP_LEN',
            'description': 'Length problem in instrucitons.'
        },
        8: {
            'name': 'OFPBIC_EPERM',
            'description': 'Permissions error.'
        },
        9: {
            'name': 'OFPBIC_DUP_INST',
            'description': 'Duplicate instruction.'
        }
    },
    4: {
        'name': 'OFPET_BAD_MATCH',
        'description': 'Error in match.',
        0: {
            'name': 'OFPBMC_BAD_TYPE',
            'description': 'Unsupported match type apecified by the match.'
        },
        1: {
            'name': 'OFPBMC_BAD_LEN',
            'description': 'Length problem in math.'
        },
        2: {
            'name': 'OFPBMC_BAD_TAG',
            'description': 'Match uses an unsupported tag/encap.'
        },
        3: {
            'name': 'OFPBMC_BAD_DL_ADDR_MASK',
            'description': 'Unsupported datalink addr mask - switch does not '
                           'support arbitrary datalink address mask.'
        },
        4: {
            'name': 'OFPBMC_BAD_NW_ADDR_MASK',
            'description': 'Unsupported network addr mask - switch does not '
                           'support arbitrary network addres mask.'
        },
        5: {
            'name': 'OFPBMC_BAD_WILDCARDS',
            'description': 'Unsupported combination of fields masked or '
                           'omitted in the match.'
        },
        6: {
            'name': 'OFPBMC_BAD_FIELD',
            'description': 'Unsupported field type in the match.'
        },
        7: {
            'name': 'OFPBMC_BAD_VALUE',
            'description': 'Unsupported value in a match field.'
        },
        8: {
            'name': 'OFPBMC_BAD_MASK',
            'description': 'Unsupported mask specified in the match.'
        },
        9: {
            'name': 'OFPBMC_BAD_PREREQ',
            'description': 'A prerequisite was not met.'
        },
        10: {
            'name': 'OFPBMC_DUP_FIELD',
            'description': 'A field type was duplicated.'
        },
        11: {
            'name': 'OFPBMC_EPERM',
            'description': 'Permissions error.'
        }
    },
    5: {
        'name': 'OFPET_FLOW_MOD_FAILED',
        'description': 'Problem modifying flow entry.',
        0: {
            'name': 'OFPFMFC_UNKNOWN',
            'description': 'Unspecified error.'
        },
        1: {
            'name': 'OFPFMFC_TABLES_FULL',
            'description': 'Flow not added because table was full.'
        },
        2: {
            'name': 'OFPFMFC_BAD_TABLE_ID',
            'description': 'Table does not exist'
        },
        3: {
            'name': 'OFPFMFC_OVERLAP',
            'description': 'Attempted to add overlapping flow with '
                           'CHECK_OVERLAP flag set.'
        },
        4: {
            'name': 'OFPFMFC_EPERM',
            'description': 'Permissions error.'
        },
        5: {
            'name': 'OFPFMFC_BAD_TIMEOUT',
            'description': 'Flow not added because of unsupported '
                           'idle/hard timeout.'
        },
        6: {
            'name': 'OFPFMFC_BAD_COMMAND',
            'description': 'Unsupported or unknown command.'
        },
        7: {
            'name': 'OFPFMFC_BAD_FLAGS',
            'description': 'Unsupported or unknown flags.'
        },
        8: {
            'name': 'OFPFMFC_CANT_SYNC',
            'description': 'Problem in table synchronisation.'
        },
        9: {
            'name': 'OFPFMFC_BAD_PRIORITY',
            'description': 'Unsupported priority value.'
        }
    },
    6: {
        'name': 'OFPET_GROUP_MOD_FAILED',
        'description': 'Problem modifying group entry.',
        0: {
            'name': 'OFPGMFC_GROUP_EXISTS',
            'description': 'Group not added because a group ADD attempted '
                           'to replace an already-present group.'
        },
        1: {
            'name': 'OFPGMFC_INVALID_GROUP',
            'description': 'Group not added because Group specified is invalid.'
        },
        2: {
            'name': 'OFPGMFC_WEIGHT_UNSUPPORTED',
            'description': 'Switch does not support unequal load sharing with '
                           'select groups.'
        },
        3: {
            'name': 'OFPGMFC_OUT_OF_GROUPS',
            'description': 'The group table is full.'
        },
        4: {
            'name': 'OFPGMFC_OUT_OF_BUCKETS',
            'description': 'The maximum number of action buckets for a group '
                           'has been exceeded.'
        },
        5: {
            'name': 'OFPGMFC_CHAINING_UNSUPPORTED',
            'description': 'Switch does not support groups that forward to groups.'
        },
        6: {
            'name': 'OFPGMFC_WATCH_UNSUPPORTED',
            'description': 'This group cannot watch the watch_port or watch_group '
                           'specified.'
        },
        7: {
            'name': 'OFPGMFC_LOOP',
            'description': 'Group entry would cause a loop.'
        },
        8: {
            'name': 'OFPGMFC_UNKNOWN_GROUP',
            'description': 'Group not modified because a group MODIFY attempted '
                           'to modify a non-existent group.'
        },
        9: {
            'name': 'OFPGMFC_CHAINED_GROUP',
            'description': 'Group not deleted because another group is forwarding '
                           'to it.'
        },
        10: {
            'name': 'OFPGMFC_BAD_TYPE',
            'description': 'Unsupported or unknown group type.'
        },
        11: {
            'name': 'OFPGMFC_BAD_COMMAND',
            'description': 'Unsupported or unknown command.'
        },
        12: {
            'name': 'OFPGMFC_BAD_BUCKET',
            'description': 'Error in bucket.'
        },
        13: {
            'name': 'OFPGMFC_BAD_WATCH',
            'description': 'Error in watch port/group.'
        },
        14: {
            'name': 'OFPGMFC_EPERM',
            'description': 'Permissions error.'
        }
    },
    7: {
        'name': 'OFPET_PORT_MOD_FAILED',
        'description': 'OFPT_PORT_MOD failed.',
        0: {
            'name': 'OFPPMFC_BAD_PORT',
            'description': 'Specified port does not exist.'
        },
        1: {
            'name': 'OFPPMFC_BAD_HW_ADDR',
            'description': 'Specified hardware address does not match the port '
                           'number.'
        },
        2: {
            'name': 'OFPPMFC_BAD_CONFIG',
            'description': 'Specified config is invalid.'
        },
        3: {
            'name': 'OFPPMFC_BAD_ADVERTISE',
            'description': 'Specified advertise is invalid.'
        },
        4: {
            'name': 'OFPPMFC_EPERM',
            'description': 'Permissions error.'
        }
    },
    8: {
        'name': 'OFPET_TABLE_MOD_FAILED',
        'description': 'Table mod request failed.',
        0: {
            'name': 'OFPTMFC_BAD_TABLE',
            'description': 'Specified table does not exist.'
        },
        1: {
            'name': 'OFPTMFC_BAD_CONFIG',
            'description': 'Specified config is invalid.'
        },
        2: {
            'name': 'OFPTMFC_EPERM',
            'description': 'Permissions error'
        }
    },
    9: {
        'name': 'OFPET_QUEUE_OP_FAILED',
        'description': 'Queue operation failed.',
        0: {
            'name': 'OFPQOFC_BAD_PORT',
            'description': 'Invalid port (or port does not exist).'
        },
        1: {
            'name': 'OFPQOFC_BAD_QUEUE',
            'description': 'Queue does not exist.'
        },
        2: {
            'name': 'OFPQOFC_EPERM',
            'description': 'Permissions error.'
        }
    },
    10: {
        'name': 'OFPET_SWITCH_CONFIG_FAILED',
        'description': 'Switch config request failed.',
        0: {
            'name': 'OFPSCFC_BAD_FLAGS',
            'description': 'Specified flags is invalid.'
        },
        1: {
            'name': 'OFPSCFC_BAD_LEN',
            'description': 'Specified len is invalid.'
        },
        2: {
            'name': 'OFPQCFC_EPERM',
            'description': 'Permissions error.'
        }
    },
    11: {
        'name': 'OFPET_ROLE_REQUEST_FAILED',
        'description': 'Controller Role request failed.',
        0: {
            'name': 'OFPRRFC_STALE',
            'description': 'Stale Message: old generation_id.'
        },
        1: {
            'name': 'OFPRRFC_UNSUP',
            'description': 'Controller role change unsupported.'
        },
        2: {
            'name': 'OFPRRFC_BAD_ROLE',
            'description': 'Invalid role.'
        }
    },
    12: {
        'name': 'OFPET_METER_MOD_FAILED',
        'description': 'Error in meter.',
        0: {
            'name': 'OFPMMFC_UNKNOWN',
            'description': 'Unspecified error.'
        },
        1: {
            'name': 'OFPMMFC_METER_EXISTS',
            'description': 'Meter not added because a Meter ADD attempted to '
                           'replace an existing Meter.'
        },
        2: {
            'name': 'OFPMMFC_INVALID_METER',
            'description': 'Meter not added because Meter specified is invalid.'
        },
        3: {
            'name': 'OFPMMFC_UNKNOWN_METER',
            'description': 'Meter not modified because a Meter MODIFY attempted '
                           'to modify a non-existent Meter.'
        },
        4: {
            'name': 'OFPMMFC_BAD_COMMAND',
            'description': 'Unsupported or unknown command.'
        },
        5: {
            'name': 'OFPMMFC_BAD_FLAGS',
            'description': 'Flag configuration unsupported.'
        },
        6: {
            'name': 'OFPMMFC_BAD_RATE',
            'description': 'Rate unsupported.'
        },
        7: {
            'name': 'OFPMMFC_BAD_BURST',
            'description': 'Burst size unsupported.'
        },
        8: {
            'name': 'OFPMMFC_BAD_BAND',
            'description': 'Band unsupported.'
        },
        9: {
            'name': 'OFPMMFC_BAD_BAND_VALUE',
            'description': 'Band value unsupported.'
        },
        10: {
            'name': 'OFPMMFC_OUT_OF_METERS',
            'description': 'No more meters availabile.'
        },
        11: {
            'name': 'OFPMMFC_OUT_OF_BANDS',
            'description': 'The maximum number of properties for a meter has been '
                           'exceeded.'
        }
    },
    13: {
        'name': 'OFPET_TABLE_FEATURES_FAILED',
        'description': 'Setting table features failed.',
        0: {
            'name': 'OFPTFFC_BAD_TABLE',
            'description': 'Specified table does not exist.'
        },
        1: {
            'name': 'OFPTFFC_BAD_METADATA',
            'description': 'Invalid metadata mask.'
        },
        2: {
            'name': 'OFPTFFC_BAD_TYPE',
            'description': 'Unknown property type.'
        },
        3: {
            'name': 'OFPTFFC_BAD_LEN',
            'description': 'Length problem in properties.'
        },
        4: {
            'name': 'OFPTFFC_BAD_ARGUMENT',
            'description': 'Unsupported property value.'
        },
        5: {
            'name': 'OFPTFFC_EPERM',
            'description': 'Permissions error.'
        }
    },
    14: {
        'name': 'OFPET_BAD_PROPERTY',
        'description': 'Some property is invalid.',
        0: {
            'name': 'OFPBPC_BAD_TYPE',
            'description': 'Unknown property type.'
        },
        1: {
            'name': 'OFPBPC_BAD_LEN',
            'description': 'Length problem in property.'
        },
        2: {
            'name': 'OFPBPC_BAD_VALUE',
            'description': 'Unsupported property value.'
        },
        3: {
            'name': 'OFPBPC_TOO_MANY',
            'description': 'Can\'t handle this many properties.'
        },
        4: {
            'name': 'OFPBPC_DUP_TYPE',
            'description': 'A property type was duplicated.'
        },
        5: {
            'name': 'OFPBPC_BAD_EXPERIMENTER',
            'description': 'Unknown experimenter id specified.'
        },
        6: {
            'name': 'OFPBPC_BAD_EXP_TYPE',
            'description': 'Unknown exp_type for experimenter id.'
        },
        7: {
            'name': 'OFPBPC_BAD_EXP_VALUE',
            'description': 'Unknown value for experimenter id.'
        },
        8: {
            'name': 'OFPBPC_EPERM',
            'description': 'ermissions error.'
        }
    },
    15: {
        'name': 'OFPET_ASYNC_CONFIG_FAILED',
        'description': 'Asynchronous config request failed.',
        0: {
            'name': 'OFPACFC_INVALID',
            'description': 'One mask is invalid.'
        },
        1: {
            'name': 'OFPACFC_UNSUPPORTED',
            'description': 'Requested configuration not supported.'
        },
        2: {
            'name': 'OFPACFC_EPERM',
            'description': 'Permissions error.'
        }
    },
    16: {
        'name': 'OFPET_FLOW_MONITOR_FAILED',
        'description': 'Setting flow monitor failed.',
        0: {
            'name': 'OFPMOFC_UNKNOWN',
            'description': 'Unspecified error.'
        },
        1: {
            'name': 'OFPMOFC_MONITOR_EXISTS',
            'description': 'Monitor not added because a Monitor ADD attempted '
                           'to replace an existing Monitor.'
        },
        2: {
            'name': 'OFPMOFC_INVALID_MONITOR',
            'description': 'Monitor not added because Monitor specified is invalid.'
        },
        3: {
            'name': 'OFPMOFC_UNKNOWN_MONITOR',
            'description': 'Monitor not modified because a Monitor MODIFY attempted '
                           'to modify a non-existent Monitor.'
        },
        4: {
            'name': 'OFPMOFC_BAD_COMMAND',
            'description': 'Unsupported or unknown command.'
        },
        5: {
            'name': 'OFPMOFC_BAD_FLAGS',
            'description': 'Flag configuration unsupported.'
        },
        6: {
            'name': 'OFPMOFC_BAD_TABLE_ID',
            'description': 'Specified table does not exist.'
        },
        7: {
            'name': 'OFPMOFC_BAD_OUT',
            'description': 'Error in output port/group.'
        }
    },
    17: {
        'name': 'OFPET_BUNDLE_FAILED',
        'description': 'Bundle operation failed.',
        0: {
            'name': 'OFPBFC_UNKNOWN',
            'description': 'Unspecified error.'
        },
        1: {
            'name': 'OFPBFC_EPERM',
            'description': 'Permissions error.'
        },
        2: {
            'name': 'OFPBFC_BAD_ID',
            'description': 'Bundle ID doesn\'t exist.'
        },
        3: {
            'name': 'OFPBFC_BUNDLE_EXIST',
            'description': 'Bundle ID already exist.'
        },
        4: {
            'name': 'OFPBFC_BUNDLE_CLOSED',
            'description': 'Bundle ID is closed.'
        },
        5: {
            'name': 'OFPBFC_OUT_OF_BUNDLES',
            'description': 'Too many bundles IDs.'
        },
        6: {
            'name': 'OFPBFC_BAD_TYPE',
            'description': 'Unsupported or unknown message control type.'
        },
        7: {
            'name': 'OFPBFC_BAD_FLAGS',
            'description': 'Unsupported, unknown, or inconsistent flags.'
        },
        8: {
            'name': 'OFPBFC_MSG_BAD_LEN',
            'description': 'Length problem in included message.'
        },
        9: {
            'name': 'OFPBFC_MSG_BAD_XID',
            'description': 'Inconsistent or duplicate XID.'
        },
        10: {
            'name': 'OFPBFC_MSG_UNSUP',
            'description': 'Unsupported message in this bundle.'
        },
        11: {
            'name': 'OFPBFC_MSG_CONFLICT',
            'description': 'Unsupported message combination in this bundle.'
        },
        12: {
            'name': 'OFPBFC_MSG_TOO_MANY',
            'description': 'Can\'t handle this many messages in bundle.'
        },
        13: {
            'name': 'OFPBFC_MSG_FAILED',
            'description': 'One message in bundle failed.'
        },
        14: {
            'name': 'OFPBFC_TIMEOUT',
            'description': 'Bundle is taking too long.'
        },
        15: {
            'name': 'OFPBFC_BUNDLE_IN_PROGRESS',
            'description': 'Bundle is locking the resource.'
        }
    },
    0xffff: {
        'name': 'OFPET_EXPERIMENTER',
        'description': 'Experimenter error messages.'
    }
}
