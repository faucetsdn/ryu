"""
Define Open Exchange Protocol V1.0 fields.
Author:www.muzixing.com

Date                Work
2015/5/29           new this file.
2015/7/13           add fields
"""

from struct import calcsize

MAX_XID = 0xffffffff

# Define constants
OXP_VERSION = 0x01
OXP_MAX_PORT_NAME_LEN = 16

OXP_TCP_PORT = 6688
OXP_SSL_PORT = 6688
OXP_ETH_ALEN = 6
OXP_ETH_ALEN_STR = str(OXP_ETH_ALEN)
OXP_IP_ALEN = 4
OXP_IP_ALEN_STR = str(OXP_IP_ALEN)

OXP_NO_BUFFER = 0xffffffff

#
#   Common structures
#

# Enum oxp_vport

OXPP_MAX = 0xff00       # Max port number
OXPP_IN_PORT = 0xfff8   # Send the packet out the input port.

OXPP_FLOOD = 0xfffb     # Flood in all outerior ports except in_port.

OXPP_ALL = 0xfffc       # send the packet to all outerior ports.
OXPP_CONTROLLER = 0xfffd    # send the packet to the super controller.
OXPP_LOCAL = 0xfffe     # indicate the port is inside.
OXPP_NONE = 0xffff

_OXP_VPORT_PACK_STR = 'HI2x'
OXP_VPORT_PACK_STR = '!' + _OXP_VPORT_PACK_STR
OXP_VPORT_SIZE = 8
assert calcsize(OXP_VPORT_PACK_STR) == OXP_VPORT_SIZE

# Enum vport state

OXPPS_LINK_DOWN = 1
OXPPS_BLOCKED = 1 << 1
OXPPS_LIVE = 1 << 2

# Enum host_state
OXPP_ACTIVE = 0
OXPP_INACTIVE = 1

OXP_HOST_PACK_STR = '!' + OXP_IP_ALEN_STR + 's' + OXP_ETH_ALEN_STR + 'sBB'
OXP_HOST_SIZE = 12
assert calcsize(OXP_HOST_PACK_STR) == OXP_HOST_SIZE

# internal links

OXP_INTERNAL_LINK_PACK_STR = '!BB6s'
OXP_INTERNAL_LINK_SIZE = 8
assert calcsize(OXP_INTERNAL_LINK_PACK_STR) == OXP_INTERNAL_LINK_SIZE

#
#   Message definition
#

# Enum oxp_type
OXPT_HELLO = 0          # Symmetric message
OXPT_ERROR = 1          # Symmetric message
OXPT_ECHO_REQUEST = 2   # Symmetric message
OXPT_ECHO_REPLY = 3     # Symmetric message
OXPT_EXPERIMENTER = 4   # Symmetric message

OXPT_FEATURES_REQUEST = 5       # Super/Domain message
OXPT_FEATURES_REPLY = 6         # Super/Domain message

OXPT_GET_CONFIG_REQUEST = 7     # Super/Domain message
OXPT_GET_CONFIG_REPLY = 8       # Super/Domain message
OXPT_SET_CONFIG = 9             # Super/Domain message

OXPT_TOPO_REQUEST = 10          # Super/Domain message
OXPT_TOPO_REPLY = 11            # Super/Domain message

OXPT_HOST_REQUEST = 12          # Super/Domain message
OXPT_HOST_REPLY = 13            # Super/Domain message
OXPT_HOST_UPDATE = 14           # Super/Domain message
OXPT_VPORT_STATUS = 15

OXPT_SBP = 16       # Southbound Protocol message

OXPT_VENDOR = 17    # Vendor message

OXP_HEADER_PACK_STR = '!BBHI'   # ! means network(=big-endian)
                                # B = unsigned char
                                # I = unsigned int
                                # H = unsigned short
                                # https://docs.python.org/2/library/struct.html
OXP_HEADER_SIZE = 8
OXP_MSG_SIZE_MAX = 65535

assert calcsize(OXP_HEADER_PACK_STR) == OXP_HEADER_SIZE


# Define constants
OXP_DEFAULT_MISS_SENDD_LEN = 128
OXPC_PERIOD = 10                 # Period of send domain network's info.

# Enum oxp_config_flags
OXPC_MODEL_ADVANCED = 1         # Send the intra-links' capability
OXPC_CAP_BW = 1 << 1            # Bandwidth
OXPC_CAP_DELAY = 1 << 2         # Delay
OXPC_CAP_HOP = 1 << 3           # Hop
OXPC_MODEL_SIMPLIFY = 1 << 4    # Compress the packet_in message
OXPC_MODEL_TRUST = 1 << 5       # Trust the adjacent domain network.

OXPC_MODEL_DEFAULT = 24         # not use.


OXP_DOMAIN_CONFIG_PACK_STR = '!BBH'
OXP_DOMAIN_CONFIG_SIZE = 12
assert(calcsize(OXP_DOMAIN_CONFIG_PACK_STR) + OXP_HEADER_SIZE ==
       OXP_DOMAIN_CONFIG_SIZE)

# Enum oxp_capabilities
OXPC_FLOW_STATS = 1 << 0        # Flow statistics.
OXPC_TABLE_STATS = 1 << 1       # Table statistics.
OXPC_PORT_STATS = 1 << 2        # Port statistics.
OXPC_GROUP_STATS = 1 << 3       # Group statistics.

OXPC_IP_REASM = 1 << 4          # Can reassemble IP fragments.
OXPC_QUEUE_STATS = 1 << 5       # Queue statistics.
OXPC_ARP_MATCH_IP = 1 << 6      # Match IP addresses in ARP pkts.

# Enum oxp_support_Southbound protocol

OXPS_OPENFLOW = 1 << 0
OXPS_XMPP = 1 << 4

OXP_DOMAIN_FEATURES_PACK_STR = '!QBB2xI'
OXP_DOMAIN_FEATURES_SIZE = 24
assert (calcsize(OXP_DOMAIN_FEATURES_PACK_STR) + OXP_HEADER_SIZE ==
        OXP_DOMAIN_FEATURES_SIZE)

# Enum oxp_vport_reason
OXPPR_ADD = 0           # The port was added.
OXPPR_DELETE = 1        # The port was removed.
OXPPR_MODIFY = 2        # Some attribute of the port has changed.

_OXP_VPORT_STATUS_PACK_STR = '!B7x'
OXP_VPORT_STATUS_PACK_STR = _OXP_VPORT_STATUS_PACK_STR + _OXP_VPORT_PACK_STR

OXP_VPORT_STATUS_DESC_OFFSET = OXP_HEADER_SIZE + 8
OXP_VPORT_STATUS_SIZE = 24
assert (calcsize(OXP_VPORT_STATUS_PACK_STR) + OXP_HEADER_SIZE ==
        OXP_VPORT_STATUS_SIZE)

# Enum error type
OXPET_HELLO_FAILED = 0,             # Hello protocol failed.
OXPET_BAD_REQUEST = 1,              # Request was not understood.
OXPET_DOMAIN_CONFIG_FAILED = 2,     # Domain config request failed.
OXPET_EXPERIMENTER = 0xffff         # Experimenter error messages.

# Enum oxp_hello_failed code
OXPHFC_INCOMPATIBLE = 0,            # No compatible version.
OXPHFC_EPERM = 1,                   # Permissions error

# Enum oxp_bad_request code
OXPBRC_BAD_VERSION = 0,             # oxp_header.version not supported.
OXPBRC_BAD_TYPE = 1,                # oxp_header.type not supported.
OXPBRC_BAD_EXPERIMENTER = 2,        # Experimenter id not supported
OXPBRC_BAD_EXP_TYPE = 3,            # Experimenter type not supported.
OXPBRC_EPERM = 4,                   # Permissions error.
OXPBRC_BAD_LEN = 5,                 # Wrong request length for type.

# Enum oxp_domain_config_failed_code
OXPBRC_BAD_VERSION = 0,              # oxp_header.version not supported.
OXPBRC_BAD_TYPE = 1,                 # oxp_header.type not supported.
OXPBRC_BAD_EXPERIMENTER = 2,        # Experimenter id not supported
OXPBRC_BAD_EXP_TYP = 3,             # Experimenter type not supported.
OXPBRC_EPERM = 4,                    # Permissions error.
OXPBRC_BAD_LEN = 5,                  # Wrong request length for type.

OXP_ERROR_PACK_STR = '!HH'
OXP_ERROR_SIZE = 12
assert calcsize(OXP_ERROR_PACK_STR) + OXP_HEADER_SIZE == OXP_ERROR_SIZE

OXP_VENDOR_HEADER_PACK_STR = '!I'
OXP_VENDOR_HEADER_SIZE = 12
assert (calcsize(OXP_VENDOR_HEADER_PACK_STR) + OXP_HEADER_SIZE ==
        OXP_VENDOR_HEADER_SIZE)
