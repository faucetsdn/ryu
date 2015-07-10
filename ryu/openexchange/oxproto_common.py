"""
This file define the common field of oxp.
Author:www.muzixing.com

"""

from struct import calcsize


OXP_HEADER_PACK_STR = '!BBHI'
OXP_HEADER_SIZE = 8
assert calcsize(OXP_HEADER_PACK_STR) == OXP_HEADER_SIZE

# We set the port 6688 as OXP's port.
OXP_TCP_PORT = 6688
OXP_SSL_PORT = 6688

# Vendor/Experimenter IDs
# https://rs.opennetworking.org/wiki/display/PUBLIC/ONF+Registry
#NX_EXPERIMENTER_ID = 0x00002320  # Nicira
#BSN_EXPERIMENTER_ID = 0x005c16c7  # Big Switch Networks
#ONF_EXPERIMENTER_ID = 0x4f4e4600  # OpenFlow Extensions for 1.3.X Pack 1
