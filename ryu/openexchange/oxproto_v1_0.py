"""
Define Open Exchange Protocol fields. 
Author:www.muzixing.com

Date                Work
2015/5/29           new this file.
"""

from struct import calcsize

MAX_XID = 0xffffffff

# define constants
OXP_VERSION = 0x01
OFP_MAX_PORT_NAME_LEN = 16

OXP_TCP_PORT = 6688
OXP_SSL_PORT = 6688
OFP_ETH_ALEN = 6
OFP_ETH_ALEN_STR = str(OFP_ETH_ALEN)

OFP_NO_BUFFER = 0xffffffff