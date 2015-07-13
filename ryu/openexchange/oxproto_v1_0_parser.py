"""
Define the community machanism.
Author:www.muzixing.com

Date                Work
2015/5/29           new this file

"""
# import ryu.ofproto.ofproto_parser
#import ryu.openexchange.oxproto_parser
import base64
import collections
import logging
import struct
import sys
import functools

from ryu import exception
from ryu import utils
from ryu.lib import stringify

from ryu.openexchange import oxproto_common

LOG = logging.getLogger('ryu.openexchange.oxproto_parser')


def header(buf):
    assert len(buf) >= oxproto_common.OXP_HEADER_SIZE
    # LOG.debug('len %d bufsize %d', len(buf), oxproto.OXP_HEADER_SIZE)
    return struct.unpack_from(oxproto_common.OXP_HEADER_PACK_STR, buffer(buf))

#_MSG_PARSERS = {}


def msg(datapath, version, msg_type, msg_len, xid, buf):
    assert len(buf) >= msg_len

    #msg_parser = _MSG_PARSERS.get(version)
    # TODO: oxp version
    msg_parser = 1
    if msg_parser is None:
        raise exception.OXPUnknownVersion(version=version)

    try:
        return msg_parser(datapath, version, msg_type, msg_len, xid, buf)
    except:
        LOG.exception(
            'Encounter an error during parsing OpenFlow packet from switch.'
            'This implies switch sending a malformed OpenFlow packet.'
            'version 0x%02x msg_type %d msg_len %d xid %d buf %s',
            version, msg_type, msg_len, xid, utils.bytearray_to_hex(buf))
        return None


# class OXPHeader():
