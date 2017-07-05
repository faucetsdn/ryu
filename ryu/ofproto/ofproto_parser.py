# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import six

import base64
import collections
import logging
import struct
import functools

from ryu import exception
from ryu import utils
from ryu.lib import stringify

from ryu.ofproto import ofproto_common

LOG = logging.getLogger('ryu.ofproto.ofproto_parser')

# This is merely for API compatibility on python2
if six.PY3:
    buffer = bytes


def header(buf):
    assert len(buf) >= ofproto_common.OFP_HEADER_SIZE
    # LOG.debug('len %d bufsize %d', len(buf), ofproto.OFP_HEADER_SIZE)
    return struct.unpack_from(ofproto_common.OFP_HEADER_PACK_STR,
                              six.binary_type(buf))


_MSG_PARSERS = {}


def register_msg_parser(version):
    def register(msg_parser):
        _MSG_PARSERS[version] = msg_parser
        return msg_parser
    return register


def msg(datapath, version, msg_type, msg_len, xid, buf):
    exp = None
    try:
        assert len(buf) >= msg_len
    except AssertionError as e:
        exp = e

    msg_parser = _MSG_PARSERS.get(version)
    if msg_parser is None:
        raise exception.OFPUnknownVersion(version=version)

    try:
        msg = msg_parser(datapath, version, msg_type, msg_len, xid, buf)
    except exception.OFPTruncatedMessage as e:
        raise e
    except:
        LOG.exception(
            'Encountered an error while parsing OpenFlow packet from switch. '
            'This implies the switch sent a malformed OpenFlow packet. '
            'version 0x%02x msg_type %d msg_len %d xid %d buf %s',
            version, msg_type, msg_len, xid, utils.hex_array(buf))
        msg = None
    if exp:
        raise exp
    return msg


def create_list_of_base_attributes(f):
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        ret = f(self, *args, **kwargs)
        cls = self.__class__
        # hasattr(cls, '_base_attributes') doesn't work because super class
        # may already have the attribute.
        if '_base_attributes' not in cls.__dict__:
            cls._base_attributes = set(dir(self))
        return ret
    return wrapper


def ofp_msg_from_jsondict(dp, jsondict):
    """
    This function instanticates an appropriate OpenFlow message class
    from the given JSON style dictionary.
    The objects created by following two code fragments are equivalent.

    Code A::

        jsonstr = '{ "OFPSetConfig": { "flags": 0, "miss_send_len": 128 } }'
        jsondict = json.loads(jsonstr)
        o = ofp_msg_from_jsondict(dp, jsondict)

    Code B::

        o = dp.ofproto_parser.OFPSetConfig(flags=0, miss_send_len=128)

    This function takes the following arguments.

    ======== =======================================
    Argument Description
    ======== =======================================
    dp       An instance of ryu.controller.Datapath.
    jsondict A JSON style dict.
    ======== =======================================
    """
    parser = dp.ofproto_parser
    assert len(jsondict) == 1
    for k, v in jsondict.items():
        cls = getattr(parser, k)
        assert issubclass(cls, MsgBase)
        return cls.from_jsondict(v, datapath=dp)


def ofp_instruction_from_jsondict(dp, jsonlist, encap=True):
    """
    This function is intended to be used with
    ryu.lib.ofctl_string.ofp_instruction_from_str.
    It is very similar to ofp_msg_from_jsondict, but works on
    a list of OFPInstructions/OFPActions. It also encapsulates
    OFPAction into OFPInstructionActions, as >OF1.0 OFPFlowMod
    requires that.

    This function takes the following arguments.

    ======== ==================================================
    Argument Description
    ======== ==================================================
    dp       An instance of ryu.controller.Datapath.
    jsonlist A list of JSON style dictionaries.
    encap    Encapsulate OFPAction into OFPInstructionActions.
             Must be false for OF10.
    ======== ==================================================
    """
    proto = dp.ofproto
    parser = dp.ofproto_parser
    actions = []
    result = []
    for jsondict in jsonlist:
        assert len(jsondict) == 1
        k, v = list(jsondict.items())[0]
        cls = getattr(parser, k)
        if issubclass(cls, parser.OFPAction):
            if encap:
                actions.append(cls.from_jsondict(v))
                continue
        else:
            ofpinst = getattr(parser, 'OFPInstruction', None)
            if not ofpinst or not issubclass(cls, ofpinst):
                raise ValueError("Supplied jsondict is of wrong type: %s",
                                 jsondict)
        result.append(cls.from_jsondict(v))

    if not encap:
        return result

    if actions:
        # Although the OpenFlow spec says Apply Actions is executed first,
        # let's place it in the head as a precaution.
        result = [parser.OFPInstructionActions(
            proto.OFPIT_APPLY_ACTIONS, actions)] + result
    return result


class StringifyMixin(stringify.StringifyMixin):
    _class_prefixes = ["OFP", "ONF", "MT", "NX"]

    @classmethod
    def cls_from_jsondict_key(cls, k):
        obj_cls = super(StringifyMixin, cls).cls_from_jsondict_key(k)
        return obj_cls


class MsgBase(StringifyMixin):
    """
    This is a base class for OpenFlow message classes.

    An instance of this class has at least the following attributes.

    ========= ==============================
    Attribute Description
    ========= ==============================
    datapath  A ryu.controller.controller.Datapath instance for this message
    version   OpenFlow protocol version
    msg_type  Type of OpenFlow message
    msg_len   Length of the message
    xid       Transaction id
    buf       Raw data
    ========= ==============================
    """

    @create_list_of_base_attributes
    def __init__(self, datapath):
        super(MsgBase, self).__init__()
        self.datapath = datapath
        self.version = None
        self.msg_type = None
        self.msg_len = None
        self.xid = None
        self.buf = None

    def set_headers(self, version, msg_type, msg_len, xid):
        assert msg_type == self.cls_msg_type

        self.version = version
        self.msg_type = msg_type
        self.msg_len = msg_len
        self.xid = xid

    def set_xid(self, xid):
        assert self.xid is None
        self.xid = xid

    def set_buf(self, buf):
        self.buf = buffer(buf)

    def __str__(self):
        def hexify(x):
            return hex(x) if isinstance(x, six.integer_types) else x
        buf = 'version=%s,msg_type=%s,msg_len=%s,xid=%s,' %\
              (hexify(self.version), hexify(self.msg_type),
               hexify(self.msg_len), hexify(self.xid))
        return buf + StringifyMixin.__str__(self)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg_ = cls(datapath)
        msg_.set_headers(version, msg_type, msg_len, xid)
        msg_.set_buf(buf)
        return msg_

    def _serialize_pre(self):
        self.version = self.datapath.ofproto.OFP_VERSION
        self.msg_type = self.cls_msg_type
        self.buf = bytearray(self.datapath.ofproto.OFP_HEADER_SIZE)

    def _serialize_header(self):
        # buffer length is determined after trailing data is formated.
        assert self.version is not None
        assert self.msg_type is not None
        assert self.buf is not None
        assert len(self.buf) >= self.datapath.ofproto.OFP_HEADER_SIZE

        self.msg_len = len(self.buf)
        if self.xid is None:
            self.xid = 0

        struct.pack_into(self.datapath.ofproto.OFP_HEADER_PACK_STR,
                         self.buf, 0,
                         self.version, self.msg_type, self.msg_len, self.xid)

    def _serialize_body(self):
        pass

    def serialize(self):
        self._serialize_pre()
        self._serialize_body()
        self._serialize_header()


class MsgInMsgBase(MsgBase):
    @classmethod
    def _decode_value(cls, k, json_value, decode_string=base64.b64decode,
                      **additional_args):
        return cls._get_decoder(k, decode_string)(json_value,
                                                  **additional_args)


def namedtuple(typename, fields, **kwargs):
    class _namedtuple(StringifyMixin,
                      collections.namedtuple(typename, fields, **kwargs)):
        pass
    return _namedtuple


def msg_str_attr(msg_, buf, attr_list=None):
    if attr_list is None:
        attr_list = stringify.obj_attrs(msg_)
    for attr in attr_list:
        val = getattr(msg_, attr, None)
        if val is not None:
            buf += ' %s %s' % (attr, val)

    return buf
