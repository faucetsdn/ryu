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

import collections
import logging
import struct
import sys
import functools

from ryu import exception
from ryu import utils
from ryu.lib import stringify

from . import ofproto_common

LOG = logging.getLogger('ryu.ofproto.ofproto_parser')


def header(buf):
    assert len(buf) >= ofproto_common.OFP_HEADER_SIZE
    #LOG.debug('len %d bufsize %d', len(buf), ofproto.OFP_HEADER_SIZE)
    return struct.unpack_from(ofproto_common.OFP_HEADER_PACK_STR, buffer(buf))


_MSG_PARSERS = {}


def register_msg_parser(version):
    def register(msg_parser):
        _MSG_PARSERS[version] = msg_parser
        return msg_parser
    return register


def msg(datapath, version, msg_type, msg_len, xid, buf):
    assert len(buf) >= msg_len

    msg_parser = _MSG_PARSERS.get(version)
    if msg_parser is None:
        raise exception.OFPUnknownVersion(version=version)

    try:
        return msg_parser(datapath, version, msg_type, msg_len, xid, buf)
    except struct.error:
        LOG.exception(
            'Encounter an error during parsing OpenFlow packet from switch.'
            'This implies switch sending a malfold OpenFlow packet.'
            'version 0x%02x msg_type %d msg_len %d xid %d buf %s',
            version, msg_type, msg_len, xid, utils.bytearray_to_hex(buf))
        raise


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
    for k, v in jsondict.iteritems():
        cls = getattr(parser, k)
        assert issubclass(cls, MsgBase)
        return cls.from_jsondict(v, datapath=dp)


class StringifyMixin(stringify.StringifyMixin):
    _class_prefixes = ["OFP", "MT"]

    @classmethod
    def cls_from_jsondict_key(cls, k):
        obj_cls = super(StringifyMixin, cls).cls_from_jsondict_key(k)
        assert not issubclass(obj_cls, MsgBase)
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
        buf = 'version: 0x%x msg_type 0x%x xid 0x%x ' % (self.version,
                                                         self.msg_type,
                                                         self.xid)
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


def msg_pack_into(fmt, buf, offset, *args):
    if len(buf) < offset:
        buf += bytearray(offset - len(buf))

    if len(buf) == offset:
        buf += struct.pack(fmt, *args)
        return

    needed_len = offset + struct.calcsize(fmt)
    if len(buf) < needed_len:
        buf += bytearray(needed_len - len(buf))

    struct.pack_into(fmt, buf, offset, *args)


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
