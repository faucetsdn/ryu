# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import struct

from ryu import exception

from . import ofproto

LOG = logging.getLogger('ryu.ofproto.ofproto_parser')


def header(buf):
    assert len(buf) >= ofproto.OFP_HEADER_SIZE
    #LOG.debug('len %d bufsize %d', len(buf), ofproto.OFP_HEADER_SIZE)
    return struct.unpack_from(ofproto.OFP_HEADER_PACK_STR, buffer(buf))


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

    return msg_parser(datapath, version, msg_type, msg_len, xid, buf)


class MsgBase(object):
    def __init__(self, datapath):
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

    def set_buf(self, buf):
        self.buf = buffer(buf)

    def __str__(self):
        return 'version: 0x%x msg_type 0x%x xid 0x%x' % (self.version,
                                                         self.msg_type,
                                                         self.xid)

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        msg = cls(datapath)
        msg.set_headers(version, msg_type, msg_len, xid)
        msg.set_buf(buf)
        return msg

    def _serialize_pre(self):
        assert self.version is None
        assert self.msg_type is None
        assert self.buf is None

        self.version = self.datapath.ofproto.OFP_VERSION
        self.msg_type = self.cls_msg_type
        self.buf = bytearray().zfill(self.datapath.ofproto.OFP_HEADER_SIZE)

    def _serialize_header(self):
        # buffer length is determined after trailing data is formated.
        assert self.version is not None
        assert self.msg_type is not None
        assert self.msg_len is None
        assert self.xid is None
        assert self.buf is not None
        assert len(self.buf) >= self.datapath.ofproto.OFP_HEADER_SIZE

        self.msg_len = len(self.buf)
        self.xid = 0  # TODO:XXX

        struct.pack_into(self.datapath.ofproto.OFP_HEADER_PACK_STR, self.buf, 0,
                         self.version, self.msg_type, self.msg_len, self.xid)

    def _serialize_body(self):
        pass

    def serialize(self):
        self._serialize_pre()
        self._serialize_body()
        self._serialize_header()

