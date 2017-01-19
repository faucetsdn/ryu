# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

import struct

from ryu.lib import stringify
from . import packet_base


class openflow(packet_base.PacketBase):
    """OpenFlow message encoder/decoder class.

    An instance has the following attributes at least.

    ============== =========================================================
    Attribute      Description
    ============== =========================================================
    msg            An instance of OpenFlow message (see :ref:`ofproto_ref`)
                   or an instance of OFPUnparseableMsg if failed to parse
                   packet as OpenFlow message.
    ============== =========================================================
    """

    PACK_STR = '!BBHI'
    _MIN_LEN = struct.calcsize(PACK_STR)

    def __init__(self, msg):
        super(openflow, self).__init__()
        self.msg = msg

    @classmethod
    def parser(cls, buf):
        from ryu.ofproto import ofproto_parser
        from ryu.ofproto import ofproto_protocol

        (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)

        msg_parser = ofproto_parser._MSG_PARSERS.get(version)
        if msg_parser is None:
            msg = OFPUnparseableMsg(
                None, version, msg_type, msg_len, xid,
                buf[cls._MIN_LEN:msg_len])
            return cls(msg), cls, buf[msg_len:]

        datapath = ofproto_protocol.ProtocolDesc(version=version)

        try:
            msg = msg_parser(datapath, version, msg_type, msg_len, xid,
                             buf[:msg_len])
        except:
            msg = OFPUnparseableMsg(
                datapath, version, msg_type, msg_len, xid,
                buf[datapath.ofproto.OFP_HEADER_SIZE:msg_len])

        return cls(msg), cls, buf[msg_len:]

    def serialize(self, _payload, _prev):
        self.msg.serialize()
        return self.msg.buf


class OFPUnparseableMsg(stringify.StringifyMixin):
    """Unparseable OpenFlow message encoder class.

    An instance has the following attributes at least.

    ============== ======================================================
    Attribute      Description
    ============== ======================================================
    datapath       A ryu.ofproto.ofproto_protocol.ProtocolDesc instance
                   for this message or None if OpenFlow protocol version
                   is unsupported version.
    version        OpenFlow protocol version
    msg_type       Type of OpenFlow message
    msg_len        Length of the message
    xid            Transaction id
    body           OpenFlow body data
    ============== ======================================================

    .. Note::

        "datapath" attribute is different from
        ryu.controller.controller.Datapath.
        So you can not use "datapath" attribute to send OpenFlow messages.
        For example, "datapath" attribute does not have send_msg method.
    """

    def __init__(self, datapath, version, msg_type, msg_len, xid, body):
        self.datapath = datapath
        self.version = version
        self.msg_type = msg_type
        self.msg_len = msg_len
        self.xid = xid
        self.body = body
        self.buf = None

    def serialize(self):
        self.buf = struct.pack(
            openflow.PACK_STR,
            self.version, self.msg_type, self.msg_len, self.xid)
        self.buf += self.body
