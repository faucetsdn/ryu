# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import unittest
import logging
import inspect
import six
import struct

from nose.tools import *
from ryu.lib import addrconv
from ryu.lib.packet import cfm

LOG = logging.getLogger(__name__)


class Test_cfm(unittest.TestCase):

    def setUp(self):
        self.message = cfm.cc_message()
        self.ins = cfm.cfm(self.message)
        data = bytearray()
        prev = None
        self.buf = self.ins.serialize(data, prev)

    def setUp_cc_message(self):
        self.cc_message_md_lv = 1
        self.cc_message_version = 1
        self.cc_message_rdi = 1
        self.cc_message_interval = 1
        self.cc_message_seq_num = 123
        self.cc_message_mep_id = 4
        self.cc_message_md_name_format = 4
        self.cc_message_md_name_length = 0
        self.cc_message_md_name = b"hoge"
        self.cc_message_short_ma_name_format = 2
        self.cc_message_short_ma_name_length = 0
        self.cc_message_short_ma_name = b"pakeratta"
        self.cc_message_md_name_txfcf = 11
        self.cc_message_md_name_rxfcb = 22
        self.cc_message_md_name_txfcb = 33
        self.cc_message_tlvs = [
            cfm.sender_id_tlv(),
            cfm.port_status_tlv(),
            cfm.data_tlv(),
            cfm.interface_status_tlv(),
            cfm.reply_ingress_tlv(),
            cfm.reply_egress_tlv(),
            cfm.ltm_egress_identifier_tlv(),
            cfm.ltr_egress_identifier_tlv(),
            cfm.organization_specific_tlv(),
        ]
        self.message = cfm.cc_message(
            self.cc_message_md_lv,
            self.cc_message_version,
            self.cc_message_rdi,
            self.cc_message_interval,
            self.cc_message_seq_num,
            self.cc_message_mep_id,
            self.cc_message_md_name_format,
            self.cc_message_md_name_length,
            self.cc_message_md_name,
            self.cc_message_short_ma_name_format,
            self.cc_message_short_ma_name_length,
            self.cc_message_short_ma_name,
            self.cc_message_tlvs
        )
        self.ins = cfm.cfm(self.message)
        data = bytearray()
        prev = None
        self.buf = self.ins.serialize(data, prev)

    def setUp_loopback_message(self):
        self.loopback_message_md_lv = 1
        self.loopback_message_version = 1
        self.loopback_message_transaction_id = 12345
        self.loopback_message_tlvs = [
            cfm.sender_id_tlv(),
            cfm.port_status_tlv(),
            cfm.data_tlv(),
            cfm.interface_status_tlv(),
            cfm.reply_ingress_tlv(),
            cfm.reply_egress_tlv(),
            cfm.ltm_egress_identifier_tlv(),
            cfm.ltr_egress_identifier_tlv(),
            cfm.organization_specific_tlv(),
        ]
        self.message = cfm.loopback_message(
            self.loopback_message_md_lv,
            self.loopback_message_version,
            self.loopback_message_transaction_id,
            self.loopback_message_tlvs)
        self.ins = cfm.cfm(self.message)
        data = bytearray()
        prev = None
        self.buf = self.ins.serialize(data, prev)

    def setUp_loopback_reply(self):
        self.loopback_reply_md_lv = 1
        self.loopback_reply_version = 1
        self.loopback_reply_transaction_id = 12345
        self.loopback_reply_tlvs = [
            cfm.sender_id_tlv(),
            cfm.port_status_tlv(),
            cfm.data_tlv(),
            cfm.interface_status_tlv(),
            cfm.reply_ingress_tlv(),
            cfm.reply_egress_tlv(),
            cfm.ltm_egress_identifier_tlv(),
            cfm.ltr_egress_identifier_tlv(),
            cfm.organization_specific_tlv(),
        ]
        self.message = cfm.loopback_reply(
            self.loopback_reply_md_lv,
            self.loopback_reply_version,
            self.loopback_reply_transaction_id,
            self.loopback_reply_tlvs)
        self.ins = cfm.cfm(self.message)
        data = bytearray()
        prev = None
        self.buf = self.ins.serialize(data, prev)

    def setUp_link_trace_message(self):
        self.link_trace_message_md_lv = 1
        self.link_trace_message_version = 1
        self.link_trace_message_use_fdb_only = 1
        self.link_trace_message_transaction_id = 12345
        self.link_trace_message_ttl = 123
        self.link_trace_message_ltm_orig_addr = '11:22:33:44:55:66'
        self.link_trace_message_ltm_targ_addr = '77:88:99:aa:cc:dd'
        self.link_trace_message_tlvs = [
            cfm.sender_id_tlv(),
            cfm.port_status_tlv(),
            cfm.data_tlv(),
            cfm.interface_status_tlv(),
            cfm.reply_ingress_tlv(),
            cfm.reply_egress_tlv(),
            cfm.ltm_egress_identifier_tlv(),
            cfm.ltr_egress_identifier_tlv(),
            cfm.organization_specific_tlv(),
        ]
        self.message = cfm.link_trace_message(
            self.link_trace_message_md_lv,
            self.link_trace_message_version,
            self.link_trace_message_use_fdb_only,
            self.link_trace_message_transaction_id,
            self.link_trace_message_ttl,
            self.link_trace_message_ltm_orig_addr,
            self.link_trace_message_ltm_targ_addr,
            self.link_trace_message_tlvs)
        self.ins = cfm.cfm(self.message)
        data = bytearray()
        prev = None
        self.buf = self.ins.serialize(data, prev)

    def setUp_link_trace_reply(self):
        self.link_trace_reply_md_lv = 1
        self.link_trace_reply_version = 1
        self.link_trace_reply_use_fdb_only = 1
        self.link_trace_reply_fwd_yes = 0
        self.link_trace_reply_terminal_mep = 1
        self.link_trace_reply_transaction_id = 5432
        self.link_trace_reply_ttl = 123
        self.link_trace_reply_relay_action = 3
        self.link_trace_reply_tlvs = [
            cfm.sender_id_tlv(),
            cfm.port_status_tlv(),
            cfm.data_tlv(),
            cfm.interface_status_tlv(),
            cfm.reply_ingress_tlv(),
            cfm.reply_egress_tlv(),
            cfm.ltm_egress_identifier_tlv(),
            cfm.ltr_egress_identifier_tlv(),
            cfm.organization_specific_tlv(),
        ]
        self.message = cfm.link_trace_reply(
            self.link_trace_reply_md_lv,
            self.link_trace_reply_version,
            self.link_trace_reply_use_fdb_only,
            self.link_trace_reply_fwd_yes,
            self.link_trace_reply_terminal_mep,
            self.link_trace_reply_transaction_id,
            self.link_trace_reply_ttl,
            self.link_trace_reply_relay_action,
            self.link_trace_reply_tlvs)
        self.ins = cfm.cfm(self.message)
        data = bytearray()
        prev = None
        self.buf = self.ins.serialize(data, prev)

    def tearDown(self):
        pass

    def test_init(self):
        eq_(str(self.message), str(self.ins.op))

    def test_init_cc_message(self):
        self.setUp_cc_message()
        self.test_init()

    def test_init_loopback_message(self):
        self.setUp_loopback_message()
        self.test_init()

    def test_init_loopback_reply(self):
        self.setUp_loopback_reply()
        self.test_init()

    def test_init_link_trace_message(self):
        self.setUp_link_trace_message()
        self.test_init()

    def test_init_link_trace_reply(self):
        self.setUp_link_trace_reply()
        self.test_init()

    def test_parser(self):
        _res = self.ins.parser(six.binary_type(self.buf))

        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(str(self.message), str(res.op))

    def test_parser_with_cc_message(self):
        self.setUp_cc_message()
        self.test_parser()

    def test_parser_with_loopback_message(self):
        self.setUp_loopback_message()
        self.test_parser()

    def test_parser_with_loopback_reply(self):
        self.setUp_loopback_reply()
        self.test_parser()

    def test_parser_with_link_trace_message(self):
        self.setUp_link_trace_message()
        self.test_parser()

    def test_parser_with_link_trace_reply(self):
        self.setUp_link_trace_reply()
        self.test_parser()

    def test_serialize(self):
        pass

    def test_serialize_with_cc_message(self):
        self.setUp_cc_message()
        self.test_serialize()
        data = bytearray()
        prev = None
        buf = self.ins.serialize(data, prev)
        cc_message = cfm.cc_message.parser(six.binary_type(buf))
        eq_(repr(self.message), repr(cc_message))

    def test_serialize_with_loopback_message(self):
        self.setUp_loopback_message()
        self.test_serialize()
        data = bytearray()
        prev = None
        buf = self.ins.serialize(data, prev)
        loopback_message = cfm.loopback_message.parser(six.binary_type(buf))
        eq_(repr(self.message), repr(loopback_message))

    def test_serialize_with_loopback_reply(self):
        self.setUp_loopback_reply()
        self.test_serialize()
        data = bytearray()
        prev = None
        buf = self.ins.serialize(data, prev)
        loopback_reply = cfm.loopback_reply.parser(six.binary_type(buf))
        eq_(repr(self.message), repr(loopback_reply))

    def test_serialize_with_link_trace_message(self):
        self.setUp_link_trace_message()
        self.test_serialize()
        data = bytearray()
        prev = None
        buf = self.ins.serialize(data, prev)
        link_trace_message = cfm.link_trace_message.parser(six.binary_type(buf))
        eq_(repr(self.message), repr(link_trace_message))

    def test_serialize_with_link_trace_reply(self):
        self.setUp_link_trace_reply()
        self.test_serialize()
        data = bytearray()
        prev = None
        buf = self.ins.serialize(data, prev)
        link_trace_reply = cfm.link_trace_reply.parser(six.binary_type(buf))
        eq_(repr(self.message), repr(link_trace_reply))

    def test_to_string(self):
        cfm_values = {'op': self.message}
        _cfm_str = ','.join(['%s=%s' % (k, cfm_values[k])
                            for k, v in inspect.getmembers(self.ins)
                            if k in cfm_values])
        cfm_str = '%s(%s)' % (cfm.cfm.__name__, _cfm_str)
        eq_(str(self.ins), cfm_str)
        eq_(repr(self.ins), cfm_str)

    def test_to_string_cc_message(self):
        self.setUp_cc_message()
        self.test_to_string()

    def test_to_string_loopback_message(self):
        self.setUp_loopback_message()
        self.test_to_string()

    def test_to_string_loopback_reply(self):
        self.setUp_loopback_reply()
        self.test_to_string()

    def test_to_string_link_trace_message(self):
        self.setUp_link_trace_message()
        self.test_to_string()

    def test_to_string_link_trace_reply(self):
        self.setUp_link_trace_reply()
        self.test_to_string()

    def test_len(self):
        pass

    def test_len_cc_message(self):
        self.setUp_cc_message()
        eq_(len(self.ins), 0 + len(self.message))

    def test_len_loopback_message(self):
        self.setUp_loopback_message()
        eq_(len(self.ins), 0 + len(self.message))

    def test_len_loopback_reply(self):
        self.setUp_loopback_reply()
        eq_(len(self.ins), 0 + len(self.message))

    def test_len_link_trace_message(self):
        self.setUp_link_trace_message()
        eq_(len(self.ins), 0 + len(self.message))

    def test_len_link_trace_reply(self):
        self.setUp_link_trace_reply()
        eq_(len(self.ins), 0 + len(self.message))

    def test_default_args(self):
        pass

    def test_json(self):
        jsondict = self.ins.to_jsondict()
        ins = cfm.cfm.from_jsondict(jsondict['cfm'])
        eq_(str(self.ins), str(ins))

    def test_json_with_cc_message(self):
        self.setUp_cc_message()
        self.test_json()

    def test_json_with_loopback_message(self):
        self.setUp_loopback_message()
        self.test_json()

    def test_json_with_loopback_reply(self):
        self.setUp_loopback_reply()
        self.test_json()

    def test_json_with_link_trace_message(self):
        self.setUp_link_trace_message()
        self.test_json()

    def test_json_with_link_trace_reply(self):
        self.setUp_link_trace_reply()
        self.test_json()


class Test_cc_message(unittest.TestCase):

    def setUp(self):
        self.md_lv = 1
        self.version = 1
        self.opcode = cfm.CFM_CC_MESSAGE
        self.rdi = 1
        self.interval = 5
        self.first_tlv_offset = cfm.cc_message._TLV_OFFSET
        self.seq_num = 2
        self.mep_id = 2
        self.md_name_format = cfm.cc_message._MD_FMT_CHARACTER_STRING
        self.md_name_length = 3
        self.md_name = b"foo"
        self.short_ma_name_format = 2
        self.short_ma_name_length = 8
        self.short_ma_name = b"hogehoge"
        self.tlvs = [
        ]
        self.end_tlv = 0
        self.ins = cfm.cc_message(
            self.md_lv,
            self.version,
            self.rdi,
            self.interval,
            self.seq_num,
            self.mep_id,
            self.md_name_format,
            self.md_name_length,
            self.md_name,
            self.short_ma_name_format,
            self.short_ma_name_length,
            self.short_ma_name,
            self.tlvs
        )

        self.form = '!4BIH2B3s2B8s33x12x4xB'
        self.buf = struct.pack(
            self.form,
            (self.md_lv << 5) | self.version,
            self.opcode,
            (self.rdi << 7) | self.interval,
            self.first_tlv_offset,
            self.seq_num,
            self.mep_id,
            self.md_name_format,
            self.md_name_length,
            self.md_name,
            self.short_ma_name_format,
            self.short_ma_name_length,
            self.short_ma_name,
            self.end_tlv
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.md_lv, self.ins.md_lv)
        eq_(self.version, self.ins.version)
        eq_(self.rdi, self.ins.rdi)
        eq_(self.interval, self.ins.interval)
        eq_(self.seq_num, self.ins.seq_num)
        eq_(self.mep_id, self.ins.mep_id)
        eq_(self.md_name_format, self.ins.md_name_format)
        eq_(self.md_name_length, self.ins.md_name_length)
        eq_(self.md_name, self.ins.md_name)
        eq_(self.short_ma_name_format, self.ins.short_ma_name_format)
        eq_(self.short_ma_name_length, self.ins.short_ma_name_length)
        eq_(self.short_ma_name, self.ins.short_ma_name)
        eq_(self.tlvs, self.ins.tlvs)

    def test_parser(self):
        _res = cfm.cc_message.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.md_lv, res.md_lv)
        eq_(self.version, res.version)
        eq_(self.rdi, res.rdi)
        eq_(self.interval, res.interval)
        eq_(self.seq_num, res.seq_num)
        eq_(self.mep_id, res.mep_id)
        eq_(self.md_name_format, res.md_name_format)
        eq_(self.md_name_length, res.md_name_length)
        eq_(self.md_name, res.md_name)
        eq_(self.short_ma_name_format, res.short_ma_name_format)
        eq_(self.short_ma_name_length, res.short_ma_name_length)
        eq_(self.short_ma_name, res.short_ma_name)
        eq_(self.tlvs, res.tlvs)

    def test_parser_with_no_maintenance_domain_name_present(self):
        form = '!4BIH3B8s37x12x4xB'
        buf = struct.pack(
            form,
            (self.md_lv << 5) | self.version,
            self.opcode,
            (self.rdi << 7) | self.interval,
            self.first_tlv_offset,
            self.seq_num,
            self.mep_id,
            cfm.cc_message._MD_FMT_NO_MD_NAME_PRESENT,
            self.short_ma_name_format,
            self.short_ma_name_length,
            self.short_ma_name,
            self.end_tlv
        )
        _res = cfm.cc_message.parser(buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.md_lv, res.md_lv)
        eq_(self.version, res.version)
        eq_(self.rdi, res.rdi)
        eq_(self.interval, res.interval)
        eq_(self.seq_num, res.seq_num)
        eq_(self.mep_id, res.mep_id)
        eq_(cfm.cc_message._MD_FMT_NO_MD_NAME_PRESENT, res.md_name_format)
        eq_(self.short_ma_name_format, res.short_ma_name_format)
        eq_(self.short_ma_name_length, res.short_ma_name_length)
        eq_(self.short_ma_name, res.short_ma_name)
        eq_(self.tlvs, res.tlvs)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self.md_lv, res[0] >> 5)
        eq_(self.version, res[0] & 0x1f)
        eq_(self.opcode, res[1])
        eq_(self.rdi, res[2] >> 7)
        eq_(self.interval, res[2] & 0x07)
        eq_(self.first_tlv_offset, res[3])
        eq_(self.seq_num, res[4])
        eq_(self.mep_id, res[5])
        eq_(self.md_name_format, res[6])
        eq_(self.md_name_length, res[7])
        eq_(self.md_name, res[8])
        eq_(self.short_ma_name_format, res[9])
        eq_(self.short_ma_name_length, res[10])
        eq_(self.short_ma_name, res[11])
        eq_(self.end_tlv, res[12])

    def test_serialize_with_md_name_length_zero(self):
        ins = cfm.cc_message(
            self.md_lv,
            self.version,
            self.rdi,
            self.interval,
            self.seq_num,
            self.mep_id,
            self.md_name_format,
            0,
            self.md_name,
            self.short_ma_name_format,
            0,
            self.short_ma_name,
            self.tlvs
        )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self.md_lv, res[0] >> 5)
        eq_(self.version, res[0] & 0x1f)
        eq_(self.opcode, res[1])
        eq_(self.rdi, res[2] >> 7)
        eq_(self.interval, res[2] & 0x07)
        eq_(self.first_tlv_offset, res[3])
        eq_(self.seq_num, res[4])
        eq_(self.mep_id, res[5])
        eq_(self.md_name_format, res[6])
        eq_(self.md_name_length, res[7])
        eq_(self.md_name, res[8])
        eq_(self.short_ma_name_format, res[9])
        eq_(self.short_ma_name_length, res[10])
        eq_(self.short_ma_name, res[11])
        eq_(self.end_tlv, res[12])

    def test_serialize_with_no_maintenance_domain_name_present(self):
        form = '!4BIH3B8s37x12x4xB'
        ins = cfm.cc_message(
            self.md_lv,
            self.version,
            self.rdi,
            self.interval,
            self.seq_num,
            self.mep_id,
            cfm.cc_message._MD_FMT_NO_MD_NAME_PRESENT,
            0,
            self.md_name,
            self.short_ma_name_format,
            0,
            self.short_ma_name,
            self.tlvs
        )
        buf = ins.serialize()
        res = struct.unpack_from(form, six.binary_type(buf))
        eq_(self.md_lv, res[0] >> 5)
        eq_(self.version, res[0] & 0x1f)
        eq_(self.opcode, res[1])
        eq_(self.rdi, res[2] >> 7)
        eq_(self.interval, res[2] & 0x07)
        eq_(self.first_tlv_offset, res[3])
        eq_(self.seq_num, res[4])
        eq_(self.mep_id, res[5])
        eq_(cfm.cc_message._MD_FMT_NO_MD_NAME_PRESENT, res[6])
        eq_(self.short_ma_name_format, res[7])
        eq_(self.short_ma_name_length, res[8])
        eq_(self.short_ma_name, res[9])
        eq_(self.end_tlv, res[10])

    def test_len(self):
        # 75 octet (If tlv does not exist)
        eq_(75, len(self.ins))

    def test_default_args(self):
        ins = cfm.cc_message()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.cc_message._PACK_STR, six.binary_type(buf))
        eq_(res[0] >> 5, 0)
        eq_(res[0] & 0x1f, 0)
        eq_(res[1], 1)
        eq_(res[2] >> 7, 0)
        eq_(res[2] & 0x07, 4)
        eq_(res[3], 70)
        eq_(res[4], 0)
        eq_(res[5], 1)
        eq_(res[6], 4)


class Test_loopback_message(unittest.TestCase):

    def setUp(self):
        self.md_lv = 1
        self.version = 1
        self.opcode = cfm.CFM_LOOPBACK_MESSAGE
        self.flags = 0
        self.first_tlv_offset = cfm.loopback_message._TLV_OFFSET
        self.transaction_id = 12345
        self.tlvs = [
        ]

        self.end_tlv = 0
        self.ins = cfm.loopback_message(
            self.md_lv,
            self.version,
            self.transaction_id,
            self.tlvs,
        )
        self.form = '!4BIB'
        self.buf = struct.pack(
            self.form,
            (self.md_lv << 5) | self.version,
            self.opcode,
            self.flags,
            self.first_tlv_offset,
            self.transaction_id,
            self.end_tlv
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.md_lv, self.ins.md_lv)
        eq_(self.version, self.ins.version)
        eq_(self.transaction_id, self.ins.transaction_id)
        eq_(self.tlvs, self.ins.tlvs)

    def test_parser(self):
        _res = cfm.loopback_message.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.md_lv, res.md_lv)
        eq_(self.version, res.version)
        eq_(self.transaction_id, res.transaction_id)
        eq_(self.tlvs, res.tlvs)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self.md_lv, res[0] >> 5)
        eq_(self.version, res[0] & 0x1f)
        eq_(self.opcode, res[1])
        eq_(self.flags, res[2])
        eq_(self.first_tlv_offset, res[3])
        eq_(self.transaction_id, res[4])
        eq_(self.end_tlv, res[5])

    def test_len(self):
        # 9 octet (If tlv does not exist)
        eq_(9, len(self.ins))

    def test_default_args(self):
        ins = cfm.loopback_message()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.loopback_message._PACK_STR,
                                 six.binary_type(buf))
        eq_(res[0] >> 5, 0)
        eq_(res[0] & 0x1f, 0)
        eq_(res[1], 3)
        eq_(res[2], 0)
        eq_(res[3], 4)
        eq_(res[4], 0)


class Test_loopback_reply(unittest.TestCase):

    def setUp(self):
        self.md_lv = 1
        self.version = 1
        self.opcode = cfm.CFM_LOOPBACK_REPLY
        self.flags = 0
        self.first_tlv_offset = cfm.loopback_reply._TLV_OFFSET
        self.transaction_id = 12345
        self.tlvs = [
        ]
        self.end_tlv = 0
        self.ins = cfm.loopback_reply(
            self.md_lv,
            self.version,
            self.transaction_id,
            self.tlvs,
        )
        self.form = '!4BIB'
        self.buf = struct.pack(
            self.form,
            (self.md_lv << 5) | self.version,
            self.opcode,
            self.flags,
            self.first_tlv_offset,
            self.transaction_id,
            self.end_tlv
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.md_lv, self.ins.md_lv)
        eq_(self.version, self.ins.version)
        eq_(self.transaction_id, self.ins.transaction_id)
        eq_(self.tlvs, self.ins.tlvs)

    def test_parser(self):
        _res = cfm.loopback_reply.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.md_lv, res.md_lv)
        eq_(self.version, res.version)
        eq_(self.transaction_id, res.transaction_id)
        eq_(self.tlvs, res.tlvs)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self.md_lv, res[0] >> 5)
        eq_(self.version, res[0] & 0x1f)
        eq_(self.opcode, res[1])
        eq_(self.flags, res[2])
        eq_(self.first_tlv_offset, res[3])
        eq_(self.transaction_id, res[4])
        eq_(self.end_tlv, res[5])

    def test_len(self):
        # 9 octet (If tlv does not exist)
        eq_(9, len(self.ins))

    def test_default_args(self):
        ins = cfm.loopback_reply()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.loopback_reply._PACK_STR, six.binary_type(buf))
        eq_(res[0] >> 5, 0)
        eq_(res[0] & 0x1f, 0)
        eq_(res[1], 2)
        eq_(res[2], 0)
        eq_(res[3], 4)
        eq_(res[4], 0)


class Test_link_trace_message(unittest.TestCase):

    def setUp(self):
        self.md_lv = 1
        self.version = 1
        self.opcode = cfm.CFM_LINK_TRACE_MESSAGE
        self.use_fdb_only = 1
        self.first_tlv_offset = cfm.link_trace_message._TLV_OFFSET
        self.transaction_id = 12345
        self.ttl = 55
        self.ltm_orig_addr = "00:11:22:44:55:66"
        self.ltm_targ_addr = "ab:cd:ef:23:12:65"
        self.tlvs = [
        ]

        self.end_tlv = 0
        self.ins = cfm.link_trace_message(
            self.md_lv,
            self.version,
            self.use_fdb_only,
            self.transaction_id,
            self.ttl,
            self.ltm_orig_addr,
            self.ltm_targ_addr,
            self.tlvs
        )
        self.form = '!4BIB6s6sB'
        self.buf = struct.pack(
            self.form,
            (self.md_lv << 5) | self.version,
            self.opcode,
            self.use_fdb_only << 7,
            self.first_tlv_offset,
            self.transaction_id,
            self.ttl,
            addrconv.mac.text_to_bin(self.ltm_orig_addr),
            addrconv.mac.text_to_bin(self.ltm_targ_addr),
            self.end_tlv
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.md_lv, self.ins.md_lv)
        eq_(self.version, self.ins.version)
        eq_(self.use_fdb_only, self.ins.use_fdb_only)
        eq_(self.transaction_id, self.ins.transaction_id)
        eq_(self.ttl, self.ins.ttl)
        eq_(self.ltm_orig_addr, self.ins.ltm_orig_addr)
        eq_(self.ltm_targ_addr, self.ins.ltm_targ_addr)
        eq_(self.tlvs, self.ins.tlvs)

    def test_parser(self):
        _res = cfm.link_trace_message.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.md_lv, res.md_lv)
        eq_(self.version, res.version)
        eq_(self.use_fdb_only, res.use_fdb_only)
        eq_(self.transaction_id, res.transaction_id)
        eq_(self.ttl, res.ttl)
        eq_(self.ltm_orig_addr, res.ltm_orig_addr)
        eq_(self.ltm_targ_addr, res.ltm_targ_addr)
        eq_(self.tlvs, res.tlvs)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self.md_lv, res[0] >> 5)
        eq_(self.version, res[0] & 0x1f)
        eq_(self.opcode, res[1])
        eq_(self.use_fdb_only, res[2] >> 7)
        eq_(self.first_tlv_offset, res[3])
        eq_(self.transaction_id, res[4])
        eq_(self.ttl, res[5])
        eq_(addrconv.mac.text_to_bin(self.ltm_orig_addr), res[6])
        eq_(addrconv.mac.text_to_bin(self.ltm_targ_addr), res[7])
        eq_(self.end_tlv, res[8])

    def test_len(self):
        # 22 octet (If tlv does not exist)
        eq_(22, len(self.ins))

    def test_default_args(self):
        ins = cfm.link_trace_message()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.link_trace_message._PACK_STR, six.binary_type(buf))
        eq_(res[0] >> 5, 0)
        eq_(res[0] & 0x1f, 0)
        eq_(res[1], 5)
        eq_(res[2] >> 7, 1)
        eq_(res[3], 17)
        eq_(res[4], 0)
        eq_(res[5], 64)
        eq_(res[6], addrconv.mac.text_to_bin('00:00:00:00:00:00'))
        eq_(res[7], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_link_trace_reply(unittest.TestCase):

    def setUp(self):
        self.md_lv = 1
        self.version = 1
        self.opcode = cfm.CFM_LINK_TRACE_REPLY
        self.use_fdb_only = 1
        self.fwd_yes = 0
        self.terminal_mep = 1
        self.first_tlv_offset = cfm.link_trace_reply._TLV_OFFSET
        self.transaction_id = 12345
        self.ttl = 55
        self.relay_action = 2
        self.ltm_orig_addr = "00:11:22:aa:bb:cc"
        self.ltm_targ_addr = "53:45:24:64:ac:ff"
        self.tlvs = [
        ]
        self.end_tlv = 0
        self.ins = cfm.link_trace_reply(
            self.md_lv,
            self.version,
            self.use_fdb_only,
            self.fwd_yes,
            self.terminal_mep,
            self.transaction_id,
            self.ttl,
            self.relay_action,
            self.tlvs,
        )
        self.form = '!4BIBBB'
        self.buf = struct.pack(
            self.form,
            (self.md_lv << 5) | self.version,
            self.opcode,
            (self.use_fdb_only << 7) | (self.fwd_yes << 6) |
            (self.terminal_mep << 5),
            self.first_tlv_offset,
            self.transaction_id,
            self.ttl,
            self.relay_action,
            self.end_tlv
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.md_lv, self.ins.md_lv)
        eq_(self.version, self.ins.version)
        eq_(self.use_fdb_only, self.ins.use_fdb_only)
        eq_(self.fwd_yes, self.ins.fwd_yes)
        eq_(self.terminal_mep, self.ins.terminal_mep)
        eq_(self.transaction_id, self.ins.transaction_id)
        eq_(self.ttl, self.ins.ttl)
        eq_(self.relay_action, self.ins.relay_action)
        eq_(self.tlvs, self.ins.tlvs)

    def test_parser(self):
        _res = cfm.link_trace_reply.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.md_lv, res.md_lv)
        eq_(self.version, res.version)
        eq_(self.use_fdb_only, self.ins.use_fdb_only)
        eq_(self.fwd_yes, self.ins.fwd_yes)
        eq_(self.terminal_mep, self.ins.terminal_mep)
        eq_(self.transaction_id, res.transaction_id)
        eq_(self.ttl, res.ttl)
        eq_(self.relay_action, res.relay_action)
        eq_(self.tlvs, res.tlvs)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self.md_lv, res[0] >> 5)
        eq_(self.version, res[0] & 0x1f)
        eq_(self.opcode, res[1])
        eq_(self.use_fdb_only, res[2] >> 7 & 0x01)
        eq_(self.fwd_yes, res[2] >> 6 & 0x01)
        eq_(self.terminal_mep, res[2] >> 5 & 0x01)
        eq_(self.first_tlv_offset, res[3])
        eq_(self.transaction_id, res[4])
        eq_(self.ttl, res[5])
        eq_(self.relay_action, res[6])
        eq_(self.end_tlv, res[7])

    def test_len(self):
        # 11 octet (If tlv does not exist)
        eq_(11, len(self.ins))

    def test_default_args(self):
        ins = cfm.link_trace_reply()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.link_trace_reply._PACK_STR, six.binary_type(buf))
        eq_(res[0] >> 5, 0)
        eq_(res[0] & 0x1f, 0)
        eq_(res[1], 4)
        eq_(res[2] >> 7, 1)
        eq_(res[2] >> 6 & 0x01, 0)
        eq_(res[2] >> 5 & 0x01, 1)
        eq_(res[3], 6)
        eq_(res[4], 0)
        eq_(res[5], 64)
        eq_(res[6], 1)


class Test_sender_id_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_SENDER_ID_TLV
        self.length = 10
        self.chassis_id_length = 1
        self.chassis_id_subtype = 3
        self.chassis_id = b"\x0a"
        self.ma_domain_length = 2
        self.ma_domain = b"\x04\x05"
        self.ma_length = 3
        self.ma = b"\x01\x02\x03"
        self.ins = cfm.sender_id_tlv(
            self.length,
            self.chassis_id_length,
            self.chassis_id_subtype,
            self.chassis_id,
            self.ma_domain_length,
            self.ma_domain,
            self.ma_length,
            self.ma,
        )
        self.form = '!BHBB1sB2sB3s'
        self.buf = struct.pack(
            self.form,
            self._type,
            self.length,
            self.chassis_id_length,
            self.chassis_id_subtype,
            self.chassis_id,
            self.ma_domain_length,
            self.ma_domain,
            self.ma_length,
            self.ma
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.chassis_id_length, self.ins.chassis_id_length)
        eq_(self.chassis_id_subtype, self.ins.chassis_id_subtype)
        eq_(self.chassis_id, self.ins.chassis_id)
        eq_(self.ma_domain_length, self.ins.ma_domain_length)
        eq_(self.ma_domain, self.ins.ma_domain)
        eq_(self.ma_length, self.ins.ma_length)
        eq_(self.ma, self.ins.ma)

    def test_parser(self):
        _res = cfm.sender_id_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.chassis_id_length, res.chassis_id_length)
        eq_(self.chassis_id_subtype, res.chassis_id_subtype)
        eq_(self.chassis_id, res.chassis_id)
        eq_(self.ma_domain_length, res.ma_domain_length)
        eq_(self.ma_domain, res.ma_domain)
        eq_(self.ma_length, res.ma_length)
        eq_(self.ma, res.ma)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.chassis_id_length, res[2])
        eq_(self.chassis_id_subtype, res[3])
        eq_(self.chassis_id, res[4])
        eq_(self.ma_domain_length, res[5])
        eq_(self.ma_domain, res[6])
        eq_(self.ma_length, res[7])
        eq_(self.ma, res[8])

    def test_serialize_semi_normal_ptn1(self):
        ins = cfm.sender_id_tlv(
            chassis_id_subtype=self.chassis_id_subtype,
            chassis_id=self.chassis_id,
            ma_domain=self.ma_domain,
        )
        buf = ins.serialize()
        form = '!BHBB1sB2sB'
        res = struct.unpack_from(form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(7, res[1])
        eq_(self.chassis_id_length, res[2])
        eq_(self.chassis_id_subtype, res[3])
        eq_(self.chassis_id, res[4])
        eq_(self.ma_domain_length, res[5])
        eq_(self.ma_domain, res[6])
        eq_(0, res[7])

    def test_serialize_semi_normal_ptn2(self):
        ins = cfm.sender_id_tlv(
            ma_domain=self.ma_domain,
            ma=self.ma,
        )
        buf = ins.serialize()
        form = '!BHBB2sB3s'
        res = struct.unpack_from(form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(8, res[1])
        eq_(0, res[2])
        eq_(self.ma_domain_length, res[3])
        eq_(self.ma_domain, res[4])
        eq_(self.ma_length, res[5])
        eq_(self.ma, res[6])

    def test_serialize_semi_normal_ptn3(self):
        ins = cfm.sender_id_tlv(
            chassis_id_subtype=self.chassis_id_subtype,
            chassis_id=self.chassis_id,
        )
        buf = ins.serialize()
        form = '!BHBB1sB'
        res = struct.unpack_from(form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(4, res[1])
        eq_(self.chassis_id_length, res[2])
        eq_(self.chassis_id_subtype, res[3])
        eq_(self.chassis_id, res[4])
        eq_(0, res[5])

    def test_serialize_semi_normal_ptn4(self):
        ins = cfm.sender_id_tlv(
            ma_domain=self.ma_domain,
        )
        buf = ins.serialize()
        form = '!BHBB2sB'
        res = struct.unpack_from(form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(5, res[1])
        eq_(0, res[2])
        eq_(self.ma_domain_length, res[3])
        eq_(self.ma_domain, res[4])
        eq_(0, res[5])

    def test_serialize_with_length_zero(self):
        ins = cfm.sender_id_tlv(
            0,
            0,
            self.chassis_id_subtype,
            self.chassis_id,
            0,
            self.ma_domain,
            0,
            self.ma,
        )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.chassis_id_length, res[2])
        eq_(self.chassis_id_subtype, res[3])
        eq_(self.chassis_id, res[4])
        eq_(self.ma_domain_length, res[5])
        eq_(self.ma_domain, res[6])
        eq_(self.ma_length, res[7])
        eq_(self.ma, res[8])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 10, len(self.ins))

    def test_default_args(self):
        ins = cfm.sender_id_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.sender_id_tlv._PACK_STR, six.binary_type(buf))
        eq_(res[0], cfm.CFM_SENDER_ID_TLV)
        eq_(res[1], 1)
        eq_(res[2], 0)


class Test_port_status_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_PORT_STATUS_TLV
        self.length = 1
        self.port_status = 1
        self.ins = cfm.port_status_tlv(
            self.length,
            self.port_status
        )
        self.form = '!BHB'
        self.buf = struct.pack(
            self.form,
            self._type,
            self.length,
            self.port_status
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.port_status, self.ins.port_status)

    def test_parser(self):
        _res = cfm.port_status_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.port_status, res.port_status)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.port_status, res[2])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 1, len(self.ins))

    def test_default_args(self):
        ins = cfm.port_status_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.port_status_tlv._PACK_STR, six.binary_type(buf))
        eq_(res[0], cfm.CFM_PORT_STATUS_TLV)
        eq_(res[1], 1)
        eq_(res[2], 2)


class Test_data_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_DATA_TLV
        self.length = 3
        self.data_value = b"\x01\x02\x03"
        self.ins = cfm.data_tlv(
            self.length,
            self.data_value
        )
        self.form = '!BH3s'
        self.buf = struct.pack(
            self.form,
            self._type,
            self.length,
            self.data_value,
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.data_value, self.ins.data_value)

    def test_parser(self):
        _res = cfm.data_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.data_value, res.data_value)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.data_value, res[2])

    def test_serialize_with_length_zero(self):
        ins = cfm.data_tlv(
            0,
            self.data_value
        )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.data_value, res[2])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 3, len(self.ins))

    def test_default_args(self):
        ins = cfm.data_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.data_tlv._PACK_STR, six.binary_type(buf))
        eq_(res[0], cfm.CFM_DATA_TLV)
        eq_(res[1], 0)


class Test_interface_status_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_INTERFACE_STATUS_TLV
        self.length = 1
        self.interface_status = 4
        self.ins = cfm.interface_status_tlv(
            self.length,
            self.interface_status
        )
        self.form = '!BHB'
        self.buf = struct.pack(
            self.form,
            self._type,
            self.length,
            self.interface_status
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.interface_status, self.ins.interface_status)

    def test_parser(self):
        _res = cfm.interface_status_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.interface_status, res.interface_status)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.interface_status, res[2])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 1, len(self.ins))

    def test_default_args(self):
        ins = cfm.interface_status_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.interface_status_tlv._PACK_STR, six.binary_type(buf))
        eq_(res[0], cfm.CFM_INTERFACE_STATUS_TLV)
        eq_(res[1], 1)
        eq_(res[2], 1)


class Test_ltm_egress_identifier_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_LTM_EGRESS_IDENTIFIER_TLV
        self.length = 8
        self.egress_id_ui = 7
        self.egress_id_mac = "11:22:33:44:55:66"
        self.ins = cfm.ltm_egress_identifier_tlv(
            self.length,
            self.egress_id_ui,
            self.egress_id_mac
        )
        self.form = '!BHH6s'
        self.buf = struct.pack(
            self.form,
            self._type,
            self.length,
            self.egress_id_ui,
            addrconv.mac.text_to_bin(self.egress_id_mac)
        )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.egress_id_ui, self.ins.egress_id_ui)
        eq_(self.egress_id_mac, self.ins.egress_id_mac)

    def test_parser(self):
        _res = cfm.ltm_egress_identifier_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.egress_id_ui, res.egress_id_ui)
        eq_(self.egress_id_mac, res.egress_id_mac)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.egress_id_ui, res[2])
        eq_(addrconv.mac.text_to_bin(self.egress_id_mac), res[3])

    def test_serialize_with_length_zero(self):
        ins = cfm.ltm_egress_identifier_tlv(
            0,
            self.egress_id_ui,
            self.egress_id_mac
        )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.egress_id_ui, res[2])
        eq_(addrconv.mac.text_to_bin(self.egress_id_mac), res[3])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 8, len(self.ins))

    def test_default_args(self):
        ins = cfm.ltm_egress_identifier_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(
            cfm.ltm_egress_identifier_tlv._PACK_STR, six.binary_type(buf))
        eq_(res[0], cfm.CFM_LTM_EGRESS_IDENTIFIER_TLV)
        eq_(res[1], 8)
        eq_(res[2], 0)
        eq_(res[3], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_ltr_egress_identifier_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_LTR_EGRESS_IDENTIFIER_TLV
        self.length = 16
        self.last_egress_id_ui = 7
        self.last_egress_id_mac = "11:22:33:44:55:66"
        self.next_egress_id_ui = 5
        self.next_egress_id_mac = "33:11:33:aa:bb:cc"
        self.ins = cfm.ltr_egress_identifier_tlv(self.length,
                                                 self.last_egress_id_ui,
                                                 self.last_egress_id_mac,
                                                 self.next_egress_id_ui,
                                                 self.next_egress_id_mac
                                                 )
        self.form = '!BHH6sH6s'
        self.buf = struct.pack(
            self.form,
            self._type,
            self.length,
            self.last_egress_id_ui,
            addrconv.mac.text_to_bin(self.last_egress_id_mac),
            self.next_egress_id_ui,
            addrconv.mac.text_to_bin(self.next_egress_id_mac))

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.last_egress_id_ui, self.ins.last_egress_id_ui)
        eq_(self.last_egress_id_mac, self.ins.last_egress_id_mac)
        eq_(self.next_egress_id_ui, self.ins.next_egress_id_ui)
        eq_(self.next_egress_id_mac, self.ins.next_egress_id_mac)

    def test_parser(self):
        _res = cfm.ltr_egress_identifier_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.last_egress_id_ui, res.last_egress_id_ui)
        eq_(self.last_egress_id_mac, res.last_egress_id_mac)
        eq_(self.next_egress_id_ui, res.next_egress_id_ui)
        eq_(self.next_egress_id_mac, res.next_egress_id_mac)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.last_egress_id_ui, res[2])
        eq_(addrconv.mac.text_to_bin(self.last_egress_id_mac), res[3])
        eq_(self.next_egress_id_ui, res[4])
        eq_(addrconv.mac.text_to_bin(self.next_egress_id_mac), res[5])

    def test_serialize_with_length_zero(self):
        ins = cfm.ltr_egress_identifier_tlv(0,
                                            self.last_egress_id_ui,
                                            self.last_egress_id_mac,
                                            self.next_egress_id_ui,
                                            self.next_egress_id_mac
                                            )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.last_egress_id_ui, res[2])
        eq_(addrconv.mac.text_to_bin(self.last_egress_id_mac), res[3])
        eq_(self.next_egress_id_ui, res[4])
        eq_(addrconv.mac.text_to_bin(self.next_egress_id_mac), res[5])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 16, len(self.ins))

    def test_default_args(self):
        ins = cfm.ltr_egress_identifier_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.ltr_egress_identifier_tlv._PACK_STR,
                                 six.binary_type(buf))
        eq_(res[0], cfm.CFM_LTR_EGRESS_IDENTIFIER_TLV)
        eq_(res[1], 16)
        eq_(res[2], 0)
        eq_(res[3], addrconv.mac.text_to_bin('00:00:00:00:00:00'))
        eq_(res[4], 0)
        eq_(res[5], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_organization_specific_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_ORGANIZATION_SPECIFIC_TLV
        self.length = 10
        self.oui = b"\xff\x12\x34"
        self.subtype = 3
        self.value = b"\x01\x02\x0f\x0e\x0d\x0c"
        self.ins = cfm.organization_specific_tlv(self.length,
                                                 self.oui,
                                                 self.subtype,
                                                 self.value
                                                 )
        self.form = '!BH3sB6s'
        self.buf = struct.pack(self.form,
                               self._type,
                               self.length,
                               self.oui,
                               self.subtype,
                               self.value
                               )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.oui, self.ins.oui)
        eq_(self.subtype, self.ins.subtype)
        eq_(self.value, self.ins.value)

    def test_parser(self):
        _res = cfm.organization_specific_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.oui, res.oui)
        eq_(self.subtype, res.subtype)
        eq_(self.value, res.value)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.oui, res[2])
        eq_(self.subtype, res[3])
        eq_(self.value, res[4])

    def test_serialize_with_zero(self):
        ins = cfm.organization_specific_tlv(0,
                                            self.oui,
                                            self.subtype,
                                            self.value
                                            )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.oui, res[2])
        eq_(self.subtype, res[3])
        eq_(self.value, res[4])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 10, len(self.ins))

    def test_default_args(self):
        ins = cfm.organization_specific_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.organization_specific_tlv._PACK_STR,
                                 six.binary_type(buf))
        eq_(res[0], cfm.CFM_ORGANIZATION_SPECIFIC_TLV)
        eq_(res[1], 4)
        eq_(res[2], b"\x00\x00\x00")
        eq_(res[3], 0)


class Test_reply_ingress_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_REPLY_INGRESS_TLV
        self.length = 12
        self.action = 2
        self.mac_address = 'aa:bb:cc:56:34:12'
        self.port_id_length = 3
        self.port_id_subtype = 2
        self.port_id = b"\x01\x04\x09"
        self.ins = cfm.reply_ingress_tlv(self.length, self.action,
                                         self.mac_address,
                                         self.port_id_length,
                                         self.port_id_subtype,
                                         self.port_id
                                         )
        self.form = '!BHB6sBB3s'
        self.buf = struct.pack(self.form,
                               self._type,
                               self.length,
                               self.action,
                               addrconv.mac.text_to_bin(self.mac_address),
                               self.port_id_length,
                               self.port_id_subtype,
                               self.port_id
                               )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.action, self.ins.action)
        eq_(self.mac_address, self.ins.mac_address)
        eq_(self.port_id_length, self.ins.port_id_length)
        eq_(self.port_id_subtype, self.ins.port_id_subtype)
        eq_(self.port_id, self.ins.port_id)

    def test_parser(self):
        _res = cfm.reply_ingress_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.action, res.action)
        eq_(self.mac_address, res.mac_address)
        eq_(self.port_id_length, res.port_id_length)
        eq_(self.port_id_subtype, res.port_id_subtype)
        eq_(self.port_id, res.port_id)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.action, res[2])
        eq_(addrconv.mac.text_to_bin(self.mac_address), res[3])
        eq_(self.port_id_length, res[4])
        eq_(self.port_id_subtype, res[5])
        eq_(self.port_id, res[6])

    def test_serialize_with_zero(self):
        ins = cfm.reply_ingress_tlv(0,
                                    self.action,
                                    self.mac_address,
                                    0,
                                    self.port_id_subtype,
                                    self.port_id
                                    )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.action, res[2])
        eq_(addrconv.mac.text_to_bin(self.mac_address), res[3])
        eq_(self.port_id_length, res[4])
        eq_(self.port_id_subtype, res[5])
        eq_(self.port_id, res[6])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 12, len(self.ins))

    def test_default_args(self):
        ins = cfm.reply_ingress_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.reply_ingress_tlv._PACK_STR, six.binary_type(buf))
        eq_(res[0], cfm.CFM_REPLY_INGRESS_TLV)
        eq_(res[1], 7)
        eq_(res[2], 1)
        eq_(res[3], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_reply_egress_tlv(unittest.TestCase):

    def setUp(self):
        self._type = cfm.CFM_REPLY_EGRESS_TLV
        self.length = 12
        self.action = 2
        self.mac_address = 'aa:bb:cc:56:34:12'
        self.port_id_length = 3
        self.port_id_subtype = 2
        self.port_id = b"\x01\x04\x09"
        self.ins = cfm.reply_egress_tlv(self.length,
                                        self.action,
                                        self.mac_address,
                                        self.port_id_length,
                                        self.port_id_subtype,
                                        self.port_id
                                        )
        self.form = '!BHB6sBB3s'
        self.buf = struct.pack(self.form,
                               self._type,
                               self.length,
                               self.action,
                               addrconv.mac.text_to_bin(self.mac_address),
                               self.port_id_length,
                               self.port_id_subtype,
                               self.port_id
                               )

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.length, self.ins.length)
        eq_(self.action, self.ins.action)
        eq_(self.mac_address, self.ins.mac_address)
        eq_(self.port_id_length, self.ins.port_id_length)
        eq_(self.port_id_subtype, self.ins.port_id_subtype)
        eq_(self.port_id, self.ins.port_id)

    def test_parser(self):
        _res = cfm.reply_ingress_tlv.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.length, res.length)
        eq_(self.action, res.action)
        eq_(self.mac_address, res.mac_address)
        eq_(self.port_id_length, res.port_id_length)
        eq_(self.port_id_subtype, res.port_id_subtype)
        eq_(self.port_id, res.port_id)

    def test_serialize(self):
        buf = self.ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.action, res[2])
        eq_(addrconv.mac.text_to_bin(self.mac_address), res[3])
        eq_(self.port_id_length, res[4])
        eq_(self.port_id_subtype, res[5])
        eq_(self.port_id, res[6])

    def test_serialize_with_zero(self):
        ins = cfm.reply_egress_tlv(0,
                                   self.action,
                                   self.mac_address,
                                   0,
                                   self.port_id_subtype,
                                   self.port_id
                                   )
        buf = ins.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        eq_(self._type, res[0])
        eq_(self.length, res[1])
        eq_(self.action, res[2])
        eq_(addrconv.mac.text_to_bin(self.mac_address), res[3])
        eq_(self.port_id_length, res[4])
        eq_(self.port_id_subtype, res[5])
        eq_(self.port_id, res[6])

    def test_len(self):
        # tlv_length = type_len + length_len + value_len
        eq_(1 + 2 + 12, len(self.ins))

    def test_default_args(self):
        ins = cfm.reply_egress_tlv()
        buf = ins.serialize()
        res = struct.unpack_from(cfm.reply_egress_tlv._PACK_STR,
                                 six.binary_type(buf))
        eq_(res[0], cfm.CFM_REPLY_EGRESS_TLV)
        eq_(res[1], 7)
        eq_(res[2], 1)
        eq_(res[3], addrconv.mac.text_to_bin('00:00:00:00:00:00'))
