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


import inspect
import logging
import six
import struct
import unittest

from nose.tools import eq_
from nose.tools import ok_
from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import sctp
from ryu.ofproto import ether
from ryu.ofproto import inet


LOG = logging.getLogger(__name__)


class Test_sctp(unittest.TestCase):

    def setUp(self):
        self.chunks = []
        self.csum = 0
        self.dst_port = 1234
        self.src_port = 5678
        self.vtag = 98765432

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf = b'\x16\x2e\x04\xd2\x05\xe3\x0a\x78\x00\x00\x00\x00'

    def setUp_with_data(self):
        self.unordered = 1
        self.begin = 1
        self.end = 1
        self.length = 16 + 10
        self.tsn = 12345
        self.sid = 1
        self.seq = 0
        self.payload_id = 0
        self.payload_data = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'

        self.data = sctp.chunk_data(
            unordered=self.unordered, begin=self.begin, end=self.end,
            tsn=self.tsn, sid=self.sid, payload_data=self.payload_data)

        self.chunks = [self.data]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x00\x07\x00\x1a\x00\x00\x30\x39\x00\x01\x00\x00' + \
            b'\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'

    def setUp_with_init(self):
        self.flags = 0
        self.length = 20 + 8 + 20 + 8 + 4 + 16 + 16
        self.init_tag = 123456
        self.a_rwnd = 9876
        self.os = 3
        self.mis = 3
        self.i_tsn = 123456

        self.p_ipv4 = sctp.param_ipv4('192.168.1.1')
        self.p_ipv6 = sctp.param_ipv6('fe80::647e:1aff:fec4:8284')
        self.p_cookie_preserve = sctp.param_cookie_preserve(5000)
        self.p_ecn = sctp.param_ecn()
        self.p_host_addr = sctp.param_host_addr(b'test host\x00')
        self.p_support_type = sctp.param_supported_addr(
            [sctp.PTYPE_IPV4, sctp.PTYPE_IPV6, sctp.PTYPE_COOKIE_PRESERVE,
             sctp.PTYPE_ECN, sctp.PTYPE_HOST_ADDR])
        self.params = [
            self.p_ipv4, self.p_ipv6, self.p_cookie_preserve,
            self.p_ecn, self.p_host_addr, self.p_support_type]

        self.init = sctp.chunk_init(
            init_tag=self.init_tag, a_rwnd=self.a_rwnd, os=self.os,
            mis=self.mis, i_tsn=self.i_tsn, params=self.params)

        self.chunks = [self.init]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x01\x00\x00\x5c\x00\x01\xe2\x40\x00\x00\x26\x94' + \
            b'\x00\x03\x00\x03\x00\x01\xe2\x40' + \
            b'\x00\x05\x00\x08\xc0\xa8\x01\x01' + \
            b'\x00\x06\x00\x14' + \
            b'\xfe\x80\x00\x00\x00\x00\x00\x00' + \
            b'\x64\x7e\x1a\xff\xfe\xc4\x82\x84' + \
            b'\x00\x09\x00\x08\x00\x00\x13\x88' + \
            b'\x80\x00\x00\x04' + \
            b'\x00\x0b\x00\x0e' + \
            b'\x74\x65\x73\x74\x20\x68\x6f\x73\x74\x00\x00\x00' + \
            b'\x00\x0c\x00\x0e\x00\x05\x00\x06\x00\x09\x80\x00' + \
            b'\x00\x0b\x00\x00'

    def setUp_with_init_ack(self):
        self.flags = 0
        self.length = 20 + 8 + 8 + 20 + 8 + 4 + 16
        self.init_tag = 123456
        self.a_rwnd = 9876
        self.os = 3
        self.mis = 3
        self.i_tsn = 123456

        self.p_state_cookie = sctp.param_state_cookie(b'\x01\x02\x03')
        self.p_ipv4 = sctp.param_ipv4('192.168.1.1')
        self.p_ipv6 = sctp.param_ipv6('fe80::647e:1aff:fec4:8284')
        self.p_unrecognized_param = sctp.param_unrecognized_param(
            b'\xff\xff\x00\x04')
        self.p_ecn = sctp.param_ecn()
        self.p_host_addr = sctp.param_host_addr(b'test host\x00')
        self.params = [
            self.p_state_cookie, self.p_ipv4, self.p_ipv6,
            self.p_unrecognized_param, self.p_ecn, self.p_host_addr]

        self.init_ack = sctp.chunk_init_ack(
            init_tag=self.init_tag, a_rwnd=self.a_rwnd, os=self.os,
            mis=self.mis, i_tsn=self.i_tsn, params=self.params)

        self.chunks = [self.init_ack]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x02\x00\x00\x54\x00\x01\xe2\x40\x00\x00\x26\x94' + \
            b'\x00\x03\x00\x03\x00\x01\xe2\x40' + \
            b'\x00\x07\x00\x07\x01\x02\x03\x00' + \
            b'\x00\x05\x00\x08\xc0\xa8\x01\x01' + \
            b'\x00\x06\x00\x14' + \
            b'\xfe\x80\x00\x00\x00\x00\x00\x00' + \
            b'\x64\x7e\x1a\xff\xfe\xc4\x82\x84' + \
            b'\x00\x08\x00\x08\xff\xff\x00\x04' + \
            b'\x80\x00\x00\x04' + \
            b'\x00\x0b\x00\x0e' + \
            b'\x74\x65\x73\x74\x20\x68\x6f\x73\x74\x00\x00\x00'

    def setUp_with_sack(self):
        self.flags = 0
        self.length = 16 + 2 * 2 * 5 + 4 * 5
        self.tsn_ack = 123456
        self.a_rwnd = 9876
        self.gapack_num = 5
        self.duptsn_num = 5
        self.gapacks = [[2, 3], [10, 12], [20, 24], [51, 52], [62, 63]]
        self.duptsns = [123458, 123466, 123476, 123507, 123518]

        self.sack = sctp.chunk_sack(
            tsn_ack=self.tsn_ack, a_rwnd=self.a_rwnd,
            gapack_num=self.gapack_num, duptsn_num=self.duptsn_num,
            gapacks=self.gapacks, duptsns=self.duptsns)

        self.chunks = [self.sack]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x03\x00\x00\x38\x00\x01\xe2\x40' + \
            b'\x00\x00\x26\x94\x00\x05\x00\x05' + \
            b'\x00\x02\x00\x03\x00\x0a\x00\x0c\x00\x14\x00\x18' + \
            b'\x00\x33\x00\x34\x00\x3e\x00\x3f' + \
            b'\x00\x01\xe2\x42\x00\x01\xe2\x4a\x00\x01\xe2\x54' + \
            b'\x00\x01\xe2\x73\x00\x01\xe2\x7e'

    def setUp_with_heartbeat(self):
        self.flags = 0
        self.length = 4 + 8

        self.p_heartbeat = sctp.param_heartbeat(b'\x01\x02\x03\x04')

        self.heartbeat = sctp.chunk_heartbeat(info=self.p_heartbeat)

        self.chunks = [self.heartbeat]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x04\x00\x00\x0c' + \
            b'\x00\x01\x00\x08' + \
            b'\x01\x02\x03\x04'

    def setUp_with_heartbeat_ack(self):
        self.flags = 0
        self.length = 4 + 12

        self.p_heartbeat = sctp.param_heartbeat(
            b'\xff\xee\xdd\xcc\xbb\xaa\x99\x88')

        self.heartbeat_ack = sctp.chunk_heartbeat_ack(info=self.p_heartbeat)

        self.chunks = [self.heartbeat_ack]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x05\x00\x00\x10' + \
            b'\x00\x01\x00\x0c' + \
            b'\xff\xee\xdd\xcc\xbb\xaa\x99\x88'

    def setUp_with_abort(self):
        self.tflag = 0
        self.length = 4 + 8 + 16 + 8 + 4 + 20 + 8 + 4 + 8 + 8 + 4 + 12 \
            + 20 + 20

        self.c_invalid_stream_id = sctp.cause_invalid_stream_id(4096)
        self.c_missing_param = sctp.cause_missing_param(
            [sctp.PTYPE_IPV4, sctp.PTYPE_IPV6,
             sctp.PTYPE_COOKIE_PRESERVE, sctp.PTYPE_HOST_ADDR])
        self.c_stale_cookie = sctp.cause_stale_cookie(b'\x00\x00\x13\x88')
        self.c_out_of_resource = sctp.cause_out_of_resource()
        self.c_unresolvable_addr = sctp.cause_unresolvable_addr(
            sctp.param_host_addr(b'test host\x00'))
        self.c_unrecognized_chunk = sctp.cause_unrecognized_chunk(
            b'\xff\x00\x00\x04')
        self.c_invalid_param = sctp.cause_invalid_param()
        self.c_unrecognized_param = sctp.cause_unrecognized_param(
            b'\xff\xff\x00\x04')
        self.c_no_userdata = sctp.cause_no_userdata(b'\x00\x01\xe2\x40')
        self.c_cookie_while_shutdown = sctp.cause_cookie_while_shutdown()
        self.c_restart_with_new_addr = sctp.cause_restart_with_new_addr(
            sctp.param_ipv4('192.168.1.1'))
        self.c_user_initiated_abort = sctp.cause_user_initiated_abort(
            b'Key Interrupt.\x00')
        self.c_protocol_violation = sctp.cause_protocol_violation(
            b'Unknown reason.\x00')

        self.causes = [
            self.c_invalid_stream_id, self.c_missing_param,
            self.c_stale_cookie, self.c_out_of_resource,
            self.c_unresolvable_addr, self.c_unrecognized_chunk,
            self.c_invalid_param, self.c_unrecognized_param,
            self.c_no_userdata, self.c_cookie_while_shutdown,
            self.c_restart_with_new_addr, self.c_user_initiated_abort,
            self.c_protocol_violation]

        self.abort = sctp.chunk_abort(causes=self.causes)

        self.chunks = [self.abort]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x06\x00\x00\x90' + \
            b'\x00\x01\x00\x08\x10\x00\x00\x00' + \
            b'\x00\x02\x00\x10\x00\x00\x00\x04' + \
            b'\x00\x05\x00\x06\x00\x09\x00\x0b' + \
            b'\x00\x03\x00\x08\x00\x00\x13\x88' + \
            b'\x00\x04\x00\x04' + \
            b'\x00\x05\x00\x14' + \
            b'\x00\x0b\x00\x0e' + \
            b'\x74\x65\x73\x74\x20\x68\x6f\x73\x74\x00\x00\x00' + \
            b'\x00\x06\x00\x08\xff\x00\x00\x04' + \
            b'\x00\x07\x00\x04' + \
            b'\x00\x08\x00\x08\xff\xff\x00\x04' + \
            b'\x00\x09\x00\x08\x00\x01\xe2\x40' + \
            b'\x00\x0a\x00\x04' + \
            b'\x00\x0b\x00\x0c' + \
            b'\x00\x05\x00\x08\xc0\xa8\x01\x01' + \
            b'\x00\x0c\x00\x13' + \
            b'\x4b\x65\x79\x20\x49\x6e\x74\x65' + \
            b'\x72\x72\x75\x70\x74\x2e\x00\x00' + \
            b'\x00\x0d\x00\x14' + \
            b'\x55\x6e\x6b\x6e\x6f\x77\x6e\x20' + \
            b'\x72\x65\x61\x73\x6f\x6e\x2e\x00'

    def setUp_with_shutdown(self):
        self.flags = 0
        self.length = 8
        self.tsn_ack = 123456

        self.shutdown = sctp.chunk_shutdown(tsn_ack=self.tsn_ack)

        self.chunks = [self.shutdown]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x07\x00\x00\x08\x00\x01\xe2\x40'

    def setUp_with_shutdown_ack(self):
        self.flags = 0
        self.length = 4

        self.shutdown_ack = sctp.chunk_shutdown_ack()

        self.chunks = [self.shutdown_ack]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x08\x00\x00\x04'

    def setUp_with_error(self):
        self.flags = 0
        self.length = 4 + 8 + 16 + 8 + 4 + 20 + 8 + 4 + 8 + 8 + 4 + 12 \
            + 20 + 20

        self.c_invalid_stream_id = sctp.cause_invalid_stream_id(4096)
        self.c_missing_param = sctp.cause_missing_param(
            [sctp.PTYPE_IPV4, sctp.PTYPE_IPV6,
             sctp.PTYPE_COOKIE_PRESERVE, sctp.PTYPE_HOST_ADDR])
        self.c_stale_cookie = sctp.cause_stale_cookie(b'\x00\x00\x13\x88')
        self.c_out_of_resource = sctp.cause_out_of_resource()
        self.c_unresolvable_addr = sctp.cause_unresolvable_addr(
            sctp.param_host_addr(b'test host\x00'))
        self.c_unrecognized_chunk = sctp.cause_unrecognized_chunk(
            b'\xff\x00\x00\x04')
        self.c_invalid_param = sctp.cause_invalid_param()
        self.c_unrecognized_param = sctp.cause_unrecognized_param(
            b'\xff\xff\x00\x04')
        self.c_no_userdata = sctp.cause_no_userdata(b'\x00\x01\xe2\x40')
        self.c_cookie_while_shutdown = sctp.cause_cookie_while_shutdown()
        self.c_restart_with_new_addr = sctp.cause_restart_with_new_addr(
            sctp.param_ipv4('192.168.1.1'))
        self.c_user_initiated_abort = sctp.cause_user_initiated_abort(
            b'Key Interrupt.\x00')
        self.c_protocol_violation = sctp.cause_protocol_violation(
            b'Unknown reason.\x00')

        self.causes = [
            self.c_invalid_stream_id, self.c_missing_param,
            self.c_stale_cookie, self.c_out_of_resource,
            self.c_unresolvable_addr, self.c_unrecognized_chunk,
            self.c_invalid_param, self.c_unrecognized_param,
            self.c_no_userdata, self.c_cookie_while_shutdown,
            self.c_restart_with_new_addr, self.c_user_initiated_abort,
            self.c_protocol_violation]

        self.error = sctp.chunk_error(causes=self.causes)

        self.chunks = [self.error]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x09\x00\x00\x90' + \
            b'\x00\x01\x00\x08\x10\x00\x00\x00' + \
            b'\x00\x02\x00\x10\x00\x00\x00\x04' + \
            b'\x00\x05\x00\x06\x00\x09\x00\x0b' + \
            b'\x00\x03\x00\x08\x00\x00\x13\x88' + \
            b'\x00\x04\x00\x04' + \
            b'\x00\x05\x00\x14' + \
            b'\x00\x0b\x00\x0e' + \
            b'\x74\x65\x73\x74\x20\x68\x6f\x73\x74\x00\x00\x00' + \
            b'\x00\x06\x00\x08\xff\x00\x00\x04' + \
            b'\x00\x07\x00\x04' + \
            b'\x00\x08\x00\x08\xff\xff\x00\x04' + \
            b'\x00\x09\x00\x08\x00\x01\xe2\x40' + \
            b'\x00\x0a\x00\x04' + \
            b'\x00\x0b\x00\x0c' + \
            b'\x00\x05\x00\x08\xc0\xa8\x01\x01' + \
            b'\x00\x0c\x00\x13' + \
            b'\x4b\x65\x79\x20\x49\x6e\x74\x65' + \
            b'\x72\x72\x75\x70\x74\x2e\x00\x00' + \
            b'\x00\x0d\x00\x14' + \
            b'\x55\x6e\x6b\x6e\x6f\x77\x6e\x20' + \
            b'\x72\x65\x61\x73\x6f\x6e\x2e\x00'

    def setUp_with_cookie_echo(self):
        self.flags = 0
        self.length = 8
        self.cookie = b'\x12\x34\x56\x78'

        self.cookie_echo = sctp.chunk_cookie_echo(cookie=self.cookie)

        self.chunks = [self.cookie_echo]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x0a\x00\x00\x08\x12\x34\x56\x78'

    def setUp_with_cookie_ack(self):
        self.flags = 0
        self.length = 4

        self.cookie_ack = sctp.chunk_cookie_ack()

        self.chunks = [self.cookie_ack]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x0b\x00\x00\x04'

    def setUp_with_ecn_echo(self):
        self.flags = 0
        self.length = 8
        self.low_tsn = 123456

        self.ecn_echo = sctp.chunk_ecn_echo(low_tsn=self.low_tsn)

        self.chunks = [self.ecn_echo]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x0c\x00\x00\x08\x00\x01\xe2\x40'

    def setUp_with_cwr(self):
        self.flags = 0
        self.length = 8
        self.low_tsn = 123456

        self.cwr = sctp.chunk_cwr(low_tsn=self.low_tsn)

        self.chunks = [self.cwr]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x0d\x00\x00\x08\x00\x01\xe2\x40'

    def setUp_with_shutdown_complete(self):
        self.tflag = 0
        self.length = 4

        self.shutdown_complete = sctp.chunk_shutdown_complete()

        self.chunks = [self.shutdown_complete]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x0e\x00\x00\x04'

    def setUp_with_multi_chunks(self):
        self.s_flags = 0
        self.s_length = 16
        self.s_tsn_ack = 123456
        self.s_a_rwnd = 9876
        self.s_gapack_num = 0
        self.s_duptsn_num = 0
        self.s_gapacks = None
        self.s_duptsns = None

        self.sack = sctp.chunk_sack(
            tsn_ack=self.s_tsn_ack, a_rwnd=self.s_a_rwnd)

        self.d1_unordered = 0
        self.d1_begin = 1
        self.d1_end = 0
        self.d1_length = 16 + 10
        self.d1_tsn = 12345
        self.d1_sid = 1
        self.d1_seq = 0
        self.d1_payload_id = 0
        self.d1_payload_data = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'

        self.data1 = sctp.chunk_data(
            begin=self.d1_begin, tsn=self.d1_tsn, sid=self.d1_sid,
            payload_data=self.d1_payload_data)

        self.d2_unordered = 0
        self.d2_begin = 0
        self.d2_end = 1
        self.d2_length = 16 + 10
        self.d2_tsn = 12346
        self.d2_sid = 1
        self.d2_seq = 1
        self.d2_payload_id = 0
        self.d2_payload_data = b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a'

        self.data2 = sctp.chunk_data(
            end=self.d2_end, tsn=self.d2_tsn, sid=self.d2_sid,
            seq=self.d2_seq, payload_data=self.d2_payload_data)

        self.chunks = [self.sack, self.data1, self.data2]

        self.sc = sctp.sctp(
            self.src_port, self.dst_port, self.vtag, self.csum,
            self.chunks)

        self.buf += b'\x03\x00\x00\x10\x00\x01\xe2\x40' + \
            b'\x00\x00\x26\x94\x00\x00\x00\x00' + \
            b'\x00\x02\x00\x1a\x00\x00\x30\x39\x00\x01\x00\x00' + \
            b'\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a' + \
            b'\x00\x01\x00\x1a\x00\x00\x30\x3a\x00\x01\x00\x01' + \
            b'\x00\x00\x00\x00\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a'

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.src_port, self.sc.src_port)
        eq_(self.dst_port, self.sc.dst_port)
        eq_(self.vtag, self.sc.vtag)
        eq_(self.csum, self.sc.csum)
        eq_(self.chunks, self.sc.chunks)

    def test_init_with_data(self):
        self.setUp_with_data()
        self.test_init()

    def test_init_with_init(self):
        self.setUp_with_init()
        self.test_init()

    def test_init_with_init_ack(self):
        self.setUp_with_init_ack()
        self.test_init()

    def test_init_with_sack(self):
        self.setUp_with_sack()
        self.test_init()

    def test_init_with_heartbeat(self):
        self.setUp_with_heartbeat()
        self.test_init()

    def test_init_with_heartbeat_ack(self):
        self.setUp_with_heartbeat_ack()
        self.test_init()

    def test_init_with_abort(self):
        self.setUp_with_abort()
        self.test_init()

    def test_init_with_shutdown(self):
        self.setUp_with_shutdown()
        self.test_init()

    def test_init_with_shutdown_ack(self):
        self.setUp_with_shutdown_ack()
        self.test_init()

    def test_init_with_error(self):
        self.setUp_with_error()
        self.test_init()

    def test_init_with_cookie_echo(self):
        self.setUp_with_cookie_echo()
        self.test_init()

    def test_init_with_cookie_ack(self):
        self.setUp_with_cookie_ack()
        self.test_init()

    def test_init_with_ecn_echo(self):
        self.setUp_with_ecn_echo()
        self.test_init()

    def test_init_with_cwr(self):
        self.setUp_with_cwr()
        self.test_init()

    def test_init_with_shutdown_complete(self):
        self.setUp_with_shutdown_complete()
        self.test_init()

    def test_init_with_multi_chunks(self):
        self.setUp_with_multi_chunks()
        self.test_init()

    def test_parser(self):
        _res = self.sc.parser(six.binary_type(self.buf))
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        # to calculate the lengths of parameters.
        self.sc.serialize(None, None)

        eq_(self.src_port, res.src_port)
        eq_(self.dst_port, res.dst_port)
        eq_(self.vtag, res.vtag)
        eq_(self.csum, res.csum)
        eq_(str(self.chunks), str(res.chunks))

    def test_parser_with_data(self):
        self.setUp_with_data()
        self.test_parser()

    def test_parser_with_init(self):
        self.setUp_with_init()
        self.test_parser()

    def test_parser_with_init_ack(self):
        self.setUp_with_init_ack()
        self.test_parser()

    def test_parser_with_sack(self):
        self.setUp_with_sack()
        self.test_parser()

    def test_parser_with_heartbeat(self):
        self.setUp_with_heartbeat()
        self.test_parser()

    def test_parser_with_heartbeat_ack(self):
        self.setUp_with_heartbeat_ack()
        self.test_parser()

    def test_parser_with_abort(self):
        self.setUp_with_abort()
        self.test_parser()

    def test_parser_with_shutdown(self):
        self.setUp_with_shutdown()
        self.test_parser()

    def test_parser_with_shutdown_ack(self):
        self.setUp_with_shutdown_ack()
        self.test_parser()

    def test_parser_with_error(self):
        self.setUp_with_error()
        self.test_parser()

    def test_parser_with_cookie_echo(self):
        self.setUp_with_cookie_echo()
        self.test_parser()

    def test_parser_with_cookie_ack(self):
        self.setUp_with_cookie_ack()
        self.test_parser()

    def test_parser_with_ecn_echo(self):
        self.setUp_with_ecn_echo()
        self.test_parser()

    def test_parser_with_cwr(self):
        self.setUp_with_cwr()
        self.test_parser()

    def test_parser_with_shutdown_complete(self):
        self.setUp_with_shutdown_complete()
        self.test_parser()

    def test_parser_with_multi_chunks(self):
        self.setUp_with_multi_chunks()
        self.test_parser()

    def _test_serialize(self):
        buf = self.sc.serialize(bytearray(), None)
        res = struct.unpack_from(sctp.sctp._PACK_STR, buf)
        eq_(self.src_port, res[0])
        eq_(self.dst_port, res[1])
        eq_(self.vtag, res[2])
        # skip compare checksum
        # eq_(self.csum, res[3])

        return buf[sctp.sctp._MIN_LEN:]

    def test_serialize(self):
        self._test_serialize()

    def test_serialize_with_data(self):
        self.setUp_with_data()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_data._PACK_STR, buf)
        eq_(sctp.chunk_data.chunk_type(), res[0])
        flags = (
            (self.unordered << 2) |
            (self.begin << 1) |
            (self.end << 0))
        eq_(flags, res[1])
        eq_(self.length, res[2])
        eq_(self.tsn, res[3])
        eq_(self.sid, res[4])
        eq_(self.seq, res[5])
        eq_(self.payload_id, res[6])
        eq_(self.payload_data, buf[sctp.chunk_data._MIN_LEN:])

    def test_serialize_with_init(self):
        self.setUp_with_init()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_init._PACK_STR, buf)
        eq_(sctp.chunk_init.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])
        eq_(self.init_tag, res[3])
        eq_(self.a_rwnd, res[4])
        eq_(self.os, res[5])
        eq_(self.mis, res[6])
        eq_(self.i_tsn, res[7])

        buf = buf[sctp.chunk_init._MIN_LEN:]
        res1 = struct.unpack_from(sctp.param_ipv4._PACK_STR, buf)
        eq_(sctp.param_ipv4.param_type(), res1[0])
        eq_(8, res1[1])
        eq_('192.168.1.1', addrconv.ipv4.bin_to_text(
            buf[sctp.param_ipv4._MIN_LEN:sctp.param_ipv4._MIN_LEN + 4]))

        buf = buf[8:]
        res2 = struct.unpack_from(sctp.param_ipv6._PACK_STR, buf)
        eq_(sctp.param_ipv6.param_type(), res2[0])
        eq_(20, res2[1])
        eq_('fe80::647e:1aff:fec4:8284', addrconv.ipv6.bin_to_text(
            buf[sctp.param_ipv6._MIN_LEN:sctp.param_ipv6._MIN_LEN + 16]))

        buf = buf[20:]
        res3 = struct.unpack_from(sctp.param_cookie_preserve._PACK_STR,
                                  buf)
        eq_(sctp.param_cookie_preserve.param_type(), res3[0])
        eq_(8, res3[1])
        eq_(5000, res3[2])

        buf = buf[8:]
        res4 = struct.unpack_from(sctp.param_ecn._PACK_STR, buf)
        eq_(sctp.param_ecn.param_type(), res4[0])
        eq_(4, res4[1])

        buf = buf[4:]
        res5 = struct.unpack_from(sctp.param_host_addr._PACK_STR, buf)
        eq_(sctp.param_host_addr.param_type(), res5[0])
        eq_(14, res5[1])
        eq_(b'test host\x00',
            buf[sctp.param_host_addr._MIN_LEN:
                sctp.param_host_addr._MIN_LEN + 10])

        buf = buf[16:]
        res6 = struct.unpack_from(sctp.param_supported_addr._PACK_STR, buf)
        res6 = list(res6)
        eq_(sctp.param_supported_addr.param_type(), res6[0])
        eq_(14, res6[1])
        buf = buf[sctp.param_supported_addr._MIN_LEN:]
        offset = 0
        tmplist = []
        while offset < len(buf):
            (tmp, ) = struct.unpack_from('!H', buf, offset)
            tmplist.append(tmp)
            offset += struct.calcsize('!H')
        res6.extend(tmplist)
        eq_(sctp.PTYPE_IPV4, res6[2])
        eq_(sctp.PTYPE_IPV6, res6[3])
        eq_(sctp.PTYPE_COOKIE_PRESERVE, res6[4])
        eq_(sctp.PTYPE_ECN, res6[5])
        eq_(sctp.PTYPE_HOST_ADDR, res6[6])

    def test_serialize_with_init_ack(self):
        self.setUp_with_init_ack()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_init_ack._PACK_STR, buf)
        eq_(sctp.chunk_init_ack.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])
        eq_(self.init_tag, res[3])
        eq_(self.a_rwnd, res[4])
        eq_(self.os, res[5])
        eq_(self.mis, res[6])
        eq_(self.i_tsn, res[7])

        buf = buf[sctp.chunk_init_ack._MIN_LEN:]
        res1 = struct.unpack_from(sctp.param_state_cookie._PACK_STR, buf)
        eq_(sctp.param_state_cookie.param_type(), res1[0])
        eq_(7, res1[1])
        eq_(b'\x01\x02\x03',
            buf[sctp.param_state_cookie._MIN_LEN:
                sctp.param_state_cookie._MIN_LEN + 3])

        buf = buf[8:]
        res2 = struct.unpack_from(sctp.param_ipv4._PACK_STR, buf)
        eq_(sctp.param_ipv4.param_type(), res2[0])
        eq_(8, res2[1])
        eq_('192.168.1.1', addrconv.ipv4.bin_to_text(
            buf[sctp.param_ipv4._MIN_LEN:sctp.param_ipv4._MIN_LEN + 4]))

        buf = buf[8:]
        res3 = struct.unpack_from(sctp.param_ipv6._PACK_STR, buf)
        eq_(sctp.param_ipv6.param_type(), res3[0])
        eq_(20, res3[1])
        eq_('fe80::647e:1aff:fec4:8284', addrconv.ipv6.bin_to_text(
            buf[sctp.param_ipv6._MIN_LEN:sctp.param_ipv6._MIN_LEN + 16]))

        buf = buf[20:]
        res4 = struct.unpack_from(
            sctp.param_unrecognized_param._PACK_STR, buf)
        eq_(sctp.param_unrecognized_param.param_type(), res4[0])
        eq_(8, res4[1])
        eq_(b'\xff\xff\x00\x04',
            buf[sctp.param_unrecognized_param._MIN_LEN:
                sctp.param_unrecognized_param._MIN_LEN + 4])

        buf = buf[8:]
        res5 = struct.unpack_from(sctp.param_ecn._PACK_STR, buf)
        eq_(sctp.param_ecn.param_type(), res5[0])
        eq_(4, res5[1])

        buf = buf[4:]
        res6 = struct.unpack_from(sctp.param_host_addr._PACK_STR, buf)
        eq_(sctp.param_host_addr.param_type(), res6[0])
        eq_(14, res6[1])
        eq_(b'test host\x00',
            buf[sctp.param_host_addr._MIN_LEN:
                sctp.param_host_addr._MIN_LEN + 10])

    def test_serialize_with_sack(self):
        self.setUp_with_sack()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_sack._PACK_STR, buf)
        eq_(sctp.chunk_sack.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])
        eq_(self.tsn_ack, res[3])
        eq_(self.a_rwnd, res[4])
        eq_(self.gapack_num, res[5])
        eq_(self.duptsn_num, res[6])

        buf = buf[sctp.chunk_sack._MIN_LEN:]
        gapacks = []
        for _ in range(self.gapack_num):
            (gap_s, gap_e) = struct.unpack_from(
                sctp.chunk_sack._GAPACK_STR, buf)
            one = [gap_s, gap_e]
            gapacks.append(one)
            buf = buf[sctp.chunk_sack._GAPACK_LEN:]
        duptsns = []
        for _ in range(self.duptsn_num):
            (duptsn, ) = struct.unpack_from(
                sctp.chunk_sack._DUPTSN_STR, buf)
            duptsns.append(duptsn)
            buf = buf[sctp.chunk_sack._DUPTSN_LEN:]
        eq_(self.gapacks, gapacks)
        eq_(self.duptsns, duptsns)

    def test_serialize_with_heartbeat(self):
        self.setUp_with_heartbeat()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_heartbeat._PACK_STR, buf)
        eq_(sctp.chunk_heartbeat.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])

        buf = buf[sctp.chunk_heartbeat._MIN_LEN:]
        res1 = struct.unpack_from(sctp.param_heartbeat._PACK_STR, buf)
        eq_(sctp.param_heartbeat.param_type(), res1[0])
        eq_(8, res1[1])
        eq_(b'\x01\x02\x03\x04',
            buf[sctp.param_heartbeat._MIN_LEN:
                sctp.param_heartbeat._MIN_LEN + 4])

    def test_serialize_with_heartbeat_ack(self):
        self.setUp_with_heartbeat_ack()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_heartbeat_ack._PACK_STR, buf)
        eq_(sctp.chunk_heartbeat_ack.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])

        buf = buf[sctp.chunk_heartbeat_ack._MIN_LEN:]
        res1 = struct.unpack_from(sctp.param_heartbeat._PACK_STR, buf)
        eq_(sctp.param_heartbeat.param_type(), res1[0])
        eq_(12, res1[1])
        eq_(b'\xff\xee\xdd\xcc\xbb\xaa\x99\x88',
            buf[sctp.param_heartbeat._MIN_LEN:
                sctp.param_heartbeat._MIN_LEN + 8])

    def test_serialize_with_abort(self):
        self.setUp_with_abort()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_abort._PACK_STR, buf)
        eq_(sctp.chunk_abort.chunk_type(), res[0])
        flags = self.tflag << 0
        eq_(flags, res[1])
        eq_(self.length, res[2])

        buf = buf[sctp.chunk_abort._MIN_LEN:]
        res1 = struct.unpack_from(sctp.cause_invalid_stream_id._PACK_STR, buf)
        eq_(sctp.cause_invalid_stream_id.cause_code(), res1[0])
        eq_(8, res1[1])
        eq_(4096, res1[2])

        buf = buf[8:]
        res2 = struct.unpack_from(sctp.cause_missing_param._PACK_STR, buf)
        eq_(sctp.cause_missing_param.cause_code(), res2[0])
        eq_(16, res2[1])
        eq_(4, res2[2])
        types = []
        for count in range(4):
            (tmp, ) = struct.unpack_from(
                '!H', buf, sctp.cause_missing_param._MIN_LEN + 2 * count)
            types.append(tmp)
        eq_(str([sctp.PTYPE_IPV4, sctp.PTYPE_IPV6,
                 sctp.PTYPE_COOKIE_PRESERVE, sctp.PTYPE_HOST_ADDR]),
            str(types))

        buf = buf[16:]
        res3 = struct.unpack_from(sctp.cause_stale_cookie._PACK_STR, buf)
        eq_(sctp.cause_stale_cookie.cause_code(), res3[0])
        eq_(8, res3[1])
        eq_(b'\x00\x00\x13\x88',
            buf[sctp.cause_stale_cookie._MIN_LEN:
                sctp.cause_stale_cookie._MIN_LEN + 4])

        buf = buf[8:]
        res4 = struct.unpack_from(sctp.cause_out_of_resource._PACK_STR, buf)
        eq_(sctp.cause_out_of_resource.cause_code(), res4[0])
        eq_(4, res4[1])

        buf = buf[4:]
        res5 = struct.unpack_from(
            sctp.cause_unresolvable_addr._PACK_STR, buf)
        eq_(sctp.cause_unresolvable_addr.cause_code(), res5[0])
        eq_(20, res5[1])
        eq_(b'\x00\x0b\x00\x0e\x74\x65\x73\x74' +
            b'\x20\x68\x6f\x73\x74\x00\x00\x00',
            buf[sctp.cause_unresolvable_addr._MIN_LEN:
                sctp.cause_unresolvable_addr._MIN_LEN + 16])

        buf = buf[20:]
        res6 = struct.unpack_from(
            sctp.cause_unrecognized_chunk._PACK_STR, buf)
        eq_(sctp.cause_unrecognized_chunk.cause_code(), res6[0])
        eq_(8, res6[1])
        eq_(b'\xff\x00\x00\x04',
            buf[sctp.cause_unrecognized_chunk._MIN_LEN:
                sctp.cause_unrecognized_chunk._MIN_LEN + 4])

        buf = buf[8:]
        res7 = struct.unpack_from(sctp.cause_invalid_param._PACK_STR, buf)
        eq_(sctp.cause_invalid_param.cause_code(), res7[0])
        eq_(4, res7[1])

        buf = buf[4:]
        res8 = struct.unpack_from(
            sctp.cause_unrecognized_param._PACK_STR, buf)
        eq_(sctp.cause_unrecognized_param.cause_code(), res8[0])
        eq_(8, res8[1])
        eq_(b'\xff\xff\x00\x04',
            buf[sctp.cause_unrecognized_param._MIN_LEN:
                sctp.cause_unrecognized_param._MIN_LEN + 4])

        buf = buf[8:]
        res9 = struct.unpack_from(sctp.cause_no_userdata._PACK_STR, buf)
        eq_(sctp.cause_no_userdata.cause_code(), res9[0])
        eq_(8, res9[1])
        eq_(b'\x00\x01\xe2\x40',
            buf[sctp.cause_no_userdata._MIN_LEN:
                sctp.cause_no_userdata._MIN_LEN + 4])

        buf = buf[8:]
        res10 = struct.unpack_from(
            sctp.cause_cookie_while_shutdown._PACK_STR, buf)
        eq_(sctp.cause_cookie_while_shutdown.cause_code(), res10[0])
        eq_(4, res10[1])

        buf = buf[4:]
        res11 = struct.unpack_from(
            sctp.cause_restart_with_new_addr._PACK_STR, buf)
        eq_(sctp.cause_restart_with_new_addr.cause_code(), res11[0])
        eq_(12, res11[1])
        eq_(b'\x00\x05\x00\x08\xc0\xa8\x01\x01',
            buf[sctp.cause_restart_with_new_addr._MIN_LEN:
                sctp.cause_restart_with_new_addr._MIN_LEN + 8])

        buf = buf[12:]
        res12 = struct.unpack_from(
            sctp.cause_user_initiated_abort._PACK_STR, buf)
        eq_(sctp.cause_user_initiated_abort.cause_code(), res12[0])
        eq_(19, res12[1])
        eq_(b'Key Interrupt.\x00',
            buf[sctp.cause_user_initiated_abort._MIN_LEN:
                sctp.cause_user_initiated_abort._MIN_LEN + 15])

        buf = buf[20:]
        res13 = struct.unpack_from(
            sctp.cause_protocol_violation._PACK_STR, buf)
        eq_(sctp.cause_protocol_violation.cause_code(), res13[0])
        eq_(20, res13[1])
        eq_(b'Unknown reason.\x00',
            buf[sctp.cause_protocol_violation._MIN_LEN:
                sctp.cause_protocol_violation._MIN_LEN + 16])

    def test_serialize_with_shutdown(self):
        self.setUp_with_shutdown()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_shutdown._PACK_STR, buf)
        eq_(sctp.chunk_shutdown.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])
        eq_(self.tsn_ack, res[3])

    def test_serialize_with_shutdown_ack(self):
        self.setUp_with_shutdown_ack()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_shutdown_ack._PACK_STR, buf)
        eq_(sctp.chunk_shutdown_ack.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])

    def test_serialize_with_error(self):
        self.setUp_with_error()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_error._PACK_STR, buf)
        eq_(sctp.chunk_error.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])

        buf = buf[sctp.chunk_error._MIN_LEN:]
        res1 = struct.unpack_from(sctp.cause_invalid_stream_id._PACK_STR, buf)
        eq_(sctp.cause_invalid_stream_id.cause_code(), res1[0])
        eq_(8, res1[1])
        eq_(4096, res1[2])

        buf = buf[8:]
        res2 = struct.unpack_from(sctp.cause_missing_param._PACK_STR, buf)
        eq_(sctp.cause_missing_param.cause_code(), res2[0])
        eq_(16, res2[1])
        eq_(4, res2[2])
        types = []
        for count in range(4):
            (tmp, ) = struct.unpack_from(
                '!H', buf, sctp.cause_missing_param._MIN_LEN + 2 * count)
            types.append(tmp)
        eq_(str([sctp.PTYPE_IPV4, sctp.PTYPE_IPV6,
                 sctp.PTYPE_COOKIE_PRESERVE, sctp.PTYPE_HOST_ADDR]),
            str(types))

        buf = buf[16:]
        res3 = struct.unpack_from(sctp.cause_stale_cookie._PACK_STR, buf)
        eq_(sctp.cause_stale_cookie.cause_code(), res3[0])
        eq_(8, res3[1])
        eq_(b'\x00\x00\x13\x88',
            buf[sctp.cause_stale_cookie._MIN_LEN:
                sctp.cause_stale_cookie._MIN_LEN + 4])

        buf = buf[8:]
        res4 = struct.unpack_from(sctp.cause_out_of_resource._PACK_STR, buf)
        eq_(sctp.cause_out_of_resource.cause_code(), res4[0])
        eq_(4, res4[1])

        buf = buf[4:]
        res5 = struct.unpack_from(
            sctp.cause_unresolvable_addr._PACK_STR, buf)
        eq_(sctp.cause_unresolvable_addr.cause_code(), res5[0])
        eq_(20, res5[1])
        eq_(b'\x00\x0b\x00\x0e\x74\x65\x73\x74' +
            b'\x20\x68\x6f\x73\x74\x00\x00\x00',
            buf[sctp.cause_unresolvable_addr._MIN_LEN:
                sctp.cause_unresolvable_addr._MIN_LEN + 16])

        buf = buf[20:]
        res6 = struct.unpack_from(
            sctp.cause_unrecognized_chunk._PACK_STR, buf)
        eq_(sctp.cause_unrecognized_chunk.cause_code(), res6[0])
        eq_(8, res6[1])
        eq_(b'\xff\x00\x00\x04',
            buf[sctp.cause_unrecognized_chunk._MIN_LEN:
                sctp.cause_unrecognized_chunk._MIN_LEN + 4])

        buf = buf[8:]
        res7 = struct.unpack_from(sctp.cause_invalid_param._PACK_STR, buf)
        eq_(sctp.cause_invalid_param.cause_code(), res7[0])
        eq_(4, res7[1])

        buf = buf[4:]
        res8 = struct.unpack_from(
            sctp.cause_unrecognized_param._PACK_STR, buf)
        eq_(sctp.cause_unrecognized_param.cause_code(), res8[0])
        eq_(8, res8[1])
        eq_(b'\xff\xff\x00\x04',
            buf[sctp.cause_unrecognized_param._MIN_LEN:
                sctp.cause_unrecognized_param._MIN_LEN + 4])

        buf = buf[8:]
        res9 = struct.unpack_from(sctp.cause_no_userdata._PACK_STR, buf)
        eq_(sctp.cause_no_userdata.cause_code(), res9[0])
        eq_(8, res9[1])
        eq_(b'\x00\x01\xe2\x40',
            buf[sctp.cause_no_userdata._MIN_LEN:
                sctp.cause_no_userdata._MIN_LEN + 4])

        buf = buf[8:]
        res10 = struct.unpack_from(
            sctp.cause_cookie_while_shutdown._PACK_STR, buf)
        eq_(sctp.cause_cookie_while_shutdown.cause_code(), res10[0])
        eq_(4, res10[1])

        buf = buf[4:]
        res11 = struct.unpack_from(
            sctp.cause_restart_with_new_addr._PACK_STR, buf)
        eq_(sctp.cause_restart_with_new_addr.cause_code(), res11[0])
        eq_(12, res11[1])
        eq_(b'\x00\x05\x00\x08\xc0\xa8\x01\x01',
            buf[sctp.cause_restart_with_new_addr._MIN_LEN:
                sctp.cause_restart_with_new_addr._MIN_LEN + 8])

        buf = buf[12:]
        res12 = struct.unpack_from(
            sctp.cause_user_initiated_abort._PACK_STR, buf)
        eq_(sctp.cause_user_initiated_abort.cause_code(), res12[0])
        eq_(19, res12[1])
        eq_(b'Key Interrupt.\x00',
            buf[sctp.cause_user_initiated_abort._MIN_LEN:
                sctp.cause_user_initiated_abort._MIN_LEN + 15])

        buf = buf[20:]
        res13 = struct.unpack_from(
            sctp.cause_protocol_violation._PACK_STR, buf)
        eq_(sctp.cause_protocol_violation.cause_code(), res13[0])
        eq_(20, res13[1])
        eq_(b'Unknown reason.\x00',
            buf[sctp.cause_protocol_violation._MIN_LEN:
                sctp.cause_protocol_violation._MIN_LEN + 16])

    def test_serialize_with_cookie_echo(self):
        self.setUp_with_cookie_echo()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_cookie_echo._PACK_STR, buf)
        eq_(sctp.chunk_cookie_echo.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])
        eq_(self.cookie,
            buf[sctp.chunk_cookie_echo._MIN_LEN:
                sctp.chunk_cookie_echo._MIN_LEN + 4])

    def test_serialize_with_cookie_ack(self):
        self.setUp_with_cookie_ack()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_cookie_ack._PACK_STR, buf)
        eq_(sctp.chunk_cookie_ack.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])

    def test_serialize_with_ecn_echo(self):
        self.setUp_with_ecn_echo()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_ecn_echo._PACK_STR, buf)
        eq_(sctp.chunk_ecn_echo.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])
        eq_(self.low_tsn, res[3])

    def test_serialize_with_cwr(self):
        self.setUp_with_cwr()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_cwr._PACK_STR, buf)
        eq_(sctp.chunk_cwr.chunk_type(), res[0])
        eq_(self.flags, res[1])
        eq_(self.length, res[2])
        eq_(self.low_tsn, res[3])

    def test_serialize_with_shutdown_complete(self):
        self.setUp_with_shutdown_complete()
        buf = self._test_serialize()
        res = struct.unpack_from(
            sctp.chunk_shutdown_complete._PACK_STR, buf)
        eq_(sctp.chunk_shutdown_complete.chunk_type(), res[0])
        flags = self.tflag << 0
        eq_(flags, res[1])
        eq_(self.length, res[2])

    def test_serialize_with_multi_chunks(self):
        self.setUp_with_multi_chunks()
        buf = self._test_serialize()
        res = struct.unpack_from(sctp.chunk_sack._PACK_STR, buf)
        eq_(sctp.chunk_sack.chunk_type(), res[0])
        eq_(self.s_flags, res[1])
        eq_(self.s_length, res[2])
        eq_(self.s_tsn_ack, res[3])
        eq_(self.s_a_rwnd, res[4])
        eq_(self.s_gapack_num, res[5])
        eq_(self.s_duptsn_num, res[6])

        buf = buf[self.s_length:]
        res = struct.unpack_from(sctp.chunk_data._PACK_STR, buf)
        eq_(sctp.chunk_data.chunk_type(), res[0])
        d1_flags = (
            (self.d1_unordered << 2) |
            (self.d1_begin << 1) |
            (self.d1_end << 0))
        eq_(d1_flags, res[1])
        eq_(self.d1_length, res[2])
        eq_(self.d1_tsn, res[3])
        eq_(self.d1_sid, res[4])
        eq_(self.d1_seq, res[5])
        eq_(self.d1_payload_id, res[6])
        eq_(self.d1_payload_data,
            buf[sctp.chunk_data._MIN_LEN:
                sctp.chunk_data._MIN_LEN + 10])

        buf = buf[self.d1_length:]
        res = struct.unpack_from(sctp.chunk_data._PACK_STR, buf)
        eq_(sctp.chunk_data.chunk_type(), res[0])
        d2_flags = (
            (self.d2_unordered << 2) |
            (self.d2_begin << 1) |
            (self.d2_end << 0))
        eq_(d2_flags, res[1])
        eq_(self.d2_length, res[2])
        eq_(self.d2_tsn, res[3])
        eq_(self.d2_sid, res[4])
        eq_(self.d2_seq, res[5])
        eq_(self.d2_payload_id, res[6])
        eq_(self.d2_payload_data,
            buf[sctp.chunk_data._MIN_LEN:
                sctp.chunk_data._MIN_LEN + 10])

    def test_build_sctp(self):
        eth = ethernet.ethernet('00:aa:aa:aa:aa:aa', '00:bb:bb:bb:bb:bb',
                                ether.ETH_TYPE_IP)
        ip4 = ipv4.ipv4(4, 5, 16, 0, 0, 2, 0, 64, inet.IPPROTO_SCTP, 0,
                        '192.168.1.1', '10.144.1.1')
        pkt = eth / ip4 / self.sc

        eth = pkt.get_protocol(ethernet.ethernet)
        ok_(eth)
        eq_(eth.ethertype, ether.ETH_TYPE_IP)

        ip4 = pkt.get_protocol(ipv4.ipv4)
        ok_(ip4)
        eq_(ip4.proto, inet.IPPROTO_SCTP)

        sc = pkt.get_protocol(sctp.sctp)
        ok_(sc)
        eq_(sc, self.sc)

    def test_build_sctp_with_data(self):
        self.setUp_with_data()
        self.test_build_sctp()

    def test_build_sctp_with_init(self):
        self.setUp_with_init()
        self.test_build_sctp()

    def test_build_sctp_with_init_ack(self):
        self.setUp_with_init_ack()
        self.test_build_sctp()

    def test_build_sctp_with_sack(self):
        self.setUp_with_sack()
        self.test_build_sctp()

    def test_build_sctp_with_heartbeat(self):
        self.setUp_with_heartbeat()
        self.test_build_sctp()

    def test_build_sctp_with_heartbeat_ack(self):
        self.setUp_with_heartbeat_ack()
        self.test_build_sctp()

    def test_build_sctp_with_abort(self):
        self.setUp_with_abort()
        self.test_build_sctp()

    def test_build_sctp_with_shutdown(self):
        self.setUp_with_shutdown()
        self.test_build_sctp()

    def test_build_sctp_with_shutdown_ack(self):
        self.setUp_with_shutdown_ack()
        self.test_build_sctp()

    def test_build_sctp_with_error(self):
        self.setUp_with_error()
        self.test_build_sctp()

    def test_build_sctp_with_cookie_echo(self):
        self.setUp_with_cookie_echo()
        self.test_build_sctp()

    def test_build_sctp_with_cookie_ack(self):
        self.setUp_with_cookie_ack()
        self.test_build_sctp()

    def test_build_sctp_with_ecn_echo(self):
        self.setUp_with_ecn_echo()
        self.test_build_sctp()

    def test_build_sctp_with_cwr(self):
        self.setUp_with_cwr()
        self.test_build_sctp()

    def test_build_sctp_with_shutdown_complete(self):
        self.setUp_with_shutdown_complete()
        self.test_build_sctp()

    def tset_build_sctp_with_multi_chunks(self):
        self.setUp_with_multi_chunks()
        self.test_build_sctp()

    def test_to_string(self):
        sctp_values = {'src_port': self.src_port,
                       'dst_port': self.dst_port,
                       'vtag': self.vtag,
                       'csum': self.csum,
                       'chunks': self.chunks}
        _sctp_str = ','.join(['%s=%s' % (k, sctp_values[k])
                              for k, _ in inspect.getmembers(self.sc)
                              if k in sctp_values])
        sctp_str = '%s(%s)' % (sctp.sctp.__name__, _sctp_str)

        eq_(str(self.sc), sctp_str)
        eq_(repr(self.sc), sctp_str)

    def test_to_string_with_data(self):
        self.setUp_with_data()
        self.test_to_string()

    def test_to_string_with_init(self):
        self.setUp_with_init()
        self.test_to_string()

    def test_to_string_with_init_ack(self):
        self.setUp_with_init_ack()
        self.test_to_string()

    def test_to_string_with_sack(self):
        self.setUp_with_sack()
        self.test_to_string()

    def test_to_string_with_heartbeat(self):
        self.setUp_with_heartbeat()
        self.test_to_string()

    def test_to_string_with_heartbeat_ack(self):
        self.setUp_with_heartbeat_ack()
        self.test_to_string()

    def test_to_string_with_abort(self):
        self.setUp_with_abort()
        self.test_to_string()

    def test_to_string_with_shutdown(self):
        self.setUp_with_shutdown()
        self.test_to_string()

    def test_to_string_with_shutdown_ack(self):
        self.setUp_with_shutdown_ack()
        self.test_to_string()

    def test_to_string_with_error(self):
        self.setUp_with_error()
        self.test_to_string()

    def test_to_string_with_cookie_echo(self):
        self.setUp_with_cookie_echo()
        self.test_to_string()

    def test_to_string_with_cookie_ack(self):
        self.setUp_with_cookie_ack()
        self.test_to_string()

    def test_to_string_with_ecn_echo(self):
        self.setUp_with_ecn_echo()
        self.test_to_string()

    def test_to_string_with_cwr(self):
        self.setUp_with_cwr()
        self.test_to_string()

    def test_to_string_with_shutdown_complete(self):
        self.setUp_with_shutdown_complete()
        self.test_to_string()

    def test_to_string_with_multi_chunks(self):
        self.setUp_with_multi_chunks()
        self.test_to_string()

    def test_json(self):
        jsondict = self.sc.to_jsondict()
        sc = sctp.sctp.from_jsondict(jsondict['sctp'])
        eq_(str(self.sc), str(sc))

    def test_json_with_data(self):
        self.setUp_with_data()
        self.test_json()

    def test_json_with_init(self):
        self.setUp_with_init()
        self.test_json()

    def test_json_with_init_ack(self):
        self.setUp_with_init_ack()
        self.test_json()

    def test_json_with_sack(self):
        self.setUp_with_sack()
        self.test_json()

    def test_json_with_heartbeat(self):
        self.setUp_with_heartbeat()
        self.test_json()

    def test_json_with_heartbeat_ack(self):
        self.setUp_with_heartbeat_ack()
        self.test_json()

    def test_json_with_abort(self):
        self.setUp_with_abort()
        self.test_json()

    def test_json_with_shutdown(self):
        self.setUp_with_shutdown()
        self.test_json()

    def test_json_with_shutdown_ack(self):
        self.setUp_with_shutdown_ack()
        self.test_json()

    def test_json_with_error(self):
        self.setUp_with_error()
        self.test_json()

    def test_json_with_cookie_echo(self):
        self.setUp_with_cookie_echo()
        self.test_json()

    def test_json_with_cookie_ack(self):
        self.setUp_with_cookie_ack()
        self.test_json()

    def test_json_with_ecn_echo(self):
        self.setUp_with_ecn_echo()
        self.test_json()

    def test_json_with_cwr(self):
        self.setUp_with_cwr()
        self.test_json()

    def test_json_with_shutdown_complete(self):
        self.setUp_with_shutdown_complete()
        self.test_json()

    def test_json_with_multi_chunks(self):
        self.setUp_with_multi_chunks()
        self.test_json()
