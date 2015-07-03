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
from ryu.lib import addrconv
from ryu.lib.packet import dhcp


LOG = logging.getLogger(__name__)


class Test_dhcp_offer(unittest.TestCase):

    op = dhcp.DHCP_BOOT_REPLY
    chaddr = 'aa:aa:aa:aa:aa:aa'
    htype = 1
    hlen = 6
    hops = 0
    xid = 1
    secs = 0
    flags = 1
    ciaddr = '192.168.10.10'
    yiaddr = '192.168.20.20'
    siaddr = '192.168.30.30'
    giaddr = '192.168.40.40'
    sname = 'abc'
    boot_file = b''

    option_list = [
        dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT, b'\x02', 1),
        dhcp.option(dhcp.DHCP_SUBNET_MASK_OPT, b'\xff\xff\xff\x00', 4),
        dhcp.option(dhcp.DHCP_GATEWAY_ADDR_OPT, b'\xc0\xa8\x0a\x09', 4),
        dhcp.option(dhcp.DHCP_DNS_SERVER_ADDR_OPT, b'\xc0\xa8\x0a\x09', 4),
        dhcp.option(dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, b'\x00\x03\xf4\x80', 4),
        dhcp.option(dhcp.DHCP_RENEWAL_TIME_OPT, b'\x00\x01\xfa\x40', 4),
        dhcp.option(dhcp.DHCP_REBINDING_TIME_OPT, b'\x00\x03\x75\xf0', 4),
        dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT, b'\xc0\xa8\x0a\x09', 4)]
    magic_cookie = '99.130.83.99'
    options = dhcp.options(option_list=option_list, options_len=50,
                           magic_cookie=magic_cookie)

    dh = dhcp.dhcp(op, chaddr, options, htype=htype, hlen=hlen,
                   hops=hops, xid=xid, secs=secs, flags=flags,
                   ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr,
                   giaddr=giaddr, sname=sname, boot_file=boot_file)

    buf = b"\x02\x01\x06\x00\x00\x00\x00\x01\x00\x00\x00\x01\xc0\xa8\x0a\x0a"\
        + b"\xc0\xa8\x14\x14\xc0\xa8\x1e\x1e\xc0\xa8\x28\x28\xaa\xaa\xaa\xaa"\
        + b"\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x62\x63\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63"\
        + b"\x35\x01\x02\x01\x04\xff\xff\xff\x00\x03\x04\xc0\xa8\x0a\x09\x06"\
        + b"\x04\xc0\xa8\x0a\x09\x33\x04\x00\x03\xf4\x80\x3a\x04\x00\x01\xfa"\
        + b"\x40\x3b\x04\x00\x03\x75\xf0\x36\x04\xc0\xa8\x0a\x09\xff"

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.op, self.dh.op)
        eq_(self.htype, self.dh.htype)
        eq_(self.hlen, self.dh.hlen)
        eq_(self.hops, self.dh.hops)
        eq_(self.xid, self.dh.xid)
        eq_(self.secs, self.dh.secs)
        eq_(self.flags, self.dh.flags)
        eq_(self.ciaddr, self.dh.ciaddr)
        eq_(self.yiaddr, self.dh.yiaddr)
        eq_(self.siaddr, self.dh.siaddr)
        eq_(self.giaddr, self.dh.giaddr)
        eq_(self.chaddr, self.dh.chaddr)
        eq_(self.sname, self.dh.sname)
        eq_(self.boot_file, self.dh.boot_file)
        eq_(str(self.options), str(self.dh.options))

    def test_parser(self):
        _res = self.dh.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        eq_(self.op, res.op)
        eq_(self.htype, res.htype)
        eq_(self.hlen, res.hlen)
        eq_(self.hops, res.hops)
        eq_(self.xid, res.xid)
        eq_(self.secs, res.secs)
        eq_(self.flags, res.flags)
        eq_(self.ciaddr, res.ciaddr)
        eq_(self.yiaddr, res.yiaddr)
        eq_(self.siaddr, res.siaddr)
        eq_(self.giaddr, res.giaddr)
        eq_(self.chaddr, res.chaddr)
        # sname is 64 byte length. rest of data is filled by '\x00'.
        eq_(self.sname.ljust(64, '\x00'), res.sname)
        # boof_file is 128 byte length. rest of data is filled by '\x00'.
        eq_(self.boot_file.ljust(128, b'\x00'), res.boot_file)
        eq_(str(self.options), str(res.options))

    def test_parser_corrupted(self):
        buf = self.buf[:128 - (14 + 20 + 8)]
        _res = self.dh.parser(buf)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.dh.serialize(data, prev)

        res = struct.unpack_from(dhcp.dhcp._DHCP_PACK_STR, six.binary_type(buf))

        eq_(self.op, res[0])
        eq_(self.htype, res[1])
        eq_(self.hlen, res[2])
        eq_(self.hops, res[3])
        eq_(self.xid, res[4])
        eq_(self.secs, res[5])
        eq_(self.flags, res[6])
        eq_(self.ciaddr, addrconv.ipv4.bin_to_text(res[7]))
        eq_(self.yiaddr, addrconv.ipv4.bin_to_text(res[8]))
        eq_(self.siaddr, addrconv.ipv4.bin_to_text(res[9]))
        eq_(self.giaddr, addrconv.ipv4.bin_to_text(res[10]))
        eq_(self.chaddr, addrconv.mac.bin_to_text(res[11][:6]))
        # sname is 64 byte length. rest of data is filled by '\x00'.
        eq_(self.sname.ljust(64, '\x00'), res[12].decode('ascii'))
        # boof_file is 128 byte length. rest of data is filled by '\x00'.
        eq_(self.boot_file.ljust(128, b'\x00'), res[13])
        options = dhcp.options.parser(
            buf[struct.calcsize(dhcp.dhcp._DHCP_PACK_STR):])
        eq_(str(self.options), str(options))

    def test_to_string(self):
        option_values = ['tag', 'length', 'value']
        opt_str_list = []
        for option in self.option_list:
            _opt_str = ','.join(['%s=%s' % (k, repr(getattr(option, k)))
                                 for k, v in inspect.getmembers(option)
                                 if k in option_values])
            opt_str = '%s(%s)' % (dhcp.option.__name__, _opt_str)
            opt_str_list.append(opt_str)
        option_str = '[%s]' % ', '.join(opt_str_list)

        opts_vals = {'magic_cookie': repr(self.magic_cookie),
                     'option_list': option_str,
                     'options_len': repr(self.options.options_len)}
        _options_str = ','.join(['%s=%s' % (k, opts_vals[k])
                                 for k, v in inspect.getmembers(self.options)
                                 if k in opts_vals])
        options_str = '%s(%s)' % (dhcp.options.__name__, _options_str)

        dhcp_values = {'op': repr(self.op),
                       'htype': repr(self.htype),
                       'hlen': repr(self.hlen),
                       'hops': repr(self.hops),
                       'xid': repr(self.xid),
                       'secs': repr(self.secs),
                       'flags': repr(self.flags),
                       'ciaddr': repr(self.ciaddr),
                       'yiaddr': repr(self.yiaddr),
                       'siaddr': repr(self.siaddr),
                       'giaddr': repr(self.giaddr),
                       'chaddr': repr(self.chaddr),
                       'sname': repr(self.sname),
                       'boot_file': repr(self.boot_file),
                       'options': options_str}
        _dh_str = ','.join(['%s=%s' % (k, dhcp_values[k])
                            for k, v in inspect.getmembers(self.dh)
                            if k in dhcp_values])
        dh_str = '%s(%s)' % (dhcp.dhcp.__name__, _dh_str)

        eq_(str(self.dh), dh_str)
        eq_(repr(self.dh), dh_str)

    def test_json(self):
        jsondict = self.dh.to_jsondict()
        dh = dhcp.dhcp.from_jsondict(jsondict['dhcp'])
        eq_(str(self.dh), str(dh))


class Test_dhcp_offer_with_hlen_zero(unittest.TestCase):

    op = dhcp.DHCP_BOOT_REPLY
    chaddr = 'aa:aa:aa:aa:aa:aa'
    htype = 1
    hlen = 6
    hops = 0
    xid = 1
    secs = 0
    flags = 1
    ciaddr = '192.168.10.10'
    yiaddr = '192.168.20.20'
    siaddr = '192.168.30.30'
    giaddr = '192.168.40.40'
    sname = 'abc'
    boot_file = ''

    option_list = [
        dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT, b'\x02', 1),
        dhcp.option(dhcp.DHCP_SUBNET_MASK_OPT, b'\xff\xff\xff\x00', 4),
        dhcp.option(dhcp.DHCP_GATEWAY_ADDR_OPT, b'\xc0\xa8\x0a\x09', 4),
        dhcp.option(dhcp.DHCP_DNS_SERVER_ADDR_OPT, b'\xc0\xa8\x0a\x09', 4),
        dhcp.option(dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, b'\x00\x03\xf4\x80', 4),
        dhcp.option(dhcp.DHCP_RENEWAL_TIME_OPT, b'\x00\x01\xfa\x40', 4),
        dhcp.option(dhcp.DHCP_REBINDING_TIME_OPT, b'\x00\x03\x75\xf0', 4),
        dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT, b'\xc0\xa8\x0a\x09', 4)]
    magic_cookie = '99.130.83.99'
    options = dhcp.options(option_list=option_list, options_len=50,
                           magic_cookie=magic_cookie)

    dh = dhcp.dhcp(op, chaddr, options, htype=htype, hlen=0,
                   hops=hops, xid=xid, secs=secs, flags=flags,
                   ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr,
                   giaddr=giaddr, sname=sname, boot_file=boot_file)

    def test_init(self):
        eq_(self.op, self.dh.op)
        eq_(self.htype, self.dh.htype)
        eq_(self.hlen, self.dh.hlen)
        eq_(self.hops, self.dh.hops)
        eq_(self.xid, self.dh.xid)
        eq_(self.secs, self.dh.secs)
        eq_(self.flags, self.dh.flags)
        eq_(self.ciaddr, self.dh.ciaddr)
        eq_(self.yiaddr, self.dh.yiaddr)
        eq_(self.siaddr, self.dh.siaddr)
        eq_(self.giaddr, self.dh.giaddr)
        eq_(self.chaddr, self.dh.chaddr)
        eq_(self.sname, self.dh.sname)
        eq_(self.boot_file, self.dh.boot_file)
        eq_(str(self.options), str(self.dh.options))
