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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import six
import struct
import inspect
from nose.tools import ok_, eq_, nottest

from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import lldp
from ryu.lib import addrconv

LOG = logging.getLogger(__name__)


class TestLLDPMandatoryTLV(unittest.TestCase):
    def setUp(self):
        # sample data is based on:
        # http://wiki.wireshark.org/LinkLayerDiscoveryProtocol
        #
        # mandatory TLV only
        self.data = b'\x01\x80\xc2\x00\x00\x0e\x00\x04' \
                    + b'\x96\x1f\xa7\x26\x88\xcc\x02\x07' \
                    + b'\x04\x00\x04\x96\x1f\xa7\x26\x04' \
                    + b'\x04\x05\x31\x2f\x33\x06\x02\x00' \
                    + b'\x78\x00\x00'

    def tearDown(self):
        pass

    def test_get_tlv_type(self):
        buf = b'\x02\x07\x04\x00\x04\x96\x1f\xa7\x26'
        eq_(lldp.LLDPBasicTLV.get_type(buf), lldp.LLDP_TLV_CHASSIS_ID)

    def test_parse_without_ethernet(self):
        buf = self.data[ethernet.ethernet._MIN_LEN:]
        (lldp_pkt, cls, rest_buf) = lldp.lldp.parser(buf)
        eq_(len(rest_buf), 0)

        tlvs = lldp_pkt.tlvs
        eq_(tlvs[0].tlv_type, lldp.LLDP_TLV_CHASSIS_ID)
        eq_(tlvs[0].len, 7)
        eq_(tlvs[0].subtype, lldp.ChassisID.SUB_MAC_ADDRESS)
        eq_(tlvs[0].chassis_id, b'\x00\x04\x96\x1f\xa7\x26')
        eq_(tlvs[1].tlv_type, lldp.LLDP_TLV_PORT_ID)
        eq_(tlvs[1].len, 4)
        eq_(tlvs[1].subtype, lldp.PortID.SUB_INTERFACE_NAME)
        eq_(tlvs[1].port_id, b'1/3')
        eq_(tlvs[2].tlv_type, lldp.LLDP_TLV_TTL)
        eq_(tlvs[2].len, 2)
        eq_(tlvs[2].ttl, 120)
        eq_(tlvs[3].tlv_type, lldp.LLDP_TLV_END)

    def test_parse(self):
        buf = self.data
        pkt = packet.Packet(buf)
        i = iter(pkt)

        eq_(type(next(i)), ethernet.ethernet)
        eq_(type(next(i)), lldp.lldp)

    def test_tlv(self):
        tlv = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                             chassis_id=b'\x00\x04\x96\x1f\xa7\x26')
        eq_(tlv.tlv_type, lldp.LLDP_TLV_CHASSIS_ID)
        eq_(tlv.len, 7)
        (typelen, ) = struct.unpack('!H', b'\x02\x07')
        eq_(tlv.typelen, typelen)

    def test_serialize_without_ethernet(self):
        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                        chassis_id=b'\x00\x04\x96\x1f\xa7\x26')
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                                  port_id=b'1/3')
        tlv_ttl = lldp.TTL(ttl=120)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)

        eq_(lldp_pkt.serialize(None, None),
            self.data[ethernet.ethernet._MIN_LEN:])

    def test_serialize(self):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = '00:04:96:1f:a7:26'
        ethertype = ether.ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                        chassis_id=addrconv.mac.
                                        text_to_bin(src))
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                                  port_id=b'1/3')
        tlv_ttl = lldp.TTL(ttl=120)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)

        eq_(len(pkt.protocols), 2)

        pkt.serialize()
        eq_(pkt.data, self.data)

    def test_to_string(self):
        chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                    chassis_id=b'\x00\x04\x96\x1f\xa7\x26')
        port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                              port_id=b'1/3')
        ttl = lldp.TTL(ttl=120)
        end = lldp.End()
        tlvs = (chassis_id, port_id, ttl, end)
        lldp_pkt = lldp.lldp(tlvs)

        chassis_id_values = {'subtype': lldp.ChassisID.SUB_MAC_ADDRESS,
                             'chassis_id': b'\x00\x04\x96\x1f\xa7\x26',
                             'len': chassis_id.len,
                             'typelen': chassis_id.typelen}
        _ch_id_str = ','.join(['%s=%s' % (k, repr(chassis_id_values[k]))
                               for k, v in inspect.getmembers(chassis_id)
                               if k in chassis_id_values])
        tlv_chassis_id_str = '%s(%s)' % (lldp.ChassisID.__name__, _ch_id_str)

        port_id_values = {'subtype': port_id.subtype,
                          'port_id': port_id.port_id,
                          'len': port_id.len,
                          'typelen': port_id.typelen}
        _port_id_str = ','.join(['%s=%s' % (k, repr(port_id_values[k]))
                                 for k, v in inspect.getmembers(port_id)
                                 if k in port_id_values])
        tlv_port_id_str = '%s(%s)' % (lldp.PortID.__name__, _port_id_str)

        ttl_values = {'ttl': ttl.ttl,
                      'len': ttl.len,
                      'typelen': ttl.typelen}
        _ttl_str = ','.join(['%s=%s' % (k, repr(ttl_values[k]))
                             for k, v in inspect.getmembers(ttl)
                             if k in ttl_values])
        tlv_ttl_str = '%s(%s)' % (lldp.TTL.__name__, _ttl_str)

        end_values = {'len': end.len,
                      'typelen': end.typelen}
        _end_str = ','.join(['%s=%s' % (k, repr(end_values[k]))
                             for k, v in inspect.getmembers(end)
                             if k in end_values])
        tlv_end_str = '%s(%s)' % (lldp.End.__name__, _end_str)

        _tlvs_str = '(%s, %s, %s, %s)'
        tlvs_str = _tlvs_str % (tlv_chassis_id_str,
                                tlv_port_id_str,
                                tlv_ttl_str,
                                tlv_end_str)

        _lldp_str = '%s(tlvs=%s)'
        lldp_str = _lldp_str % (lldp.lldp.__name__,
                                tlvs_str)

        eq_(str(lldp_pkt), lldp_str)
        eq_(repr(lldp_pkt), lldp_str)

    def test_json(self):
        chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                    chassis_id=b'\x00\x04\x96\x1f\xa7\x26')
        port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                              port_id=b'1/3')
        ttl = lldp.TTL(ttl=120)
        end = lldp.End()
        tlvs = (chassis_id, port_id, ttl, end)
        lldp1 = lldp.lldp(tlvs)
        jsondict = lldp1.to_jsondict()
        lldp2 = lldp.lldp.from_jsondict(jsondict['lldp'])
        eq_(str(lldp1), str(lldp2))


class TestLLDPOptionalTLV(unittest.TestCase):
    def setUp(self):
        # sample data is based on:
        # http://wiki.wireshark.org/LinkLayerDiscoveryProtocol
        #
        # include optional TLV
        self.data = b'\x01\x80\xc2\x00\x00\x0e\x00\x01' \
                    + b'\x30\xf9\xad\xa0\x88\xcc\x02\x07' \
                    + b'\x04\x00\x01\x30\xf9\xad\xa0\x04' \
                    + b'\x04\x05\x31\x2f\x31\x06\x02\x00' \
                    + b'\x78\x08\x17\x53\x75\x6d\x6d\x69' \
                    + b'\x74\x33\x30\x30\x2d\x34\x38\x2d' \
                    + b'\x50\x6f\x72\x74\x20\x31\x30\x30' \
                    + b'\x31\x00\x0a\x0d\x53\x75\x6d\x6d' \
                    + b'\x69\x74\x33\x30\x30\x2d\x34\x38' \
                    + b'\x00\x0c\x4c\x53\x75\x6d\x6d\x69' \
                    + b'\x74\x33\x30\x30\x2d\x34\x38\x20' \
                    + b'\x2d\x20\x56\x65\x72\x73\x69\x6f' \
                    + b'\x6e\x20\x37\x2e\x34\x65\x2e\x31' \
                    + b'\x20\x28\x42\x75\x69\x6c\x64\x20' \
                    + b'\x35\x29\x20\x62\x79\x20\x52\x65' \
                    + b'\x6c\x65\x61\x73\x65\x5f\x4d\x61' \
                    + b'\x73\x74\x65\x72\x20\x30\x35\x2f' \
                    + b'\x32\x37\x2f\x30\x35\x20\x30\x34' \
                    + b'\x3a\x35\x33\x3a\x31\x31\x00\x0e' \
                    + b'\x05\x01\x00\x14\x00\x14\x10\x0e' \
                    + b'\x07' \
                    + b'\x06\x00\x01\x30\xf9\xad\xa0\x02' \
                    + b'\x00\x00\x03\xe9\x00\xfe\x07\x00' \
                    + b'\x12\x0f\x02\x07\x01\x00\xfe\x09' \
                    + b'\x00\x12\x0f\x01\x03\x6c\x00\x00' \
                    + b'\x10\xfe\x09\x00\x12\x0f\x03\x01' \
                    + b'\x00\x00\x00\x00\xfe\x06\x00\x12' \
                    + b'\x0f\x04\x05\xf2\xfe\x06\x00\x80' \
                    + b'\xc2\x01\x01\xe8\xfe\x07\x00\x80' \
                    + b'\xc2\x02\x01\x00\x00\xfe\x17\x00' \
                    + b'\x80\xc2\x03\x01\xe8\x10\x76\x32' \
                    + b'\x2d\x30\x34\x38\x38\x2d\x30\x33' \
                    + b'\x2d\x30\x35\x30\x35\x00\xfe\x05' \
                    + b'\x00\x80\xc2\x04\x00\x00\x00'

    def tearDown(self):
        pass

    def test_parse(self):
        buf = self.data
        pkt = packet.Packet(buf)
        i = iter(pkt)

        eq_(type(next(i)), ethernet.ethernet)
        lldp_pkt = next(i)
        eq_(type(lldp_pkt), lldp.lldp)

        tlvs = lldp_pkt.tlvs

        # Port Description
        eq_(tlvs[3].tlv_type, lldp.LLDP_TLV_PORT_DESCRIPTION)
        eq_(tlvs[3].port_description, b'Summit300-48-Port 1001\x00')

        # System Name
        eq_(tlvs[4].tlv_type, lldp.LLDP_TLV_SYSTEM_NAME)
        eq_(tlvs[4].system_name, b'Summit300-48\x00')

        # System Description

        eq_(tlvs[5].tlv_type, lldp.LLDP_TLV_SYSTEM_DESCRIPTION)
        eq_(tlvs[5].system_description,
            b'Summit300-48 - Version 7.4e.1 (Build 5) '
            + b'by Release_Master 05/27/05 04:53:11\x00')

        # SystemCapabilities
        eq_(tlvs[6].tlv_type, lldp.LLDP_TLV_SYSTEM_CAPABILITIES)
        eq_(tlvs[6].subtype, lldp.ChassisID.SUB_CHASSIS_COMPONENT)
        eq_(tlvs[6].system_cap & lldp.SystemCapabilities.CAP_MAC_BRIDGE,
            lldp.SystemCapabilities.CAP_MAC_BRIDGE)
        eq_(tlvs[6].enabled_cap & lldp.SystemCapabilities.CAP_MAC_BRIDGE,
            lldp.SystemCapabilities.CAP_MAC_BRIDGE)
        eq_(tlvs[6].system_cap & lldp.SystemCapabilities.CAP_TELEPHONE, 0)
        eq_(tlvs[6].enabled_cap & lldp.SystemCapabilities.CAP_TELEPHONE, 0)

        # Management Address
        eq_(tlvs[7].tlv_type, lldp.LLDP_TLV_MANAGEMENT_ADDRESS)
        eq_(tlvs[7].addr_len, 7)
        eq_(tlvs[7].addr, b'\x00\x01\x30\xf9\xad\xa0')
        eq_(tlvs[7].intf_num, 1001)

        # Organizationally Specific
        eq_(tlvs[8].tlv_type, lldp.LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
        eq_(tlvs[8].oui, b'\x00\x12\x0f')  # IEEE 802.3
        eq_(tlvs[8].subtype, 0x02)  # Power Via MDI

        # End
        eq_(tlvs[16].tlv_type, lldp.LLDP_TLV_END)

    def test_parse_corrupted(self):
        buf = self.data
        pkt = packet.Packet(buf[:128])

    def test_serialize(self):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = '00:01:30:f9:ad:a0'
        ethertype = ether.ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                        chassis_id=addrconv.mac.
                                        text_to_bin(src))
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                                  port_id=b'1/1')
        tlv_ttl = lldp.TTL(ttl=120)
        tlv_port_description = lldp.PortDescription(
            port_description=b'Summit300-48-Port 1001\x00')
        tlv_system_name = lldp.SystemName(system_name=b'Summit300-48\x00')
        tlv_system_description = lldp.SystemDescription(
            system_description=b'Summit300-48 - Version 7.4e.1 (Build 5) '
                               + b'by Release_Master 05/27/05 04:53:11\x00')
        tlv_system_capabilities = lldp.SystemCapabilities(
            subtype=lldp.ChassisID.SUB_CHASSIS_COMPONENT,
            system_cap=0x14,
            enabled_cap=0x14)
        tlv_management_address = lldp.ManagementAddress(
            addr_subtype=0x06, addr=b'\x00\x01\x30\xf9\xad\xa0',
            intf_subtype=0x02, intf_num=1001,
            oid=b'')
        tlv_organizationally_specific = lldp.OrganizationallySpecific(
            oui=b'\x00\x12\x0f', subtype=0x02, info=b'\x07\x01\x00')
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_port_description,
                tlv_system_name, tlv_system_description,
                tlv_system_capabilities, tlv_management_address,
                tlv_organizationally_specific, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)

        eq_(len(pkt.protocols), 2)

        pkt.serialize()

        # self.data has many organizationally specific TLVs
        data = six.binary_type(pkt.data[:-2])
        eq_(data, self.data[:len(data)])

    def test_to_string(self):
        chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                    chassis_id=b'\x00\x01\x30\xf9\xad\xa0')
        port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                              port_id=b'1/1')
        ttl = lldp.TTL(ttl=120)
        port_desc = lldp.PortDescription(
            port_description=b'Summit300-48-Port 1001\x00')
        sys_name = lldp.SystemName(system_name=b'Summit300-48\x00')
        sys_desc = lldp.SystemDescription(
            system_description=b'Summit300-48 - Version 7.4e.1 (Build 5) '
                               + b'by Release_Master 05/27/05 04:53:11\x00')
        sys_cap = lldp.SystemCapabilities(
            subtype=lldp.ChassisID.SUB_CHASSIS_COMPONENT,
            system_cap=0x14,
            enabled_cap=0x14)
        man_addr = lldp.ManagementAddress(
            addr_subtype=0x06, addr=b'\x00\x01\x30\xf9\xad\xa0',
            intf_subtype=0x02, intf_num=1001,
            oid='')
        org_spec = lldp.OrganizationallySpecific(
            oui=b'\x00\x12\x0f', subtype=0x02, info=b'\x07\x01\x00')
        end = lldp.End()
        tlvs = (chassis_id, port_id, ttl, port_desc, sys_name,
                sys_desc, sys_cap, man_addr, org_spec, end)
        lldp_pkt = lldp.lldp(tlvs)

        # ChassisID string
        chassis_id_values = {'subtype': lldp.ChassisID.SUB_MAC_ADDRESS,
                             'chassis_id': b'\x00\x01\x30\xf9\xad\xa0',
                             'len': chassis_id.len,
                             'typelen': chassis_id.typelen}
        _ch_id_str = ','.join(['%s=%s' % (k, repr(chassis_id_values[k]))
                               for k, v in inspect.getmembers(chassis_id)
                               if k in chassis_id_values])
        tlv_chassis_id_str = '%s(%s)' % (lldp.ChassisID.__name__, _ch_id_str)

        # PortID string
        port_id_values = {'subtype': port_id.subtype,
                          'port_id': port_id.port_id,
                          'len': port_id.len,
                          'typelen': port_id.typelen}
        _port_id_str = ','.join(['%s=%s' % (k, repr(port_id_values[k]))
                                 for k, v in inspect.getmembers(port_id)
                                 if k in port_id_values])
        tlv_port_id_str = '%s(%s)' % (lldp.PortID.__name__, _port_id_str)

        # TTL string
        ttl_values = {'ttl': ttl.ttl,
                      'len': ttl.len,
                      'typelen': ttl.typelen}
        _ttl_str = ','.join(['%s=%s' % (k, repr(ttl_values[k]))
                             for k, v in inspect.getmembers(ttl)
                             if k in ttl_values])
        tlv_ttl_str = '%s(%s)' % (lldp.TTL.__name__, _ttl_str)

        # PortDescription string
        port_desc_values = {'tlv_info': port_desc.tlv_info,
                            'len': port_desc.len,
                            'typelen': port_desc.typelen}
        _port_desc_str = ','.join(['%s=%s' % (k, repr(port_desc_values[k]))
                                   for k, v in inspect.getmembers(port_desc)
                                   if k in port_desc_values])
        tlv_port_desc_str = '%s(%s)' % (lldp.PortDescription.__name__,
                                        _port_desc_str)

        # SystemName string
        sys_name_values = {'tlv_info': sys_name.tlv_info,
                           'len': sys_name.len,
                           'typelen': sys_name.typelen}
        _system_name_str = ','.join(['%s=%s' % (k, repr(sys_name_values[k]))
                                     for k, v in inspect.getmembers(sys_name)
                                     if k in sys_name_values])
        tlv_system_name_str = '%s(%s)' % (lldp.SystemName.__name__,
                                          _system_name_str)

        # SystemDescription string
        sys_desc_values = {'tlv_info': sys_desc.tlv_info,
                           'len': sys_desc.len,
                           'typelen': sys_desc.typelen}
        _sys_desc_str = ','.join(['%s=%s' % (k, repr(sys_desc_values[k]))
                                  for k, v in inspect.getmembers(sys_desc)
                                  if k in sys_desc_values])
        tlv_sys_desc_str = '%s(%s)' % (lldp.SystemDescription.__name__,
                                       _sys_desc_str)

        # SystemCapabilities string
        sys_cap_values = {'subtype': lldp.ChassisID.SUB_CHASSIS_COMPONENT,
                          'system_cap': 0x14,
                          'enabled_cap': 0x14,
                          'len': sys_cap.len,
                          'typelen': sys_cap.typelen}
        _sys_cap_str = ','.join(['%s=%s' % (k, repr(sys_cap_values[k]))
                                 for k, v in inspect.getmembers(sys_cap)
                                 if k in sys_cap_values])
        tlv_sys_cap_str = '%s(%s)' % (lldp.SystemCapabilities.__name__,
                                      _sys_cap_str)

        # ManagementAddress string
        man_addr_values = {'addr_subtype': 0x06,
                           'addr': b'\x00\x01\x30\xf9\xad\xa0',
                           'addr_len': man_addr.addr_len,
                           'intf_subtype': 0x02,
                           'intf_num': 1001,
                           'oid': '',
                           'oid_len': man_addr.oid_len,
                           'len': man_addr.len,
                           'typelen': man_addr.typelen}
        _man_addr_str = ','.join(['%s=%s' % (k, repr(man_addr_values[k]))
                                  for k, v in inspect.getmembers(man_addr)
                                  if k in man_addr_values])
        tlv_man_addr_str = '%s(%s)' % (lldp.ManagementAddress.__name__,
                                       _man_addr_str)

        # OrganizationallySpecific string
        org_spec_values = {'oui': b'\x00\x12\x0f',
                           'subtype': 0x02,
                           'info': b'\x07\x01\x00',
                           'len': org_spec.len,
                           'typelen': org_spec.typelen}
        _org_spec_str = ','.join(['%s=%s' % (k, repr(org_spec_values[k]))
                                  for k, v in inspect.getmembers(org_spec)
                                  if k in org_spec_values])
        tlv_org_spec_str = '%s(%s)' % (lldp.OrganizationallySpecific.__name__,
                                       _org_spec_str)

        # End string
        end_values = {'len': end.len,
                      'typelen': end.typelen}
        _end_str = ','.join(['%s=%s' % (k, repr(end_values[k]))
                             for k, v in inspect.getmembers(end)
                             if k in end_values])
        tlv_end_str = '%s(%s)' % (lldp.End.__name__, _end_str)

        # tlvs string
        _tlvs_str = '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
        tlvs_str = _tlvs_str % (tlv_chassis_id_str,
                                tlv_port_id_str,
                                tlv_ttl_str,
                                tlv_port_desc_str,
                                tlv_system_name_str,
                                tlv_sys_desc_str,
                                tlv_sys_cap_str,
                                tlv_man_addr_str,
                                tlv_org_spec_str,
                                tlv_end_str)

        # lldp string
        _lldp_str = '%s(tlvs=%s)'
        lldp_str = _lldp_str % (lldp.lldp.__name__,
                                tlvs_str)

        eq_(str(lldp_pkt), lldp_str)
        eq_(repr(lldp_pkt), lldp_str)

    def test_json(self):
        chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                    chassis_id=b'\x00\x01\x30\xf9\xad\xa0')
        port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                              port_id=b'1/1')
        ttl = lldp.TTL(ttl=120)
        port_desc = lldp.PortDescription(
            port_description=b'Summit300-48-Port 1001\x00')
        sys_name = lldp.SystemName(system_name=b'Summit300-48\x00')
        sys_desc = lldp.SystemDescription(
            system_description=b'Summit300-48 - Version 7.4e.1 (Build 5) '
                               + b'by Release_Master 05/27/05 04:53:11\x00')
        sys_cap = lldp.SystemCapabilities(
            subtype=lldp.ChassisID.SUB_CHASSIS_COMPONENT,
            system_cap=0x14,
            enabled_cap=0x14)
        man_addr = lldp.ManagementAddress(
            addr_subtype=0x06, addr=b'\x00\x01\x30\xf9\xad\xa0',
            intf_subtype=0x02, intf_num=1001,
            oid='')
        org_spec = lldp.OrganizationallySpecific(
            oui=b'\x00\x12\x0f', subtype=0x02, info=b'\x07\x01\x00')
        end = lldp.End()
        tlvs = (chassis_id, port_id, ttl, port_desc, sys_name,
                sys_desc, sys_cap, man_addr, org_spec, end)
        lldp1 = lldp.lldp(tlvs)
        jsondict = lldp1.to_jsondict()
        lldp2 = lldp.lldp.from_jsondict(jsondict['lldp'])
        eq_(str(lldp1), str(lldp2))
