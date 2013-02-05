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
import struct
from nose.tools import ok_, eq_, nottest

from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import lldp

LOG = logging.getLogger(__name__)


class TestLLDPMandatoryTLV(unittest.TestCase):
    def setUp(self):
        # sample data is based on:
        # http://wiki.wireshark.org/LinkLayerDiscoveryProtocol
        #
        # mandatory TLV only
        self.data = '\x01\x80\xc2\x00\x00\x0e\x00\x04' \
                    + '\x96\x1f\xa7\x26\x88\xcc\x02\x07' \
                    + '\x04\x00\x04\x96\x1f\xa7\x26\x04' \
                    + '\x04\x05\x31\x2f\x33\x06\x02\x00' \
                    + '\x78\x00\x00'

    def tearDown(self):
        pass

    def test_get_tlv_type(self):
        buf = str(bytearray('\x02\x07\x04\x00\x04\x96\x1f\xa7\x26'))
        eq_(lldp.LLDPBasicTLV.get_type(buf), lldp.LLDP_TLV_CHASSIS_ID)

    def test_parse_without_ethernet(self):
        buf = self.data[ethernet.ethernet._MIN_LEN:]
        (lldp_pkt, cls) = lldp.lldp.parser(buf)
        eq_(lldp_pkt.length, len(buf))

        tlvs = lldp_pkt.tlvs
        eq_(tlvs[0].tlv_type, lldp.LLDP_TLV_CHASSIS_ID)
        eq_(tlvs[0].len, 7)
        eq_(tlvs[0].subtype, lldp.ChassisID.SUB_MAC_ADDRESS)
        eq_(tlvs[0].chassis_id, '\x00\x04\x96\x1f\xa7\x26')
        eq_(tlvs[1].tlv_type, lldp.LLDP_TLV_PORT_ID)
        eq_(tlvs[1].len, 4)
        eq_(tlvs[1].subtype, lldp.PortID.SUB_INTERFACE_NAME)
        eq_(tlvs[1].port_id, '1/3')
        eq_(tlvs[2].tlv_type, lldp.LLDP_TLV_TTL)
        eq_(tlvs[2].len, 2)
        eq_(tlvs[2].ttl, 120)
        eq_(tlvs[3].tlv_type, lldp.LLDP_TLV_END)

    def test_parse(self):
        buf = self.data
        pkt = packet.Packet(buf)

        eq_(type(pkt.next()), ethernet.ethernet)
        eq_(type(pkt.next()), lldp.lldp)

    def test_tlv(self):
        tlv = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                             chassis_id='\x00\x04\x96\x1f\xa7\x26')
        eq_(tlv.tlv_type, lldp.LLDP_TLV_CHASSIS_ID)
        eq_(tlv.len, 7)
        (typelen, ) = struct.unpack('!H', '\x02\x07')
        eq_(tlv.typelen, typelen)

    def test_serialize_without_ethernet(self):
        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                        chassis_id='\x00\x04\x96\x1f\xa7\x26')
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                                  port_id='1/3')
        tlv_ttl = lldp.TTL(ttl=120)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)

        eq_(lldp_pkt.serialize(None, None),
            self.data[ethernet.ethernet._MIN_LEN:])

    def test_serialize(self):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = '\x00\x04\x96\x1f\xa7\x26'
        ethertype = ether.ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                        chassis_id=src)
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                                  port_id='1/3')
        tlv_ttl = lldp.TTL(ttl=120)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)

        eq_(len(pkt.protocols), 2)

        pkt.serialize()
        eq_(pkt.data, self.data)


class TestLLDPOptionalTLV(unittest.TestCase):
    def setUp(self):
        # sample data is based on:
        # http://wiki.wireshark.org/LinkLayerDiscoveryProtocol
        #
        # include optional TLV
        self.data = '\x01\x80\xc2\x00\x00\x0e\x00\x01' \
                    + '\x30\xf9\xad\xa0\x88\xcc\x02\x07' \
                    + '\x04\x00\x01\x30\xf9\xad\xa0\x04' \
                    + '\x04\x05\x31\x2f\x31\x06\x02\x00' \
                    + '\x78\x08\x17\x53\x75\x6d\x6d\x69' \
                    + '\x74\x33\x30\x30\x2d\x34\x38\x2d' \
                    + '\x50\x6f\x72\x74\x20\x31\x30\x30' \
                    + '\x31\x00\x0a\x0d\x53\x75\x6d\x6d' \
                    + '\x69\x74\x33\x30\x30\x2d\x34\x38' \
                    + '\x00\x0c\x4c\x53\x75\x6d\x6d\x69' \
                    + '\x74\x33\x30\x30\x2d\x34\x38\x20' \
                    + '\x2d\x20\x56\x65\x72\x73\x69\x6f' \
                    + '\x6e\x20\x37\x2e\x34\x65\x2e\x31' \
                    + '\x20\x28\x42\x75\x69\x6c\x64\x20' \
                    + '\x35\x29\x20\x62\x79\x20\x52\x65' \
                    + '\x6c\x65\x61\x73\x65\x5f\x4d\x61' \
                    + '\x73\x74\x65\x72\x20\x30\x35\x2f' \
                    + '\x32\x37\x2f\x30\x35\x20\x30\x34' \
                    + '\x3a\x35\x33\x3a\x31\x31\x00\x0e' \
                    + '\x05\x01\x00\x14\x00\x14\x10\x0e' \
                    + '\x07' \
                    + '\x06\x00\x01\x30\xf9\xad\xa0\x02' \
                    + '\x00\x00\x03\xe9\x00\xfe\x07\x00' \
                    + '\x12\x0f\x02\x07\x01\x00\xfe\x09' \
                    + '\x00\x12\x0f\x01\x03\x6c\x00\x00' \
                    + '\x10\xfe\x09\x00\x12\x0f\x03\x01' \
                    + '\x00\x00\x00\x00\xfe\x06\x00\x12' \
                    + '\x0f\x04\x05\xf2\xfe\x06\x00\x80' \
                    + '\xc2\x01\x01\xe8\xfe\x07\x00\x80' \
                    + '\xc2\x02\x01\x00\x00\xfe\x17\x00' \
                    + '\x80\xc2\x03\x01\xe8\x10\x76\x32' \
                    + '\x2d\x30\x34\x38\x38\x2d\x30\x33' \
                    + '\x2d\x30\x35\x30\x35\x00\xfe\x05' \
                    + '\x00\x80\xc2\x04\x00\x00\x00'

    def tearDown(self):
        pass

    def test_parse(self):
        buf = self.data
        pkt = packet.Packet(buf)

        eq_(type(pkt.next()), ethernet.ethernet)
        lldp_pkt = pkt.next()
        eq_(type(lldp_pkt), lldp.lldp)
        eq_(lldp_pkt.length, len(buf) - ethernet.ethernet._MIN_LEN)

        tlvs = lldp_pkt.tlvs

        # Port Description
        eq_(tlvs[3].tlv_type, lldp.LLDP_TLV_PORT_DESCRIPTION)
        eq_(tlvs[3].port_description, 'Summit300-48-Port 1001\x00')

        # System Name
        eq_(tlvs[4].tlv_type, lldp.LLDP_TLV_SYSTEM_NAME)
        eq_(tlvs[4].system_name, 'Summit300-48\x00')

        # System Description

        eq_(tlvs[5].tlv_type, lldp.LLDP_TLV_SYSTEM_DESCRIPTION)
        eq_(tlvs[5].system_description,
            'Summit300-48 - Version 7.4e.1 (Build 5) '
            + 'by Release_Master 05/27/05 04:53:11\x00')

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
        eq_(tlvs[7].addr, '\x00\x01\x30\xf9\xad\xa0')
        eq_(tlvs[7].intf_num, 1001)

        # Organizationally Specific
        eq_(tlvs[8].tlv_type, lldp.LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
        eq_(tlvs[8].oui, '\x00\x12\x0f')  # IEEE 802.3
        eq_(tlvs[8].subtype, 0x02)  # Power Via MDI

        # End
        eq_(tlvs[16].tlv_type, lldp.LLDP_TLV_END)

    def test_serialize(self):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = '\x00\x01\x30\xf9\xad\xa0'
        ethertype = ether.ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
                                        chassis_id=src)
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME,
                                  port_id='1/1')
        tlv_ttl = lldp.TTL(ttl=120)
        tlv_port_description = lldp.PortDescription(
            port_description='Summit300-48-Port 1001\x00')
        tlv_system_name = lldp.SystemName(system_name='Summit300-48\x00')
        tlv_system_description = lldp.SystemDescription(
            system_description='Summit300-48 - Version 7.4e.1 (Build 5) '
                               + 'by Release_Master 05/27/05 04:53:11\x00')
        tlv_system_capabilities = lldp.SystemCapabilities(
            subtype=lldp.ChassisID.SUB_CHASSIS_COMPONENT,
            system_cap=0x14,
            enabled_cap=0x14)
        tlv_management_address = lldp.ManagementAddress(
            addr_subtype=0x06, addr='\x00\x01\x30\xf9\xad\xa0',
            intf_subtype=0x02, intf_num=1001,
            oid='')
        tlv_organizationally_specific = lldp.OrganizationallySpecific(
            oui='\x00\x12\x0f', subtype=0x02, info='\x07\x01\x00')
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
        data = str(pkt.data[:-2])
        eq_(data, self.data[:len(data)])
