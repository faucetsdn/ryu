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

import struct
import logging

SFLOW_V2 = 0x00000002
SFLOW_V3 = 0x00000003
SFLOW_V4 = 0x00000004
SFLOW_V5 = 0x00000005

LOG = logging.getLogger('ryu.lib.xflow.sflow')


class sFlow(object):
    _PACK_STR = '!i'
    _SFLOW_VERSIONS = {}

    @staticmethod
    def register_sflow_version(version):
        def _register_sflow_version(cls):
            sFlow._SFLOW_VERSIONS[version] = cls
            return cls
        return _register_sflow_version

    def __init__(self):
        super(sFlow, self).__init__()

    @classmethod
    def parser(cls, buf):
        (version,) = struct.unpack_from(cls._PACK_STR, buf)

        cls_ = cls._SFLOW_VERSIONS.get(version, None)
        if cls_:
            return cls_.parser(buf)
        else:
            return None


@sFlow.register_sflow_version(SFLOW_V5)
class sFlowV5(object):
    _PACK_STR = '!ii'
    _PACK_STR_IPV4 = '!iiIIIII'
    _PACK_STR_IPV6 = '!ii4IIIII'
    _AGENT_IPTYPE_V4 = 1
    _AGENT_IPTYPE_V6 = 2
    _MIN_LEN_V4 = struct.calcsize(_PACK_STR_IPV4)
    _MIN_LEN_V6 = struct.calcsize(_PACK_STR_IPV6)

    def __init__(self, version, address_type, agent_address, sub_agent_id,
                 sequence_number, uptime, samples_num, samples):
        super(sFlowV5, self).__init__()
        self.version = version
        self.address_type = address_type
        self.agent_address = agent_address
        self.sub_agent_id = sub_agent_id
        self.sequence_number = sequence_number
        self.uptime = uptime
        self.samples_num = samples_num
        self.samples = samples

    @classmethod
    def parser(cls, buf):
        (version, address_type) = struct.unpack_from(cls._PACK_STR, buf)

        if address_type == cls._AGENT_IPTYPE_V4:
            pack_str = cls._PACK_STR_IPV4
            min_len = cls._MIN_LEN_V4
        elif address_type == cls._AGENT_IPTYPE_V6:
            pack_str = cls._PACK_STR_IPV6
            min_len = cls._MIN_LEN_V6
        else:
            LOG.info("Unknown address_type. sFlowV5.address_type=%d"
                     % address_type)
            return None

        (version, address_type, agent_address, sub_agent_id, sequence_number,
         uptime, samples_num) = struct.unpack_from(pack_str, buf)
        offset = min_len

        samples = []

        while len(buf) > offset:
            sample = sFlowV5Sample.parser(buf, offset)
            offset += sFlowV5Sample.MIN_LEN + sample.sample_length
            samples.append(sample)

        msg = cls(version, address_type, agent_address, sub_agent_id,
                  sequence_number, uptime, samples_num, samples)

        return msg


class sFlowV5Sample(object):
    _PACK_STR = '!II'
    MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, enterprise, sample_format, sample_length, sample):
        super(sFlowV5Sample, self).__init__()
        self.enterprise = enterprise
        self.sample_format = sample_format
        self.sample_length = sample_length
        self.sample = sample

    @classmethod
    def parser(cls, buf, offset):
        (sampledata_format,
         sample_length) = struct.unpack_from(cls._PACK_STR, buf, offset)

        format_mask = 0xfff
        enterprise_shiftbit = 12

        sample_format = sampledata_format & format_mask
        enterprise = sampledata_format >> enterprise_shiftbit

        offset += cls.MIN_LEN

        if sample_format == 1:
            # Flow Sample
            sample = sFlowV5FlowSample.parser(buf, offset)
        elif sample_format == 2:
            # Counter Sample
            sample = sFlowV5CounterSample.parser(buf, offset)
        else:
            #TODO:
            # sample_format == 3    : Expanded Flow Sample
            # sample_format == 4    : Expanded Counter Sample
            LOG.info("Unknown format. sFlowV5Sample.sample_format=%d"
                     % sample_format)
            pack_str = '!%sc' % sample_length
            sample = struct.unpack_from(pack_str, buf, offset)

        msg = cls(enterprise, sample_format, sample_length, sample)

        return msg


class sFlowV5FlowSample(object):
    _PACK_STR = '!IIIIIIII'

    def __init__(self, sequence_number, source_id_type, source_id_index,
                 sampling_rate, sample_pool, drops, input_if, output_if,
                 flow_records_num, flow_records):
        super(sFlowV5FlowSample, self).__init__()
        self.sequence_number = sequence_number
        self.source_id_type = source_id_type
        self.source_id_index = source_id_index
        self.sampling_rate = sampling_rate
        self.sample_pool = sample_pool
        self.drops = drops
        self.input_if = input_if
        self.output_if = output_if
        self.flow_records_num = flow_records_num
        self.flow_records = flow_records

    @classmethod
    def parser(cls, buf, offset):
        (sequence_number, source_id, sampling_rate,
         sample_pool, drops, input_if, output_if,
         flow_records_num) = struct.unpack_from(cls._PACK_STR, buf, offset)

        index_mask = 0xffffff
        type_shiftbit = 24

        source_id_index = source_id & index_mask
        source_id_type = source_id >> type_shiftbit

        offset += struct.calcsize(cls._PACK_STR)

        flow_records = []

        for i in range(flow_records_num):
            flow_record = sFlowV5FlowRecord.parser(buf, offset)
            offset += sFlowV5FlowRecord.MIN_LEN + flow_record.flow_data_length
            flow_records.append(flow_record)

        msg = cls(sequence_number, source_id_type, source_id_index,
                  sampling_rate, sample_pool, drops, input_if, output_if,
                  flow_records_num, flow_records)

        return msg


class sFlowV5FlowRecord(object):
    _PACK_STR = '!II'
    MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, enterprise, flow_data_format,
                 flow_data_length, flow_data):
        super(sFlowV5FlowRecord, self).__init__()
        self.enterprise = enterprise
        self.flow_data_format = flow_data_format
        self.flow_data_length = flow_data_length
        self.flow_data = flow_data

    @classmethod
    def parser(cls, buf, offset):
        (flowdata_format,
         flow_data_length) = struct.unpack_from(cls._PACK_STR, buf, offset)

        format_mask = 0xfff
        enterprise_shiftbit = 12

        flow_data_format = flowdata_format & format_mask
        enterprise = flowdata_format >> enterprise_shiftbit

        offset += cls.MIN_LEN

        if flow_data_format == 1:
            # Raw Packet Header
            flow_data = sFlowV5RawPacketHeader.parser(buf, offset)
        elif flow_data_format == 1001:
            # Extended Switch Data
            flow_data = sFlowV5ExtendedSwitchData.parser(buf, offset)
        else:
            #TODO:
            # flow_data_format == 2    : Ethernet Frame Data
            # flow_data_format == 3    : IPv4 Data
            # flow_data_format == 4    : IPv6 Data
            # flow_data_format == 1002 : Extended Router Data
            # flow_data_format == 1003 : Extended Gateway Data
            # flow_data_format == 1004 : Extended User Data
            # flow_data_format == 1005 : Extended Url Data
            # flow_data_format == 1006 : Extended MPLS Data
            # flow_data_format == 1007 : Extended NAT Data
            # flow_data_format == 1008 : Extended MPLS Tunnel
            # flow_data_format == 1009 : Extended MPLS VC
            # flow_data_format == 1010 : Extended MPLS FEC
            # flow_data_format == 1011 : Extended MPLS LVP FEC
            # flow_data_format == 1012 : Extended VLAN tunnel
            LOG.info("Unknown format. sFlowV5FlowRecord.flow_data_format=%d"
                     % flow_data_format)
            pack_str = '!%sc' % flow_data_length
            flow_data = struct.unpack_from(pack_str, buf, offset)

        msg = cls(enterprise, flow_data_format, flow_data_length, flow_data)

        return msg


class sFlowV5RawPacketHeader(object):
    _PACK_STR = '!iIII'

    def __init__(self, header_protocol, frame_length, stripped,
                 header_size, header):
        super(sFlowV5RawPacketHeader, self).__init__()
        self.header_protocol = header_protocol
        self.frame_length = frame_length
        self.stripped = stripped
        self.header_size = header_size
        self.header = header

    @classmethod
    def parser(cls, buf, offset):
        (header_protocol, frame_length, stripped,
         header_size) = struct.unpack_from(cls._PACK_STR, buf, offset)

        offset += struct.calcsize(cls._PACK_STR)

        header_pack_str = '!%sc' % header_size
        header = struct.unpack_from(header_pack_str, buf, offset)

        msg = cls(header_protocol, frame_length, stripped, header_size, header)
        return msg


class sFlowV5ExtendedSwitchData(object):
    _PACK_STR = '!IIII'

    def __init__(self, src_vlan, src_priority, dest_vlan, dest_priority):
        super(sFlowV5ExtendedSwitchData, self).__init__()
        self.src_vlan = src_vlan
        self.src_priority = src_priority
        self.dest_vlan = dest_vlan
        self.dest_priority = dest_priority

    @classmethod
    def parser(cls, buf, offset):
        (src_vlan, src_priority, dest_vlan,
         dest_priority) = struct.unpack_from(cls._PACK_STR, buf, offset)

        msg = cls(src_vlan, src_priority, dest_vlan, dest_priority)
        return msg


class sFlowV5CounterSample(object):
    _PACK_STR = '!III'

    def __init__(self, sequence_number, source_id_type, source_id_index,
                 counters_records_num, counters_records):
        super(sFlowV5CounterSample, self).__init__()
        self.sequence_number = sequence_number
        self.source_id_type = source_id_type
        self.source_id_index = source_id_index
        self.counters_records_num = counters_records_num
        self.counters_records = counters_records

    @classmethod
    def parser(cls, buf, offset):
        (sequence_number, source_id,
         counters_records_num) = struct.unpack_from(cls._PACK_STR, buf, offset)

        index_mask = 0xffffff
        type_shiftbit = 24

        source_id_index = source_id & index_mask
        source_id_type = source_id >> type_shiftbit

        offset += struct.calcsize(cls._PACK_STR)

        counters_records = []

        for i in range(counters_records_num):
            counter_record = sFlowV5CounterRecord.parser(buf, offset)
            offset += sFlowV5CounterRecord.MIN_LEN
            offset += counter_record.counter_data_length
            counters_records.append(counter_record)

        msg = cls(sequence_number, source_id_type, source_id_index,
                  counters_records_num, counters_records)

        return msg


class sFlowV5CounterRecord(object):
    _PACK_STR = '!II'
    MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, enterprise, counter_data_format,
                 counter_data_length, counter_data):
        super(sFlowV5CounterRecord, self).__init__()
        self.enterprise = enterprise
        self.counter_data_format = counter_data_format
        self.counter_data_length = counter_data_length
        self.counter_data = counter_data

    @classmethod
    def parser(cls, buf, offset):
        (counterdata_format,
         counter_data_length) = struct.unpack_from(cls._PACK_STR, buf, offset)

        format_mask = 0xfff
        enterprise_shiftbit = 12

        counter_data_format = counterdata_format & format_mask
        enterprise = counterdata_format >> enterprise_shiftbit

        offset += cls.MIN_LEN

        if counter_data_format == 1:
            # Generic Interface Counters
            counter_data = sFlowV5GenericInterfaceCounters.parser(buf, offset)
        else:
            #TODO:
            # counter_data_format == 2    : Ethernet Interface Counters
            # counter_data_format == 3    : Token Ring Counters
            # counter_data_format == 4    : 100 BaseVG Interface Counters
            # counter_data_format == 5    : VLAN Counters
            # counter_data_format == 1001 : Processor Information
            LOG.info("Unknown format. " +
                     "sFlowV5CounterRecord.counter_data_format=%d"
                     % counter_data_format)
            pack_str = '!%sc' % counter_data_length
            counter_data = struct.unpack_from(pack_str, buf, offset)

        msg = cls(enterprise, counter_data_format,
                  counter_data_length, counter_data)

        return msg


class sFlowV5GenericInterfaceCounters(object):
    _PACK_STR = '!IIQIIQIIIIIIQIIIIII'

    def __init__(self, ifIndex, ifType, ifSpeed, ifDirection,
                 ifAdminStatus, ifOperStatus, ifInOctets, ifInUcastPkts,
                 ifInMulticastPkts, ifInBroadcastPkts, ifInDiscards,
                 ifInErrors, ifInUnknownProtos, ifOutOctets,
                 ifOutUcastPkts, ifOutMulticastPkts, ifOutBroadcastPkts,
                 ifOutDiscards, ifOutErrors, ifPromiscuousMode):
        super(sFlowV5GenericInterfaceCounters, self).__init__()
        self.ifIndex = ifIndex
        self.ifType = ifType
        self.ifSpeed = ifSpeed
        self.ifDirection = ifDirection
        self.ifAdminStatus = ifAdminStatus
        self.ifOperStatus = ifOperStatus
        self.ifInOctets = ifInOctets
        self.ifInUcastPkts = ifInUcastPkts
        self.ifInMulticastPkts = ifInMulticastPkts
        self.ifInBroadcastPkts = ifInBroadcastPkts
        self.ifInDiscards = ifInDiscards
        self.ifInErrors = ifInErrors
        self.ifInUnknownProtos = ifInUnknownProtos
        self.ifOutOctets = ifOutOctets
        self.ifOutUcastPkts = ifOutUcastPkts
        self.ifOutMulticastPkts = ifOutMulticastPkts
        self.ifOutBroadcastPkts = ifOutBroadcastPkts
        self.ifOutDiscards = ifOutDiscards
        self.ifOutErrors = ifOutErrors
        self.ifPromiscuousMode = ifPromiscuousMode

    @classmethod
    def parser(cls, buf, offset):
        (ifIndex, ifType, ifSpeed, ifDirection, ifStatus, ifInOctets,
         ifInUcastPkts, ifInMulticastPkts, ifInBroadcastPkts, ifInDiscards,
         ifInErrors, ifInUnknownProtos, ifOutOctets, ifOutUcastPkts,
         ifOutMulticastPkts, ifOutBroadcastPkts, ifOutDiscards, ifOutErrors,
         ifPromiscuousMode,) = struct.unpack_from(cls._PACK_STR, buf, offset)

        ifStatus_mask = 0x1
        ifAdminStatus_shiftbit = 1

        ifOperStatus = ifStatus & ifStatus_mask
        ifAdminStatus = ifStatus >> ifAdminStatus_shiftbit & ifStatus_mask

        msg = cls(ifIndex, ifType, ifSpeed, ifDirection, ifAdminStatus,
                  ifOperStatus, ifInOctets, ifInUcastPkts,
                  ifInMulticastPkts, ifInBroadcastPkts, ifInDiscards,
                  ifInErrors, ifInUnknownProtos, ifOutOctets,
                  ifOutUcastPkts, ifOutMulticastPkts, ifOutBroadcastPkts,
                  ifOutDiscards, ifOutErrors, ifPromiscuousMode)

        return msg
