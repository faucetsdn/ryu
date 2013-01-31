# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

NETFLOW_V1 = 0x01
NETFLOW_V5 = 0x05
NETFLOW_V6 = 0x06
NETFLOW_V7 = 0x07
NETFLOW_V8 = 0x08
NETFLOW_V9 = 0x09


class NetFlow(object):
    _PACK_STR = '!H'
    _NETFLOW_VERSIONS = {}

    @staticmethod
    def register_netflow_version(version):
        def _register_netflow_version(cls):
            NetFlow._NETFLOW_VERSIONS[version] = cls
            return cls
        return _register_netflow_version

    def __init__(self):
        super(NetFlow, self).__init__()

    @classmethod
    def parser(cls, buf):
        (version,) = struct.unpack_from(cls._PACK_STR, buf)

        cls_ = cls._NETFLOW_VERSIONS.get(version, None)
        if cls_:
            return cls_.parser(buf)
        else:
            return None


@NetFlow.register_netflow_version(NETFLOW_V5)
class NetFlowV5(object):
    _PACK_STR = '!HHIIIIBBH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, version, count, sys_uptime, unix_secs,
                 unix_nsecs, flow_sequence, engine_type, engine_id,
                 sampling_interval, flows=None):
        self.version = version
        self.count = count
        self.sys_uptime = sys_uptime
        self.unix_secs = unix_secs
        self.unix_nsecs = unix_nsecs
        self.flow_sequence = flow_sequence
        self.engine_type = engine_type
        self.engine_id = engine_id
        self.sampling_interval = sampling_interval

    @classmethod
    def parser(cls, buf):
        (version, count, sys_uptime, unix_secs, unix_nsecs,
         flow_sequence, engine_type, engine_id, sampling_interval) = \
            struct.unpack_from(cls._PACK_STR, buf)

        msg = cls(version, count, sys_uptime, unix_secs, unix_nsecs,
                  flow_sequence, engine_type, engine_id,
                  sampling_interval)
        offset = cls._MIN_LEN
        msg.flows = []
        while len(buf) > offset:
            f = NetFlowV5Flow.parser(buf, offset)
            offset += NetFlowV5Flow._MIN_LEN
            msg.flows.append(f)

        return msg


class NetFlowV5Flow(object):
    _PACK_STR = '!IIIHHIIIIHHxBBBHHBB2x'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, srcaddr, dstaddr, nexthop, input_, output,
                 dpkts, doctets, first, last, srcport, dstport,
                 tcp_flags, prot, tos, src_as, dst_as, src_mask,
                 dst_mask):
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr
        self.nexthop = nexthop
        self.input = input_
        self.output = output
        self.dpkts = dpkts
        self.doctets = doctets
        self.first = first
        self.last = last
        self.srcport = srcport
        self.dstport = dstport
        self.tcp_flags = tcp_flags
        self.prot = prot
        self.tos = tos
        self.src_as = src_as
        self.dst_as = dst_as
        self.src_mask = src_mask
        self.dst_mask = dst_mask

    @classmethod
    def parser(cls, buf, offset):
        (srcaddr, dstaddr, nexthop, input_, output, dpkts, doctets,
         first, last, srcport, dstport, tcp_flags, prot, tos, src_as,
         dst_as, src_mask, dst_mask) = struct.unpack_from(
             cls._PACK_STR, buf, offset)
        msg = cls(srcaddr, dstaddr, nexthop, input_, output, dpkts,
                  doctets, first, last, srcport, dstport, tcp_flags,
                  prot, tos, src_as, dst_as, src_mask, dst_mask)

        return msg
