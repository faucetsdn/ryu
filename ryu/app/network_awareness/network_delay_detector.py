# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
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

from __future__ import division
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology.switches import Switches
from ryu.topology.switches import LLDPPacket
import networkx as nx
import time
import setting


CONF = cfg.CONF


class NetworkDelayDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkDelayDetector, self).__init__(*args, **kwargs)
        self.name = 'delaydetector'
        self.sw_module = lookup_service_brick('switches')
        self.awareness = lookup_service_brick('awareness')

        self.datapaths = {}
        self.echo_latency = {}
        self.measure_thread = hub.spawn(self._detector)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _detector(self):
        while CONF.weight == 'delay':
            self.create_link_delay()
            try:
                self.awareness.shortest_paths = {}
                self.logger.debug("Refresh the shortest_paths")
            except:
                self.awareness = lookup_service_brick('awareness')

            self.show_delay_statis()
            self._send_echo_request()
            hub.sleep(setting.DELAY_DETECTING_PERIOD)

    def _send_echo_request(self):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            data = "%.6f" % time.time()
            echo_req = parser.OFPEchoRequest(datapath, data=data)
            datapath.send_msg(echo_req)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        try:
            latency = time.time() - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = latency
        except:
            return

    def get_dalay(self, src, dst):
        try:
            fwd_delay = self.awareness.graph[src][dst]['lldpdelay']
            re_delay = self.awareness.graph[dst][src]['lldpdelay']
            src_latency = self.echo_latency[src]
            dst_latency = self.echo_latency[dst]

            delay = (fwd_delay + re_delay - src_latency - dst_latency)/2
            return max(delay, 0)
        except:
            return float('inf')

    def _save_lldp_delay(self, src=0, dst=0, lldpdelay=0):
        try:
            self.awareness.graph[src][dst]['lldpdelay'] = lldpdelay
        except:
            if self.awareness is None:
                self.awareness = lookup_service_brick('awareness')
            return

    def create_link_delay(self):
        try:
            for src in self.awareness.graph:
                for dst in self.awareness.graph[src]:
                    if src == dst:
                        self.awareness.graph[src][dst]['delay'] = 0
                        continue
                    delay = self.get_dalay(src, dst)
                    self.awareness.graph[src][dst]['delay'] = delay
        except:
            if self.awareness is None:
                self.awareness = lookup_service_brick('awareness')
            return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
            dpid = msg.datapath.id
            in_port = msg.match['in_port']
            if self.sw_module is None:
                self.sw_module = lookup_service_brick('switches')

            for port in self.sw_module.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    port_data = self.sw_module.ports[port]
                    timestamp = port_data.timestamp
                    if timestamp:
                        delay = time.time() - timestamp
                        self._save_lldp_delay(src=src_dpid, dst=dpid,
                                              lldpdelay=delay)
        except LLDPPacket.LLDPUnknownFormat as e:
            return

    def show_delay_statis(self):
        if setting.TOSHOW and self.awareness is not None:
            self.logger.info("\nsrc   dst      delay")
            self.logger.info("---------------------------")
            for src in self.awareness.graph:
                for dst in self.awareness.graph[src]:
                    delay = self.awareness.graph[src][dst]['delay']
                    self.logger.info("%s<-->%s : %s" % (src, dst, delay))
