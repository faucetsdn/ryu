from __future__ import division
from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


class SimpleMonitor(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.sleep = 2

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _save_stats(self, dist, key, value, length):
        if key not in dist:
                dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
        return (now-pre)/period/8

    def _get_time(self, sec, nsec):
        return sec + nsec/(10**9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # self.logger.info('datapath         '
        #                  'in-port  eth-dst           '
        #                  'out-port packets  bytes')
        # self.logger.info('---------------- '
        #                  '-------- ----------------- '
        #                  '-------- -------- --------')

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            # self.logger.info('%016x %8x %17s %8x %8d %8d',
            #                  ev.msg.datapath.id,
            #                  stat.match['in_port'], stat.match['eth_dst'],
            #                  stat.instructions[0].actions[0].port,
            #                  stat.packet_count, stat.byte_count)

            key = (
                stat.match['in_port'], stat.match['eth_dst'],
                stat.instructions[0].actions[0].port,)
            value = (
                stat.packet_count, stat.byte_count,
                stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats, key, value, 5)

            # Get flow's speed.
            pre = 0
            period = self.sleep
            tmp = self.flow_stats[key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(
                    tmp[-1][2], tmp[-1][3],
                    tmp[-2][2], tmp[-2][3])
                # print "flow period: ", period

            speed = self._get_speed(
                self.flow_stats[key][-1][1], pre, period)

            self._save_stats(self.flow_speed, key, speed, 5)
            print '\n Flow Speed:\n', self.flow_speed

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        # self.logger.info('datapath         port     '
        #                 'rx-pkts  rx-bytes rx-error '
        #                 'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                 '-------- -------- -------- '
        #                 '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            # self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
            #                  ev.msg.datapath.id, stat.port_no,
            #                  stat.rx_packets, stat.rx_bytes, stat.rx_errors,
            #                  stat.tx_packets, stat.tx_bytes, stat.tx_errors)

            key = (ev.msg.datapath.id, stat.port_no)
            value = (
                stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                stat.duration_sec, stat.duration_nsec)

            self._save_stats(self.port_stats, key, value, 5)

            # Get port speed.
            pre = 0
            period = self.sleep
            tmp = self.port_stats[key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(
                    tmp[-1][3], tmp[-1][4],
                    tmp[-2][3], tmp[-2][4])

            speed = self._get_speed(
                self.port_stats[key][-1][1], pre, period)

            self._save_stats(self.port_speed, key, speed, 5)
            print '\n Speed:\n', self.port_speed
