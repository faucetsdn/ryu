import unittest
import logging
import socket
from nose.tools import eq_
from nose.tools import raises

from ryu.controller import api
from ryu.controller import dpset

from ryu.ofproto.ofproto_parser import MsgBase
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from ryu.controller import ofp_event

from ryu.lib import hub
from ryu.lib import rpc
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp


class DummyEndpoint(object):
    def __init__(self):
        self.response = []
        self.notification = []

    def send_response(self, msgid, error, result):
        self.response.append((msgid, error, result))

    def send_notification(self, method, params):
        self.notification.append((method, params))


class DummyDatapath(object):
    def __init__(self, ofp=None, ofpp=None):
        if ofp is None:
            ofp = ofproto_v1_2
        self.ofproto = ofp
        if ofpp is None:
            ofpp = ofproto_v1_2_parser
        self.ofproto_parser = ofpp
        self.port_state = {}
        self.ports = {}
        self.sent = []

    def set_xid(self, msg):
        msg.set_xid(1)

    def send_msg(self, msg):
        assert isinstance(msg, MsgBase)
        msg.serialize()
        self.sent.append(msg)

    def send_packet_out(self, in_port, actions, data):
        self.sent.append((in_port, actions, data))


class TestRpcOFPManager(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_logger(self):
        _ = api._
        m = {'hello': 'world'}
        r = eval(str(_(m)))
        eq_(r['msg'], m)
        eq_(r['component_name'], _.COMPONENT_NAME)
        eq_(r['log_type'], 'log')

    def test_monitor_port(self):
        m = api.RpcOFPManager(dpset=None)
        msgid = 1
        try:
            m._monitor_port(msgid, {})
        except api.RPCError as e:
            pass

        port_name = 'OFP11'
        interval = 10
        try:
            m._monitor_port(msgid, {'physical_port_no': port_name})
        except api.RPCError as e:
            pass

        contents = {'hoge': 'jail'}
        r = m._monitor_port(msgid, [{'physical_port_no': port_name,
                                     'contexts': contents,
                                     'interval': interval}])
        eq_(r, {})
        eq_(m.monitored_ports[port_name], (contents, interval))

    def test_monitor_queue(self):
        m = api.RpcOFPManager(dpset=None)
        msgid = 1
        try:
            m._monitor_queue(msgid, {})
        except api.RPCError as e:
            pass

        queue_id = 10
        port_no = 10
        interval = 10
        try:
            m._monitor_queue(msgid, {'queue_id': queue_id, 'port_no': port_no})
        except api.RPCError as e:
            pass

        contents = {'hoge': 'jail'}
        r = m._monitor_queue(msgid, [{'queue_id': queue_id,
                                      'port_no': port_no,
                                      'contexts': contents,
                                      'interval': interval}])
        eq_(r, {})
        eq_(m.monitored_queues[queue_id], (contents, interval))

    def test_register_traceroute(self):
        m = api.RpcOFPManager(dpset=None)
        msgid = 1
        try:
            m._register_traceroute([{}])
        except api.RPCError as e:
            pass

        try:
            m._register_traceroute([{'vlan': 1}])
        except api.RPCError as e:
            pass

        vlan_id = 1
        port_no = 10
        m._register_traceroute([{'vlan': vlan_id,
                                 'ip': '192.168.1.1',
                                 'port': port_no}])

    def test_handle_ofprotocol_without_dp(self):
        m = api.RpcOFPManager(dpset=dpset.DPSet())
        msgid = 1
        try:
            m._handle_ofprotocol(msgid, [{}])
        except api.PendingRPC:
            pass

        try:
            m._handle_ofprotocol(msgid, [{'dpid': 1}])
        except api.PendingRPC:
            pass

    def _create_dpset(self, dpid=0, ports=None, ofp=None, ofpp=None):
        dps = dpset.DPSet()
        dp = DummyDatapath(ofp=ofp, ofpp=ofpp)
        dp.id = dpid
        if ports:
            class DummyPort(object):
                def __init__(self, port_no):
                    self.port_no = port_no
            dps.ports = map(lambda n: DummyPort(n), ports)
            dps.get_ports = lambda dpid: dps.ports

        dps._register(dp)
        return dps

    def _test_handle_ofprotocol_flowmod(self, ofp, ofpp):
        dpid = 10
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        m = api.RpcOFPManager(dpset=dps)
        msgid = 1
        nr_sent = 0

        try:
            m._handle_ofprotocol(msgid, [{'dpid': dpid}])
        except api.RPCError:
            pass

        dp = dps.get(dpid)
        match = ofpp.OFPMatch(metadata=(100, 63),
                              eth_type=2048,
                              ip_proto=112,
                              ipv4_src='172.17.45.1',
                              ipv4_dst='224.0.0.18')
        inst = [ofpp.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, [ofpp.OFPActionPopVlan()]),
                ofpp.OFPInstructionGotoTable(35),
                ofpp.OFPInstructionWriteMetadata(100, 0x255)]

        ofmsg = ofpp.OFPFlowMod(datapath=dp, match=match, instructions=inst)

        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict()}])
        nr_sent += 1
        eq_(r, {'xid': 1})
        eq_(len(dp.sent), nr_sent)

        contexts = {'hello': 'world'}
        r = m._handle_ofprotocol(msgid, [{'ofmsg': ofmsg.to_jsondict(),
                                          'internal': 30,
                                          'contexts': contexts}])
        nr_sent += 1
        eq_(r, {'xid': 1})
        eq_(len(dp.sent), nr_sent)
        eq_(len(m.monitored_flows), 1)
        eq_(m.monitored_flows[m.format_key(match.to_jsondict())],
            contexts)

        ofmsg = ofpp.OFPFlowMod(datapath=dp,
                                command=ofp.OFPFC_DELETE,
                                match=match)

        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict(),
                                          'contexts': contexts}])
        nr_sent += 1
        eq_(r, {'xid': 1})
        eq_(len(dp.sent), nr_sent)

        try:
            r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                              'ofmsg': ofmsg.to_jsondict(),
                                              'contexts': contexts}])
        except api.RPCError as e:
            assert 'unknown key' in str(e)
            eq_(len(dp.sent), nr_sent)

    def test_handle_ofprotocol_flowmod_12(self):
        self._test_handle_ofprotocol_flowmod(ofproto_v1_2, ofproto_v1_2_parser)

    def test_handle_ofprotocol_flowmod_13(self):
        self._test_handle_ofprotocol_flowmod(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_handle_ofprotocol_meter_mod(self, ofp, ofpp):
        dpid = 10
        msgid = 1
        nr_sent = 0
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        m = api.RpcOFPManager(dpset=dps)

        dp = dps.get(dpid)
        bands = [ofpp.OFPMeterBandDrop(10, 100)]
        meter_id = 10
        ofmsg = ofpp.OFPMeterMod(dp, ofp.OFPMC_ADD,
                                 ofp.OFPMF_KBPS, meter_id, bands)

        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict()}])
        nr_sent += 1
        eq_(r, {'xid': 1})
        eq_(len(dp.sent), nr_sent)

        contexts = {'hello': 'world'}
        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict(),
                                          'contexts': contexts}])
        nr_sent += 1
        eq_(r, {'xid': 1})
        eq_(len(dp.sent), nr_sent)
        eq_(len(m.monitored_meters), 1)
        eq_(m.monitored_meters[meter_id], contexts)

        ofmsg = ofpp.OFPMeterMod(dp, ofp.OFPMC_DELETE, ofp.OFPMF_KBPS,
                                 meter_id)
        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict(),
                                          'contexts': contexts}])
        nr_sent += 1
        eq_(r, {'xid': 1})
        eq_(len(dp.sent), nr_sent)
        eq_(len(m.monitored_meters), 0)

    def test_handle_ofprotocol_meter_mod_13(self):
        self._test_handle_ofprotocol_meter_mod(ofproto_v1_3,
                                               ofproto_v1_3_parser)

    def _test_handle_ofprotocol(self, ofp, ofpp):
        dpid = 10
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        m = api.RpcOFPManager(dpset=dps)
        msgid = 1
        nr_sent = 0

        dp = dps.get(dpid)
        ofmsg = ofpp.OFPBarrierRequest(datapath=dp)
        nr_sent += 1
        try:
            r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                              'ofmsg': ofmsg.to_jsondict()}])
        except api.NoRPCResponse as e:
            eq_(e.dpid, dpid)
            eq_(e.xid, 1)
            eq_(e.msgid, msgid)
            eq_(len(dp.sent), nr_sent)

        ofmsg = ofpp.OFPFlowStatsRequest(datapath=dp)
        nr_sent += 1
        try:
            r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                              'ofmsg': ofmsg.to_jsondict()}])
        except api.NoRPCResponse as e:
            eq_(e.dpid, dpid)
            eq_(e.xid, 1)
            eq_(e.msgid, msgid)
            eq_(len(dp.sent), nr_sent)

        ofmsg = ofpp.OFPHello(datapath=dp)
        try:
            r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                              'ofmsg': ofmsg.to_jsondict()}])
        except api.RPCError as e:
            assert 'unknown of message' in str(e)
            eq_(len(dp.sent), nr_sent)

    def test_handle_ofprotocol_12(self):
        self._test_handle_ofprotocol(ofproto_v1_2, ofproto_v1_2_parser)

    def test_handle_ofprotocol_13(self):
        self._test_handle_ofprotocol(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_port_status_handler(self, ofp, ofpp):
        dpid = 10
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        dp = dps.get(dpid)
        port = ofpp.OFPPort(1, 'aa:aa:aa:aa:aa:aa', 'hoge', 0, 0, 0,
                            0, 0, 0, 0, 0)
        msg = ofpp.OFPPortStatus(datapath=dp, reason=ofp.OFPPR_MODIFY,
                                 desc=port)
        ev = ofp_event.EventOFPPortStatus(msg)

        m = api.RpcOFPManager(dpset=dps)
        peer = api.Peer(None)
        peer._endpoint = DummyEndpoint()
        m._peers.append(peer)
        m._port_status_handler(ev)

        eq_(len(peer._endpoint.notification), 1)
        (method, params) = peer._endpoint.notification[0]
        eq_(method, 'port_status')
        eq_(params[0], {'port_no': port.port_no, 'port_state': port.state})

    def test_port_status_handler_12(self):
        self._test_port_status_handler(ofproto_v1_2, ofproto_v1_2_parser)

    def test_port_status_handler_13(self):
        self._test_port_status_handler(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_packet_in_handler(self, ofp, ofpp):
        dpid = 10
        src_ip = '10.0.0.1'
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        dp = dps.get(dpid)
        msg = ofpp.OFPPacketIn(datapath=dp)
        ev = ofp_event.EventOFPPacketIn(msg)

        in_port = 10
        vlan_id = 100
        target_ip = '192.168.1.1'
        msg.match = ofpp.OFPMatch(in_port=in_port)
        protocols = [ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q),
                     vlan.vlan(vid=vlan_id), ipv4.ipv4(src=target_ip)]
        p = packet.Packet(protocols=protocols)
        p.serialize()
        msg.data = p.data
        msg.reason = ofp.OFPR_INVALID_TTL

        m = api.RpcOFPManager(dpset=dps)
        port_no = 5
        msgid = 7

        # test the failure case
        m._packet_in_handler(ev)

        m._register_traceroute([{'vlan': vlan_id,
                                 'ip': src_ip,
                                 'port': port_no}])
        m._packet_in_handler(ev)

        (in_port, actions, data) = dp.sent[0]
        eq_(in_port, port_no)
        pkt = packet.Packet(data)
        ip = pkt.get_protocol(ipv4.ipv4)
        v = pkt.get_protocol(vlan.vlan)
        ic = pkt.get_protocol(icmp.icmp)
        eq_(ip.src, src_ip)
        eq_(ip.dst, target_ip)
        eq_(ip.proto, inet.IPPROTO_ICMP)
        eq_(v.vid, vlan_id)
        eq_(ic.type, icmp.ICMP_TIME_EXCEEDED)
        eq_(len(actions), 1)
        eq_(actions[0].port, ofp.OFPP_TABLE)

    def test_packet_in_handler_12(self):
        self._test_packet_in_handler(ofproto_v1_2, ofproto_v1_2_parser)

    def test_packet_in_handler_13(self):
        self._test_packet_in_handler(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_handler_datapath(self, ofp, parser):
        dpid = 10
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=parser)
        dp = dps.get(dpid)
        ev = dpset.EventDP(dp=dp, enter_leave=True)

        m = api.RpcOFPManager(dpset=dps)

        peer = api.Peer(None)
        peer._endpoint = DummyEndpoint()
        m._peers.append(peer)

        m._handler_datapath(ev)
        eq_(len(peer._endpoint.notification), 1)
        (method, params) = peer._endpoint.notification[0]
        eq_(method, 'state')
        eq_(params[0], {'secure_channel_state': 'Up'})

        peer._endpoint.notification.pop()
        ev = dpset.EventDP(dp=dp, enter_leave=False)
        m._handler_datapath(ev)
        eq_(len(peer._endpoint.notification), 1)
        (method, params) = peer._endpoint.notification[0]
        eq_(method, 'state')
        eq_(params[0], {'secure_channel_state': 'Down'})

        eq_(len(dp.sent), 1)
        return dp

    def test_handler_datapath_12(self):
        dp = self._test_handler_datapath(ofproto_v1_2, ofproto_v1_2_parser)
        msg = dp.sent[0]
        eq_(msg.__class__, ofproto_v1_2_parser.OFPSetConfig)
        eq_(msg.flags, ofproto_v1_2.OFPC_INVALID_TTL_TO_CONTROLLER)

    def test_handler_datapath_13(self):
        ofp = ofproto_v1_3
        dp = self._test_handler_datapath(ofp, ofproto_v1_3_parser)
        msg = dp.sent[0]
        eq_(msg.__class__, ofproto_v1_3_parser.OFPSetAsync)
        eq_(msg.packet_in_mask,
            [1 << ofp.OFPR_ACTION | 1 << ofp.OFPR_INVALID_TTL, 0])
        eq_(msg.port_status_mask,
            [(1 << ofp.OFPPR_ADD | 1 << ofp.OFPPR_DELETE |
              1 << ofp.OFPPR_MODIFY), 0])

    def _test_port_status_thread(self, ofp, ofpp):
        dpid = 10
        port_no = 1
        port_name = 'OFP11'
        dps = self._create_dpset(dpid, ports=(port_no,), ofp=ofp, ofpp=ofpp)
        dp = dps.get(dpid)
        m = api.RpcOFPManager(dpset=dps)
        p = dps.get_ports(dpid)
        p[0].name = port_name
        threads = []
        m.monitored_ports[port_name] = ({}, 1)
        with hub.Timeout(2):
            threads.append(hub.spawn(m._monitor_thread, port_name,
                                     m.monitored_ports, {},
                                     m._port_stats_generator))
            hub.sleep(0.5)
            for t in threads:
                hub.kill(t)
            hub.joinall(threads)

        assert len(dp.sent)
        for m in dp.sent:
            eq_(m.__class__, ofpp.OFPPortStatsRequest)
            eq_(m.port_no, port_no)

    def test_port_status_thread_12(self):
        self._test_port_status_thread(ofproto_v1_2, ofproto_v1_2_parser)

    def test_port_status_thread_13(self):
        self._test_port_status_thread(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_queue_status_thread(self, ofp, ofpp):
        dpid = 10
        queue_id = 2
        port_no = 16
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        dp = dps.get(dpid)
        m = api.RpcOFPManager(dpset=dps)
        p = dps.get_ports(dpid)
        threads = []
        m.monitored_queues[queue_id] = ({}, 1)
        with hub.Timeout(2):
            threads.append(hub.spawn(m._monitor_thread, queue_id,
                                     m.monitored_queues, {'port_no': port_no},
                                     m._queue_stats_generator))
            hub.sleep(0.5)
            for t in threads:
                hub.kill(t)
            hub.joinall(threads)

        assert len(dp.sent)
        for m in dp.sent:
            eq_(m.__class__, ofpp.OFPQueueStatsRequest)
            eq_(m.port_no, port_no)
            eq_(m.queue_id, queue_id)

    def test_queue_status_thread_12(self):
        self._test_queue_status_thread(ofproto_v1_2, ofproto_v1_2_parser)

    def test_queue_status_thread_13(self):
        self._test_queue_status_thread(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_flow_stats_loop(self, ofp, ofpp):
        dpid = 10
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        dp = dps.get(dpid)
        m = api.RpcOFPManager(dpset=dps)

        match = ofpp.OFPMatch(in_port=1)
        ofmsg = ofpp.OFPFlowMod(datapath=dp, match=match)

        contexts = {'hello': 'you'}
        msgid = 10
        r = m._handle_ofprotocol(msgid, [{'ofmsg': ofmsg.to_jsondict(),
                                          'internal': 30,
                                          'contexts': contexts}])
        threads = []
        key = m.format_key(ofmsg.match.to_jsondict())
        with hub.Timeout(5):
            threads.append(hub.spawn(m._flow_stats_loop,
                                     dp, ofmsg.table_id, match, 0.1, key))
            hub.sleep(0.5)

            ofmsg = ofpp.OFPFlowMod(datapath=dp,
                                    command=ofp.OFPFC_DELETE,
                                    match=match)
            msgid = 11
            r = m._handle_ofprotocol(msgid, [{'ofmsg': ofmsg.to_jsondict(),
                                              'internal': 30,
                                              'contexts': contexts}])
            eq_(len(m.monitored_flows), 0)
            hub.joinall(threads)

        for m in dp.sent:
            if m.__class__ in (ofpp.OFPFlowMod, ofpp.OFPPortStatsRequest):
                continue
            eq_(m.__class__, ofpp.OFPFlowStatsRequest)
            eq_(m.table_id, ofmsg.table_id)
            eq_(m.match.to_jsondict(), match.to_jsondict())

    def test_flow_stats_loop_12(self):
        self._test_flow_stats_loop(ofproto_v1_2, ofproto_v1_2_parser)

    def test_flow_stats_loop_13(self):
        self._test_flow_stats_loop(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_meter_stats_loop(self, ofp, ofpp):
        dpid = 10
        msgid = 1
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        dp = dps.get(dpid)
        m = api.RpcOFPManager(dpset=dps)
        bands = [ofpp.OFPMeterBandDrop(10, 100)]
        meter_id = 10
        ofmsg = ofpp.OFPMeterMod(dp, ofp.OFPMC_ADD,
                                 ofp.OFPMF_KBPS, meter_id, bands)
        contexts = {'hello': 'world'}
        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict(),
                                          'contexts': contexts}])
        threads = []
        with hub.Timeout(5):
            threads.append(hub.spawn(m._meter_stats_loop,
                                     dp, 0.1, meter_id))
            hub.sleep(0.5)
            ofmsg = ofpp.OFPMeterMod(dp, ofp.OFPMC_DELETE, ofp.OFPMF_KBPS,
                                     meter_id)
            r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                              'ofmsg': ofmsg.to_jsondict(),
                                              'contexts': contexts}])
            eq_(len(m.monitored_meters), 0)
            hub.joinall(threads)

        for m in dp.sent:
            if m.__class__ in (ofpp.OFPMeterMod, ofpp.OFPPortStatsRequest):
                continue
            eq_(m.__class__, ofpp.OFPMeterStatsRequest)
            eq_(m.meter_id, ofmsg.meter_id)

    def test_meter_stats_loop_13(self):
        self._test_meter_stats_loop(ofproto_v1_3, ofproto_v1_3_parser)

    def _test_rpc_message_thread(self, ofp, ofpp):
        dpid = 10
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        dp = dps.get(dpid)
        m = api.RpcOFPManager(dpset=dps)

        peer = api.Peer(m._rpc_events)
        peer._endpoint = DummyEndpoint()
        m._peers.append(peer)

        msgid = 7
        ofmsg = ofpp.OFPBarrierRequest(datapath=dp)
        params = {'dpid': dpid,
                  'ofmsg': ofmsg.to_jsondict()}
        data = (msgid, 'ofp', [params])
        with hub.Timeout(2):
            peer._handle_rpc_request(data)
            hub.sleep(0.5)

        for s in dp.sent:
            if s.__class__ in (ofpp.OFPPortStatsRequest,):
                continue
            eq_(s.__class__, ofpp.OFPBarrierRequest)

        msg = ofpp.OFPBarrierReply(datapath=dp)
        msg.set_xid(1)
        ev = ofp_event.EventOFPBarrierReply(msg)
        m._barrier_reply_handler(ev)
        eq_(len(peer._endpoint.response), 1)
        rsp = peer._endpoint.response.pop()
        eq_(rsp[0], msgid)
        eq_(rsp[1], None)
        eq_(rsp[2], msg.to_jsondict())
        eq_(len(peer.wait_for_ofp_resepnse[dpid]), 0)

        m._barrier_reply_handler(ev)
        eq_(len(peer._endpoint.response), 0)

        ev = dpset.EventDP(dp=dp, enter_leave=False)
        m._handler_datapath(ev)
        eq_(len(peer.wait_for_ofp_resepnse), 0)

        # bogus RPC
        with hub.Timeout(2):
            m._rpc_events.put((peer, rpc.MessageType.REQUEST,
                               (msgid, 'you')))
            hub.sleep(0.5)

    def test_rpc_message_thread_12(self):
        self._test_rpc_message_thread(ofproto_v1_2, ofproto_v1_2_parser)

    def test_rpc_message_thread_13(self):
        self._test_rpc_message_thread(ofproto_v1_3, ofproto_v1_3_parser)

    def _create_port_stats_args(self, port_no=0):
        return {'port_no': port_no, 'rx_packets': 10, 'tx_packets': 30,
                'rx_bytes': 1024, 'tx_bytes': 2048,
                'rx_dropped': 0, 'tx_dropped': 1,
                'rx_errors': 0, 'tx_errors': 0,
                'rx_frame_err': 0, 'rx_over_err': 0, 'rx_crc_err': 0,
                'collisions': 0}

    def _test_stats_reply_port_handler(self, ofp, ofpp):
        dpid = 10
        dps = self._create_dpset(dpid, (0, 1, 2), ofp, ofpp)
        dp = dps.get(dpid)
        m = api.RpcOFPManager(dpset=dps)

        msgid = 1
        r = m._monitor_port(msgid, [{'physical_port_no': 0,
                                     'contexts': {'hello': 'world'},
                                     'interval': 30}])
        return m, dp

    def test_stats_reply_port_handler_12(self):
        ofp = ofproto_v1_2
        ofpp = ofproto_v1_2_parser
        manager, dp = self._test_stats_reply_port_handler(ofp, ofpp)

        msg = ofpp.OFPStatsReply(datapath=dp, type_=ofp.OFPST_PORT)
        ev = ofp_event.EventOFPStatsReply(msg)
        msg.body = []
        for p in range(2):
            port = ofpp.OFPPortStats(**self._create_port_stats_args(p))
            msg.body.append(port)
        manager._stats_reply_handler(ev)

    def test_stats_reply_port_handler_13(self):
        ofp = ofproto_v1_3
        ofpp = ofproto_v1_3_parser
        manager, dp = self._test_stats_reply_port_handler(ofp, ofpp)
        msg = ofpp.OFPPortStatsReply(dp)
        ev = ofp_event.EventOFPPortStatsReply(msg)
        msg.body = []
        for p in range(2):
            d = self._create_port_stats_args(p)
            d['duration_sec'] = 0
            d['duration_nsec'] = 0
            port = ofpp.OFPPortStats(**d)
            msg.body.append(port)
        manager._port_stats_reply_handler(ev)

    def _test_stats_reply_flow_handler(self, ofp, ofpp):
        dpid = 10
        msgid = 9
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        m = api.RpcOFPManager(dpset=dps)

        dp = dps.get(dpid)
        match = ofpp.OFPMatch(in_port=1)
        ofmsg = ofpp.OFPFlowMod(datapath=dp, match=match)

        contexts = {'hello': 'world'}
        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict(),
                                          'contexts': contexts}])
        return m, dp

    def test_stats_reply_flow_handler_12(self):
        ofp = ofproto_v1_2
        ofpp = ofproto_v1_2_parser
        manager, dp = self._test_stats_reply_flow_handler(ofp, ofpp)

        msg = ofpp.OFPStatsReply(datapath=dp,
                                 type_=ofp.OFPST_FLOW)
        ev = ofp_event.EventOFPStatsReply(msg)
        s1 = ofpp.OFPFlowStats(table_id=0, duration_sec=10, duration_nsec=10,
                               priority=0, idle_timeout=0, hard_timeout=0,
                               cookie=0, packet_count=10, byte_count=100,
                               match=ofpp.OFPMatch(in_port=1))
        # not-monitored flow
        s2 = ofpp.OFPFlowStats(table_id=0, duration_sec=10, duration_nsec=10,
                               priority=0, idle_timeout=0, hard_timeout=0,
                               cookie=0, packet_count=10, byte_count=100,
                               match=ofpp.OFPMatch(in_port=2))
        msg.body = [s1, s2]
        manager._stats_reply_handler(ev)

    def test_stats_reply_flow_handler_13(self):
        ofp = ofproto_v1_3
        ofpp = ofproto_v1_3_parser
        manager, dp = self._test_stats_reply_flow_handler(ofp, ofpp)

        msg = ofpp.OFPFlowStatsReply(datapath=dp)
        ev = ofp_event.EventOFPStatsReply(msg)
        s1 = ofpp.OFPFlowStats(table_id=0, duration_sec=10, duration_nsec=10,
                               priority=0, idle_timeout=0, hard_timeout=0,
                               cookie=0, packet_count=10, byte_count=100,
                               match=ofpp.OFPMatch(in_port=1))
        # not-monitored flow
        s2 = ofpp.OFPFlowStats(table_id=0, duration_sec=10, duration_nsec=10,
                               priority=0, idle_timeout=0, hard_timeout=0,
                               cookie=0, packet_count=10, byte_count=100,
                               match=ofpp.OFPMatch(in_port=2))
        msg.body = [s1, s2]
        manager._flow_stats_reply_handler(ev)

    def test_stats_reply_meter_handler_13(self):
        ofp = ofproto_v1_3
        ofpp = ofproto_v1_3_parser
        dpid = 10
        msgid = 9
        dps = self._create_dpset(dpid, ofp=ofp, ofpp=ofpp)
        m = api.RpcOFPManager(dpset=dps)

        dp = dps.get(dpid)
        bands = [ofpp.OFPMeterBandDrop(10, 100)]
        meter_id = 10
        ofmsg = ofpp.OFPMeterMod(dp, ofp.OFPMC_ADD,
                                 ofp.OFPMF_KBPS, meter_id, bands)
        contexts = {'hello': 'world'}
        r = m._handle_ofprotocol(msgid, [{'dpid': dpid,
                                          'ofmsg': ofmsg.to_jsondict(),
                                          'contexts': contexts}])

        msg = ofpp.OFPMeterStatsReply(datapath=dp)
        ev = ofp_event.EventOFPStatsReply(msg)
        s = ofpp.OFPMeterStats(meter_id=meter_id, flow_count=10,
                               packet_in_count=10, byte_in_count=10,
                               duration_sec=10, duration_nsec=10,
                               band_stats=[ofpp.OFPMeterBandStats(1, 8),
                                           ofpp.OFPMeterBandStats(2, 16)])

        msg.body = [s]
        m._meter_stats_reply_handler(ev)
