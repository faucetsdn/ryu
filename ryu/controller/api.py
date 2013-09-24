import eventlet
import time
from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.ofproto.ofproto_parser import MsgBase
from ryu.lib.rpc import RpcSession, RpcMessage
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_0_parser
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu.lib import mac


traceroute_source = {}
flow_sem = eventlet.semaphore.Semaphore()
monitored_flows = {}


class OFWireRpcSession(object):
    def __init__(self, socket, dpset):
        self.socket = socket
        self.dpset = dpset
        self.session = RpcSession()
        self.pool = eventlet.GreenPool()
        self.send_queue = eventlet.queue.Queue()
        self.pool.spawn_n(self._send)

    def _send(self):
        while True:
            m = self.send_queue.get()
            self.socket.sendall(m)

    def _flow_stats_loop(self, dp, table_id, match, interval, key):
        while True:
            if not key in monitored_flows:
                break
            msg = dp.ofproto_parser.OFPFlowStatsRequest(dp,
                                                        table_id,
                                                        dp.ofproto.OFPP_ANY,
                                                        dp.ofproto.OFPG_ANY,
                                                        0, 0,
                                                        match)
            dp.send_msg(msg)
            eventlet.sleep(interval)

    def ofp_handle_request(self, msg):
        send_response = True

        param_dict = msg[3][0]
        if 'dpid' in param_dict:
            dp = self.dpset.get(int(param_dict['dpid']))
        else:
            dp = None
        if dp is None:
            for k, v in self.dpset.get_all():
                dp = v
                break

        ofmsg = None
        # default interval
        interval = 60
        contexts = None
        for k, v in param_dict.items():
            if k == 'dpid':
                continue
            elif k == 'ofmsg':
                try:
                    ofmsg = ofproto_parser.ofp_msg_from_jsondict(dp, v)
                except:
                    pass
            elif k == 'interval':
                interval = int(v)
            elif k == 'contexts':
                contexts = v
        if ofmsg is None or (contexts and interval == 0):
            m = req.session.create_response(msg[1], None,
                                            [{'error': 'invalid'}])
            self.send_queue.put(m)
            return

        if ofmsg.msg_type in (dp.ofproto.OFPT_STATS_REQUEST,
                              dp.ofproto.OFPT_BARRIER_REQUEST):
            self.waiters[dp.id] = (ofmsg.xid, msg[1])
        else:
            error = 0
            result = {'xid': ofmsg.xid}
            print "got"
            if contexts:
                flow_sem.acquire()
                key = str(ofmsg.match.to_jsondict())
                if ofmsg.command is dp.ofproto.OFPFC_ADD:
                    if key in monitored_flows:
                        error = None
                        result = [{'error': 'the existing flow'}]
                    else:
                        monitored_flows[key] = contexts
                        self.pool.spawn_n(self._flow_stats_loop,
                                          dp, ofmsg.table_id, ofmsg.match,
                                          interval, key)

                elif ofmsg.command in (dp.ofproto.OFPFC_DELETE,
                                       dp.ofproto.OFPFC_DELETE_STRICT):
                    print "delete command"
                    if key in monitored_flows:
                        print "delete flow"
                        del monitored_flows[key]
                flow_sem.release()

            r = self.session.create_response(msg[1], error, result)
            self.send_queue.put(r)
        dp.send_msg(ofmsg)

    def _tr_handle_notify(self, msg):
        params = msg[2][0]
        traceroute_source[params['vlan']] = {
            'ip': params['ip'],
            'port': params['port']
            }
        print traceroute_source

    def serve(self):
        while True:
            ret = self.socket.recv(4096)
            if len(ret) == 0:
                break
            messages = self.session.get_messages(ret)
            for m in messages:
                if m[0] == RpcMessage.REQUEST:
                    if m[2] == 'ofp':
                        self.ofp_handle_request(m)
                elif m[0] == RpcMessage.RESPONSE:
                    pass
                elif m[0] == RpcMessage.NOTIFY:
                    if m[1] == 'traceroute':
                        self._tr_handle_notify(m)
                else:
                    print "invalid type", m


class RPCApi(app_manager.RyuApp):
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        self.dpset = kwargs['dpset']
        super(RPCApi, self).__init__(*args, **kwargs)
        self.server = eventlet.listen(('', 50001))
        self.pool = eventlet.GreenPool()
        self.sessions = []
        self.dp_joined = False
        self.pool.spawn_n(self.serve)

    def _wait_for_dp_joined(self):
        while not self.dp_joined:
            #print "waiting for dp joined..."
            eventlet.sleep(0.1)

    def serve(self):
        self._wait_for_dp_joined()
        while True:
            sock, address = self.server.accept()
            session = OFWireRpcSession(sock, self.dpset)
            session.waiters = {}
            self.sessions.append(session)
            self.pool.spawn_n(session.serve)

    def handle_traceroute(self, msg):
        dp = msg.datapath
        in_port = None
        for f in msg.match.fields:
            if f.header == ofproto_v1_2.OXM_OF_IN_PORT:
                in_port = f.value

        if in_port is None:
            print "in_port is missing"
            return

        pkt = packet.Packet(msg.data)
        if not ipv4.ipv4 in pkt:
            print "ip header doesn't exit"
            return

        if vlan.vlan in pkt:
            o_vlan = pkt.get_protocols(vlan.vlan)[0]
            vlan_p = vlan.vlan(vid=o_vlan.vid)
        else:
            print "vlan header doesn't exit"
            return

        o_eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth = ethernet.ethernet(o_eth.src, o_eth.dst, o_eth.ethertype)
        o_ip = pkt.get_protocols(ipv4.ipv4)[0]
        # needs to set src properly for either side (vlan or mpls)
        # ip = ipv4.ipv4(src=ip_lib.ipv4_to_bin(V1_GS_IP), dst=o_ip.src,
        #                proto=1)

        src_ip = traceroute_source[o_vlan.vid]['ip']
        in_port = traceroute_source[o_vlan.vid]['port']

        ip = ipv4.ipv4(src=src_ip, dst=o_ip.src, proto=1)
        ip_offset = o_eth.length
        # vlan header
        ip_offset += 4
        data = msg.data[ip_offset:ip_offset +
                        (o_ip.header_length * 4 + 8)]
        ic = icmp.icmp(icmp.ICMP_TIME_EXCEEDED, 0, 0,
                       icmp.TimeExceeded(data))

        proto_list = [eth, vlan_p, ip, ic]

        p = packet.Packet(protocols=proto_list)
        p.serialize()
        self.send_openflow_packet(dp=dp, packet=p.data,
                                  port_no=ofproto_v1_2.OFPP_TABLE,
                                  inport=in_port)

    def send_openflow_packet(self, dp, packet, port_no,
                             inport=ofproto_v1_2.OFPP_CONTROLLER):

        actions = [dp.ofproto_parser.OFPActionOutput(port_no, 0)]
        dp.send_packet_out(in_port=inport, actions=actions, data=packet)

    def _ofp_reply(self, msg):
        for sess in self.sessions:
            if msg.datapath.id in sess.waiters:
                (xid, msgid) = sess.waiters[msg.datapath.id]
                results = msg.to_jsondict()
                r = sess.session.create_response(msgid, None, results)
                sess.send_queue.put(r)

    @handler.set_ev_cls(ofp_event.EventOFPBarrierReply,
                        handler.MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        msg = ev.msg
        self._ofp_reply(msg)

    @handler.set_ev_cls(ofp_event.EventOFPStatsReply,
                        handler.MAIN_DISPATCHER)
    def flow_reply_handler(self, ev):
        msg = ev.msg
        self._ofp_reply(msg)
        if msg.type == ofproto_v1_2.OFPST_FLOW:
            for body in msg.body:
                key = str(body.match.to_jsondict())
                contexts = None
                flow_sem.acquire()
                if key in monitored_flows:
                    contexts = monitored_flows[key]
                flow_sem.release()
                if contexts:
                    stats = {'byte_count': body.byte_count,
                             'packet_count': body.packet_count}
                    stats.update(contexts)
                    stats['timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    print stats

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn)
    def packet_in_handler(self, ev):
        msg = ev.msg
        print "trace"
        if ofproto_v1_2.OFPR_INVALID_TTL == msg.reason:
            print "zero ttl packet"
            self.handle_traceroute(msg)
            return

    @handler.set_ev_cls(dpset.EventDP)
    def handler_datapath(self, ev):
        print "join"
        if ev.enter:
            print "dp joined"
            dp = ev.dp
            m = dp.ofproto_parser.OFPSetConfig(dp, 1 << 2, miss_send_len=1600)
            dp.send_msg(m)
            self.dp_joined = True

    def handle_port_status(self, msg):
        reason = msg.reason
        datapath = msg.datapath
        port = msg.desc
        ofproto = datapath.ofproto
        # For now just port modifications are reported
        if reason == ofproto.OFPPR_MODIFY:
            print port.port_no, port.state
            params = {'port_no': port.port_no, 'port_state': port.state}
            for s in self.sessions:
                m = s.session.create_notification('port_status', params)
                s.send_queue.put(m)

    @handler.set_ev_cls(ofp_event.EventOFPPortStatus)
    def port_status_handler(self, ev):
        print "port status called"
        if hasattr(ev, 'msg'):
            msg = ev.msg
            self.handle_port_status(msg)
