import json
import logging
from operator import attrgetter
from oslo.config import cfg
from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_error_table
from ryu.lib import hub
from ryu.lib import apgw_log
from ryu.lib import rpc
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import vlan
from ryu.lib.of_config import capable_switch as cs
from ryu.lib.of_config import constants as consts
import ryu.lib.of_config.classes as ofc
import eventlet
import sys


logging.setLoggerClass(apgw_log.ApgwLogger)

class RPCError(Exception):
    pass


class NoRPCResponse(Exception):
    def __init__(self, dpid=None, xid=None, msgid=None):
        self.dpid = dpid
        self.xid = xid
        self.msgid = msgid


class PendingRPC(Exception):
    pass


class Peer(object):
    def __init__(self, queue, log):
        super(Peer, self).__init__()
        self._queue = queue
        self.wait_for_ofp_resepnse = {}
        self.log = log

    def _handle_rpc_request(self, data):
        if data[2]:
            params = str(data[2][0])
        else:
            params = ''
        m = {'RPC request': {'method': data[1], 'params': params, 'msgid': data[0]}}
        self.log.info(m)
        self._queue.put((self, rpc.MessageType.REQUEST, data))

    def _handle_rpc_notify(self, data):
        self._queue.put((self, rpc.MessageType.NOTIFY, data))


class RpcOFPManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION, ofproto_v1_3.OFP_VERSION]
    LOGGER_NAME = 'ofwire'
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(RpcOFPManager, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self._peers = []
        self.traceroute_source = {}
        self.monitored_ports = {}
        self.monitored_flows = {}
        self.monitored_meters = {}
        self.flow_stats_interval = 30
        self.meter_stats_epoch = 0
        self.monitored_queues = {}
        self.pending_rpc_requests = []
        self._rpc_events = hub.Queue(128)
        # we assume that there is only one datapath.
        self.secure_channel_state = None
        hub.spawn(self._peer_accept_thread)
        hub.spawn(self._rpc_message_thread)
        hub.spawn(self._meter_stats_thread)
        self.log = logging.getLogger('ofwire')
        apgw_log.configure_logging(self.log, 'ofwire')
        self.states_log = apgw_log.DictAndLogTypeAdapter(self.log,
                                                         log_type='states')
        self.stats_log = apgw_log.DictAndLogTypeAdapter(self.log,
                                                        log_type='stats')

    def _first_datapath(self):
        # use the first datapath
        for k, v in self.dpset.get_all():
            return v
        return None

    def _meter_stats_thread(self):
        while True:
            dp = self._first_datapath()
            if dp:
                msg = dp.ofproto_parser.OFPMeterStatsRequest(datapath=dp)
                dp.send_msg(msg)
            hub.sleep(self.flow_stats_interval)

    def _rpc_message_thread(self):
        while True:
            (peer, _type, data) = self._rpc_events.get()
            error = None
            result = None
            try:
                if _type == rpc.MessageType.REQUEST:
                    msgid, target_method, params = data
                    if target_method == "ofp":
                        result = self._handle_ofprotocol(msgid, params)
                    elif target_method == "monitor_port":
                        result = self._monitor_port(msgid, params)
                    elif target_method == "monitor_queue":
                        result = self._monitor_queue(msgid, params)
                    elif target_method == 'query_secure_channel_state':
                        result = self._query_secure_channel_state(msgid,
                                                                  params)
                    elif target_method == 'query_port_desc_stats':
                        result = self._query_port_desc_stats(msgid, params)
                    else:
                        error = 'Unknown method %s' % (target_method)
                elif _type == rpc.MessageType.NOTIFY:
                    target_method, params = data
                    if target_method == 'traceroute':
                        try:
                            self._register_traceroute(params)
                        except RPCError as e:
                            self.log.error({'error': str(e)})
                    else:
                        self.log.error({'unknown method': target_method})
                    continue
            except RPCError as e:
                error = str(e)
            except PendingRPC as e:
                # we handle the RPC request after a datapath joins.
                self.pending_rpc_requests.append((peer, data))
                continue
            except NoRPCResponse as e:
                # we'll send RPC sesponse after we get a response from
                # datapath.
                if e.dpid is not None:
                    d = peer.wait_for_ofp_resepnse.setdefault(e.dpid, {})
                    d[e.xid] = e.msgid
                continue
            except:
                self.log.info({'bogus RPC': data})

            peer._endpoint.send_response(msgid, error=error, result=result)
            m = {'RPC response': {'result': result, 'error': error, 'msgid': msgid}}
            self.log.info(m)

    def _peer_loop_thread(self, peer):
        peer._endpoint.serve()
        # the peer connection is closed
        self._peers.remove(peer)

    def peer_accept_handler(self, new_sock, addr):
        peer = Peer(self._rpc_events, self.log)
        table = {
            rpc.MessageType.REQUEST: peer._handle_rpc_request,
            rpc.MessageType.NOTIFY: peer._handle_rpc_notify,
            }
        peer._endpoint = rpc.EndPoint(new_sock, disp_table=table)
        self._peers.append(peer)
        hub.spawn(self._peer_loop_thread, peer)

    def _peer_accept_thread(self):
        server = hub.StreamServer(('', 50001),
                                  self.peer_accept_handler)
        server.serve_forever()

    def _send_waited_rpc_response(self, msg):
        for peer in self._peers:
            if not msg.datapath.id in peer.wait_for_ofp_resepnse:
                continue
            if msg.xid in peer.wait_for_ofp_resepnse[msg.datapath.id]:
                msgid = peer.wait_for_ofp_resepnse[msg.datapath.id][msg.xid]
                peer._endpoint.send_response(msgid, error=None,
                                             result=msg.to_jsondict())
                m = {'RPC response': {'result': msg.to_jsondict(), 'error': None, 'msgid': msgid}}
                self.log.info(m)
                del peer.wait_for_ofp_resepnse[msg.datapath.id][msg.xid]
                return

    def compare_key(self, k1, k2):
        k1 = eval(k1)
        k2 = eval(k2)
        l1 = k1['OFPMatch']['oxm_fields']
        l2 = k2['OFPMatch']['oxm_fields']
        return sorted(l1) == sorted(l2)

    def format_key(self, match_json):
        del match_json['OFPMatch']['length']
        for t in match_json['OFPMatch']['oxm_fields']:
            tlv = t['OXMTlv']
            if tlv['field'] in ['ipv4_dst', 'ipv4_src']:
                if tlv['mask'] == '255.255.255.255':
                    tlv['mask'] = None
        return str(match_json)

    def _get_secure_channel_state_param(self):
        return {'secure_channel_state': self.secure_channel_state}

    @handler.set_ev_cls(dpset.EventDP)
    def _handler_datapath(self, ev):
        if ev.enter:
            self.secure_channel_state = 'Up'
            dp = ev.dp
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            if ofp.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
                m = parser.OFPSetConfig(dp,
                                        ofp.OFPC_INVALID_TTL_TO_CONTROLLER,
                                        ofp.OFPCML_MAX)
            elif ofp.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
                packet_in_mask = (ofp.OFPR_ACTION_MASK |
                                  ofp.OFPR_INVALID_TTL_MASK)
                port_status_mask = (ofp.OFPPR_ADD_MASK |
                                    ofp.OFPPR_DELETE_MASK |
                                    ofp.OFPPR_MODIFY_MASK)
                m = parser.OFPSetAsync(dp, [packet_in_mask, 0],
                                       [port_status_mask, 0],
                                       [0, 0])
            dp.send_msg(m)

            log_msg = {"event": "dp connected", "dpid": ev.dp.id}
            for p in self.pending_rpc_requests:
                (peer, data) = p
                self._rpc_events.put((peer, rpc.MessageType.REQUEST, data))
        else:
            self.secure_channel_state = 'Down'
            log_msg = {"event": "dp disconnected"}
            for peer in self._peers:
                if ev.dp.id in peer.wait_for_ofp_resepnse:
                    del peer.wait_for_ofp_resepnse[ev.dp.id]

        self.states_log.critical(log_msg)
        notify_param = self._get_secure_channel_state_param()
        for peer in self._peers:
            peer._endpoint.send_notification("state", [notify_param])

    @handler.set_ev_cls(ofp_event.EventOFPErrorMsg,
                        handler.MAIN_DISPATCHER)
    def _error_msg_handler(self, ev):
        d = ev.msg.to_jsondict()
        d = d['OFPErrorMsg']
        d['xid'] = ev.msg.xid
        d['description'] = \
            ofproto_error_table.error_description(ev.msg.type, ev.msg.code)
        self.log.info(d)
        for peer in self._peers:
            peer._endpoint.send_notification("ofp_error", [d])

    @handler.set_ev_cls(ofp_event.EventOFPBarrierReply,
                        handler.MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        self._send_waited_rpc_response(ev.msg)

    @handler.set_ev_cls(ofp_event.EventOFPFlowStatsReply,
                        handler.MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        msg = ev.msg
        self._send_waited_rpc_response(msg)
        for body in msg.body:
            key = self.format_key(body.match.to_jsondict())
            contexts = None
            for k in self.monitored_flows.keys():
                if self.compare_key(k, key):
                    contexts = self.monitored_flows[k]
                    break
            if contexts is not None:
                stats = body.to_jsondict()['OFPFlowStats']
                stats.update(contexts)
                self.stats_log.info(stats)

    @handler.set_ev_cls(ofp_event.EventOFPPortStatsReply,
                        handler.MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        msg = ev.msg
        self._send_waited_rpc_response(msg)
        dp = msg.datapath
        for stat in sorted(msg.body, key=attrgetter('port_no')):
            try:
                port = self.dpset.get_port(dp.id, stat.port_no)
            except:
                continue
            if port.name in self.monitored_ports:
                stats = {'physical_port_no': port.name}
                stats.update(stat.to_jsondict()['OFPPortStats'])
                contexts, interval_ = self.monitored_ports[port.name]
                stats.update(contexts)
                self.stats_log.info(stats)

    def _add_band_name(self, stats):
        new_stats = [
            {'band_name': {'pir': stats[0]}},
            {'band_name': {'cir': stats[1]}}
            ]
        return new_stats

    @handler.set_ev_cls(ofp_event.EventOFPMeterStatsReply,
                        handler.MAIN_DISPATCHER)
    def _meter_stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        for stat in msg.body:
            if stat.meter_id in self.monitored_meters:
                contexts, interval = self.monitored_meters[stat.meter_id]
                if (self.meter_stats_epoch % interval) != 0:
                    continue
                stats = stat.to_jsondict()['OFPMeterStats']
                stats['band_stats'] = self._add_band_name(stats['band_stats'])
                stats.update(contexts)
                self.stats_log.info(stats)
        self.meter_stats_epoch += self.flow_stats_interval

    @handler.set_ev_cls(ofp_event.EventOFPQueueStatsReply,
                        handler.MAIN_DISPATCHER)
    def _queue_stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        for stat in msg.body:
            key = str(stat.queue_id) + '-' + str(stat.port_no)
            if key in self.monitored_queues:
                contexts, interval_ = self.monitored_queues[key]
                stats = stat.to_jsondict()['OFPQueueStats']
                stats = {'queue_id': stat.queue_id,
                         'port_no': stat.port_no,
                         'tx_bytes': stat.tx_bytes,
                         'tx_packets': stat.tx_packets,
                         'tx_errors': stat.tx_errors}
                stats.update(contexts)
                self.stats_log.info(stats)

    @handler.set_ev_cls(ofp_event.EventOFPStatsReply,
                        handler.MAIN_DISPATCHER)
    def _stats_reply_handler(self, ev):
        msg = ev.msg

        if msg.type == ofproto_v1_2.OFPST_FLOW:
            self._flow_stats_reply_handler(ev)
        elif msg.type == ofproto_v1_2.OFPST_PORT:
            self._port_stats_reply_handler(ev)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        self.log.debug({"event": "packet_in", "reason": msg.reason})
        if dp.ofproto.OFPR_INVALID_TTL != msg.reason:
            return

        if not 'in_port' in msg.match:
            return
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        if not pkt.get_protocol(ipv4.ipv4):
            return

        o_vlan = pkt.get_protocol(vlan.vlan)
        if o_vlan is None:
            return
        vlan_p = vlan.vlan(vid=o_vlan.vid)

        o_eth = pkt.get_protocol(ethernet.ethernet)
        eth = ethernet.ethernet(o_eth.src, o_eth.dst, o_eth.ethertype)
        o_ip = pkt.get_protocol(ipv4.ipv4)
        # needs to set src properly for either side (vlan or mpls)
        # ip = ipv4.ipv4(src=ip_lib.ipv4_to_bin(V1_GS_IP), dst=o_ip.src,
        #                proto=1)
        try:
            src_ip = self.traceroute_source[o_vlan.vid]['ip']
            in_port = self.traceroute_source[o_vlan.vid]['port']
        except:
            self.log.info({"event": "traceroute error",
                           "reason": "can't find ip", "vid": o_vlan.vid})
            return
        ip = ipv4.ipv4(src=src_ip, dst=o_ip.src, proto=1)
        ip_offset = 14 + 4
        # ether + vlan headers
        data = msg.data[ip_offset:ip_offset +
                        (o_ip.header_length * 4 + 8)]
        ic = icmp.icmp(icmp.ICMP_TIME_EXCEEDED, 0, 0,
                       icmp.TimeExceeded(data_len=len(data), data=data))

        p = packet.Packet(protocols=[eth, vlan_p, ip, ic])
        p.serialize()
        actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_TABLE, 0)]
        dp.send_packet_out(in_port=in_port, actions=actions, data=p.data)

    @handler.set_ev_cls(ofp_event.EventOFPPortStatus)
    def _port_status_handler(self, ev):
        if hasattr(ev, 'msg'):
            msg = ev.msg

            reason = msg.reason
            datapath = msg.datapath
            port = msg.desc
            ofproto = datapath.ofproto
            self.states_log.info({"event": "port status change",
                                  "reason": reason,
                                  "port_no": port.port_no, "state": port.state})
            # For now just port modifications are reported
            if reason == ofproto.OFPPR_MODIFY:
                params = {'port_no': port.port_no, 'port_state': port.state}
                for peer in self._peers:
                    peer._endpoint.send_notification("port_status", [params])

    def _flow_stats_loop(self, dp, table_id, match, interval, key):
        while True:
            if not key in self.monitored_flows:
                break
            msg = dp.ofproto_parser.OFPFlowStatsRequest(datapath=dp,
                                                        table_id=table_id,
                                                        match=match)
            dp.send_msg(msg)
            hub.sleep(interval)

    def _handle_ofprotocol(self, msgid, params):
        try:
            param_dict = params[0]
        except:
            raise RPCError('parameters are missing')

        send_response = True

        dp = None
        if 'dpid' in param_dict:
            dp = self.dpset.get(int(param_dict['dpid']))
            param_dict.pop('dpid')
        else:
            # use the first datapath
            for k, v in self.dpset.get_all():
                dp = v
                break

        if dp is None:
            self.log.info({"event": "no datapath, queued",
                           "msg": str(param_dict)})
            raise PendingRPC()

        contexts = None
        ofmsg = None
        # default interval
        interval = 60
        for k, v in param_dict.items():
            if k == 'ofmsg':
                try:
                    ofmsg = ofproto_parser.ofp_msg_from_jsondict(dp, v)
                except:
                    raise RPCError('parameters are invalid, %s' %
                                   (str(param_dict)))
            elif k == 'interval':
                interval = int(v)
            elif k == 'contexts':
                contexts = v
        if ofmsg is None:
            raise RPCError('"ofmsg" parameter is invalid, %s' %
                           (str(param_dict)))
        if contexts is not None and not isinstance(contexts, dict):
            raise RPCError('"contexts" must be dictionary, %s' %
                           (str(param_dict)))
        if contexts is not None:
            if interval == 0:
                raise RPCError('"interval" must be non zero with'
                               ' "contexts", %s' % (str(param_dict)))
            if interval % self.flow_stats_interval != 0 or \
                    interval < self.flow_stats_interval:
                self.logger.warning('"interval" must be a multiple of %d' %
                                    self.flow_stats_interval)
                interval = ((interval + (self.flow_stats_interval - 1)) /
                            self.flow_stats_interval *
                            self.flow_stats_interval)

        dp.set_xid(ofmsg)
        ofmsg.serialize()
        if dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            msg_types = (dp.ofproto.OFPT_STATS_REQUEST,
                         dp.ofproto.OFPT_BARRIER_REQUEST)
        else:
            msg_types = (dp.ofproto.OFPT_MULTIPART_REQUEST,
                         dp.ofproto.OFPT_BARRIER_REQUEST)

        if ofmsg.msg_type in msg_types:
            dp.send_msg(ofmsg)
            raise NoRPCResponse(dpid=dp.id, xid=ofmsg.xid, msgid=msgid)

        result = {'xid': ofmsg.xid}
        if ofmsg.msg_type is dp.ofproto.OFPT_FLOW_MOD:
            key = self.format_key(ofmsg.match.to_jsondict())
            if contexts is not None:
                if ofmsg.command is dp.ofproto.OFPFC_ADD:
                    if key in self.monitored_flows:
                        raise RPCError('the existing flow, %s' % (str(key)))

                    self.monitored_flows[key] = contexts
                    hub.spawn(self._flow_stats_loop,
                              dp, ofmsg.table_id, ofmsg.match,
                              interval, key)

            if ofmsg.command in (dp.ofproto.OFPFC_DELETE,
                                 dp.ofproto.OFPFC_DELETE_STRICT):
                try:
                    del self.monitored_flows[key]
                except:
                    # some flows are added without contexts so we hit
                    # the following with such. For just to be safe, we
                    # log it for debugging.
                    self.log.debug({'tried to remove an unknown flow':
                                        str(key)})
        elif (dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION and
              ofmsg.msg_type is dp.ofproto.OFPT_METER_MOD):
            if contexts is not None:
                if ofmsg.command is dp.ofproto.OFPMC_ADD:
                    if ofmsg.meter_id in self.monitored_meters:
                        raise RPCError('meter already exitsts %d' %
                                       (ofmsg.meter_id))
                    self.monitored_meters[ofmsg.meter_id] = (contexts,
                                                             interval)
                elif ofmsg.command is dp.ofproto.OFPMC_DELETE:
                    try:
                        del self.monitored_meters[ofmsg.meter_id]
                    except:
                        raise RPCError('unknown meter %d' % (ofmsg.meter_id))
                elif ofmsg.command is dp.ofproto.OFPMC_MODIFY:
                    raise RPCError('METER_MOD with contexts is not supported')
                else:
                    raise RPCError('unknown meter_mod command')
        else:
            raise RPCError('unknown of message, %s' % (str(param_dict)))

        dp.send_msg(ofmsg)
        return result

    def _register_traceroute(self, params):
        try:
            param_dict = params[0]
        except:
            raise RPCError('parameters are missing')
        try:
            self.traceroute_source[param_dict['vlan']] = {
                'ip': param_dict['ip'],
                'port': param_dict['port']
                }
        except Exception as e:
            raise RPCError('parameters are invalid, %s' % (str(param_dict)))

        self.log.info({'event': 'register traceroute source',
                       'vlan': param_dict['vlan'],
                       'ip': param_dict['ip'],
                       'port': param_dict['port']})
        return {}

    def _monitor(self, mandatory_params, resource_dict, request_generator,
                 msgid, params):
        try:
            param_dict = params[0]
        except:
            raise RPCError('parameters are missing')
        resource_id = None
        contexts = None
        interval = 60

        resource_name = mandatory_params.pop(0)
        for k, v in param_dict.items():
            if k == resource_name:
                resource_id = v
            elif k == 'contexts':
                contexts = v
            elif k == 'interval':
                interval = v
            elif k in mandatory_params:
                pass
            else:
                raise RPCError('unknown parameters, %s' % k)

        if mandatory_params:
            for k in mandatory_params:
                resource_id = str(resource_id) + '-' + str(param_dict[k])

        if contexts is None and interval > 0:
            raise RPCError('"contexts" parameter is necessary')
        if contexts is not None and not isinstance(contexts, dict):
            raise RPCError('"contexts" parameter must be dictionary')
        if resource_id is None:
            raise RPCError('"%s" parameter is necessary' % resource_name)

        if interval == 0:
            if resource_id in resource_dict:
                del resource_dict[resource_id]
            else:
                raise RPCError('%s %d does not exist' % (resource_name,
                                                         resource_id))
        else:
            need_spawn = False
            if not resource_id in resource_dict:
                need_spawn = True
            resource_dict[resource_id] = (contexts, interval)
            if need_spawn:
                pass
                hub.spawn(self._monitor_thread, resource_id, resource_dict,
                          param_dict, request_generator)
        return {}

    def _port_stats_generator(self, dp, port_name, param_dict):
        port_no = None
        ports = self.dpset.get_ports(dp.id)
        for port in ports:
            if port.name == port_name:
                port_no = port.port_no
                break
        if port_no is None:
            return None
        return dp.ofproto_parser.OFPPortStatsRequest(datapath=dp,
                                                     port_no=port_no)

    def _monitor_port(self, msgid, params):
        return self._monitor(['physical_port_no'],
                             self.monitored_ports,
                             self._port_stats_generator,
                             msgid, params)

    def _monitor_thread(self, resource_id, resource_dict, param_dict,
                        generator):
        while resource_id in resource_dict:
            _contexts, interval = resource_dict[resource_id]
            for k, dp in self.dpset.get_all():
                try:
                    ofmsg = generator(dp, resource_id, param_dict)
                    if ofmsg:
                        dp.send_msg(ofmsg)
                except:
                    # ignore the error due to dead datapath
                    pass
            hub.sleep(interval)

    def _queue_stats_generator(self, dp, resource_id, param_dict):
        queue_id = param_dict['queue_id']
        port_no = param_dict['port_no']
        return dp.ofproto_parser.OFPQueueStatsRequest(datapath=dp,
                                                      port_no=port_no,
                                                      queue_id=queue_id)

    def _monitor_queue(self, msgid, params):
        return self._monitor(['queue_id', 'port_no'],
                             self.monitored_queues,
                             self._queue_stats_generator,
                             msgid, params)

    def _query_secure_channel_state(self, msgid, params):
        return self._get_secure_channel_state_param()

    def _query_port_desc_stats(self, msgid, params):
        try:
            param_dict = params[0]
            port_no = param_dict.get('port_no')
        except:
            port_no = None

        results = []
        for k, v in self.dpset.get_all():
            for p in self.dpset.get_ports(k):
                if port_no is not None and port_no != p.port_no:
                    continue
                d = p.to_jsondict()
                d['OFPPort']['name'] = d['OFPPort']['name'].encode('ascii')
                d['OFPPort']['hw_addr'] = \
                    d['OFPPort']['hw_addr'].encode('ascii')
                results.append(d)
        return results
