"""
Define some utils functions.
"""
import logging


LOG = logging.getLogger('ryu.openexchange.utils')


def add_flow(dp, p, match, actions, idle_timeout=0, hard_timeout=0):
    ofproto = dp.ofproto
    parser = dp.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    mod = parser.OFPFlowMod(datapath=dp, priority=p,
                            idle_timeout=idle_timeout,
                            hard_timeout=hard_timeout,
                            match=match, instructions=inst)
    dp.send_msg(mod)


def get_link2port(link_to_port, src_dpid, dst_dpid):
    if (src_dpid, dst_dpid) in link_to_port:
        return link_to_port[(src_dpid, dst_dpid)]
    else:
        LOG.debug("Link to port is not found.")
        return None


def send_packet_out(datapath, buffer_id, src_port, dst_port, data):
    msg_data = None
    actions = []
    actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

    if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
        msg_data = data

    out = datapath.ofproto_parser.OFPPacketOut(
        datapath=datapath, buffer_id=buffer_id,
        data=msg_data, in_port=src_port, actions=actions)

    datapath.send_msg(out)


def send_flow_mod(datapath, flow_info, src_port, dst_port):
    parser = datapath.ofproto_parser
    actions = []
    actions.append(parser.OFPActionOutput(dst_port))

    match = parser.OFPMatch(
        in_port=src_port, eth_type=flow_info[0],
        ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

    add_flow(datapath, 1, match, actions, idle_timeout=10, hard_timeout=30)


def install_flow(datapaths, link2port, access_table,
                 path, flow_info, buffer_id, data):
    ''' path=[dpid1, dpid2, dpid3...]
        flow_info=(eth_type, src_ip, dst_ip, in_port)
    '''
    # first flow entry
    in_port = flow_info[3]
    assert path
    first_dp = datapaths[path[0]]
    ofproto = first_dp.ofproto
    parser = first_dp.ofproto_parser
    out_port = ofproto.OFPP_LOCAL

    # inter_link
    if len(path) > 2:
        for i in xrange(1, len(path) - 1):
            port = get_link2port(link2port, path[i-1], path[i])
            port_next = get_link2port(link2port, path[i], path[i + 1])
            if port:
                src_port, dst_port = port[1], port_next[0]
                datapath = datapaths[path[i]]
                send_flow_mod(datapath, flow_info, src_port, dst_port)
                send_packet_out(datapath, buffer_id, src_port, dst_port, data)
    if len(path) > 1:
        # the  first flow entry
        port_pair = get_link2port(link2port, path[0], path[1])
        out_port = port_pair[0]
        send_flow_mod(first_dp, flow_info, in_port, out_port)

        # the last hop: tor -> host
        datapath = datapaths[path[-1]]
        src_port = get_link2port(link2port, path[-2], path[-1])[1]
        dst_port = None
        for key in access_table.keys():
            if flow_info[2] == access_table[key][0]:
                dst_port = key[1]
                break
        send_flow_mod(datapath, flow_info, src_port, dst_port)
        # first and last pkt_out
        send_packet_out(first_dp, buffer_id, in_port, out_port, data)
        send_packet_out(datapath, buffer_id, src_port, dst_port, data)
    else:  # src and dst on the same
        for key in access_table.keys():
            if flow_info[2] == access_table[key][0]:
                out_port = key[1]
                break

        send_flow_mod(first_dp, flow_info, in_port, out_port)
        send_packet_out(first_dp, buffer_id, in_port, out_port, data)
