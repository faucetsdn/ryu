def install_flow(self, path, flow_info, buffer_id, data):
    '''
        path=[dpid1, dpid2, dpid3...]
        flow_info=(eth_type, src_ip, dst_ip, in_port)
    '''
    # first flow entry
    in_port = flow_info[3]
    assert path
    datapath_first = self.datapaths[path[0]]
    ofproto = datapath_first.ofproto
    parser = datapath_first.ofproto_parser
    out_port = ofproto.OFPP_LOCAL

    # inter_link
    if len(path) > 2:
        for i in xrange(1, len(path) - 1):
            port = self.get_link2port(path[i - 1], path[i])
            port_next = self.get_link2port(path[i], path[i + 1])
            if port:
                src_port, dst_port = port[1], port_next[0]
                datapath = self.datapaths[path[i]]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                actions = []

                actions.append(parser.OFPActionOutput(dst_port))
                match = parser.OFPMatch(
                    in_port=src_port,
                    eth_type=flow_info[0],
                    ipv4_src=flow_info[1],
                    ipv4_dst=flow_info[2])
                self.add_flow(
                    datapath, 1, match, actions,
                    idle_timeout=10, hard_timeout=30)

                # inter links pkt_out
                msg_data = None
                if buffer_id == ofproto.OFP_NO_BUFFER:
                    msg_data = data

                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=buffer_id,
                    data=msg_data, in_port=src_port, actions=actions)

                datapath.send_msg(out)

    if len(path) > 1:
        # the  first flow entry
        port_pair = self.get_link2port(path[0], path[1])
        out_port = port_pair[0]

        actions = []
        actions.append(parser.OFPActionOutput(out_port))
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=flow_info[0],
            ipv4_src=flow_info[1],
            ipv4_dst=flow_info[2])
        self.add_flow(datapath_first,
                      1, match, actions, idle_timeout=10, hard_timeout=30)

        # the last hop: tor -> host
        datapath = self.datapaths[path[-1]]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []
        src_port = self.get_link2port(path[-2], path[-1])[1]
        dst_port = None

        for key in self.access_table.keys():
            if flow_info[2] == self.access_table[key][0]:
                dst_port = key[1]
                break
        actions.append(parser.OFPActionOutput(dst_port))
        match = parser.OFPMatch(
            in_port=src_port,
            eth_type=flow_info[0],
            ipv4_src=flow_info[1],
            ipv4_dst=flow_info[2])

        self.add_flow(
            datapath, 1, match, actions, idle_timeout=10, hard_timeout=30)

        # first pkt_out
        actions = []

        actions.append(parser.OFPActionOutput(out_port))
        msg_data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            msg_data = data

        out = parser.OFPPacketOut(
            datapath=datapath_first, buffer_id=buffer_id,
            data=msg_data, in_port=in_port, actions=actions)

        datapath_first.send_msg(out)

        # last pkt_out
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))
        msg_data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            msg_data = data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)

        datapath.send_msg(out)

    else:  # src and dst on the same
        out_port = None
        actions = []
        for key in self.access_table.keys():
            if flow_info[2] == self.access_table[key][0]:
                out_port = key[1]
                break

        actions.append(parser.OFPActionOutput(out_port))
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=flow_info[0],
            ipv4_src=flow_info[1],
            ipv4_dst=flow_info[2])
        self.add_flow(
            datapath_first, 1, match, actions,
            idle_timeout=10, hard_timeout=30)

        # pkt_out
        msg_data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            msg_data = data

        out = parser.OFPPacketOut(
            datapath=datapath_first, buffer_id=buffer_id,
            data=msg_data, in_port=in_port, actions=actions)

        datapath_first.send_msg(out)
