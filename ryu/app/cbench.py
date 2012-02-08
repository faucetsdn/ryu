# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls


class Cbench(object):
    def __init__(self, *_args, **kwargs):
        pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(ofproto.OFPFW_ALL,
                                                 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0)

        datapath.send_flow_mod(
            match=match, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0, priority=32768,
            flags=0, actions=None)
