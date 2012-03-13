# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import nx_match


class Cbench(object):
    def __init__(self, *_args, **kwargs):
        pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        rule = nx_match.ClsRule()
        datapath.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0, priority=32768,
            flags=0, actions=None)
