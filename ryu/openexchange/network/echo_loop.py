"""
Define the community machanism.
Author:www.muzixing.com

Date                Work
2015/8/5            define echo loop

"""
from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER

from ryu.openexchange import oxp_event
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange import oxproto_v1_0_parser

from ryu import cfg
from ryu.lib import hub
import time

CONF = cfg.CONF


class EchoLoop(app_manager.RyuApp):
    """EchoLoop handle the echo message."""

    def __init__(self, *args, **kwargs):
        super(EchoLoop, self).__init__(*args, **kwargs)
        self.name = 'oxp_echo_loop'
        self.args = args
        self.domain = None
        self.oxparser = oxproto_v1_0_parser
        self.oxproto = oxproto_v1_0
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            self.echo_reply()
            hub.sleep(CONF.oxp_period)

    @set_ev_cls(oxp_event.EventOXPFeaturesRequest, CONFIG_DISPATCHER)
    def features_request_handler(self, ev):
        msg = ev.msg
        # Only to get domain.
        self.domain = msg.domain
        self.oxproto = self.domain.oxproto
        self.oxparser = self.domain.oxproto_parser

    @set_ev_handler(oxp_event.EventOXPEchoRequest,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_request_handler(self, ev):
        msg = ev.msg
        domain = msg.domain
        echo_reply = domain.oxproto_parser.OXPEchoReply(domain)
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        domain.send_msg(echo_reply)

    def echo_reply(self):
        if self.domain is not None:
            echo_reply = self.domain.oxproto_parser.OXPEchoReply(self.domain)
            echo_reply.data = str(time.time())
            self.domain.send_msg(echo_reply)
