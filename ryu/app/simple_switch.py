# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import struct

from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import haddr_to_str


LOG = logging.getLogger('ryu.app.simple_switch')

# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


class SimpleSwitch(object):
    def __init__(self, *_args, **_kwargs):
        self.mac2port = mac_to_port.MacToPortTable()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
        self.mac2port.dpid_add(dpid)
        LOG.info("packet in %s %s %s %s",
                 dpid, haddr_to_str(src), haddr_to_str(dst), msg.in_port)

        self.mac2port.port_add(dpid, msg.in_port, src)
        out_port = self.mac2port.port_get(dpid, dst)

        if out_port == None:
            LOG.info("out_port not found")
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            wildcards = ofproto.OFPFW_ALL
            wildcards &= ~(ofproto.OFPFW_IN_PORT |
                           ofproto.OFPFW_DL_DST |
                           ofproto.OFPFW_NW_TOS)
            match = datapath.ofproto_parser.OFPMatch(
                wildcards, msg.in_port,
                0, dst,
                0, 0, 0, 0, 0, 0, 0, 0, 0)

            datapath.send_flow_mod(
                match=match, cookie=0, command=ofproto.OFPFC_ADD,
                idle_timeout=0, hard_timeout=0, priority=32768,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            LOG.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            LOG.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info("port modified %s", port_no)
        else:
            LOG.info("Illeagal port state %s %s", port_no, reason)
