# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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

from ryu.app.rest_nw_id import NW_ID_UNKNOWN, NW_ID_EXTERNAL
from ryu.exception import MacAddressDuplicated
from ryu.exception import PortUnknown
from ryu.controller import event
from ryu.controller import mac_to_network
from ryu.controller import mac_to_port
from ryu.controller.handler import main_dispatcher
from ryu.controller.handler import config_dispatcher
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import haddr_to_str

LOG = logging.getLogger('ryu.app.simple_isolation')


class SimpleIsolation(object):
    def __init__(self, *args, **kwargs):
        self.nw = kwargs['network']
        self.mac2port = mac_to_port.MacToPortTable()
        self.mac2net = mac_to_network.MacToNetwork(self.nw)

    @set_ev_cls(event.EventOFPSwitchFeatures, config_dispatcher)
    def switch_features_handler(self, ev):
        self.mac2port.dpid_add(ev.msg.datapath_id)
        self.nw.add_datapath(ev.msg)

    @set_ev_cls(event.EventOFPBarrierReply)
    def barrier_reply_handler(ev):
        LOG.debug('barrier reply ev %s msg %s', ev, ev.msg)

    def _modflow_and_send_packet(self, msg, src, dst, actions):
        datapath = msg.datapath

        #
        # install flow and then send packet
        #
        wildcards = datapath.ofproto.OFPFW_ALL
        wildcards &= ~(datapath.ofproto.OFPFW_IN_PORT |
                       datapath.ofproto.OFPFW_DL_SRC |
                       datapath.ofproto.OFPFW_DL_DST)
        match = datapath.ofproto_parser.OFPMatch(wildcards,
                                                 msg.in_port, src, dst,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0)

        datapath.send_flow_mod(
            match=match, cookie=0, command=datapath.ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0, priority=32768,
            buffer_id=0xffffffff, out_port=datapath.ofproto.OFPP_NONE,
            flags=datapath.ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)

    def _forward_to_nw_id(self, msg, src, dst, nw_id, out_port):
        assert out_port is not None
        datapath = msg.datapath

        if not self.nw.same_network(datapath.id, nw_id, out_port,
                                    NW_ID_EXTERNAL):
            LOG.debug('packet is blocked src %s dst %s '
                      'from %d to %d on datapath %d',
                      haddr_to_str(src), haddr_to_str(dst),
                      msg.in_port, out_port, datapath.id)
            return

        LOG.debug("learned dpid %s in_port %d out_port %d src %s dst %s",
                  datapath.id, msg.in_port, out_port,
                  haddr_to_str(src), haddr_to_str(dst))
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        self._modflow_and_send_packet(msg, src, dst, actions)

    def _flood_to_nw_id(self, msg, src, dst, nw_id):
        datapath = msg.datapath
        actions = []
        LOG.debug("dpid %s in_port %d src %s dst %s ports %s",
                  datapath.id, msg.in_port,
                  haddr_to_str(src), haddr_to_str(dst),
                  self.nw.dpids.get(datapath.id, {}).items())
        for port_no in self.nw.filter_ports(datapath.id, msg.in_port,
                                            nw_id, NW_ID_EXTERNAL):
            LOG.debug("port_no %s", port_no)
            actions.append(datapath.ofproto_parser.OFPActionOutput(port_no))
        self._modflow_and_send_packet(msg, src, dst, actions)

    def _learned_mac_or_flood_to_nw_id(self, msg, src, dst,
                                       dst_nw_id, out_port):
        if out_port is not None:
            self._forward_to_nw_id(msg, src, dst, dst_nw_id, out_port)
        else:
            self._flood_to_nw_id(msg, src, dst, dst_nw_id)

    @set_ev_cls(event.EventOFPPacketIn, main_dispatcher)
    def packet_in_handler(self, ev):
        # LOG.debug('packet in ev %s msg %s', ev, ev.msg)
        msg = ev.msg
        datapath = msg.datapath

        dst, src, eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        try:
            port_nw_id = self.nw.get_network(datapath.id, msg.in_port)
        except PortUnknown:
            port_nw_id = NW_ID_UNKNOWN

        if port_nw_id != NW_ID_UNKNOWN:
            # Here it is assumed that the
            # (port <-> network id)/(mac <-> network id) relationship
            # is stable once the port is created. The port will be destroyed
            # before assigning new network id to the given port.
            # This is correct nova-network/nova-compute.
            try:
                # allow external -> known nw id change
                self.mac2net.add_mac(src, port_nw_id, NW_ID_EXTERNAL)
            except MacAddressDuplicated:
                LOG.warn('mac address %s is already in use.'
                         ' So (dpid %s, port %s) can not use it',
                         haddr_to_str(src), datapath.id, msg.in_port)
                #
                # should we install drop action pro-actively for future?
                #
                return

        old_port = self.mac2port.port_add(datapath.id, msg.in_port, src)
        if old_port is not None and old_port != msg.in_port:
            # We really overwrite already learned mac address.
            # So discard already installed stale flow entry which conflicts
            # new port.
            wildcards = datapath.ofproto.OFPFW_ALL
            wildcards &= ~datapath.ofproto.OFPFW_DL_DST
            match = datapath.ofproto_parser.OFPMatch(wildcards,
                                                     0, 0, src,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 0)

            datapath.send_flow_mod(match=match, cookie=0,
                command=datapath.ofproto.OFPFC_DELETE, idle_timeout=0,
                hard_timeout=0, priority=32768, out_port=old_port)

            # to make sure the old flow entries are purged.
            datapath.send_barrier()

        src_nw_id = self.mac2net.get_network(src, NW_ID_UNKNOWN)
        dst_nw_id = self.mac2net.get_network(dst, NW_ID_UNKNOWN)

        # we handle multicast packet as same as broadcast
        first_oct = struct.unpack_from('B', dst)[0]
        broadcast = (dst == '\xff' * 6) or (first_oct & 0x01)
        out_port = self.mac2port.port_get(datapath.id, dst)

        #
        # there are several combinations:
        # in_port: known nw_id, external, unknown nw,
        # src mac: known nw_id, external, unknown nw,
        # dst mac: known nw_id, external, unknown nw, and broadcast/multicast
        # where known nw_id: is quantum network id
        #       external: means that these ports are connected to outside
        #       unknown nw: means that we don't know this port is bounded to
        #                   specific nw_id or external
        #       broadcast: the destination mac address is broadcast address
        #                  (or multicast address)
        #
        # Can the following logic be refined/shortened?
        #

        if port_nw_id != NW_ID_EXTERNAL and port_nw_id != NW_ID_UNKNOWN:
            if broadcast:
                # flood to all ports of external or src_nw_id
                self._flood_to_nw_id(msg, src, dst, src_nw_id)
            elif src_nw_id != NW_ID_EXTERNAL and src_nw_id != NW_ID_UNKNOWN:
                # try learned mac check if the port is net_id
                # or
                # flood to all ports of external or src_nw_id
                self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                    src_nw_id, out_port)
            else:
                # NW_ID_EXTERNAL or NW_ID_UNKNOWN
                # drop packets
                return

        elif port_nw_id == NW_ID_EXTERNAL:
            if src_nw_id != NW_ID_EXTERNAL and src_nw_id != NW_ID_UNKNOWN:
                if broadcast:
                    # flood to all ports of external or src_nw_id
                    self._flood_to_nw_id(msg, src, dst, src_nw_id)
                elif (dst_nw_id != NW_ID_EXTERNAL and
                      dst_nw_id != NW_ID_UNKNOWN):
                    if src_nw_id == dst_nw_id:
                        # try learned mac
                        # check if the port is external or same net_id
                        # or
                        # flood to all ports of external or src_nw_id
                        self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                            src_nw_id,
                                                            out_port)
                    else:
                        # should not occur?
                        LOG.debug("should this case happen?")
                elif dst_nw_id == NW_ID_EXTERNAL:
                    # try learned mac
                    # or
                    # flood to all ports of external or src_nw_id
                    self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                        src_nw_id, out_port)
                else:
                    assert dst_nw_id == NW_ID_UNKNOWN

            elif src_nw_id == NW_ID_EXTERNAL:
                # drop packet
                pass
            else:
                # should not occur?
                # drop packets
                assert src_nw_id == NW_ID_UNKNOWN
        else:
            # drop packets?
            assert port_nw_id == NW_ID_UNKNOWN

    @set_ev_cls(event.EventOFPPortStatus, main_dispatcher)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        datapath.send_delete_all_flows()
        datapath.send_barrier()

    @set_ev_cls(event.EventOFPBarrierReply, main_dispatcher)
    def barrier_replay_handler(self, ev):
        pass
