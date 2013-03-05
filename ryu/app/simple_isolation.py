# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import struct

from ryu.app.rest_nw_id import NW_ID_UNKNOWN, NW_ID_EXTERNAL
from ryu.base import app_manager
from ryu.exception import MacAddressDuplicated
from ryu.exception import PortUnknown
from ryu.controller import dpset
from ryu.controller import mac_to_network
from ryu.controller import mac_to_port
from ryu.controller import network
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import nx_match
from ryu.lib.mac import haddr_to_str
from ryu.lib import mac


class SimpleIsolation(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleIsolation, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        self.dpset = kwargs['dpset']
        self.mac2port = mac_to_port.MacToPortTable()
        self.mac2net = mac_to_network.MacToNetwork(self.nw)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        datapath.send_delete_all_flows()
        datapath.send_barrier()

        self.mac2port.dpid_add(ev.msg.datapath_id)
        self.nw.add_datapath(ev.msg)

    @staticmethod
    def _modflow_and_send_packet(msg, src, dst, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto

        #
        # install flow and then send packet
        #
        rule = nx_match.ClsRule()
        rule.set_in_port(msg.in_port)
        rule.set_dl_dst(dst)
        rule.set_dl_src(src)
        datapath.send_flow_mod(
            rule=rule, cookie=0, command=datapath.ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            buffer_id=0xffffffff, out_port=ofproto.OFPP_NONE,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)

    def _forward_to_nw_id(self, msg, src, dst, nw_id, out_port):
        assert out_port is not None
        datapath = msg.datapath

        if not self.nw.same_network(datapath.id, nw_id, out_port,
                                    NW_ID_EXTERNAL):
            self.logger.debug('packet is blocked src %s dst %s '
                              'from %d to %d on datapath %d',
                              haddr_to_str(src), haddr_to_str(dst),
                              msg.in_port, out_port, datapath.id)
            return

        self.logger.debug("learned dpid %s in_port %d out_port "
                          "%d src %s dst %s",
                          datapath.id, msg.in_port, out_port,
                          haddr_to_str(src), haddr_to_str(dst))
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        self._modflow_and_send_packet(msg, src, dst, actions)

    def _flood_to_nw_id(self, msg, src, dst, nw_id):
        datapath = msg.datapath
        actions = []
        self.logger.debug("dpid %s in_port %d src %s dst %s ports %s",
                          datapath.id, msg.in_port,
                          haddr_to_str(src), haddr_to_str(dst),
                          self.nw.dpids.get(datapath.id, {}).items())
        for port_no in self.nw.filter_ports(datapath.id, msg.in_port,
                                            nw_id, NW_ID_EXTERNAL):
            self.logger.debug("port_no %s", port_no)
            actions.append(datapath.ofproto_parser.OFPActionOutput(port_no))
        self._modflow_and_send_packet(msg, src, dst, actions)

    def _learned_mac_or_flood_to_nw_id(self, msg, src, dst,
                                       dst_nw_id, out_port):
        if out_port is not None:
            self._forward_to_nw_id(msg, src, dst, dst_nw_id, out_port)
        else:
            self._flood_to_nw_id(msg, src, dst, dst_nw_id)

    def _modflow_and_drop_packet(self, msg, src, dst):
        self._modflow_and_send_packet(msg, src, dst, [])

    def _drop_packet(self, msg):
        datapath = msg.datapath
        datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # self.logger.debug('packet in ev %s msg %s', ev, ev.msg)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

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
                self.logger.warn('mac address %s is already in use.'
                                 ' So (dpid %s, port %s) can not use it',
                                 haddr_to_str(src), datapath.id, msg.in_port)
                #
                # should we install drop action pro-actively for future?
                #
                self._drop_packet(msg)
                return

        old_port = self.mac2port.port_add(datapath.id, msg.in_port, src)
        if old_port is not None and old_port != msg.in_port:
            # We really overwrite already learned mac address.
            # So discard already installed stale flow entry which conflicts
            # new port.
            rule = nx_match.ClsRule()
            rule.set_dl_dst(src)
            datapath.send_flow_mod(rule=rule,
                                   cookie=0,
                                   command=ofproto.OFPFC_DELETE,
                                   idle_timeout=0,
                                   hard_timeout=0,
                                   priority=ofproto.OFP_DEFAULT_PRIORITY,
                                   out_port=old_port)

            # to make sure the old flow entries are purged.
            datapath.send_barrier()

        src_nw_id = self.mac2net.get_network(src, NW_ID_UNKNOWN)
        dst_nw_id = self.mac2net.get_network(dst, NW_ID_UNKNOWN)

        # we handle multicast packet as same as broadcast
        broadcast = (dst == mac.BROADCAST) or mac.is_multicast(dst)
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

        # When NW_ID_UNKNOWN is found, registering ports might be delayed.
        # So just drop only this packet and not install flow entry.
        # It is expected that when next packet arrives, the port is registers
        # with some network id

        if port_nw_id != NW_ID_EXTERNAL and port_nw_id != NW_ID_UNKNOWN:
            if broadcast:
                # flood to all ports of external or src_nw_id
                self._flood_to_nw_id(msg, src, dst, src_nw_id)
            elif src_nw_id == NW_ID_EXTERNAL:
                self._modflow_and_drop_packet(msg, src, dst)
                return
            elif src_nw_id == NW_ID_UNKNOWN:
                self._drop_packet(msg)
                return
            else:
                # src_nw_id != NW_ID_EXTERNAL and src_nw_id != NW_ID_UNKNOWN:
                #
                # try learned mac check if the port is net_id
                # or
                # flood to all ports of external or src_nw_id
                self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                    src_nw_id, out_port)

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
                        self.logger.debug("should this case happen?")
                        self._drop_packet(msg)
                elif dst_nw_id == NW_ID_EXTERNAL:
                    # try learned mac
                    # or
                    # flood to all ports of external or src_nw_id
                    self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                        src_nw_id, out_port)
                else:
                    assert dst_nw_id == NW_ID_UNKNOWN
                    self.logger.debug("Unknown dst_nw_id")
                    self._drop_packet(msg)
            elif src_nw_id == NW_ID_EXTERNAL:
                self._modflow_and_drop_packet(msg, src, dst)
            else:
                # should not occur?
                assert src_nw_id == NW_ID_UNKNOWN
                self._drop_packet(msg)
        else:
            # drop packets
            assert port_nw_id == NW_ID_UNKNOWN
            self._drop_packet(msg)
            # self.logger.debug("Unknown port_nw_id")

    def _port_add(self, ev):
        #
        # delete flows entries that matches with
        # dl_dst == broadcast/multicast
        # and dl_src = network id if network id of this port is known
        # to send broadcast packet to this newly added port.
        #
        # Openflow v1.0 doesn't support masked match of dl_dst,
        # so delete all flow entries. It's inefficient, though.
        #
        msg = ev.msg
        datapath = msg.datapath

        datapath.send_delete_all_flows()
        datapath.send_barrier()
        self.nw.port_added(datapath, msg.desc.port_no)

    def _port_del(self, ev):
        # free mac addresses associated to this VM port,
        # and delete related flow entries for later reuse of mac address

        dps_needs_barrier = set()

        msg = ev.msg
        datapath = msg.datapath
        datapath_id = datapath.id
        port_no = msg.desc.port_no

        rule = nx_match.ClsRule()
        rule.set_in_port(port_no)
        datapath.send_flow_del(rule=rule, cookie=0)

        rule = nx_match.ClsRule()
        datapath.send_flow_del(rule=rule, cookie=0, out_port=port_no)
        dps_needs_barrier.add(datapath)

        try:
            port_nw_id = self.nw.get_network(datapath_id, port_no)
        except PortUnknown:
            # race condition between rest api delete port
            # and openflow port deletion ofp_event
            pass
        else:
            if port_nw_id in (NW_ID_UNKNOWN, NW_ID_EXTERNAL):
                datapath.send_barrier()
                return

        for mac_ in self.mac2port.mac_list(datapath_id, port_no):
            for (_dpid, dp) in self.dpset.get_all():
                if self.mac2port.port_get(dp.id, mac_) is None:
                    continue

                rule = nx_match.ClsRule()
                rule.set_dl_src(mac_)
                dp.send_flow_del(rule=rule, cookie=0)

                rule = nx_match.ClsRule()
                rule.set_dl_dst(mac_)
                dp.send_flow_del(rule=rule, cookie=0)
                dps_needs_barrier.add(dp)

                self.mac2port.mac_del(dp.id, mac_)

            self.mac2net.del_mac(mac_)

        self.nw.port_deleted(datapath.id, port_no)

        for dp in dps_needs_barrier:
            dp.send_barrier()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        ofproto = msg.datapath.ofproto

        if reason == ofproto.OFPPR_ADD:
            self._port_add(ev)
        elif reason == ofproto.OFPPR_DELETE:
            self._port_del(ev)
        else:
            assert reason == ofproto.OFPPR_MODIFY
