# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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

from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import vrrp
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.services.protocols.vrrp import monitor
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import utils


@monitor.VRRPInterfaceMonitor.register(vrrp_event.VRRPInterfaceOpenFlow)
class VRRPInterfaceMonitorOpenFlow(monitor.VRRPInterfaceMonitor):
    # OF1.2
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]   # probably work with OF1.3

    _TABLE = 0          # generate packet-in in this table
    _PRIORITY = 0x8000  # default priority

    def __init__(self, *args, **kwargs):
        super(VRRPInterfaceMonitorOpenFlow, self).__init__(*args, **kwargs)
        table = kwargs.get('vrrp_imof_table', None)
        if table is not None:
            self._TABLE = int(table)
        priority = kwargs.get('vrrp_imof_priority', None)
        if priority is not None:
            self._PRIORITY = int(priority)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.logger.debug('packet_in_handler')
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        # TODO: subscribe only the designated datapath
        dpid = datapath.id
        if dpid != self.interface.dpid:
            self.logger.debug('packet_in_handler dpid %s %s',
                              dpid_lib.dpid_to_str(dpid),
                              dpid_lib.dpid_to_str(self.interface.dpid))
            return

        in_port = None
        for field in msg.match.fields:
            if field.header == ofproto.OXM_OF_IN_PORT:
                in_port = field.value
                break

        if in_port != self.interface.port_no:
            self.logger.debug('packet_in_handler in_port %s %s',
                              in_port, self.interface.port_no)
            return

        self._send_vrrp_packet_received(msg.data)

    def _get_dp(self):
        return utils.get_dp(self, self.interface.dpid)

    @handler.set_ev_handler(vrrp_event.EventVRRPTransmitRequest)
    def vrrp_transmit_request_handler(self, ev):
        dp = self._get_dp()
        if not dp:
            return
        utils.dp_packet_out(dp, self.interface.port_no, ev.data)

    def _ofp_match(self, ofproto_parser):
        is_ipv6 = vrrp.is_ipv6(self.config.ip_addresses[0])
        kwargs = {}
        kwargs['in_port'] = self.interface.port_no
        if is_ipv6:
            kwargs['eth_dst'] = vrrp.VRRP_IPV6_DST_MAC_ADDRESS
            kwargs['eth_src'] = \
                vrrp.vrrp_ipv6_src_mac_address(self.config.vrid)
            kwargs['eth_type'] = ether.ETH_TYPE_IPV6
            kwargs['ipv6_dst'] = vrrp.VRRP_IPV6_DST_ADDRESS
        else:
            kwargs['eth_dst'] = vrrp.VRRP_IPV4_DST_MAC_ADDRESS
            kwargs['eth_src'] = \
                vrrp.vrrp_ipv4_src_mac_address(self.config.vrid)
            kwargs['eth_type'] = ether.ETH_TYPE_IP
            kwargs['ipv4_dst'] = vrrp.VRRP_IPV4_DST_ADDRESS

        if self.interface.vlan_id is not None:
            kwargs['vlan_vid'] = self.interface.vlan_id
        kwargs['ip_proto'] = inet.IPPROTO_VRRP
        # OF1.2 doesn't support TTL match.
        # It needs to be checked by packet in handler

        return ofproto_parser.OFPMatch(**kwargs)

    def _initialize(self):
        dp = self._get_dp()
        if not dp:
            return

        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser

        match = self._ofp_match(ofproto_parser)
        utils.dp_flow_mod(dp, self._TABLE, ofproto.OFPFC_DELETE_STRICT,
                          self._PRIORITY, match, [],
                          out_port=ofproto.OFPP_CONTROLLER)

        match = self._ofp_match(ofproto_parser)
        actions = [ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                  ofproto.OFPCML_NO_BUFFER)]
        instructions = [ofproto_parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        utils.dp_flow_mod(dp, self._TABLE, ofproto.OFPFC_ADD, self._PRIORITY,
                          match, instructions)

    def _shutdown(self):
        dp = self._get_dp()
        if not dp:
            return

        ofproto = dp.ofproto
        match = self._ofp_match(dp.ofproto_parser)
        utils.dp_flow_mod(dp, self._TABLE, ofproto.OFPFC_DELETE_STRICT,
                          self._PRIORITY, match, [],
                          out_port=ofproto.OFPP_CONTROLLER)
