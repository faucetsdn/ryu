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

"""
router implementation base class
a template for router implementation that support VRRP
Those routers needs to be created by someone else.
sample_manager.routerManager is an example.
Usage example:
PYTHONPATH=. ./bin/ryu-manager --verbose \
             ryu.services.protocols.vrrp.manager \
             ryu.services.protocols.vrrp.dumper \
             ryu.services.protocols.vrrp.sample_manager
"""

import contextlib
import greenlet
import socket

from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.lib import hub
from ryu.lib import mac as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet import vlan
from ryu.lib.packet import vrrp
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_2
from ryu.services.protocols.vrrp import api as vrrp_api
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import utils


class RouterBase(app_manager.RyuApp):
    def _router_name(self, config, interface):
        ip_version = 'ipv6' if config.is_ipv6 else 'ipv4'
        return '%s-%s-%d-%s' % (self.__class__.__name__,
                                str(interface), config.vrid, ip_version)

    def __init__(self, *args, **kwargs):
        super(RouterBase, self).__init__(*args, **kwargs)
        self.instance_name = kwargs['name']
        self.monitor_name = kwargs['monitor_name']
        self.config = kwargs['config']
        self.interface = kwargs['interface']
        self.name = self._router_name(self.config, self.interface)

    def _transmit(self, data):
        vrrp_api.vrrp_transmit(self, self.monitor_name, data)

    def _initialized(self):
        self.logger.debug('initialized')

    def _initialized_to_master(self):
        self.logger.debug('initialized to master')
        # RFC3768 6.4.1
        # o  Broadcast a gratuitous ARP request containing the virtual
        # router MAC address for each IP address associated with the
        # virtual router.
        #
        # or
        #
        # RFC 5795 6.4.1
        # (115)+ If the protected IPvX address is an IPv4 address, then:
        #   (120) * Broadcast a gratuitous ARP request containing the
        #   virtual router MAC address for each IP address associated
        #   with the virtual router.
        # (125) + else // IPv6
        #   (130) * For each IPv6 address associated with the virtual
        #   router, send an unsolicited ND Neighbor Advertisement with
        #   the Router Flag (R) set, the Solicited Flag (S) unset, the
        #   Override flag (O) set, the target address set to the IPv6
        #   address of the virtual router, and the target link-layer
        #   address set to the virtual router MAC address.

    def _become_master(self):
        self.logger.debug('become master')
        # RFC3768 6.4.2
        # o  Broadcast a gratuitous ARP request containing the virtual
        #    router MAC address for each IP address associated with the
        #    virtual router
        #
        # or
        #
        # RFC 5795 6.4.2
        # (375)+ If the protected IPvX address is an IPv4 address, then:
        #   (380)* Broadcast a gratuitous ARP request on that interface
        #   containing the virtual router MAC address for each IPv4
        #   address associated with the virtual router.
        # (385) + else // ipv6
        #   (390) * Compute and join the Solicited-Node multicast
        #   address [RFC4291] for the IPv6 address(es) associated with
        #   the virtual router.
        #   (395) * For each IPv6 address associated with the virtual
        #   router, send an unsolicited ND Neighbor Advertisement with
        #   the Router Flag (R) set, the Solicited Flag (S) unset, the
        #   Override flag (O) set, the target address set to the IPv6
        #   address of the virtual router, and the target link-layer
        #   address set to the virtual router MAC address.

    def _become_backup(self):
        self.logger.debug('become backup')
        # RFC 3768 6.4.2 Backup
        # -  MUST NOT respond to ARP requests for the IP address(s)
        #    associated with the virtual router.
        # -  MUST discard packets with a destination link layer MAC address
        #    equal to the virtual router MAC address.
        # -  MUST NOT accept packets addressed to the IP address(es)
        #    associated with the virtual router.
        #
        # or
        #
        # RFC 5798 6.4.2 Backup
        # (305) - If the protected IPvX address is an IPv4 address, then:
        #   (310) + MUST NOT respond to ARP requests for the IPv4
        #   address(es) associated with the virtual router.
        # (315) - else // protected addr is IPv6
        #   (320) + MUST NOT respond to ND Neighbor Solicitation messages
        #   for the IPv6 address(es) associated with the virtual router.
        #   (325) + MUST NOT send ND Router Advertisement messages for the
        #   virtual router.
        # (330) -endif // was protected addr IPv4?
        # (335) - MUST discard packets with a destination link-layer MAC
        # address equal to the virtual router MAC address.
        # (340) - MUST NOT accept packets addressed to the IPvX address(es)
        # associated with the virtual router.

    def _shutdowned(self):
        self.logger.debug('shutdowned')

    @handler.set_ev_handler(vrrp_event.EventVRRPStateChanged)
    def vrrp_state_changed_handler(self, ev):
        old_state = ev.old_state
        new_state = ev.new_state
        self.logger.debug('sample router %s -> %s', old_state, new_state)
        if new_state == vrrp_event.VRRP_STATE_MASTER:
            if old_state == vrrp_event.VRRP_STATE_INITIALIZE:
                self._initialized_to_master()
            elif old_state == vrrp_event.VRRP_STATE_BACKUP:
                self._become_master()

            # RFC 3768 6.4.3
            # -  MUST respond to ARP requests for the IP address(es) associated
            #    with the virtual router.
            # -  MUST forward packets with a destination link layer MAC address
            #    equal to the virtual router MAC address.
            # -  MUST NOT accept packets addressed to the IP address(es)
            #    associated with the virtual router if it is not the IP address
            #    owner.
            # -  MUST accept packets addressed to the IP address(es) associated
            #    with the virtual router if it is the IP address owner.
            #
            # or
            #
            # RFC5798 6.4.3
            # (605) - If the protected IPvX address is an IPv4 address, then:
            #   (610) + MUST respond to ARP requests for the IPv4 address(es)
            #   associated with the virtual router.
            # (615) - else // ipv6
            #   (620) + MUST be a member of the Solicited-Node multicast
            #   address for the IPv6 address(es) associated with the virtual
            #   router.
            #   (625) + MUST respond to ND Neighbor Solicitation message for
            #   the IPv6 address(es) associated with the virtual router.
            #   (630) ++ MUST send ND Router Advertisements for the virtual
            #   router.
            #   (635) ++ If Accept_Mode is False:  MUST NOT drop IPv6 Neighbor
            #   Solicitations and Neighbor Advertisements.
            # (640) +-endif // ipv4?
            # (645) - MUST forward packets with a destination link-layer MAC
            # address equal to the virtual router MAC address.
            # (650) - MUST accept packets addressed to the IPvX address(es)
            # associated with the virtual router if it is the IPvX address
            # owner or if Accept_Mode is True.  Otherwise, MUST NOT accept
            # these packets.

        elif new_state == vrrp_event.VRRP_STATE_BACKUP:
            self._become_backup()
        elif new_state == vrrp_event.VRRP_STATE_INITIALIZE:
            if old_state is None:
                self._initialized()
            else:
                self._shutdowned()
        else:
            raise ValueError('invalid vrrp state %s' % new_state)


class RouterIPV4(RouterBase):
    def _garp_packet(self, ip_address):
        # prepare garp packet
        src_mac = vrrp.vrrp_ipv4_src_mac_address(self.config.vrid)
        e = ethernet.ethernet(mac_lib.BROADCAST_STR, src_mac,
                              ether.ETH_TYPE_ARP)
        a = arp.arp_ip(arp.ARP_REQUEST, src_mac, ip_address,
                       mac_lib.DONTCARE_STR, ip_address)

        p = packet.Packet()
        p.add_protocol(e)
        utils.may_add_vlan(p, self.interface.vlan_id)
        p.add_protocol(a)
        p.serialize()
        return p

    def __init__(self, *args, **kwargs):
        super(RouterIPV4, self).__init__(*args, **kwargs)
        assert not self.config.is_ipv6

        self.garp_packets = [self._garp_packet(ip_address)
                             for ip_address in self.config.ip_addresses]

    def _send_garp(self):
        self.logger.debug('_send_garp')
        for garp_packet in self.garp_packets:
            self._transmit(garp_packet.data)

    def _arp_reply_packet(self, arp_req_sha, arp_req_spa, arp_req_tpa):
        if not (arp_req_tpa in self.config.ip_addresses or
                arp_req_tpa == self.config.primary_ip_address):
            return None

        src_mac = vrrp.vrrp_ipv4_src_mac_address(self.config.vrid)
        e = ethernet.ethernet(arp_req_sha, src_mac, ether.ETH_TYPE_ARP)
        a = arp.arp_ip(arp.ARP_REPLY, src_mac, arp_req_tpa,
                       arp_req_sha, arp_req_spa)

        p = packet.Packet()
        p.add_protocol(e)
        utils.may_add_vlan(p, self.interface.vlan_id)
        p.add_protocol(a)
        p.serialize()
        self._transmit(p.data)

    def _arp_process(self, data):
        dst_mac = vrrp.vrrp_ipv4_src_mac_address(self.config.vrid)
        arp_sha = None
        arp_spa = None
        arp_tpa = None

        p = packet.Packet(data)
        for proto in p.protocols:
            if isinstance(proto, ethernet.ethernet):
                if proto.dst not in (mac_lib.BROADCAST_STR, dst_mac):
                    return None
                ethertype = proto.ethertype
                if not ((self.interface.vlan_id is None and
                         ethertype == ether.ETH_TYPE_ARP) or
                        (self.interface.vlan_id is not None and
                         ethertype == ether.ETH_TYPE_8021Q)):
                    return None
            elif isinstance(proto, vlan.vlan):
                if (proto.vid != self.interface.vlan_id or
                        proto.ethertype != ether.ETH_TYPE_ARP):
                    return None
            elif isinstance(proto, arp.arp):
                if (proto.hwtype != arp.ARP_HW_TYPE_ETHERNET or
                    proto.proto != ether.ETH_TYPE_IP or
                    proto.hlen != 6 or proto.plen != 4 or
                    proto.opcode != arp.ARP_REQUEST or
                        proto.dst_mac != dst_mac):
                    return None
                arp_sha = proto.src_mac
                arp_spa = proto.src_ip
                arp_tpa = proto.dst_ip
                break

        if arp_sha is None or arp_spa is None or arp_tpa is None:
            self.logger.debug('malformed arp request? arp_sha %s arp_spa %s',
                              arp_sha, arp_spa)
            return None

        self._arp_reply_packet(arp_sha, arp_spa, arp_tpa)


class RouterIPV4Linux(RouterIPV4):
    def __init__(self, *args, **kwargs):
        super(RouterIPV4Linux, self).__init__(*args, **kwargs)
        assert isinstance(self.interface,
                          vrrp_event.VRRPInterfaceNetworkDevice)
        self.__is_master = False
        self._arp_thread = None

    def start(self):
        self._disable_router()
        super(RouterIPV4Linux, self).start()

    def _initialized_to_master(self):
        self.logger.debug('initialized to master')
        self._master()

    def _become_master(self):
        self.logger.debug('become master')
        self._master()

    def _master(self):
        self.__is_master = True
        self._enable_router()
        self._send_garp()

    def _become_backup(self):
        self.logger.debug('become backup')
        self.__is_master = False
        self._disable_router()

    def _shutdowned(self):
        # When VRRP functionality is disabled, what to do?
        #  should we also exit? or continue to route packets?
        self._disable_router()

    def _arp_loop_socket(self, packet_socket):
        while True:
            try:
                buf = packet_socket.recv(1500)
            except socket.timeout:
                continue

            self._arp_process(buf)

    def _arp_loop(self):
        try:
            with contextlib.closing(
                socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW,
                    socket.htons(ether.ETH_TYPE_ARP))) as packet_socket:
                packet_socket.bind((self.interface.device_name,
                                    socket.htons(ether.ETH_TYPE_ARP),
                                    socket.PACKET_BROADCAST,
                                    arp.ARP_HW_TYPE_ETHERNET,
                                    mac_lib.BROADCAST))
                self._arp_loop_socket(packet_socket)
        except greenlet.GreenletExit:
            # suppress thread.kill exception
            pass

    def _enable_router(self):
        if self._arp_thread is None:
            self._arp_thread = hub.spawn(self._arp_loop)
        # TODO: implement real routing logic
        self.logger.debug('TODO:_enable_router')

    def _disable_router(self):
        if self._arp_thread is not None:
            self._arp_thread.kill()
            hub.joinall([self._arp_thread])
            self._arp_thread = None
        # TODO: implement real routing logic
        self.logger.debug('TODO:_disable_router')


class RouterIPV4OpenFlow(RouterIPV4):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    # it must be that
    # _DROP_PRIORITY < monitor.VRRPInterfaceMonitorOpenFlow._PRIORITY or
    # _DROP_TABLE > monitor.VRRPInterfaceMonitorOpenFlow._TABLE
    # to gurantee that VRRP packets are send to controller
    _DROP_TABLE = 0
    _DROP_PRIORITY = 0x8000 / 2

    # it must be that
    # _ARP_PRIORITY < _DROP_PRIORITY or
    # _ARP_TABLE > _DROP_TABLE
    # to gurantee that responding arp can be disabled
    _ARP_TABLE = 0
    _ARP_PRIORITY = _DROP_PRIORITY // 2

    # it must be that
    # _ROUTEING_TABLE < _ARP_TABLE or
    # _ROUTING_TABLE > _ARP_TABLE
    # to gurantee that routing can be disabled
    _ROUTING_TABLE = 0
    _ROUTING_PRIORITY = _ARP_PRIORITY // 2

    def __init__(self, *args, **kwargs):
        super(RouterIPV4OpenFlow, self).__init__(*args, **kwargs)
        assert isinstance(self.interface, vrrp_event.VRRPInterfaceOpenFlow)

    def _get_dp(self):
        return utils.get_dp(self, self.interface.dpid)

    def start(self):
        dp = self._get_dp()
        assert dp
        self._uninstall_route_rule(dp)
        self._uninstall_arp_rule(dp)
        self._uninstall_drop_rule(dp)
        self._install_drop_rule(dp)
        self._install_arp_rule(dp)
        self._install_route_rule(dp)
        super(RouterIPV4OpenFlow, self).start()

    def _initialized_to_master(self):
        self.logger.debug('initialized to master')
        self._master()

    def _become_master(self):
        self.logger.debug('become master')
        self._master()

    def _master(self):
        dp = self._get_dp()
        if dp is None:
            return

        self._uninstall_drop_rule(dp)
        self._send_garp(dp)

    def _become_backup(self):
        self.logger.debug('become backup')
        dp = self._get_dp()
        if dp is None:
            return

        self._install_drop_rule(dp)

    def _shutdowned(self):
        dp = self._get_dp()
        if dp is None:
            return

        # When VRRP functionality is disabled, what to do?
        #  should we also exit? or continue to route packets?
        self._uninstall_route_rule(dp)
        self._uninstall_arp_rule(dp)
        self._uninstall_drop_rule(dp)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        # TODO: subscribe only the datapath that we route
        dpid = datapath.dpid
        if dpid != self.interface.dpid:
            return

        for field in msg.match.fields:
            header = field.header
            if header == ofproto.OXM_OF_IN_PORT:
                if field.value != self.interface.port_no:
                    return
                break

        self._arp_process(msg.data)

    def _drop_match(self, dp):
        kwargs = {}
        kwargs['in_port'] = self.interface.port_no
        kwargs['eth_dst'] = vrrp.vrrp_ipv4_src_mac_address(self.config.vrid)
        if self.interface.vlan_id is not None:
            kwargs['vlan_vid'] = self.interface.vlan_id
        return dp.ofproto_parser.OFPMatch(**kwargs)

    def _install_drop_rule(self, dp):
        match = self._drop_match(dp)
        utils.dp_flow_mod(dp, self._DROP_TABLE, dp.ofproto.OFPFC_ADD,
                          self._DROP_PRIORITY, match, [])

    def _uninstall_drop_rule(self, dp):
        match = self._drop_match(dp)
        utils.dp_flow_mod(dp, self._DROP_TABLE, dp.ofproto.OFPFC_DELETE_STRICT,
                          self._DROP_PRIORITY, match, [])

    def _arp_match(self, dp):
        kwargs = {}
        kwargs['in_port'] = self.interface.port_no
        kwargs['eth_dst'] = mac_lib.BROADCAST_STR
        kwargs['eth_type'] = ether.ETH_TYPE_ARP
        if self.interface.vlan_id is not None:
            kwargs['vlan_vid'] = self.interface.vlan_id
        kwargs['arp_op'] = arp.ARP_REQUEST
        kwargs['arp_tpa'] = vrrp.vrrp_ipv4_src_mac_address(self.config.vrid)
        return dp.ofproto_parser.OFPMatch(**kwargs)

    def _install_arp_rule(self, dp):
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser

        match = self._arp_match(dp)
        actions = [ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                  ofproto.OFPCML_NO_BUFFER)]
        instructions = [ofproto_parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        utils.dp_flow_mod(dp, self._ARP_TABLE, dp.fproto.OFPFC_ADD,
                          self._ARP_PRIORITY, match, instructions)

    def _uninstall_arp_rule(self, dp):
        match = self._arp_match(dp)
        utils.dp_flow_mod(dp, self._ARP_TABLE, dp.fproto.OFPFC_DELETE_STRICT,
                          self._ARP_PRIORITY, match, [])

    def _install_route_rule(self, dp):
        # TODO: implement real routing logic
        self.logger.debug('TODO:_install_router_rule')

    def _uninstall_route_rule(self, dp):
        # TODO: implement real routing logic
        self.logger.debug('TODO:_uninstall_router_rule')


class RouterIPV6(RouterBase):
    def __init__(self, *args, **kwargs):
        super(RouterIPV6, self).__init__(*args, **kwargs)
        assert self.config.is_ipv6


class RouterIPV6Linux(RouterIPV6):
    def __init__(self, *args, **kwargs):
        super(RouterIPV6Linux, self).__init__(*args, **kwargs)
        assert isinstance(self.interface,
                          vrrp_event.VRRPInterfaceNetworkDevice)

    # TODO: reader's home work
    pass


class RouterIPV6OpenFlow(RouterIPV6):
    def __init__(self, *args, **kwargs):
        super(RouterIPV6OpenFlow, self).__init__(*args, **kwargs)
        assert isinstance(self.interface, vrrp_event.VRRPInterfaceOpenFlow)

    # TODO: reader's home work
    pass
