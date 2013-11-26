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
Interface monitor.
Watching packet received on this interface and parse VRRP packet.

VRRPManager creates/deletes instances of interface monitor dynamically.
"""

from ryu.base import app_manager
from ryu.controller import handler
from ryu.lib.packet import packet
from ryu.lib.packet import vlan
from ryu.lib.packet import vrrp
from ryu.services.protocols.vrrp import event as vrrp_event


class VRRPInterfaceMonitor(app_manager.RyuApp):
    # subclass of VRRPInterfaceBase -> subclass of VRRPInterfaceMonitor
    _CONSTRUCTORS = {}

    @staticmethod
    def register(interface_cls):
        def _register(cls):
            VRRPInterfaceMonitor._CONSTRUCTORS[interface_cls] = cls
            return cls
        return _register

    @staticmethod
    def factory(interface, config, router_name, statistics, *args, **kwargs):
        cls = VRRPInterfaceMonitor._CONSTRUCTORS[interface.__class__]
        app_mgr = app_manager.AppManager.get_instance()

        kwargs = kwargs.copy()
        kwargs['router_name'] = router_name
        kwargs['vrrp_config'] = config
        kwargs['vrrp_interface'] = interface
        kwargs['vrrp_statistics'] = statistics
        app = app_mgr.instantiate(cls, *args, **kwargs)
        return app

    @classmethod
    def instance_name(cls, interface, vrid):
        return '%s-%s-%d' % (cls.__name__, str(interface), vrid)

    def __init__(self, *args, **kwargs):
        super(VRRPInterfaceMonitor, self).__init__(*args, **kwargs)
        self.config = kwargs['vrrp_config']
        self.interface = kwargs['vrrp_interface']
        self.router_name = kwargs['router_name']
        self.statistics = kwargs['vrrp_statistics']
        self.name = self.instance_name(self.interface, self.config.vrid)

    def _parse_received_packet(self, packet_data):
        # OF doesn't support VRRP packet matching, so we have to parse
        # it ourselvs.
        packet_ = packet.Packet(packet_data)
        protocols = packet_.protocols

        # we expect either of
        #   [ether, vlan, ip, vrrp{, padding}]
        # or
        #   [ether, ip, vrrp{, padding}]

        if len(protocols) < 2:
            self.logger.debug('len(protocols) %d', len(protocols))
            return

        vlan_vid = self.interface.vlan_id
        may_vlan = protocols[1]
        if (vlan_vid is not None) != isinstance(may_vlan, vlan.vlan):
            self.logger.debug('vlan_vid: %s %s', vlan_vid, type(may_vlan))
            return
        if vlan_vid is not None and vlan_vid != may_vlan.vid:
            self.logger.debug('vlan_vid: %s vlan %s', vlan_vid, type(may_vlan))
            return

        # self.logger.debug('%s %s', packet_, packet_.protocols)
        may_ip, may_vrrp = vrrp.vrrp.get_payload(packet_)
        if not may_ip or not may_vrrp:
            # self.logger.debug('may_ip %s may_vrrp %s', may_ip, may_vrrp)
            return
        if not vrrp.vrrp.is_valid_ttl(may_ip):
            self.logger.debug('valid_ttl')
            return
        if may_vrrp.version != self.config.version:
            self.logger.debug('vrrp version %d %d',
                              may_vrrp.version, self.config.version)
            return
        if not may_vrrp.is_valid():
            self.logger.debug('valid vrrp')
            return
        offset = 0
        for proto in packet_.protocols:
            if proto == may_vrrp:
                break
            offset += len(proto)
        if not may_vrrp.checksum_ok(
                may_ip, packet_.data[offset:offset + len(may_vrrp)]):
            self.logger.debug('bad checksum')
            return
        if may_vrrp.vrid != self.config.vrid:
            self.logger.debug('vrid %d %d', may_vrrp.vrid, self.config.vrid)
            return
        if may_vrrp.is_ipv6 != self.config.is_ipv6:
            self.logger.debug('is_ipv6 %s %s',
                              may_vrrp.is_ipv6, self.config.is_ipv6)
            return

        # TODO: Optional check rfc5798 7.1
        # may_vrrp.ip_addresses equals to self.config.ip_addresses
        if may_vrrp.priority == 0:
            self.statistics.rx_vrrp_zero_prio_packets += 1

        vrrp_received = vrrp_event.EventVRRPReceived(self.interface, packet_)
        self.send_event(self.router_name, vrrp_received)
        return True

    def _send_vrrp_packet_received(self, packet_data):
        valid = self._parse_received_packet(packet_data)
        if valid is True:
            self.statistics.rx_vrrp_packets += 1
        else:
            self.statistics.rx_vrrp_invalid_packets += 1

    @handler.set_ev_handler(vrrp_event.EventVRRPTransmitRequest)
    def vrrp_transmit_request_handler(self, ev):
        raise NotImplementedError()

    def _initialize(self):
        raise NotImplementedError()

    def _shutdown(self):
        raise NotImplementedError()

    @handler.set_ev_handler(vrrp_event.EventVRRPStateChanged)
    def vrrp_state_changed_handler(self, ev):
        assert ev.interface == self.interface

        if ev.new_state == vrrp_event.VRRP_STATE_INITIALIZE:
            # add/del packet in rule
            if ev.old_state:
                self._shutdown()
            else:
                self._initialize()
        elif ev.new_state in [vrrp_event.VRRP_STATE_BACKUP,
                              vrrp_event.VRRP_STATE_MASTER]:

            if ev.old_state == vrrp_event.VRRP_STATE_INITIALIZE:
                if ev.new_state == vrrp_event.VRRP_STATE_MASTER:
                    self.statistics.idle_to_master_transitions += 1
                else:
                    self.statistics.idle_to_backup_transitions += 1
            elif ev.old_state == vrrp_event.VRRP_STATE_MASTER:
                self.statistics.master_to_backup_transitions += 1
            else:
                self.statistics.backup_to_master_transitions += 1
        else:
            raise RuntimeError('unknown vrrp state %s' % ev.new_state)
