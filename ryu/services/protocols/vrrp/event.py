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
Events for VRRP
"""

from ryu.controller import handler
from ryu.controller import event
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac as mac_lib
from ryu.lib.packet import vrrp
from ryu.lib import addrconv


# When an instance is created, state transition is None -> Initialize
VRRP_STATE_INITIALIZE = 'Initialize'
VRRP_STATE_MASTER = 'Master'
VRRP_STATE_BACKUP = 'Backup'


VRRP_MANAGER_NAME = 'VRRPManager'


class VRRPInterfaceBase(object):
    """
    interface on which VRRP router works
    vlan_id = None means no vlan.
    NOTE: multiple virtual router can be configured on single port
          See RFC 5798 4.2 Sample Configuration 2
    """
    def __init__(self, mac_address, primary_ip_address, vlan_id=None):
        super(VRRPInterfaceBase, self).__init__()
        self.mac_address = mac_address
        self.primary_ip_address = primary_ip_address
        self.vlan_id = vlan_id

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.mac_address == other.mac_address and
                self.primary_ip_address == other.primary_ip_address and
                self.vlan_id == other.vlan_id)

    def __hash__(self):
        return hash((
            addrconv.mac.text_to_bin(self.mac_address),
            vrrp.ip_text_to_bin(self.primary_ip_address), self.vlan_id))


class VRRPInterfaceNetworkDevice(VRRPInterfaceBase):
    def __init__(self, mac_address, primary_ip_address, vlan_id,
                 device_name):
        super(VRRPInterfaceNetworkDevice, self).__init__(
            mac_address, primary_ip_address, vlan_id)
        self.device_name = device_name

    def __str__(self):
        return '%s<%s, %s, %s, %s>' % (
            self.__class__.__name__,
            self.mac_address,
            self.primary_ip_address, self.vlan_id,
            self.device_name)

    def __eq__(self, other):
        return (super(VRRPInterfaceNetworkDevice, self).__eq__(other) and
                self.device_name == other.device_name)

    def __hash__(self):
        return hash((
            addrconv.mac.text_to_bin(self.mac_address),
            vrrp.ip_text_to_bin(self.primary_ip_address), self.vlan_id,
            self.device_name))


class VRRPInterfaceOpenFlow(VRRPInterfaceBase):
    def __init__(self, mac_address, primary_ip_address, vlan_id,
                 dpid, port_no):
        super(VRRPInterfaceOpenFlow, self).__init__(
            mac_address, primary_ip_address, vlan_id)
        self.dpid = dpid
        self.port_no = port_no

    def __str__(self):
        return '%s<%s, %s, %s, %s, %d>' % (
            self.__class__.__name__,
            self.mac_address,
            self.primary_ip_address, self.vlan_id,
            dpid_lib.dpid_to_str(self.dpid), self.port_no)

    def __eq__(self, other):
        return (super(VRRPInterfaceOpenFlow, self).__eq__(other) and
                self.dpid == other.dpid and self.port_no == other.port_no)

    def __hash__(self):
        return hash((
            addrconv.mac.text_to_bin(self.mac_address),
            vrrp.ip_text_to_bin(self.primary_ip_address), self.vlan_id,
            self.dpid, self.port_no))


class VRRPConfig(object):
    """
    advertmisement_interval is in seconds as float. (Not in centiseconds)
    """
    def __init__(self, version=vrrp.VRRP_VERSION_V3, vrid=None,
                 admin_state=True,
                 priority=vrrp.VRRP_PRIORITY_BACKUP_DEFAULT, ip_addresses=None,
                 advertisement_interval=vrrp.VRRP_MAX_ADVER_INT_DEFAULT_IN_SEC,
                 preempt_mode=True, preempt_delay=0, accept_mode=False,
                 statistics_interval=30, resource_id=None):
        # To allow version and priority default
        assert vrid is not None
        assert ip_addresses is not None
        super(VRRPConfig, self).__init__()

        self.version = version
        self.admin_state = admin_state
        self.vrid = vrid
        self.priority = priority
        self.ip_addresses = ip_addresses
        self.advertisement_interval = advertisement_interval
        self.preempt_mode = preempt_mode
        self.preempt_delay = preempt_delay
        self.accept_mode = accept_mode
        self.is_ipv6 = vrrp.is_ipv6(ip_addresses[0])
        self.statistics_interval = statistics_interval
        self.resource_id = resource_id

    @property
    def address_owner(self):
        return self.priority == vrrp.VRRP_PRIORITY_ADDRESS_OWNER

    def __eq__(self, other):
        return (self.version == other.version and
                self.vrid == other.vrid and
                self.priority == other.priority and
                self.ip_addresses == other.ip_addresses and
                self.advertisement_interval == other.advertisement_interval and
                self.preempt_mode == other.preempt_mode and
                self.preempt_delay == other.preempt_delay and
                self.accept_mode == other.accept_mode and
                self.is_ipv6 == other.is_ipv6)

    def __hash__(self):
        hash((self.version, self.vrid, self.priority,
              list(map(vrrp.ip_text_to_bin, self.ip_addresses)),
              self.advertisement_interval, self.preempt_mode,
              self.preempt_delay, self.accept_mode, self.is_ipv6))


class EventVRRPConfigRequest(event.EventRequestBase):
    """
    Request from management layer to VRRP manager to initialize VRRP Router.
    """
    def __init__(self, interface, config):
        super(EventVRRPConfigRequest, self).__init__()
        self.dst = VRRP_MANAGER_NAME
        self.interface = interface
        self.config = config


class EventVRRPConfigReply(event.EventReplyBase):
    def __init__(self, instance_name, interface, config):
        # dst = None. dst is filled by app_base.RyuApp#reply_to_request()
        super(EventVRRPConfigReply, self).__init__(None)
        self.instance_name = instance_name  # None means failure
        self.interface = interface
        self.config = config


class EventVRRPShutdownRequest(event.EventRequestBase):
    """
    Request from management layer to VRRP to shutdown VRRP Router.
    """
    def __init__(self, instance_name):
        super(EventVRRPShutdownRequest, self).__init__()
        self.instance_name = instance_name


class EventVRRPStateChanged(event.EventBase):
    """
    Event that this VRRP Router changed its state.
    """
    def __init__(self, instance_name, monitor_name, interface, config,
                 old_state, new_state):
        super(EventVRRPStateChanged, self).__init__()
        self.instance_name = instance_name
        self.monitor_name = monitor_name
        self.interface = interface
        self.config = config
        self.old_state = old_state
        self.new_state = new_state


class VRRPInstance(object):
    def __init__(self, instance_name, monitor_name, config, interface, state):
        super(VRRPInstance, self).__init__()
        self.instance_name = instance_name
        self.monitor_name = monitor_name
        self.config = config
        self.interface = interface
        self.state = state


class EventVRRPListRequest(event.EventRequestBase):
    """
    Event that requests list of configured VRRP router
    instance_name=None means all instances.
    """
    def __init__(self, instance_name=None):
        super(EventVRRPListRequest, self).__init__()
        self.instance_name = instance_name


class EventVRRPListReply(event.EventReplyBase):
    def __init__(self, instance_list):
        super(EventVRRPListReply, self).__init__(None)
        self.instance_list = instance_list


class EventVRRPConfigChangeRequest(event.EventRequestBase):
    """
    Event that requests to change configuration of a given VRRP router.
    None means no-change.
    """
    def __init__(self, instance_name, priority=None,
                 advertisement_interval=None, preempt_mode=None,
                 preempt_delay=None, accept_mode=None):
        super(EventVRRPConfigChangeRequest, self).__init__()
        self.instance_name = instance_name
        self.priority = priority
        self.advertisement_interval = advertisement_interval
        self.preempt_mode = preempt_mode
        self.preempt_delay = preempt_delay
        self.accept_mode = accept_mode


# Following classes are internally used by VRRP

class EventVRRPReceived(event.EventBase):
    """
    Event that port manager received valid VRRP packet.
    Usually handed by VRRP Router.
    """
    def __init__(self, interface, packet):
        super(EventVRRPReceived, self).__init__()
        self.interface = interface
        self.packet = packet


class EventVRRPTransmitRequest(event.EventRequestBase):
    """
    Request from VRRP router to port manager to transmit VRRP packet.
    """
    def __init__(self, data):
        super(EventVRRPTransmitRequest, self).__init__()
        self.data = data


handler.register_service('ryu.services.protocols.vrrp.manager')
