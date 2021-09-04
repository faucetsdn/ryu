# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
"""This module offers a class to enable your code to speak BGP protocol.

"""

import netaddr
from ryu.lib import hub
from ryu.lib import ip
from ryu.lib.packet.bgp import (
    BGPFlowSpecTrafficActionCommunity,
    BGPFlowSpecVlanActionCommunity,
    BGPFlowSpecTPIDActionCommunity,
)

from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.signals.emit import BgpSignalBus
from ryu.services.protocols.bgp.api.base import call
from ryu.services.protocols.bgp.api.base import PREFIX
from ryu.services.protocols.bgp.api.base import EVPN_ROUTE_TYPE
from ryu.services.protocols.bgp.api.base import EVPN_ESI
from ryu.services.protocols.bgp.api.base import EVPN_ETHERNET_TAG_ID
from ryu.services.protocols.bgp.api.base import REDUNDANCY_MODE
from ryu.services.protocols.bgp.api.base import IP_ADDR
from ryu.services.protocols.bgp.api.base import MAC_ADDR
from ryu.services.protocols.bgp.api.base import NEXT_HOP
from ryu.services.protocols.bgp.api.base import IP_PREFIX
from ryu.services.protocols.bgp.api.base import GW_IP_ADDR
from ryu.services.protocols.bgp.api.base import ROUTE_DISTINGUISHER
from ryu.services.protocols.bgp.api.base import ROUTE_FAMILY
from ryu.services.protocols.bgp.api.base import EVPN_VNI
from ryu.services.protocols.bgp.api.base import TUNNEL_TYPE
from ryu.services.protocols.bgp.api.base import PMSI_TUNNEL_TYPE
from ryu.services.protocols.bgp.api.base import MAC_MOBILITY
from ryu.services.protocols.bgp.api.base import TUNNEL_ENDPOINT_IP
from ryu.services.protocols.bgp.api.prefix import EVPN_MAX_ET
from ryu.services.protocols.bgp.api.prefix import ESI_TYPE_LACP
from ryu.services.protocols.bgp.api.prefix import ESI_TYPE_L2_BRIDGE
from ryu.services.protocols.bgp.api.prefix import ESI_TYPE_MAC_BASED
from ryu.services.protocols.bgp.api.prefix import EVPN_ETH_AUTO_DISCOVERY
from ryu.services.protocols.bgp.api.prefix import EVPN_MAC_IP_ADV_ROUTE
from ryu.services.protocols.bgp.api.prefix import EVPN_MULTICAST_ETAG_ROUTE
from ryu.services.protocols.bgp.api.prefix import EVPN_ETH_SEGMENT
from ryu.services.protocols.bgp.api.prefix import EVPN_IP_PREFIX_ROUTE
from ryu.services.protocols.bgp.api.prefix import REDUNDANCY_MODE_ALL_ACTIVE
from ryu.services.protocols.bgp.api.prefix import REDUNDANCY_MODE_SINGLE_ACTIVE
from ryu.services.protocols.bgp.api.prefix import TUNNEL_TYPE_VXLAN
from ryu.services.protocols.bgp.api.prefix import TUNNEL_TYPE_NVGRE
from ryu.services.protocols.bgp.api.prefix import (
    PMSI_TYPE_NO_TUNNEL_INFO,
    PMSI_TYPE_INGRESS_REP)
from ryu.services.protocols.bgp.api.prefix import (
    FLOWSPEC_FAMILY,
    FLOWSPEC_FAMILY_IPV4,
    FLOWSPEC_FAMILY_VPNV4,
    FLOWSPEC_FAMILY_IPV6,
    FLOWSPEC_FAMILY_VPNV6,
    FLOWSPEC_FAMILY_L2VPN,
    FLOWSPEC_RULES,
    FLOWSPEC_ACTIONS)
from ryu.services.protocols.bgp.model import ReceivedRoute
from ryu.services.protocols.bgp.rtconf.common import LOCAL_AS
from ryu.services.protocols.bgp.rtconf.common import ROUTER_ID
from ryu.services.protocols.bgp.rtconf.common import CLUSTER_ID
from ryu.services.protocols.bgp.rtconf.common import BGP_SERVER_HOSTS
from ryu.services.protocols.bgp.rtconf.common import BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_BGP_SERVER_HOSTS
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common import (
    DEFAULT_REFRESH_MAX_EOR_TIME, DEFAULT_REFRESH_STALEPATH_TIME)
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_LABEL_RANGE
from ryu.services.protocols.bgp.rtconf.common import REFRESH_MAX_EOR_TIME
from ryu.services.protocols.bgp.rtconf.common import REFRESH_STALEPATH_TIME
from ryu.services.protocols.bgp.rtconf.common import LABEL_RANGE
from ryu.services.protocols.bgp.rtconf.common import ALLOW_LOCAL_AS_IN_COUNT
from ryu.services.protocols.bgp.rtconf.common import LOCAL_PREF
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_LOCAL_PREF
from ryu.services.protocols.bgp.rtconf import neighbors
from ryu.services.protocols.bgp.rtconf import vrfs
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV6
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_EVPN
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV4FS
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV6FS
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV4FS
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV6FS
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_L2VPNFS
from ryu.services.protocols.bgp.rtconf.base import CAP_ENHANCED_REFRESH
from ryu.services.protocols.bgp.rtconf.base import CAP_FOUR_OCTET_AS_NUMBER
from ryu.services.protocols.bgp.rtconf.base import MULTI_EXIT_DISC
from ryu.services.protocols.bgp.rtconf.base import SITE_OF_ORIGINS
from ryu.services.protocols.bgp.rtconf.neighbors import (
    DEFAULT_CAP_MBGP_IPV4,
    DEFAULT_CAP_MBGP_IPV6,
    DEFAULT_CAP_MBGP_VPNV4,
    DEFAULT_CAP_MBGP_VPNV6,
    DEFAULT_CAP_MBGP_EVPN,
    DEFAULT_CAP_MBGP_IPV4FS,
    DEFAULT_CAP_MBGP_IPV6FS,
    DEFAULT_CAP_MBGP_VPNV4FS,
    DEFAULT_CAP_MBGP_VPNV6FS,
    DEFAULT_CAP_MBGP_L2VPNFS,
    DEFAULT_CAP_ENHANCED_REFRESH,
    DEFAULT_CAP_FOUR_OCTET_AS_NUMBER,
    DEFAULT_CONNECT_MODE,
    REMOTE_PORT,
    DEFAULT_BGP_PORT,
    PEER_NEXT_HOP,
    PASSWORD,
    DEFAULT_IS_ROUTE_SERVER_CLIENT,
    IS_ROUTE_SERVER_CLIENT,
    DEFAULT_IS_ROUTE_REFLECTOR_CLIENT,
    IS_ROUTE_REFLECTOR_CLIENT,
    DEFAULT_IS_NEXT_HOP_SELF,
    IS_NEXT_HOP_SELF,
    CONNECT_MODE,
    LOCAL_ADDRESS,
    LOCAL_PORT,
)
from ryu.services.protocols.bgp.rtconf.vrfs import SUPPORTED_VRF_RF
from ryu.services.protocols.bgp.info_base.base import Filter
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Path
from ryu.services.protocols.bgp.info_base.ipv6 import Ipv6Path
from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Path
from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Path
from ryu.services.protocols.bgp.info_base.evpn import EvpnPath


NEIGHBOR_CONF_MED = MULTI_EXIT_DISC  # for backward compatibility
RF_VPN_V4 = vrfs.VRF_RF_IPV4
RF_VPN_V6 = vrfs.VRF_RF_IPV6
RF_L2_EVPN = vrfs.VRF_RF_L2_EVPN
RF_VPNV4_FLOWSPEC = vrfs.VRF_RF_IPV4_FLOWSPEC
RF_VPNV6_FLOWSPEC = vrfs.VRF_RF_IPV6_FLOWSPEC
RF_L2VPN_FLOWSPEC = vrfs.VRF_RF_L2VPN_FLOWSPEC

# Constants for the Traffic Filtering Actions of Flow Specification.
FLOWSPEC_TA_SAMPLE = BGPFlowSpecTrafficActionCommunity.SAMPLE
FLOWSPEC_TA_TERMINAL = BGPFlowSpecTrafficActionCommunity.TERMINAL

# Constants for the VLAN Actions of Flow Specification.
FLOWSPEC_VLAN_POP = BGPFlowSpecVlanActionCommunity.POP
FLOWSPEC_VLAN_PUSH = BGPFlowSpecVlanActionCommunity.PUSH
FLOWSPEC_VLAN_SWAP = BGPFlowSpecVlanActionCommunity.SWAP
FLOWSPEC_VLAN_RW_INNER = BGPFlowSpecVlanActionCommunity.REWRITE_INNER
FLOWSPEC_VLAN_RW_OUTER = BGPFlowSpecVlanActionCommunity.REWRITE_OUTER

# Constants for the TPID Actions of Flow Specification.
FLOWSPEC_TPID_TI = BGPFlowSpecTPIDActionCommunity.TI
FLOWSPEC_TPID_TO = BGPFlowSpecTPIDActionCommunity.TO


class EventPrefix(object):
    """
    Used to pass an update on any best remote path to
    best_path_change_handler.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    remote_as        The AS number of a peer that caused this change
    route_dist       None in the case of IPv4 or IPv6 family
    prefix           A prefix was changed
    nexthop          The nexthop of the changed prefix
    label            MPLS label for VPNv4, VPNv6 or EVPN prefix
    path             An instance of ``info_base.base.Path`` subclass
    is_withdraw      True if this prefix has gone otherwise False
    ================ ======================================================
    """

    def __init__(self, path, is_withdraw):
        self.path = path
        self.is_withdraw = is_withdraw

    @property
    def remote_as(self):
        return self.path.source.remote_as

    @property
    def route_dist(self):
        if (isinstance(self.path, Vpnv4Path)
                or isinstance(self.path, Vpnv6Path)
                or isinstance(self.path, EvpnPath)):
            return self.path.nlri.route_dist
        else:
            return None

    @property
    def prefix(self):
        if isinstance(self.path, Ipv4Path) or isinstance(self.path, Ipv6Path):
            return self.path.nlri.addr + '/' + str(self.path.nlri.length)
        elif (isinstance(self.path, Vpnv4Path)
              or isinstance(self.path, Vpnv6Path)
              or isinstance(self.path, EvpnPath)):
            return self.path.nlri.prefix
        else:
            return None

    @property
    def nexthop(self):
        return self.path.nexthop

    @property
    def label(self):
        if (isinstance(self.path, Vpnv4Path)
                or isinstance(self.path, Vpnv6Path)
                or isinstance(self.path, EvpnPath)):
            return getattr(self.path.nlri, 'label_list', None)
        else:
            return None


class BGPSpeaker(object):
    """Class to provide the APIs of Ryu BGP Speaker.

    ``as_number`` specifies an Autonomous Number. It must be an integer
    between 1 and 65535.

    ``router_id`` specifies BGP router identifier. It must be the
    string representation of an IPv4 address (e.g. 10.0.0.1).

    ``bgp_server_host`` specifies a list of TCP listen host addresses.

    ``bgp_server_port`` specifies TCP listen port number. 179 is
    used if not specified.

    ``refresh_stalepath_time`` causes the BGP speaker to remove
    stale routes from the BGP table after the timer expires, even
    if the speaker does not receive a Router-Refresh End-of-RIB
    message. This feature is disabled (not implemented yet).

    ``refresh_max_eor_time`` causes the BGP speaker to generate a
    Route-Refresh End-of-RIB message if it was not able to
    generate one due to route flapping. This feature is disabled
    (not implemented yet).

    ``best_path_change_handler``, if specified, is called when any
    best remote path is changed due to an update message or remote
    peer down. The handler is supposed to take one argument, the
    instance of an EventPrefix class instance.

    ``adj_rib_in_change_handler``, if specified, is called when any
    adj-RIB-in path is changed due to an update message or remote
    peer down. The given handler should take three argument, the
    instance of an EventPrefix class instance, str type peer's IP address
    and int type peer's AS number.

    ``peer_down_handler``, if specified, is called when BGP peering
    session goes down.

    ``peer_up_handler``, if specified, is called when BGP peering
    session goes up.

    ``ssh_console`` specifies whether or not SSH CLI need to be started.

    ``ssh_port`` specifies the port number for SSH CLI server.
    The default is bgp.operator.ssh.DEFAULT_SSH_PORT.

    ``ssh_host`` specifies the IP address for SSH CLI server.
    The default is bgp.operator.ssh.DEFAULT_SSH_HOST.

    ``ssh_host_key`` specifies the path to the host key added to
    the keys list used by SSH CLI server.
    The default is bgp.operator.ssh.DEFAULT_SSH_HOST_KEY.

    ``label_range`` specifies the range of MPLS labels generated
    automatically.

    ``allow_local_as_in_count`` maximum number of local AS number
    occurrences in AS_PATH.  This option is useful for e.g.  auto RD/RT
    configurations in leaf/spine architecture with shared AS numbers.
    The default is 0 and means "local AS number is not allowed in
    AS_PATH".  To allow local AS, 3 is recommended (Cisco's default).

    ``cluster_id`` specifies the cluster identifier for Route Reflector.
    It must be the string representation of an IPv4 address.
    If omitted, "router_id" is used for this field.

    ``local_pref`` specifies the default local preference. It must be an
    integer.
    """

    def __init__(self, as_number, router_id,
                 bgp_server_hosts=DEFAULT_BGP_SERVER_HOSTS,
                 bgp_server_port=DEFAULT_BGP_SERVER_PORT,
                 refresh_stalepath_time=DEFAULT_REFRESH_STALEPATH_TIME,
                 refresh_max_eor_time=DEFAULT_REFRESH_MAX_EOR_TIME,
                 best_path_change_handler=None,
                 adj_rib_in_change_handler=None,
                 peer_down_handler=None,
                 peer_up_handler=None,
                 ssh_console=False,
                 ssh_port=None, ssh_host=None, ssh_host_key=None,
                 label_range=DEFAULT_LABEL_RANGE,
                 allow_local_as_in_count=0,
                 cluster_id=None,
                 local_pref=DEFAULT_LOCAL_PREF):
        super(BGPSpeaker, self).__init__()

        settings = {
            LOCAL_AS: as_number,
            ROUTER_ID: router_id,
            BGP_SERVER_HOSTS: bgp_server_hosts,
            BGP_SERVER_PORT: bgp_server_port,
            REFRESH_STALEPATH_TIME: refresh_stalepath_time,
            REFRESH_MAX_EOR_TIME: refresh_max_eor_time,
            LABEL_RANGE: label_range,
            ALLOW_LOCAL_AS_IN_COUNT: allow_local_as_in_count,
            CLUSTER_ID: cluster_id,
            LOCAL_PREF: local_pref,
        }
        self._core_start(settings)
        self._init_signal_listeners()
        self._best_path_change_handler = best_path_change_handler
        self._adj_rib_in_change_handler = adj_rib_in_change_handler
        self._peer_down_handler = peer_down_handler
        self._peer_up_handler = peer_up_handler
        if ssh_console:
            # Note: paramiko used in bgp.operator.ssh is the optional
            # requirements, imports bgp.operator.ssh here.
            from ryu.services.protocols.bgp.operator import ssh
            ssh_settings = {
                ssh.SSH_PORT: ssh_port or ssh.DEFAULT_SSH_PORT,
                ssh.SSH_HOST: ssh_host or ssh.DEFAULT_SSH_HOST,
                ssh.SSH_HOST_KEY: ssh_host_key or ssh.DEFAULT_SSH_HOST_KEY,
            }
            hub.spawn(ssh.SSH_CLI_CONTROLLER.start, **ssh_settings)

    def _notify_peer_down(self, peer):
        remote_ip = peer.ip_address
        remote_as = peer.remote_as
        if self._peer_down_handler:
            self._peer_down_handler(remote_ip, remote_as)

    def _notify_peer_up(self, peer):
        remote_ip = peer.protocol.recv_open_msg.bgp_identifier
        remote_as = peer.protocol.recv_open_msg.my_as
        if self._peer_up_handler:
            self._peer_up_handler(remote_ip, remote_as)

    def _notify_best_path_changed(self, path, is_withdraw):
        if (not path.source
                or not isinstance(path, (Ipv4Path, Ipv6Path,
                                         Vpnv4Path, Vpnv6Path, EvpnPath))):
            return

        ev = EventPrefix(path, is_withdraw)

        if self._best_path_change_handler:
            self._best_path_change_handler(ev)

    def _notify_adj_rib_in_changed(self, peer, route):
        if not isinstance(route, ReceivedRoute):
            return

        if self._adj_rib_in_change_handler:
            self._adj_rib_in_change_handler(
                EventPrefix(route.path, route.path.is_withdraw),
                peer.ip_address, peer.remote_as)

    def _init_signal_listeners(self):
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            BgpSignalBus.BGP_BEST_PATH_CHANGED,
            lambda _, info:
            self._notify_best_path_changed(info['path'],
                                           info['is_withdraw'])
        )
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            BgpSignalBus.BGP_ADJ_RIB_IN_CHANGED,
            lambda _, info:
            self._notify_adj_rib_in_changed(info['peer'],
                                            info['received_route'])
        )
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            BgpSignalBus.BGP_ADJ_DOWN,
            lambda _, info:
            self._notify_peer_down(info['peer'])
        )
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            BgpSignalBus.BGP_ADJ_UP,
            lambda _, info:
            self._notify_peer_up(info['peer'])
        )

    def _core_start(self, settings):
        waiter = hub.Event()
        call('core.start', waiter=waiter, **settings)
        waiter.wait()

    def _serve_forever(self):
        pass

    def shutdown(self):
        """ Shutdown BGP speaker
        """
        call('core.stop')

    def neighbor_add(self, address, remote_as,
                     remote_port=DEFAULT_BGP_PORT,
                     enable_ipv4=DEFAULT_CAP_MBGP_IPV4,
                     enable_ipv6=DEFAULT_CAP_MBGP_IPV6,
                     enable_vpnv4=DEFAULT_CAP_MBGP_VPNV4,
                     enable_vpnv6=DEFAULT_CAP_MBGP_VPNV6,
                     enable_evpn=DEFAULT_CAP_MBGP_EVPN,
                     enable_ipv4fs=DEFAULT_CAP_MBGP_IPV4FS,
                     enable_ipv6fs=DEFAULT_CAP_MBGP_IPV6FS,
                     enable_vpnv4fs=DEFAULT_CAP_MBGP_VPNV4FS,
                     enable_vpnv6fs=DEFAULT_CAP_MBGP_VPNV6FS,
                     enable_l2vpnfs=DEFAULT_CAP_MBGP_L2VPNFS,
                     enable_enhanced_refresh=DEFAULT_CAP_ENHANCED_REFRESH,
                     enable_four_octet_as_number=DEFAULT_CAP_FOUR_OCTET_AS_NUMBER,
                     next_hop=None, password=None, multi_exit_disc=None,
                     site_of_origins=None,
                     is_route_server_client=DEFAULT_IS_ROUTE_SERVER_CLIENT,
                     is_route_reflector_client=DEFAULT_IS_ROUTE_REFLECTOR_CLIENT,
                     is_next_hop_self=DEFAULT_IS_NEXT_HOP_SELF,
                     local_address=None,
                     local_port=None, local_as=None,
                     connect_mode=DEFAULT_CONNECT_MODE):
        """ This method registers a new neighbor. The BGP speaker tries to
        establish a bgp session with the peer (accepts a connection
        from the peer and also tries to connect to it).

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address. Only IPv4 is
        supported now.

        ``remote_as`` specifies the AS number of the peer. It must be
        an integer between 1 and 65535.

        ``remote_port`` specifies the TCP port number of the peer.

        ``enable_ipv4`` enables IPv4 address family for this
        neighbor.

        ``enable_ipv6`` enables IPv6 address family for this
        neighbor.

        ``enable_vpnv4`` enables VPNv4 address family for this
        neighbor.

        ``enable_vpnv6`` enables VPNv6 address family for this
        neighbor.

        ``enable_evpn`` enables Ethernet VPN address family for this
        neighbor.

        ``enable_ipv4fs`` enables IPv4 Flow Specification address family
        for this neighbor.

        ``enable_ipv6fs`` enables IPv6 Flow Specification address family
        for this neighbor.

        ``enable_vpnv4fs`` enables VPNv4 Flow Specification address family
        for this neighbor.

        ``enable_vpnv6fs`` enables VPNv6 Flow Specification address family
        for this neighbor.

        ``enable_l2vpnfs`` enables L2VPN Flow Specification address family
        for this neighbor.

        ``enable_enhanced_refresh`` enables Enhanced Route Refresh for this
        neighbor.

        ``enable_four_octet_as_number`` enables Four-Octet AS Number
        capability for this neighbor.

        ``next_hop`` specifies the next hop IP address. If not
        specified, host's ip address to access to a peer is used.

        ``password`` is used for the MD5 authentication if it's
        specified. By default, the MD5 authentication is disabled.

        ``multi_exit_disc`` specifies multi exit discriminator (MED) value
        as an int type value.
        If omitted, MED is not sent to the neighbor.

        ``site_of_origins`` specifies site_of_origin values.
        This parameter must be a list of string.

        ``is_route_server_client`` specifies whether this neighbor is a
        router server's client or not.

        ``is_route_reflector_client`` specifies whether this neighbor is a
        router reflector's client or not.

        ``is_next_hop_self`` specifies whether the BGP speaker announces
        its own ip address to iBGP neighbor or not as path's next_hop address.

        ``local_address`` specifies Loopback interface address for
        iBGP peering.

        ``local_port`` specifies source TCP port for iBGP peering.

        ``local_as`` specifies local AS number per-peer.
        If omitted, the AS number of BGPSpeaker instance is used.

        ``connect_mode`` specifies how to connect to this neighbor.
        This parameter must be one of the following.

        - CONNECT_MODE_ACTIVE         = 'active'
        - CONNECT_MODE_PASSIVE        = 'passive'
        - CONNECT_MODE_BOTH (default) = 'both'
        """
        bgp_neighbor = {
            neighbors.IP_ADDRESS: address,
            neighbors.REMOTE_AS: remote_as,
            REMOTE_PORT: remote_port,
            PEER_NEXT_HOP: next_hop,
            PASSWORD: password,
            IS_ROUTE_SERVER_CLIENT: is_route_server_client,
            IS_ROUTE_REFLECTOR_CLIENT: is_route_reflector_client,
            IS_NEXT_HOP_SELF: is_next_hop_self,
            CONNECT_MODE: connect_mode,
            CAP_ENHANCED_REFRESH: enable_enhanced_refresh,
            CAP_FOUR_OCTET_AS_NUMBER: enable_four_octet_as_number,
            CAP_MBGP_IPV4: enable_ipv4,
            CAP_MBGP_IPV6: enable_ipv6,
            CAP_MBGP_VPNV4: enable_vpnv4,
            CAP_MBGP_VPNV6: enable_vpnv6,
            CAP_MBGP_EVPN: enable_evpn,
            CAP_MBGP_IPV4FS: enable_ipv4fs,
            CAP_MBGP_IPV6FS: enable_ipv6fs,
            CAP_MBGP_VPNV4FS: enable_vpnv4fs,
            CAP_MBGP_VPNV6FS: enable_vpnv6fs,
            CAP_MBGP_L2VPNFS: enable_l2vpnfs,
        }

        if multi_exit_disc:
            bgp_neighbor[MULTI_EXIT_DISC] = multi_exit_disc

        if site_of_origins:
            bgp_neighbor[SITE_OF_ORIGINS] = site_of_origins

        if local_address:
            bgp_neighbor[LOCAL_ADDRESS] = local_address

        if local_port:
            bgp_neighbor[LOCAL_PORT] = local_port

        if local_as:
            bgp_neighbor[LOCAL_AS] = local_as

        call('neighbor.create', **bgp_neighbor)

    def neighbor_del(self, address):
        """ This method unregister the registered neighbor. If a session with
        the peer exists, the session will be closed.

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address.
        """
        bgp_neighbor = {
            neighbors.IP_ADDRESS: address,
        }

        call('neighbor.delete', **bgp_neighbor)

    def neighbor_reset(self, address):
        """ This method reset the registered neighbor.

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address.
        """
        bgp_neighbor = {
            neighbors.IP_ADDRESS: address,
        }

        call('core.reset_neighbor', **bgp_neighbor)

    def neighbor_update(self, address, conf_type, conf_value):
        """ This method changes the neighbor configuration.

        ``address`` specifies the IP address of the peer.

        ``conf_type`` specifies configuration type which you want to change.
        Currently ryu.services.protocols.bgp.bgpspeaker.MULTI_EXIT_DISC
        can be specified.

        ``conf_value`` specifies value for the configuration type.
        """

        assert conf_type == MULTI_EXIT_DISC or conf_type == CONNECT_MODE

        func_name = 'neighbor.update'
        attribute_param = {}
        if conf_type == MULTI_EXIT_DISC:
            attribute_param = {neighbors.MULTI_EXIT_DISC: conf_value}
        elif conf_type == CONNECT_MODE:
            attribute_param = {neighbors.CONNECT_MODE: conf_value}

        param = {neighbors.IP_ADDRESS: address,
                 neighbors.CHANGES: attribute_param}

        call(func_name, **param)

    def neighbor_state_get(self, address=None, format='json'):
        """ This method returns the state of peer(s) in a json
        format.

        ``address`` specifies the address of a peer. If not given, the
        state of all the peers return.

        ``format`` specifies the format of the response.
        This parameter must be one of the following.

        - 'json' (default)
        - 'cli'
        """
        show = {
            'params': ['neighbor', 'summary'],
            'format': format,
        }
        if address:
            show['params'].append(address)

        return call('operator.show', **show)

    def prefix_add(self, prefix, next_hop=None, route_dist=None):
        """ This method adds a new prefix to be advertised.

        ``prefix`` must be the string representation of an IP network
        (e.g., 10.1.1.0/24).

        ``next_hop`` specifies the next hop address for this
        prefix. This parameter is necessary for only VPNv4 and VPNv6
        address families.

        ``route_dist`` specifies a route distinguisher value. This
        parameter is necessary for only VPNv4 and VPNv6 address
        families.
        """
        func_name = 'network.add'
        networks = {
            PREFIX: prefix,
        }
        if next_hop:
            networks[NEXT_HOP] = next_hop
        if route_dist:
            func_name = 'prefix.add_local'
            networks[ROUTE_DISTINGUISHER] = route_dist

            rf, p = self._check_rf_and_normalize(prefix)
            networks[ROUTE_FAMILY] = rf
            networks[PREFIX] = p

            if rf == vrfs.VRF_RF_IPV6 and ip.valid_ipv4(next_hop):
                # convert the next_hop to IPv4-Mapped IPv6 Address
                networks[NEXT_HOP] = \
                    str(netaddr.IPAddress(next_hop).ipv6())

        return call(func_name, **networks)

    def prefix_del(self, prefix, route_dist=None):
        """ This method deletes a advertised prefix.

        ``prefix`` must be the string representation of an IP network.

        ``route_dist`` specifies a route distinguisher value.
        """
        func_name = 'network.del'
        networks = {
            PREFIX: prefix,
        }
        if route_dist:
            func_name = 'prefix.delete_local'
            networks[ROUTE_DISTINGUISHER] = route_dist

            rf, p = self._check_rf_and_normalize(prefix)
            networks[ROUTE_FAMILY] = rf
            networks[PREFIX] = p

        call(func_name, **networks)

    def evpn_prefix_add(self, route_type, route_dist, esi=0,
                        ethernet_tag_id=None, mac_addr=None, ip_addr=None,
                        ip_prefix=None, gw_ip_addr=None, vni=None,
                        next_hop=None, tunnel_type=None, pmsi_tunnel_type=None,
                        redundancy_mode=None, tunnel_endpoint_ip=None, mac_mobility=None):
        """ This method adds a new EVPN route to be advertised.

        ``route_type`` specifies one of the EVPN route type name.
        This parameter must be one of the following.

        - EVPN_ETH_AUTO_DISCOVERY   = 'eth_ad'
        - EVPN_MAC_IP_ADV_ROUTE     = 'mac_ip_adv'
        - EVPN_MULTICAST_ETAG_ROUTE = 'multicast_etag'
        - EVPN_ETH_SEGMENT          = 'eth_seg'
        - EVPN_IP_PREFIX_ROUTE      = 'ip_prefix'

        ``route_dist`` specifies a route distinguisher value.

        ``esi`` is an value to specify the Ethernet Segment Identifier.
        0 is the default and denotes a single-homed site.
        If you want to advertise esi other than 0,
        it must be set as dictionary type.
        If esi is dictionary type, 'type' key must be set
        and specifies ESI type.
        For the supported ESI type, see :py:mod:`ryu.lib.packet.bgp.EvpnEsi`.
        The remaining arguments are the same as that for
        the corresponding class.

        ``ethernet_tag_id`` specifies the Ethernet Tag ID.

        ``mac_addr`` specifies a MAC address to advertise.

        ``ip_addr`` specifies an IPv4 or IPv6 address to advertise.

        ``ip_prefix`` specifies an IPv4 or IPv6 prefix to advertise.

        ``gw_ip_addr`` specifies an IPv4 or IPv6 address of
        gateway to advertise.

        ``vni`` specifies an Virtual Network Identifier for VXLAN
        or Virtual Subnet Identifier for NVGRE.
        If tunnel_type is not TUNNEL_TYPE_VXLAN or TUNNEL_TYPE_NVGRE,
        this field is ignored.

        ``next_hop`` specifies the next hop address for this prefix.

        ``tunnel_type`` specifies the data plane encapsulation type
        to advertise. By the default, this attribute is not advertised.
        The supported encapsulation types are following.

        - TUNNEL_TYPE_VXLAN = 'vxlan'
        - TUNNEL_TYPE_NVGRE = 'nvgre

        ``pmsi_tunnel_type`` specifies the type of the PMSI tunnel attribute
        used to encode the multicast tunnel identifier.
        This attribute is advertised only if route_type is
        EVPN_MULTICAST_ETAG_ROUTE and not advertised by the default.
        This attribute can also carry vni if tunnel_type is specified.
        The supported PMSI tunnel types are following.

        - PMSI_TYPE_NO_TUNNEL_INFO = 0
        - PMSI_TYPE_INGRESS_REP    = 6

        ``redundancy_mode`` specifies a redundancy mode type.
        This attribute is advertised only if route_type is
        EVPN_ETH_AUTO_DISCOVERY and not advertised by the default.
        The supported redundancy mode types are following.

        - REDUNDANCY_MODE_ALL_ACTIVE    = 'all_active'
        - REDUNDANCY_MODE_SINGLE_ACTIVE = 'single_active'

        ``tunnel_endpoint_ip`` specifies a VTEP IP address other than the
        local router ID. This attribute is advertised only if route_type is
        EVPN_MULTICAST_ETAG_ROUTE, and defaults to the local router ID.

        ``mac_mobility`` specifies an optional integer sequence number to use
        in a MAC Mobility extended community field. The special value '-1' can
        be used to set the STATIC flag with a 0-value sequence number.

        """
        func_name = 'evpn_prefix.add_local'

        # Check the default values
        if not next_hop:
            next_hop = '0.0.0.0'

        # Set required arguments
        kwargs = {EVPN_ROUTE_TYPE: route_type,
                  ROUTE_DISTINGUISHER: route_dist,
                  NEXT_HOP: next_hop}

        # Set optional arguments
        if tunnel_type in [TUNNEL_TYPE_VXLAN, TUNNEL_TYPE_NVGRE]:
            kwargs[TUNNEL_TYPE] = tunnel_type
        elif tunnel_type is not None:
            raise ValueError('Unsupported tunnel type: %s' % tunnel_type)

        # Set route type specific arguments
        if route_type == EVPN_ETH_AUTO_DISCOVERY:
            kwargs.update({
                EVPN_ESI: esi,
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
            })
            if vni is not None:
                kwargs[EVPN_VNI] = vni
            # Set Redundancy Mode Attribute arguments
            if redundancy_mode in [
                    REDUNDANCY_MODE_ALL_ACTIVE,
                    REDUNDANCY_MODE_SINGLE_ACTIVE]:
                kwargs[REDUNDANCY_MODE] = redundancy_mode
            elif redundancy_mode is not None:
                raise ValueError('Unsupported Redundancy Mode: %s' %
                                 redundancy_mode)
        elif route_type == EVPN_MAC_IP_ADV_ROUTE:
            kwargs.update({
                EVPN_ESI: esi,
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
                MAC_ADDR: mac_addr,
                IP_ADDR: ip_addr,
            })
            # Set tunnel type specific arguments
            if tunnel_type in [TUNNEL_TYPE_VXLAN, TUNNEL_TYPE_NVGRE]:
                kwargs[EVPN_VNI] = vni

            # Pass on mac_mobility, must be integer value
            if mac_mobility is not None:
                kwargs[MAC_MOBILITY] = int(mac_mobility)
        elif route_type == EVPN_MULTICAST_ETAG_ROUTE:
            kwargs.update({
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
                IP_ADDR: ip_addr,
            })
            # Set tunnel type specific arguments
            if tunnel_type in [TUNNEL_TYPE_VXLAN, TUNNEL_TYPE_NVGRE]:
                kwargs[EVPN_VNI] = vni
            # Set PMSI Tunnel Attribute arguments
            if pmsi_tunnel_type in [
                    PMSI_TYPE_NO_TUNNEL_INFO,
                    PMSI_TYPE_INGRESS_REP]:
                kwargs[PMSI_TUNNEL_TYPE] = pmsi_tunnel_type
            elif pmsi_tunnel_type is not None:
                raise ValueError('Unsupported PMSI tunnel type: %s' %
                                 pmsi_tunnel_type)
            # Set non-default tunnel endpoint IP, if provided
            if tunnel_endpoint_ip is not None:
                kwargs[TUNNEL_ENDPOINT_IP] = tunnel_endpoint_ip
        elif route_type == EVPN_ETH_SEGMENT:
            kwargs.update({
                EVPN_ESI: esi,
                IP_ADDR: ip_addr,
            })
        elif route_type == EVPN_IP_PREFIX_ROUTE:
            kwargs.update({
                EVPN_ESI: esi,
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
                IP_PREFIX: ip_prefix,
                GW_IP_ADDR: gw_ip_addr,
            })
            # Set tunnel type specific arguments
            if tunnel_type in [TUNNEL_TYPE_VXLAN, TUNNEL_TYPE_NVGRE]:
                kwargs[EVPN_VNI] = vni

            # Add mac_mobility
            if mac_mobility is not None:
                kwargs[MAC_MOBILITY] = int(mac_mobility)
        else:
            raise ValueError('Unsupported EVPN route type: %s' % route_type)

        call(func_name, **kwargs)

    def evpn_prefix_del(self, route_type, route_dist, esi=0,
                        ethernet_tag_id=None, mac_addr=None, ip_addr=None,
                        ip_prefix=None):
        """ This method deletes an advertised EVPN route.

        ``route_type`` specifies one of the EVPN route type name.

        ``route_dist`` specifies a route distinguisher value.

        ``esi`` is an value to specify the Ethernet Segment Identifier.

        ``ethernet_tag_id`` specifies the Ethernet Tag ID.

        ``mac_addr`` specifies a MAC address to advertise.

        ``ip_addr`` specifies an IPv4 or IPv6 address to advertise.

        ``ip_prefix`` specifies an IPv4 or IPv6 prefix to advertise.
        """
        func_name = 'evpn_prefix.delete_local'

        # Set required arguments
        kwargs = {EVPN_ROUTE_TYPE: route_type,
                  ROUTE_DISTINGUISHER: route_dist}

        # Set route type specific arguments
        if route_type == EVPN_ETH_AUTO_DISCOVERY:
            kwargs.update({
                EVPN_ESI: esi,
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
            })
        elif route_type == EVPN_MAC_IP_ADV_ROUTE:
            kwargs.update({
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
                MAC_ADDR: mac_addr,
                IP_ADDR: ip_addr,
            })
        elif route_type == EVPN_MULTICAST_ETAG_ROUTE:
            kwargs.update({
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
                IP_ADDR: ip_addr,
            })
        elif route_type == EVPN_ETH_SEGMENT:
            kwargs.update({
                EVPN_ESI: esi,
                IP_ADDR: ip_addr,
            })
        elif route_type == EVPN_IP_PREFIX_ROUTE:
            kwargs.update({
                EVPN_ETHERNET_TAG_ID: ethernet_tag_id,
                IP_PREFIX: ip_prefix,
            })
        else:
            raise ValueError('Unsupported EVPN route type: %s' % route_type)

        call(func_name, **kwargs)

    def flowspec_prefix_add(self, flowspec_family, rules, route_dist=None,
                            actions=None):
        """ This method adds a new Flow Specification prefix to be advertised.

        ``flowspec_family`` specifies one of the flowspec family name.
        This parameter must be one of the following.

        - FLOWSPEC_FAMILY_IPV4  = 'ipv4fs'
        - FLOWSPEC_FAMILY_IPV6  = 'ipv6fs'
        - FLOWSPEC_FAMILY_VPNV4 = 'vpnv4fs'
        - FLOWSPEC_FAMILY_VPNV6 = 'vpnv6fs'
        - FLOWSPEC_FAMILY_L2VPN = 'l2vpnfs'

        ``rules`` specifies NLRIs of Flow Specification as
        a dictionary type value.
        For the supported NLRI types and arguments,
        see `from_user()` method of the following classes.

        - :py:mod:`ryu.lib.packet.bgp.FlowSpecIPv4NLRI`
        - :py:mod:`ryu.lib.packet.bgp.FlowSpecIPv6NLRI`
        - :py:mod:`ryu.lib.packet.bgp.FlowSpecVPNv4NLRI`
        - :py:mod:`ryu.lib.packet.bgp.FlowSpecVPNv6NLRI`
        - :py:mod:`ryu.lib.packet.bgp.FlowSpecL2VPNNLRI`

        ``route_dist`` specifies a route distinguisher value.
        This parameter is required only if flowspec_family is one of the
        following address family.

        - FLOWSPEC_FAMILY_VPNV4 = 'vpnv4fs'
        - FLOWSPEC_FAMILY_VPNV6 = 'vpnv6fs'
        - FLOWSPEC_FAMILY_L2VPN = 'l2vpnfs'

        ``actions`` specifies Traffic Filtering Actions of
        Flow Specification as a dictionary type value.
        The keys are "ACTION_NAME" for each action class and
        values are used for the arguments to that class.
        For the supported "ACTION_NAME" and arguments,
        see the following table.

        =============== ===============================================================
        ACTION_NAME     Action Class
        =============== ===============================================================
        traffic_rate    :py:mod:`ryu.lib.packet.bgp.BGPFlowSpecTrafficRateCommunity`
        traffic_action  :py:mod:`ryu.lib.packet.bgp.BGPFlowSpecTrafficActionCommunity`
        redirect        :py:mod:`ryu.lib.packet.bgp.BGPFlowSpecRedirectCommunity`
        traffic_marking :py:mod:`ryu.lib.packet.bgp.BGPFlowSpecTrafficMarkingCommunity`
        vlan_action     :py:mod:`ryu.lib.packet.bgp.BGPFlowSpecVlanActionCommunity`
        tpid_action     :py:mod:`ryu.lib.packet.bgp.BGPFlowSpecTPIDActionCommunity`
        =============== ===============================================================

        Example(IPv4)::

            >>> speaker = BGPSpeaker(as_number=65001, router_id='172.17.0.1')
            >>> speaker.neighbor_add(address='172.17.0.2',
            ...                      remote_as=65002,
            ...                      enable_ipv4fs=True)
            >>> speaker.flowspec_prefix_add(
            ...     flowspec_family=FLOWSPEC_FAMILY_IPV4,
            ...     rules={
            ...         'dst_prefix': '10.60.1.0/24'
            ...     },
            ...     actions={
            ...         'traffic_marking': {
            ...             'dscp': 24
            ...         }
            ...     }
            ... )

        Example(VPNv4)::

            >>> speaker = BGPSpeaker(as_number=65001, router_id='172.17.0.1')
            >>> speaker.neighbor_add(address='172.17.0.2',
            ...                      remote_as=65002,
            ...                      enable_vpnv4fs=True)
            >>> speaker.vrf_add(route_dist='65001:100',
            ...                 import_rts=['65001:100'],
            ...                 export_rts=['65001:100'],
            ...                 route_family=RF_VPNV4_FLOWSPEC)
            >>> speaker.flowspec_prefix_add(
            ...     flowspec_family=FLOWSPEC_FAMILY_VPNV4,
            ...     route_dist='65000:100',
            ...     rules={
            ...         'dst_prefix': '10.60.1.0/24'
            ...     },
            ...     actions={
            ...         'traffic_marking': {
            ...             'dscp': 24
            ...         }
            ...     }
            ... )
        """
        func_name = 'flowspec.add'

        # Set required arguments
        kwargs = {
            FLOWSPEC_FAMILY: flowspec_family,
            FLOWSPEC_RULES: rules,
            FLOWSPEC_ACTIONS: actions or {},
        }

        if flowspec_family in [FLOWSPEC_FAMILY_VPNV4, FLOWSPEC_FAMILY_VPNV6,
                               FLOWSPEC_FAMILY_L2VPN]:
            func_name = 'flowspec.add_local'
            kwargs.update({ROUTE_DISTINGUISHER: route_dist})

        call(func_name, **kwargs)

    def flowspec_prefix_del(self, flowspec_family, rules, route_dist=None):
        """ This method deletes an advertised Flow Specification route.

        ``flowspec_family`` specifies one of the flowspec family name.

        ``rules`` specifies NLRIs of Flow Specification as
        a dictionary type value.

        ``route_dist`` specifies a route distinguisher value.
        """
        func_name = 'flowspec.del'

        # Set required arguments
        kwargs = {
            FLOWSPEC_FAMILY: flowspec_family,
            FLOWSPEC_RULES: rules,
        }

        if flowspec_family in [FLOWSPEC_FAMILY_VPNV4, FLOWSPEC_FAMILY_VPNV6,
                               FLOWSPEC_FAMILY_L2VPN]:
            func_name = 'flowspec.del_local'
            kwargs.update({ROUTE_DISTINGUISHER: route_dist})

        call(func_name, **kwargs)

    def vrf_add(self, route_dist, import_rts, export_rts, site_of_origins=None,
                route_family=RF_VPN_V4, multi_exit_disc=None):
        """ This method adds a new vrf used for VPN.

        ``route_dist`` specifies a route distinguisher value.

        ``import_rts`` specifies a list of route targets to be imported.

        ``export_rts`` specifies a list of route targets to be exported.

        ``site_of_origins`` specifies site_of_origin values.
        This parameter must be a list of string.

        ``route_family`` specifies route family of the VRF.
        This parameter must be one of the following.

        - RF_VPN_V4 (default) = 'ipv4'
        - RF_VPN_V6           = 'ipv6'
        - RF_L2_EVPN          = 'evpn'
        - RF_VPNV4_FLOWSPEC   = 'ipv4fs'
        - RF_VPNV6_FLOWSPEC   = 'ipv6fs'
        - RF_L2VPN_FLOWSPEC   = 'l2vpnfs'

        ``multi_exit_disc`` specifies multi exit discriminator (MED) value.
        It must be an integer.
        """
        if route_family not in SUPPORTED_VRF_RF:
            raise ValueError('Unsupported route_family: %s' % route_family)

        vrf = {
            vrfs.ROUTE_DISTINGUISHER: route_dist,
            vrfs.IMPORT_RTS: import_rts,
            vrfs.EXPORT_RTS: export_rts,
            vrfs.SITE_OF_ORIGINS: site_of_origins,
            vrfs.VRF_RF: route_family,
            vrfs.MULTI_EXIT_DISC: multi_exit_disc,
        }

        call('vrf.create', **vrf)

    def vrf_del(self, route_dist):
        """ This method deletes the existing vrf.

        ``route_dist`` specifies a route distinguisher value.
        """

        vrf = {vrfs.ROUTE_DISTINGUISHER: route_dist}

        call('vrf.delete', **vrf)

    def vrfs_get(self, subcommand='routes', route_dist=None,
                 route_family='all', format='json'):
        """ This method returns the existing vrfs.

        ``subcommand`` specifies one of the following.

        - 'routes': shows routes present for vrf
        - 'summary': shows configuration and summary of vrf

        ``route_dist`` specifies a route distinguisher value.
        If route_family is not 'all', this value must be specified.

        ``route_family`` specifies route family of the VRF.
        This parameter must be one of the following.

        - RF_VPN_V4  = 'ipv4'
        - RF_VPN_V6  = 'ipv6'
        - RF_L2_EVPN = 'evpn'
        - 'all' (default)

        ``format`` specifies the format of the response.
        This parameter must be one of the following.

        - 'json' (default)
        - 'cli'
        """
        show = {
            'format': format,
        }
        if route_family in SUPPORTED_VRF_RF:
            assert route_dist is not None
            show['params'] = ['vrf', subcommand, route_dist, route_family]
        else:
            show['params'] = ['vrf', subcommand, 'all']

        return call('operator.show', **show)

    def rib_get(self, family='all', format='json'):
        """ This method returns the BGP routing information in a json
        format. This will be improved soon.

        ``family`` specifies the address family of the RIB (e.g. 'ipv4').

        ``format`` specifies the format of the response.
        This parameter must be one of the following.

        - 'json' (default)
        - 'cli'
        """
        show = {
            'params': ['rib', family],
            'format': format
        }

        return call('operator.show', **show)

    def neighbor_get(self, route_type, address, format='json'):
        """ This method returns the BGP adj-RIB-in/adj-RIB-out information
        in a json format.

        ``route_type`` This parameter is necessary for only received-routes
        and sent-routes.

        - received-routes : paths received and not withdrawn by given peer
        - sent-routes : paths sent and not withdrawn to given peer

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address.

        ``format`` specifies the format of the response.
        This parameter must be one of the following.

        - 'json' (default)
        - 'cli'
        """
        show = {
            'format': format,
        }
        if route_type == 'sent-routes' or route_type == 'received-routes':
            show['params'] = ['neighbor', route_type, address, 'all']
        else:
            show['params'] = ['neighbor', 'received-routes', address, 'all']

        return call('operator.show', **show)

    def neighbors_get(self, format='json'):
        """ This method returns a list of the BGP neighbors.

        ``format`` specifies the format of the response.
        This parameter must be one of the following.

        - 'json' (default)
        - 'cli'
        """
        show = {
            'params': ['neighbor'],
            'format': format,
        }

        return call('operator.show', **show)

    def _set_filter(self, filter_type, address, filters):
        assert filter_type in ('in', 'out'), (
            "filter type must be 'in' or 'out'")

        assert all(isinstance(f, Filter) for f in filters), (
            'all the items in filters must be an instance of Filter sub-class')

        if filters is None:
            filters = []

        func_name = 'neighbor.' + filter_type + '_filter.set'
        param = {
            neighbors.IP_ADDRESS: address,
        }
        if filter_type == 'in':
            param[neighbors.IN_FILTER] = filters
        else:
            param[neighbors.OUT_FILTER] = filters

        call(func_name, **param)

    def out_filter_set(self, address, filters):
        """ This method sets out-filter to neighbor.

        ``address`` specifies the IP address of the peer.

        ``filters`` specifies a filter list to filter the path advertisement.
        The contents must be an instance of Filter sub-class

        If you want to define out-filter that send only a particular
        prefix to neighbor, filters can be created as follows::

            p = PrefixFilter('10.5.111.0/24',
                             policy=PrefixFilter.POLICY_PERMIT)

            all = PrefixFilter('0.0.0.0/0',
                               policy=PrefixFilter.POLICY_DENY)

            pList = [p, all]

            self.bgpspeaker.out_filter_set(neighbor_address, pList)

        .. Note::

            out-filter evaluates paths in the order of Filter in the pList.
        """

        self._set_filter('out', address, filters)

    def out_filter_get(self, address):
        """ This method gets out-filter setting from the specified neighbor.

        ``address`` specifies the IP address of the peer.

        Returns a list object containing an instance of Filter sub-class
        """

        func_name = 'neighbor.out_filter.get'
        param = {
            neighbors.IP_ADDRESS: address,
        }

        return call(func_name, **param)

    def in_filter_set(self, address, filters):
        """This method sets in-bound filters to a neighbor.

        ``address`` specifies the IP address of the neighbor

        ``filters`` specifies filter list applied before advertised paths are
        imported to the global rib. All the items in the list must be an
        instance of Filter sub-class.
        """

        self._set_filter('in', address, filters)

    def in_filter_get(self, address):
        """This method gets in-bound filters of the specified neighbor.

        ``address`` specifies the IP address of the neighbor.

        Returns a list object containing an instance of Filter sub-class
        """

        func_name = 'neighbor.in_filter.get'
        param = {
            neighbors.IP_ADDRESS: address,
        }

        return call(func_name, **param)

    def bmp_server_add(self, address, port):
        """This method registers a new BMP (BGP monitoring Protocol)
        server. The BGP speaker starts to send BMP messages to the
        server. Currently, only one BMP server can be registered.

        ``address`` specifies the IP address of a BMP server.

        ``port`` specifies the listen port number of a BMP server.
        """

        func_name = 'bmp.start'
        param = {
            'host': address,
            'port': port,
        }

        call(func_name, **param)

    def bmp_server_del(self, address, port):
        """ This method unregister the registered BMP server.

        ``address`` specifies the IP address of a BMP server.

        ``port`` specifies the listen port number of a BMP server.
        """

        func_name = 'bmp.stop'
        param = {
            'host': address,
            'port': port,
        }

        call(func_name, **param)

    def attribute_map_set(self, address, attribute_maps,
                          route_dist=None, route_family=RF_VPN_V4):
        """This method sets attribute mapping to a neighbor.
        attribute mapping can be used when you want to apply
        attribute to BGPUpdate under specific conditions.

        ``address`` specifies the IP address of the neighbor

        ``attribute_maps`` specifies attribute_map list that are used
        before paths are advertised. All the items in the list must
        be an instance of AttributeMap class

        ``route_dist`` specifies route dist in which attribute_maps
        are added.

        ``route_family`` specifies route family of the VRF.
        This parameter must be one of the following.

        - RF_VPN_V4 (default) = 'ipv4'
        - RF_VPN_V6           = 'ipv6'

        We can set AttributeMap to a neighbor as follows::

            pref_filter = PrefixFilter('192.168.103.0/30',
                                       PrefixFilter.POLICY_PERMIT)

            attribute_map = AttributeMap([pref_filter],
                                         AttributeMap.ATTR_LOCAL_PREF, 250)

            speaker.attribute_map_set('192.168.50.102', [attribute_map])
        """

        if route_family not in SUPPORTED_VRF_RF:
            raise ValueError('Unsupported route_family: %s' % route_family)

        func_name = 'neighbor.attribute_map.set'
        param = {
            neighbors.IP_ADDRESS: address,
            neighbors.ATTRIBUTE_MAP: attribute_maps,
        }
        if route_dist is not None:
            param[vrfs.ROUTE_DISTINGUISHER] = route_dist
            param[vrfs.VRF_RF] = route_family

        call(func_name, **param)

    def attribute_map_get(self, address, route_dist=None,
                          route_family=RF_VPN_V4):
        """This method gets in-bound filters of the specified neighbor.

        ``address`` specifies the IP address of the neighbor.

        ``route_dist`` specifies route distinguisher that has attribute_maps.

        ``route_family`` specifies route family of the VRF.
        This parameter must be one of the following.

        - RF_VPN_V4 (default) = 'ipv4'
        - RF_VPN_V6           = 'ipv6'

        Returns a list object containing an instance of AttributeMap
        """

        if route_family not in SUPPORTED_VRF_RF:
            raise ValueError('Unsupported route_family: %s' % route_family)

        func_name = 'neighbor.attribute_map.get'
        param = {
            neighbors.IP_ADDRESS: address,
        }
        if route_dist is not None:
            param[vrfs.ROUTE_DISTINGUISHER] = route_dist
            param[vrfs.VRF_RF] = route_family

        return call(func_name, **param)

    @staticmethod
    def _check_rf_and_normalize(prefix):
        """ check prefix's route_family and if the address is
        IPv6 address, return IPv6 route_family and normalized IPv6 address.
        If the address is IPv4 address, return IPv4 route_family
        and the prefix itself.
        """
        addr, masklen = prefix.split('/')
        if ip.valid_ipv6(addr):
            # normalize IPv6 address
            ipv6_prefix = str(netaddr.IPAddress(addr)) + '/' + masklen
            return vrfs.VRF_RF_IPV6, ipv6_prefix
        else:
            return vrfs.VRF_RF_IPV4, prefix
