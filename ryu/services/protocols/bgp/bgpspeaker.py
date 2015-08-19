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

from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.signals.emit import BgpSignalBus
from ryu.services.protocols.bgp.api.base import call
from ryu.services.protocols.bgp.api.base import PREFIX
from ryu.services.protocols.bgp.api.base import NEXT_HOP
from ryu.services.protocols.bgp.api.base import ROUTE_DISTINGUISHER
from ryu.services.protocols.bgp.api.base import ROUTE_FAMILY
from ryu.services.protocols.bgp.rtconf.common import LOCAL_AS
from ryu.services.protocols.bgp.rtconf.common import ROUTER_ID
from ryu.services.protocols.bgp.rtconf.common import BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common \
    import DEFAULT_REFRESH_MAX_EOR_TIME
from ryu.services.protocols.bgp.rtconf.common \
    import DEFAULT_REFRESH_STALEPATH_TIME
from ryu.services.protocols.bgp.rtconf.common \
    import DEFAULT_BGP_CONN_RETRY_TIME
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_LABEL_RANGE
from ryu.services.protocols.bgp.rtconf.common import REFRESH_MAX_EOR_TIME
from ryu.services.protocols.bgp.rtconf.common import REFRESH_STALEPATH_TIME
from ryu.services.protocols.bgp.rtconf.common import LABEL_RANGE
from ryu.services.protocols.bgp.rtconf import neighbors
from ryu.services.protocols.bgp.rtconf import vrfs
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV6
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.rtconf.base import MULTI_EXIT_DISC
from ryu.services.protocols.bgp.rtconf.base import SITE_OF_ORIGINS
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_IPV4
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CONNECT_MODE
from ryu.services.protocols.bgp.rtconf.neighbors import PEER_NEXT_HOP
from ryu.services.protocols.bgp.rtconf.neighbors import PASSWORD
from ryu.services.protocols.bgp.rtconf.neighbors import IN_FILTER
from ryu.services.protocols.bgp.rtconf.neighbors import OUT_FILTER
from ryu.services.protocols.bgp.rtconf.neighbors import IS_ROUTE_SERVER_CLIENT
from ryu.services.protocols.bgp.rtconf.neighbors import IS_NEXT_HOP_SELF
from ryu.services.protocols.bgp.rtconf.neighbors import CONNECT_MODE
from ryu.services.protocols.bgp.rtconf.neighbors import LOCAL_ADDRESS
from ryu.services.protocols.bgp.rtconf.neighbors import LOCAL_PORT
from ryu.services.protocols.bgp.info_base.base import Filter
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Path
from ryu.services.protocols.bgp.info_base.ipv6 import Ipv6Path
from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Path
from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Path


NEIGHBOR_CONF_MED = 'multi_exit_disc'
RF_VPN_V4 = vrfs.VRF_RF_IPV4
RF_VPN_V6 = vrfs.VRF_RF_IPV6


class EventPrefix(object):
    """
    Used to pass an update on any best remote path to
    best_path_change_handler.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    remote_as        The AS number of a peer that caused this change
    route_dist       None in the case of ipv4 or ipv6 family
    prefix           A prefix was changed
    nexthop          The nexthop of the changed prefix
    label            mpls label for vpnv4 prefix
    is_withdraw      True if this prefix has gone otherwise False
    ================ ======================================================

    """

    def __init__(self, remote_as, route_dist, prefix, nexthop, label,
                 is_withdraw):
        self.remote_as = remote_as
        self.route_dist = route_dist
        self.prefix = prefix
        self.nexthop = nexthop
        self.label = label
        self.is_withdraw = is_withdraw


class BGPSpeaker(object):
    def __init__(self, as_number, router_id,
                 bgp_server_port=DEFAULT_BGP_SERVER_PORT,
                 refresh_stalepath_time=DEFAULT_REFRESH_STALEPATH_TIME,
                 refresh_max_eor_time=DEFAULT_REFRESH_MAX_EOR_TIME,
                 best_path_change_handler=None,
                 peer_down_handler=None,
                 peer_up_handler=None,
                 ssh_console=False,
                 label_range=DEFAULT_LABEL_RANGE):
        """Create a new BGPSpeaker object with as_number and router_id to
        listen on bgp_server_port.

        ``as_number`` specifies an Autonomous Number. It must be an integer
        between 1 and 65535.

        ``router_id`` specifies BGP router identifier. It must be the
        string representation of an IPv4 address (e.g. 10.0.0.1).

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

        ``peer_down_handler``, if specified, is called when BGP peering
        session goes down.

        ``peer_up_handler``, if specified, is called when BGP peering
        session goes up.

        """
        super(BGPSpeaker, self).__init__()

        settings = {}
        settings[LOCAL_AS] = as_number
        settings[ROUTER_ID] = router_id
        settings[BGP_SERVER_PORT] = bgp_server_port
        settings[REFRESH_STALEPATH_TIME] = refresh_stalepath_time
        settings[REFRESH_MAX_EOR_TIME] = refresh_max_eor_time
        settings[LABEL_RANGE] = label_range
        self._core_start(settings)
        self._init_signal_listeners()
        self._best_path_change_handler = best_path_change_handler
        self._peer_down_handler = peer_down_handler
        self._peer_up_handler = peer_up_handler
        if ssh_console:
            from ryu.services.protocols.bgp.operator import ssh

            hub.spawn(ssh.SSH_CLI_CONTROLLER.start)

    def _notify_peer_down(self, peer):
        remote_ip = peer.protocol.recv_open_msg.bgp_identifier
        remote_as = peer.protocol.recv_open_msg.my_as
        if self._peer_down_handler:
            self._peer_down_handler(remote_ip, remote_as)

    def _notify_peer_up(self, peer):
        remote_ip = peer.protocol.recv_open_msg.bgp_identifier
        remote_as = peer.protocol.recv_open_msg.my_as
        if self._peer_up_handler:
            self._peer_up_handler(remote_ip, remote_as)

    def _notify_best_path_changed(self, path, is_withdraw):
        if path.source:
            nexthop = path.nexthop
            is_withdraw = is_withdraw
            remote_as = path.source.remote_as
        else:
            return

        if isinstance(path, Ipv4Path) or isinstance(path, Ipv6Path):
            prefix = path.nlri.addr + '/' + str(path.nlri.length)
            route_dist = None
            label = None
        elif isinstance(path, Vpnv4Path) or isinstance(path, Vpnv6Path):
            prefix = path.nlri.prefix
            route_dist = path.nlri.route_dist
            label = path.nlri.label_list
        else:
            return

        ev = EventPrefix(remote_as, route_dist, prefix, nexthop, label,
                         is_withdraw)

        if self._best_path_change_handler:
            self._best_path_change_handler(ev)

    def _init_signal_listeners(self):
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            BgpSignalBus.BGP_BEST_PATH_CHANGED,
            lambda _, info:
            self._notify_best_path_changed(info['path'],
                                           info['is_withdraw'])
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
                     enable_ipv4=DEFAULT_CAP_MBGP_IPV4,
                     enable_vpnv4=DEFAULT_CAP_MBGP_VPNV4,
                     enable_vpnv6=DEFAULT_CAP_MBGP_VPNV6,
                     next_hop=None, password=None, multi_exit_disc=None,
                     site_of_origins=None, is_route_server_client=False,
                     is_next_hop_self=False, local_address=None,
                     local_port=None, connect_mode=DEFAULT_CONNECT_MODE):
        """ This method registers a new neighbor. The BGP speaker tries to
        establish a bgp session with the peer (accepts a connection
        from the peer and also tries to connect to it).

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address. Only IP v4 is
        supported now.

        ``remote_as`` specifies the AS number of the peer. It must be
        an integer between 1 and 65535.

        ``enable_ipv4`` enables IPv4 address family for this
        neighbor. The default is True.

        ``enable_vpnv4`` enables VPNv4 address family for this
        neighbor. The default is False.

        ``enable_vpnv6`` enables VPNv6 address family for this
        neighbor. The default is False.

        ``next_hop`` specifies the next hop IP address. If not
        specified, host's ip address to access to a peer is used.

        ``password`` is used for the MD5 authentication if it's
        specified. By default, the MD5 authenticaiton is disabled.

        ``multi_exit_disc`` specifies multi exit discriminator (MED) value.
        The default is None and if not specified, MED value is
        not sent to the neighbor. It must be an integer.

        ``site_of_origins`` specifies site_of_origin values.
        This parameter must be a list of string.

        ``is_route_server_client`` specifies whether this neighbor is a
        router server's client or not.

        ``is_next_hop_self`` specifies whether the BGP speaker announces
        its own ip address to iBGP neighbor or not as path's next_hop address.

        ``connect_mode`` specifies how to connect to this neighbor.
        CONNECT_MODE_ACTIVE tries to connect from us.
        CONNECT_MODE_PASSIVE just listens and wait for the connection.
        CONNECT_MODE_BOTH use both methods.
        The default is CONNECT_MODE_BOTH

        ``local_address`` specifies Loopback interface address for
        iBGP peering.

        ``local_port`` specifies source TCP port for iBGP peering.

        """
        bgp_neighbor = {}
        bgp_neighbor[neighbors.IP_ADDRESS] = address
        bgp_neighbor[neighbors.REMOTE_AS] = remote_as
        bgp_neighbor[PEER_NEXT_HOP] = next_hop
        bgp_neighbor[PASSWORD] = password
        bgp_neighbor[IS_ROUTE_SERVER_CLIENT] = is_route_server_client
        bgp_neighbor[IS_NEXT_HOP_SELF] = is_next_hop_self
        bgp_neighbor[CONNECT_MODE] = connect_mode
        # v6 advertizement is available with only v6 peering
        if netaddr.valid_ipv4(address):
            bgp_neighbor[CAP_MBGP_IPV4] = enable_ipv4
            bgp_neighbor[CAP_MBGP_IPV6] = False
            bgp_neighbor[CAP_MBGP_VPNV4] = enable_vpnv4
            bgp_neighbor[CAP_MBGP_VPNV6] = enable_vpnv6
        elif netaddr.valid_ipv6(address):
            bgp_neighbor[CAP_MBGP_IPV4] = False
            bgp_neighbor[CAP_MBGP_IPV6] = True
            bgp_neighbor[CAP_MBGP_VPNV4] = False
            bgp_neighbor[CAP_MBGP_VPNV6] = False
        else:
            # FIXME: should raise an exception
            pass

        if multi_exit_disc:
            bgp_neighbor[MULTI_EXIT_DISC] = multi_exit_disc

        if site_of_origins:
            bgp_neighbor[SITE_OF_ORIGINS] = site_of_origins

        if local_address:
            bgp_neighbor[LOCAL_ADDRESS] = local_address

        if local_port:
            bgp_neighbor[LOCAL_PORT] = local_port

        call('neighbor.create', **bgp_neighbor)

    def neighbor_del(self, address):
        """ This method unregister the registered neighbor. If a session with
        the peer exists, the session will be closed.

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address.

        """
        bgp_neighbor = {}
        bgp_neighbor[neighbors.IP_ADDRESS] = address
        call('neighbor.delete', **bgp_neighbor)

    def neighbor_reset(self, address):
        """ This method reset the registered neighbor.

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address.

        """
        bgp_neighbor = {}
        bgp_neighbor[neighbors.IP_ADDRESS] = address
        call('core.reset_neighbor', **bgp_neighbor)

    def neighbor_update(self, address, conf_type, conf_value):
        """ This method changes the neighbor configuration.

        ``conf_type`` specifies configuration type which you want to change.
        Currently ryu.services.protocols.bgp.bgpspeaker.NEIGHBOR_CONF_MED
        can be specified.

        ``conf_value`` specifies value for the configuration type.

        """

        assert conf_type == NEIGHBOR_CONF_MED or conf_type == CONNECT_MODE

        func_name = 'neighbor.update'
        attribute_param = {}
        if conf_type == NEIGHBOR_CONF_MED:
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

        """
        show = {}
        show['params'] = ['neighbor', 'summary']
        if address:
            show['params'].append(address)
        show['format'] = format
        return call('operator.show', **show)

    def prefix_add(self, prefix, next_hop=None, route_dist=None):
        """ This method adds a new prefix to be advertized.

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
        networks = {}
        networks[PREFIX] = prefix
        if next_hop:
            networks[NEXT_HOP] = next_hop
        if route_dist:
            func_name = 'prefix.add_local'
            networks[ROUTE_DISTINGUISHER] = route_dist

            rf, p = self._check_rf_and_normalize(prefix)
            networks[ROUTE_FAMILY] = rf
            networks[PREFIX] = p

            if rf == vrfs.VRF_RF_IPV6 and netaddr.valid_ipv4(next_hop):
                # convert the next_hop to IPv4-Mapped IPv6 Address
                networks[NEXT_HOP] = \
                    str(netaddr.IPAddress(next_hop).ipv6())

        return call(func_name, **networks)

    def prefix_del(self, prefix, route_dist=None):
        """ This method deletes a advertized prefix.

        ``prefix`` must be the string representation of an IP network
        (e.g., 10.1.1.0/24).

        ``route_dist`` specifies a route distinguisher value. This
        parameter is necessary for only VPNv4 and VPNv6 address
        families.

        """
        func_name = 'network.del'
        networks = {}
        networks[PREFIX] = prefix
        if route_dist:
            func_name = 'prefix.delete_local'
            networks[ROUTE_DISTINGUISHER] = route_dist

            rf, p = self._check_rf_and_normalize(prefix)
            networks[ROUTE_FAMILY] = rf
            networks[PREFIX] = p

        call(func_name, **networks)

    def vrf_add(self, route_dist, import_rts, export_rts, site_of_origins=None,
                route_family=RF_VPN_V4, multi_exit_disc=None):
        """ This method adds a new vrf used for VPN.

        ``route_dist`` specifies a route distinguisher value.

        ``import_rts`` specifies route targets to be imported.

        ``export_rts`` specifies route targets to be exported.

        ``site_of_origins`` specifies site_of_origin values.
        This parameter must be a list of string.

        ``route_family`` specifies route family of the VRF.
        This parameter must be RF_VPN_V4 or RF_VPN_V6.
        """

        assert route_family in (RF_VPN_V4, RF_VPN_V6),\
            'route_family must be RF_VPN_V4 or RF_VPN_V6'

        vrf = {}
        vrf[vrfs.ROUTE_DISTINGUISHER] = route_dist
        vrf[vrfs.IMPORT_RTS] = import_rts
        vrf[vrfs.EXPORT_RTS] = export_rts
        vrf[vrfs.SITE_OF_ORIGINS] = site_of_origins
        vrf[vrfs.VRF_RF] = route_family
        call('vrf.create', **vrf)

    def vrf_del(self, route_dist):
        """ This method deletes the existing vrf.

        ``route_dist`` specifies a route distinguisher value.

        """

        vrf = {}
        vrf[vrfs.ROUTE_DISTINGUISHER] = route_dist
        call('vrf.delete', **vrf)

    def vrfs_get(self, format='json'):
        show = {}
        show['params'] = ['vrf', 'routes', 'all']
        show['format'] = format
        return call('operator.show', **show)

    def rib_get(self, family='ipv4', format='json'):
        """ This method returns the BGP routing information in a json
        format. This will be improved soon.

        ``family`` specifies the address family of the RIB.

        """
        show = {}
        show['params'] = ['rib', family]
        show['format'] = format
        return call('operator.show', **show)

    def neighbor_get(self, routetype, address, format='json'):
        """ This method returns the BGP adj-RIB-in information in a json
        format.

        ``routetype`` This parameter is necessary for only received-routes
        and sent-routes.

          received-routes : paths received and not withdrawn by given peer

          sent-routes : paths sent and not withdrawn to given peer

        ``address`` specifies the IP address of the peer. It must be
        the string representation of an IP address.

        """
        show = {}
        if routetype == 'sent-routes' or routetype == 'received-routes':
            show['params'] = ['neighbor', routetype, address, 'all']
        else:
            show['params'] = ['neighbor', 'received-routes', address, 'all']
        show['format'] = format
        return call('operator.show', **show)

    def _set_filter(self, filter_type, address, filters):
        assert filter_type in ('in', 'out'),\
            'filter type must be \'in\' or \'out\''

        assert all(isinstance(f, Filter) for f in filters),\
            'all the items in filters must be an instance of Filter sub-class'

        if filters is None:
            filters = []

        func_name = 'neighbor.' + filter_type + '_filter.set'
        param = {}
        param[neighbors.IP_ADDRESS] = address
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
        prefix to neighbor, filters can be created as follows;

          p = PrefixFilter('10.5.111.0/24',
                           policy=PrefixFilter.POLICY_PERMIT)

          all = PrefixFilter('0.0.0.0/0',
                             policy=PrefixFilter.POLICY_DENY)

          pList = [p, all]

          self.bgpspeaker.out_filter_set(neighbor_address, pList)

        NOTE:
        out-filter evaluates paths in the order of Filter in the pList.

        """

        self._set_filter('out', address, filters)

    def out_filter_get(self, address):
        """ This method gets out-filter setting from the specified neighbor.

        ``address`` specifies the IP address of the peer.

        Returns a list object containing an instance of Filter sub-class

        """

        func_name = 'neighbor.out_filter.get'
        param = {}
        param[neighbors.IP_ADDRESS] = address
        out_filter = call(func_name, **param)
        return out_filter

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
        param = {}
        param[neighbors.IP_ADDRESS] = address
        in_filter = call(func_name, **param)
        return in_filter

    def bmp_server_add(self, address, port):
        """This method registers a new BMP (BGP monitoring Protocol)
        server. The BGP speaker starts to send BMP messages to the
        server. Currently, only one BMP server can be registered.

        ``address`` specifies the IP address of a BMP server.

        ``port`` specifies the listen port number of a BMP server.
        """

        func_name = 'bmp.start'
        param = {}
        param['host'] = address
        param['port'] = port
        call(func_name, **param)

    def bmp_server_del(self, address, port):
        """ This method unregister the registered BMP server.

        ``address`` specifies the IP address of a BMP server.

        ``port`` specifies the listen port number of a BMP server.
        """

        func_name = 'bmp.stop'
        param = {}
        param['host'] = address
        param['port'] = port
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
        This parameter must be RF_VPN_V4 or RF_VPN_V6.

        We can set AttributeMap to a neighbor as follows;

          pref_filter = PrefixFilter('192.168.103.0/30',
                                     PrefixFilter.POLICY_PERMIT)

          attribute_map = AttributeMap([pref_filter],
                                       AttributeMap.ATTR_LOCAL_PREF, 250)

          speaker.attribute_map_set('192.168.50.102', [attribute_map])

        """

        assert route_family in (RF_VPN_V4, RF_VPN_V6),\
            'route_family must be RF_VPN_V4 or RF_VPN_V6'

        func_name = 'neighbor.attribute_map.set'
        param = {}
        param[neighbors.IP_ADDRESS] = address
        param[neighbors.ATTRIBUTE_MAP] = attribute_maps
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
        This parameter must be RF_VPN_V4 or RF_VPN_V6.

        Returns a list object containing an instance of AttributeMap

        """

        assert route_family in (RF_VPN_V4, RF_VPN_V6),\
            'route_family must be RF_VPN_V4 or RF_VPN_V6'

        func_name = 'neighbor.attribute_map.get'
        param = {}
        param[neighbors.IP_ADDRESS] = address
        if route_dist is not None:
            param[vrfs.ROUTE_DISTINGUISHER] = route_dist
            param[vrfs.VRF_RF] = route_family
        attribute_maps = call(func_name, **param)
        return attribute_maps

    @staticmethod
    def _check_rf_and_normalize(prefix):
        """ check prefix's route_family and if the address is
        IPv6 address, return IPv6 route_family and normalized IPv6 address.
        If the address is IPv4 address, return IPv4 route_family
        and the prefix itself.

        """
        ip, masklen = prefix.split('/')
        if netaddr.valid_ipv6(ip):
            # normalize IPv6 address
            ipv6_prefix = str(netaddr.IPAddress(ip)) + '/' + masklen
            return vrfs.VRF_RF_IPV6, ipv6_prefix
        else:
            return vrfs.VRF_RF_IPV4, prefix
