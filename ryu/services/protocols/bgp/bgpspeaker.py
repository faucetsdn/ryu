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
from ryu.base import app_manager
from ryu.services.protocols.bgp.operator import ssh

from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.signals.emit import BgpSignalBus
from ryu.services.protocols.bgp.api.base import call
from ryu.services.protocols.bgp.api.base import PREFIX
from ryu.services.protocols.bgp.api.base import NEXT_HOP
from ryu.services.protocols.bgp.api.base import ROUTE_DISTINGUISHER
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
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_IPV4
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.rtconf.neighbors import PEER_NEXT_HOP
from ryu.services.protocols.bgp.rtconf.neighbors import PASSWORD
from ryu.services.protocols.bgp.rtconf.neighbors import OUT_FILTER
from ryu.services.protocols.bgp.application import RyuBGPSpeaker
from netaddr.ip import IPAddress, IPNetwork
from ryu.lib.packet.bgp import RF_IPv4_UC, RF_IPv6_UC


OUT_FILTER_RF_IPv4_UC = RF_IPv4_UC
OUT_FILTER_RF_IPv6_UC = RF_IPv6_UC
NEIGHBOR_CONF_MED = 'multi_exit_disc'


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
    is_withdraw      True if this prefix has gone otherwise False
    ================ ======================================================

    """

    def __init__(self, remote_as, route_dist, prefix, nexthop, is_withdraw):
        self.remote_as = remote_as
        self.route_dist = route_dist
        self.prefix = prefix
        self.nexthop = nexthop
        self.is_withdraw = is_withdraw


class PrefixList(object):
    """
    used to specify a prefix for out-filter.

    We can create PrefixList object as follows.

    prefix_list = PrefixList('10.5.111.0/24', policy=PrefixList.POLICY_PERMIT)

    ================ ==================================================
    Attribute        Description
    ================ ==================================================
    prefix           A prefix used for out-filter
    policy           PrefixList.POLICY.PERMIT or PrefixList.POLICY_DENY
    ge               Prefix length that will be applied out-filter.
                     ge means greater than or equal.
    le               Prefix length that will be applied out-filter.
                     le means less than or equal.
    ================ ==================================================


    For example, when PrefixList object is created as follows:

    * p = PrefixList('10.5.111.0/24',
                   policy=PrefixList.POLICY_DENY,
                   ge=26, le=28)


    prefixes which match 10.5.111.0/24 and its length matches
    from 26 to 28 will be filtered and stopped to send to neighbor
    because of POLICY_DENY. If you specify POLICY_PERMIT,
    the path is sent to neighbor.

    If you don't want to send prefixes 10.5.111.64/26 and 10.5.111.32/27
    and 10.5.111.16/28, and allow to send other 10.5.111.0's prefixes,
    you can do it by specifying as follows;

    * p = PrefixList('10.5.111.0/24',
                   policy=PrefixList.POLICY_DENY,
                   ge=26, le=28).

    """
    POLICY_DENY = 0
    POLICY_PERMIT = 1

    def __init__(self, prefix, policy=POLICY_PERMIT, ge=None, le=None):
        self._prefix = prefix
        self._policy = policy
        self._network = IPNetwork(prefix)
        self._ge = ge
        self._le = le

    def __cmp__(self, other):
        return cmp(self.prefix, other.prefix)

    def __repr__(self):
        policy = 'PERMIT' \
            if self._policy == self.POLICY_PERMIT else 'DENY'

        return 'PrefixList(prefix=%s,policy=%s,ge=%s,le=%s)'\
               % (self._prefix, policy, self._ge, self._le)

    @property
    def prefix(self):
        return self._prefix

    @property
    def policy(self):
        return self._policy

    @property
    def ge(self):
        return self._ge

    @property
    def le(self):
        return self._le

    def evaluate(self, prefix):
        """ This method evaluates the prefix.

        Returns this object's policy and the result of matching.
        If the specified prefix matches this object's prefix and
        ge and le condition,
        this method returns True as the matching result.

        ``prefix`` specifies the prefix. prefix must be string.

        """

        result = False
        length = prefix.length
        net = IPNetwork(prefix.formatted_nlri_str)

        if net in self._network:
            if self._ge is None and self._le is None:
                result = True

            elif self._ge is None and self._le:
                if length <= self._le:
                    result = True

            elif self._ge and self._le is None:
                if self._ge <= length:
                    result = True

            elif self._ge and self._le:
                if self._ge <= length <= self._le:
                    result = True

        return self.policy, result

    def clone(self):
        """ This method clones PrefixList object.

        Returns PrefixList object that has the same values with the
        original one.

        """

        return PrefixList(self.prefix,
                          policy=self._policy,
                          ge=self._ge,
                          le=self._le)


class BGPSpeaker(object):
    def __init__(self, as_number, router_id,
                 bgp_server_port=DEFAULT_BGP_SERVER_PORT,
                 refresh_stalepath_time=DEFAULT_REFRESH_STALEPATH_TIME,
                 refresh_max_eor_time=DEFAULT_REFRESH_MAX_EOR_TIME,
                 best_path_change_handler=None,
                 ssh_console=False):
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

        """
        super(BGPSpeaker, self).__init__()
        self.speaker = RyuBGPSpeaker()

        settings = {}
        settings[LOCAL_AS] = as_number
        settings[ROUTER_ID] = router_id
        settings[BGP_SERVER_PORT] = bgp_server_port
        settings[REFRESH_STALEPATH_TIME] = refresh_stalepath_time
        settings[REFRESH_MAX_EOR_TIME] = refresh_max_eor_time
        self._core_start(settings)
        self._init_signal_listeners()
        self._best_path_change_handler = best_path_change_handler

        if ssh_console:
            app_mgr = app_manager.AppManager.get_instance()
            ssh_cli = app_mgr.instantiate(ssh.Cli)
            ssh_cli.start()

    def _notify_best_path_changed(self, path, is_withdraw):
        if not path.source:
            # ours
            return
        ev = EventPrefix(remote_as=path.source.remote_as,
                         route_dist=None,
                         prefix=path.nlri.addr + '/' + str(path.nlri.length),
                         nexthop=path.nexthop, is_withdraw=is_withdraw)
        if self._best_path_change_handler:
            self._best_path_change_handler(ev)

    def _init_signal_listeners(self):
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            BgpSignalBus.BGP_BEST_PATH_CHANGED,
            lambda _, info:
                self._notify_best_path_changed(info['path'],
                                               info['is_withdraw'])
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
                     next_hop=None, password=None, multi_exit_disc=None):
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

        """
        bgp_neighbor = {}
        bgp_neighbor[neighbors.IP_ADDRESS] = address
        bgp_neighbor[neighbors.REMOTE_AS] = remote_as
        bgp_neighbor[PEER_NEXT_HOP] = next_hop
        bgp_neighbor[PASSWORD] = password
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

    def neighbor_update(self, address, conf_type, conf_value):
        """ This method changes the neighbor configuration.

        ``conf_type`` specifies configuration type which you want to change.
        Currently ryu.services.protocols.bgp.bgpspeaker.NEIGHBOR_CONF_MED
        can be specified.

        ``conf_value`` specifies value for the configuration type.

        """

        assert conf_type == NEIGHBOR_CONF_MED

        func_name = 'neighbor.update'
        attribute_param = {}
        if conf_type == NEIGHBOR_CONF_MED:
            attribute_param = {neighbors.MULTI_EXIT_DISC: conf_value}

        param = {neighbors.IP_ADDRESS: address,
                 neighbors.CHANGES: attribute_param}
        call(func_name, **param)

    def prefix_add(self, prefix, next_hop=None, route_dist=None,
                   route_family=None):
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
        call(func_name, **networks)

    def prefix_del(self, prefix, route_dist=None, route_family=None):
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
        call(func_name, **networks)

    def vrf_add(self, route_dist, import_rts, export_rts, site_of_origins=None,
                multi_exit_disc=None):
        """ This method adds a new vrf used for VPN.

        ``route_dist`` specifies a route distinguisher value.

        ``import_rts`` specifies route targets to be imported.

        ``export_rts`` specifies route targets to be exported.

        """

        vrf = {}
        vrf[vrfs.ROUTE_DISTINGUISHER] = route_dist
        vrf[vrfs.IMPORT_RTS] = import_rts
        vrf[vrfs.EXPORT_RTS] = export_rts
        call('vrf.create', **vrf)

    def vrf_del(self, route_dist):
        """ This method deletes the existing vrf.

        ``route_dist`` specifies a route distinguisher value.

        """

        vrf = {}
        vrf[vrfs.ROUTE_DISTINGUISHER] = route_dist
        call('vrf.delete', **vrf)

    def vrfs_get(self):
        show = {}
        show['params'] = ['vrf', 'routes', 'all']
        return call('operator.show', **show)

    def rib_get(self, family='ipv4'):
        """ This method returns the BGP routing information in a json
        format. This will be improved soon.

        ``family`` specifies the address family of the RIB.

        """
        show = {}
        show['params'] = ['rib', family]
        return call('operator.show', **show)

    def out_filter_set(self, address, prefix_lists,
                       route_family=OUT_FILTER_RF_IPv4_UC):
        """ This method sets out-filter to neighbor.

        ``address`` specifies the IP address of the peer.

        ``prefix_lists`` specifies prefix list to filter path advertisement.
         This parameter must be list that has PrefixList objects.

        ``route_family`` specifies the route family for out-filter.
        This parameter must be bgpspeaker.OUT_FILTER_RF_IPv4_UC or
        bgpspeaker.OUT_FILTER_RF_IPv6_UC.


        If you want to define out-filter that send only a particular
        prefix to neighbor, prefix_lists can be created as follows;

          p = PrefixList('10.5.111.0/24', policy=PrefixList.POLICY_PERMIT)

          all = PrefixList('0.0.0.0/0', policy=PrefixList.POLICY_DENY)

          pList = [p, all]

          self.bgpspeaker.out_filter_set(neighbor_address, pList)

        NOTE:
        out-filter evaluates prefixes in the order of PrefixList in the pList.

        """

        assert route_family in (OUT_FILTER_RF_IPv4_UC,
                                OUT_FILTER_RF_IPv6_UC),\
            "route family must be IPv4 or IPv6"

        if prefix_lists is None:
            prefix_lists = []

        func_name = 'neighbor.update'
        prefix_value = {'prefix_lists': prefix_lists,
                        'route_family': route_family}
        filter_param = {neighbors.OUT_FILTER: prefix_value}

        param = {}
        param[neighbors.IP_ADDRESS] = address
        param[neighbors.CHANGES] = filter_param
        call(func_name, **param)

    def out_filter_get(self, address):
        """ This method gets out-filter setting from the specified neighbor.

        ``address`` specifies the IP address of the peer.

        Returns list object that has PrefixList objects.

        """

        func_name = 'neighbor.get'
        param = {}
        param[neighbors.IP_ADDRESS] = address
        settings = call(func_name, **param)
        return settings[OUT_FILTER]
