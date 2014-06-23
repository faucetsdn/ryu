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
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_IPV4
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.neighbors import DEFAULT_CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.application import RyuBGPSpeaker


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

    def _notify_best_path_changed(self, path):
        if not path.source:
            # ours
            return
        ev = EventPrefix(remote_as=path.source.remote_as,
                         route_dist=None,
                         prefix=path.nlri.addr + '/' + str(path.nlri.length),
                         nexthop=path.nexthop, is_withdraw=path.is_withdraw)
        if self._best_path_change_handler:
            self._best_path_change_handler(ev)

    def _init_signal_listeners(self):
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            BgpSignalBus.BGP_BEST_PATH_CHANGED,
            lambda _, dest: self._notify_best_path_changed(dest)
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
                     enable_vpnv6=DEFAULT_CAP_MBGP_VPNV6):
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

        """
        bgp_neighbor = {}
        bgp_neighbor[neighbors.IP_ADDRESS] = address
        bgp_neighbor[neighbors.REMOTE_AS] = remote_as
        bgp_neighbor[CAP_MBGP_IPV4] = enable_ipv4
        bgp_neighbor[CAP_MBGP_VPNV4] = enable_vpnv4
        bgp_neighbor[CAP_MBGP_VPNV6] = enable_vpnv6
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
