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

"""
This module provides a convenient application for using Ryu BGPSpeaker and for
writing your BGP application.

It reads a configuration file which includes settings for neighbors, routes
and some others.
Please refer to ``ryu/services/protocols/bgp/bgp_sample_conf.py`` for the
sample configuration.

Usage Example::

    $ ryu-manager ryu/services/protocols/bgp/application.py \\
        --bgp-app-config-file ryu/services/protocols/bgp/bgp_sample_conf.py

SSH Console
===========

You can also use the SSH console and see the RIB and do some operations from
this console.
The SSH port and username/password can be configured by the configuration file.
You can check the help by hitting '?' key in this interface.

Example::

    $ ssh localhost -p 4990

    Hello, this is Ryu BGP speaker (version 4.19).

    bgpd> # Hit '?' key
     clear - allows to reset BGP connections
     help - show this help
     quit - exit this session
     set - set runtime settings
     show - shows runtime state information
    bgpd>
    bgpd> show rib all
    Status codes: * valid, > best
    Origin codes: i - IGP, e - EGP, ? - incomplete
         Network        Labels   Next Hop   Reason      Metric LocPrf Path
     *>  10.10.1.0/24   None     0.0.0.0    Only Path                 i
    bgpd>

Integration with Other Applications
===================================

``ryu.services.protocols.bgp.application.RyuBGPSpeaker`` will notifies the
following events to other Ryu applications.

    - ``EventBestPathChanged``
    - ``EventAdjRibInChanged``
    - ``EventPeerDown``
    - ``EventPeerUp``

To catch these events, specify ``@set_ev_cls()`` decorator to the event
handlers in the Ryu applications.

Example Application::

    # my_bgp_app.py

    from ryu.base import app_manager
    from ryu.controller.handler import set_ev_cls
    from ryu.services.protocols.bgp import application as bgp_application


    class MyBGPApp(app_manager.RyuApp):
        _CONTEXTS = {
            'ryubgpspeaker': bgp_application.RyuBGPSpeaker,
        }

        def __init__(self, *args, **kwargs):
            super(MyBGPApp, self).__init__(*args, **kwargs)

            # Stores "ryu.services.protocols.bgp.application.RyuBGPSpeaker"
            # instance in order to call the APIs of
            # "ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker" via
            # "self.app.speaker".
            # Please note at this time, "BGPSpeaker" is NOT instantiated yet.
            self.app = kwargs['ryubgpspeaker']

        @set_ev_cls(bgp_application.EventBestPathChanged)
        def _best_patch_changed_handler(self, ev):
            self.logger.info(
                'Best path changed: is_withdraw=%s, path=%s',
                ev.is_withdraw, ev.path)

Usage Example::

    $ ryu-manager my_bgp_app.py \\
        --bgp-app-config-file ryu/services/protocols/bgp/bgp_sample_conf.py

.. note::

    For the APIs for ``ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker``,
    please refer to :doc:`../library_bgp_speaker_ref`.

API Reference
=============
"""

import logging
import os

from ryu import cfg
from ryu.lib import hub
from ryu.utils import load_source
from ryu.base.app_manager import RyuApp
from ryu.controller.event import EventBase
from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.base import BIN_ERROR
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
from ryu.services.protocols.bgp.net_ctrl import NET_CONTROLLER
from ryu.services.protocols.bgp.net_ctrl import NC_RPC_BIND_IP
from ryu.services.protocols.bgp.net_ctrl import NC_RPC_BIND_PORT
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.common import LOCAL_AS
from ryu.services.protocols.bgp.rtconf.common import ROUTER_ID
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv6


LOG = logging.getLogger('bgpspeaker.application')

CONF = cfg.CONF['bgp-app']


@add_bgp_error_metadata(code=BIN_ERROR,
                        sub_code=1,
                        def_desc='Unknown bootstrap exception.')
class ApplicationException(BGPSException):
    """
    Specific Base exception related to `BSPSpeaker`.
    """
    pass


def validate_rpc_host(ip):
    """
    Validates the given ip for use as RPC server address.
    """
    if not is_valid_ipv4(ip) and not is_valid_ipv6(ip):
        raise ApplicationException(
            desc='Invalid RPC ip address: %s' % ip)
    return ip


def load_config(config_file):
    """
    Validates the given file for use as the settings file for BGPSpeaker
    and loads the configuration from the given file as a module instance.
    """
    if not config_file or not os.path.isfile(config_file):
        raise ApplicationException(
            desc='Invalid configuration file: %s' % config_file)

    # Loads the configuration from the given file, if available.
    try:
        return load_source('bgpspeaker.application.settings', config_file)
    except Exception as e:
        raise ApplicationException(desc=str(e))


class EventBestPathChanged(EventBase):
    """
    Event called when any best remote path is changed due to UPDATE messages
    or remote peer's down.

    This event is the wrapper for ``best_path_change_handler`` of
    ``bgpspeaker.BGPSpeaker``.

    ``path`` attribute contains an instance of ``info_base.base.Path``
    subclasses.

    If ``is_withdraw`` attribute is ``True``, ``path`` attribute has the
    information of the withdraw route.
    """

    def __init__(self, path, is_withdraw):
        super(EventBestPathChanged, self).__init__()
        self.path = path
        self.is_withdraw = is_withdraw


class EventAdjRibInChanged(EventBase):
    """
    Event called when any adj-RIB-in path is changed due to UPDATE messages
    or remote peer's down.

    This event is the wrapper for ``adj_rib_in_change_handler`` of
    ``bgpspeaker.BGPSpeaker``.

    ``path`` attribute contains an instance of ``info_base.base.Path``
    subclasses.

    If ``is_withdraw`` attribute is ``True``, ``path`` attribute has the
    information of the withdraw route.

    ``peer_ip`` is the peer's IP address who sent this path.

    ``peer_as`` is the peer's AS number who sent this path.
    """

    def __init__(self, path, is_withdraw, peer_ip, peer_as):
        super(EventAdjRibInChanged, self).__init__()
        self.path = path
        self.is_withdraw = is_withdraw
        self.peer_ip = peer_ip
        self.peer_as = peer_as


class EventPeerDown(EventBase):
    """
    Event called when the session to the remote peer goes down.

    This event is the wrapper for ``peer_down_handler`` of
    ``bgpspeaker.BGPSpeaker``.

    ``remote_ip`` attribute is the IP address of the remote peer.

    ``remote_as`` attribute is the AS number of the remote peer.
    """

    def __init__(self, remote_ip, remote_as):
        super(EventPeerDown, self).__init__()
        self.remote_ip = remote_ip
        self.remote_as = remote_as


class EventPeerUp(EventBase):
    """
    Event called when the session to the remote peer goes up.

    This event is the wrapper for ``peer_up_handler`` of
    ``bgpspeaker.BGPSpeaker``.

    ``remote_ip`` attribute is the IP address of the remote peer.

    ``remote_as`` attribute is the AS number of the remote peer.
    """

    def __init__(self, remote_ip, remote_as):
        super(EventPeerUp, self).__init__()
        self.remote_ip = remote_ip
        self.remote_as = remote_as


class RyuBGPSpeaker(RyuApp):
    """
    Base application for implementing BGP applications.
    """
    _EVENTS = [
        EventBestPathChanged,
        EventAdjRibInChanged,
        EventPeerDown,
        EventPeerUp,
    ]

    def __init__(self, *args, **kwargs):
        super(RyuBGPSpeaker, self).__init__(*args, **kwargs)
        self.config_file = CONF.config_file

        # BGPSpeaker instance (not instantiated yet)
        self.speaker = None

    def start(self):
        super(RyuBGPSpeaker, self).start()

        # If configuration file was provided and loaded successfully, we start
        # BGPSpeaker using the given settings.
        # If no configuration file is provided or if any minimum required
        # setting is missing, BGPSpeaker will not be started.
        if self.config_file:
            LOG.debug('Loading config file %s...', self.config_file)
            settings = load_config(self.config_file)

            # Configure logging settings, if available.
            if hasattr(settings, 'LOGGING'):
                # Not implemented yet.
                LOG.debug('Loading LOGGING settings... (NOT implemented yet)')
                # from logging.config import dictConfig
                # logging_settings = dictConfig(settings.LOGGING)

            # Configure BGP settings, if available.
            if hasattr(settings, 'BGP'):
                LOG.debug('Loading BGP settings...')
                self._start_speaker(settings.BGP)

            # Configure SSH settings, if available.
            if hasattr(settings, 'SSH'):
                LOG.debug('Loading SSH settings...')
                # Note: paramiko used in bgp.operator.ssh is the optional
                # requirements, imports bgp.operator.ssh here.
                from ryu.services.protocols.bgp.operator import ssh
                hub.spawn(ssh.SSH_CLI_CONTROLLER.start, **settings.SSH)

        # Start RPC server with the given RPC settings.
        rpc_settings = {
            NC_RPC_BIND_PORT: CONF.rpc_port,
            NC_RPC_BIND_IP: validate_rpc_host(CONF.rpc_host),
        }
        return hub.spawn(NET_CONTROLLER.start, **rpc_settings)

    def _start_speaker(self, settings):
        """
        Starts BGPSpeaker using the given settings.
        """
        # Check required settings.
        _required_settings = (
            LOCAL_AS,
            ROUTER_ID,
        )
        for required in _required_settings:
            if required not in settings:
                raise ApplicationException(
                    desc='Required BGP configuration missing: %s' % required)

        # Set event notify handlers if no corresponding handler specified.
        settings.setdefault(
            'best_path_change_handler', self._notify_best_path_changed_event)
        settings.setdefault(
            'adj_rib_in_change_handler', self._notify_adj_rib_in_changed_event)
        settings.setdefault(
            'peer_down_handler', self._notify_peer_down_event)
        settings.setdefault(
            'peer_up_handler', self._notify_peer_up_event)

        # Pop settings other than creating BGPSpeaker instance.
        neighbors_settings = settings.pop('neighbors', [])
        vrfs_settings = settings.pop('vrfs', [])
        routes_settings = settings.pop('routes', [])

        # Create BGPSpeaker instance.
        LOG.debug('Starting BGPSpeaker...')
        settings.setdefault('as_number', settings.pop(LOCAL_AS))
        self.speaker = BGPSpeaker(**settings)

        # Add neighbors.
        LOG.debug('Adding neighbors...')
        self._add_neighbors(neighbors_settings)

        # Add VRFs.
        LOG.debug('Adding VRFs...')
        self._add_vrfs(vrfs_settings)

        # Add routes
        LOG.debug('Adding routes...')
        self._add_routes(routes_settings)

    def _notify_best_path_changed_event(self, ev):
        ev = EventBestPathChanged(ev.path, ev.is_withdraw)
        self.send_event_to_observers(ev)

    def _notify_adj_rib_in_changed_event(self, ev, peer_ip, peer_as):
        ev = EventAdjRibInChanged(ev.path, ev.is_withdraw, peer_ip, peer_as)
        self.send_event_to_observers(ev)

    def _notify_peer_down_event(self, remote_ip, remote_as):
        ev = EventPeerDown(remote_ip, remote_as)
        self.send_event_to_observers(ev)

    def _notify_peer_up_event(self, remote_ip, remote_as):
        ev = EventPeerUp(remote_ip, remote_as)
        self.send_event_to_observers(ev)

    def _add_neighbors(self, settings):
        """
        Add BGP neighbors from the given settings.

        All valid neighbors are loaded.
        Miss-configured neighbors are ignored and errors are logged.
        """
        for neighbor_settings in settings:
            LOG.debug('Adding neighbor settings: %s', neighbor_settings)
            try:
                self.speaker.neighbor_add(**neighbor_settings)
            except RuntimeConfigError as e:
                LOG.exception(e)

    def _add_vrfs(self, settings):
        """
        Add BGP VRFs from the given settings.

        All valid VRFs are loaded.
        Miss-configured VRFs are ignored and errors are logged.
        """
        for vrf_settings in settings:
            LOG.debug('Adding VRF settings: %s', vrf_settings)
            try:
                self.speaker.vrf_add(**vrf_settings)
            except RuntimeConfigError as e:
                LOG.exception(e)

    def _add_routes(self, settings):
        """
        Add BGP routes from given settings.

        All valid routes are loaded.
        Miss-configured routes are ignored and errors are logged.
        """
        for route_settings in settings:
            if 'prefix' in route_settings:
                prefix_add = self.speaker.prefix_add
            elif 'route_type' in route_settings:
                prefix_add = self.speaker.evpn_prefix_add
            elif 'flowspec_family' in route_settings:
                prefix_add = self.speaker.flowspec_prefix_add
            else:
                LOG.debug('Skip invalid route settings: %s', route_settings)
                continue

            LOG.debug('Adding route settings: %s', route_settings)
            try:
                prefix_add(**route_settings)
            except RuntimeConfigError as e:
                LOG.exception(e)
