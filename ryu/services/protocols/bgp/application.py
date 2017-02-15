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
  Defines bases classes to create a BGP application.
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
from ryu.services.protocols.bgp.rtconf.common import BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common import (
    DEFAULT_REFRESH_MAX_EOR_TIME, DEFAULT_REFRESH_STALEPATH_TIME)
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_LABEL_RANGE
from ryu.services.protocols.bgp.rtconf.common import LABEL_RANGE
from ryu.services.protocols.bgp.rtconf.common import LOCAL_AS
from ryu.services.protocols.bgp.rtconf.common import REFRESH_MAX_EOR_TIME
from ryu.services.protocols.bgp.rtconf.common import REFRESH_STALEPATH_TIME
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

    This application will notifies
     - ``EventBestPathChanged``
     - ``EventPeerDown``
     - ``EventPeerUp``
    to other BGP applications.
    To catch these events, specify ``@set_ev_cls()`` decorator to the event
    handlers in the Ryu applications.

    Example::

        ...
        from ryu.base import app_manager
        from ryu.controller.handler import set_ev_cls
        from ryu.services.protocols.bgp import application as bgp_application
        ...

        class MyBGPApp(app_manager.RyuApp):
            _CONTEXTS = {
                'ryubgpspeaker': bgp_application.RyuBGPSpeaker,
            }

            ...
            @set_ev_cls(bgp_application.EventBestPathChanged)
            def _best_patch_changed_handler(self, ev):
                self.logger.info(
                    'Best path changed: is_withdraw=%s, path=%s',
                    ev.is_withdraw, ev.path)
    """
    _EVENTS = [
        EventBestPathChanged,
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
        # Settings for starting BGPSpeaker
        bgp_settings = {}

        # Get required settings.
        try:
            bgp_settings['as_number'] = settings.get(LOCAL_AS)
            bgp_settings['router_id'] = settings.get(ROUTER_ID)
        except KeyError as e:
            raise ApplicationException(
                desc='Required BGP configuration missing: %s' % e)

        # Set event notify handlers if no corresponding handler specified.
        bgp_settings['best_path_change_handler'] = settings.get(
            'best_path_change_handler', self._notify_best_path_changed_event)
        bgp_settings['peer_down_handler'] = settings.get(
            'peer_down_handler', self._notify_peer_down_event)
        bgp_settings['peer_up_handler'] = settings.get(
            'peer_up_handler', self._notify_peer_up_event)

        # Get optional settings.
        bgp_settings[BGP_SERVER_PORT] = settings.get(
            BGP_SERVER_PORT, DEFAULT_BGP_SERVER_PORT)
        bgp_settings[REFRESH_STALEPATH_TIME] = settings.get(
            REFRESH_STALEPATH_TIME, DEFAULT_REFRESH_STALEPATH_TIME)
        bgp_settings[REFRESH_MAX_EOR_TIME] = settings.get(
            REFRESH_MAX_EOR_TIME, DEFAULT_REFRESH_MAX_EOR_TIME)
        bgp_settings[LABEL_RANGE] = settings.get(
            LABEL_RANGE, DEFAULT_LABEL_RANGE)
        bgp_settings['allow_local_as_in_count'] = settings.get(
            'allow_local_as_in_count', 0)

        # Create BGPSpeaker instance.
        LOG.debug('Starting BGPSpeaker...')
        self.speaker = BGPSpeaker(**bgp_settings)

        # Add neighbors.
        LOG.debug('Adding neighbors...')
        self._add_neighbors(settings.get('neighbors', []))

        # Add VRFs.
        LOG.debug('Adding VRFs...')
        self._add_vrfs(settings.get('vrfs', []))

        # Add Networks
        LOG.debug('Adding routes...')
        self._add_routes(settings.get('routes', []))

    def _notify_best_path_changed_event(self, ev):
        ev = EventBestPathChanged(ev.path, ev.is_withdraw)
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
            else:
                LOG.debug('Skip invalid route settings: %s', route_settings)
                continue

            LOG.debug('Adding route settings: %s', route_settings)
            try:
                prefix_add(**route_settings)
            except RuntimeConfigError as e:
                LOG.exception(e)
