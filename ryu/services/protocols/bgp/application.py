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
import imp
import logging
import traceback
from oslo_config import cfg

from ryu.lib import hub
from ryu.base.app_manager import RyuApp

from ryu.services.protocols.bgp.api.base import call
from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.base import BIN_ERROR
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp import net_ctrl
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.common import BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_BGP_SERVER_PORT
from ryu.services.protocols.bgp.rtconf.common import \
    DEFAULT_REFRESH_MAX_EOR_TIME
from ryu.services.protocols.bgp.rtconf.common import \
    DEFAULT_REFRESH_STALEPATH_TIME
from ryu.services.protocols.bgp.rtconf.common import DEFAULT_LABEL_RANGE
from ryu.services.protocols.bgp.rtconf.common import LABEL_RANGE
from ryu.services.protocols.bgp.rtconf.common import LOCAL_AS
from ryu.services.protocols.bgp.rtconf.common import REFRESH_MAX_EOR_TIME
from ryu.services.protocols.bgp.rtconf.common import REFRESH_STALEPATH_TIME
from ryu.services.protocols.bgp.rtconf.common import ROUTER_ID
from ryu.services.protocols.bgp.rtconf import neighbors
from ryu.services.protocols.bgp.rtconf import vrfs
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.operator import ssh

try:
    from logging.config import dictConfig
except Exception:
    from ryu.services.protocols.bgp.utils.dictconfig import dictConfig


LOG = logging.getLogger('bgpspeaker.application')
CONF = cfg.CONF

CONF.register_opts([
    cfg.IntOpt('bind-port', default=50002, help='rpc-port'),
    cfg.StrOpt('bind-ip', default='0.0.0.0', help='rpc-bind-ip'),
    cfg.StrOpt('bgp-config-file', default=None,
               help='bgp-config-file')
])


@add_bgp_error_metadata(code=BIN_ERROR,
                        sub_code=1,
                        def_desc='Unknown bootstrap exception.')
class ApplicationException(BGPSException):
    """Specific Base exception related to `BSPSpeaker`."""
    pass


class RyuBGPSpeaker(RyuApp):
    def __init__(self, *args, **kwargs):
        self.bind_ip = RyuBGPSpeaker.validate_rpc_ip(CONF.bind_ip)
        self.bind_port = RyuBGPSpeaker.validate_rpc_port(CONF.bind_port)
        self.config_file = CONF.bgp_config_file
        super(RyuBGPSpeaker, self).__init__(*args, **kwargs)

    def start(self):
        # Only two main green threads are required for APGW bgp-agent.
        # One for NetworkController, another for BGPS core.

        # If configuration file was provided and loaded successfully. We start
        # BGPS core using these settings. If no configuration file is provided
        # or if configuration file is missing minimum required settings BGPS
        # core is not started.
        if self.config_file:
            LOG.debug('Loading config. from settings file.')
            settings = self.load_config(self.config_file)
            # Configure log settings, if available.
            if getattr(settings, 'LOGGING', None):
                dictConfig(settings.LOGGING)

            if getattr(settings, 'BGP', None):
                self._start_core(settings)

            if getattr(settings, 'SSH', None) is not None:
                hub.spawn(ssh.SSH_CLI_CONTROLLER.start, None, **settings.SSH)
        # Start Network Controller to server RPC peers.
        t = hub.spawn(net_ctrl.NET_CONTROLLER.start, *[],
                      **{net_ctrl.NC_RPC_BIND_IP: self.bind_ip,
                      net_ctrl.NC_RPC_BIND_PORT: self.bind_port})
        LOG.debug('Started Network Controller')

        super(RyuBGPSpeaker, self).start()

        return t

    @classmethod
    def validate_rpc_ip(cls, ip):
        """Validates given ip for use as rpc host bind address.
        """
        if not is_valid_ipv4(ip):
            raise ApplicationException(desc='Invalid rpc ip address.')
        return ip

    @classmethod
    def validate_rpc_port(cls, port):
        """Validates give port for use as rpc server port.
        """
        if not port:
            raise ApplicationException(desc='Invalid rpc port number.')
        if isinstance(port, str):
            port = int(port)

        return port

    def load_config(self, config_file):
        """Validates give file as settings file for BGPSpeaker.

        Load the configuration from file as settings module.
        """
        if not config_file or not isinstance(config_file, str):
            raise ApplicationException('Invalid configuration file.')

        # Check if file can be read
        try:
            return imp.load_source('settings', config_file)
        except Exception as e:
            raise ApplicationException(desc=str(e))

    def _start_core(self, settings):
        """Starts BGPS core using setting and given pool.
        """
        # Get common settings
        routing_settings = settings.BGP.get('routing')
        common_settings = {}

        # Get required common settings.
        try:
            common_settings[LOCAL_AS] = routing_settings.pop(LOCAL_AS)
            common_settings[ROUTER_ID] = routing_settings.pop(ROUTER_ID)
        except KeyError as e:
            raise ApplicationException(
                desc='Required minimum configuration missing %s' %
                     e)

        # Get optional common settings
        common_settings[BGP_SERVER_PORT] = \
            routing_settings.get(BGP_SERVER_PORT, DEFAULT_BGP_SERVER_PORT)
        common_settings[REFRESH_STALEPATH_TIME] = \
            routing_settings.get(REFRESH_STALEPATH_TIME,
                                 DEFAULT_REFRESH_STALEPATH_TIME)
        common_settings[REFRESH_MAX_EOR_TIME] = \
            routing_settings.get(REFRESH_MAX_EOR_TIME,
                                 DEFAULT_REFRESH_MAX_EOR_TIME)
        common_settings[LABEL_RANGE] = \
            routing_settings.get(LABEL_RANGE, DEFAULT_LABEL_RANGE)

        # Start BGPS core service
        waiter = hub.Event()
        call('core.start', waiter=waiter, **common_settings)
        waiter.wait()

        LOG.debug('Core started %s', CORE_MANAGER.started)
        # Core manager started add configured neighbor and vrfs
        if CORE_MANAGER.started:
            # Add neighbors.
            self._add_neighbors(routing_settings)

            # Add Vrfs.
            self._add_vrfs(routing_settings)

            # Add Networks
            self._add_networks(routing_settings)

    def _add_neighbors(self, routing_settings):
        """Add bgp peers/neighbors from given settings to BGPS runtime.

        All valid neighbors are loaded. Miss-configured neighbors are ignored
        and error is logged.
        """
        bgp_neighbors = routing_settings.setdefault('bgp_neighbors', {})
        for ip, bgp_neighbor in bgp_neighbors.items():
            try:
                bgp_neighbor[neighbors.IP_ADDRESS] = ip
                call('neighbor.create', **bgp_neighbor)
                LOG.debug('Added neighbor %s', ip)
            except RuntimeConfigError as re:
                LOG.error(re)
                LOG.error(traceback.format_exc())
                continue

    def _add_vrfs(self, routing_settings):
        """Add VRFs from given settings to BGPS runtime.

        If any of the VRFs are miss-configured errors are logged.
        All valid VRFs are loaded.
        """
        vpns_conf = routing_settings.setdefault('vpns', {})
        for vrfname, vrf in vpns_conf.items():
            try:
                vrf[vrfs.VRF_NAME] = vrfname
                call('vrf.create', **vrf)
                LOG.debug('Added vrf  %s', vrf)
            except RuntimeConfigError as e:
                LOG.error(e)
                continue

    def _add_networks(self, routing_settings):
        """Add networks from given settings to BGPS runtime.

        If any of the networks are miss-configured errors are logged.
        All valid networks are loaded.
        """
        networks = routing_settings.setdefault('networks', [])
        for prefix in networks:
            try:
                call('network.add', prefix=prefix)
                LOG.debug('Added network %s', prefix)
            except RuntimeConfigError as e:
                LOG.error(e)
                continue
