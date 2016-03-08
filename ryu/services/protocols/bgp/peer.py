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
 BGP peer related classes and utils.
"""
from collections import namedtuple
import logging
import socket
import time
import traceback

from ryu.services.protocols.bgp.base import Activity
from ryu.services.protocols.bgp.base import Sink
from ryu.services.protocols.bgp.base import Source
from ryu.services.protocols.bgp.base import SUPPORTED_GLOBAL_RF
from ryu.services.protocols.bgp import constants as const
from ryu.services.protocols.bgp.model import OutgoingRoute
from ryu.services.protocols.bgp.model import SentRoute
from ryu.services.protocols.bgp.info_base.base import PrefixFilter
from ryu.services.protocols.bgp.info_base.base import AttributeMap
from ryu.services.protocols.bgp.model import ReceivedRoute
from ryu.services.protocols.bgp.net_ctrl import NET_CONTROLLER
from ryu.services.protocols.bgp.rtconf.neighbors import NeighborConfListener
from ryu.services.protocols.bgp.rtconf.neighbors import CONNECT_MODE_PASSIVE
from ryu.services.protocols.bgp.signals.emit import BgpSignalBus
from ryu.services.protocols.bgp.speaker import BgpProtocol
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Path
from ryu.services.protocols.bgp.info_base.vpnv4 import Vpnv4Path
from ryu.services.protocols.bgp.info_base.vpnv6 import Vpnv6Path
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4, VRF_RF_IPV6
from ryu.services.protocols.bgp.utils import bgp as bgp_utils
from ryu.services.protocols.bgp.utils.evtlet import EventletIOFactory
from ryu.services.protocols.bgp.utils import stats

from ryu.lib.packet import bgp

from ryu.lib.packet.bgp import RouteFamily
from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import get_rf

from ryu.lib.packet.bgp import BGPOpen
from ryu.lib.packet.bgp import BGPUpdate
from ryu.lib.packet.bgp import BGPRouteRefresh

from ryu.lib.packet.bgp import BGP_ERROR_CEASE
from ryu.lib.packet.bgp import BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
from ryu.lib.packet.bgp import BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION


from ryu.lib.packet.bgp import BGP_MSG_UPDATE
from ryu.lib.packet.bgp import BGP_MSG_KEEPALIVE
from ryu.lib.packet.bgp import BGP_MSG_ROUTE_REFRESH

from ryu.lib.packet.bgp import BGPPathAttributeNextHop
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGPPathAttributeLocalPref
from ryu.lib.packet.bgp import BGPPathAttributeExtendedCommunities
from ryu.lib.packet.bgp import BGPPathAttributeMpReachNLRI
from ryu.lib.packet.bgp import BGPPathAttributeMpUnreachNLRI
from ryu.lib.packet.bgp import BGPPathAttributeCommunities
from ryu.lib.packet.bgp import BGPPathAttributeMultiExitDisc

from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_NEXT_HOP
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MP_REACH_NLRI
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MP_UNREACH_NLRI
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MULTI_EXIT_DISC
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_COMMUNITIES
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_EXTENDED_COMMUNITIES

from ryu.lib.packet.bgp import BGPTwoOctetAsSpecificExtendedCommunity
from ryu.lib.packet.bgp import BGPIPv4AddressSpecificExtendedCommunity

LOG = logging.getLogger('bgpspeaker.peer')


def is_valid_state(state):
    """Returns True if given state is a valid bgp finite state machine state.
    """
    return state in const.BGP_FSM_VALID_STATES


class PeerRf(object):
    """State maintained per-RouteFamily for a Peer."""

    def __init__(self, peer, route_family, enabled=False):
        assert peer and route_family

        self.enabled = enabled

        # Back pointers.
        self.peer = peer
        self.rf = route_family


PeerCounterNames = namedtuple(
    'PeerCounterNames',
    ('RECV_PREFIXES',
     'RECV_UPDATES',
     'SENT_UPDATES',
     'RECV_NOTIFICATION',
     'SENT_NOTIFICATION',
     'SENT_REFRESH',
     'RECV_REFRESH',
     'FSM_ESTB_TRANSITIONS')
)(
    'recv_prefixes',
    'recv_updates',
    'sent_updates',
    'recv_notification',
    'sent_notification',
    'sent_refresh',
    'recv_refresh',
    'fms_established_transitions'
)


class PeerState(object):
    """A BGP neighbor state. Think of this class as of information and stats
    container for Peer.
    """

    def __init__(self, peer, signal_bus):
        # Back pointer to peer whose stats this instances represents.
        self.peer = peer
        # Current state of BGP finite state machine.
        self._bgp_state = const.BGP_FSM_IDLE
        self._established_time = 0
        self._last_bgp_error = None
        self.counters = {
            'recv_prefixes': 0,
            'recv_updates': 0,
            'sent_updates': 0,
            'recv_notification': 0,
            'sent_notification': 0,
            'sent_refresh': 0,
            'recv_refresh': 0,
            'fms_established_transitions': 0,
        }
        self._signal_bus = signal_bus

        # TODO(JK): refactor other counters to use signals also
        self._signal_bus.register_listener(
            ('error', 'bgp', self.peer),
            self._remember_last_bgp_error
        )

        self._signal_bus.register_listener(
            BgpSignalBus.BGP_NOTIFICATION_RECEIVED + (self.peer,),
            lambda _, msg: self.incr(PeerCounterNames.RECV_NOTIFICATION)
        )

        self._signal_bus.register_listener(
            BgpSignalBus.BGP_NOTIFICATION_SENT + (self.peer,),
            lambda _, msg: self.incr(PeerCounterNames.SENT_NOTIFICATION)
        )

    def _remember_last_bgp_error(self, identifier, data):
        self._last_bgp_error = dict([(k, v)
                                     for k, v in data.items()
                                     if k != 'peer'])

    @property
    def recv_prefix(self):
        # Number of prefixes received from peer.
        return self.counters[PeerCounterNames.RECV_PREFIXES]

    @property
    def bgp_state(self):
        return self._bgp_state

    @bgp_state.setter
    def bgp_state(self, new_state):
        old_state = self._bgp_state
        if old_state == new_state:
            return

        self._bgp_state = new_state
        NET_CONTROLLER.send_rpc_notification(
            'neighbor.state',
            {
                'ip_address': self.peer.ip_address,
                'state': new_state
            }
        )

        # transition to Established from another state
        if new_state == const.BGP_FSM_ESTABLISHED:
            self.incr(PeerCounterNames.FSM_ESTB_TRANSITIONS)
            self._established_time = time.time()
            self._signal_bus.adj_up(self.peer)
            NET_CONTROLLER.send_rpc_notification(
                'neighbor.up', {'ip_address': self.peer.ip_address}
            )
        # transition from Established to another state
        elif old_state == const.BGP_FSM_ESTABLISHED:
            self._established_time = 0
            self._signal_bus.adj_down(self.peer)
            NET_CONTROLLER.send_rpc_notification(
                'neighbor.down', {'ip_address': self.peer.ip_address}
            )

        LOG.debug('Peer %s BGP FSM went from %s to %s',
                  self.peer.ip_address, old_state, self.bgp_state)

    def incr(self, counter_name, incr_by=1):
        if counter_name not in self.counters:
            raise ValueError('Un-recognized counter name: %s' % counter_name)
        counter = self.counters.setdefault(counter_name, 0)
        counter += incr_by
        self.counters[counter_name] = counter

    def get_count(self, counter_name):
        if counter_name not in self.counters:
            raise ValueError('Un-recognized counter name: %s' % counter_name)
        return self.counters.get(counter_name, 0)

    @property
    def total_msg_sent(self):
        """Returns total number of UPDATE, NOTIFICATION and ROUTE_REFRESH
         message sent to this peer.
         """
        return (self.get_count(PeerCounterNames.SENT_REFRESH) +
                self.get_count(PeerCounterNames.SENT_UPDATES))

    @property
    def total_msg_recv(self):
        """Returns total number of UPDATE, NOTIFCATION and ROUTE_REFRESH
        messages received from this peer.
        """
        return (self.get_count(PeerCounterNames.RECV_UPDATES) +
                self.get_count(PeerCounterNames.RECV_REFRESH) +
                self.get_count(PeerCounterNames.RECV_NOTIFICATION))

    def get_stats_summary_dict(self):
        """Returns basic stats.

        Returns a `dict` with various counts and stats, see below.
        """
        uptime = time.time() - self._established_time \
            if self._established_time != 0 else -1
        return {
            stats.UPDATE_MSG_IN: self.get_count(PeerCounterNames.RECV_UPDATES),
            stats.UPDATE_MSG_OUT: self.get_count(
                PeerCounterNames.SENT_UPDATES
            ),
            stats.TOTAL_MSG_IN: self.total_msg_recv,
            stats.TOTAL_MSG_OUT: self.total_msg_sent,
            stats.FMS_EST_TRANS: self.get_count(
                PeerCounterNames.FSM_ESTB_TRANSITIONS
            ),
            stats.UPTIME: uptime
        }


class Peer(Source, Sink, NeighborConfListener, Activity):
    """A BGP neighbor/peer.

    Listens on neighbor configuration changes and handles change events
    appropriately. If peering is enabled tries 'actively'/'pro-actively' to
    establish session with peer. Allows binding of `BgpProtocol` instances to
    allow 'passive'/'reactive' establishment of bgp session with peer.
    Maintains BGP state machine (may not be fully compliant with RFC). Handles
    bgp UPDATE messages. Provides a queue to send update message to peer.
    """

    RTC_EOR_TIMER_NAME = 'RTC_EOR_Timer'

    def __init__(self, common_conf, neigh_conf,
                 core_service, signal_bus, peer_manager):
        peer_activity_name = 'Peer: %s' % neigh_conf.ip_address
        Activity.__init__(self, name=peer_activity_name)
        Source.__init__(self, version_num=1)
        Sink.__init__(self)
        # Add listener for configuration changes.
        NeighborConfListener.__init__(self, neigh_conf)

        # Current configuration of this peer.
        self._neigh_conf = neigh_conf
        self._common_conf = common_conf
        self._core_service = core_service
        self._signal_bus = signal_bus
        self._peer_manager = peer_manager

        # Host Bind IP
        self._host_bind_ip = None
        self._host_bind_port = None

        # TODO(PH): revisit maintaining state/stats information.
        # Peer state.
        self.state = PeerState(self, self._signal_bus)
        self._periodic_stats_logger = \
            self._create_timer('Peer State Summary Stats Timer',
                               stats.log,
                               stats_resource=self._neigh_conf,
                               stats_source=self.state.get_stats_summary_dict)
        if self._neigh_conf.stats_log_enabled:
            self._periodic_stats_logger.start(self._neigh_conf.stats_time)

        # State per route family, {RouteFamily: PeerRf,}.
        self.rf_state = {}
        # Get vpnv4 route family settings.
        prf = PeerRf(self, RF_IPv4_VPN,
                     enabled=self._neigh_conf.cap_mbgp_vpnv4)
        self.rf_state[RF_IPv4_VPN] = prf
        # Get vpnv6 route family settings.
        prf = PeerRf(self, RF_IPv6_VPN, self._neigh_conf.cap_mbgp_vpnv6)
        self.rf_state[RF_IPv6_VPN] = prf

        # Bound protocol instance
        self._protocol = None

        # Setting this event starts the connect_loop loop again
        # Clearing this event will stop the connect_loop loop
        self._connect_retry_event = EventletIOFactory.create_custom_event()

        # Reference to threads related to enhanced refresh timers.
        self._refresh_stalepath_timer = None
        self._refresh_max_eor_timer = None

        # Latest valid Open Message
        self.curr_open_msg = None

        # RTC end-of-rib timer
        self._rtc_eor_timer = None
        self._sent_init_non_rtc_update = False
        self._init_rtc_nlri_path = []

        # in-bound filters
        self._in_filters = self._neigh_conf.in_filter

        # out-bound filters
        self._out_filters = self._neigh_conf.out_filter

        # Adj-rib-in
        self._adj_rib_in = {}

        # Adj-rib-out
        self._adj_rib_out = {}

        # attribute maps
        self._attribute_maps = {}

    @property
    def remote_as(self):
        return self._neigh_conf.remote_as

    @property
    def rtc_as(self):
        return self._neigh_conf.rtc_as

    @property
    def ip_address(self):
        return self._neigh_conf.ip_address

    @property
    def protocol(self):
        return self._protocol

    @property
    def host_bind_ip(self):
        return self._host_bind_ip

    @property
    def host_bind_port(self):
        return self._host_bind_port

    @property
    def enabled(self):
        return self._neigh_conf.enabled

    @property
    def med(self):
        return self._neigh_conf.multi_exit_disc

    @property
    def in_filters(self):
        return self._in_filters

    @in_filters.setter
    def in_filters(self, filters):
        self._in_filters = [f.clone() for f in filters]
        LOG.debug('set in-filter : %s', filters)
        self.on_update_in_filter()

    @property
    def out_filters(self):
        return self._out_filters

    @out_filters.setter
    def out_filters(self, filters):
        self._out_filters = [f.clone() for f in filters]
        LOG.debug('set out-filter : %s', filters)
        self.on_update_out_filter()

    @property
    def adj_rib_in(self):
        return self._adj_rib_in

    @property
    def adj_rib_out(self):
        return self._adj_rib_out

    @property
    def is_route_server_client(self):
        return self._neigh_conf.is_route_server_client

    @property
    def check_first_as(self):
        return self._neigh_conf.check_first_as

    @property
    def connect_mode(self):
        return self._neigh_conf.connect_mode

    @property
    def attribute_maps(self):
        return self._attribute_maps

    @attribute_maps.setter
    def attribute_maps(self, attribute_maps):
        _attr_maps = {}
        _attr_maps.setdefault(const.ATTR_MAPS_ORG_KEY, [])

        # key is 'default' or rd_rf that represents RD and route_family
        key = attribute_maps[const.ATTR_MAPS_LABEL_KEY]
        at_maps = attribute_maps[const.ATTR_MAPS_VALUE]

        for a in at_maps:
            cloned = a.clone()
            LOG.debug("AttributeMap attr_type: %s, attr_value: %s",
                      cloned.attr_type, cloned.attr_value)
            attr_list = _attr_maps.setdefault(cloned.attr_type, [])
            attr_list.append(cloned)

            # preserve original order of attribute_maps
            _attr_maps[const.ATTR_MAPS_ORG_KEY].append(cloned)

        self._attribute_maps[key] = _attr_maps
        self.on_update_attribute_maps()

    def is_mpbgp_cap_valid(self, route_family):
        if not self.in_established:
            raise ValueError('Invalid request: Peer not in established state')
        return self._protocol.is_mbgp_cap_valid(route_family)

    def is_ebgp_peer(self):
        """Returns *True* if this is a eBGP peer, else *False*."""
        return self._common_conf.local_as != self._neigh_conf.remote_as

    def in_established(self):
        return self.state.bgp_state == const.BGP_FSM_ESTABLISHED

    def in_idle(self):
        return self.state.bgp_state == const.BGP_FSM_IDLE

    def in_active(self):
        return self.state.bgp_state == const.BGP_FSM_ACTIVE

    def in_open_sent(self):
        return self.state.bgp_state == const.BGP_FSM_OPEN_SENT

    def in_open_confirm(self):
        return self.state.bgp_state == const.BGP_FSM_OPEN_CONFIRM

    def in_connect(self):
        return self.state.bgp_state == const.BGP_FSM_CONNECT

    def curr_fms_state(self):
        return self.state.bgp_state

    def is_mbgp_cap_valid(self, route_family):
        if not self.in_established():
            return False

        return self._protocol.is_mbgp_cap_valid(route_family)

    def on_chg_stats_time_conf_with_stats(self, evt):
        # TODO(PH): provide implementation when updating neighbor is needed
        pass

    def on_chg_stats_enabled_conf_with_stats(self, evt):
        # TODO(PH): provide implementation when updating neighbor is needed
        pass

    def on_update_enabled(self, conf_evt):
        """Implements neighbor configuration change listener.
        """
        enabled = conf_evt.value
        # If we do not have any protocol bound and configuration asks us to
        # enable this peer, we try to establish connection again.
        if enabled:
            LOG.info('%s enabled', self)
            if self._protocol and self._protocol.started:
                LOG.error('Tried to enable neighbor that is already enabled')
            else:
                self.state.bgp_state = const.BGP_FSM_CONNECT
                # Restart connect loop if not already running.
                if not self._connect_retry_event.is_set():
                    self._connect_retry_event.set()
                    LOG.debug('Starting connect loop as neighbor is enabled.')
        else:
            LOG.info('%s disabled', self)
            if self._protocol:
                # Stopping protocol will eventually trigger connection_lost
                # handler which will do some clean-up.
                # But the greenlet that is in charge of the socket may be kill
                # when we stop the protocol, hence we call connection_lost
                # here as we triggered socket to close.
                self._protocol.send_notification(
                    BGP_ERROR_CEASE,
                    BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
                )
                self._protocol.stop()
                self._protocol = None
                self.state.bgp_state = const.BGP_FSM_IDLE
            # If this peer is not enabled any-more we stop trying to make any
            # connection.
            LOG.debug('Disabling connect-retry as neighbor was disabled')
            self._connect_retry_event.clear()

    def on_update_med(self, conf_evt):
        LOG.debug('on_update_med fired')
        if self._protocol is not None and self._protocol.started:
            negotiated_afs = self._protocol.negotiated_afs
            for af in negotiated_afs:
                self._fire_route_refresh(af)

    def _on_update_connect_mode(self, mode):
        if mode is not CONNECT_MODE_PASSIVE and \
                'peer.connect_loop' not in self._child_thread_map:
            LOG.debug("start connect loop. (mode: %s)", mode)
            self._spawn('peer.connect_loop', self._connect_loop,
                        self._client_factory)
        elif mode is CONNECT_MODE_PASSIVE:
            LOG.debug("stop connect loop. (mode: %s)", mode)
            self._stop_child_threads('peer.connect_loop')

    def on_update_connect_mode(self, conf_evt):
        self._on_update_connect_mode(conf_evt.value)

    def _apply_filter(self, filters, path):
        block = False
        blocked_cause = None

        for filter_ in filters:
            if filter_.ROUTE_FAMILY != path.ROUTE_FAMILY:
                continue

            policy, is_matched = filter_.evaluate(path)
            if policy == PrefixFilter.POLICY_PERMIT and is_matched:
                block = False
                break
            elif policy == PrefixFilter.POLICY_DENY and is_matched:
                block = True
                blocked_cause = filter_.prefix + ' - DENY'
                break

        return block, blocked_cause

    def _apply_in_filter(self, path):
        return self._apply_filter(self._in_filters, path)

    def _apply_out_filter(self, path):
        return self._apply_filter(self._out_filters, path)

    def on_update_in_filter(self):
        LOG.debug('on_update_in_filter fired')
        for received_path in self._adj_rib_in.values():
            LOG.debug('received_path: %s', received_path)
            path = received_path.path
            nlri_str = path.nlri.formatted_nlri_str
            block, blocked_reason = self._apply_in_filter(path)
            if block == received_path.filtered:
                LOG.debug('block situation not changed: %s', block)
                continue
            elif block:
                # path wasn't blocked, but must be blocked by this update
                path = path.clone(for_withdrawal=True)
                LOG.debug('withdraw %s because of in filter update', nlri_str)
            else:
                # path was blocked, but mustn't be blocked by this update
                LOG.debug('learn blocked %s because of in filter update',
                          nlri_str)
            received_path.filtered = block
            tm = self._core_service.table_manager
            tm.learn_path(path)

    def on_update_out_filter(self):
        LOG.debug('on_update_out_filter fired')
        for sent_path in self._adj_rib_out.values():
            LOG.debug('sent_path: %s', sent_path)
            path = sent_path.path
            nlri_str = path.nlri.formatted_nlri_str
            block, blocked_reason = self._apply_out_filter(path)
            if block == sent_path.filtered:
                LOG.debug('block situation not changed: %s', block)
                continue
            elif block:
                # path wasn't blocked, but must be blocked by this update
                withdraw_clone = path.clone(for_withdrawal=True)
                outgoing_route = OutgoingRoute(withdraw_clone)
                LOG.debug('send withdraw %s because of out filter update',
                          nlri_str)
            else:
                # path was blocked, but mustn't be blocked by this update
                outgoing_route = OutgoingRoute(path)
                LOG.debug('send blocked %s because of out filter update',
                          nlri_str)
            sent_path.filtered = block
            self.enque_outgoing_msg(outgoing_route)

    def on_update_attribute_maps(self):
        # resend sent_route in case of filter matching
        LOG.debug('on_update_attribute_maps fired')
        for sent_path in self._adj_rib_out.values():
            LOG.debug('resend path: %s', sent_path)
            path = sent_path.path
            self.enque_outgoing_msg(OutgoingRoute(path))

    def __str__(self):
        return 'Peer(ip: %s, asn: %s)' % (self._neigh_conf.ip_address,
                                          self._neigh_conf.remote_as)

    def _run(self, client_factory):
        LOG.debug('Started peer %s', self)
        self._client_factory = client_factory

        # Tries actively to establish session if CONNECT_MODE is not PASSIVE
        self._on_update_connect_mode(self._neigh_conf.connect_mode)

        # Start sink processing
        self._process_outgoing_msg_list()

    def _send_outgoing_route_refresh_msg(self, rr_msg):
        """Sends given message `rr_msg` to peer.

        Parameters:
            - rr_msg: (RouteRefresh) route refresh message to send to peer.

        Update appropriate counters and set appropriate timers.
        """
        assert rr_msg.type == BGP_MSG_ROUTE_REFRESH
        self._protocol.send(rr_msg)
        LOG.debug('RouteRefresh %s>> %s',
                  self._neigh_conf.ip_address, rr_msg)
        # Collect update statistics for sent refresh request.
        if rr_msg.demarcation == 0:
            self.state.incr(PeerCounterNames.SENT_REFRESH)
        # If SOR is sent, we set Max. EOR timer if needed.
        elif (rr_msg.demarcation == 1 and
              self._common_conf.refresh_max_eor_time != 0):
            eor_timer = self._common_conf.refresh_max_eor_time
            # Set timer to send EOR demarcation.
            self._spawn_after('end-of-rib-timer', eor_timer,
                              self._enqueue_eor_msg, rr_msg)
            LOG.debug('Enhanced RR max. EOR timer set.')

    def _send_outgoing_route(self, outgoing_route):
        """Constructs `Update` message from given `outgoing_route` and sends
        it to peer.

        Also, checks if any policies prevent sending this message.
        Populates Adj-RIB-out with corresponding `SentRoute`.
        """

        path = outgoing_route.path
        block, blocked_cause = self._apply_out_filter(path)

        nlri_str = outgoing_route.path.nlri.formatted_nlri_str
        sent_route = SentRoute(outgoing_route.path, self, block)
        self._adj_rib_out[nlri_str] = sent_route
        self._signal_bus.adj_rib_out_changed(self, sent_route)

        # TODO(PH): optimized by sending several prefixes per update.
        # Construct and send update message.
        if not block:
            update_msg = self._construct_update(outgoing_route)
            self._protocol.send(update_msg)
            # Collect update statistics.
            self.state.incr(PeerCounterNames.SENT_UPDATES)
        else:
            LOG.debug('prefix : %s is not sent by filter : %s',
                      path.nlri, blocked_cause)

        # We have to create sent_route for every OutgoingRoute which is
        # not a withdraw or was for route-refresh msg.
        if (not outgoing_route.path.is_withdraw and
                not outgoing_route.for_route_refresh):
            # Update the destination with new sent route.
            tm = self._core_service.table_manager
            tm.remember_sent_route(sent_route)

    def _process_outgoing_msg_list(self):
        while True:
            outgoing_msg = None

            if self._protocol is not None:
                # We pick the first outgoing msg. available and send it.
                outgoing_msg = self.outgoing_msg_list.pop_first()

            # If we do not have any outgoing route, we wait.
            if outgoing_msg is None:
                self.outgoing_msg_event.clear()
                self.outgoing_msg_event.wait()
                continue

            # Check currently supported out-going msgs.
            assert isinstance(
                outgoing_msg,
                (BGPRouteRefresh, BGPUpdate, OutgoingRoute)
            ), ('Peer cannot process object: %s in its outgoing queue'
                % outgoing_msg)

            # Send msg. to peer.
            if isinstance(outgoing_msg, BGPRouteRefresh):
                self._send_outgoing_route_refresh_msg(outgoing_msg)
            elif isinstance(outgoing_msg, OutgoingRoute):
                self._send_outgoing_route(outgoing_msg)

            # EOR are enqueued as plain Update messages.
            elif isinstance(outgoing_msg, BGPUpdate):
                self._protocol.send(outgoing_msg)
                LOG.debug('Update %s>> %s', self._neigh_conf.ip_address,
                          outgoing_msg)
                self.state.incr(PeerCounterNames.SENT_UPDATES)

    def request_route_refresh(self, *route_families):
        """Request route refresh to peer for given `route_families`.

         If no `route_families` are given, we make request for all supported
         route families with this peer.
        Parameters:
            - `route_families`: list of route families to request route
            refresh for.

        If this peer is currently not in Established state, we raise exception.
        If any of the `route_families` are invalid we raise exception.
        """
        # If this peer has not established session yet
        if not self.in_established:
            raise ValueError('Peer not in established state to satisfy'
                             ' this request.')

        skip_validation = False
        # If request is made for all supported route_families for current
        # session, we collect all route_families for valid for current session.
        if len(route_families) == 0:
            route_families = []
            # We skip validation of route families that we collect ourselves
            # below.
            skip_validation = True
            for route_family in SUPPORTED_GLOBAL_RF:
                if self.is_mbgp_cap_valid(route_family):
                    route_families.append(route_family)

        for route_family in route_families:
            if (skip_validation or
                    ((route_family in SUPPORTED_GLOBAL_RF) and
                     # We ignore request for route_family not valid
                     # for current session.
                     self._protocol.is_mbgp_cap_valid(route_family))):
                rr_req = BGPRouteRefresh(route_family.afi, route_family.safi)
                self.enque_outgoing_msg(rr_req)
                LOG.debug('Enqueued Route Refresh message to '
                          'peer %s for rf: %s', self, route_family)

    def enque_end_of_rib(self, route_family):
        # MP_UNREACH_NLRI Attribute.
        mpunreach_attr = BGPPathAttributeMpUnreachNLRI(route_family.afi,
                                                       route_family.safi,
                                                       [])
        update = BGPUpdate(path_attributes=[mpunreach_attr])
        self.enque_outgoing_msg(update)

    def _session_next_hop(self, path):
        """Returns nexthop address relevant to current session

        Nexthop used can depend on capabilities of the session. If VPNv6
        capability is active and session is on IPv4 connection, we have to use
        IPv4 mapped IPv6 address. In other cases we can use connection end
        point/local ip address.
        """
        route_family = path.route_family

        # By default we use BGPS's interface IP with this peer as next_hop.
        if self._neigh_conf.next_hop:
            next_hop = self._neigh_conf.next_hop
        else:
            next_hop = self.host_bind_ip
        if route_family == RF_IPv6_VPN:
            next_hop = self._ipv4_mapped_ipv6(next_hop)

        return next_hop

    @staticmethod
    def _ipv4_mapped_ipv6(ipv4_address):
        # Next hop ipv4_mapped ipv6
        from netaddr import IPAddress
        return str(IPAddress(ipv4_address).ipv6())

    def _construct_update(self, outgoing_route):
        """Construct update message with Outgoing-routes path attribute
        appropriately cloned/copied/updated.
        """
        update = None
        path = outgoing_route.path
        # Get copy of path's path attributes.
        pathattr_map = path.pathattr_map
        new_pathattr = []

        if path.is_withdraw:
            if isinstance(path, Ipv4Path):
                update = BGPUpdate(withdrawn_routes=[path.nlri])
                return update
            else:
                mpunreach_attr = BGPPathAttributeMpUnreachNLRI(
                    path.route_family.afi, path.route_family.safi, [path.nlri]
                )
                new_pathattr.append(mpunreach_attr)
        elif self.is_route_server_client:
            nlri_list = [path.nlri]
            for pathattr in path.pathattr_map.values():
                new_pathattr.append(pathattr)
        else:
            # Supported and un-supported/unknown attributes.
            origin_attr = None
            nexthop_attr = None
            aspath_attr = None
            extcomm_attr = None
            community_attr = None
            localpref_attr = None
            unknown_opttrans_attrs = None
            nlri_list = [path.nlri]

            # By default we use BGPS's interface IP with this peer as next_hop.
            if self.is_ebgp_peer():
                next_hop = self._session_next_hop(path)
                if path.is_local() and path.has_nexthop():
                    next_hop = path.nexthop
            else:
                next_hop = path.nexthop
                # RFC 4271 allows us to change next_hop
                # if configured to announce its own ip address.
                if self._neigh_conf.is_next_hop_self:
                    next_hop = self._session_next_hop(path)
                    LOG.debug('using %s as a next_hop address instead'
                              ' of path.nexthop %s', next_hop, path.nexthop)

            nexthop_attr = BGPPathAttributeNextHop(next_hop)
            assert nexthop_attr, 'Missing NEXTHOP mandatory attribute.'

            if not isinstance(path, Ipv4Path):
                # We construct mpreach-nlri attribute.
                mpnlri_attr = BGPPathAttributeMpReachNLRI(
                    path.route_family.afi,
                    path.route_family.safi,
                    next_hop,
                    nlri_list
                )

            # ORIGIN Attribute.
            # According to RFC this attribute value SHOULD NOT be changed by
            # any other speaker.
            origin_attr = pathattr_map.get(BGP_ATTR_TYPE_ORIGIN)
            assert origin_attr, 'Missing ORIGIN mandatory attribute.'

            # AS_PATH Attribute.
            # Construct AS-path-attr using paths aspath attr. with local AS as
            # first item.
            path_aspath = pathattr_map.get(BGP_ATTR_TYPE_AS_PATH)
            assert path_aspath, 'Missing AS_PATH mandatory attribute.'
            # Deep copy aspath_attr value
            path_seg_list = path_aspath.path_seg_list
            # If this is a iBGP peer.
            if not self.is_ebgp_peer():
                # When a given BGP speaker advertises the route to an internal
                # peer, the advertising speaker SHALL NOT modify the AS_PATH
                # attribute associated with the route.
                aspath_attr = BGPPathAttributeAsPath(path_seg_list)
            else:
                # When a given BGP speaker advertises the route to an external
                # peer, the advertising speaker updates the AS_PATH attribute
                # as follows:
                # 1) if the first path segment of the AS_PATH is of type
                #    AS_SEQUENCE, the local system prepends its own AS num as
                #    the last element of the sequence (put it in the left-most
                #    position with respect to the position of  octets in the
                #    protocol message).  If the act of prepending will cause an
                #    overflow in the AS_PATH segment (i.e.,  more than 255
                #    ASes), it SHOULD prepend a new segment of type AS_SEQUENCE
                #    and prepend its own AS number to this new segment.
                #
                # 2) if the first path segment of the AS_PATH is of type AS_SET
                #    , the local system prepends a new path segment of type
                #    AS_SEQUENCE to the AS_PATH, including its own AS number in
                #    that segment.
                #
                # 3) if the AS_PATH is empty, the local system creates a path
                #    segment of type AS_SEQUENCE, places its own AS into that
                #    segment, and places that segment into the AS_PATH.
                if (len(path_seg_list) > 0 and
                        isinstance(path_seg_list[0], list) and
                        len(path_seg_list[0]) < 255):
                    path_seg_list[0].insert(0, self._core_service.asn)
                else:
                    path_seg_list.insert(0, [self._core_service.asn])
                aspath_attr = BGPPathAttributeAsPath(path_seg_list)

            # MULTI_EXIT_DISC Attribute.
            # For eBGP session we can send multi-exit-disc if configured.
            multi_exit_disc = None
            if self.is_ebgp_peer():
                if self._neigh_conf.multi_exit_disc:
                    multi_exit_disc = BGPPathAttributeMultiExitDisc(
                        self._neigh_conf.multi_exit_disc
                    )
                else:
                    pass
            if not self.is_ebgp_peer():
                multi_exit_disc = pathattr_map.get(
                    BGP_ATTR_TYPE_MULTI_EXIT_DISC)

            # LOCAL_PREF Attribute.
            if not self.is_ebgp_peer():
                # For iBGP peers we are required to send local-pref attribute
                # for connected or local prefixes. We check if the path matches
                # attribute_maps and set local-pref value.
                # If the path doesn't match, we set default local-pref 100.
                localpref_attr = BGPPathAttributeLocalPref(100)
                key = const.ATTR_MAPS_LABEL_DEFAULT

                if isinstance(path, (Vpnv4Path, Vpnv6Path)):
                    nlri = nlri_list[0]
                    rf = VRF_RF_IPV4 if isinstance(path, Vpnv4Path)\
                        else VRF_RF_IPV6
                    key = ':'.join([nlri.route_dist, rf])

                attr_type = AttributeMap.ATTR_LOCAL_PREF
                at_maps = self._attribute_maps.get(key, {})
                result = self._lookup_attribute_map(at_maps, attr_type, path)
                if result:
                    localpref_attr = result

            # COMMUNITY Attribute.
            community_attr = pathattr_map.get(BGP_ATTR_TYPE_COMMUNITIES)

            # EXTENDED COMMUNITY Attribute.
            # Construct ExtCommunity path-attr based on given.
            path_extcomm_attr = pathattr_map.get(
                BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
            )
            if path_extcomm_attr:
                # SOO list can be configured per VRF and/or per Neighbor.
                # NeighborConf has this setting we add this to existing list.
                communities = path_extcomm_attr.communities
                if self._neigh_conf.soo_list:
                    # construct extended community
                    soo_list = self._neigh_conf.soo_list
                    subtype = 0x03
                    for soo in soo_list:
                        first, second = soo.split(':')
                        if '.' in first:
                            c = BGPIPv4AddressSpecificExtendedCommunity(
                                subtype=subtype,
                                ipv4_address=first,
                                local_administrator=int(second))
                        else:
                            c = BGPTwoOctetAsSpecificExtendedCommunity(
                                subtype=subtype,
                                as_number=int(first),
                                local_administrator=int(second))
                        communities.append(c)

                extcomm_attr = BGPPathAttributeExtendedCommunities(
                    communities=communities
                )

            # UNKOWN Attributes.
            # Get optional transitive path attributes
            unknown_opttrans_attrs = bgp_utils.get_unknown_opttrans_attr(path)

            # Ordering path attributes according to type as RFC says. We set
            # MPReachNLRI first as advised by experts as a new trend in BGP
            # implementation.
            if isinstance(path, Ipv4Path):
                new_pathattr.append(nexthop_attr)
            else:
                new_pathattr.append(mpnlri_attr)

            new_pathattr.append(origin_attr)
            new_pathattr.append(aspath_attr)
            if multi_exit_disc:
                new_pathattr.append(multi_exit_disc)
            if localpref_attr:
                new_pathattr.append(localpref_attr)
            if community_attr:
                new_pathattr.append(community_attr)
            if extcomm_attr:
                new_pathattr.append(extcomm_attr)
            if unknown_opttrans_attrs:
                new_pathattr.extend(unknown_opttrans_attrs.values())

        if isinstance(path, Ipv4Path):
            update = BGPUpdate(path_attributes=new_pathattr,
                               nlri=nlri_list)
        else:
            update = BGPUpdate(path_attributes=new_pathattr)
        return update

    def _connect_loop(self, client_factory):
        """In the current greeenlet we try to establish connection with peer.

        This greenlet will spin another greenlet to handle incoming data
        from the peer once connection is established.
        """
        # If current configuration allow, enable active session establishment.
        if self._neigh_conf.enabled:
            self._connect_retry_event.set()

        while True:
            self._connect_retry_event.wait()

            # Reconnecting immediately after closing connection may be not very
            # well seen by some peers (ALU?)
            self.pause(1.0)
            if self.state.bgp_state in \
                    (const.BGP_FSM_IDLE, const.BGP_FSM_ACTIVE):

                # Check if we have to stop or retry
                self.state.bgp_state = const.BGP_FSM_CONNECT
                # If we have specific host interface to bind to, we will do so
                # else we will bind to system default.
                if self._neigh_conf.host_bind_ip and \
                        self._neigh_conf.host_bind_port:
                    bind_addr = (self._neigh_conf.host_bind_ip,
                                 self._neigh_conf.host_bind_port)
                else:
                    bind_addr = None
                peer_address = (self._neigh_conf.ip_address,
                                const.STD_BGP_SERVER_PORT_NUM)

                if bind_addr:
                    LOG.debug('%s trying to connect from'
                              '%s to %s', self, bind_addr, peer_address)
                else:
                    LOG.debug('%s trying to connect to %s', self, peer_address)
                tcp_conn_timeout = self._common_conf.tcp_conn_timeout
                try:
                    password = self._neigh_conf.password
                    self._connect_tcp(peer_address,
                                      client_factory,
                                      time_out=tcp_conn_timeout,
                                      bind_address=bind_addr,
                                      password=password)
                except socket.error:
                    self.state.bgp_state = const.BGP_FSM_ACTIVE
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug('Socket could not be created in time'
                                  ' (%s secs), reason %s', tcp_conn_timeout,
                                  traceback.format_exc())
                    LOG.info('Will try to reconnect to %s after %s secs: %s',
                             self._neigh_conf.ip_address,
                             self._common_conf.bgp_conn_retry_time,
                             self._connect_retry_event.is_set())

            self.pause(self._common_conf.bgp_conn_retry_time)

    def _set_protocol(self, proto):
        self._protocol = proto

        # Update state attributes
        self.state.peer_ip, self.state.peer_port = self._protocol._remotename
        self.state.local_ip, self.state.local_port = self._protocol._localname
#         self.state.bgp_state = self._protocol.state
        # Stop connect_loop retry timer as we are now connected
        if self._protocol and self._connect_retry_event.is_set():
            self._connect_retry_event.clear()
            LOG.debug('Connect retry event for %s is cleared', self)

        if self._protocol and self.outgoing_msg_event.is_set():
            # Start processing sink.
            self.outgoing_msg_event.set()
            LOG.debug('Processing of outgoing msg. started for %s.', self)

    def _send_collision_err_and_stop(self, protocol):
        code = BGP_ERROR_CEASE
        subcode = BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION
        self._signal_bus.bgp_error(self, code, subcode, None)
        protocol.send_notification(code, subcode)
        protocol.stop()

    def bind_protocol(self, proto):
        """Tries to bind given protocol to this peer.

        Should only be called by `proto` trying to bind.
        Once bound this protocol instance will be used to communicate with
        peer. If another protocol is already bound, connection collision
        resolution takes place.
        """
        LOG.debug('Trying to bind protocol %s to peer %s', proto, self)
        # Validate input.
        if not isinstance(proto, BgpProtocol):
            raise ValueError('Currently only supports valid instances of'
                             ' `BgpProtocol`')

        if proto.state != const.BGP_FSM_OPEN_CONFIRM:
            raise ValueError('Only protocols in OpenConfirm state can be'
                             ' bound')

        # If we are not bound to any protocol
        is_bound = False
        if not self._protocol:
            self._set_protocol(proto)
            is_bound = True
        else:
            # If existing protocol is already established, we raise exception.
            if self.state.bgp_state != const.BGP_FSM_IDLE:
                LOG.debug('Currently in %s state, hence will send collision'
                          ' Notification to close this protocol.',
                          self.state.bgp_state)
                self._send_collision_err_and_stop(proto)
                return

            # If we have a collision that need to be resolved
            assert proto.is_colliding(self._protocol), \
                ('Tried to bind second protocol that is not colliding with '
                 'first/bound protocol')
            LOG.debug('Currently have one protocol in %s state and '
                      'another protocol in %s state',
                      self._protocol.state, proto.state)
            # Protocol that is already bound
            first_protocol = self._protocol
            assert ((first_protocol.is_reactive and not proto.is_reactive) or
                    (proto.is_reactive and not first_protocol.is_reactive))
            # Connection initiated by peer.
            reactive_proto = None
            # Connection initiated locally.
            proactive_proto = None
            # Identify which protocol was initiated by which peer.
            if proto.is_reactive:
                reactive_proto = proto
                proactive_proto = self._protocol
            else:
                reactive_proto = self._protocol
                proactive_proto = proto

            LOG.debug('Pro-active/Active protocol %s', proactive_proto)
            # We compare bgp local and remote router id and keep the protocol
            # that was initiated by peer with highest id.
            if proto.is_local_router_id_greater():
                self._set_protocol(proactive_proto)
            else:
                self._set_protocol(reactive_proto)

            if self._protocol is not proto:
                # If new proto did not win collision we return False to
                # indicate this.
                is_bound = False
            else:
                # If first protocol did not win collision resolution we
                # we send notification to peer and stop it
                self._send_collision_err_and_stop(first_protocol)
                is_bound = True

        return is_bound

    def create_open_msg(self):
        """Create `Open` message using current settings.

        Current setting include capabilities, timers and ids.
        """
        asnum = self._common_conf.local_as
        bgpid = self._common_conf.router_id
        holdtime = self._neigh_conf.hold_time

        def flatten(L):
            if isinstance(L, list):
                for i in range(len(L)):
                    for e in flatten(L[i]):
                        yield e
            else:
                yield L
        opts = list(flatten(
            list(self._neigh_conf.get_configured_capabilites().values())))
        open_msg = BGPOpen(
            my_as=asnum,
            bgp_identifier=bgpid,
            version=const.BGP_VERSION_NUM,
            hold_time=holdtime,
            opt_param=opts
        )
        return open_msg

    def _validate_update_msg(self, update_msg):
        """Validate update message as per RFC.

        Here we validate the message after it has been parsed. Message
        has already been validated against some errors inside parsing
        library.
        """
        # TODO(PH): finish providing implementation, currently low priority
        assert update_msg.type == BGP_MSG_UPDATE
        # An UPDATE message may be received only in the Established state.
        # Receiving an UPDATE message in any other state is an error.
        if self.state.bgp_state != const.BGP_FSM_ESTABLISHED:
            LOG.error('Received UPDATE message when not in ESTABLISHED'
                      ' state.')
            raise bgp.FiniteStateMachineError()

        mp_reach_attr = update_msg.get_path_attr(
            BGP_ATTR_TYPE_MP_REACH_NLRI
        )
        mp_unreach_attr = update_msg.get_path_attr(
            BGP_ATTR_TYPE_MP_UNREACH_NLRI
        )

        # non-MPBGP Update msg.
        if not (mp_reach_attr or mp_unreach_attr):
            if not self.is_mpbgp_cap_valid(RF_IPv4_UC):
                LOG.error('Got UPDATE message with un-available'
                          ' afi/safi %s', RF_IPv4_UC)
            nlri_list = update_msg.nlri
            if len(nlri_list) > 0:
                # Check for missing well-known mandatory attributes.
                aspath = update_msg.get_path_attr(BGP_ATTR_TYPE_AS_PATH)
                if not aspath:
                    raise bgp.MissingWellKnown(
                        BGP_ATTR_TYPE_AS_PATH)

                if (self.check_first_as and self.is_ebgp_peer() and
                        not aspath.has_matching_leftmost(self.remote_as)):
                    LOG.error('First AS check fails. Raise appropriate'
                              ' exception.')
                    raise bgp.MalformedAsPath()

                origin = update_msg.get_path_attr(BGP_ATTR_TYPE_ORIGIN)
                if not origin:
                    raise bgp.MissingWellKnown(BGP_ATTR_TYPE_ORIGIN)

                nexthop = update_msg.get_path_attr(BGP_ATTR_TYPE_NEXT_HOP)
                if not nexthop:
                    raise bgp.MissingWellKnown(BGP_ATTR_TYPE_NEXT_HOP)

            return True

        # Check if received MP_UNREACH path attribute is of available afi/safi
        if mp_unreach_attr:
            if not self.is_mpbgp_cap_valid(mp_unreach_attr.route_family):
                LOG.error('Got UPDATE message with un-available afi/safi for'
                          ' MP_UNREACH path attribute (non-negotiated'
                          ' afi/safi) %s', mp_unreach_attr.route_family)
                # raise bgp.OptAttrError()

        if mp_reach_attr:
            # Check if received MP_REACH path attribute is of available
            # afi/safi
            if not self.is_mpbgp_cap_valid(mp_reach_attr.route_family):
                LOG.error('Got UPDATE message with un-available afi/safi for'
                          ' MP_UNREACH path attribute (non-negotiated'
                          ' afi/safi) %s', mp_reach_attr.route_family)
                # raise bgp.OptAttrError()

            # Check for missing well-known mandatory attributes.
            aspath = update_msg.get_path_attr(BGP_ATTR_TYPE_AS_PATH)
            if not aspath:
                raise bgp.MissingWellKnown(BGP_ATTR_TYPE_AS_PATH)

            if (self.check_first_as and self.is_ebgp_peer() and
                    not aspath.has_matching_leftmost(self.remote_as)):
                LOG.error('First AS check fails. Raise appropriate exception.')
                raise bgp.MalformedAsPath()

            origin = update_msg.get_path_attr(BGP_ATTR_TYPE_ORIGIN)
            if not origin:
                raise bgp.MissingWellKnown(BGP_ATTR_TYPE_ORIGIN)

            # Validate Next hop.
            # TODO(PH): Currently ignore other cases.
            if (not mp_reach_attr.next_hop or
                    (mp_reach_attr.next_hop == self.host_bind_ip)):
                LOG.error('Nexthop of received UPDATE msg. (%s) same as local'
                          ' interface address %s.',
                          mp_reach_attr.next_hop,
                          self.host_bind_ip)
                return False

        return True

    def _handle_update_msg(self, update_msg):
        """Extracts and processes new paths or withdrawals in given
         `update_msg`.

        Parameter:
            - `update_msg`: update message to process.
            - `valid_rts`: current valid/interesting rts to the application
            according to configuration of all VRFs.
        Assumes Multiprotocol Extensions capability is supported and enabled.
        """
        assert self.state.bgp_state == const.BGP_FSM_ESTABLISHED
        self.state.incr(PeerCounterNames.RECV_UPDATES)
        if not self._validate_update_msg(update_msg):
            # If update message was not valid for some reason, we ignore its
            # routes.
            LOG.error('UPDATE message was invalid, hence ignoring its routes.')
            return

        # Increment count of update received.
        mp_reach_attr = update_msg.get_path_attr(BGP_ATTR_TYPE_MP_REACH_NLRI)
        mp_unreach_attr = update_msg.get_path_attr(
            BGP_ATTR_TYPE_MP_UNREACH_NLRI
        )

        nlri_list = update_msg.nlri
        withdraw_list = update_msg.withdrawn_routes

        if mp_reach_attr:
            # Extract advertised paths from given message.
            self._extract_and_handle_mpbgp_new_paths(update_msg)

        if mp_unreach_attr:
            # Extract withdraws from given message.
            self._extract_and_handle_mpbgp_withdraws(mp_unreach_attr)

        if nlri_list:
            self._extract_and_handle_bgp4_new_paths(update_msg)

        if withdraw_list:
            self._extract_and_handle_bgp4_withdraws(withdraw_list)

    def _extract_and_handle_bgp4_new_paths(self, update_msg):
        """Extracts new paths advertised in the given update message's
         *MpReachNlri* attribute.

        Assumes MPBGP capability is enabled and message was validated.
        Parameters:
            - update_msg: (Update) is assumed to be checked for all bgp
            message errors.
            - valid_rts: (iterable) current valid/configured RTs.

        Extracted paths are added to appropriate *Destination* for further
        processing.
        """
        umsg_pattrs = update_msg.pathattr_map

        msg_rf = RF_IPv4_UC
        # Check if this route family is among supported route families.
        if msg_rf not in SUPPORTED_GLOBAL_RF:
            LOG.info(('Received route for route family %s which is'
                      ' not supported. Ignoring paths from this UPDATE: %s') %
                     (msg_rf, update_msg))
            return

        aspath = umsg_pattrs.get(BGP_ATTR_TYPE_AS_PATH)
        # Check if AS_PATH has loops.
        if aspath.has_local_as(self._common_conf.local_as):
            LOG.error('Update message AS_PATH has loops. Ignoring this'
                      ' UPDATE. %s', update_msg)
            return

        next_hop = update_msg.get_path_attr(BGP_ATTR_TYPE_NEXT_HOP).value
        # Nothing to do if we do not have any new NLRIs in this message.
        msg_nlri_list = update_msg.nlri
        if not msg_nlri_list:
            LOG.debug('Update message did not have any new MP_REACH_NLRIs.')
            return

        # Create path instances for each NLRI from the update message.
        for msg_nlri in msg_nlri_list:
            LOG.debug('NLRI: %s', msg_nlri)
            new_path = bgp_utils.create_path(
                self,
                msg_nlri,
                pattrs=umsg_pattrs,
                nexthop=next_hop
            )
            LOG.debug('Extracted paths from Update msg.: %s', new_path)

            block, blocked_cause = self._apply_in_filter(new_path)

            nlri_str = new_path.nlri.formatted_nlri_str
            received_route = ReceivedRoute(new_path, self, block)
            self._adj_rib_in[nlri_str] = received_route
            self._signal_bus.adj_rib_in_changed(self, received_route)

            if not block:
                # Update appropriate table with new paths.
                tm = self._core_service.table_manager
                tm.learn_path(new_path)
            else:
                LOG.debug('prefix : %s is blocked by in-bound filter: %s',
                          msg_nlri, blocked_cause)

        # If update message had any qualifying new paths, do some book-keeping.
        if msg_nlri_list:
            # Update prefix statistics.
            self.state.incr(PeerCounterNames.RECV_PREFIXES,
                            incr_by=len(msg_nlri_list))
            # Check if we exceed max. prefixes allowed for this neighbor.
            if self._neigh_conf.exceeds_max_prefix_allowed(
                    self.state.get_count(PeerCounterNames.RECV_PREFIXES)):
                LOG.error('Max. prefix allowed for this neighbor '
                          'exceeded.')

    def _extract_and_handle_bgp4_withdraws(self, withdraw_list):
        """Extracts withdraws advertised in the given update message's
         *MpUnReachNlri* attribute.

        Assumes MPBGP capability is enabled.
        Parameters:
            - update_msg: (Update) is assumed to be checked for all bgp
            message errors.

        Extracted withdraws are added to appropriate *Destination* for further
        processing.
        """
        msg_rf = RF_IPv4_UC
        # Check if this route family is among supported route families.
        if msg_rf not in SUPPORTED_GLOBAL_RF:
            LOG.info(
                (
                    'Received route for route family %s which is'
                    ' not supported. Ignoring withdraws form this UPDATE.'
                ) % msg_rf
            )
            return

        w_nlris = withdraw_list
        if not w_nlris:
            # If this is EOR of some kind, handle it
            self._handle_eor(msg_rf)

        for w_nlri in w_nlris:
            w_path = bgp_utils.create_path(
                self,
                w_nlri,
                is_withdraw=True
            )

            block, blocked_cause = self._apply_in_filter(w_path)

            received_route = ReceivedRoute(w_path, self, block)
            nlri_str = w_nlri.formatted_nlri_str

            if nlri_str in self._adj_rib_in:
                del self._adj_rib_in[nlri_str]
                self._signal_bus.adj_rib_in_changed(self, received_route)

            if not block:
                # Update appropriate table with withdraws.
                tm = self._core_service.table_manager
                tm.learn_path(w_path)
            else:
                LOG.debug('prefix : %s is blocked by in-bound filter: %s',
                          nlri_str, blocked_cause)

    def _extract_and_handle_mpbgp_new_paths(self, update_msg):
        """Extracts new paths advertised in the given update message's
         *MpReachNlri* attribute.

        Assumes MPBGP capability is enabled and message was validated.
        Parameters:
            - update_msg: (Update) is assumed to be checked for all bgp
            message errors.
            - valid_rts: (iterable) current valid/configured RTs.

        Extracted paths are added to appropriate *Destination* for further
        processing.
        """
        umsg_pattrs = update_msg.pathattr_map
        mpreach_nlri_attr = umsg_pattrs.get(BGP_ATTR_TYPE_MP_REACH_NLRI)
        assert mpreach_nlri_attr

        msg_rf = mpreach_nlri_attr.route_family
        # Check if this route family is among supported route families.
        if msg_rf not in SUPPORTED_GLOBAL_RF:
            LOG.info(('Received route for route family %s which is'
                      ' not supported. Ignoring paths from this UPDATE: %s') %
                     (msg_rf, update_msg))
            return

        aspath = umsg_pattrs.get(BGP_ATTR_TYPE_AS_PATH)
        # Check if AS_PATH has loops.
        if aspath.has_local_as(self._common_conf.local_as):
            LOG.error('Update message AS_PATH has loops. Ignoring this'
                      ' UPDATE. %s', update_msg)
            return

        if msg_rf in (RF_IPv4_VPN, RF_IPv6_VPN):
            # Check if we have Extended Communities Attribute.
            # TODO(PH): Check if RT_NLRI afi/safi will ever have this attribute
            ext_comm_attr = umsg_pattrs.get(BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
            # Check if we have at-least one RT is of interest to us.
            if not ext_comm_attr:
                LOG.info('Missing Extended Communities Attribute. '
                         'Ignoring paths from this UPDATE: %s', update_msg)
                return

            msg_rts = ext_comm_attr.rt_list
            # If we do not have any RTs associated with this msg., we do not
            # extract any paths.
            if not msg_rts:
                LOG.info('Received route with no RTs. Ignoring paths in this'
                         ' UPDATE: %s', update_msg)
                return

            # If none of the RTs in the message are of interest, we do not
            # extract any paths.
            interested_rts = self._core_service.global_interested_rts
            if not interested_rts.intersection(msg_rts):
                LOG.info('Received route with RT %s that is of no interest to'
                         ' any VRFs or Peers %s.'
                         ' Ignoring paths from this UPDATE: %s',
                         msg_rts, interested_rts, update_msg)
                return

        next_hop = mpreach_nlri_attr.next_hop
        # Nothing to do if we do not have any new NLRIs in this message.
        msg_nlri_list = mpreach_nlri_attr.nlri
        if not msg_nlri_list:
            LOG.debug('Update message did not have any new MP_REACH_NLRIs.')
            return

        # Create path instances for each NLRI from the update message.
        for msg_nlri in msg_nlri_list:
            new_path = bgp_utils.create_path(
                self,
                msg_nlri,
                pattrs=umsg_pattrs,
                nexthop=next_hop
            )
            LOG.debug('Extracted paths from Update msg.: %s', new_path)

            block, blocked_cause = self._apply_in_filter(new_path)

            received_route = ReceivedRoute(new_path, self, block)
            nlri_str = msg_nlri.formatted_nlri_str
            self._adj_rib_in[nlri_str] = received_route
            self._signal_bus.adj_rib_in_changed(self, received_route)

            if not block:
                if msg_rf == RF_RTC_UC \
                        and self._init_rtc_nlri_path is not None:
                    self._init_rtc_nlri_path.append(new_path)
                else:
                    # Update appropriate table with new paths.
                    tm = self._core_service.table_manager
                    tm.learn_path(new_path)
            else:
                LOG.debug('prefix : %s is blocked by in-bound filter: %s',
                          msg_nlri, blocked_cause)

        # If update message had any qualifying new paths, do some book-keeping.
        if msg_nlri_list:
            # Update prefix statistics.
            self.state.incr(PeerCounterNames.RECV_PREFIXES,
                            incr_by=len(msg_nlri_list))
            # Check if we exceed max. prefixes allowed for this neighbor.
            if self._neigh_conf.exceeds_max_prefix_allowed(
                    self.state.get_count(PeerCounterNames.RECV_PREFIXES)):
                LOG.error('Max. prefix allowed for this neighbor '
                          'exceeded.')

    def _extract_and_handle_mpbgp_withdraws(self, mp_unreach_attr):
        """Extracts withdraws advertised in the given update message's
         *MpUnReachNlri* attribute.

        Assumes MPBGP capability is enabled.
        Parameters:
            - update_msg: (Update) is assumed to be checked for all bgp
            message errors.

        Extracted withdraws are added to appropriate *Destination* for further
        processing.
        """
        msg_rf = mp_unreach_attr.route_family
        # Check if this route family is among supported route families.
        if msg_rf not in SUPPORTED_GLOBAL_RF:
            LOG.info(
                (
                    'Received route for route family %s which is'
                    ' not supported. Ignoring withdraws form this UPDATE.'
                ) % msg_rf
            )
            return

        w_nlris = mp_unreach_attr.withdrawn_routes
        if not w_nlris:
            # If this is EOR of some kind, handle it
            self._handle_eor(msg_rf)

        for w_nlri in w_nlris:
            w_path = bgp_utils.create_path(
                self,
                w_nlri,
                is_withdraw=True
            )
            block, blocked_cause = self._apply_in_filter(w_path)

            received_route = ReceivedRoute(w_path, self, block)
            nlri_str = w_nlri.formatted_nlri_str

            if nlri_str in self._adj_rib_in:
                del self._adj_rib_in[nlri_str]
                self._signal_bus.adj_rib_in_changed(self, received_route)

            if not block:
                # Update appropriate table with withdraws.
                tm = self._core_service.table_manager
                tm.learn_path(w_path)
            else:
                LOG.debug('prefix : %s is blocked by in-bound filter: %s',
                          w_nlri, blocked_cause)

    def _handle_eor(self, route_family):
        """Currently we only handle EOR for RTC address-family.

        We send non-rtc initial updates if not already sent.
        """
        LOG.debug('Handling EOR for %s', route_family)
#         assert (route_family in SUPPORTED_GLOBAL_RF)
#         assert self.is_mbgp_cap_valid(route_family)

        if route_family == RF_RTC_UC:
            self._unschedule_sending_init_updates()

            # Learn all rt_nlri at the same time As RT are learned and RT
            # filter get updated, qualifying NLRIs are automatically sent to
            # peer including initial update
            tm = self._core_service.table_manager
            for rt_nlri in self._init_rtc_nlri_path:
                tm.learn_path(rt_nlri)
                # Give chance to process new RT_NLRI so that we have updated RT
                # filter for all peer including this peer before we communicate
                # NLRIs for other address-families
                self.pause(0)
            # Clear collection of initial RTs as we no longer need to wait for
            # EOR for RT NLRIs and to indicate that new RT NLRIs should be
            # handled in a regular fashion
            self._init_rtc_nlri_path = None

    def handle_msg(self, msg):
        """BGP message handler.

        BGP message handling is shared between protocol instance and peer. Peer
        only handles limited messages under suitable state. Here we handle
        KEEPALIVE, UPDATE and ROUTE_REFRESH messages. UPDATE and ROUTE_REFRESH
        messages are handled only after session is established.
        """
        if msg.type == BGP_MSG_KEEPALIVE:
            # If we receive a Keep Alive message in open_confirm state, we
            # transition to established state.
            if self.state.bgp_state == const.BGP_FSM_OPEN_CONFIRM:
                self.state.bgp_state = const.BGP_FSM_ESTABLISHED
                self._enqueue_init_updates()

        elif msg.type == BGP_MSG_UPDATE:
            assert self.state.bgp_state == const.BGP_FSM_ESTABLISHED
            # Will try to process this UDPATE message further
            self._handle_update_msg(msg)

        elif msg.type == BGP_MSG_ROUTE_REFRESH:
            # If its route-refresh message
            assert self.state.bgp_state == const.BGP_FSM_ESTABLISHED
            self._handle_route_refresh_msg(msg)

        else:
            # Open/Notification messages are currently handled by protocol and
            # nothing is done inside peer, so should not see them here.
            raise ValueError('Peer does not support handling of %s'
                             ' message during % state' %
                             (msg, self.state.bgp_state()))

    def _handle_err_sor_msg(self, afi, safi):
        # Check if ERR capability is enabled for this peer.
        if not self._protocol.is_enhanced_rr_cap_valid():
            LOG.error('Received Start-of-RIB (SOR) even though ERR is not'
                      ' enabled')
            return

        # Increment the version number of this peer so that we can identify
        # inconsistencies/stale routes.
        self.version_num += 1

        # Check if refresh_stalepath_time is enabled.
        rst = self._common_conf.refresh_stalepath_time
        if rst != 0:
            # Set a timer to clean the stale paths at configured time.
            # Clean/track inconsistent/stale routes.
            route_family = RouteFamily(afi, safi)
            if route_family in SUPPORTED_GLOBAL_RF:
                self._refresh_stalepath_timer = self._spawn_after(
                    'err-refresh-stale-path-timer', rst,
                    self._core_service.table_manager.clean_stale_routes, self,
                    route_family)
                LOG.debug('Refresh Stale Path timer set (%s sec).', rst)

    def _handle_route_refresh_msg(self, msg):
        afi = msg.afi
        safi = msg.safi
        demarcation = msg.demarcation

        # If this normal route-refresh request.
        if demarcation == 0:
            self._handle_route_refresh_req(afi, safi)

        # If this is start of RIB (SOR) message.
        elif demarcation == 1:
            self._handle_err_sor_msg(afi, safi)

        # If this is end of RIB (EOR) message.
        elif demarcation == 2:
            # Clean/track inconsistent/stale routes.
            route_family = RouteFamily(afi, safi)
            if route_family in SUPPORTED_GLOBAL_RF:
                tm = self._core_service.table_manager
                tm.clean_stale_routes(self, route_family)

        else:
            LOG.error('Route refresh message has invalid demarcation %s',
                      demarcation)

    def _handle_route_refresh_req(self, afi, safi):
        rr_af = get_rf(afi, safi)
        self.state.incr(PeerCounterNames.RECV_REFRESH)

        # Check if peer has asked for route-refresh for af that was advertised
        if not self._protocol.is_route_family_adv(rr_af):
            LOG.info('Peer asked for route - refresh for un - advertised '
                     'address - family %s', rr_af)
            return

        self._fire_route_refresh(rr_af)

    def _fire_route_refresh(self, af):
        # Check if enhanced route refresh is enabled/valid.
        sor = None
        if self._protocol.is_enhanced_rr_cap_valid():
            # If enhanced route-refresh is valid/enabled, enqueue SOR.
            afi = af.afi
            safi = af.safi
            sor = BGPRouteRefresh(afi, safi, demarcation=1)
            self.enque_first_outgoing_msg(sor)

        # Ask core to re-send sent routes
        self._peer_manager.resend_sent(af, self)

        # If enhanced route-refresh is valid/enabled, then we enqueue EOR.
        if sor is not None:
            self._enqueue_eor_msg(sor)

    def _enqueue_eor_msg(self, sor):
        """Enqueues Enhanced RR EOR if for given SOR a EOR is not already
        sent.
        """
        if self._protocol.is_enhanced_rr_cap_valid() and not sor.eor_sent:
            afi = sor.afi
            safi = sor.safi
            eor = BGPRouteRefresh(afi, safi, demarcation=2)
            self.enque_outgoing_msg(eor)
            sor.eor_sent = True

    def _schedule_sending_init_updates(self):
        """Setup timer for sending best-paths for all other address-families
        that qualify.

        Setup timer for sending initial updates to peer.
        """

        def _enqueue_non_rtc_init_updates():
            LOG.debug('Scheduled queuing of initial Non-RTC UPDATEs')
            tm = self._core_service.table_manager
            self.comm_all_best_paths(tm.global_tables)
            self._sent_init_non_rtc_update = True
            # Stop the timer as we have handled RTC EOR
            self._rtc_eor_timer.stop()
            self._rtc_eor_timer = None

        self._sent_init_non_rtc_update = False
        self._rtc_eor_timer = self._create_timer(
            Peer.RTC_EOR_TIMER_NAME,
            _enqueue_non_rtc_init_updates
        )
        # Start timer for sending initial updates
        self._rtc_eor_timer.start(const.RTC_EOR_DEFAULT_TIME, now=False)
        LOG.debug('Scheduled sending of initial Non-RTC UPDATEs after:'
                  ' %s sec', const.RTC_EOR_DEFAULT_TIME)

    def _unschedule_sending_init_updates(self):
        """Un-schedules sending of initial updates

        Stops the timer if set for sending initial updates.
        Returns:
            - True if timer was stopped
            - False if timer was already stopped and nothing was done
        """
        LOG.debug('Un-scheduling sending of initial Non-RTC UPDATEs'
                  ' (init. UPDATEs already sent: %s)',
                  self._sent_init_non_rtc_update)
        if self._rtc_eor_timer:
            self._rtc_eor_timer.stop()
            self._rtc_eor_timer = None
            return True
        return False

    def _enqueue_init_updates(self):
        """Enqueues current routes to be shared with this peer."""
        assert self.state.bgp_state == const.BGP_FSM_ESTABLISHED
        if self.is_mbgp_cap_valid(RF_RTC_UC):
            # Enqueues all best-RTC_NLRIs to be sent as initial update to this
            # peer.
            self._peer_manager.comm_all_rt_nlris(self)
            self._schedule_sending_init_updates()
        else:
            # Enqueues all best-path to be sent as initial update to this peer
            # expect for RTC route-family.
            tm = self._core_service.table_manager
            self.comm_all_best_paths(tm.global_tables)

    def comm_all_best_paths(self, global_tables):
        """Shares/communicates current best paths with this peers.

        Can be used to send initial updates after we have established session
        with `peer`.
        """
        LOG.debug('Communicating current best path for all afi/safi except'
                  ' 1/132')
        # We will enqueue best path from all global destination.
        for route_family, table in global_tables.items():
            if route_family == RF_RTC_UC:
                continue
            if self.is_mbgp_cap_valid(route_family):
                for dest in table.values():
                    if dest.best_path:
                        self.communicate_path(dest.best_path)

    def communicate_path(self, path):
        """Communicates `path` to this peer if it qualifies.

        Checks if `path` should be shared/communicated with this peer according
        to various conditions: like bgp state, transmit side loop, local and
        remote AS path, community attribute, etc.
        """
        LOG.debug('Peer %s asked to communicate path', self)
        if not path:
            raise ValueError('Invalid path %s given.' % path)

        # We do not send anything to peer who is not in established state.
        if not self.in_established():
            LOG.debug('Skipping sending path as peer is not in '
                      'ESTABLISHED state %s', path)
            return

        # Check if this session is available for given paths afi/safi
        path_rf = path.route_family
        if not self.is_mpbgp_cap_valid(path_rf):
            LOG.debug('Skipping sending path as %s route family is not'
                      ' available for this session', path_rf)
            return

        # If RTC capability is available and path afi/saif is other than  RT
        # nlri
        if path_rf != RF_RTC_UC and \
                self.is_mpbgp_cap_valid(RF_RTC_UC):
            rtfilter = self._peer_manager.curr_peer_rtfilter(self)
            # If peer does not have any rtfilter or if rtfilter does not have
            # any RTs common with path RTs we do not share this path with the
            # peer
            if rtfilter and not path.has_rts_in(rtfilter):
                LOG.debug('Skipping sending path as rffilter %s and path '
                          'rts %s have no RT in common',
                          rtfilter, path.get_rts())
                return

        # Transmit side loop detection: We check if leftmost AS matches
        # peers AS, if so we do not send UPDATE message to this peer.
        as_path = path.get_pattr(BGP_ATTR_TYPE_AS_PATH)
        if as_path and as_path.has_matching_leftmost(self.remote_as):
            LOG.debug('Skipping sending path as AS_PATH has peer AS %s',
                      self.remote_as)
            return

        # If this peer is a route server client, we forward the path
        # regardless of AS PATH loop, whether the connction is iBGP or eBGP,
        # or path's communities.
        if self.is_route_server_client:
            outgoing_route = OutgoingRoute(path)
            self.enque_outgoing_msg(outgoing_route)

        if self._neigh_conf.multi_exit_disc:
            med_attr = path.get_pattr(BGP_ATTR_TYPE_MULTI_EXIT_DISC)
            if not med_attr:
                path = bgp_utils.clone_path_and_update_med_for_target_neighbor(
                    path,
                    self._neigh_conf.multi_exit_disc
                )

        # For connected/local-prefixes, we send update to all peers.
        if path.source is None:
            # Construct OutgoingRoute specific for this peer and put it in
            # its sink.
            outgoing_route = OutgoingRoute(path)
            self.enque_outgoing_msg(outgoing_route)

        # If path from a bgp-peer is new best path, we share it with
        # all bgp-peers except the source peer and other peers in his AS.
        # This is default JNOS setting that in JNOS can be disabled with
        # 'advertise-peer-as' setting.
        elif (self != path.source or
              self.remote_as != path.source.remote_as):
            # When BGP speaker receives an UPDATE message from an internal
            # peer, the receiving BGP speaker SHALL NOT re-distribute the
            # routing information contained in that UPDATE message to other
            # internal peers (unless the speaker acts as a BGP Route
            # Reflector) [RFC4271].
            if (self.remote_as == self._core_service.asn and
                    self.remote_as == path.source.remote_as):
                return

            # If new best path has community attribute, it should be taken into
            # account when sending UPDATE to peers.
            comm_attr = path.get_pattr(BGP_ATTR_TYPE_COMMUNITIES)
            if comm_attr:
                comm_attr_na = comm_attr.has_comm_attr(
                    BGPPathAttributeCommunities.NO_ADVERTISE
                )
                # If we have NO_ADVERTISE attribute present, we do not send
                # UPDATE to any peers
                if comm_attr_na:
                    LOG.debug('Path has community attr. NO_ADVERTISE = %s'
                              '. Hence not advertising to peer',
                              comm_attr_na)
                    return

                comm_attr_ne = comm_attr.has_comm_attr(
                    BGPPathAttributeCommunities.NO_EXPORT
                )
                comm_attr_nes = comm_attr.has_comm_attr(
                    BGPPathAttributeCommunities.NO_EXPORT_SUBCONFED
                )
                # If NO_EXPORT_SUBCONFED/NO_EXPORT is one of the attribute, we
                # do not advertise to eBGP peers as we do not have any
                # confederation feature at this time.
                if ((comm_attr_nes or comm_attr_ne) and
                        (self.remote_as != self._core_service.asn)):
                    LOG.debug('Skipping sending UPDATE to peer: %s as per '
                              'community attribute configuration', self)
                    return

            # Construct OutgoingRoute specific for this peer and put it in
            # its sink.
            outgoing_route = OutgoingRoute(path)
            self.enque_outgoing_msg(outgoing_route)
            LOG.debug('Enqueued outgoing route %s for peer %s',
                      outgoing_route.path.nlri, self)

    def connection_made(self):
        """Protocols connection established handler
        """
        LOG.info(
            'Connection to peer: %s established',
            self._neigh_conf.ip_address,
            extra={
                'resource_name': self._neigh_conf.name,
                'resource_id': self._neigh_conf.id
            }
        )

    def connection_lost(self, reason):
        """Protocols connection lost handler.
        """
        LOG.info(
            'Connection to peer %s lost, reason: %s Resetting '
            'retry connect loop: %s' %
            (self._neigh_conf.ip_address, reason,
             self._connect_retry_event.is_set()),
            extra={
                'resource_name': self._neigh_conf.name,
                'resource_id': self._neigh_conf.id
            }
        )
        self.state.bgp_state = const.BGP_FSM_IDLE
        if self._protocol:
            self._protocol.stop()
            self._protocol = None
            # Create new collection for initial RT NLRIs
            self._init_rtc_nlri_path = []
            self._sent_init_non_rtc_update = False
            # Clear sink.
            self.clear_outgoing_msg_list()
            # Un-schedule timers
            self._unschedule_sending_init_updates()

            # Increment the version number of this source.
            self.version_num += 1
            self._peer_manager.on_peer_down(self)

            # Check configuration if neighbor is still enabled, we try
            # reconnecting.
            if self._neigh_conf.enabled:
                if not self._connect_retry_event.is_set():
                    self._connect_retry_event.set()

    @staticmethod
    def _lookup_attribute_map(attribute_map, attr_type, path):
        result_attr = None
        if attr_type in attribute_map:
            maps = attribute_map[attr_type]
            for m in maps:
                cause, result = m.evaluate(path)
                LOG.debug(
                    "local_pref evaluation result:%s, cause:%s",
                    result, cause)
                if result:
                    result_attr = m.get_attribute()
                    break
        return result_attr
