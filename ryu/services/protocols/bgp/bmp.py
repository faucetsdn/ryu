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

from ryu.services.protocols.bgp.base import Activity
from ryu.lib import hub
from ryu.lib.packet import bmp
from ryu.lib.packet import bgp
from ryu.services.protocols.bgp import constants as const
import socket
import logging
from calendar import timegm
from ryu.services.protocols.bgp.signals.emit import BgpSignalBus
from ryu.services.protocols.bgp.info_base.ipv4 import Ipv4Path
from ryu.lib.packet.bgp import BGPUpdate
from ryu.lib.packet.bgp import BGPPathAttributeNextHop
from ryu.lib.packet.bgp import BGPPathAttributeMpReachNLRI
from ryu.lib.packet.bgp import BGPPathAttributeMpUnreachNLRI

LOG = logging.getLogger('bgpspeaker.bmp')


class BMPClient(Activity):
    """A BMP client.

    Try to establish BMP session between a configured BMP server.
    If BMP session is established, transfer information about peers
    (e.g. received and sent open msgs, contents of adj-rib-in, other stats)

    """

    def __init__(self, core_service, host, port):
        super(BMPClient, self).__init__(name='BMPClient(%s:%s)' % (host, port))
        self._core_service = core_service
        self._core_service.signal_bus.register_listener(
            BgpSignalBus.BGP_ADJ_RIB_IN_CHANGED,
            lambda _, data: self.on_adj_rib_in_changed(data)
        )
        self._core_service.signal_bus.register_listener(
            BgpSignalBus.BGP_ADJ_UP,
            lambda _, data: self.on_adj_up(data)
        )
        self._core_service.signal_bus.register_listener(
            BgpSignalBus.BGP_ADJ_DOWN,
            lambda _, data: self.on_adj_down(data)
        )
        self._socket = None
        self.server_address = (host, port)
        self._connect_retry_event = hub.Event()
        self._connect_retry_time = 5

    def _run(self):
        self._connect_retry_event.set()

        while True:
            self._connect_retry_event.wait()

            try:
                self._connect_retry_event.clear()
                self._connect_tcp(self.server_address,
                                  self._handle_bmp_session)
            except socket.error:
                    self._connect_retry_event.set()
                    LOG.info('Will try to reconnect to %s after %s secs: %s',
                             self.server_address, self._connect_retry_time,
                             self._connect_retry_event.is_set())

            self.pause(self._connect_retry_time)

    def _send(self, msg):
        if not self._socket:
            return
        assert isinstance(msg, bmp.BMPMessage)
        serialized_msg = msg.serialize()

        ret = self._socket.send(msg.serialize())

    def on_adj_rib_in_changed(self, data):
        peer = data['peer']
        path = data['received_route']
        msg = self._construct_route_monitoring(peer, path)
        self._send(msg)

    def on_adj_up(self, data):
        peer = data['peer']
        msg = self._construct_peer_up_notification(peer)
        self._send(msg)

    def on_adj_down(self, data):
        peer = data['peer']
        msg = self._construct_peer_down_notification(peer)
        self._send(msg)

    def _construct_peer_up_notification(self, peer):
        if peer.is_mpbgp_cap_valid(bgp.RF_IPv4_VPN) or \
                peer.is_mpbgp_cap_valid(bgp.RF_IPv6_VPN):
            peer_type = bmp.BMP_PEER_TYPE_L3VPN
        else:
            peer_type = bmp.BMP_PEER_TYPE_GLOBAL

        peer_distinguisher = 0
        peer_as = peer._neigh_conf.remote_as
        peer_bgp_id = peer.protocol.recv_open_msg.bgp_identifier
        timestamp = peer.state._established_time

        local_address = peer.host_bind_ip
        local_port = int(peer.host_bind_port)
        peer_address, remote_port = peer.protocol._remotename
        remote_port = int(remote_port)

        sent_open_msg = peer.protocol.sent_open_msg
        recv_open_msg = peer.protocol.recv_open_msg

        msg = bmp.BMPPeerUpNotification(local_address=local_address,
                                        local_port=local_port,
                                        remote_port=remote_port,
                                        sent_open_message=sent_open_msg,
                                        received_open_message=recv_open_msg,
                                        peer_type=peer_type,
                                        is_post_policy=False,
                                        peer_distinguisher=peer_distinguisher,
                                        peer_address=peer_address,
                                        peer_as=peer_as,
                                        peer_bgp_id=peer_bgp_id,
                                        timestamp=timestamp)

        return msg

    def _construct_peer_down_notification(self, peer):
        if peer.is_mpbgp_cap_valid(bgp.RF_IPv4_VPN) or \
                peer.is_mpbgp_cap_valid(bgp.RF_IPv6_VPN):
            peer_type = bmp.BMP_PEER_TYPE_L3VPN
        else:
            peer_type = bmp.BMP_PEER_TYPE_GLOBAL

        peer_as = peer._neigh_conf.remote_as
        peer_bgp_id = peer.protocol.recv_open_msg.bgp_identifier
        peer_address, _ = peer.protocol._remotename

        return bmp.BMPPeerDownNotification(bmp.BMP_PEER_DOWN_REASON_UNKNOWN,
                                           data=None,
                                           peer_type=peer_type,
                                           is_post_policy=False,
                                           peer_distinguisher=0,
                                           peer_address=peer_address,
                                           peer_as=peer_as,
                                           peer_bgp_id=peer_bgp_id,
                                           timestamp=0)

    def _construct_update(self, path):
        # Get copy of path's path attributes.
        new_pathattr = [attr for attr in path.pathattr_map.values()]

        if path.is_withdraw:
            if isinstance(path, Ipv4Path):
                return BGPUpdate(withdrawn_routes=[path.nlri],
                                 path_attributes=new_pathattr)
            else:
                mpunreach_attr = BGPPathAttributeMpUnreachNLRI(
                    path.route_family.afi, path.route_family.safi, [path.nlri]
                )
                new_pathattr.append(mpunreach_attr)
        else:
            if isinstance(path, Ipv4Path):
                return BGPUpdate(nlri=[path.nlri],
                                 path_attributes=new_pathattr)

        return BGPUpdate(path_attributes=new_pathattr)

    def _construct_route_monitoring(self, peer, route):
        if peer.is_mpbgp_cap_valid(bgp.RF_IPv4_VPN) or \
                peer.is_mpbgp_cap_valid(bgp.RF_IPv6_VPN):
            peer_type = bmp.BMP_PEER_TYPE_L3VPN
        else:
            peer_type = bmp.BMP_PEER_TYPE_GLOBAL

        peer_distinguisher = 0
        peer_as = peer._neigh_conf.remote_as
        peer_bgp_id = peer.protocol.recv_open_msg.bgp_identifier
        peer_address, _ = peer.protocol._remotename

        bgp_update = self._construct_update(route.path)
        is_post_policy = not route.filtered
        timestamp = timegm(route.timestamp)

        msg = bmp.BMPRouteMonitoring(bgp_update=bgp_update,
                                     peer_type=peer_type,
                                     is_post_policy=is_post_policy,
                                     peer_distinguisher=peer_distinguisher,
                                     peer_address=peer_address,
                                     peer_as=peer_as, peer_bgp_id=peer_bgp_id,
                                     timestamp=timestamp)

        return msg

    def _handle_bmp_session(self, socket):

        self._socket = socket
        # send init message
        init_info = {'type': bmp.BMP_INIT_TYPE_STRING,
                     'value': u'This is Ryu BGP BMP message'}
        init_msg = bmp.BMPInitiation([init_info])
        self._send(init_msg)

        # send peer-up message for each peers
        peer_manager = self._core_service.peer_manager

        for peer in (p for p in peer_manager.iterpeers if p.in_established()):
            msg = self._construct_peer_up_notification(peer)
            self._send(msg)

            for path in peer._adj_rib_in.values():
                msg = self._construct_route_monitoring(peer, path)
                self._send(msg)

        # TODO periodically send stats to bmpstation

        while True:
            # bmpstation shouldn't send any packet to bmpclient.
            # this recv() is only meant to detect socket closed
            ret = self._socket.recv(1)
            if len(ret) == 0:
                LOG.debug('BMP socket is closed. retry connecting..')
                self._socket = None
                self._connect_retry_event.set()
                break

            # silently ignore packets from the bmpstation
