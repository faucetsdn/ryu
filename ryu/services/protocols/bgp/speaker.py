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
 BGP protocol implementation.
"""
import logging
import socket
import struct
import traceback
from socket import IPPROTO_TCP, TCP_NODELAY
from eventlet import semaphore

from ryu.lib.packet import bgp
from ryu.lib.packet.bgp import BGPMessage
from ryu.lib.packet.bgp import BGPOpen
from ryu.lib.packet.bgp import BGPUpdate
from ryu.lib.packet.bgp import BGPKeepAlive
from ryu.lib.packet.bgp import BGPNotification
from ryu.lib.packet.bgp import BGP_MSG_OPEN
from ryu.lib.packet.bgp import BGP_MSG_UPDATE
from ryu.lib.packet.bgp import BGP_MSG_KEEPALIVE
from ryu.lib.packet.bgp import BGP_MSG_NOTIFICATION
from ryu.lib.packet.bgp import BGP_MSG_ROUTE_REFRESH
from ryu.lib.packet.bgp import BGP_CAP_ENHANCED_ROUTE_REFRESH
from ryu.lib.packet.bgp import BGP_CAP_MULTIPROTOCOL
from ryu.lib.packet.bgp import BGP_ERROR_HOLD_TIMER_EXPIRED
from ryu.lib.packet.bgp import BGP_ERROR_SUB_HOLD_TIMER_EXPIRED
from ryu.lib.packet.bgp import get_rf

from ryu.services.protocols.bgp.base import Activity
from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.base import CORE_ERROR_CODE
from ryu.services.protocols.bgp.constants import BGP_FSM_CONNECT
from ryu.services.protocols.bgp.constants import BGP_FSM_OPEN_CONFIRM
from ryu.services.protocols.bgp.constants import BGP_FSM_OPEN_SENT
from ryu.services.protocols.bgp.constants import BGP_VERSION_NUM
from ryu.services.protocols.bgp.protocol import Protocol
from ryu.services.protocols.bgp.utils.validation import is_valid_old_asn

LOG = logging.getLogger('bgpspeaker.speaker')

# BGP min. and max. message lengths as per RFC.
BGP_MIN_MSG_LEN = 19
BGP_MAX_MSG_LEN = 4096

# Keep-alive singleton.
_KEEP_ALIVE = BGPKeepAlive()


@add_bgp_error_metadata(code=CORE_ERROR_CODE, sub_code=2,
                        def_desc='Unknown error occurred related to Speaker.')
class BgpProtocolException(BGPSException):
    """Base exception related to peer connection management.
    """
    pass


def nofitication_factory(code, subcode):
    """Returns a `Notification` message corresponding to given codes.

    Parameters:
    - `code`: (int) BGP error code
    - `subcode`: (int) BGP error sub-code
    """
    notification = BGPNotification(code, subcode)
    if not notification.reason:
        raise ValueError('Invalid code/sub-code.')

    return notification


class BgpProtocol(Protocol, Activity):
    """Protocol that handles BGP messages.
    """
    MESSAGE_MARKER = (b'\xff\xff\xff\xff\xff\xff\xff\xff'
                      b'\xff\xff\xff\xff\xff\xff\xff\xff')

    def __init__(self, socket, signal_bus, is_reactive_conn=False):
        # Validate input.
        if socket is None:
            raise ValueError('Invalid arguments passed.')
        self._remotename = self.get_remotename(socket)
        self._localname = self.get_localname(socket)
        activity_name = ('BgpProtocol %s, %s, %s' % (is_reactive_conn,
                                                     self._remotename,
                                                     self._localname))
        Activity.__init__(self, name=activity_name)
        # Intialize instance variables.
        self._peer = None
        self._recv_buff = ''
        self._socket = socket
        self._socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self._sendlock = semaphore.Semaphore()
        self._signal_bus = signal_bus
        self._holdtime = None
        self._keepalive = None
        self._expiry = None
        # Add socket to Activity's socket container for managing it.
        if is_reactive_conn:
            self._asso_socket_map['passive_conn'] = self._socket
        else:
            self._asso_socket_map['active_conn'] = self._socket
        self._open_msg = None
        self.state = BGP_FSM_CONNECT
        self._is_reactive = is_reactive_conn
        self.sent_open_msg = None
        self.recv_open_msg = None
        self._is_bound = False

    @property
    def is_reactive(self):
        return self._is_reactive

    @property
    def holdtime(self):
        return self._holdtime

    @property
    def keepalive(self):
        return self._keepalive

    def is_colliding(self, other_protocol):
        if not isinstance(other_protocol, BgpProtocol):
            raise ValueError('Currently only support comparing with '
                             '`BgpProtocol`')

        # Compare protocol connection end point's addresses
        if (self._remotename[0] == other_protocol._remotename[0] and
                self._localname[0] == other_protocol._localname[0]):
            return True

        return False

    def is_local_router_id_greater(self):
        """Compares *True* if local router id is greater when compared to peer
        bgp id.

        Should only be called after protocol has reached OpenConfirm state.
        """
        from ryu.services.protocols.bgp.utils.bgp import from_inet_ptoi

        if not self.state == BGP_FSM_OPEN_CONFIRM:
            raise BgpProtocolException(desc='Can access remote router id only'
                                            ' after open message is received')
        remote_id = self.recv_open_msg.bgp_identifier
        local_id = self.sent_open_msg.bgp_identifier
        return from_inet_ptoi(local_id) > from_inet_ptoi(remote_id)

    def is_enhanced_rr_cap_valid(self):
        """Checks is enhanced route refresh capability is enabled/valid.

        Checks sent and received `Open` messages to see if this session with
        peer is capable of enhanced route refresh capability.
        """
        if not self.recv_open_msg:
            raise ValueError('Did not yet receive peers open message.')

        err_cap_enabled = False
        local_caps = self.sent_open_msg.opt_param
        peer_caps = self.recv_open_msg.opt_param

        local_cap = [cap for cap in local_caps
                     if cap.cap_code == BGP_CAP_ENHANCED_ROUTE_REFRESH]
        peer_cap = [cap for cap in peer_caps
                    if cap.cap_code == BGP_CAP_ENHANCED_ROUTE_REFRESH]

        # Both local and peer should advertise ERR capability for it to be
        # enabled.
        if local_cap and peer_cap:
            err_cap_enabled = True

        return err_cap_enabled

    def _check_route_fmly_adv(self, open_msg, route_family):
        match_found = False

        local_caps = open_msg.opt_param
        for cap in local_caps:
            # Check MP_BGP capability was advertised.
            if cap.cap_code == BGP_CAP_MULTIPROTOCOL:
                # Iterate over all advertised mp_bgp caps to find a match.
                if (route_family.afi == cap.afi and
                        route_family.safi == cap.safi):
                    match_found = True

        return match_found

    def is_route_family_adv(self, route_family):
        """Checks if `route_family` was advertised to peer as per MP_BGP cap.

        Returns:
            - True: if given address family was advertised.
            - False: if given address family was not advertised.
        """
        return self._check_route_fmly_adv(self.sent_open_msg, route_family)

    def is_route_family_adv_recv(self, route_family):
        """Checks if `route_family` was advertised by peer as per MP_BGP cap.

        Returns:
            - True: if given address family was advertised.
            - False: if given address family was not advertised.
        """
        return self._check_route_fmly_adv(self.recv_open_msg, route_family)

    @property
    def negotiated_afs(self):
        local_caps = self.sent_open_msg.opt_param
        remote_caps = self.recv_open_msg.opt_param

        local_mbgp_cap = [cap for cap in local_caps
                          if cap.cap_code == BGP_CAP_MULTIPROTOCOL]
        remote_mbgp_cap = [cap for cap in remote_caps
                           if cap.cap_code == BGP_CAP_MULTIPROTOCOL]

        # Check MP_BGP capabilities were advertised.
        if local_mbgp_cap and remote_mbgp_cap:
            local_families = set([
                (peer_cap.afi, peer_cap.safi)
                for peer_cap in local_mbgp_cap
            ])
            remote_families = set([
                (peer_cap.afi, peer_cap.safi)
                for peer_cap in remote_mbgp_cap
            ])
            afi_safi = local_families.intersection(remote_families)
        else:
            afi_safi = set()

        afs = []
        for afi, safi in afi_safi:
            afs.append(get_rf(afi, safi))
        return afs

    def is_mbgp_cap_valid(self, route_family):
        """Returns true if both sides of this protocol have advertise
        capability for this address family.
        """
        return (self.is_route_family_adv(route_family) and
                self.is_route_family_adv_recv(route_family))

    def _run(self, peer):
        """Sends open message to peer and handles received messages.

        Parameters:
            - `peer`: the peer to which this protocol instance is connected to.
        """
        # We know the peer we are connected to, we send open message.
        self._peer = peer
        self.connection_made()

        # We wait for peer to send messages.
        self._recv_loop()

    def data_received(self, next_bytes):
        try:
            self._data_received(next_bytes)
        except bgp.BgpExc as exc:
            LOG.error(
                "BGPExc Exception while receiving data: "
                "%s \n Traceback %s \n"
                % (str(exc), traceback.format_exc())
            )
            if exc.SEND_ERROR:
                self.send_notification(exc.CODE, exc.SUB_CODE)
            else:
                self._socket.close()
            raise exc

    @staticmethod
    def parse_msg_header(buff):
        """Parses given `buff` into bgp message header format.

        Returns a tuple of marker, length, type of bgp message.
        """
        return struct.unpack('!16sHB', buff)

    def _data_received(self, next_bytes):
        """Maintains buffer of bytes received from peer and extracts bgp
        message from this buffer if enough data is received.

        Validates bgp message marker, length, type and data and constructs
        appropriate bgp message instance and calls handler.

        :Parameters:
            - `next_bytes`: next set of bytes received from peer.
        """
        # Append buffer with received bytes.
        self._recv_buff += next_bytes

        while True:
            # If current buffer size is less then minimum bgp message size, we
            # return as we do not have a complete bgp message to work with.
            if len(self._recv_buff) < BGP_MIN_MSG_LEN:
                return

            # Parse message header into elements.
            auth, length, ptype = BgpProtocol.parse_msg_header(
                self._recv_buff[:BGP_MIN_MSG_LEN])

            # Check if we have valid bgp message marker.
            # We should get default marker since we are not supporting any
            # authentication.
            if (auth != BgpProtocol.MESSAGE_MARKER):
                LOG.error('Invalid message marker received: %s', auth)
                raise bgp.NotSync()

            # Check if we have valid bgp message length.
            check = (length < BGP_MIN_MSG_LEN or length > BGP_MAX_MSG_LEN)

            # RFC says: The minimum length of the OPEN message is 29
            # octets (including the message header).
            check2 = (ptype == BGP_MSG_OPEN and length < BGPOpen._MIN_LEN)

            # RFC says: A KEEPALIVE message consists of only the
            # message header and has a length of 19 octets.
            check3 = (ptype == BGP_MSG_KEEPALIVE and
                      length != BGPKeepAlive._MIN_LEN)

            # RFC says: The minimum length of the UPDATE message is 23
            # octets.
            check4 = (ptype == BGP_MSG_UPDATE and
                      length < BGPUpdate._MIN_LEN)

            if any((check, check2, check3, check4)):
                raise bgp.BadLen(ptype, length)

            # If we have partial message we wait for rest of the message.
            if len(self._recv_buff) < length:
                return
            msg, rest = BGPMessage.parser(self._recv_buff)
            self._recv_buff = rest

            # If we have a valid bgp message we call message handler.
            self._handle_msg(msg)

    def send_notification(self, code, subcode):
        """Utility to send notification message.

        Closes the socket after sending the message.
        :Parameters:
            - `socket`: (socket) - socket over which to send notification
             message.
            - `code`: (int) - BGP Notification code
            - `subcode`: (int) - BGP Notification sub-code

        RFC ref: http://tools.ietf.org/html/rfc4486
        http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
        """
        notification = BGPNotification(code, subcode)
        reason = notification.reason
        self._send_with_lock(notification)
        self._signal_bus.bgp_error(self._peer, code, subcode, reason)
        if len(self._localname):
            LOG.error('Sent notification to %r >> %s', self._localname,
                      notification)
        self._socket.close()

    def _send_with_lock(self, msg):
        self._sendlock.acquire()
        try:
            self._socket.sendall(msg.serialize())
        except socket.error:
            self.connection_lost('failed to write to socket')
        finally:
            self._sendlock.release()

    def send(self, msg):
        if not self.started:
            raise BgpProtocolException('Tried to send message to peer when '
                                       'this protocol instance is not started'
                                       ' or is no longer is started state.')
        self._send_with_lock(msg)

        if msg.type == BGP_MSG_NOTIFICATION:
            LOG.error('Sent notification to %s >> %s', self._remotename, msg)

            self._signal_bus.bgp_notification_sent(self._peer, msg)
        else:
            LOG.debug('Sent msg to %s >> %s', self._remotename, msg)

    def stop(self):
        Activity.stop(self)

    def _validate_open_msg(self, open_msg):
        """Validates BGP OPEN message according from application context.

        Parsing modules takes care of validating OPEN message that need no
        context. But here we validate it according to current application
        settings. RTC or RR/ERR are MUST capability if peer does not support
        either one of them we have to end session.
        """
        assert open_msg.type == BGP_MSG_OPEN
        # Validate remote ASN.
        remote_asnum = open_msg.my_as
        # Since 4byte AS is not yet supported, we validate AS as old style AS.
        if (not is_valid_old_asn(remote_asnum) or
                remote_asnum != self._peer.remote_as):
            raise bgp.BadPeerAs()

        # Validate bgp version number.
        if open_msg.version != BGP_VERSION_NUM:
            raise bgp.UnsupportedVersion(BGP_VERSION_NUM)

    def _handle_msg(self, msg):
        """When a BGP message is received, send it to peer.

        Open messages are validated here. Peer handler is called to handle each
        message except for *Open* and *Notification* message. On receiving
        *Notification* message we close connection with peer.
        """
        LOG.debug('Received msg from %s << %s', self._remotename, msg)

        # If we receive open message we try to bind to protocol
        if (msg.type == BGP_MSG_OPEN):
            if self.state == BGP_FSM_OPEN_SENT:
                # Validate open message.
                self._validate_open_msg(msg)
                self.recv_open_msg = msg
                self.state = BGP_FSM_OPEN_CONFIRM
                self._peer.state.bgp_state = self.state

                # Try to bind this protocol to peer.
                self._is_bound = self._peer.bind_protocol(self)

                # If this protocol failed to bind to peer.
                if not self._is_bound:
                    # Failure to bind to peer indicates connection collision
                    # resolution choose different instance of protocol and this
                    # instance has to close. Before closing it sends
                    # appropriate notification msg. to peer.
                    raise bgp.CollisionResolution()

                # If peer sends Hold Time as zero, then according to RFC we do
                # not set Hold Time and Keep Alive timer.
                if msg.hold_time == 0:
                    LOG.info('The Hold Time sent by the peer is zero, hence '
                             'not setting any Hold Time and Keep Alive'
                             ' timers.')
                else:
                    # Start Keep Alive timer considering Hold Time preference
                    # of the peer.
                    self._start_timers(msg.hold_time)
                    self._send_keepalive()

                # Peer does not see open message.
                return
            else:
                # If we receive a Open message out of order
                LOG.error('Open message received when current state is not '
                          'OpenSent')
                # Received out-of-order open message
                # We raise Finite state machine error
                raise bgp.FiniteStateMachineError()
        elif msg.type == BGP_MSG_NOTIFICATION:
            if self._peer:
                self._signal_bus.bgp_notification_received(self._peer, msg)
            # If we receive notification message
            LOG.error('Received notification message, hence closing '
                      'connection %s', msg)
            self._socket.close()
            return

        # If we receive keepalive or update message, we reset expire timer.
        if (msg.type == BGP_MSG_KEEPALIVE or
                msg.type == BGP_MSG_UPDATE):
            if self._expiry:
                self._expiry.reset()

        # Call peer message handler for appropriate messages.
        if (msg.type in
                (BGP_MSG_UPDATE, BGP_MSG_KEEPALIVE, BGP_MSG_ROUTE_REFRESH)):
            self._peer.handle_msg(msg)
        # We give chance to other threads to run.
        self.pause(0)

    def _start_timers(self, peer_holdtime):
        """Starts keepalive and expire timers.

        Hold time is set to min. of peer and configured/default hold time.
        Starts keep alive timer and expire timer based on this value.
        """
        neg_timer = min(self._holdtime, peer_holdtime)
        if neg_timer < self._holdtime:
            LOG.info('Negotiated hold time (%s) is lower then '
                     'configured/default (%s).', neg_timer, self._holdtime)
        # We use negotiated timer value.
        self._holdtime = neg_timer
        self._keepalive = self._create_timer('Keepalive Timer',
                                             self._send_keepalive)
        interval = self._holdtime // 3
        self._keepalive.start(interval, now=False)
        # Setup the expire timer.
        self._expiry = self._create_timer('Holdtime Timer', self._expired)
        self._expiry.start(self._holdtime, now=False)
        LOG.debug('Started keep-alive and expire timer for negotiated hold'
                  'time %s', self._holdtime)

    def _expired(self):
        """Hold timer expired event handler.
        """
        LOG.info('Negotiated hold time %s expired.', self._holdtime)
        code = BGP_ERROR_HOLD_TIMER_EXPIRED
        subcode = BGP_ERROR_SUB_HOLD_TIMER_EXPIRED
        self.send_notification(code, subcode)
        self.connection_lost('Negotiated hold time %s expired.' %
                             self._holdtime)
        self.stop()

    def _send_keepalive(self):
        self.send(_KEEP_ALIVE)

    def _recv_loop(self):
        """Sits in tight loop collecting data received from peer and
        processing it.
        """
        required_len = BGP_MIN_MSG_LEN
        conn_lost_reason = "Connection lost as protocol is no longer active"
        try:
            while True:
                next_bytes = self._socket.recv(required_len)
                if len(next_bytes) == 0:
                    conn_lost_reason = 'Peer closed connection'
                    break
                self.data_received(next_bytes)
        except socket.error as err:
            conn_lost_reason = 'Connection to peer lost: %s.' % err
        except bgp.BgpExc as ex:
            conn_lost_reason = 'Connection to peer lost, reason: %s.' % ex
        except Exception as e:
            LOG.debug(traceback.format_exc())
            conn_lost_reason = str(e)
        finally:
            self.connection_lost(conn_lost_reason)

    def connection_made(self):
        """Connection to peer handler.

        We send bgp open message to peer and intialize related attributes.
        """
        assert self.state == BGP_FSM_CONNECT
        # We have a connection with peer we send open message.
        open_msg = self._peer.create_open_msg()
        self._holdtime = open_msg.hold_time
        self.state = BGP_FSM_OPEN_SENT
        if not self.is_reactive:
            self._peer.state.bgp_state = self.state
        self.sent_open_msg = open_msg
        self.send(open_msg)
        self._peer.connection_made()

    def connection_lost(self, reason):
        """Stops all timers and notifies peer that connection is lost.
        """

        if self._peer:
            state = self._peer.state.bgp_state
            if self._is_bound or state == BGP_FSM_OPEN_SENT:
                self._peer.connection_lost(reason)

            self._peer = None

        if reason:
            LOG.info(reason)
        else:
            LOG.info('Connection to peer closed for unknown reasons.')
