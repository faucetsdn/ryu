# Copyright (C) 2014 Xinguard, Inc.
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
Implementation of Bidirectional Forwarding Detection for IPv4 (Single Hop)

This module provides a simple way to let Ryu act like a daemon for running
IPv4 single hop BFD (RFC5881).

Please note that:

* Demand mode and echo function are not yet supported.
* Mechanism on negotiating L2/L3 addresses for an established
  session is not yet implemented.
* The interoperability of authentication support is not tested.
* Configuring a BFD session with too small interval may lead to
  full of event queue and congestion of Openflow channels.
  For deploying a low-latency configuration or with a large number
  of BFD sessions, use standalone BFD daemon instead.
"""


import logging
import time
import random

import six

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import inet
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import bfd
from ryu.lib.packet import arp
from ryu.lib.packet.arp import ARP_REQUEST, ARP_REPLY

LOG = logging.getLogger(__name__)

UINT16_MAX = (1 << 16) - 1
UINT32_MAX = (1 << 32) - 1

# RFC5881 Section 8
BFD_CONTROL_UDP_PORT = 3784
BFD_ECHO_UDP_PORT = 3785


class BFDSession(object):
    """BFD Session class.

    An instance maintains a BFD session.
    """

    def __init__(self, app, my_discr, dpid, ofport,
                 src_mac, src_ip, src_port,
                 dst_mac="FF:FF:FF:FF:FF:FF", dst_ip="255.255.255.255",
                 detect_mult=3,
                 desired_min_tx_interval=1000000,
                 required_min_rx_interval=1000000,
                 auth_type=0, auth_keys=None):
        """
        Initialize a BFD session.

        __init__ takes the corresponding args in this order.

        .. tabularcolumns:: |l|L|

        ========================= ============================================
        Argument                  Description
        ========================= ============================================
        app                       The instance of BFDLib.
        my_discr                  My Discriminator.
        dpid                      Datapath ID of the BFD interface.
        ofport                    Openflow port number of the BFD interface.
        src_mac                   Source MAC address of the BFD interface.
        src_ip                    Source IPv4 address of the BFD interface.
        dst_mac                   (Optional) Destination MAC address of the
                                  BFD interface.
        dst_ip                    (Optional) Destination IPv4 address of the
                                  BFD interface.
        detect_mult               (Optional) Detection time multiplier.
        desired_min_tx_interval   (Optional) Desired Min TX Interval.
                                  (in microseconds)
        required_min_rx_interval  (Optional) Required Min RX Interval.
                                  (in microseconds)
        auth_type                 (Optional) Authentication type.
        auth_keys                 (Optional) A dictionary of authentication
                                  key chain which key is an integer of
                                  *Auth Key ID* and value is a string of
                                  *Password* or *Auth Key*.
        ========================= ============================================

        Example::

            sess = BFDSession(app=self.bfdlib,
                              my_discr=1,
                              dpid=1,
                              ofport=1,
                              src_mac="01:23:45:67:89:AB",
                              src_ip="192.168.1.1",
                              dst_mac="12:34:56:78:9A:BC",
                              dst_ip="192.168.1.2",
                              detect_mult=3,
                              desired_min_tx_interval=1000000,
                              required_min_rx_interval=1000000,
                              auth_type=bfd.BFD_AUTH_KEYED_SHA1,
                              auth_keys={1: "secret key 1",
                                         2: "secret key 2"})
        """
        auth_keys = auth_keys if auth_keys else {}
        assert not (auth_type and len(auth_keys) == 0)

        # RyuApp reference to BFDLib
        self.app = app

        # RFC5880 Section 6.8.1.
        # BFD Internal Variables
        self._session_state = bfd.BFD_STATE_DOWN
        self._remote_session_state = bfd.BFD_STATE_DOWN
        self._local_discr = my_discr
        self._remote_discr = 0
        self._local_diag = 0
        self._desired_min_tx_interval = 1000000
        self._required_min_rx_interval = required_min_rx_interval
        self._remote_min_rx_interval = -1
        # TODO: Demand mode is not yet supported.
        self._demand_mode = 0
        self._remote_demand_mode = 0
        self._detect_mult = detect_mult
        self._auth_type = auth_type
        self._auth_keys = auth_keys

        if self._auth_type in [bfd.BFD_AUTH_KEYED_MD5,
                               bfd.BFD_AUTH_METICULOUS_KEYED_MD5,
                               bfd.BFD_AUTH_KEYED_SHA1,
                               bfd.BFD_AUTH_METICULOUS_KEYED_SHA1]:
            self._rcv_auth_seq = 0
            self._xmit_auth_seq = random.randint(0, UINT32_MAX)
            self._auth_seq_known = 0

        # BFD Runtime Variables
        self._cfg_desired_min_tx_interval = desired_min_tx_interval
        self._cfg_required_min_echo_rx_interval = 0
        self._active_role = True
        self._detect_time = 0
        self._xmit_period = None
        self._update_xmit_period()
        self._is_polling = True
        self._pending_final = False
        # _enable_send indicates the switch of the periodic transmission of
        # BFD Control packets.
        self._enable_send = True
        self._lock = None

        # L2/L3/L4 Header fields
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ipv4_id = random.randint(0, UINT16_MAX)
        self.src_port = src_port
        self.dst_port = BFD_CONTROL_UDP_PORT

        if dst_mac == "FF:FF:FF:FF:FF:FF" or dst_ip == "255.255.255.255":
            self._remote_addr_config = False
        else:
            self._remote_addr_config = True

        # Switch and port associated to this BFD session.
        self.dpid = dpid
        self.datapath = None
        self.ofport = ofport

        # Spawn a periodic transmission loop for BFD Control packets.
        hub.spawn(self._send_loop)

        LOG.info("[BFD][%s][INIT] BFD Session initialized.",
                 hex(self._local_discr))

    @property
    def my_discr(self):
        """
        Returns My Discriminator of the BFD session.
        """
        return self._local_discr

    @property
    def your_discr(self):
        """
        Returns Your Discriminator of the BFD session.
        """
        return self._remote_discr

    def set_remote_addr(self, dst_mac, dst_ip):
        """
        Configure remote ethernet and IP addresses.
        """
        self.dst_mac = dst_mac
        self.dst_ip = dst_ip

        if not (dst_mac == "FF:FF:FF:FF:FF:FF" or dst_ip == "255.255.255.255"):
            self._remote_addr_config = True

        LOG.info("[BFD][%s][REMOTE] Remote address configured: %s, %s.",
                 hex(self._local_discr), self.dst_ip, self.dst_mac)

    def recv(self, bfd_pkt):
        """
        BFD packet receiver.
        """
        LOG.debug("[BFD][%s][RECV] BFD Control received: %s",
                  hex(self._local_discr), six.binary_type(bfd_pkt))
        self._remote_discr = bfd_pkt.my_discr
        self._remote_state = bfd_pkt.state
        self._remote_demand_mode = bfd_pkt.flags & bfd.BFD_FLAG_DEMAND

        if self._remote_min_rx_interval != bfd_pkt.required_min_rx_interval:
            self._remote_min_rx_interval = bfd_pkt.required_min_rx_interval
            # Update transmit interval (RFC5880 Section 6.8.2.)
            self._update_xmit_period()

        # TODO: Echo function (RFC5880 Page 35)

        if bfd_pkt.flags & bfd.BFD_FLAG_FINAL and self._is_polling:
            self._is_polling = False

        # Check and update the session state (RFC5880 Page 35)
        if self._session_state == bfd.BFD_STATE_ADMIN_DOWN:
            return

        if bfd_pkt.state == bfd.BFD_STATE_ADMIN_DOWN:
            if self._session_state != bfd.BFD_STATE_DOWN:
                self._set_state(bfd.BFD_STATE_DOWN,
                                bfd.BFD_DIAG_NEIG_SIG_SESS_DOWN)
        else:
            if self._session_state == bfd.BFD_STATE_DOWN:
                if bfd_pkt.state == bfd.BFD_STATE_DOWN:
                    self._set_state(bfd.BFD_STATE_INIT)
                elif bfd_pkt.state == bfd.BFD_STATE_INIT:
                    self._set_state(bfd.BFD_STATE_UP)

            elif self._session_state == bfd.BFD_STATE_INIT:
                if bfd_pkt.state in [bfd.BFD_STATE_INIT, bfd.BFD_STATE_UP]:
                    self._set_state(bfd.BFD_STATE_UP)

            else:
                if bfd_pkt.state == bfd.BFD_STATE_DOWN:
                    self._set_state(bfd.BFD_STATE_DOWN,
                                    bfd.BFD_DIAG_NEIG_SIG_SESS_DOWN)

        # TODO: Demand mode support.

        if self._remote_demand_mode and \
                self._session_state == bfd.BFD_STATE_UP and \
                self._remote_session_state == bfd.BFD_STATE_UP:
            self._enable_send = False

        if not self._remote_demand_mode or \
                self._session_state != bfd.BFD_STATE_UP or \
                self._remote_session_state != bfd.BFD_STATE_UP:
            if not self._enable_send:
                self._enable_send = True
                hub.spawn(self._send_loop)

        # Update the detection time (RFC5880 Section 6.8.4.)
        if self._detect_time == 0:
            self._detect_time = bfd_pkt.desired_min_tx_interval * \
                bfd_pkt.detect_mult / 1000000.0
            # Start the timeout loop.
            hub.spawn(self._recv_timeout_loop)

        if bfd_pkt.flags & bfd.BFD_FLAG_POLL:
            self._pending_final = True
            self._detect_time = bfd_pkt.desired_min_tx_interval * \
                bfd_pkt.detect_mult / 1000000.0

        # Update the remote authentication sequence number.
        if self._auth_type in [bfd.BFD_AUTH_KEYED_MD5,
                               bfd.BFD_AUTH_METICULOUS_KEYED_MD5,
                               bfd.BFD_AUTH_KEYED_SHA1,
                               bfd.BFD_AUTH_METICULOUS_KEYED_SHA1]:
            self._rcv_auth_seq = bfd_pkt.auth_cls.seq
            self._auth_seq_known = 1

        # Set the lock.
        if self._lock is not None:
            self._lock.set()

    def _set_state(self, new_state, diag=None):
        """
        Set the state of the BFD session.
        """
        old_state = self._session_state

        LOG.info("[BFD][%s][STATE] State changed from %s to %s.",
                 hex(self._local_discr),
                 bfd.BFD_STATE_NAME[old_state],
                 bfd.BFD_STATE_NAME[new_state])
        self._session_state = new_state

        if new_state == bfd.BFD_STATE_DOWN:
            if diag is not None:
                self._local_diag = diag
            self._desired_min_tx_interval = 1000000
            self._is_polling = True
            self._update_xmit_period()
        elif new_state == bfd.BFD_STATE_UP:
            self._desired_min_tx_interval = self._cfg_desired_min_tx_interval
            self._is_polling = True
            self._update_xmit_period()

        self.app.send_event_to_observers(
            EventBFDSessionStateChanged(self, old_state, new_state))

    def _recv_timeout_loop(self):
        """
        A loop to check timeout of receiving remote BFD packet.
        """
        while self._detect_time:
            last_wait = time.time()
            self._lock = hub.Event()

            self._lock.wait(timeout=self._detect_time)

            if self._lock.is_set():
                # Authentication variable check (RFC5880 Section 6.8.1.)
                if getattr(self, "_auth_seq_known", 0):
                    if last_wait > time.time() + 2 * self._detect_time:
                        self._auth_seq_known = 0

            else:
                # Check Detection Time expiration (RFC5880 section 6.8.4.)
                LOG.info("[BFD][%s][RECV] BFD Session timed out.",
                         hex(self._local_discr))
                if self._session_state not in [bfd.BFD_STATE_DOWN,
                                               bfd.BFD_STATE_ADMIN_DOWN]:
                    self._set_state(bfd.BFD_STATE_DOWN,
                                    bfd.BFD_DIAG_CTRL_DETECT_TIME_EXPIRED)

                # Authentication variable check (RFC5880 Section 6.8.1.)
                if getattr(self, "_auth_seq_known", 0):
                    self._auth_seq_known = 0

    def _update_xmit_period(self):
        """
        Update transmission period of the BFD session.
        """
        # RFC5880 Section 6.8.7.
        if self._desired_min_tx_interval > self._remote_min_rx_interval:
            xmit_period = self._desired_min_tx_interval
        else:
            xmit_period = self._remote_min_rx_interval

        # This updates the transmission period of BFD Control packets.
        # (RFC5880 Section 6.8.2 & 6.8.3.)
        if self._detect_mult == 1:
            xmit_period *= random.randint(75, 90) / 100.0
        else:
            xmit_period *= random.randint(75, 100) / 100.0

        self._xmit_period = xmit_period / 1000000.0
        LOG.info("[BFD][%s][XMIT] Transmission period changed to %f",
                 hex(self._local_discr), self._xmit_period)

    def _send_loop(self):
        """
        A loop to proceed periodic BFD packet transmission.
        """
        while self._enable_send:
            hub.sleep(self._xmit_period)

            # Send BFD packet. (RFC5880 Section 6.8.7.)

            if self._remote_discr == 0 and not self._active_role:
                continue

            if self._remote_min_rx_interval == 0:
                continue

            if self._remote_demand_mode and \
                    self._session_state == bfd.BFD_STATE_UP and \
                    self._remote_session_state == bfd.BFD_STATE_UP and \
                    not self._is_polling:
                continue

            self._send()

    def _send(self):
        """
        BFD packet sender.
        """
        # If the switch was not connected to controller, exit.
        if self.datapath is None:
            return

        # BFD Flags Setup
        flags = 0

        if self._pending_final:
            flags |= bfd.BFD_FLAG_FINAL
            self._pending_final = False
            self._is_polling = False

        if self._is_polling:
            flags |= bfd.BFD_FLAG_POLL

        # Authentication Section
        auth_cls = None
        if self._auth_type:
            auth_key_id = list(self._auth_keys.keys())[
                random.randint(0, len(list(self._auth_keys.keys())) - 1)]
            auth_key = self._auth_keys[auth_key_id]

            if self._auth_type == bfd.BFD_AUTH_SIMPLE_PASS:
                auth_cls = bfd.SimplePassword(auth_key_id=auth_key_id,
                                              password=auth_key)

            if self._auth_type in [bfd.BFD_AUTH_KEYED_MD5,
                                   bfd.BFD_AUTH_METICULOUS_KEYED_MD5,
                                   bfd.BFD_AUTH_KEYED_SHA1,
                                   bfd.BFD_AUTH_METICULOUS_KEYED_SHA1]:
                if self._auth_type in [bfd.BFD_AUTH_KEYED_MD5,
                                       bfd.BFD_AUTH_KEYED_SHA1]:
                    if random.randint(0, 1):
                        self._xmit_auth_seq = \
                            (self._xmit_auth_seq + 1) & UINT32_MAX
                else:
                    self._xmit_auth_seq = \
                        (self._xmit_auth_seq + 1) & UINT32_MAX

                auth_cls = bfd.bfd._auth_parsers[self._auth_type](
                    auth_key_id=auth_key_id,
                    seq=self._xmit_auth_seq,
                    auth_key=auth_key)

        if auth_cls is not None:
            flags |= bfd.BFD_FLAG_AUTH_PRESENT

        if self._demand_mode and \
                self._session_state == bfd.BFD_STATE_UP and \
                self._remote_session_state == bfd.BFD_STATE_UP:
            flags |= bfd.BFD_FLAG_DEMAND

        diag = self._local_diag
        state = self._session_state
        detect_mult = self._detect_mult
        my_discr = self._local_discr
        your_discr = self._remote_discr
        desired_min_tx_interval = self._desired_min_tx_interval
        required_min_rx_interval = self._required_min_rx_interval
        required_min_echo_rx_interval = self._cfg_required_min_echo_rx_interval

        # Prepare for Ethernet/IP/UDP header fields
        src_mac = self.src_mac
        dst_mac = self.dst_mac
        src_ip = self.src_ip
        dst_ip = self.dst_ip
        self.ipv4_id = (self.ipv4_id + 1) & UINT16_MAX
        ipv4_id = self.ipv4_id
        src_port = self.src_port
        dst_port = self.dst_port

        # Construct BFD Control packet
        data = BFDPacket.bfd_packet(
            src_mac=src_mac, dst_mac=dst_mac,
            src_ip=src_ip, dst_ip=dst_ip, ipv4_id=ipv4_id,
            src_port=src_port, dst_port=dst_port,
            diag=diag, state=state, flags=flags, detect_mult=detect_mult,
            my_discr=my_discr, your_discr=your_discr,
            desired_min_tx_interval=desired_min_tx_interval,
            required_min_rx_interval=required_min_rx_interval,
            required_min_echo_rx_interval=required_min_echo_rx_interval,
            auth_cls=auth_cls)

        # Prepare for a datapath
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(self.ofport)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)

        datapath.send_msg(out)
        LOG.debug("[BFD][%s][SEND] BFD Control sent.", hex(self._local_discr))


class BFDPacket(object):
    """
    BFDPacket class for parsing raw BFD packet, and generating BFD packet with
    Ethernet, IPv4, and UDP headers.
    """

    class BFDUnknownFormat(RyuException):
        message = '%(msg)s'

    @staticmethod
    def bfd_packet(src_mac, dst_mac, src_ip, dst_ip, ipv4_id,
                   src_port, dst_port,
                   diag=0, state=0, flags=0, detect_mult=0,
                   my_discr=0, your_discr=0, desired_min_tx_interval=0,
                   required_min_rx_interval=0,
                   required_min_echo_rx_interval=0,
                   auth_cls=None):
        """
        Generate BFD packet with Ethernet/IPv4/UDP encapsulated.
        """
        # Generate ethernet header first.
        pkt = packet.Packet()
        eth_pkt = ethernet.ethernet(dst_mac, src_mac, ETH_TYPE_IP)
        pkt.add_protocol(eth_pkt)

        # IPv4 encapsulation
        # set ToS to 192 (Network control/CS6)
        # set TTL to 255 (RFC5881 Section 5.)
        ipv4_pkt = ipv4.ipv4(proto=inet.IPPROTO_UDP, src=src_ip, dst=dst_ip,
                             tos=192, identification=ipv4_id, ttl=255)
        pkt.add_protocol(ipv4_pkt)

        # UDP encapsulation
        udp_pkt = udp.udp(src_port=src_port, dst_port=dst_port)
        pkt.add_protocol(udp_pkt)

        # BFD payload
        bfd_pkt = bfd.bfd(
            ver=1, diag=diag, state=state, flags=flags,
            detect_mult=detect_mult,
            my_discr=my_discr, your_discr=your_discr,
            desired_min_tx_interval=desired_min_tx_interval,
            required_min_rx_interval=required_min_rx_interval,
            required_min_echo_rx_interval=required_min_echo_rx_interval,
            auth_cls=auth_cls)
        pkt.add_protocol(bfd_pkt)

        pkt.serialize()
        return pkt.data

    @staticmethod
    def bfd_parse(data):
        """
        Parse raw packet and return BFD class from packet library.
        """
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = next(i)

        assert isinstance(eth_pkt, ethernet.ethernet)

        ipv4_pkt = next(i)
        assert isinstance(ipv4_pkt, ipv4.ipv4)

        udp_pkt = next(i)
        assert isinstance(udp_pkt, udp.udp)

        udp_payload = next(i)

        return bfd.bfd.parser(udp_payload)[0]


class ARPPacket(object):
    """
    ARPPacket class for parsing raw ARP packet, and generating ARP packet with
    Ethernet header.
    """

    class ARPUnknownFormat(RyuException):
        message = '%(msg)s'

    @staticmethod
    def arp_packet(opcode, src_mac, src_ip, dst_mac, dst_ip):
        """
        Generate ARP packet with ethernet encapsulated.
        """
        # Generate ethernet header first.
        pkt = packet.Packet()
        eth_pkt = ethernet.ethernet(dst_mac, src_mac, ETH_TYPE_ARP)
        pkt.add_protocol(eth_pkt)

        # Use IPv4 ARP wrapper from packet library directly.
        arp_pkt = arp.arp_ip(opcode, src_mac, src_ip, dst_mac, dst_ip)
        pkt.add_protocol(arp_pkt)

        pkt.serialize()
        return pkt.data

    @staticmethod
    def arp_parse(data):
        """
        Parse ARP packet, return ARP class from packet library.
        """
        # Iteratize pkt
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = next(i)
        # Ensure it's an ethernet frame.
        assert isinstance(eth_pkt, ethernet.ethernet)

        arp_pkt = next(i)
        if not isinstance(arp_pkt, arp.arp):
            raise ARPPacket.ARPUnknownFormat()

        if arp_pkt.opcode not in (ARP_REQUEST, ARP_REPLY):
            raise ARPPacket.ARPUnknownFormat(
                msg='unsupported opcode %d' % arp_pkt.opcode)

        if arp_pkt.proto != ETH_TYPE_IP:
            raise ARPPacket.ARPUnknownFormat(
                msg='unsupported arp ethtype 0x%04x' % arp_pkt.proto)

        return arp_pkt


class EventBFDSessionStateChanged(event.EventBase):
    """
    An event class that notifies the state change of a BFD session.
    """

    def __init__(self, session, old_state, new_state):
        super(EventBFDSessionStateChanged, self).__init__()
        self.session = session
        self.old_state = old_state
        self.new_state = new_state


class BFDLib(app_manager.RyuApp):
    """
    BFD daemon library.

    Add this library as a context in your app and use ``add_bfd_session``
    function to establish a BFD session.

    Example::

        from ryu.base import app_manager
        from ryu.controller.handler import set_ev_cls
        from ryu.ofproto import ofproto_v1_3
        from ryu.lib import bfdlib
        from ryu.lib.packet import bfd

        class Foo(app_manager.RyuApp):
            OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

            _CONTEXTS = {
                'bfdlib': bfdlib.BFDLib
            }

            def __init__(self, *args, **kwargs):
                super(Foo, self).__init__(*args, **kwargs)
                self.bfdlib = kwargs['bfdlib']
                self.my_discr = \
                    self.bfdlib.add_bfd_session(dpid=1,
                                                ofport=1,
                                                src_mac="00:23:45:67:89:AB",
                                                src_ip="192.168.1.1")

            @set_ev_cls(bfdlib.EventBFDSessionStateChanged)
            def bfd_state_handler(self, ev):
                if ev.session.my_discr != self.my_discr:
                    return

                if ev.new_state == bfd.BFD_STATE_DOWN:
                    print "BFD Session=%d is DOWN!" % ev.session.my_discr
                elif ev.new_state == bfd.BFD_STATE_UP:
                    print "BFD Session=%d is UP!" % ev.session.my_discr
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _EVENTS = [EventBFDSessionStateChanged]

    def __init__(self, *args, **kwargs):
        super(BFDLib, self).__init__(*args, **kwargs)

        # BFD Session Dictionary
        # key: My Discriminator
        # value: BFDSession object
        self.session = {}

    def close(self):
        pass

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Update datapath object in BFD sessions
        for s in self.session.values():
            if s.dpid == datapath.id:
                s.datapath = datapath

        # Install default flows for capturing ARP & BFD packets.
        match = parser.OFPMatch(eth_type=ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0xFFFF, match, actions)

        match = parser.OFPMatch(eth_type=ETH_TYPE_IP,
                                ip_proto=inet.IPPROTO_UDP,
                                udp_dst=3784)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0xFFFF, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Packet-In Handler, only for BFD packets.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        # If there's someone asked for an IP address associated
        # with a BFD session, generate an ARP reply for it.
        if arp.arp in pkt:
            arp_pkt = ARPPacket.arp_parse(msg.data)
            if arp_pkt.opcode == ARP_REQUEST:
                for s in self.session.values():
                    if s.dpid == datapath.id and \
                            s.ofport == in_port and \
                            s.src_ip == arp_pkt.dst_ip:

                        ans = ARPPacket.arp_packet(
                            ARP_REPLY,
                            s.src_mac, s.src_ip,
                            arp_pkt.src_mac, arp_pkt.src_ip)

                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(
                            datapath=datapath,
                            buffer_id=ofproto.OFP_NO_BUFFER,
                            in_port=ofproto.OFPP_CONTROLLER,
                            actions=actions, data=ans)

                        datapath.send_msg(out)
                        return
            return

        # Check whether it's BFD packet or not.
        if ipv4.ipv4 not in pkt or udp.udp not in pkt:
            return

        udp_hdr = pkt.get_protocols(udp.udp)[0]
        if udp_hdr.dst_port != BFD_CONTROL_UDP_PORT:
            return

        # Parse BFD packet here.
        self.recv_bfd_pkt(datapath, in_port, msg.data)

    def add_bfd_session(self, dpid, ofport, src_mac, src_ip,
                        dst_mac="FF:FF:FF:FF:FF:FF", dst_ip="255.255.255.255",
                        auth_type=0, auth_keys=None):
        """
        Establish a new BFD session and return My Discriminator of new session.

        Configure the BFD session with the following arguments.

        ================ ======================================================
        Argument         Description
        ================ ======================================================
        dpid             Datapath ID of the BFD interface.
        ofport           Openflow port number of the BFD interface.
        src_mac          Source MAC address of the BFD interface.
        src_ip           Source IPv4 address of the BFD interface.
        dst_mac          (Optional) Destination MAC address of the BFD
                         interface.
        dst_ip           (Optional) Destination IPv4 address of the BFD
                         interface.
        auth_type        (Optional) Authentication type.
        auth_keys        (Optional) A dictionary of authentication key chain
                         which key is an integer of *Auth Key ID* and value
                         is a string of *Password* or *Auth Key*.
        ================ ======================================================

        Example::

            add_bfd_session(dpid=1,
                            ofport=1,
                            src_mac="01:23:45:67:89:AB",
                            src_ip="192.168.1.1",
                            dst_mac="12:34:56:78:9A:BC",
                            dst_ip="192.168.1.2",
                            auth_type=bfd.BFD_AUTH_KEYED_SHA1,
                            auth_keys={1: "secret key 1",
                                       2: "secret key 2"})
        """
        auth_keys = auth_keys if auth_keys else {}
        # Generate a unique discriminator
        while True:
            # Generate My Discriminator
            my_discr = random.randint(1, UINT32_MAX)

            # Generate an UDP destination port according to RFC5881 Section 4.
            src_port = random.randint(49152, 65535)

            # Ensure generated discriminator and UDP port are unique.
            if my_discr in self.session:
                continue

            unique_flag = True

            for s in self.session.values():
                if s.your_discr == my_discr or s.src_port == src_port:
                    unique_flag = False
                    break

            if unique_flag:
                break

        sess = BFDSession(app=self, my_discr=my_discr,
                          dpid=dpid, ofport=ofport,
                          src_mac=src_mac, src_ip=src_ip, src_port=src_port,
                          dst_mac=dst_mac, dst_ip=dst_ip,
                          auth_type=auth_type, auth_keys=auth_keys)

        self.session[my_discr] = sess

        return my_discr

    def recv_bfd_pkt(self, datapath, in_port, data):
        pkt = packet.Packet(data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype != ETH_TYPE_IP:
            return

        ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]

        # Discard it if TTL != 255 for single hop bfd. (RFC5881 Section 5.)
        if ip_pkt.ttl != 255:
            return

        # Parse BFD packet here.
        bfd_pkt = BFDPacket.bfd_parse(data)

        if not isinstance(bfd_pkt, bfd.bfd):
            return

        # BFD sanity checks
        # RFC 5880 Section 6.8.6.
        if bfd_pkt.ver != 1:
            return

        if bfd_pkt.flags & bfd.BFD_FLAG_AUTH_PRESENT:
            if bfd_pkt.length < 26:
                return
        else:
            if bfd_pkt.length < 24:
                return

        if bfd_pkt.detect_mult == 0:
            return

        if bfd_pkt.flags & bfd.BFD_FLAG_MULTIPOINT:
            return

        if bfd_pkt.my_discr == 0:
            return

        if bfd_pkt.your_discr != 0 and bfd_pkt.your_discr not in self.session:
            return

        if bfd_pkt.your_discr == 0 and \
                bfd_pkt.state not in [bfd.BFD_STATE_ADMIN_DOWN,
                                      bfd.BFD_STATE_DOWN]:
            return

        sess_my_discr = None

        if bfd_pkt.your_discr == 0:
            # Select session (Page 34)
            for s in self.session.values():
                if s.dpid == datapath.id and s.ofport == in_port:
                    sess_my_discr = s.my_discr
                    break

            # BFD Session not found.
            if sess_my_discr is None:
                return
        else:
            sess_my_discr = bfd_pkt.your_discr

        sess = self.session[sess_my_discr]

        if bfd_pkt.flags & bfd.BFD_FLAG_AUTH_PRESENT and sess._auth_type == 0:
            return

        if bfd_pkt.flags & bfd.BFD_FLAG_AUTH_PRESENT == 0 and \
                sess._auth_type != 0:
            return

        # Authenticate the session (Section 6.7.)
        if bfd_pkt.flags & bfd.BFD_FLAG_AUTH_PRESENT:
            if sess._auth_type == 0:
                return

            if bfd_pkt.auth_cls.auth_type != sess._auth_type:
                return

            # Check authentication sequence number to defend replay attack.
            if sess._auth_type in [bfd.BFD_AUTH_KEYED_MD5,
                                   bfd.BFD_AUTH_METICULOUS_KEYED_MD5,
                                   bfd.BFD_AUTH_KEYED_SHA1,
                                   bfd.BFD_AUTH_METICULOUS_KEYED_SHA1]:
                if sess._auth_seq_known:
                    if bfd_pkt.auth_cls.seq < sess._rcv_auth_seq:
                        return

                    if sess._auth_type in [bfd.BFD_AUTH_METICULOUS_KEYED_MD5,
                                           bfd.BFD_AUTH_METICULOUS_KEYED_SHA1]:
                        if bfd_pkt.auth_cls.seq <= sess._rcv_auth_seq:
                            return

                    if bfd_pkt.auth_cls.seq > sess._rcv_auth_seq \
                            + 3 * sess._detect_mult:
                        return

            if not bfd_pkt.authenticate(sess._auth_keys):
                LOG.debug("[BFD][%s][AUTH] BFD Control authentication failed.",
                          hex(sess._local_discr))
                return

        # Sanity check passed, proceed.
        if sess is not None:
            # Check whether L2/L3 addresses were configured or not.
            # TODO: L2/L3 addresses negotiation for an established session.
            if not sess._remote_addr_config:
                sess.set_remote_addr(eth.src, ip_pkt.src)
            # Proceed to session update.
            sess.recv(bfd_pkt)
