# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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
VRRP state machine implementation

VRRPManager creates/deletes VRRPRounter instances dynamically.
"""

import abc
import six

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import handler
from ryu.lib import hub
from ryu.lib.packet import vrrp
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import api as vrrp_api


# TODO: improve Timer service and move it into framework
class Timer(object):
    def __init__(self, handler_):
        assert callable(handler_)

        super(Timer, self).__init__()
        self._handler = handler_
        self._event = hub.Event()
        self._thread = None

    def start(self, interval):
        """interval is in seconds"""
        if self._thread:
            self.cancel()
        self._event.clear()
        self._thread = hub.spawn(self._timer, interval)

    def cancel(self):
        if self._thread is None:
            return
        self._event.set()
        hub.joinall([self._thread])
        self._thread = None

    def is_running(self):
        return self._thread is not None

    def _timer(self, interval):
        # Avoid cancellation during execution of self._callable()
        cancel = self._event.wait(interval)
        if cancel:
            return

        self._handler()


class TimerEventSender(Timer):
    # timeout handler is called by timer thread context.
    # So in order to actual execution context to application's event thread,
    # post the event to the application
    def __init__(self, app, ev_cls):
        super(TimerEventSender, self).__init__(self._timeout)
        self._app = app
        self._ev_cls = ev_cls

    def _timeout(self):
        self._app.send_event(self._app.name, self._ev_cls())


class VRRPParams(object):
    def __init__(self, config):
        self.config = config
        self.master_adver_interval = None       # In seconds

    @property
    def skew_time(self):
        # In seconds
        config = self.config
        version = config.version
        priority = config.priority
        if config.version == vrrp.VRRP_VERSION_V2:
            return (256.0 - priority) / 256.0
        if config.version == vrrp.VRRP_VERSION_V3:
            return (((256.0 - priority) * self.master_adver_interval) / 256.0)
        raise ValueError('unknown vrrp version %d' % version)

    @property
    def master_down_interval(self):
        # In seconds
        return (3.0 * self.master_adver_interval) + self.skew_time


@six.add_metaclass(abc.ABCMeta)
class VRRPState(object):
    def __init__(self, vrrp_router):
        super(VRRPState, self).__init__()
        self.vrrp_router = vrrp_router

    @abc.abstractmethod
    def master_down(self, ev):
        pass

    @abc.abstractmethod
    def adver(self, ev):
        pass

    @abc.abstractmethod
    def preempt_delay(self, ev):
        pass

    @abc.abstractmethod
    def vrrp_received(self, ev):
        pass

    @abc.abstractmethod
    def vrrp_shutdown_request(self, ev):
        pass

    @abc.abstractmethod
    def vrrp_config_change_request(self, ev):
        pass


class VRRPRouter(app_manager.RyuApp):
    _EVENTS = [vrrp_event.EventVRRPStateChanged]
    _CONSTRUCTORS = {}
    _STATE_MAP = {}     # should be overrided by concrete class

    @staticmethod
    def register(version):
        def _register(cls):
            VRRPRouter._CONSTRUCTORS[version] = cls
            return cls
        return _register

    @staticmethod
    def factory(name, monitor_name, interface, config, statistics, *args,
                **kwargs):
        cls = VRRPRouter._CONSTRUCTORS[config.version]
        app_mgr = app_manager.AppManager.get_instance()
        kwargs = kwargs.copy()
        kwargs['name'] = name
        kwargs['monitor_name'] = monitor_name
        kwargs['vrrp_interface'] = interface
        kwargs['vrrp_config'] = config
        kwargs['vrrp_statistics'] = statistics
        return app_mgr.instantiate(cls, *args, **kwargs)

    class _EventMasterDown(event.EventBase):
        pass

    class _EventAdver(event.EventBase):
        pass

    class _EventPreemptDelay(event.EventBase):
        pass

    class _EventStatisticsOut(event.EventBase):
        pass

    def __init__(self, *args, **kwargs):
        super(VRRPRouter, self).__init__(*args, **kwargs)
        self.name = kwargs['name']
        self.monitor_name = kwargs['monitor_name']
        self.interface = kwargs['vrrp_interface']
        self.config = kwargs['vrrp_config']
        self.statistics = kwargs['vrrp_statistics']
        self.params = VRRPParams(self.config)
        self.state = None
        self.state_impl = None
        self.vrrp = None

        self.master_down_timer = TimerEventSender(self, self._EventMasterDown)
        self.adver_timer = TimerEventSender(self, self._EventAdver)
        self.preempt_delay_timer = TimerEventSender(self,
                                                    self._EventPreemptDelay)
        self.register_observer(self._EventMasterDown, self.name)
        self.register_observer(self._EventAdver, self.name)

        self.stats_out_timer = TimerEventSender(self,
                                                self._EventStatisticsOut)
        self.register_observer(self._EventStatisticsOut, self.name)

    def send_advertisement(self, release=False):
        if self.vrrp is None:
            config = self.config
            max_adver_int = vrrp.vrrp.sec_to_max_adver_int(
                config.version, config.advertisement_interval)
            self.vrrp = vrrp.vrrp.create_version(
                config.version, vrrp.VRRP_TYPE_ADVERTISEMENT, config.vrid,
                config.priority, max_adver_int, config.ip_addresses)

        vrrp_ = self.vrrp
        if release:
            vrrp_ = vrrp_.create(vrrp_.type, vrrp_.vrid,
                                 vrrp.VRRP_PRIORITY_RELEASE_RESPONSIBILITY,
                                 vrrp_.max_adver_int, vrrp_.ip_addresses)

        if self.vrrp.priority == 0:
            self.statistics.tx_vrrp_zero_prio_packets += 1
        # create packet frame each time to generate new ip identity
        interface = self.interface
        packet_ = vrrp_.create_packet(interface.primary_ip_address,
                                      interface.vlan_id)
        packet_.serialize()
        vrrp_api.vrrp_transmit(self, self.monitor_name, packet_.data)
        self.statistics.tx_vrrp_packets += 1

    def state_change(self, new_state):
        old_state = self.state
        self.state = new_state
        self.state_impl = self._STATE_MAP[new_state](self)
        state_changed = vrrp_event.EventVRRPStateChanged(
            self.name, self.monitor_name, self.interface, self.config,
            old_state, new_state)
        self.send_event_to_observers(state_changed)

    @handler.set_ev_handler(_EventMasterDown)
    def master_down_handler(self, ev):
        self.state_impl.master_down(ev)

    @handler.set_ev_handler(_EventAdver)
    def adver_handler(self, ev):
        self.state_impl.adver(ev)

    @handler.set_ev_handler(_EventPreemptDelay)
    def preempt_delay_handler(self, ev):
        self.state_impl.preempt_delay(ev)

    @handler.set_ev_handler(vrrp_event.EventVRRPReceived)
    def vrrp_received_handler(self, ev):
        self.state_impl.vrrp_received(ev)

    @handler.set_ev_handler(vrrp_event.EventVRRPShutdownRequest)
    def vrrp_shutdown_request_handler(self, ev):
        assert ev.instance_name == self.name
        self.state_impl.vrrp_shutdown_request(ev)

    @handler.set_ev_handler(vrrp_event.EventVRRPConfigChangeRequest)
    def vrrp_config_change_request_handler(self, ev):
        config = self.config
        if ev.priority is not None:
            config.priority = ev.priority
        if ev.advertisement_interval is not None:
            config.advertisement_interval = ev.advertisement_interval
        if ev.preempt_mode is not None:
            config.preempt_mode = ev.preempt_mode
        if ev.preempt_delay is not None:
            config.preempt_delay = ev.preempt_delay
        if ev.accept_mode is not None:
            config.accept_mode = ev.accept_mode

        # force to recreate cached vrrp packet
        self.vrrp = None

        self.state_impl.vrrp_config_change_request(ev)

    @handler.set_ev_handler(_EventStatisticsOut)
    def statistics_handler(self, ev):
        # sends stats to somewhere here
        # print self.statistics.get_stats()
        self.stats_out_timer.start(self.statistics.statistics_interval)

# RFC defines that start timer, then change the state.
# This causes the race between state change and event dispatching.
# So our implementation does, state change, then start timer


class VRRPV2StateInitialize(VRRPState):
    # In theory this shouldn't be called.
    def master_down(self, ev):
        self.vrrp_router.logger.warn('%s master_down', self.__class__.__name__)

    def adver(self, ev):
        self.vrrp_router.logger.warn('%s adver', self.__class__.__name__)

    def preempt_delay(self, ev):
        self.vrrp_router.logger.warn('%s preempt_delay',
                                     self.__class__.__name__)

    def vrrp_received(self, ev):
        self.vrrp_router.logger.warn('%s vrrp_received',
                                     self.__class__.__name__)

    def vrrp_shutdown_request(self, ev):
        self.vrrp_router.logger.warn('%s vrrp_shutdown_request',
                                     self.__class__.__name__)

    def vrrp_config_change_request(self, ev):
        self.vrrp_router.logger.warn('%s vrrp_config_change_request',
                                     self.__class__.__name__)


class VRRPV2StateMaster(VRRPState):
    def master_down(self, ev):
        # should not reach here.
        # In fact this can be happned due to event scheduling
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s master_down %s %s',
                                 self.__class__.__name__,
                                 ev.__class__.__name__, vrrp_router.state)

    def _adver(self):
        vrrp_router = self.vrrp_router
        vrrp_router.send_advertisement()
        vrrp_router.adver_timer.start(
            vrrp_router.config.advertisement_interval)

    def adver(self, ev):
        self.vrrp_router.logger.debug('%s adver', self.__class__.__name__)
        self._adver()

    def preempt_delay(self, ev):
        self.vrrp_router.logger.warn('%s preempt_delay',
                                     self.__class__.__name__)

    def vrrp_received(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_received', self.__class__.__name__)

        ip, vrrp_ = vrrp.vrrp.get_payload(ev.packet)
        config = vrrp_router.config
        if vrrp_.priority == 0:
            vrrp_router.send_advertisement()
            vrrp_router.adver_timer.start(config.advertisement_interval)
        else:
            params = vrrp_router.params
            if (config.priority < vrrp_.priority or
                (config.priority == vrrp_.priority and
                 vrrp.ip_address_lt(vrrp_router.interface.primary_ip_address,
                                    ip.src))):
                vrrp_router.adver_timer.cancel()

                vrrp_router.state_change(vrrp_event.VRRP_STATE_BACKUP)
                vrrp_router.master_down_timer.start(
                    params.master_down_interval)

    def vrrp_shutdown_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_shutdown_request',
                                 self.__class__.__name__)

        vrrp_router.adver_timer.cancel()
        vrrp_router.send_advertisement(True)
        vrrp_router.state_change(vrrp_event.VRRP_STATE_INITIALIZE)

    def vrrp_config_change_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.warn('%s vrrp_config_change_request',
                                self.__class__.__name__)
        if ev.priority is not None or ev.advertisement_interval is not None:
            vrrp_router.adver_timer.cancel()
            self._adver()


class VRRPV2StateBackup(VRRPState):
    def _master_down(self):
        vrrp_router = self.vrrp_router
        vrrp_router.send_advertisement()

        # This action should be done router on
        # EventVRRPStateChanged(VRRP_STATE_BACKUP->VRRP_STATE_MASTER)
        #
        # RFC3768 6.4.2 Backup
        # o  Broadcast a gratuitous ARP request containing the virtual
        #    router MAC address for each IP address associated with the
        #    virtual router

        # RACE: actual router has the responsiblity to send garp.
        #       so due to thread scheduling there is a race between
        #       actual router sending GARP and VRRPRouter becoming
        #       master/backup

        vrrp_router.preempt_delay_timer.cancel()
        vrrp_router.state_change(vrrp_event.VRRP_STATE_MASTER)
        vrrp_router.adver_timer.start(
            vrrp_router.config.advertisement_interval)

    def master_down(self, ev):
        self.vrrp_router.logger.debug('%s master_down',
                                      self.__class__.__name__)
        self._master_down()

    def adver(self, ev):
        # should not reach here
        # In fact this can be happned due to event scheduling
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s adver %s %s',
                                 self.__class__.__name__,
                                 ev.__class__.__name__, vrrp_router.state)

    def preempt_delay(self, ev):
        self.vrrp_router.logger.warn('%s preempt_delay',
                                     self.__class__.__name__)
        self._master_down()

    def vrrp_received(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_received', self.__class__.__name__)

        _ip, vrrp_ = vrrp.vrrp.get_payload(ev.packet)
        if vrrp_.priority == 0:
            vrrp_router.master_down_timer.start(vrrp_router.params.skew_time)
        else:
            config = vrrp_router.config
            params = vrrp_router.params
            if (not config.preempt_mode or config.priority <= vrrp_.priority):
                vrrp_router.preempt_delay_timer.cancel()
                vrrp_router.master_down_timer.start(
                    params.master_down_interval)
            elif (config.preempt_mode and config.preempt_delay > 0 and
                  config.priority > vrrp_.priority):
                if not vrrp_router.preempt_delay_timer.is_running():
                    vrrp_router.preempt_delay_timer.start(config.preempt_delay)
                vrrp_router.master_down_timer.start(
                    params.master_down_interval)

    def vrrp_shutdown_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_shutdown_request',
                                 self.__class__.__name__)

        vrrp_router.master_down_timer.cancel()
        vrrp_router.preempt_delay_timer.cancel()
        vrrp_router.state_change(vrrp_event.VRRP_STATE_INITIALIZE)

    def vrrp_config_change_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.warn('%s vrrp_config_change_request',
                                self.__class__.__name__)
        if ev.priority is not None and vrrp_router.config.address_owner:
            vrrp_router.master_down_timer.cancel()
            self._master_down()
        if ev.preempt_mode is not None or ev.preempt_delay is not None:
            vrrp_router.preempt_delay_timer.cancel()


@VRRPRouter.register(vrrp.VRRP_VERSION_V2)
class VRRPRouterV2(VRRPRouter):
    _STATE_MAP = {
        vrrp_event.VRRP_STATE_INITIALIZE: VRRPV2StateInitialize,
        vrrp_event.VRRP_STATE_MASTER: VRRPV2StateMaster,
        vrrp_event.VRRP_STATE_BACKUP: VRRPV2StateBackup,
    }

    def __init__(self, *args, **kwargs):
        super(VRRPRouterV2, self).__init__(*args, **kwargs)

    def start(self):
        params = self.params
        params.master_adver_interval = self.config.advertisement_interval
        self.state_change(vrrp_event.VRRP_STATE_INITIALIZE)
        if self.config.address_owner:
            self.send_advertisement()

            # This action should be done router on
            # EventVRRPStateChanged(None->VRRP_STATE_MASTER)
            #
            # RFC3768 6.4.1
            # o  Broadcast a gratuitous ARP request containing the virtual
            # router MAC address for each IP address associated with the
            # virtual router.

            self.state_change(vrrp_event.VRRP_STATE_MASTER)
            self.adver_timer.start(self.config.advertisement_interval)
        else:
            self.state_change(vrrp_event.VRRP_STATE_BACKUP)
            self.master_down_timer.start(params.master_down_interval)

        super(VRRPRouterV2, self).start()


class VRRPV3StateInitialize(VRRPState):
    # In theory this shouldn't be called.
    def master_down(self, ev):
        self.vrrp_router.logger.debug('%s master_down',
                                      self.__class__.__name__)

    def adver(self, ev):
        self.vrrp_router.logger.debug('%s adver', self.__class__.__name__)

    def preempt_delay(self, ev):
        self.vrrp_router.logger.warn('%s preempt_delay',
                                     self.__class__.__name__)

    def vrrp_received(self, ev):
        self.vrrp_router.logger.debug('%s vrrp_received',
                                      self.__class__.__name__)

    def vrrp_shutdown_request(self, ev):
        self.vrrp_router.logger.debug('%s vrrp_shutdown_request',
                                      self.__class__.__name__)

    def vrrp_config_change_request(self, ev):
        self.vrrp_router.logger.warn('%s vrrp_config_change_request',
                                     self.__class__.__name__)


class VRRPV3StateMaster(VRRPState):
    def master_down(self, ev):
        # should not reach here
        # In fact this can be happned due to event scheduling
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s master_down %s %s',
                                 self.__class__.__name__,
                                 ev.__class__.__name__, vrrp_router.state)

    def _adver(self):
        vrrp_router = self.vrrp_router
        vrrp_router.send_advertisement()
        vrrp_router.adver_timer.start(
            vrrp_router.config.advertisement_interval)

    def adver(self, ev):
        self.vrrp_router.logger.debug('%s adver', self.__class__.__name__)
        self._adver()

    def preempt_delay(self, ev):
        self.vrrp_router.logger.warn('%s preempt_delay',
                                     self.__class__.__name__)

    def vrrp_received(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_received', self.__class__.__name__)

        ip, vrrp_ = vrrp.vrrp.get_payload(ev.packet)
        config = vrrp_router.config
        if vrrp_.priority == 0:
            vrrp_router.send_advertisement()
            vrrp_router.adver_timer.start(config.advertisement_interval)
        else:
            params = vrrp_router.params
            if (config.priority < vrrp_.priority or
                (config.priority == vrrp_.priority and
                 vrrp.ip_address_lt(vrrp_router.interface.primary_ip_address,
                                    ip.src))):
                vrrp_router.adver_timer.cancel()
                params.master_adver_interval = vrrp_.max_adver_int_in_sec

                vrrp_router.state_change(vrrp_event.VRRP_STATE_BACKUP)
                vrrp_router.master_down_timer.start(
                    params.master_down_interval)

    def vrrp_shutdown_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_shutdown_request',
                                 self.__class__.__name__)

        vrrp_router.adver_timer.cancel()
        vrrp_router.send_advertisement(True)
        vrrp_router.state_change(vrrp_event.VRRP_STATE_INITIALIZE)

    def vrrp_config_change_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.warn('%s vrrp_config_change_request',
                                self.__class__.__name__)
        if ev.priority is not None or ev.advertisement_interval is not None:
            vrrp_router.adver_timer.cancel()
            self._adver()


class VRRPV3StateBackup(VRRPState):
    def _master_down(self):
        vrrp_router = self.vrrp_router
        vrrp_router.send_advertisement()

        # This action should be done by router on
        # EventStateChange(VRRP_SATE_BACKUP -> VRRP_STATE_MASTER)
        #
        # RFC 5795 6.4.2
        # (375) + If the protected IPvX address is an IPv4 address, then:
        #   (380) * Broadcast a gratuitous ARP request on that interface
        #   containing the virtual router MAC address for each IPv4
        #   address associated with the virtual router.
        # (385) + else // ipv6
        #   (390) * Compute and join the Solicited-Node multicast
        #   address [RFC4291] for the IPv6 address(es) associated with
        #   the virtual router.
        #   (395) * For each IPv6 address associated with the virtual
        #   router, send an unsolicited ND Neighbor Advertisement with
        #   the Router Flag (R) set, the Solicited Flag (S) unset, the
        #   Override flag (O) set, the target address set to the IPv6
        #   address of the virtual router, and the target link-layer
        #   address set to the virtual router MAC address.

        # RACE: actual router has the responsiblity to send garp.
        #       so due to thread scheduling there is a race between
        #       actual router sending GARP and VRRPRouter becoming
        #       master/backup

        vrrp_router.preempt_delay_timer.cancel()
        vrrp_router.state_change(vrrp_event.VRRP_STATE_MASTER)
        vrrp_router.adver_timer.start(
            vrrp_router.config.advertisement_interval)

    def master_down(self, ev):
        self.vrrp_router.logger.debug('%s master_down',
                                      self.__class__.__name__)
        self._master_down()

    def adver(self, ev):
        # should not reach here
        # In fact this can be happned due to event scheduling
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('adver %s %s %s',
                                 self.__class__.__name__,
                                 ev.__class__.__name__, vrrp_router.state)

    def preempt_delay(self, ev):
        self.vrrp_router.logger.warn('%s preempt_delay',
                                     self.__class__.__name__)
        self._master_down()

    def vrrp_received(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_received', self.__class__.__name__)

        _ip, vrrp_ = vrrp.vrrp.get_payload(ev.packet)
        if vrrp_.priority == 0:
            vrrp_router.master_down_timer.start(vrrp_router.params.skew_time)
        else:
            params = vrrp_router.params
            config = vrrp_router.config
            if (not config.preempt_mode or config.priority <= vrrp_.priority):
                params.master_adver_interval = vrrp_.max_adver_int_in_sec
                vrrp_router.master_down_timer.start(
                    params.master_down_interval)
            elif (config.preempt_mode and config.preempt_delay > 0 and
                  config.priority > vrrp_.priority):
                if not vrrp_router.preempt_delay_timer.is_running():
                    vrrp_router.preempt_delay_timer.start(config.preempt_delay)
                vrrp_router.master_down_timer.start(
                    params.master_down_interval)

    def vrrp_shutdown_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.debug('%s vrrp_shutdown_request',
                                 self.__class__.__name__)

        vrrp_router.preempt_delay_timer.cancel()
        vrrp_router.master_down_timer.cancel()
        vrrp_router.state_change(vrrp_event.VRRP_STATE_INITIALIZE)

    def vrrp_config_change_request(self, ev):
        vrrp_router = self.vrrp_router
        vrrp_router.logger.warn('%s vrrp_config_change_request',
                                self.__class__.__name__)
        if ev.priority is not None and vrrp_router.config.address_owner:
            vrrp_router.master_down_timer.cancel()
            self._master_down()
        if ev.preempt_mode is not None or ev.preempt_delay is not None:
            vrrp_router.preempt_delay_timer.cancel()


@VRRPRouter.register(vrrp.VRRP_VERSION_V3)
class VRRPRouterV3(VRRPRouter):
    _STATE_MAP = {
        vrrp_event.VRRP_STATE_INITIALIZE: VRRPV3StateInitialize,
        vrrp_event.VRRP_STATE_MASTER: VRRPV3StateMaster,
        vrrp_event.VRRP_STATE_BACKUP: VRRPV3StateBackup,
    }

    def __init__(self, *args, **kwargs):
        super(VRRPRouterV3, self).__init__(*args, **kwargs)

    def start(self):
        self.state_change(vrrp_event.VRRP_STATE_INITIALIZE)
        # Check role here and change accordingly
        # Check config.admin_state
        if self.config.address_owner or self.config.admin_state == 'master':
            self.send_advertisement()

            # This action should be done router on
            # EventVRRPStateChanged(None->VRRP_STATE_MASTER)
            #
            # RFC 5795 6.4.1
            # (115) + If the protected IPvX address is an IPv4 address, then:
            #   (120) * Broadcast a gratuitous ARP request containing the
            #   virtual router MAC address for each IP address associated
            #   with the virtual router.
            # (125) + else // IPv6
            #   (130) * For each IPv6 address associated with the virtual
            #   router, send an unsolicited ND Neighbor Advertisement with
            #   the Router Flag (R) set, the Solicited Flag (S) unset, the
            #   Override flag (O) set, the target address set to the IPv6
            #   address of the virtual router, and the target link-layer
            #   address set to the virtual router MAC address.

            self.state_change(vrrp_event.VRRP_STATE_MASTER)
            self.adver_timer.start(self.config.advertisement_interval)
        else:
            params = self.params
            params.master_adver_interval = self.config.advertisement_interval
            self.state_change(vrrp_event.VRRP_STATE_BACKUP)
            self.master_down_timer.start(params.master_down_interval)

        self.stats_out_timer.start(self.statistics.statistics_interval)
        super(VRRPRouterV3, self).start()
