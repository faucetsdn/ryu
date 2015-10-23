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

from ryu import cfg
import socket

import netaddr
from ryu.base import app_manager
from ryu.controller import handler
from ryu.services.protocols.vrrp import event as vrrp_event
from ryu.services.protocols.vrrp import api as vrrp_api
from ryu.lib import rpc
from ryu.lib import hub
from ryu.lib import mac

VRRP_RPC_PORT = 50004  # random


class RPCError(Exception):
    pass


class Peer(object):
    def __init__(self, queue):
        super(Peer, self).__init__()
        self.queue = queue

    def _handle_vrrp_request(self, data):
        self.queue.put((self, data))


class RpcVRRPManager(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(RpcVRRPManager, self).__init__(*args, **kwargs)
        self.CONF.register_opts([
            cfg.IntOpt('vrrp-rpc-port', default=VRRP_RPC_PORT,
                       help='port for vrrp rpc interface')])

        self._args = args
        self._kwargs = kwargs
        self._peers = []
        self._rpc_events = hub.Queue(128)
        self.server_thread = hub.spawn(self._peer_accept_thread)
        self.event_thread = hub.spawn(self._rpc_request_loop_thread)

    def _rpc_request_loop_thread(self):
        while True:
            (peer, data) = self._rpc_events.get()
            msgid, target_method, params = data
            error = None
            result = None
            try:
                if target_method == b'vrrp_config':
                    result = self._config(msgid, params)
                elif target_method == b'vrrp_list':
                    result = self._list(msgid, params)
                elif target_method == b'vrrp_config_change':
                    result = self._config_change(msgid, params)
                else:
                    error = 'Unknown method %s' % (target_method)
            except RPCError as e:
                error = str(e)
            peer._endpoint.send_response(msgid, error=error, result=result)

    def _peer_loop_thread(self, peer):
        peer._endpoint.serve()
        # the peer connection is closed
        self._peers.remove(peer)

    def peer_accept_handler(self, new_sock, addr):
        peer = Peer(self._rpc_events)
        table = {
            rpc.MessageType.REQUEST: peer._handle_vrrp_request,
        }
        peer._endpoint = rpc.EndPoint(new_sock, disp_table=table)
        self._peers.append(peer)
        hub.spawn(self._peer_loop_thread, peer)

    def _peer_accept_thread(self):
        server = hub.StreamServer(('', self.CONF.vrrp_rpc_port),
                                  self.peer_accept_handler)
        server.serve_forever()

    def _params_to_dict(self, params, keys):
        d = {}
        for k, v in params.items():
            if k in keys:
                d[k] = v
        return d

    def _config(self, msgid, params):
        self.logger.debug('handle vrrp_config request')
        try:
            param_dict = params[0]
        except:
            raise RPCError('parameters are missing')

        if_params = self._params_to_dict(param_dict,
                                         ('primary_ip_address',
                                          'device_name'))
        # drop vlan support later
        if_params['vlan_id'] = None
        if_params['mac_address'] = mac.DONTCARE_STR
        try:
            interface = vrrp_event.VRRPInterfaceNetworkDevice(**if_params)
        except:
            raise RPCError('parameters are invalid, %s' % (str(param_dict)))

        config_params = self._params_to_dict(param_dict,
                                             ('vrid',  # mandatory
                                              'ip_addresses',  # mandatory
                                              'version',
                                              'admin_state',
                                              'priority',
                                              'advertisement_interval',
                                              'preempt_mode',
                                              'preempt_delay',
                                              'statistics_interval'))
        try:
            ip_addr = config_params.pop('ip_addresses')
            config_params['ip_addresses'] = [ip_addr]
            config = vrrp_event.VRRPConfig(**config_params)
        except:
            raise RPCError('parameters are invalid, %s' % (str(param_dict)))

        config_result = vrrp_api.vrrp_config(self, interface, config)

        api_result = [
            config_result.config.vrid,
            config_result.config.priority,
            str(netaddr.IPAddress(config_result.config.ip_addresses[0]))]
        return api_result

    def _lookup_instance(self, vrid):
        for instance in vrrp_api.vrrp_list(self).instance_list:
            if vrid == instance.config.vrid:
                return instance.instance_name
        return None

    def _config_change(self, msgid, params):
        self.logger.debug('handle vrrp_config_change request')
        try:
            config_values = params[0]
        except:
            raise RPCError('parameters are missing')

        vrid = config_values.get('vrid')
        instance_name = self._lookup_instance(vrid)
        if not instance_name:
            raise RPCError('vrid %d is not found' % (vrid))

        priority = config_values.get('priority')
        interval = config_values.get('advertisement_interval')
        vrrp_api.vrrp_config_change(self, instance_name, priority=priority,
                                    advertisement_interval=interval)
        return {}

    def _list(self, msgid, params):
        self.logger.debug('handle vrrp_list request')
        result = vrrp_api.vrrp_list(self)
        instance_list = result.instance_list
        ret_list = []
        for instance in instance_list:
            c = instance.config
            info_dict = {
                "instance_name": instance.instance_name,
                "vrid": c.vrid,
                "version": c.version,
                "advertisement_interval": c.advertisement_interval,
                "priority": c.priority,
                "virtual_ip_address": str(netaddr.IPAddress(c.ip_addresses[0]))
            }
            ret_list.append(info_dict)
        return ret_list

    @handler.set_ev_cls(vrrp_event.EventVRRPStateChanged)
    def vrrp_state_changed_handler(self, ev):
        self.logger.info('handle EventVRRPStateChanged')
        name = ev.instance_name
        old_state = ev.old_state
        new_state = ev.new_state
        vrid = ev.config.vrid
        self.logger.info('VRID:%s %s: %s -> %s', vrid, name, old_state,
                         new_state)
        params = {'vrid': vrid, 'old_state': old_state, 'new_state': new_state}
        for peer in self._peers:
            peer._endpoint.send_notification("notify_status", [params])
