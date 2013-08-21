from oslo.config import cfg
import socket
import select
from contextlib import closing

import netaddr
from ryu.base import app_manager
from ryu.controller import handler
from ryu.services.vrrp import event as vrrp_event
from ryu.services.vrrp import api as vrrp_api
from ryu.lib import rpc
from ryu.lib import hub
from ryu.lib import mac


VRRP_RPC_PORT = 50004
CONF_KEY_PRIORITY = "priority"
CONF_KEY_ADVERTISEMENT_INTERVAL = "advertisement_interval"
CONF_KEY_PORT_IFNAME = "ifname"
CONF_KEY_PORT_IP_ADDR = "ip_address"
CONF_KEY_PORT_VLAN_ID = "vlan_id"
CONF_KEY_PORT_PREEMPT_MODE = "preempt_mode"
CONF_KEY_PORT_PREEMPT_DELAY = "preempt_delay"

CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.IntOpt('vrrp-rpc-port', default=VRRP_RPC_PORT,
               help='port for vrrp rpc interface')])


class VRRPParam(object):
    def __init__(self, version, vrid, ip_address):
        self.version = version
        self.vrid = vrid
        self.ip_address = ip_address

    def setPort(self, ifname, ip_address, priority, vlan_id=None):
        self.port = {
            CONF_KEY_PORT_IP_ADDR: ip_address,
            CONF_KEY_PORT_IFNAME: ifname,
            CONF_KEY_PRIORITY: priority,
            CONF_KEY_PORT_VLAN_ID: vlan_id
        }

    def toArray(self):
        return [self.version, self.vrid, self.ip_address, self.port]


class RpcVRRPManager(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(RpcVRRPManager, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs
        self.serverThread = hub.spawn(self._startRPCServer)

    def _startRPCServer(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_sock.setblocking(0)
        with closing(server_sock):
            server_sock.bind(("0.0.0.0", CONF.vrrp_rpc_port))
            server_sock.listen(1)
            self.logger.info("RPCServer starting.")

            while True:
                reader, writer, err = select.select([server_sock], [], [])
                if reader[0] == server_sock:
                    conn, address = server_sock.accept()
                    conn.setblocking(0)
                table = {
                    rpc.MessageType.REQUEST: self._handle_vrrp_request,
                    rpc.MessageType.RESPONSE: self._handle_vrrp_response,
                    rpc.MessageType.NOTIFY: self._handle_vrrp_notification
                }

                self._requests = set()
                self._server_endpoint = rpc.EndPoint(conn, disp_table=table)
                self._server_thread = hub.spawn(self._server_endpoint.serve)

    @handler.set_ev_cls(vrrp_event.EventVRRPStateChanged)
    def vrrp_state_changed_handler(self, ev):
        self.logger.info('handle EventVRRPStateChanged')
        name = ev.instance_name
        old_state = ev.old_state
        new_state = ev.new_state
        vrid = ev.config.vrid
        self.logger.info('VRID:%s %s: %s -> %s', vrid, name, old_state, new_state)
        params = {'vrid': vrid, 'old_state': old_state, 'new_state': new_state}
        self._server_endpoint.send_notification("notify_status", [params])

    def _config(self, endpoint, msgid, params):
        self.logger.debug('handle vrrp_config request')
        vrrp_params = params[0]
        print vrrp_params
        port = vrrp_params[3]

        interface = vrrp_event.VRRPInterfaceNetworkDevice(
            mac.DONTCARE,
            netaddr.IPAddress(port[CONF_KEY_PORT_IP_ADDR]).value,
            port[CONF_KEY_PORT_VLAN_ID],
            port[CONF_KEY_PORT_IFNAME])

        config = vrrp_event.VRRPConfig(
            version=vrrp_params[0], vrid=vrrp_params[1],
            priority=port["priority"], 
            ip_addresses=[netaddr.IPAddress(vrrp_params[2]).value],
            advertisement_interval=port[CONF_KEY_ADVERTISEMENT_INTERVAL]
            #preempt_mode=port[CONF_KEY_PORT_PREEMPT_MODE],
            #preempt_delay=port[CONF_KEY_PORT_PREEMPT_DELAY]
            )
        config_result = vrrp_api.vrrp_config(self, interface, config)

        api_result = [config_result.config.vrid,
                      config_result.config.priority,
                      str(netaddr.IPAddress(config_result.config.ip_addresses[0]))]

        endpoint.send_response(msgid, error=None, result=api_result)

    def _lookup(self, vrid):
        result = vrrp_api.vrrp_list(self)
        self.logger.debug("result length : ", len(result.instance_list))
        instance_list = result.instance_list
        instance_name = None
        for instance in instance_list:
            if vrid == instance.config.vrid:
                instance_name = instance.instance_name
                break

        return instance_name

    def _config_change(self, endpoint, msgid, params):
        self.logger.debug('handle vrrp_config_change request')
        vrid = params[0]
        self.logger.info("VRID : %s", vrid)
        instance_name = self._lookup(vrid)

        if instance_name:
            config_values = params[1]
            priority = config_values[CONF_KEY_PRIORITY] if CONF_KEY_PRIORITY in config_values else None
            adv_int = config_values[
                CONF_KEY_ADVERTISEMENT_INTERVAL] if CONF_KEY_ADVERTISEMENT_INTERVAL in config_values else None
            vrrp_api.vrrp_config_change(self, instance_name,
                                        priority=priority,
                                        advertisement_interval=adv_int)
            result = 0
            error = None
        else:
            result = 1
            error = "couldn't find vrid"

        endpoint.send_response(msgid, error=error, result=result)

    def _list(self, endpoint, msgid, params):
        self.logger.debug('handle vrrp_list request')
        vrrp_params = params[0]
        result = vrrp_api.vrrp_list(self)
        self.logger.debug("result length : ", len(result.instance_list))
        instance_list = result.instance_list
        # print dir(instance_list)
        ret_list = []
        for instance in instance_list:
            info_dict = {
                "instance_name": instance.instance_name,
                "vrid": instance.config.vrid,
                "version": instance.config.version,
                "advertisement_interval": instance.config.advertisement_interval,
                "priority": instance.config.priority,
                "virtual_ip_address": str(netaddr.IPAddress(instance.config.ip_addresses[0]))
            }
            ret_list.append(info_dict)
        endpoint.send_response(msgid, error=None, result=ret_list)

    def _handle_vrrp_request(self, method):
        msgid, target_method, params = method
        endpoint = self._server_endpoint
        if target_method == "vrrp_config":
            self._config(endpoint, msgid, params)
        elif target_method == "vrrp_list":
            self._list(endpoint, msgid, params)
        elif target_method == "vrrp_config_change":
            self._config_change(endpoint, msgid, params)

    def _handle_vrrp_response(self, method):
        pass

    def _handle_vrrp_notification(self, method):
        pass
