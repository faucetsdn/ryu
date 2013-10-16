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
CONF_KEY_ADMIN_STATE = "admin_state"
CONF_KEY_PRIORITY = "priority"
CONF_KEY_ADVERTISEMENT_INTERVAL = "advertisement_interval"
CONF_KEY_PORT_IFNAME = "ifname"
CONF_KEY_PORT_IP_ADDR = "ip_address"
CONF_KEY_PORT_VLAN_ID = "vlan_id"
CONF_KEY_PORT_PREEMPT_MODE = "preempt_mode"
CONF_KEY_PORT_PREEMPT_DELAY = "preempt_delay"
CONF_KEY_STATISTICS_LOG_ENABLED = "statistics_log_enabled"
CONF_KEY_STATISTICS_INTERVAL = "statistics_interval"
CONF_KEY_VRID = 'vrid'
CONF_KEY_VRRP_VERSION = 'version'
CONF_KEY_IP_ADDR = 'ip_addr'

CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.IntOpt('vrrp-rpc-port', default=VRRP_RPC_PORT,
               help='port for vrrp rpc interface'),
    cfg.StrOpt('stats-file', default='/tmp/vrrp-stats.log',
    help='name of the file that statistics is written to')])


class VRRPParam(object):
    def __init__(self, version, vrid, ip_address, admin_state=None, advertisement_interval=1, preempt_mode=True, preempt_delay=0):
        self.version = version
        self.vrid = vrid
        self.ip_address = ip_address
        self.admin_state = admin_state
        self.advertisement_interval = advertisement_interval
        self.preempt_mode = preempt_mode
        self.preempt_delay = preempt_delay

    def setPort(self, ifname, ip_address, priority, vlan_id=None):
        self.port = {
            CONF_KEY_PORT_IP_ADDR: ip_address,
            CONF_KEY_PORT_IFNAME: ifname,
            CONF_KEY_PRIORITY: priority,
            CONF_KEY_PORT_VLAN_ID: vlan_id
        }

    def toDict(self):
        param_dict = {CONF_KEY_VRRP_VERSION: self.version,
                CONF_KEY_VRID: self.vrid,
                CONF_KEY_IP_ADDR: self.ip_address,
                CONF_KEY_ADMIN_STATE: self.admin_state,
                CONF_KEY_ADVERTISEMENT_INTERVAL: self.advertisement_interval,
                CONF_KEY_PORT_PREEMPT_MODE: self.preempt_mode,
                CONF_KEY_PORT_PREEMPT_DELAY: self.preempt_delay
                }
        param_dict.update(self.port)
        return param_dict


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
        param_dict = params[0]

        interface = vrrp_event.VRRPInterfaceNetworkDevice(
            mac.DONTCARE,
            netaddr.IPAddress(param_dict[CONF_KEY_PORT_IP_ADDR]).value,
            param_dict[CONF_KEY_PORT_VLAN_ID],
            param_dict[CONF_KEY_PORT_IFNAME])

        config = vrrp_event.VRRPConfig(
            version=param_dict[CONF_KEY_VRRP_VERSION], vrid=param_dict[CONF_KEY_VRID],
            admin_state=param_dict[CONF_KEY_ADMIN_STATE],
            priority=param_dict[CONF_KEY_PRIORITY],
            ip_addresses=[netaddr.IPAddress(param_dict[CONF_KEY_IP_ADDR]).value],
            advertisement_interval=param_dict[CONF_KEY_ADVERTISEMENT_INTERVAL],
            preempt_mode=param_dict[CONF_KEY_PORT_PREEMPT_MODE],
            preempt_delay=param_dict[CONF_KEY_PORT_PREEMPT_DELAY],
            statistics_interval=param_dict.get(CONF_KEY_STATISTICS_INTERVAL),
            contexts = param_dict.get('contexts')
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
        config_values = params[0]
        vrid = config_values[CONF_KEY_VRID]
        self.logger.info("VRID : %s", vrid)
        instance_name = self._lookup(vrid)

        if instance_name:
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
