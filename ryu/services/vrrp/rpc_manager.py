import netaddr

from ryu.base import app_manager
from ryu.controller import handler
from ryu.lib.packet import vrrp
from ryu.services.vrrp import event as vrrp_event
from ryu.services.vrrp import api as vrrp_api
from ryu.topology import event as topo_event
from ryu.lib import rpc
from ryu.lib import hub
from ryu.lib import mac
import socket
from contextlib import closing


class VRRPParam(object):
    def __init__(self, version, vrid, ip_address):
        self.version = version
        self.vrid = vrid
        self.ip_address = ip_address


    def setPort(self, dpid, port_no, hw_addr, ip_address, priority):
        self.port = {
            "hw_addr": hw_addr,
            "ip_address": ip_address,
            "dpid": dpid,
            "port_no": port_no,
            "priority": priority}

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
        with closing(server_sock):
            server_sock.bind(("0.0.0.0", 51717))
            server_sock.listen(1)
            self.logger.info("RPCServer starting.")

            while True:
                conn, address = server_sock.accept()
                self.logger.info('client connected')

                table = {
                    rpc.MessageType.REQUEST: self._handle_vrrp_request,
                    rpc.MessageType.RESPONSE: self._handle_vrrp_response,
                    rpc.MessageType.NOTIFY: self._handle_vrrp_notification
                }
                self._requests = set()
                #server_sock.setblocking(0)
                self._server_endpoint = rpc.EndPoint(conn, disp_table=table)
                self._server_thread = hub.spawn(self._server_endpoint.serve)


    @handler.set_ev_cls(vrrp_event.EventVRRPStateChanged)
    def vrrp_state_changed_handler(self, ev):
        self.logger.info('handle EventVRRPStateChanged')
        name = ev.instance_name
        old_state = ev.old_state
        new_state = ev.new_state
        self.logger.info('%s: %s -> %s', name, old_state, new_state)
        #TODO: notify


    def _config(self, endpoint, msgid, params):
        self.logger.info('handle vrrp_config request')
        vrrp_params = params[0]
        print vrrp_params
        port = vrrp_params[3]
        interface = vrrp_event.VRRPInterfaceOpenFlow(
            mac.haddr_to_bin(port["hw_addr"]),
            netaddr.IPAddress(port["ip_address"]).value, None,
            port["dpid"], port["port_no"])

        config = vrrp_event.VRRPConfig(
            version=vrrp_params[0], vrid=vrrp_params[1],
            priority=port["priority"], ip_addresses=[netaddr.IPAddress(vrrp_params[2]).value])
        vrrp_api.vrrp_config(self, interface, config)
        endpoint.send_response(msgid, error=None, result=0)


    def _handle_vrrp_request(self, method):
        msgid, target_method, params = method
        endpoint = self._server_endpoint
        if target_method == "vrrp_config":
            self._config(endpoint, msgid, params)


    def _handle_vrrp_response(self, method):
        pass

    def _handle_vrrp_notification(self, method):
        pass