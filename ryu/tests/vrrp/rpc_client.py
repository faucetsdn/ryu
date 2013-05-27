from ryu.lib import rpc
from ryu.services.vrrp import rpc_manager
from ryu.lib.packet import vrrp
from contextlib import closing

import socket
import sys


def vrrp_config(client):

    vrrp_param = rpc_manager.VRRPParam(vrrp.VRRP_VERSION_V3, 1, "10.0.0.1")
    vrrp_param.setPort("veth0", 1, "10.0.0.101", 150,100)
    result = client.call("vrrp_config", [vrrp_param.toArray()])
    print result


def vrrp_config_change(client):
    change_param = {rpc_manager.CONF_KEY_PRIORITY: 199, rpc_manager.CONF_KEY_ADVERTISEMENT_INTERVAL: 3}
    vrid = 1
    result = client.call("vrrp_config_change", [vrid, change_param])
    print result


def vrrp_list(client):
    vrid = 1
    result = client.call("vrrp_list", [vrid])
    info = result[0]
    for key in info:
        print key, " : ", info[key]


def main(method):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with closing(client_sock):
        client = rpc.Client(client_sock)
        client_sock.connect(("127.0.0.1", rpc_manager.VRRP_RPC_PORT))
        if method == "config":
            vrrp_config(client)
        elif method == "list":
            vrrp_list(client)
        elif method == "config_change":
            vrrp_config_change(client)
        else:
            print "target method is nothing."


if __name__ == '__main__':
    method = sys.argv[1]
    main(method)

