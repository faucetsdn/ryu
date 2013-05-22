from ryu.lib import rpc
from ryu.services.vrrp import rpc_manager
from ryu.lib.packet import vrrp
from contextlib import closing


import socket


def main():
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with closing(client_sock):
        client = rpc.Client(client_sock)
        client_sock.connect(("127.0.0.1", 51717))
        vrrp_param = rpc_manager.VRRPParam(vrrp.VRRP_VERSION_V2, 1, "10.0.0.1")
        vrrp_param.appendPort(1, 1, "00:00:00:00:00:01", "10.0.0.101", 150)
        vrrp_param.appendPort(2, 1, "00:00:00:00:00:02", "10.0.0.102", 150)
        result = client.call("vrrp_config", [vrrp_param.toArray()])
        print result


if __name__ == '__main__':
    main()

