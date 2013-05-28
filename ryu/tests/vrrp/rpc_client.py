"""

1. server side

# ip link add veth0 type veth peer name veth0-dump
# ip link set veth0 up
# ip link set veth0-dump up

sudo PYTHONPATH=. ./bin/ryu-manager \
             ./ryu/services/vrrp/manager.py \
             ./ryu/services/vrrp/rpc_manager.py --vrrp-rpc-port <server-port>

ex. sudo PYTHONPATH=. ./bin/ryu-manager \
               ./ryu/services/vrrp/manager.py \
               ./ryu/services/vrrp/rpc_manager.py --vrrp-rpc-port 51720


2. client side

PYTHONPATH=. python ./ryu/tests/vrrp/rpc_client.py <server-host> <server-port> <method>

ex.
  PYTHONPATH=. python ./ryu/tests/vrrp/rpc_client.py 127.0.0.1 51720 config

  method: config
          config_change
          list

  Client wait notification from the server if you specify config method.


"""

from ryu.lib import rpc
from ryu.services.vrrp import rpc_manager
from ryu.lib.packet import vrrp
from ryu.lib import hub

import socket
import sys

hub.patch()


def vrrp_config(client):
    vrid = 1
    virtual_ipaddr = "10.0.0.1"
    ifname = "veth0"
    nic_ipaddr = "10.0.0.101"
    priority = 150
    vlan_id = 100

    vrrp_param = rpc_manager.VRRPParam(vrrp.VRRP_VERSION_V3, vrid, virtual_ipaddr)
    vrrp_param.setPort(ifname, nic_ipaddr, priority, vlan_id)
    result = client.call("vrrp_config", [vrrp_param.toArray()])
    print "api result : ", result


def vrrp_config_change(client):
    change_param = {rpc_manager.CONF_KEY_PRIORITY: 199, rpc_manager.CONF_KEY_ADVERTISEMENT_INTERVAL: 3}
    vrid = 1
    result = client.call("vrrp_config_change", [vrid, change_param])
    print "api result : ", result


def vrrp_list(client):
    vrid = 1
    result = client.call("vrrp_list", [vrid])
    info = result[0]
    for key in info:
        print key, " : ", info[key]


def receive_notification_loop(client):
    loop = True
    while loop:
        try:
            hub.sleep(0.5)
            client.receive_notification()
        except Exception as e:
            print e
            loop = False


def notification_callback(msg):
    print msg


def main(host, port, method):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((host, port))
    client = rpc.Client(client_sock, notification_callback=notification_callback)

    print "target method : ", method
    if method == "config":
        vrrp_config(client)
        hub.spawn(receive_notification_loop, client)
        while True:
            hub.sleep(0.5)

    elif method == "list":
        vrrp_list(client)

    elif method == "config_change":
        vrrp_config_change(client)
    else:
        print "target method is nothing."


if __name__ == '__main__':
    host = sys.argv[1]
    port = int(sys.argv[2])
    method = sys.argv[3]
    main(host, port, method)
