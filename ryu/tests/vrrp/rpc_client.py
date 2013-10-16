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
               ./ryu/services/vrrp/rpc_manager.py --vrrp-rpc-port 50004


2. client side

PYTHONPATH=. python ./ryu/tests/vrrp/rpc_client.py --host <server-host> --port <server-port> \
                    --method <method> --vrid <vrid> --priority <priority> --ifname <ifname> --ifipaddr <ipaddr>

  method: config
          config_change
          list

ex.
  PYTHONPATH=. python ./ryu/tests/vrrp/rpc_client.py --host 172.16.10.1 --port 51820 --method config \
                    --vrid 10 --priority 255 --ifname veth1 --ifipaddr 172.16.10.1


  Client wait notification from the server if you specify config method.


"""

import socket
import sys

from ryu.lib import rpc
from ryu.services.vrrp import rpc_manager
from ryu.lib.packet import vrrp
from ryu.lib import hub

from argparse import ArgumentParser

hub.patch()


def vrrp_config(client, args):
    vrid = args.vrid
    virtual_ipaddr = args.vripaddr
    ifname = args.ifname
    nic_ipaddr = args.ifipaddr
    priority = args.priority
    vlan_id = args.ifvlanid

    vrrp_param = rpc_manager.VRRPParam(vrrp.VRRP_VERSION_V3, vrid, virtual_ipaddr)
    vrrp_param.setPort(ifname, nic_ipaddr, priority, vlan_id)
    param_dict = vrrp_param.toDict()
    context = {'contexts': {'resource_id': 'vrrp_resource', 'resource_name': 'vrrp_session'}}
    param_dict.update(context)
    result = client.call("vrrp_config", [param_dict])
    print "api result : ", result


def vrrp_config_change(client, args):
    change_param = {rpc_manager.CONF_KEY_PRIORITY: args.priority,
                    rpc_manager.CONF_KEY_ADVERTISEMENT_INTERVAL: args.interval}
    vrid = args.vrid
    param_dict = {'vrid':vrid}
    param_dict.update(change_param)
    result = client.call("vrrp_config_change", [param_dict])
    print "api result : ", result


def vrrp_list(client, args):
    vrid = args.vrid
    result = client.call("vrrp_list", [vrid])
    for info in result:
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


def main(args):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((args.host, args.port))
    client = rpc.Client(client_sock, notification_callback=notification_callback)

    method = args.method
    print "target method : ", method
    if method == "config":
        vrrp_config(client, args)
        hub.spawn(receive_notification_loop, client)
        while True:
            hub.sleep(0.5)

    elif method == "list":
        vrrp_list(client, args)

    elif method == "config_change":
        vrrp_config_change(client, args)
    else:
        print "target method is nothing."

def _parse_args():
    parser = ArgumentParser()
    parser.add_argument("--method", dest="method", type=str, default="config")
    parser.add_argument("--vrid", dest="vrid", type=int, default=16)
    parser.add_argument("--vripaddr", dest="vripaddr", type=str, default="172.16.10.10")
    parser.add_argument("--ifname", dest="ifname", type=str, default="veth1")
    parser.add_argument("--ifipaddr", dest="ifipaddr", type=str, default="172.16.10.1")
    parser.add_argument("--ifvlanid", dest="ifvlanid", type=int, default=None)
    parser.add_argument("--priority", dest="priority", type=int, default="100")
    parser.add_argument("--interval", dest="interval", type=int, default="1")
    parser.add_argument("--host", dest="host", type=str, default="127.0.0.1")
    parser.add_argument("--port", dest="port", type=int, default="50004")
    return parser.parse_args()


if __name__ == '__main__':
    main(_parse_args())
