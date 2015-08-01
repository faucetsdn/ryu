"""
This file define hosts' data structure.
Author:www.muzixing.com
Date                Work
2015/5/29           new this file
2015/7/27           define class host.
"""
from . import data_base
from ryu.lib.ip import ipv4_to_bin
from ryu.lib.ip import ipv4_to_str
from ryu.openexchange.oxproto_v1_0 import OXPP_INACTIVE, OXPP_ACTIVE

IP2HOST = {}
HOSTLIST = []


class Host(data_base.DataBase):
    def __init__(self, ip=None, MAC=None, mask=None, state=OXPP_INACTIVE):
        self.ip = ip
        self.MAC = MAC
        self.mask = mask
        self.state = state

        IP2HOST[self.ip] = self
        HOSTLIST.append(self)


class location(object):
    def __init__(self, locations={}):
        # locations: {domain:[ip1,ip2,...]}
        self.locations = locations

    def update(self, domain, hosts):
        for host in hosts:
            if host.state == OXPP_ACTIVE:
                if host.ip not in self.locations[domain]:
                    IP2HOST.setdefault(host.ip, None)
                    IP2HOST[host.ip] = host

                    self.locations[domain].insert(0, ipv4_to_str(host.ip))
            else:
                if host.ip in self.locations[domain]:
                    self.locations[domain].remove(host.ip)

                    HOSTLIST.remove(IP2HOST[host.ip])
                    del IP2HOST[host.ip]
