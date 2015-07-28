"""
This file define hosts' data structure.
Author:www.muzixing.com
Date                Work
2015/5/29           new this file
2015/7/27           define class host.
"""
from . import data_base
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
    def __init__(self, location={}):
        # location: {domain:[ip1,ip2,...]}
        self.location = location

    def update(self, domain, hosts):
        for host in hosts:
            if host.state == OXPP_ACTIVE:
                if host.ip not in self.location[domain]:
                    IP2HOST.setdefault(host.ip, None)
                    IP2HOST[host.ip] = host

                    self.location[domain].insert(0, host.ip)
            else:
                # state =OXPP_INACTIVE
                if host.ip in self.location[domain]:
                    self.location[domain].remove(host.ip)

                    HOSTLIST.remove(IP2HOST[host.ip])
                    del IP2HOST[host.ip]
