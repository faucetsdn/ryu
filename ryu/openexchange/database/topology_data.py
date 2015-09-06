"""
This file define the topology's data structure.
Author:www.muzixing.com


Link:((src_domain, dst_domain), (src_port, dst_port)): capacity

If src_domain ==dst_domain, the link will be an interallink.
esle, it is an intralink.

"""
from . import data_base
from ryu.openexchange import oxproto_v1_0
from ryu.openexchange.oxproto_common import OXP_DEFAULT_FLAGS


class Domain(data_base.DataBase):
    """
        class Topo describe the link and vport of domain network
        @args:  domain_id = domain id
                link is the link from msg.
                links: {
                    (src_port, dst_port): capacity,
                    ...
                    }
                self.links:
                [
                ((domain_id, domain_id), (i.src_vport, i.dst_vport)):capacities
                ]

                paths: domain usage, save the intralinks' paths.
                capabilities:domain usage, save the capabilities of intralinks.
    """
    def __init__(self, domain_id=None, links={},
                 ports=set(), paths={}, capabilities={}):
        self.domain_id = domain_id
        self.links = links
        self.ports = ports

        self.paths = paths
        self.capabilities = capabilities

    def __call__(self):
        self.get_links(self.links)

    def get_links(self, links):
        return self.links

    def update_port(self, msg):
        if msg.reason == oxproto_v1_0.OXPPR_ADD:
            self.ports.add((msg.vport_no, msg.state))
        elif msg.reason == oxproto_v1_0.OXPPR_DELETE:
            self.ports.remove((msg.vport_no, msg.state))
            for key in self.links.keys():
                if msg.vport_no in [key[1][0], key[1][1]]:
                    del self.links[key]

    def update_link(self, domain, links):
        for i in links:
            if OXP_DEFAULT_FLAGS == domain.flags:
                capability = int(i.capability[0])
            else:
                capability = i.capability
            self.links[(
                (self.domain_id, self.domain_id),
                (i.src_vport, i.dst_vport))] = capability

            self.ports.add((i.src_vport, oxproto_v1_0.OXPPS_LIVE))
            self.ports.add((i.dst_vport, oxproto_v1_0.OXPPS_LIVE))
        return self.links


class Super_Topo(data_base.DataBase):
    """
        class Topo describe the domains and inter-links of full networks

        @args:  domains: {id:domain, }
                links: {
                    ((src_domain, dst_domain), (src_port, dst_port)): capacity,
                    ...
                        }
                links is interlinks.
    """

    def __init__(self, domains={}, links={}):
        self.domains = domains
        self.links = links

    def get_domain(self, domain_id):
        return self.domains[domain_id]

    def get_topo(self):
        return self.domains, self.links

    def update_link(self, link):
        self.links.update(link)

    def update_port(self, msg):
        domain = msg.domain
        if domain.id in self.domains:
            # update intra-links
            self.domains[domain.id].update_port(msg)

            # update inter-links
            if msg.reason == oxproto_v1_0.OXPPR_DELETE:
                for key in self.links.keys():
                    vport = [(key[0][0], key[1][0]), (key[0][1], key[1][1])]
                    if (msg.domain.id, msg.vport_no) in vport:
                        del self.links[key]

    def delete_domain(self, domain):
        if domain in self.domains:
            self.domains.remove(domain)
