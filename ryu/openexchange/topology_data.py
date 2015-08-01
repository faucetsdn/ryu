"""
This file define the topology's data structure.
Author:www.muzixing.com


Link:((src_domain, dst_domain, src_port, dst_port): capacity)

If src_domain ==dst_domain, the link will be an interallink.
esle, it is an intralink.

"""
from . import data_base
from ryu.openexchange import oxproto_v1_0


class InteralLinks(data_base.DataBase):
    def __init__(self, links={}, domain_id=None):
        self.links = links
        self.domain_id = domain_id

    def update(self, links):
        '''
            @args:links: src_vport, dst_vport, capability
        '''
        for i in links:
            self.links[(
                domain_id, domain_id, i.src_vport, i.dst_vport)] = i.capability

    def get_links(self):
        return self.links

    def delete_links(self, links):
        for link in links:
            del self.links[link]

    def delete_link(self, link):
        del self.links[link]


class IntraLinks(data_base.DataBase):
    def __init__(self, links={}):
        self.links = links

    def update(self, links):
        '''
        links: {(src_domain, dst_domain, src_port, dst_port): capacity}

        '''
        # links have been formated.
        self.links.update(links)

    def get_links(self):
        return self.links

    def delete_links(self, links):
        for link in links:
            del self.links[link]

    def delete_link(self, link):
        del self.links[link]


class Links(data_base.DataBase):
    def __init__(self, interallinks=InteralLinks(), intralinks=IntraLinks()):
        self.interallinks = interallinks    # object InterallLinks
        self.intralinks = interallinks      # object Intralinks
        self.links = {}

    def __call__(self):
        self.merge()

    def merge(self):
        self.links.update(self.interallinks.links)
        self.links.update(self.intralinks.links)

    def get_links(self):
        return self.links


class Domain(data_base.DataBase):
    """
        class Topo describe the link and vport of domain network
        @args:  domain_id = domain id
                link is the link from msg.
                links: {
                    (src_port, dst_port): capacity,
                    ...
                self.links[
                (domain_id, domain_id, i.src_vport, i.dst_vport):capacities]
                }
    """
    def __init__(self, domain_id=None, links={}, ports=set()):
        self.domain_id = domain_id
        self.links = links
        self.ports = ports

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
                if msg.vport_no in [key[0], key[1]]:
                    del self.links[key]

    def update_link(self, links):
        for i in links:
            self.links[(
                domain_id, domain_id, i.src_vport, i.dst_vport)] = i.capability
        return self.links


class Super_Topo(data_base.DataBase):
    """
        class Topo describe the domains and intra-links of full networks
        @args:   domains: set(domain_id1,id2....)
                links: {
                    (src_domain, dst_domain, src_port, dst_port): capacity,
                    ...
                }
    """

    def __init__(self, domains=set(), links={}):
        self.domains = domains
        # links is intra-links.
        self.links = links

    def get_topo(self):
        return self.domains, self.links

    def update_link(self, msg):
        if msg.reason == oxproto_v1_0.OXPPR_DELETE:
            for key in self.links.keys():
                if msg.vport_no in [key[2], key[3]]:
                    del self.links[key]

    def delete_domain(self, domain):
        if domain in self.domains:
            self.domains.remove(domain)
