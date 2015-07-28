"""
This file define the topology's data structure.
Author:www.muzixing.com


Link:((src_domain, dst_domain, src_port, dst_port): capacity)

If src_domain ==dst_domain, the link will be an interallink.
esle, it is an intralink.

"""
form . import data_base


class InteralLinks(data_base.DataBase):
    def __init__(self, links={}, domain_id=None):
        self.links = links
        self.domain_id = domain_id

    def update(self, links):
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
    def __init__(self, links):
        self.links = links

    def update(self, links):
        # link: ((src_domain, dst_domain, src_port, dst_port): capacity)
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


class Topo(data_base.DataBase):
    def __init__(self, domains=[], links=[]):
        self.domains = domains
        self.links = links

    def get_topo(self):
        return self.domains, self.links
