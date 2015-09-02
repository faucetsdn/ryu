'''
This module is about domain features.

Author:www.muzixing.com
Date                Work
2015/7/29           new this file

'''
from ryu.openexchange.domain.setting import features
from ryu.openexchange.utils import controller_id
from ryu import cfg

CONF = cfg.CONF


class features(object):
    def __init__(self,
                 domain_id=features['domain_id'],
                 proto_type=features['proto_type'],
                 sbp_version=features['sbp_version'],
                 capabilities=features['capabilities']):
        self.domain_id = domain_id
        self.proto_type = proto_type
        self.sbp_version = sbp_version
        self.capabilities = capabilities

    def set_domain_id(self, domain_id):
        if isinstance(domain_id, str):
            self.domain_id = controller_id.str_to_dpid(domain_id)
            CONF.oxp_domain_id = controller_id.str_to_dpid(domain_id)

    def set_proto_type(self, proto_type):
        self.proto_type = proto_type
        CONF.sbp_proto_type = proto_type

    def set_version(self, version):
        self.sbp_version = version
        CONF.sbp_proto_version = version

    def set_capabilities(self, capabilities):
        self.capabilities = capabilities
        CONF.oxp_capabilities = capabilities

    def set_features(self,
                     domain_id=features['domain_id'],
                     proto_type=features['proto_type'],
                     sbp_version=features['sbp_version'],
                     capabilities=features['capabilities']):

        self.set_domain_id(domain_id)
        self.set_version(sbp_version)
        self.set_proto_type(proto_type)
        self.set_capabilities(capabilities)
