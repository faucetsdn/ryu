'''
This module is about domain setting

Author:www.muzixing.com
Date                Work
2015/7/29           new this file
2015/7/29           Finish.

'''
from ryu import cfg

CONF = cfg.CONF


config = {'flags': CONF.oxp_flags,
          'period': CONF.oxp_period,
          'miss_send_len': CONF.oxp_miss_send_len, }


features = {'domain_id': CONF.oxp_domain_id,
            'sbp_version': CONF.sbp_proto_version,
            'proto_type': CONF.sbp_proto_type,
            'capabilities': CONF.oxp_capabilities,
            }
