'''
This module is about domain config.

Author:www.muzixing.com
Date                Work
2015/7/29           new this file

'''
from ryu.openexchange.domain.setting import config
from ryu import cfg

CONF = cfg.CONF


class config(object):
    def __init__(self,
                 flags=config['flags'], period=config['period'],
                 miss_send_len=config['miss_send_len']):
        self.flags = flags
        self.period = period
        self.miss_send_len = miss_send_len

    def set_flags(self, flags):
        self.flags = flags
        CONF.oxp_flags = flags

    def set_period(self, period):
        self.period = period
        CONF.oxp_period = period

    def set_miss_send_len(self, miss_send_len):
        self.miss_send_len = miss_send_len
        CONF.oxp_miss_send_len = miss_send_len

    def set_config(self, flags, period, miss_send_len):
        self.set_flags(flags)
        self.set_period(period)
        self.set_miss_send_len(miss_send_len)
