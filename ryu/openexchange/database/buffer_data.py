"""
This file save buffer data.
Author:www.muzixing.com

Date                Work
2015/9/5           new this file
"""

from . import data_base
from ryu.lib.ip import ipv4_to_bin
from ryu.lib.ip import ipv4_to_str
from ryu.openexchange.oxproto_v1_0 import OXPP_INACTIVE, OXPP_ACTIVE


class Buffer_Data(data_base.DataBase):
    def __init__(self):
        self.buffer = {}
