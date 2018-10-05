# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import numbers

from ryu.controller import event


# base classes

class _RequestBase(event.EventRequestBase):
    def __init__(self):
        self.dst = 'ofctl_service'


class _ReplyBase(event.EventReplyBase):
    pass


# get datapath

class GetDatapathRequest(_RequestBase):
    def __init__(self, dpid=None):
        assert dpid is None or isinstance(dpid, numbers.Integral)
        super(GetDatapathRequest, self).__init__()
        self.dpid = dpid


# send msg

class SendMsgRequest(_RequestBase):
    def __init__(self, msg, reply_cls=None, reply_multi=False):
        super(SendMsgRequest, self).__init__()
        self.msg = msg
        self.reply_cls = reply_cls
        self.reply_multi = reply_multi


# generic reply

class Reply(_ReplyBase):
    def __init__(self, result=None, exception=None):
        self.result = result
        self.exception = exception

    def __call__(self):
        if self.exception:
            raise self.exception
        return self.result
