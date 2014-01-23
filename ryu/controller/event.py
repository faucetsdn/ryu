# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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


class EventBase(object):
    # Nothing yet
    pass


class EventRequestBase(EventBase):
    def __init__(self):
        super(EventRequestBase, self).__init__()
        self.dst = None  # app.name of provide the event.
        self.src = None
        self.sync = False
        self.reply_q = None


class EventReplyBase(EventBase):
    def __init__(self, dst):
        super(EventReplyBase, self).__init__()
        self.dst = dst
