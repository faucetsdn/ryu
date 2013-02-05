# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import logging

from ryu.controller import event
from ryu.lib.dpid import dpid_to_str
from ryu.base import app_manager

LOG = logging.getLogger(__name__)


class EventConfSwitchDelDPID(event.EventBase):
    def __init__(self, dpid):
        super(EventConfSwitchDelDPID, self).__init__()
        self.dpid = dpid

    def __str__(self):
        return 'EventConfSwitchDelDPID<%s>' % dpid_to_str(self.dpid)


class EventConfSwitchSet(event.EventBase):
    def __init__(self, dpid, key, value):
        super(EventConfSwitchSet, self).__init__()
        self.dpid = dpid
        self.key = key
        self.value = value

    def __str__(self):
        return 'EventConfSwitchSet<%s, %s, %s>' % (
            dpid_to_str(self.dpid), self.key, self.value)


class EventConfSwitchDel(event.EventBase):
    def __init__(self, dpid, key):
        super(EventConfSwitchDel, self).__init__()
        self.dpid = dpid
        self.key = key

    def __str__(self):
        return 'EventConfSwitchDel<%s, %s>' % (dpid_to_str(self.dpid),
                                               self.key)


class ConfSwitchSet(app_manager.RyuApp):
    def __init__(self):
        super(ConfSwitchSet, self).__init__()
        self.name = 'conf_switch'
        self.confs = {}

    def dpids(self):
        return self.confs.keys()

    def del_dpid(self, dpid):
        del self.confs[dpid]
        self.send_event_to_observers(EventConfSwitchDelDPID(dpid))

    def keys(self, dpid):
        return self.confs[dpid].keys()

    def set_key(self, dpid, key, value):
        conf = self.confs.setdefault(dpid, {})
        conf[key] = value
        self.send_event_to_observers(EventConfSwitchSet(dpid, key, value))

    def get_key(self, dpid, key):
        return self.confs[dpid][key]

    def del_key(self, dpid, key):
        del self.confs[dpid][key]
        self.send_event_to_observers(EventConfSwitchDel(dpid, key))

    # methods for TunnelUpdater
    def __contains__(self, (dpid, key)):
        """(dpid, key) in <ConfSwitchSet instance>"""
        return dpid in self.confs and key in self.confs[dpid]

    def find_dpid(self, key, value):
        for dpid, conf in self.confs.items():
            if key in conf:
                if conf[key] == value:
                    return dpid

        return None
