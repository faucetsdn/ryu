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

import logging
from ryu.lib.mac import haddr_to_str

LOG = logging.getLogger('ryu.controller.mac_to_port')


class MacToPortTable(object):
    """MAC addr <-> (dpid, port name)"""

    def __init__(self):
        super(MacToPortTable, self).__init__()
        self.mac_to_port = {}

    def dpid_add(self, dpid):
        LOG.debug('dpid_add: 0x%016x', dpid)
        self.mac_to_port.setdefault(dpid, {})

    def port_add(self, dpid, port, mac):
        """
        :returns: old port if learned. (this may be = port)
                  None otherwise
        """
        old_port = self.mac_to_port[dpid].get(mac, None)
        self.mac_to_port[dpid][mac] = port

        if old_port is not None and old_port != port:
            LOG.debug('port_add: 0x%016x 0x%04x %s',
                      dpid, port, haddr_to_str(mac))

        return old_port

    def port_get(self, dpid, mac):
        # LOG.debug('dpid 0x%016x mac %s', dpid, haddr_to_str(mac))
        return self.mac_to_port[dpid].get(mac)

    def mac_list(self, dpid, port):
        return [mac for (mac, port_) in self.mac_to_port.get(dpid, {}).items()
                if port_ == port]

    def mac_del(self, dpid, mac):
        del self.mac_to_port[dpid][mac]
