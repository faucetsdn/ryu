# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
from ryu.lib.mac import haddr_to_str

LOG = logging.getLogger('ryu.controller.mac_to_port')


class MacToPortTable(object):
    """MAC addr <-> (dpid, port name)"""

    def __init__(self):
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
