# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging

from ryu.exception import MacAddressDuplicated
from ryu.lib.mac import haddr_to_str

LOG = logging.getLogger('ryu.controller.mac_to_network')


class MacToNetwork(object):
    def __init__(self, nw):
        self.mac_to_net = {}
        self.dpid = {}
        self.nw = nw

    def get_network(self, mac, default=None):
        return self.mac_to_net.get(mac, default)

    def add_mac(self, mac, nw_id, nw_id_external=None):
        _nw_id = self.mac_to_net.get(mac)
        if _nw_id == nw_id:
            return

        # allow changing from nw_id_external to known nw id
        if _nw_id is None or _nw_id == nw_id_external:
            self.mac_to_net[mac] = nw_id
            LOG.debug('overwrite nw_id: mac %s nw old %s new %s',
                      haddr_to_str(mac), _nw_id, nw_id)
            return

        if nw_id == nw_id_external:
            # this can happens when the packet traverses
            # VM-> tap-> ovs-> ext-port-> wire-> ext-port-> ovs-> tap-> VM
            return

        LOG.warn('duplicated nw_id: mac %s nw old %s new %s',
                 haddr_to_str(mac), _nw_id, nw_id)

        raise MacAddressDuplicated(mac=mac)

    def del_mac(self, mac):
        del self.mac_to_net[mac]
