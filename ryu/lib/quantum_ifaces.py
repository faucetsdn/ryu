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

from ryu.base import app_manager
from ryu.controller import event

LOG = logging.getLogger(__name__)


class EventQuantumIfaceSet(event.EventBase):
    def __init__(self, iface_id, key, value):
        super(EventQuantumIfaceSet, self).__init__()
        self.iface_id = iface_id
        self.key = key
        self.value = value

    def __str__(self):
        return 'EventQuantumIfaceSet<%s, %s, %s>' % (
            self.iface_id, self.key, self.value)


class QuantumIfaces(app_manager.RyuApp, dict):
    # iface-id => dict
    #    {'iface_id': {
    #         'network_id': net-id,
    #         'ports': [{'datapath_id': dpid, 'ofport': ofport, 'name': name}]
    #     }}

    KEY_NETWORK_ID = 'network_id'
    KEY_PORTS = 'ports'
    SUBKEY_DATAPATH_ID = 'datapath_id'
    SUBKEY_OFPORT = 'ofport'
    SUBKEY_NAME = 'name'

    def __init__(self):
        super(QuantumIfaces, self).__init__()
        self.name = 'quantum_ifaces'

    def register(self, iface_id):
        self.setdefault(iface_id, {})

    def unregister(self, iface_id):
        del self[iface_id]

    def get_iface_dict(self, iface_id):
        return self[iface_id]

    def list_keys(self, iface_id):
        return self[iface_id].keys()

    def get_key(self, iface_id, key):
        return self[iface_id][key]

    def _update_key(self, iface_id, key, value):
        if key == self.KEY_PORTS:
            ports = self[iface_id].setdefault(key, [])
            try:
                ports.remove(value)
            except ValueError:
                pass
            ports.append(value)
        else:
            self[iface_id][key] = value
        self.send_event_to_observers(
            EventQuantumIfaceSet(iface_id, key, value))

    def set_key(self, iface_id, key, value):
        iface = self.setdefault(iface_id, {})
        if key in iface:
            raise ValueError('trying to set already existing value '
                             '%s %s -> %s', key, iface[key], value)
        self._update_key(iface_id, key, value)

    def update_key(self, iface_id, key, value):
        iface = self.setdefault(iface_id, {})
        if key in iface:
            err = False
            if key == self.KEY_PORTS:
                dpid = value.get(self.SUBKEY_DATAPATH_ID)
                ofport = value.get(self.SUBKEY_OFPORT)
                name = value.get(self.SUBKEY_NAME)
                if not dpid or not ofport or not name:
                    raise ValueError(
                        'invalid port data: dpid=%s ofport=%s name=%s',
                        dpid, ofport, name)
                for p in iface[key]:
                    if (p[self.SUBKEY_DATAPATH_ID] == dpid and
                        (p[self.SUBKEY_OFPORT] != ofport or
                         p[self.SUBKEY_NAME] != name)):
                        err = True
                        break
            elif iface[key] != value:
                err = True
            if err:
                raise ValueError('unmatched updated %s %s -> %s',
                                 key, iface[key], value)
        self._update_key(iface_id, key, value)

    def del_key(self, iface_id, key, value=None):
        if iface_id not in self or key not in self[iface_id]:
            return

        if key != self.KEY_PORTS:
            assert value is None
            del self[iface_id][key]
            return

        ports = self[iface_id][key]
        try:
            ports.remove(value)
        except ValueError:
            pass
        if not ports:
            del self[iface_id][key]
            return
        return True
