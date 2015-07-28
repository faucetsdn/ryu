# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
import json
from socket import error as SocketError
from httplib import HTTPException

import gevent
import gevent.monkey
gevent.monkey.patch_all()

from ryu.lib.dpid import str_to_dpid
from ryu.lib.port_no import str_to_port_no
from ryu.app.client import TopologyClient

LOG = logging.getLogger('ryu.gui')


class Port(object):
    def __init__(self, dpid, port_no, hw_addr, name):
        assert type(dpid) == int
        assert type(port_no) == int
        assert type(hw_addr) == str or type(hw_addr) == unicode
        assert type(name) == str or type(name) == unicode

        self.dpid = dpid
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.name = name

    def to_dict(self):
        return {'dpid': self.dpid,
                'port_no': self.port_no,
                'hw_addr': self.hw_addr,
                'name': self.name}

    @classmethod
    def from_rest_dict(cls, p):
        return cls(str_to_dpid(p['dpid']),
                   str_to_port_no(p['port_no']),
                   p['hw_addr'],
                   p['name'])

    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        return 'Port<dpid=%s, port_no=%s, hw_addr=%s, name=%s>' % \
            (self.dpid, self.port_no, self.hw_addr, self.name)


class Switch(object):
    def __init__(self, dpid, ports):
        assert type(dpid) == int
        assert type(ports) == list

        self.dpid = dpid
        self.ports = ports

    def to_dict(self):
        return {'dpid': self.dpid,
                'ports': [port.to_dict() for port in self.ports]}

    def __eq__(self, other):
        return self.dpid == other.dpid

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.dpid)

    def __str__(self):
        return 'Switch<dpid=%s>' % (self.dpid)


class Link(object):
    def __init__(self, src, dst):
        assert type(src) == Port
        assert type(dst) == Port

        self.src = src
        self.dst = dst

    def to_dict(self):
        return {'src': self.src.to_dict(),
                'dst': self.dst.to_dict()}

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.src, self.dst))

    def __str__(self):
        return 'Link<%s to %s>' % (self.src, self.dst)


class Topology(dict):
    def __init__(self, switches_json=None, links_json=None):
        super(Topology, self).__init__()

        self['switches'] = []
        if switches_json:
            for s in json.loads(switches_json):
                ports = []
                for p in s['ports']:
                    ports.append(Port.from_rest_dict(p))
                switch = Switch(str_to_dpid(s['dpid']), ports)
                self['switches'].append(switch)

        self['links'] = []
        if links_json:
            for l in json.loads(links_json):
                link = Link(Port.from_rest_dict(l['src']),
                            Port.from_rest_dict(l['dst']))
                self['links'].append(link)

        self['ports'] = []
        for switch in self['switches']:
            self['ports'].extend(switch.ports)

    def peer(self, port):
        for link in self['links']:
            if link.src == port:
                return link.dst
            elif link.dst == port:
                return link.src

        return None

    def attached(self, port):
        for switch in self['switches']:
            if port in switch.port:
                return switch

        return None

    def neighbors(self, switch):
        ns = []
        for port in switch.port:
            ns.append(self.attached(self.peer(port)))

        return ns

    # TopologyDelta = new_Topology - old_Topology
    def __sub__(self, old):
        assert type(old) == Topology

        added = Topology()
        deleted = Topology()
        for k in self.iterkeys():
            new_set = set(self[k])
            old_set = set(old[k])

            added[k] = list(new_set - old_set)
            deleted[k] = list(old_set - new_set)

        return TopologyDelta(added, deleted)

    def __str__(self):
        return 'Topology<switches=%d, ports=%d, links=%d>' % (
            len(self['switches']),
            len(self['ports']),
            len(self['links']))


class TopologyDelta(object):
    def __init__(self, added, deleted):
        self.added = added
        self.deleted = deleted

    def __str__(self):
        return 'TopologyDelta<added=%s, deleted=%s>' % \
            (self.added, self.deleted)


class TopologyWatcher(object):
    _LOOP_WAIT = 3
    _REST_RETRY_WAIT = 10

    def __init__(self, update_handler=None, rest_error_handler=None):
        self.update_handler = update_handler
        self.rest_error_handler = rest_error_handler
        self.address = None
        self.tc = None

        self.threads = []
        self.topo = Topology()
        self.prev_switches_json = ''
        self.prev_links_json = ''

    def start(self, address):
        LOG.debug('TopologyWatcher: start')
        self.address = address
        self.tc = TopologyClient(address)
        self.is_active = True
        self.threads.append(gevent.spawn(self._polling_loop))

    def stop(self):
        LOG.debug('TopologyWatcher: stop')
        self.is_active = False

    def _polling_loop(self):
        LOG.debug('TopologyWatcher: Enter polling loop')
        while self.is_active:
            try:
                switches_json = self.tc.list_switches().read()
                links_json = self.tc.list_links().read()
            except (SocketError, HTTPException) as e:
                LOG.debug('TopologyWatcher: REST API(%s) is not avaliable.' %
                          self.address)
                LOG.debug('        wait %d secs...' %
                          self._REST_RETRY_WAIT)
                self._call_rest_error_handler(e)
                gevent.sleep(self._REST_RETRY_WAIT)
                continue

            if self._is_updated(switches_json, links_json):
                LOG.debug('TopologyWatcher: topology updated')
                new_topo = Topology(switches_json, links_json)
                delta = new_topo - self.topo
                self.topo = new_topo

                self._call_update_handler(delta)

            gevent.sleep(self._LOOP_WAIT)

    def _is_updated(self, switches_json, links_json):
        updated = (
            self.prev_switches_json != switches_json or
            self.prev_links_json != links_json)

        self.prev_switches_json = switches_json
        self.prev_links_json = links_json

        return updated

    def _call_rest_error_handler(self, e):
        if self.rest_error_handler:
            self.rest_error_handler(self.address, e)

    def _call_update_handler(self, delta):
        if self.update_handler:
            self.update_handler(self.address, delta)


def handler(address, delta):
    print delta

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    watcher = TopologyWatcher(handler)
    watcher.start('127.0.0.1:8080')
    gevent.joinall(watcher.threads)
