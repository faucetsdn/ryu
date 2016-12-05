# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# This is based on the following
#     https://github.com/osrg/gobgp/test/lib/quagga.py
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

from __future__ import absolute_import

import logging
import os

import netaddr

from . import docker_base as base

LOG = logging.getLogger(__name__)


class QuaggaBGPContainer(base.BGPContainer):

    WAIT_FOR_BOOT = 1
    SHARED_VOLUME = '/etc/quagga'

    def __init__(self, name, asn, router_id, ctn_image_name, zebra=False):
        super(QuaggaBGPContainer, self).__init__(name, asn, router_id,
                                                 ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))
        self.zebra = zebra
        self._create_config_debian()

    def run(self, wait=False, w_time=WAIT_FOR_BOOT):
        w_time = super(QuaggaBGPContainer,
                       self).run(wait=wait, w_time=self.WAIT_FOR_BOOT)
        return w_time

    def get_global_rib(self, prefix='', rf='ipv4'):
        rib = []
        if prefix != '':
            return self.get_global_rib_with_prefix(prefix, rf)

        out = self.vtysh('show bgp {0} unicast'.format(rf), config=False)
        if out.startswith('No BGP network exists'):
            return rib

        read_next = False

        for line in out.split('\n'):
            ibgp = False
            if line[:2] == '*>':
                line = line[2:]
                if line[0] == 'i':
                    line = line[1:]
                    ibgp = True
            elif not read_next:
                continue

            elems = line.split()

            if len(elems) == 1:
                read_next = True
                prefix = elems[0]
                continue
            elif read_next:
                nexthop = elems[0]
            else:
                prefix = elems[0]
                nexthop = elems[1]
            read_next = False

            rib.append({'prefix': prefix, 'nexthop': nexthop,
                        'ibgp': ibgp})

        return rib

    def get_global_rib_with_prefix(self, prefix, rf):
        rib = []

        lines = [line.strip() for line in self.vtysh(
            'show bgp {0} unicast {1}'.format(rf, prefix),
            config=False).split('\n')]

        if lines[0] == '% Network not in table':
            return rib

        lines = lines[2:]

        if lines[0].startswith('Not advertised'):
            lines.pop(0)  # another useless line
        elif lines[0].startswith('Advertised to non peer-group peers:'):
            lines = lines[2:]  # other useless lines
        else:
            raise Exception('unknown output format {0}'.format(lines))

        if lines[0] == 'Local':
            aspath = []
        else:
            aspath = [int(asn) for asn in lines[0].split()]

        nexthop = lines[1].split()[0].strip()
        info = [s.strip(',') for s in lines[2].split()]
        attrs = []
        if 'metric' in info:
            med = info[info.index('metric') + 1]
            attrs.append({'type': base.BGP_ATTR_TYPE_MULTI_EXIT_DISC,
                          'metric': int(med)})
        if 'localpref' in info:
            localpref = info[info.index('localpref') + 1]
            attrs.append({'type': base.BGP_ATTR_TYPE_LOCAL_PREF,
                          'value': int(localpref)})

        rib.append({'prefix': prefix, 'nexthop': nexthop,
                    'aspath': aspath, 'attrs': attrs})

        return rib

    def get_neighbor_state(self, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))

        neigh_addr = self.peers[peer]['neigh_addr'].split('/')[0]

        info = [l.strip() for l in self.vtysh(
            'show bgp neighbors {0}'.format(neigh_addr),
            config=False).split('\n')]

        if not info[0].startswith('BGP neighbor is'):
            raise Exception('unknown format')

        idx1 = info[0].index('BGP neighbor is ')
        idx2 = info[0].index(',')
        n_addr = info[0][idx1 + len('BGP neighbor is '):idx2]
        if n_addr == neigh_addr:
            idx1 = info[2].index('= ')
            state = info[2][idx1 + len('= '):]
            if state.startswith('Idle'):
                return base.BGP_FSM_IDLE
            elif state.startswith('Active'):
                return base.BGP_FSM_ACTIVE
            elif state.startswith('Established'):
                return base.BGP_FSM_ESTABLISHED
            else:
                return state

        raise Exception('not found peer {0}'.format(peer.router_id))

    def send_route_refresh(self):
        self.vtysh('clear ip bgp * soft', config=False)

    def create_config(self):
        zebra = 'no'
        self._create_config_bgp()
        if self.zebra:
            zebra = 'yes'
            self._create_config_zebra()
        self._create_config_daemons(zebra)

    def _create_config_debian(self):
        c = base.CmdBuffer()
        c << 'vtysh_enable=yes'
        c << 'zebra_options="  --daemon -A 127.0.0.1"'
        c << 'bgpd_options="   --daemon -A 127.0.0.1"'
        c << 'ospfd_options="  --daemon -A 127.0.0.1"'
        c << 'ospf6d_options=" --daemon -A ::1"'
        c << 'ripd_options="   --daemon -A 127.0.0.1"'
        c << 'ripngd_options=" --daemon -A ::1"'
        c << 'isisd_options="  --daemon -A 127.0.0.1"'
        c << 'babeld_options=" --daemon -A 127.0.0.1"'
        c << 'watchquagga_enable=yes'
        c << 'watchquagga_options=(--daemon)'
        with open('{0}/debian.conf'.format(self.config_dir), 'w') as f:
            LOG.info("[%s's new config]", self.name)
            LOG.info(str(c))
            f.writelines(str(c))

    def _create_config_daemons(self, zebra='no'):
        c = base.CmdBuffer()
        c << 'zebra=%s' % zebra
        c << 'bgpd=yes'
        c << 'ospfd=no'
        c << 'ospf6d=no'
        c << 'ripd=no'
        c << 'ripngd=no'
        c << 'isisd=no'
        c << 'babeld=no'
        with open('{0}/daemons'.format(self.config_dir), 'w') as f:
            LOG.info("[%s's new config]", self.name)
            LOG.info(str(c))
            f.writelines(str(c))

    def _create_config_bgp(self):

        c = base.CmdBuffer()
        c << 'hostname bgpd'
        c << 'password zebra'
        c << 'router bgp {0}'.format(self.asn)
        c << 'bgp router-id {0}'.format(self.router_id)
        if any(info['graceful_restart'] for info in self.peers.values()):
            c << 'bgp graceful-restart'

        version = 4
        for peer, info in self.peers.items():
            version = netaddr.IPNetwork(info['neigh_addr']).version
            n_addr = info['neigh_addr'].split('/')[0]
            if version == 6:
                c << 'no bgp default ipv4-unicast'

            c << 'neighbor {0} remote-as {1}'.format(n_addr, peer.asn)
            if info['is_rs_client']:
                c << 'neighbor {0} route-server-client'.format(n_addr)
            for typ, p in info['policies'].items():
                c << 'neighbor {0} route-map {1} {2}'.format(n_addr, p['name'],
                                                             typ)
            if info['passwd']:
                c << 'neighbor {0} password {1}'.format(n_addr, info['passwd'])
            if info['passive']:
                c << 'neighbor {0} passive'.format(n_addr)
            if version == 6:
                c << 'address-family ipv6 unicast'
                c << 'neighbor {0} activate'.format(n_addr)
                c << 'exit-address-family'

        for route in self.routes.values():
            if route['rf'] == 'ipv4':
                c << 'network {0}'.format(route['prefix'])
            elif route['rf'] == 'ipv6':
                c << 'address-family ipv6 unicast'
                c << 'network {0}'.format(route['prefix'])
                c << 'exit-address-family'
            else:
                raise Exception(
                    'unsupported route faily: {0}'.format(route['rf']))

        if self.zebra:
            if version == 6:
                c << 'address-family ipv6 unicast'
                c << 'redistribute connected'
                c << 'exit-address-family'
            else:
                c << 'redistribute connected'

        for name, policy in self.policies.items():
            c << 'access-list {0} {1} {2}'.format(name, policy['type'],
                                                  policy['match'])
            c << 'route-map {0} permit 10'.format(name)
            c << 'match ip address {0}'.format(name)
            c << 'set metric {0}'.format(policy['med'])

        c << 'debug bgp as4'
        c << 'debug bgp fsm'
        c << 'debug bgp updates'
        c << 'debug bgp events'
        c << 'log file {0}/bgpd.log'.format(self.SHARED_VOLUME)

        with open('{0}/bgpd.conf'.format(self.config_dir), 'w') as f:
            LOG.info("[%s's new config]", self.name)
            LOG.info(str(c))
            f.writelines(str(c))

    def _create_config_zebra(self):
        c = base.CmdBuffer()
        c << 'hostname zebra'
        c << 'password zebra'
        c << 'log file {0}/zebra.log'.format(self.SHARED_VOLUME)
        c << 'debug zebra packet'
        c << 'debug zebra kernel'
        c << 'debug zebra rib'
        c << ''

        with open('{0}/zebra.conf'.format(self.config_dir), 'w') as f:
            LOG.info("[%s's new config]", self.name)
            LOG.info(str(c))
            f.writelines(str(c))

    def vtysh(self, cmd, config=True):
        if not isinstance(cmd, list):
            cmd = [cmd]
        cmd = ' '.join("-c '{0}'".format(c) for c in cmd)
        if config:
            return self.exec_on_ctn(
                "vtysh -d bgpd -c 'en' -c 'conf t' -c "
                "'router bgp {0}' {1}".format(self.asn, cmd),
                capture=True)
        else:
            return self.exec_on_ctn("vtysh -d bgpd {0}".format(cmd),
                                    capture=True)

    def reload_config(self):
        daemon = []
        daemon.append('bgpd')
        if self.zebra:
            daemon.append('zebra')
        for d in daemon:
            cmd = '/usr/bin/pkill {0} -SIGHUP'.format(d)
            self.exec_on_ctn(cmd, capture=True)


class RawQuaggaBGPContainer(QuaggaBGPContainer):
    def __init__(self, name, config, ctn_image_name,
                 zebra=False):
        asn = None
        router_id = None
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('router bgp'):
                asn = int(line[len('router bgp'):].strip())
            if line.startswith('bgp router-id'):
                router_id = line[len('bgp router-id'):].strip()
        if not asn:
            raise Exception('asn not in quagga config')
        if not router_id:
            raise Exception('router-id not in quagga config')
        self.config = config
        super(RawQuaggaBGPContainer, self).__init__(name, asn, router_id,
                                                    ctn_image_name, zebra)

    def create_config(self):
        with open(os.path.join(self.config_dir, 'bgpd.conf'), 'w') as f:
            LOG.info("[%s's new config]", self.name)
            LOG.info(self.config)
            f.writelines(self.config)
