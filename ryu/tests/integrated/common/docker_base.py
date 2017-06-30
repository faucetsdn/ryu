# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# This is based on the following
#     https://github.com/osrg/gobgp/test/lib/base.py
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

import itertools
import logging
import os
import subprocess
import time

import netaddr
import six

LOG = logging.getLogger(__name__)

DEFAULT_TEST_PREFIX = ''
DEFAULT_TEST_BASE_DIR = '/tmp/ctn_docker/bgp'
TEST_PREFIX = DEFAULT_TEST_PREFIX
TEST_BASE_DIR = DEFAULT_TEST_BASE_DIR

BGP_FSM_IDLE = 'BGP_FSM_IDLE'
BGP_FSM_ACTIVE = 'BGP_FSM_ACTIVE'
BGP_FSM_ESTABLISHED = 'BGP_FSM_ESTABLISHED'

BGP_ATTR_TYPE_ORIGIN = 1
BGP_ATTR_TYPE_AS_PATH = 2
BGP_ATTR_TYPE_NEXT_HOP = 3
BGP_ATTR_TYPE_MULTI_EXIT_DISC = 4
BGP_ATTR_TYPE_LOCAL_PREF = 5
BGP_ATTR_TYPE_COMMUNITIES = 8
BGP_ATTR_TYPE_ORIGINATOR_ID = 9
BGP_ATTR_TYPE_CLUSTER_LIST = 10
BGP_ATTR_TYPE_MP_REACH_NLRI = 14
BGP_ATTR_TYPE_EXTENDED_COMMUNITIES = 16

BRIDGE_TYPE_DOCKER = 'docker'
BRIDGE_TYPE_BRCTL = 'brctl'
BRIDGE_TYPE_OVS = 'ovs'


class CommandError(Exception):
    def __init__(self, out):
        super(CommandError, self).__init__()
        self.out = out


def try_several_times(f, t=3, s=1):
    e = RuntimeError()
    for _ in range(t):
        try:
            r = f()
        except RuntimeError as e:
            time.sleep(s)
        else:
            return r
    raise e


class CmdBuffer(list):
    def __init__(self, delim='\n'):
        super(CmdBuffer, self).__init__()
        self.delim = delim

    def __lshift__(self, value):
        self.append(value)

    def __str__(self):
        return self.delim.join(self)


class CommandOut(str):

    def __new__(cls, stdout, stderr, command, returncode, **kwargs):
        stdout = stdout or ''
        obj = super(CommandOut, cls).__new__(cls, stdout, **kwargs)
        obj.stderr = stderr or ''
        obj.command = command
        obj.returncode = returncode
        return obj


class Command(object):

    def _execute(self, cmd, capture=False, executable=None):
        """Execute a command using subprocess.Popen()
        :Parameters:
            - out: stdout from subprocess.Popen()
              out has some attributes.
              out.returncode: returncode of subprocess.Popen()
              out.stderr: stderr from subprocess.Popen()
        """
        if capture:
            p_stdout = subprocess.PIPE
            p_stderr = subprocess.PIPE
        else:
            p_stdout = None
            p_stderr = None
        pop = subprocess.Popen(cmd, shell=True, executable=executable,
                               stdout=p_stdout,
                               stderr=p_stderr)
        __stdout, __stderr = pop.communicate()
        _stdout = six.text_type(__stdout, 'utf-8')
        _stderr = six.text_type(__stderr, 'utf-8')
        out = CommandOut(_stdout, _stderr, cmd, pop.returncode)
        return out

    def execute(self, cmd, capture=True, try_times=1, interval=1):
        out = None
        for i in range(try_times):
            out = self._execute(cmd, capture=capture)
            LOG.info(out.command)
            if out.returncode == 0:
                return out
            LOG.error("stdout: %s", out)
            LOG.error("stderr: %s", out.stderr)
            if i + 1 >= try_times:
                break
            time.sleep(interval)
        raise CommandError(out)

    def sudo(self, cmd, capture=True, try_times=1, interval=1):
        cmd = 'sudo %s' % cmd
        return self.execute(cmd, capture=capture,
                            try_times=try_times, interval=interval)


class DockerImage(object):
    def __init__(self, baseimage='ubuntu:16.04'):
        self.baseimage = baseimage
        self.cmd = Command()

    def get_images(self):
        out = self.cmd.sudo('sudo docker images')
        images = []
        for line in out.splitlines()[1:]:
            images.append(line.split()[0])
        return images

    def exist(self, name):
        return name in self.get_images()

    def build(self, tagname, dockerfile_dir):
        self.cmd.sudo(
            "docker build -t {0} {1}".format(tagname, dockerfile_dir),
            try_times=3)

    def remove(self, tagname, check_exist=False):
        if check_exist and not self.exist(tagname):
            return tagname
        self.cmd.sudo("docker rmi -f %s" % tagname, try_times=3)

    def create_quagga(self, tagname='quagga', image=None, check_exist=False):
        if check_exist and self.exist(tagname):
            return tagname
        workdir = os.path.join(TEST_BASE_DIR, tagname)
        pkges = ' '.join([
            'telnet',
            'tcpdump',
            'quagga',
        ])
        if image:
            use_image = image
        else:
            use_image = self.baseimage
        c = CmdBuffer()
        c << 'FROM %s' % use_image
        c << 'RUN apt-get update'
        c << 'RUN apt-get install -qy --no-install-recommends %s' % pkges
        c << 'CMD /usr/lib/quagga/bgpd'

        self.cmd.sudo('rm -rf %s' % workdir)
        self.cmd.execute('mkdir -p %s' % workdir)
        self.cmd.execute("echo '%s' > %s/Dockerfile" % (str(c), workdir))
        self.build(tagname, workdir)
        return tagname

    def create_ryu(self, tagname='ryu', image=None, check_exist=False):
        if check_exist and self.exist(tagname):
            return tagname
        workdir = os.path.join(TEST_BASE_DIR, tagname)
        workdir_ctn = '/root/osrg/ryu'
        pkges = ' '.join([
            'tcpdump',
            'iproute2',
        ])
        if image:
            use_image = image
        else:
            use_image = self.baseimage
        c = CmdBuffer()
        c << 'FROM %s' % use_image
        c << 'ADD ryu %s' % workdir_ctn
        install = ' '.join([
            'RUN apt-get update',
            '&& apt-get install -qy --no-install-recommends %s' % pkges,
            '&& cd %s' % workdir_ctn,
            # Note: Clean previous builds, because "python setup.py install"
            # might fail if the current directory contains the symlink to
            # Docker host file systems.
            '&& rm -rf *.egg-info/ build/ dist/ .tox/ *.log'
            '&& pip install -r tools/pip-requires -r tools/optional-requires',
            '&& python setup.py install',
        ])
        c << install

        self.cmd.sudo('rm -rf %s' % workdir)
        self.cmd.execute('mkdir -p %s' % workdir)
        self.cmd.execute("echo '%s' > %s/Dockerfile" % (str(c), workdir))
        self.cmd.execute('cp -r ../ryu %s/' % workdir)
        self.build(tagname, workdir)
        return tagname


class Bridge(object):
    def __init__(self, name, subnet='', start_ip=None, end_ip=None,
                 with_ip=True, self_ip=False,
                 fixed_ip=None, reuse=False,
                 br_type='docker'):
        """Manage a bridge
        :Parameters:
            - name: bridge name
            - subnet: network cider to be used in this bridge
            - start_ip: start address of an ip to be used in the subnet
            - end_ip: end address of an ip to be used in the subnet
            - with_ip: specify if assign automatically an ip address
            - self_ip: specify if assign an ip address for the bridge
            - fixed_ip: an ip address to be assigned to the bridge
            - reuse: specify if use an existing bridge
            - br_type: One either in a 'docker', 'brctl' or 'ovs'
        """
        self.cmd = Command()
        self.name = name
        if br_type not in (BRIDGE_TYPE_DOCKER, BRIDGE_TYPE_BRCTL,
                           BRIDGE_TYPE_OVS):
            raise Exception("argument error br_type: %s" % br_type)
        self.br_type = br_type
        self.docker_nw = bool(self.br_type == BRIDGE_TYPE_DOCKER)
        if TEST_PREFIX != '':
            self.name = '{0}_{1}'.format(TEST_PREFIX, name)
        self.with_ip = with_ip
        if with_ip:
            self.subnet = netaddr.IPNetwork(subnet)
            if start_ip:
                self.start_ip = start_ip
            else:
                self.start_ip = netaddr.IPAddress(self.subnet.first)
            if end_ip:
                self.end_ip = end_ip
            else:
                self.end_ip = netaddr.IPAddress(self.subnet.last)

            def _ip_gen():
                for host in netaddr.IPRange(self.start_ip, self.end_ip):
                    yield host
            self._ip_generator = _ip_gen()
            # throw away first network address
            self.next_ip_address()

        self.self_ip = self_ip
        if fixed_ip:
            self.ip_addr = fixed_ip
        else:
            self.ip_addr = self.next_ip_address()
        if not reuse:
            def f():
                if self.br_type == BRIDGE_TYPE_DOCKER:
                    gw = "--gateway %s" % self.ip_addr.split('/')[0]
                    v6 = ''
                    if self.subnet.version == 6:
                        v6 = '--ipv6'
                    cmd = ("docker network create --driver bridge %s "
                           "%s --subnet %s %s" % (v6, gw, subnet, self.name))
                elif self.br_type == BRIDGE_TYPE_BRCTL:
                    cmd = "ip link add {0} type bridge".format(self.name)
                elif self.br_type == BRIDGE_TYPE_OVS:
                    cmd = "ovs-vsctl add-br {0}".format(self.name)
                else:
                    raise ValueError('Unsupported br_type: %s' % self.br_type)
                self.delete()
                self.execute(cmd, sudo=True, retry=True)
            try_several_times(f)
        if not self.docker_nw:
            self.execute("ip link set up dev {0}".format(self.name),
                         sudo=True, retry=True)

        if not self.docker_nw and self_ip:
            ips = self.check_br_addr(self.name)
            for key, ip in ips.items():
                if self.subnet.version == key:
                    self.execute(
                        "ip addr del {0} dev {1}".format(ip, self.name),
                        sudo=True, retry=True)
            self.execute(
                "ip addr add {0} dev {1}".format(self.ip_addr, self.name),
                sudo=True, retry=True)
        self.ctns = []

    def get_bridges_dc(self):
        out = self.execute('docker network ls', sudo=True, retry=True)
        bridges = []
        for line in out.splitlines()[1:]:
            bridges.append(line.split()[1])
        return bridges

    def get_bridges_brctl(self):
        out = self.execute('brctl show', retry=True)
        bridges = []
        for line in out.splitlines()[1:]:
            bridges.append(line.split()[0])
        return bridges

    def get_bridges_ovs(self):
        out = self.execute('ovs-vsctl list-br', sudo=True, retry=True)
        return out.splitlines()

    def get_bridges(self):
        if self.br_type == BRIDGE_TYPE_DOCKER:
            return self.get_bridges_dc()
        elif self.br_type == BRIDGE_TYPE_BRCTL:
            return self.get_bridges_brctl()
        elif self.br_type == BRIDGE_TYPE_OVS:
            return self.get_bridges_ovs()

    def exist(self):
        return self.name in self.get_bridges()

    def execute(self, cmd, capture=True, sudo=False, retry=False):
        if sudo:
            m = self.cmd.sudo
        else:
            m = self.cmd.execute
        if retry:
            return m(cmd, capture=capture, try_times=3, interval=1)
        else:
            return m(cmd, capture=capture)

    def check_br_addr(self, br):
        ips = {}
        cmd = "ip a show dev %s" % br
        for line in self.execute(cmd, sudo=True).split('\n'):
            if line.strip().startswith("inet "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ips[4] = elems[1]
            elif line.strip().startswith("inet6 "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ips[6] = elems[1]
        return ips

    def next_ip_address(self):
        return "{0}/{1}".format(next(self._ip_generator),
                                self.subnet.prefixlen)

    def addif(self, ctn):
        name = ctn.next_if_name()
        self.ctns.append(ctn)
        ip_address = None
        if self.docker_nw:
            ipv4 = None
            ipv6 = None
            ip_address = self.next_ip_address()
            ip_address_ip = ip_address.split('/')[0]
            version = 4
            if netaddr.IPNetwork(ip_address).version == 6:
                version = 6
            opt_ip = "--ip %s" % ip_address_ip
            if version == 4:
                ipv4 = ip_address
            else:
                opt_ip = "--ip6 %s" % ip_address_ip
                ipv6 = ip_address
            cmd = "docker network connect %s %s %s" % (
                opt_ip, self.name, ctn.docker_name())
            self.execute(cmd, sudo=True)
            ctn.set_addr_info(bridge=self.name, ipv4=ipv4, ipv6=ipv6,
                              ifname=name)
        else:
            if self.with_ip:
                ip_address = self.next_ip_address()
                version = 4
                if netaddr.IPNetwork(ip_address).version == 6:
                    version = 6
                ctn.pipework(self, ip_address, name, version=version)
            else:
                ctn.pipework(self, '0/0', name)
        return ip_address

    def delete(self, check_exist=True):
        if check_exist:
            if not self.exist():
                return
        if self.br_type == BRIDGE_TYPE_DOCKER:
            self.execute("docker network rm %s" % self.name,
                         sudo=True, retry=True)
        elif self.br_type == BRIDGE_TYPE_BRCTL:
            self.execute("ip link set down dev %s" % self.name,
                         sudo=True, retry=True)
            self.execute(
                "ip link delete %s type bridge" % self.name,
                sudo=True, retry=True)
        elif self.br_type == BRIDGE_TYPE_OVS:
            self.execute(
                "ovs-vsctl del-br %s" % self.name,
                sudo=True, retry=True)


class Container(object):
    def __init__(self, name, image=None):
        self.name = name
        self.image = image
        self.shared_volumes = []
        self.ip_addrs = []
        self.ip6_addrs = []
        self.is_running = False
        self.eths = []
        self.id = None

        self.cmd = Command()
        self.remove()

    def docker_name(self):
        if TEST_PREFIX == DEFAULT_TEST_PREFIX:
            return self.name
        return '{0}_{1}'.format(TEST_PREFIX, self.name)

    def get_docker_id(self):
        if self.id:
            return self.id
        else:
            return self.docker_name()

    def next_if_name(self):
        name = 'eth{0}'.format(len(self.eths) + 1)
        self.eths.append(name)
        return name

    def set_addr_info(self, bridge, ipv4=None, ipv6=None, ifname='eth0'):
        if ipv4:
            self.ip_addrs.append((ifname, ipv4, bridge))
        if ipv6:
            self.ip6_addrs.append((ifname, ipv6, bridge))

    def get_addr_info(self, bridge, ipv=4):
        addrinfo = {}
        if ipv == 4:
            ip_addrs = self.ip_addrs
        elif ipv == 6:
            ip_addrs = self.ip6_addrs
        else:
            return None
        for addr in ip_addrs:
            if addr[2] == bridge:
                addrinfo[addr[1]] = addr[0]
        return addrinfo

    def execute(self, cmd, capture=True, sudo=False, retry=False):
        if sudo:
            m = self.cmd.sudo
        else:
            m = self.cmd.execute
        if retry:
            return m(cmd, capture=capture, try_times=3, interval=1)
        else:
            return m(cmd, capture=capture)

    def dcexec(self, cmd, capture=True, retry=False):
        if retry:
            return self.cmd.sudo(cmd, capture=capture, try_times=3, interval=1)
        else:
            return self.cmd.sudo(cmd, capture=capture)

    def exec_on_ctn(self, cmd, capture=True, detach=False):
        name = self.docker_name()
        flag = '-d' if detach else ''
        return self.dcexec('docker exec {0} {1} {2}'.format(
            flag, name, cmd), capture=capture)

    def get_containers(self, allctn=False):
        cmd = 'docker ps --no-trunc=true'
        if allctn:
            cmd += ' --all=true'
        out = self.dcexec(cmd, retry=True)
        containers = []
        for line in out.splitlines()[1:]:
            containers.append(line.split()[-1])
        return containers

    def exist(self, allctn=False):
        return self.docker_name() in self.get_containers(allctn=allctn)

    def run(self):
        c = CmdBuffer(' ')
        c << "docker run --privileged=true"
        for sv in self.shared_volumes:
            c << "-v {0}:{1}".format(sv[0], sv[1])
        c << "--name {0} --hostname {0} -id {1}".format(self.docker_name(),
                                                        self.image)
        self.id = self.dcexec(str(c), retry=True)
        self.is_running = True
        self.exec_on_ctn("ip li set up dev lo")
        ipv4 = None
        ipv6 = None
        for line in self.exec_on_ctn("ip a show dev eth0").split('\n'):
            if line.strip().startswith("inet "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ipv4 = elems[1]
            elif line.strip().startswith("inet6 "):
                elems = [e.strip() for e in line.strip().split(' ')]
                ipv6 = elems[1]
        self.set_addr_info(bridge='docker0', ipv4=ipv4, ipv6=ipv6,
                           ifname='eth0')
        return 0

    def stop(self, check_exist=True):
        if check_exist:
            if not self.exist(allctn=False):
                return
        ctn_id = self.get_docker_id()
        out = self.dcexec('docker stop -t 0 %s' % ctn_id, retry=True)
        self.is_running = False
        return out

    def remove(self, check_exist=True):
        if check_exist:
            if not self.exist(allctn=True):
                return
        ctn_id = self.get_docker_id()
        out = self.dcexec('docker rm -f %s' % ctn_id, retry=True)
        self.is_running = False
        return out

    def pipework(self, bridge, ip_addr, intf_name="", version=4):
        if not self.is_running:
            LOG.warning('Call run() before pipeworking')
            return
        c = CmdBuffer(' ')
        c << "pipework {0}".format(bridge.name)

        if intf_name != "":
            c << "-i {0}".format(intf_name)
        else:
            intf_name = "eth1"
        ipv4 = None
        ipv6 = None
        if version == 4:
            ipv4 = ip_addr
        else:
            c << '-a 6'
            ipv6 = ip_addr
        c << "{0} {1}".format(self.docker_name(), ip_addr)
        self.set_addr_info(bridge=bridge.name, ipv4=ipv4, ipv6=ipv6,
                           ifname=intf_name)
        self.execute(str(c), sudo=True, retry=True)

    def get_pid(self):
        if self.is_running:
            cmd = "docker inspect -f '{{.State.Pid}}' %s" % self.docker_name()
            return int(self.dcexec(cmd))
        return -1

    def start_tcpdump(self, interface=None, filename=None):
        if not interface:
            interface = "eth0"
        if not filename:
            filename = "{0}/{1}.dump".format(
                self.shared_volumes[0][1], interface)
        self.exec_on_ctn(
            "tcpdump -i {0} -w {1}".format(interface, filename),
            detach=True)


class BGPContainer(Container):

    WAIT_FOR_BOOT = 1
    RETRY_INTERVAL = 5
    DEFAULT_PEER_ARG = {'neigh_addr': '',
                        'passwd': None,
                        'vpn': False,
                        'flowspec': False,
                        'is_rs_client': False,
                        'is_rr_client': False,
                        'cluster_id': None,
                        'policies': None,
                        'passive': False,
                        'local_addr': '',
                        'as2': False,
                        'graceful_restart': None,
                        'local_as': None,
                        'prefix_limit': None}
    default_peer_keys = sorted(DEFAULT_PEER_ARG.keys())
    DEFAULT_ROUTE_ARG = {'prefix': None,
                         'rf': 'ipv4',
                         'attr': None,
                         'next-hop': None,
                         'as-path': None,
                         'community': None,
                         'med': None,
                         'local-pref': None,
                         'extended-community': None,
                         'matchs': None,
                         'thens': None}
    default_route_keys = sorted(DEFAULT_ROUTE_ARG.keys())

    def __init__(self, name, asn, router_id, ctn_image_name=None):
        self.config_dir = TEST_BASE_DIR
        if TEST_PREFIX:
            self.config_dir = os.path.join(self.config_dir, TEST_PREFIX)
        self.config_dir = os.path.join(self.config_dir, name)
        self.asn = asn
        self.router_id = router_id
        self.peers = {}
        self.routes = {}
        self.policies = {}
        super(BGPContainer, self).__init__(name, ctn_image_name)
        self.execute(
            'rm -rf {0}'.format(self.config_dir), sudo=True)
        self.execute('mkdir -p {0}'.format(self.config_dir))
        self.execute('chmod 777 {0}'.format(self.config_dir))

    def __repr__(self):
        return str({'name': self.name, 'asn': self.asn,
                    'router_id': self.router_id})

    def run(self, wait=False, w_time=WAIT_FOR_BOOT):
        self.create_config()
        super(BGPContainer, self).run()
        if wait:
            time.sleep(w_time)
        return w_time

    def add_peer(self, peer, bridge='', reload_config=True, v6=False,
                 peer_info=None):
        peer_info = peer_info or {}
        self.peers[peer] = self.DEFAULT_PEER_ARG.copy()
        self.peers[peer].update(peer_info)
        peer_keys = sorted(self.peers[peer].keys())
        if peer_keys != self.default_peer_keys:
            raise Exception("argument error peer_info: %s" % peer_info)

        neigh_addr = ''
        local_addr = ''
        it = itertools.product(self.ip_addrs, peer.ip_addrs)
        if v6:
            it = itertools.product(self.ip6_addrs, peer.ip6_addrs)

        for me, you in it:
            if bridge != '' and bridge != me[2]:
                continue
            if me[2] == you[2]:
                neigh_addr = you[1]
                local_addr = me[1]
                if v6:
                    addr, mask = local_addr.split('/')
                    local_addr = "{0}%{1}/{2}".format(addr, me[0], mask)
                break

        if neigh_addr == '':
            raise Exception('peer {0} seems not ip reachable'.format(peer))

        if not self.peers[peer]['policies']:
            self.peers[peer]['policies'] = {}

        self.peers[peer]['neigh_addr'] = neigh_addr
        self.peers[peer]['local_addr'] = local_addr
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def del_peer(self, peer, reload_config=True):
        del self.peers[peer]
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def disable_peer(self, peer):
        raise NotImplementedError()

    def enable_peer(self, peer):
        raise NotImplementedError()

    def log(self):
        return self.execute('cat {0}/*.log'.format(self.config_dir))

    def add_route(self, route, reload_config=True, route_info=None):
        route_info = route_info or {}
        self.routes[route] = self.DEFAULT_ROUTE_ARG.copy()
        self.routes[route].update(route_info)
        route_keys = sorted(self.routes[route].keys())
        if route_keys != self.default_route_keys:
            raise Exception("argument error route_info: %s" % route_info)
        self.routes[route]['prefix'] = route
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def add_policy(self, policy, peer, typ, default='accept',
                   reload_config=True):
        self.set_default_policy(peer, typ, default)
        self.define_policy(policy)
        self.assign_policy(peer, policy, typ)
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def set_default_policy(self, peer, typ, default):
        if (typ in ['in', 'out', 'import', 'export'] and
                default in ['reject', 'accept']):
            if 'default-policy' not in self.peers[peer]:
                self.peers[peer]['default-policy'] = {}
            self.peers[peer]['default-policy'][typ] = default
        else:
            raise Exception('wrong type or default')

    def define_policy(self, policy):
        self.policies[policy['name']] = policy

    def assign_policy(self, peer, policy, typ):
        if peer not in self.peers:
            raise Exception('peer {0} not found'.format(peer.name))
        name = policy['name']
        if name not in self.policies:
            raise Exception('policy {0} not found'.format(name))
        self.peers[peer]['policies'][typ] = policy

    def get_local_rib(self, peer, rf):
        raise NotImplementedError()

    def get_global_rib(self, rf):
        raise NotImplementedError()

    def get_neighbor_state(self, peer_id):
        raise NotImplementedError()

    def get_reachablily(self, prefix, timeout=20):
        version = netaddr.IPNetwork(prefix).version
        addr = prefix.split('/')[0]
        if version == 4:
            ping_cmd = 'ping'
        elif version == 6:
            ping_cmd = 'ping6'
        else:
            raise Exception(
                'unsupported route family: {0}'.format(version))
        cmd = '/bin/bash -c "/bin/{0} -c 1 -w 1 {1} | xargs echo"'.format(
            ping_cmd, addr)
        interval = 1
        count = 0
        while True:
            res = self.exec_on_ctn(cmd)
            LOG.info(res)
            if '1 packets received' in res and '0% packet loss':
                break
            time.sleep(interval)
            count += interval
            if count >= timeout:
                raise Exception('timeout')
        return True

    def wait_for(self, expected_state, peer, timeout=120):
        interval = 1
        count = 0
        while True:
            state = self.get_neighbor_state(peer)
            LOG.info("%s's peer %s state: %s",
                     self.router_id, peer.router_id, state)
            if state == expected_state:
                return

            time.sleep(interval)
            count += interval
            if count >= timeout:
                raise Exception('timeout')

    def add_static_route(self, network, next_hop):
        cmd = '/sbin/ip route add {0} via {1}'.format(network, next_hop)
        self.exec_on_ctn(cmd)

    def set_ipv6_forward(self):
        cmd = 'sysctl -w net.ipv6.conf.all.forwarding=1'
        self.exec_on_ctn(cmd)

    def create_config(self):
        raise NotImplementedError()

    def reload_config(self):
        raise NotImplementedError()
