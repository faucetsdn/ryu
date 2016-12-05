# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
import time

from . import docker_base as base

LOG = logging.getLogger(__name__)


class RyuBGPContainer(base.BGPContainer):

    WAIT_FOR_BOOT = 1
    SHARED_VOLUME = '/etc/ryu'

    def __init__(self, name, asn, router_id, ctn_image_name):
        super(RyuBGPContainer, self).__init__(name, asn, router_id,
                                              ctn_image_name)
        self.RYU_CONF = os.path.join(self.config_dir, 'ryu.conf')
        self.SHARED_RYU_CONF = os.path.join(self.SHARED_VOLUME, 'ryu.conf')
        self.SHARED_BGP_CONF = os.path.join(self.SHARED_VOLUME, 'bgp_conf.py')
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))

    def _create_config_ryu(self):
        c = base.CmdBuffer()
        c << '[DEFAULT]'
        c << 'verbose=True'
        c << 'log_file=/etc/ryu/manager.log'
        with open(self.RYU_CONF, 'w') as f:
            LOG.info("[%s's new config]" % self.name)
            LOG.info(str(c))
            f.writelines(str(c))

    def _create_config_ryu_bgp(self):
        c = base.CmdBuffer()
        c << 'import os'
        c << ''
        c << 'BGP = {'
        c << "    'local_as': %s," % str(self.asn)
        c << "    'router_id': '%s'," % self.router_id
        c << "    'neighbors': ["
        c << "        {"
        for peer, info in self.peers.items():
            n_addr = info['neigh_addr'].split('/')[0]
            c << "            'address': '%s'," % n_addr
            c << "            'remote_as': %s," % str(peer.asn)
            c << "            'enable_ipv4': True,"
            c << "            'enable_ipv6': True,"
            c << "            'enable_vpnv4': True,"
            c << "            'enable_vpnv6': True,"
            c << '        },'
            c << '    ],'
        c << "    'routes': ["
        for route in self.routes.values():
            c << "        {"
            c << "            'prefix': '%s'," % route['prefix']
            c << "        },"
        c << "    ],"
        c << "}"
        log_conf = """LOGGING = {

    # We use python logging package for logging.
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s ' +
                      '[%(process)d %(thread)d] %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(asctime)s %(module)s %(lineno)s ' +
                      '%(message)s'
        },
        'stats': {
            'format': '%(message)s'
        },
    },

    'handlers': {
        # Outputs log to console.
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'console_stats': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'stats'
        },
        # Rotates log file when its size reaches 10MB.
        'log_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('.', 'bgpspeaker.log'),
            'maxBytes': '10000000',
            'formatter': 'verbose'
        },
        'stats_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('.', 'statistics_bgps.log'),
            'maxBytes': '10000000',
            'formatter': 'stats'
        },
    },

    # Fine-grained control of logging per instance.
    'loggers': {
        'bgpspeaker': {
            'handlers': ['console', 'log_file'],
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'stats': {
            'handlers': ['stats_file', 'console_stats'],
            'level': 'INFO',
            'propagate': False,
            'formatter': 'stats',
        },
    },

    # Root loggers.
    'root': {
        'handlers': ['console', 'log_file'],
        'level': 'DEBUG',
        'propagate': True,
    },
}"""
        c << log_conf
        with open(os.path.join(self.config_dir, 'bgp_conf.py'), 'w') as f:
            LOG.info("[%s's new config]", self.name)
            LOG.info(str(c))
            f.writelines(str(c))

    def create_config(self):
        self._create_config_ryu()
        self._create_config_ryu_bgp()

    def is_running_ryu(self):
        results = self.exec_on_ctn('ps ax')
        running = False
        for line in results.split('\n')[1:]:
            if 'ryu-manager' in line:
                running = True
        return running

    def start_ryubgp(self, check_running=True, retry=False):
        if check_running:
            if self.is_running_ryu():
                return True
        result = False
        if retry:
            try_times = 3
        else:
            try_times = 1
        cmd = "ryu-manager --verbose "
        cmd += "--config-file %s " % self.SHARED_RYU_CONF
        cmd += "--bgp-app-config-file %s " % self.SHARED_BGP_CONF
        cmd += "ryu.services.protocols.bgp.application"
        for _ in range(try_times):
            self.exec_on_ctn(cmd, detach=True)
            if self.is_running_ryu():
                result = True
                break
            time.sleep(1)
        return result

    def stop_ryubgp(self, check_running=True, retry=False):
        if check_running:
            if not self.is_running_ryu():
                return True
        result = False
        if retry:
            try_times = 3
        else:
            try_times = 1
        for _ in range(try_times):
            cmd = '/usr/bin/pkill ryu-manager -SIGTERM'
            self.exec_on_ctn(cmd)
            if not self.is_running_ryu():
                result = True
                break
            time.sleep(1)
        return result

    def run(self, wait=False, w_time=WAIT_FOR_BOOT):
        w_time = super(RyuBGPContainer,
                       self).run(wait=wait, w_time=self.WAIT_FOR_BOOT)
        return w_time

    def reload_config(self):
        self.stop_ryubgp(retry=True)
        self.start_ryubgp(retry=True)
