# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

"""
 Core Manager module dedicated for providing CORE_MANAGER singleton
"""
from ryu.services.protocols.bgp.base import Activity
from ryu.services.protocols.bgp.base import ActivityException
from ryu.services.protocols.bgp.rtconf.neighbors import NeighborsConf
from ryu.services.protocols.bgp.rtconf.vrfs import VrfsConf


class _CoreManager(Activity):
    """Core service manager.
    """

    def __init__(self):
        self._common_conf = None
        self._neighbors_conf = None
        self._vrfs_conf = None
        self._core_service = None
        super(_CoreManager, self).__init__()

    def _run(self, *args, **kwargs):
        self._common_conf = kwargs.pop('common_conf')
        self._neighbors_conf = NeighborsConf()
        self._vrfs_conf = VrfsConf()
        from ryu.services.protocols.bgp.core import CoreService
        self._core_service = CoreService(self._common_conf,
                                         self._neighbors_conf,
                                         self._vrfs_conf)
        waiter = kwargs.pop('waiter')
        core_activity = self._spawn_activity(self._core_service, waiter=waiter)
        core_activity.wait()

    def get_core_service(self):
        self._check_started()
        return self._core_service

    def _check_started(self):
        if not self.started:
            raise ActivityException('Cannot access any property before '
                                    'activity has started')

    @property
    def common_conf(self):
        self._check_started()
        return self._common_conf

    @property
    def neighbors_conf(self):
        self._check_started()
        return self._neighbors_conf

    @property
    def vrfs_conf(self):
        self._check_started()
        return self._vrfs_conf

# _CoreManager instance that manages core bgp service and configuration data.
CORE_MANAGER = _CoreManager()
