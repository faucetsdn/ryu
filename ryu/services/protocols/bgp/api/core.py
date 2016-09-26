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
 Defines APIs related to Core/CoreManager.
"""
from ryu.lib import hub

from ryu.services.protocols.bgp.api.base import register
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.common import CommonConf


NEIGHBOR_RESET_WAIT_TIME = 3


@register(name='core.start')
def start(**kwargs):
    """Starts new context using provided configuration.

    Raises RuntimeConfigError if a context is already active.
    """
    if CORE_MANAGER.started:
        raise RuntimeConfigError('Current context has to be stopped to start '
                                 'a new context.')

    try:
        waiter = kwargs.pop('waiter')
    except KeyError:
        waiter = hub.Event()
    common_config = CommonConf(**kwargs)
    hub.spawn(CORE_MANAGER.start, *[], **{'common_conf': common_config,
                                          'waiter': waiter})
    return True


@register(name='core.stop')
def stop(**kwargs):
    """Stops current context is one is active.

    Raises RuntimeConfigError if runtime is not active or initialized yet.
    """
    if not CORE_MANAGER.started:
        raise RuntimeConfigError('No runtime is active. Call start to create '
                                 'a runtime')
    CORE_MANAGER.stop()
    return True


@register(name='core.reset_neighbor')
def reset_neighbor(ip_address):
    neighs_conf = CORE_MANAGER.neighbors_conf
    neigh_conf = neighs_conf.get_neighbor_conf(ip_address)
    # Check if we have neighbor with given IP.
    if not neigh_conf:
        raise RuntimeConfigError('No neighbor configuration found for given'
                                 ' IP: %s' % ip_address)
    # If neighbor is enabled, we disable it.
    if neigh_conf.enabled:
        # Disable neighbor to close existing session.
        neigh_conf.enabled = False
        # Enable neighbor after NEIGHBOR_RESET_WAIT_TIME
        # this API works asynchronously
        # it's recommended to check it really reset neighbor later

        def up():
            neigh_conf.enabled = True
        hub.spawn_after(NEIGHBOR_RESET_WAIT_TIME, up)
    else:
        raise RuntimeConfigError('Neighbor %s is not enabled, hence cannot'
                                 ' reset.' % ip_address)
    return True


# =============================================================================
# Common configuration related APIs
# =============================================================================

@register(name='comm_conf.get')
def get_common_conf():
    comm_conf = CORE_MANAGER.common_conf
    return comm_conf.settings
