# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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

from ryu.base import app_manager
from ryu.services.protocols.vrrp import event as vrrp_event


def vrrp_config(app, interface, config):
    """create an instance.
    returns EventVRRPConfigReply(instance.name, interface, config)
    on success.
    returns EventVRRPConfigReply(None, interface, config)
    on failure.
    """
    config_request = vrrp_event.EventVRRPConfigRequest(interface, config)
    config_request.sync = True
    return app.send_request(config_request)


def vrrp_shutdown(app, instance_name):
    """shutdown the instance.
    """
    shutdown_request = vrrp_event.EventVRRPShutdownRequest(instance_name)
    app.send_event(vrrp_event.VRRP_MANAGER_NAME, shutdown_request)


def vrrp_transmit(app, monitor_name, data):
    """transmit a packet from the switch.  this is internal use only.
    data is str-like, a packet to send.
    """
    transmit_request = vrrp_event.EventVRRPTransmitRequest(data)
    app.send_event(monitor_name, transmit_request)


def vrrp_list(app, instance_name=None):
    """list instances.
    returns EventVRRPListReply([VRRPInstance]).
    """
    list_request = vrrp_event.EventVRRPListRequest(instance_name)
    list_request.dst = vrrp_event.VRRP_MANAGER_NAME
    return app.send_request(list_request)


def vrrp_config_change(app, instance_name,
                       priority=None, advertisement_interval=None,
                       preempt_mode=None, accept_mode=None):
    """change configuration of an instance.
    None means no change.
    """
    config_change = vrrp_event.EventVRRPConfigChangeRequest(
        instance_name, priority, advertisement_interval,
        preempt_mode, accept_mode)
    return app.send_event(vrrp_event.VRRP_MANAGER_NAME, config_change)


app_manager.require_app('ryu.services.protocols.vrrp.manager', api_style=True)
