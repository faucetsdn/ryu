# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# NOTE: this file is intendend to be replaced with mechanically generated
# file if/when OF-Config yang specification is available with a suitable
# license.

from ryu.lib.of_config.base import _Base, _e, _ct


class OFPortConfigurationType(_Base):
    _ELEMENTS = [
        _e('admin-state', is_list=False),
        _e('no-receive', is_list=False),
        _e('no-forward', is_list=False),
        _e('no-packet-in', is_list=False),
    ]


class OFPortStateType(_Base):
    _ELEMENTS = [
        _e('oper-state', is_list=False),
        _e('blocked', is_list=False),
        _e('live', is_list=False),
    ]


class OFPortType(_Base):
    _ELEMENTS = [
        _e('resource-id', is_list=False),
        _e('number', is_list=False),
        _e('name', is_list=False),
        _e('current-rate', is_list=False),
        _e('max-rate', is_list=False),
        _ct('configuration', OFPortConfigurationType, is_list=False),
        _ct('state', OFPortStateType, is_list=False),
        _ct('features', None, is_list=False),
        _ct('tunnel-type', None, is_list=False),
    ]


class OFQueuePropertiesType(_Base):
    _ELEMENTS = [
        _e('min-rate', is_list=False),
        _e('max-rate', is_list=False),
        _e('experimenter', is_list=True),
    ]


class OFQueueType(_Base):
    _ELEMENTS = [
        _e('resource-id', is_list=False),
        _e('id', is_list=False),
        _e('port', is_list=False),
        _ct('properties', OFQueuePropertiesType, is_list=False),
    ]


class OFCapableSwitchResourcesType(_Base):
    _ELEMENTS = [
        _ct('port', OFPortType, is_list=True),
        _ct('queue', OFQueueType, is_list=True),
        _ct('owned-certificate', None, is_list=True),
        _ct('external-certificate', None, is_list=True),
        _ct('flow-table', None, is_list=True),
    ]


class OFControllerStateType(_Base):
    _ELEMENTS = [
        _e('connection-state', is_list=False),
        _e('current-version', is_list=False),

        # XXX OF-Config 1.1.1 is inconsistent about supported-versions.
        #
        # according to its xml schema (p.43), i believe this should look
        # like the following.  it's what linc/of_config does, too.
        #     <supported-versions>1.3</supported-versions>
        #
        # on the other hand, it has an example (p.45) like the following.
        # this one is compatible with OF-Config 1.1.
        #     <supported-versions>
        #         <version>1.2</version>
        #         <version>1.1</version>
        #     </supported-versions>

        _e('supported-versions', is_list=True),
        _e('local-ip-address-in-use', is_list=False),
        _e('local-port-in-use', is_list=False),
    ]


class OFControllerType(_Base):
    _ELEMENTS = [
        _e('id', is_list=False),
        _e('role', is_list=False),
        _e('ip-address', is_list=False),
        _e('port', is_list=False),
        _e('local-ip-address', is_list=False),
        _e('local-port', is_list=False),
        _e('protocol', is_list=False),
        _ct('state', OFControllerStateType, is_list=False),
    ]


class OFLogicalSwitchControllersType(_Base):
    _ELEMENTS = [
        _ct('controller', OFControllerType, is_list=True),
    ]


class OFLogicalSwitchResourcesType(_Base):
    _ELEMENTS = [
        _e('port', is_list=True),
        _e('queue', is_list=True),
        _e('certificate', is_list=False),
        _e('flow-table', is_list=True),
    ]


class OFLogicalSwitchType(_Base):
    _ELEMENTS = [
        _e('id', is_list=False),
        _ct('capabilities', None, is_list=False),
        _e('datapath-id', is_list=False),
        _e('enabled', is_list=False),
        _e('check-controller-certificate', is_list=False),
        _e('lost-connection-behavior', is_list=False),
        _ct('controllers', OFLogicalSwitchControllersType, is_list=False),
        _ct('resources', OFLogicalSwitchResourcesType, is_list=False),
    ]


class OFCapableSwitchLogicalSwitchesType(_Base):
    _ELEMENTS = [
        # this is named 'logical-switch' for OF-Config 1.1.
        _ct('switch', OFLogicalSwitchType, is_list=True),
    ]


class OFCapableSwitchType(_Base):
    _ELEMENTS = [
        _e('id', is_list=False),
        _e('config-version', is_list=False),
        _ct('configuration-points', None, is_list=False),
        _ct('resources', OFCapableSwitchResourcesType, is_list=False),
        _ct('logical-switches', OFCapableSwitchLogicalSwitchesType,
            is_list=False),
    ]
