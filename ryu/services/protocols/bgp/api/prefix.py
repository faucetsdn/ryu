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
 Prefix related APIs.
"""
import logging

from ryu.services.protocols.bgp.api.base import NEXT_HOP
from ryu.services.protocols.bgp.api.base import PREFIX
from ryu.services.protocols.bgp.api.base import RegisterWithArgChecks
from ryu.services.protocols.bgp.api.base import ROUTE_DISTINGUISHER
from ryu.services.protocols.bgp.api.base import VPN_LABEL
from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import PREFIX_ERROR_CODE
from ryu.services.protocols.bgp.base import validate
from ryu.services.protocols.bgp.core import BgpCoreError
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF
from ryu.services.protocols.bgp.rtconf.vrfs import VRF_RF_IPV4
from ryu.services.protocols.bgp.utils import validation


LOG = logging.getLogger('bgpspeaker.api.prefix')


@add_bgp_error_metadata(code=PREFIX_ERROR_CODE,
                        sub_code=1,
                        def_desc='Unknown error related to operation on '
                        'prefixes')
class PrefixError(RuntimeConfigError):
    pass


@validate(name=PREFIX)
def is_valid_prefix(ipv4_prefix):
    return validation.is_valid_ipv4_prefix(ipv4_prefix)


@validate(name=NEXT_HOP)
def is_valid_next_hop(next_hop_addr):
    return validation.is_valid_ipv4(next_hop_addr)


@RegisterWithArgChecks(name='prefix.add_local',
                       req_args=[ROUTE_DISTINGUISHER, PREFIX, NEXT_HOP],
                       opt_args=[VRF_RF])
def add_local(route_dist, prefix, next_hop, route_family=VRF_RF_IPV4):
    """Adds *prefix* from VRF identified by *route_dist* and sets the source as
    network controller.
    """
    try:
        # Create new path and insert into appropriate VRF table.
        tm = CORE_MANAGER.get_core_service().table_manager
        label = tm.add_to_vrf(route_dist, prefix, next_hop, route_family)
        # Currently we only allocate one label per local_prefix,
        # so we share first label from the list.
        if label:
            label = label[0]

        # Send success response with new label.
        return [{ROUTE_DISTINGUISHER: route_dist, PREFIX: prefix,
                 VRF_RF: route_family, VPN_LABEL: label}]
    except BgpCoreError as e:
        raise PrefixError(desc=e)


@RegisterWithArgChecks(name='prefix.delete_local',
                       req_args=[ROUTE_DISTINGUISHER, PREFIX],
                       opt_args=[VRF_RF])
def delete_local(route_dist, prefix, route_family=VRF_RF_IPV4):
    """Deletes/withdraws *prefix* from VRF identified by *route_dist* and
    source as network controller.
    """
    try:
        tm = CORE_MANAGER.get_core_service().table_manager
        tm.remove_from_vrf(route_dist, prefix, route_family)
        # Send success response to ApgwAgent.
        return [{ROUTE_DISTINGUISHER: route_dist, PREFIX: prefix,
                 VRF_RF: route_family}]
    except BgpCoreError as e:
        raise PrefixError(desc=e)
