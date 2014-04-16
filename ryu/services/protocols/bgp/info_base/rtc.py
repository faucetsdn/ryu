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
 Defines data types and models required specifically for RTC support.
"""

import logging

from ryu.lib.packet.bgp import RF_RTC_UC

from ryu.services.protocols.bgp.info_base.base import Destination
from ryu.services.protocols.bgp.info_base.base import NonVrfPathProcessingMixin
from ryu.services.protocols.bgp.info_base.base import Path
from ryu.services.protocols.bgp.info_base.base import Table

LOG = logging.getLogger('bgpspeaker.info_base.rtc')


class RtcTable(Table):
    """Global table to store RT membership information.

    Uses `RtDest` to store destination information for each known RT NLRI path.
    """
    ROUTE_FAMILY = RF_RTC_UC

    def __init__(self, core_service, signal_bus):
        Table.__init__(self, None, core_service, signal_bus)

    def _table_key(self, rtc_nlri):
        """Return a key that will uniquely identify this RT NLRI inside
        this table.
        """
        return str(rtc_nlri.origin_as) + ':' + rtc_nlri.route_target

    def _create_dest(self, nlri):
        return RtcDest(self, nlri)

    def __str__(self):
        return 'RtcTable(scope_id: %s, rf: %s)' % (self.scope_id,
                                                   self.route_family)


class RtcDest(Destination, NonVrfPathProcessingMixin):
    ROUTE_FAMILY = RF_RTC_UC

    def _new_best_path(self, new_best_path):
        NonVrfPathProcessingMixin._new_best_path(self, new_best_path)

    def _best_path_lost(self):
        NonVrfPathProcessingMixin._best_path_lost(self)


class RtcPath(Path):
    ROUTE_FAMILY = RF_RTC_UC

    def __init__(self, source, nlri, src_ver_num, pattrs=None,
                 nexthop='0.0.0.0', is_withdraw=False,
                 med_set_by_target_neighbor=False):
        Path.__init__(self, source, nlri, src_ver_num, pattrs, nexthop,
                      is_withdraw, med_set_by_target_neighbor)
