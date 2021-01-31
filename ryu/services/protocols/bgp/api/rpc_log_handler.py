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
 Defined log handler to be used to log to RPC connection.
"""

import logging

from ryu.services.protocols.bgp.net_ctrl import NET_CONTROLLER
from ryu.services.protocols.bgp.net_ctrl import NOTIFICATION_LOG


class RpcLogHandler(logging.Handler):
    """Outputs log records to `NET_CONTROLLER`."""

    def emit(self, record):
        msg = self.format(record)
        NET_CONTROLLER.send_rpc_notification(
            NOTIFICATION_LOG,
            {
                'level': record.levelname,
                'msg': msg
            }
        )
