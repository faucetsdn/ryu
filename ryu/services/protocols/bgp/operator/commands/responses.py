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
 Defines classes related to incorrect parameters.
"""
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.internal_api import WrongParamError


class WrongParamResp(object):
    def __new__(cls, e=None):
        return cls.wrong_param_resp_factory(e)

    @staticmethod
    def wrong_param_resp_factory(e=None):
        if not e:
            e = WrongParamError()
        desc = 'wrong parameters: %s' % str(e)

        return CommandsResponse(STATUS_ERROR, desc)
