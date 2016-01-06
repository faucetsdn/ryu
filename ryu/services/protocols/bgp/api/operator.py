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
 Api for operator. Mainly commands to build CLI and
 operator interface around them.
"""
import logging

from ryu.services.protocols.bgp.api.base import ApiException
from ryu.services.protocols.bgp.api.base import register_class
from ryu.services.protocols.bgp.api.base import register_method
from ryu.services.protocols.bgp.api.rpc_log_handler import RpcLogHandler
from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.commands.clear import ClearCmd
from ryu.services.protocols.bgp.operator.commands.set import SetCmd
from ryu.services.protocols.bgp.operator.commands.show import ShowCmd
from ryu.services.protocols.bgp.operator.internal_api import InternalApi

LOG = logging.getLogger('bgpspeaker.api.rtconf')


class RootCmd(Command):
    subcommands = {
        'show': ShowCmd,
        'set': SetCmd,
        'clear': ClearCmd}


@register_class
class OperatorApi(object):
    default_log_format = '%(asctime)s %(levelname)s %(message)s'

    def __init__(self):
        self._init_log_handler()
        self.internal_api = InternalApi(self.log_handler)

    def _init_log_handler(self):
        self.log_handler = RpcLogHandler()
        self.log_handler.setLevel(logging.ERROR)
        self.log_handler.formatter = logging.Formatter(self.default_log_format)

    @register_method(name="operator.show")
    def show(self, **kwargs):
        return self._run('show', kw=kwargs)

    @register_method(name="operator.set")
    def set(self, **kwargs):
        return self._run('set', kw=kwargs)

    @register_method(name="operator.clear")
    def clear(self, **kwargs):
        return self._run('clear', kw=kwargs)

    def _run(self, cmd, kw=None):
        kw = kw if kw else {}
        params = kw.get('params', [])
        fmt = kw.get('format', 'json')
        root = RootCmd(api=self.internal_api, resp_formatter_name=fmt)
        ret, _ = root([cmd] + params)
        if ret.status == STATUS_ERROR:
            raise ApiException(str(ret.value))
        return ret.value

_OPERATOR_API = OperatorApi()
