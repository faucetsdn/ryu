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
from ryu.services.protocols.bgp.api.base import register
from ryu.services.protocols.bgp.api.rpc_log_handler import RpcLogHandler
from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.commands.clear import ClearCmd
from ryu.services.protocols.bgp.operator.commands.set import SetCmd
from ryu.services.protocols.bgp.operator.commands.show import ShowCmd
from ryu.services.protocols.bgp.operator.internal_api import InternalApi

LOG = logging.getLogger('bgpspeaker.api.rtconf')

DEFAULT_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'


def _init_log_handler():
    log_handler = RpcLogHandler()
    log_handler.setLevel(logging.ERROR)
    log_handler.formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    return log_handler


INTERNAL_API = InternalApi(_init_log_handler())


class RootCmd(Command):
    subcommands = {
        'show': ShowCmd,
        'set': SetCmd,
        'clear': ClearCmd}


def operator_run(cmd, **kwargs):
    params = kwargs.get('params', [])
    fmt = kwargs.get('format', 'json')
    root = RootCmd(api=INTERNAL_API, resp_formatter_name=fmt)
    ret, _ = root([cmd] + params)
    if ret.status == STATUS_ERROR:
        raise ApiException(str(ret.value))
    return ret.value


@register(name="operator.show")
def operator_show(**kwargs):
    return operator_run('show', **kwargs)


@register(name="operator.set")
def operator_set(**kwargs):
    return operator_run('set', **kwargs)


@register(name="operator.clear")
def operator_clear(**kwargs):
    return operator_run('clear', **kwargs)
