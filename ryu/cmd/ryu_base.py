# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import argparse
import os.path
import sys

from ryu import cfg
from ryu import utils
from ryu import version


subcommands = {
    'run': 'ryu.cmd.manager',
    'of-config-cli': 'ryu.cmd.of_config_cli',
    'rpc-cli': 'ryu.cmd.rpc_cli',
}


class RemainderOpt(cfg.MultiStrOpt):
    def _get_argparse_kwargs(self, group, **kwargs):
        kwargs = cfg.MultiStrOpt._get_argparse_kwargs(self, group, **kwargs)
        kwargs['nargs'] = argparse.REMAINDER
        return kwargs


base_conf = cfg.ConfigOpts()
base_conf.register_cli_opt(cfg.StrOpt('subcommand', positional=True,
                                      required=True,
                                      help='[%s]' % '|'.join(
                                          list(subcommands.keys()))))
base_conf.register_cli_opt(RemainderOpt('subcommand_args', default=[],
                                        positional=True,
                                        help='subcommand specific arguments'))


class SubCommand(object):
    def __init__(self, name, entry):
        self.name = name
        self.entry = entry

    def run(self, args):
        prog = '%s %s' % (os.path.basename(sys.argv[0]), self.name,)
        self.entry(args=args, prog=prog)


def main():
    try:
        base_conf(project='ryu', version='ryu %s' % version)
    except cfg.RequiredOptError as e:
        base_conf.print_help()
        raise SystemExit(1)
    subcmd_name = base_conf.subcommand
    try:
        subcmd_mod_name = subcommands[subcmd_name]
    except KeyError:
        base_conf.print_help()
        raise SystemExit('Unknown subcommand %s' % subcmd_name)
    subcmd_mod = utils.import_module(subcmd_mod_name)
    subcmd = SubCommand(name=subcmd_name, entry=subcmd_mod.main)
    subcmd.run(base_conf.subcommand_args)
