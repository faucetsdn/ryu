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

import glob
import inspect
import os.path

from ryu import utils


_OFPROTO_DIR = os.path.dirname(__file__)

_OFPROTO_PARSER_FILE_NAMES = glob.glob(os.path.join(
    _OFPROTO_DIR, 'ofproto_v[0-9]*_[0-9]*_parser.py*'))
_OFPROTO_PARSER_FILE_NAMES = [os.path.basename(name)
                              for name in _OFPROTO_PARSER_FILE_NAMES]


_OFPROTO_MODULES = {}
for parser_file_name in _OFPROTO_PARSER_FILE_NAMES:
    # drop tailing '.py*'
    parser_mod_name = __name__ + '.' + \
        '.'.join(parser_file_name.split('.')[:-1])
    consts_mod_name = parser_mod_name[:-7]      # drop trailing '_parser'
    try:
        parser_mod = utils.import_module(parser_mod_name)
        consts_mod = utils.import_module(consts_mod_name)
    except:
        continue

    if consts_mod.OFP_VERSION not in _OFPROTO_MODULES:
        _OFPROTO_MODULES[consts_mod.OFP_VERSION] = (consts_mod, parser_mod)


def get_ofp_modules():
    """get modules pair for the constants and parser of OF-wire of
    a given OF version.
    """
    return _OFPROTO_MODULES


def get_ofp_module(ofp_version):
    """get modules pair for the constants and parser of OF-wire of
    a given OF version.
    """
    return _OFPROTO_MODULES[ofp_version]


def get_ofp_cls(ofp_version, name):
    """get class for name of a given OF version"""
    (_consts_mod, parser_mod) = get_ofp_module(ofp_version)
    for i in inspect.getmembers(parser_mod, inspect.isclass):
        if i[0] == name:
            return i[1]
    return None
