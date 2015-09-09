# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

import re


def generate(modname):
    import sys
    import functools

    mod = sys.modules[modname]

    def add_attr(k, v):
        setattr(mod, k, v)

    add_attr('ofp_msg_type_to_str',
             functools.partial(_msg_type_to_str, mod))
    add_attr('ofp_error_type_to_str',
             functools.partial(_error_type_to_str, mod))
    add_attr('ofp_error_code_to_str',
             functools.partial(_error_code_to_str, mod))
    add_attr('ofp_error_to_jsondict',
             functools.partial(_error_to_jsondict, mod))


def _get_value_name(mod, value, pattern):
    for k, v in mod.__dict__.items():
        if k.startswith(pattern):
            if v == value:
                return k
    return 'Unknown'


def _msg_type_to_str(mod, type_):
    """
    This method is registered as ofp_msg_type_to_str(type_) method
    into ryu.ofproto.ofproto_v1_* modules.
    And this method returns the message type as a string value for given
    'type' defined in ofp_type enum.

    Example::

        >>> ofproto.ofp_msg_type_to_str(14)
        'OFPT_FLOW_MOD(14)'
    """
    return '%s(%d)' % (_get_value_name(mod, type_, 'OFPT_'), type_)


def _error_type_to_str(mod, type_):
    """
    This method is registered as ofp_error_type_to_str(type_) method
    into ryu.ofproto.ofproto_v1_* modules.
    And this method returns the error type as a string value for given
    'type' defined in ofp_error_msg structure.

    Example::

        >>> ofproto.ofp_error_type_to_str(4)
        'OFPET_BAD_MATCH(4)'
    """
    return '%s(%d)' % (_get_value_name(mod, type_, 'OFPET_'), type_)


def _get_error_names(mod, type_, code):
    t_name = _get_value_name(mod, type_, 'OFPET_')
    if t_name == 'Unknown':
        return 'Unknown', 'Unknown'
    # Construct error code name pattern
    # e.g.) "OFPET_BAD_MATCH" -> "OFPBMC_"
    if t_name == 'OFPET_FLOW_MONITOR_FAILED':
        c_name_p = 'OFPMOFC_'
    else:
        c_name_p = 'OFP'
        for m in re.findall("_(.)", t_name):
            c_name_p += m.upper()
        c_name_p += 'C_'
    c_name = _get_value_name(mod, code, c_name_p)
    return t_name, c_name


def _error_code_to_str(mod, type_, code):
    """
    This method is registered as ofp_error_code_to_str(type_, code) method
    into ryu.ofproto.ofproto_v1_* modules.
    And this method returns the error code as a string value for given
    'type' and 'code' defined in ofp_error_msg structure.

    Example::

        >>> ofproto.ofp_error_code_to_str(4, 9)
        'OFPBMC_BAD_PREREQ(9)'
    """
    (_, c_name) = _get_error_names(mod, type_, code)
    return '%s(%d)' % (c_name, code)


def _error_to_jsondict(mod, type_, code):
    """
    This method is registered as ofp_error_to_jsondict(type_, code) method
    into ryu.ofproto.ofproto_v1_* modules.
    And this method returns ofp_error_msg as a json format for given
    'type' and 'code' defined in ofp_error_msg structure.

    Example::

        >>> ofproto.ofp_error_to_jsondict(4, 9)
        {'code': 'OFPBMC_BAD_PREREQ(9)', 'type': 'OFPET_BAD_MATCH(4)'}
    """
    (t_name, c_name) = _get_error_names(mod, type_, code)
    return {'type': '%s(%d)' % (t_name, type_),
            'code': '%s(%d)' % (c_name, code)}
