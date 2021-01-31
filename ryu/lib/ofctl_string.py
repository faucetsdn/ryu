# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

import ryu.exception
from ryu.lib.ofctl_utils import str_to_int
from ryu.ofproto import nicira_ext


def ofp_instruction_from_str(ofproto, action_str):
    """
    Parse an ovs-ofctl style action string and return a list of
    jsondict representations of OFPInstructionActions, which
    can then be passed to ofproto_parser.ofp_instruction_from_jsondict.

    Please note that this is for making transition from ovs-ofctl
    easier. Please consider using OFPAction constructors when writing
    new codes.

    This function takes the following arguments.

    =========== =================================================
    Argument    Description
    =========== =================================================
    ofproto     An ofproto module.
    action_str  An action string.
    =========== =================================================
    """
    action_re = re.compile(r"([a-z_]+)(\([^)]*\)|[^a-z_,()][^,()]*)*")
    result = []
    while len(action_str):
        m = action_re.match(action_str)
        if not m:
            raise ryu.exception.OFPInvalidActionString(action_str=action_str)
        action_name = m.group(1)
        this_action = m.group(0)
        paren_level = this_action.count('(') - this_action.count(')')
        assert paren_level >= 0
        try:
            # Parens can be nested. Look for as many ')'s as '('s.
            if paren_level > 0:
                this_action, rest = _tokenize_paren_block(action_str, m.end(0))
            else:
                rest = action_str[m.end(0):]
            if len(rest):
                assert rest[0] == ','
                rest = rest[1:]
        except Exception:
            raise ryu.exception.OFPInvalidActionString(action_str=action_str)
        if action_name == 'drop':
            assert this_action == 'drop'
            assert len(result) == 0 and rest == ''
            return []
        converter = getattr(OfctlActionConverter, action_name, None)
        if converter is None or not callable(converter):
            raise ryu.exception.OFPInvalidActionString(action_str=action_name)
        result.append(converter(ofproto, this_action))
        action_str = rest

    return result


def _tokenize_paren_block(string, pos):
    paren_re = re.compile("[()]")
    paren_level = string[:pos].count('(') - string[:pos].count(')')
    while paren_level > 0:
        m = paren_re.search(string[pos:])
        if m.group(0) == '(':
            paren_level += 1
        else:
            paren_level -= 1
        pos += m.end(0)
    return string[:pos], string[pos:]


def tokenize_ofp_instruction_arg(arg):
    """
    Tokenize an argument portion of ovs-ofctl style action string.
    """
    arg_re = re.compile("[^,()]*")
    try:
        rest = arg
        result = []
        while len(rest):
            m = arg_re.match(rest)
            if m.end(0) == len(rest):
                result.append(rest)
                return result
            if rest[m.end(0)] == '(':
                this_block, rest = _tokenize_paren_block(
                    rest, m.end(0) + 1)
                result.append(this_block)
            elif rest[m.end(0)] == ',':
                result.append(m.group(0))
                rest = rest[m.end(0):]
            else:  # is ')'
                raise Exception
            if len(rest):
                assert rest[0] == ','
                rest = rest[1:]
        return result
    except Exception:
        raise ryu.exception.OFPInvalidActionString(action_str=arg)


_OXM_FIELD_OFCTL_ALIASES = {
    'tun_id': 'tunnel_id',
    'in_port': 'in_port_nxm',
    'in_port_oxm': 'in_port',
    'dl_src': 'eth_src',
    'dl_type': 'eth_type',
    'nw_src': 'ipv4_src',
    'ip_src': 'ipv4_src',
    'nw_proto': 'ip_proto',
    'nw_ecn': 'ip_ecn',
    'tp_src': 'tcp_src',
    'icmp_type': 'icmpv4_type',
    'icmp_code': 'icmpv4_code',
    'nd_target': 'ipv6_nd_target',
    'nd_sll': 'ipv6_nd_sll',
    'nd_tll': 'ipv6_nd_tll',
    # Nicira extension
    'tun_src': 'tun_ipv4_src'
}


def ofp_ofctl_field_name_to_ryu(field):
    """Convert an ovs-ofctl field name to ryu equivalent."""
    mapped = _OXM_FIELD_OFCTL_ALIASES.get(field)
    if mapped:
        return mapped
    if field.endswith("_dst"):
        mapped = _OXM_FIELD_OFCTL_ALIASES.get(field[:-3] + "src")
        if mapped:
            return mapped[:-3] + "dst"
    return field


_NXM_FIELD_MAP = dict([(key, key + '_nxm') for key in [
    'arp_sha', 'arp_tha', 'ipv6_src', 'ipv6_dst',
    'icmpv6_type', 'icmpv6_code', 'ip_ecn', 'tcp_flags']])
_NXM_FIELD_MAP.update({
    'tun_id': 'tunnel_id_nxm', 'ip_ttl': 'nw_ttl'})

_NXM_OF_FIELD_MAP = dict([(key, key + '_nxm') for key in [
    'in_port', 'eth_dst', 'eth_src', 'eth_type', 'ip_proto',
    'tcp_src', 'tcp_dst', 'udp_src', 'udp_dst',
    'arp_op', 'arp_spa', 'arp_tpa']])
_NXM_OF_FIELD_MAP.update({
    'ip_src': 'ipv4_src_nxm', 'ip_dst': 'ipv4_dst_nxm',
    'icmp_type': 'icmpv4_type_nxm', 'icmp_code': 'icmpv4_code_nxm'})


def nxm_field_name_to_ryu(field):
    """
    Convert an ovs-ofctl style NXM_/OXM_ field name to
    a ryu match field name.
    """
    if field.endswith("_W"):
        field = field[:-2]
    prefix = field[:7]
    field = field[7:].lower()
    mapped_result = None

    if prefix == 'NXM_NX_':
        mapped_result = _NXM_FIELD_MAP.get(field)
    elif prefix == "NXM_OF_":
        mapped_result = _NXM_OF_FIELD_MAP.get(field)
    elif prefix == "OXM_OF_":
        # no mapping needed
        pass
    else:
        raise ValueError
    if mapped_result is not None:
        return mapped_result
    return field


class OfctlActionConverter(object):

    @classmethod
    def goto_table(cls, ofproto, action_str):
        assert action_str.startswith('goto_table:')
        table_id = str_to_int(action_str[len('goto_table:'):])
        return dict(OFPInstructionGotoTable={'table_id': table_id})

    @classmethod
    def normal(cls, ofproto, action_str):
        return cls.output(ofproto, action_str)

    @classmethod
    def output(cls, ofproto, action_str):
        if action_str == 'normal':
            port = ofproto.OFPP_NORMAL
        else:
            assert action_str.startswith('output:')
            port = str_to_int(action_str[len('output:'):])
        return dict(OFPActionOutput={'port': port})

    @classmethod
    def pop_vlan(cls, ofproto, action_str):
        return dict(OFPActionPopVlan={})

    @classmethod
    def set_field(cls, ofproto, action_str):
        try:
            assert action_str.startswith("set_field:")
            value, key = action_str[len("set_field:"):].split("->", 1)
            fieldarg = dict(field=ofp_ofctl_field_name_to_ryu(key))
            m = value.find('/')
            if m >= 0:
                fieldarg['value'] = str_to_int(value[:m])
                fieldarg['mask'] = str_to_int(value[m + 1:])
            else:
                fieldarg['value'] = str_to_int(value)
        except Exception:
            raise ryu.exception.OFPInvalidActionString(action_str=action_str)
        return dict(OFPActionSetField={
            'field': {'OXMTlv': fieldarg}})

    # NX actions
    @classmethod
    def resubmit(cls, ofproto, action_str):
        arg = action_str[len("resubmit"):]
        kwargs = {}
        try:
            if arg[0] == ':':
                kwargs['in_port'] = str_to_int(arg[1:])
            elif arg[0] == '(' and arg[-1] == ')':
                in_port, table_id = arg[1:-1].split(',')
                if in_port:
                    kwargs['in_port'] = str_to_int(in_port)
                if table_id:
                    kwargs['table_id'] = str_to_int(table_id)
            else:
                raise Exception
            return dict(NXActionResubmitTable=kwargs)
        except Exception:
            raise ryu.exception.OFPInvalidActionString(
                action_str=action_str)

    @classmethod
    def conjunction(cls, ofproto, action_str):
        try:
            assert action_str.startswith('conjunction(')
            assert action_str[-1] == ')'
            args = action_str[len('conjunction('):-1].split(',')
            assert len(args) == 2
            id_ = str_to_int(args[0])
            clauses = list(map(str_to_int, args[1].split('/')))
            assert len(clauses) == 2
            return dict(NXActionConjunction={
                'clause': clauses[0] - 1,
                'n_clauses': clauses[1],
                'id': id_})
        except Exception:
            raise ryu.exception.OFPInvalidActionString(
                action_str=action_str)

    @classmethod
    def ct(cls, ofproto, action_str):
        str_to_port = {'ftp': 21, 'tftp': 69}
        flags = 0
        zone_src = ""
        zone_ofs_nbits = 0
        recirc_table = nicira_ext.NX_CT_RECIRC_NONE
        alg = 0
        ct_actions = []

        if len(action_str) > 2:
            if (not action_str.startswith('ct(') or
                    action_str[-1] != ')'):
                raise ryu.exception.OFPInvalidActionString(
                    action_str=action_str)
            rest = tokenize_ofp_instruction_arg(action_str[len('ct('):-1])
        else:
            rest = []
        for arg in rest:
            if arg == 'commit':
                flags |= nicira_ext.NX_CT_F_COMMIT
                rest = rest[len('commit'):]
            elif arg == 'force':
                flags |= nicira_ext.NX_CT_F_FORCE
            elif arg.startswith('exec('):
                ct_actions = ofp_instruction_from_str(
                    ofproto, arg[len('exec('):-1])
            else:
                try:
                    k, v = arg.split('=', 1)
                    if k == 'table':
                        recirc_table = str_to_int(v)
                    elif k == 'zone':
                        m = re.search(r'\[(\d*)\.\.(\d*)\]', v)
                        if m:
                            zone_ofs_nbits = nicira_ext.ofs_nbits(
                                int(m.group(1)), int(m.group(2)))
                            zone_src = nxm_field_name_to_ryu(
                                v[:m.start(0)])
                        else:
                            zone_ofs_nbits = str_to_int(v)
                    elif k == 'alg':
                        alg = str_to_port[arg[len('alg='):]]
                except Exception:
                    raise ryu.exception.OFPInvalidActionString(
                        action_str=action_str)
        return dict(NXActionCT={'flags': flags,
                                'zone_src': zone_src,
                                'zone_ofs_nbits': zone_ofs_nbits,
                                'recirc_table': recirc_table,
                                'alg': alg,
                                'actions': ct_actions})

    @classmethod
    def ct_clear(cls, ofproto, action_str):
        return dict(NXActionCTClear={})
