# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging
import json

from webob import Response

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib import mac
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


# =============================
#          REST API
# =============================
#
#  Note: specify switch and vlan group, as follows.
#   {switch-id} : 'all' or switchID
#   {vlan-id}   : 'all' or vlanID
#
#

# about Firewall status
#
# get status of all firewall switches
# GET /firewall/module/status
#
# set enable the firewall switches
# PUT /firewall/module/enable/{switch-id}
#
# set disable the firewall switches
# PUT /firewall/module/disable/{switch-id}
#

# about Firewall logs
#
# get log status of all firewall switches
# GET /firewall/log/status
#
# set log enable the firewall switches
# PUT /firewall/log/enable/{switch-id}
#
# set log disable the firewall switches
# PUT /firewall/log/disable/{switch-id}
#

# about Firewall rules
#
# get rules of the firewall switches
# * for no vlan
# GET /firewall/rules/{switch-id}
#
# * for specific vlan group
# GET /firewall/rules/{switch-id}/{vlan-id}
#
#
# set a rule to the firewall switches
# * for no vlan
# POST /firewall/rules/{switch-id}
#
# * for specific vlan group
# POST /firewall/rules/{switch-id}/{vlan-id}
#
#  request body format:
#   {"<field1>":"<value1>", "<field2>":"<value2>",...}
#
#     <field>  : <value>
#    "priority": "0 to 65533"
#    "in_port" : "<int>"
#    "dl_src"  : "<xx:xx:xx:xx:xx:xx>"
#    "dl_dst"  : "<xx:xx:xx:xx:xx:xx>"
#    "dl_type" : "<ARP or IPv4 or IPv6>"
#    "nw_src"  : "<A.B.C.D/M>"
#    "nw_dst"  : "<A.B.C.D/M>"
#    "ipv6_src": "<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/M>"
#    "ipv6_dst": "<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/M>"
#    "nw_proto": "<TCP or UDP or ICMP or ICMPv6>"
#    "tp_src"  : "<int>"
#    "tp_dst"  : "<int>"
#    "actions" : "<ALLOW or DENY>"
#
#   Note: specifying nw_src/nw_dst
#         without specifying dl-type as "ARP" or "IPv4"
#         will automatically set dl-type as "IPv4".
#
#   Note: specifying ipv6_src/ipv6_dst
#         without specifying dl-type as "IPv6"
#         will automatically set dl-type as "IPv6".
#
#   Note: When "priority" has not been set up,
#         "0" is set to "priority".
#
#   Note: When "actions" has not been set up,
#         "ALLOW" is set to "actions".
#
#
# delete a rule of the firewall switches from ruleID
# * for no vlan
# DELETE /firewall/rules/{switch-id}
#
# * for specific vlan group
# DELETE /firewall/rules/{switch-id}/{vlan-id}
#
#  request body format:
#   {"<field>":"<value>"}
#
#     <field>  : <value>
#    "rule_id" : "<int>" or "all"
#


SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_VLANID = 'vlan_id'
REST_RULE_ID = 'rule_id'
REST_STATUS = 'status'
REST_LOG_STATUS = 'log_status'
REST_STATUS_ENABLE = 'enable'
REST_STATUS_DISABLE = 'disable'
REST_COMMAND_RESULT = 'command_result'
REST_ACL = 'access_control_list'
REST_RULES = 'rules'
REST_COOKIE = 'cookie'
REST_PRIORITY = 'priority'
REST_MATCH = 'match'
REST_IN_PORT = 'in_port'
REST_SRC_MAC = 'dl_src'
REST_DST_MAC = 'dl_dst'
REST_DL_TYPE = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_DL_TYPE_IPV6 = 'IPv6'
REST_DL_VLAN = 'dl_vlan'
REST_SRC_IP = 'nw_src'
REST_DST_IP = 'nw_dst'
REST_SRC_IPV6 = 'ipv6_src'
REST_DST_IPV6 = 'ipv6_dst'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_NW_PROTO_ICMPV6 = 'ICMPv6'
REST_TP_SRC = 'tp_src'
REST_TP_DST = 'tp_dst'
REST_ACTION = 'actions'
REST_ACTION_ALLOW = 'ALLOW'
REST_ACTION_DENY = 'DENY'
REST_ACTION_PACKETIN = 'PACKETIN'


STATUS_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX
ARP_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX - 1
LOG_FLOW_PRIORITY = 0
ACL_FLOW_PRIORITY_MIN = LOG_FLOW_PRIORITY + 1
ACL_FLOW_PRIORITY_MAX = ofproto_v1_3_parser.UINT16_MAX - 2

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094
COOKIE_SHIFT_VLANID = 32


class RestFirewallAPI(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestFirewallAPI, self).__init__(*args, **kwargs)

        # logger configure
        FirewallController.set_logger(self.logger)

        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters

        mapper = wsgi.mapper
        wsgi.registory['FirewallController'] = self.data
        path = '/firewall'
        requirements = {'switchid': SWITCHID_PATTERN,
                        'vlanid': VLANID_PATTERN}

        # for firewall status
        uri = path + '/module/status'
        mapper.connect('firewall', uri,
                       controller=FirewallController, action='get_status',
                       conditions=dict(method=['GET']))

        uri = path + '/module/enable/{switchid}'
        mapper.connect('firewall', uri,
                       controller=FirewallController, action='set_enable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        uri = path + '/module/disable/{switchid}'
        mapper.connect('firewall', uri,
                       controller=FirewallController, action='set_disable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        # for firewall logs
        uri = path + '/log/status'
        mapper.connect('firewall', uri,
                       controller=FirewallController, action='get_log_status',
                       conditions=dict(method=['GET']))

        uri = path + '/log/enable/{switchid}'
        mapper.connect('firewall', uri,
                       controller=FirewallController, action='set_log_enable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        uri = path + '/log/disable/{switchid}'
        mapper.connect('firewall', uri,
                       controller=FirewallController, action='set_log_disable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        # for no VLAN data
        uri = path + '/rules/{switchid}'
        mapper.connect('firewall', uri,
                       controller=FirewallController, action='get_rules',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('firewall', uri,
                       controller=FirewallController, action='set_rule',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('firewall', uri,
                       controller=FirewallController, action='delete_rule',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)

        # for VLAN data
        uri += '/{vlanid}'
        mapper.connect('firewall', uri, controller=FirewallController,
                       action='get_vlan_rules',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('firewall', uri, controller=FirewallController,
                       action='set_vlan_rule',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('firewall', uri, controller=FirewallController,
                       action='delete_vlan_rule',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            FirewallController.regist_ofs(ev.dp)
        else:
            FirewallController.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        FirewallController.packet_in_handler(ev.msg)


class FirewallOfsList(dict):
    def __init__(self):
        super(FirewallOfsList, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('firewall sw is not connected.')

        dps = {}
        if dp_id == REST_ALL:
            dps = self
        else:
            try:
                dpid = dpid_lib.str_to_dpid(dp_id)
            except:
                raise ValueError('Invalid switchID.')

            if dpid in self:
                dps = {dpid: self[dpid]}
            else:
                msg = 'firewall sw is not connected. : switchID=%s' % dp_id
                raise ValueError(msg)

        return dps


class FirewallController(ControllerBase):

    _OFS_LIST = FirewallOfsList()
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[FW][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @staticmethod
    def regist_ofs(dp):
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        try:
            f_ofs = Firewall(dp)
        except OFPUnknownVersion as message:
            FirewallController._LOGGER.info('dpid=%s: %s',
                                            dpid_str, message)
            return

        FirewallController._OFS_LIST.setdefault(dp.id, f_ofs)

        f_ofs.set_disable_flow()
        f_ofs.set_arp_flow()
        f_ofs.set_log_enable()
        FirewallController._LOGGER.info('dpid=%s: Join as firewall.',
                                        dpid_str)

    @staticmethod
    def unregist_ofs(dp):
        if dp.id in FirewallController._OFS_LIST:
            del FirewallController._OFS_LIST[dp.id]
            FirewallController._LOGGER.info('dpid=%s: Leave firewall.',
                                            dpid_lib.dpid_to_str(dp.id))

    # GET /firewall/module/status
    def get_status(self, req, **_kwargs):
        return self._access_module(REST_ALL, 'get_status',
                                   waiters=self.waiters)

    # POST /firewall/module/enable/{switchid}
    def set_enable(self, req, switchid, **_kwargs):
        return self._access_module(switchid, 'set_enable_flow')

    # POST /firewall/module/disable/{switchid}
    def set_disable(self, req, switchid, **_kwargs):
        return self._access_module(switchid, 'set_disable_flow')

    # GET /firewall/log/status
    def get_log_status(self, dummy, **_kwargs):
        return self._access_module(REST_ALL, 'get_log_status',
                                   waiters=self.waiters)

    # PUT /firewall/log/enable/{switchid}
    def set_log_enable(self, dummy, switchid, **_kwargs):
        return self._access_module(switchid, 'set_log_enable',
                                   waiters=self.waiters)

    # PUT /firewall/log/disable/{switchid}
    def set_log_disable(self, dummy, switchid, **_kwargs):
        return self._access_module(switchid, 'set_log_disable',
                                   waiters=self.waiters)

    def _access_module(self, switchid, func, waiters=None):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            function = getattr(f_ofs, func)
            msg = function() if waiters is None else function(waiters)
            msgs.append(msg)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # GET /firewall/rules/{switchid}
    def get_rules(self, req, switchid, **_kwargs):
        return self._get_rules(switchid)

    # GET /firewall/rules/{switchid}/{vlanid}
    def get_vlan_rules(self, req, switchid, vlanid, **_kwargs):
        return self._get_rules(switchid, vlan_id=vlanid)

    # POST /firewall/rules/{switchid}
    def set_rule(self, req, switchid, **_kwargs):
        return self._set_rule(req, switchid)

    # POST /firewall/rules/{switchid}/{vlanid}
    def set_vlan_rule(self, req, switchid, vlanid, **_kwargs):
        return self._set_rule(req, switchid, vlan_id=vlanid)

    # DELETE /firewall/rules/{switchid}
    def delete_rule(self, req, switchid, **_kwargs):
        return self._delete_rule(req, switchid)

    # DELETE /firewall/rules/{switchid}/{vlanid}
    def delete_vlan_rule(self, req, switchid, vlanid, **_kwargs):
        return self._delete_rule(req, switchid, vlan_id=vlanid)

    def _get_rules(self, switchid, vlan_id=VLANID_NONE):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = FirewallController._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            rules = f_ofs.get_rules(self.waiters, vid)
            msgs.append(rules)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    def _set_rule(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            rule = req.json if req.body else {}
        except ValueError:
            FirewallController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = FirewallController._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_rule(rule, self.waiters, vid)
                msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    def _delete_rule(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            ruleid = req.json if req.body else {}
        except ValueError:
            FirewallController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = FirewallController._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.delete_rule(ruleid, self.waiters, vid)
                msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    @staticmethod
    def _conv_toint_vlanid(vlan_id):
        if vlan_id != REST_ALL:
            vlan_id = int(vlan_id)
            if (vlan_id != VLANID_NONE and
                    (vlan_id < VLANID_MIN or VLANID_MAX < vlan_id)):
                msg = 'Invalid {vlan_id} value. Set [%d-%d]' % (VLANID_MIN,
                                                                VLANID_MAX)
                raise ValueError(msg)
        return vlan_id

    @staticmethod
    def packet_in_handler(msg):
        pkt = packet.Packet(msg.data)
        dpid_str = dpid_lib.dpid_to_str(msg.datapath.id)
        FirewallController._LOGGER.info('dpid=%s: Blocked packet = %s',
                                        dpid_str, pkt)


class Firewall(object):

    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, dp):
        super(Firewall, self).__init__()
        self.vlan_list = {}
        self.vlan_list[VLANID_NONE] = 0  # for VLAN=None
        self.dp = dp
        version = dp.ofproto.OFP_VERSION

        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)

        self.ofctl = self._OFCTL[version]

    def _update_vlan_list(self, vlan_list):
        for vlan_id in self.vlan_list.keys():
            if vlan_id is not VLANID_NONE and vlan_id not in vlan_list:
                del self.vlan_list[vlan_id]

    def _get_cookie(self, vlan_id):
        if vlan_id == REST_ALL:
            vlan_ids = self.vlan_list.keys()
        else:
            vlan_ids = [vlan_id]

        cookie_list = []
        for vlan_id in vlan_ids:
            self.vlan_list.setdefault(vlan_id, 0)
            self.vlan_list[vlan_id] += 1
            self.vlan_list[vlan_id] &= ofproto_v1_3_parser.UINT32_MAX
            cookie = (vlan_id << COOKIE_SHIFT_VLANID) + \
                self.vlan_list[vlan_id]
            cookie_list.append([cookie, vlan_id])

        return cookie_list

    @staticmethod
    def _cookie_to_ruleid(cookie):
        return cookie & ofproto_v1_3_parser.UINT32_MAX

    # REST command template
    def rest_command(func):
        def _rest_command(*args, **kwargs):
            key, value = func(*args, **kwargs)
            switch_id = dpid_lib.dpid_to_str(args[0].dp.id)
            return {REST_SWITCHID: switch_id,
                    key: value}
        return _rest_command

    @rest_command
    def get_status(self, waiters):
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)

        status = REST_STATUS_ENABLE
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                if flow_stat['priority'] == STATUS_FLOW_PRIORITY:
                    status = REST_STATUS_DISABLE

        return REST_STATUS, status

    @rest_command
    def set_disable_flow(self):
        cookie = 0
        priority = STATUS_FLOW_PRIORITY
        match = {}
        actions = []
        flow = self._to_of_flow(cookie=cookie, priority=priority,
                                match=match, actions=actions)

        cmd = self.dp.ofproto.OFPFC_ADD
        self.ofctl.mod_flow_entry(self.dp, flow, cmd)

        msg = {'result': 'success',
               'details': 'firewall stopped.'}
        return REST_COMMAND_RESULT, msg

    @rest_command
    def set_enable_flow(self):
        cookie = 0
        priority = STATUS_FLOW_PRIORITY
        match = {}
        actions = []
        flow = self._to_of_flow(cookie=cookie, priority=priority,
                                match=match, actions=actions)

        cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
        self.ofctl.mod_flow_entry(self.dp, flow, cmd)

        msg = {'result': 'success',
               'details': 'firewall running.'}
        return REST_COMMAND_RESULT, msg

    @rest_command
    def get_log_status(self, waiters):
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)

        status = REST_STATUS_DISABLE
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                if flow_stat['priority'] == LOG_FLOW_PRIORITY:
                    if flow_stat['actions']:
                        status = REST_STATUS_ENABLE

        return REST_LOG_STATUS, status

    @rest_command
    def set_log_disable(self, waiters=None):
        return self._set_log_status(False, waiters)

    @rest_command
    def set_log_enable(self, waiters=None):
        return self._set_log_status(True, waiters)

    def _set_log_status(self, is_enable, waiters):
        if is_enable:
            actions = Action.to_openflow(self.dp,
                                         {REST_ACTION: REST_ACTION_PACKETIN})
            details = 'Log collection started.'
        else:
            actions = []
            details = 'Log collection stopped.'

        cmd = self.dp.ofproto.OFPFC_ADD

        if waiters:
            msgs = self.ofctl.get_flow_stats(self.dp, waiters)

            if str(self.dp.id) in msgs:
                flow_stats = msgs[str(self.dp.id)]
                for flow_stat in flow_stats:
                    priority = flow_stat[REST_PRIORITY]
                    if (priority == STATUS_FLOW_PRIORITY
                            or priority == ARP_FLOW_PRIORITY):
                        continue
                    action = flow_stat[REST_ACTION]
                    if action == ['OUTPUT:%d' % self.dp.ofproto.OFPP_NORMAL]:
                        continue

                    cookie = flow_stat[REST_COOKIE]
                    match = Match.to_mod_openflow(flow_stat[REST_MATCH])
                    flow = self._to_of_flow(cookie=cookie, priority=priority,
                                            match=match, actions=actions)
                    self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        else:
            # Initialize.
            flow = self._to_of_flow(cookie=0, priority=LOG_FLOW_PRIORITY,
                                    match={}, actions=actions)
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)

        msg = {'result': 'success',
               'details': details}
        return REST_COMMAND_RESULT, msg

    def set_arp_flow(self):
        cookie = 0
        priority = ARP_FLOW_PRIORITY
        match = {REST_DL_TYPE: ether.ETH_TYPE_ARP}
        action = {REST_ACTION: REST_ACTION_ALLOW}
        actions = Action.to_openflow(self.dp, action)
        flow = self._to_of_flow(cookie=cookie, priority=priority,
                                match=match, actions=actions)

        cmd = self.dp.ofproto.OFPFC_ADD
        self.ofctl.mod_flow_entry(self.dp, flow, cmd)

    @rest_command
    def set_rule(self, rest, waiters, vlan_id):
        msgs = []
        cookie_list = self._get_cookie(vlan_id)
        for cookie, vid in cookie_list:
            msg = self._set_rule(cookie, rest, waiters, vid)
            msgs.append(msg)
        return REST_COMMAND_RESULT, msgs

    def _set_rule(self, cookie, rest, waiters, vlan_id):
        priority = int(rest.get(REST_PRIORITY, ACL_FLOW_PRIORITY_MIN))

        if (priority < ACL_FLOW_PRIORITY_MIN
                or ACL_FLOW_PRIORITY_MAX < priority):
            raise ValueError('Invalid priority value. Set [%d-%d]'
                             % (ACL_FLOW_PRIORITY_MIN, ACL_FLOW_PRIORITY_MAX))

        if vlan_id:
            rest[REST_DL_VLAN] = vlan_id

        match = Match.to_openflow(rest)
        if rest.get(REST_ACTION) == REST_ACTION_DENY:
            result = self.get_log_status(waiters)
            if result[REST_LOG_STATUS] == REST_STATUS_ENABLE:
                rest[REST_ACTION] = REST_ACTION_PACKETIN
        actions = Action.to_openflow(self.dp, rest)
        flow = self._to_of_flow(cookie=cookie, priority=priority,
                                match=match, actions=actions)

        cmd = self.dp.ofproto.OFPFC_ADD
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        rule_id = Firewall._cookie_to_ruleid(cookie)
        msg = {'result': 'success',
               'details': 'Rule added. : rule_id=%d' % rule_id}

        if vlan_id != VLANID_NONE:
            msg.setdefault(REST_VLANID, vlan_id)
        return msg

    @rest_command
    def get_rules(self, waiters, vlan_id):
        rules = {}
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)

        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                priority = flow_stat[REST_PRIORITY]
                if (priority != STATUS_FLOW_PRIORITY
                        and priority != ARP_FLOW_PRIORITY
                        and priority != LOG_FLOW_PRIORITY):
                    vid = flow_stat[REST_MATCH].get(REST_DL_VLAN, VLANID_NONE)
                    if vlan_id == REST_ALL or vlan_id == vid:
                        rule = self._to_rest_rule(flow_stat)
                        rules.setdefault(vid, [])
                        rules[vid].append(rule)

        get_data = []
        for vid, rule in rules.items():
            if vid == VLANID_NONE:
                vid_data = {REST_RULES: rule}
            else:
                vid_data = {REST_VLANID: vid, REST_RULES: rule}
            get_data.append(vid_data)

        return REST_ACL, get_data

    @rest_command
    def delete_rule(self, rest, waiters, vlan_id):
        try:
            if rest[REST_RULE_ID] == REST_ALL:
                rule_id = REST_ALL
            else:
                rule_id = int(rest[REST_RULE_ID])
        except:
            raise ValueError('Invalid ruleID.')

        vlan_list = []
        delete_list = []

        msgs = self.ofctl.get_flow_stats(self.dp, waiters)
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                cookie = flow_stat[REST_COOKIE]
                ruleid = Firewall._cookie_to_ruleid(cookie)
                priority = flow_stat[REST_PRIORITY]
                dl_vlan = flow_stat[REST_MATCH].get(REST_DL_VLAN, VLANID_NONE)

                if (priority != STATUS_FLOW_PRIORITY
                        and priority != ARP_FLOW_PRIORITY
                        and priority != LOG_FLOW_PRIORITY):
                    if ((rule_id == REST_ALL or rule_id == ruleid) and
                            (vlan_id == dl_vlan or vlan_id == REST_ALL)):
                        match = Match.to_mod_openflow(flow_stat[REST_MATCH])
                        delete_list.append([cookie, priority, match])
                    else:
                        if dl_vlan not in vlan_list:
                            vlan_list.append(dl_vlan)

        self._update_vlan_list(vlan_list)

        if len(delete_list) == 0:
            msg_details = 'Rule is not exist.'
            if rule_id != REST_ALL:
                msg_details += ' : ruleID=%d' % rule_id
            msg = {'result': 'failure',
                   'details': msg_details}
        else:
            cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
            actions = []
            delete_ids = {}
            for cookie, priority, match in delete_list:
                flow = self._to_of_flow(cookie=cookie, priority=priority,
                                        match=match, actions=actions)
                self.ofctl.mod_flow_entry(self.dp, flow, cmd)

                vid = match.get(REST_DL_VLAN, VLANID_NONE)
                rule_id = Firewall._cookie_to_ruleid(cookie)
                delete_ids.setdefault(vid, '')
                delete_ids[vid] += (('%d' if delete_ids[vid] == ''
                                     else ',%d') % rule_id)

            msg = []
            for vid, rule_ids in delete_ids.items():
                del_msg = {'result': 'success',
                           'details': 'Rule deleted. : ruleID=%s' % rule_ids}
                if vid != VLANID_NONE:
                    del_msg.setdefault(REST_VLANID, vid)
                msg.append(del_msg)

        return REST_COMMAND_RESULT, msg

    def _to_of_flow(self, cookie, priority, match, actions):
        flow = {'cookie': cookie,
                'priority': priority,
                'flags': 0,
                'idle_timeout': 0,
                'hard_timeout': 0,
                'match': match,
                'actions': actions}
        return flow

    def _to_rest_rule(self, flow):
        ruleid = Firewall._cookie_to_ruleid(flow[REST_COOKIE])
        rule = {REST_RULE_ID: ruleid}
        rule.update({REST_PRIORITY: flow[REST_PRIORITY]})
        rule.update(Match.to_rest(flow))
        rule.update(Action.to_rest(self.dp, flow))
        return rule


class Match(object):

    _CONVERT = {REST_DL_TYPE:
                {REST_DL_TYPE_ARP: ether.ETH_TYPE_ARP,
                 REST_DL_TYPE_IPV4: ether.ETH_TYPE_IP,
                 REST_DL_TYPE_IPV6: ether.ETH_TYPE_IPV6},
                REST_NW_PROTO:
                {REST_NW_PROTO_TCP: inet.IPPROTO_TCP,
                 REST_NW_PROTO_UDP: inet.IPPROTO_UDP,
                 REST_NW_PROTO_ICMP: inet.IPPROTO_ICMP,
                 REST_NW_PROTO_ICMPV6: inet.IPPROTO_ICMPV6}}

    _MATCHES = [REST_IN_PORT,
                REST_SRC_MAC,
                REST_DST_MAC,
                REST_DL_TYPE,
                REST_DL_VLAN,
                REST_SRC_IP,
                REST_DST_IP,
                REST_SRC_IPV6,
                REST_DST_IPV6,
                REST_NW_PROTO,
                REST_TP_SRC,
                REST_TP_DST]

    @staticmethod
    def to_openflow(rest):

        def __inv_combi(msg):
            raise ValueError('Invalid combination: [%s]' % msg)

        def __inv_2and1(*args):
            __inv_combi('%s=%s and %s' % (args[0], args[1], args[2]))

        def __inv_2and2(*args):
            __inv_combi('%s=%s and %s=%s' % (
                args[0], args[1], args[2], args[3]))

        def __inv_1and1(*args):
            __inv_combi('%s and %s' % (args[0], args[1]))

        def __inv_1and2(*args):
            __inv_combi('%s and %s=%s' % (args[0], args[1], args[2]))

        match = {}

        # error check
        dl_type = rest.get(REST_DL_TYPE)
        nw_proto = rest.get(REST_NW_PROTO)
        if dl_type is not None:
            if dl_type == REST_DL_TYPE_ARP:
                if REST_SRC_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_ARP, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_ARP, REST_DST_IPV6)
                if nw_proto:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_ARP, REST_NW_PROTO)
            elif dl_type == REST_DL_TYPE_IPV4:
                if REST_SRC_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV4, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV4, REST_DST_IPV6)
                if nw_proto == REST_NW_PROTO_ICMPV6:
                    __inv_2and2(
                        REST_DL_TYPE, REST_DL_TYPE_IPV4,
                        REST_NW_PROTO, REST_NW_PROTO_ICMPV6)
            elif dl_type == REST_DL_TYPE_IPV6:
                if REST_SRC_IP in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV6, REST_SRC_IP)
                if REST_DST_IP in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV6, REST_DST_IP)
                if nw_proto == REST_NW_PROTO_ICMP:
                    __inv_2and2(
                        REST_DL_TYPE, REST_DL_TYPE_IPV6,
                        REST_NW_PROTO, REST_NW_PROTO_ICMP)
            else:
                raise ValueError('Unknown dl_type : %s' % dl_type)
        else:
            if REST_SRC_IP in rest:
                if REST_SRC_IPV6 in rest:
                    __inv_1and1(REST_SRC_IP, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_1and1(REST_SRC_IP, REST_DST_IPV6)
                if nw_proto == REST_NW_PROTO_ICMPV6:
                    __inv_1and2(
                        REST_SRC_IP, REST_NW_PROTO, REST_NW_PROTO_ICMPV6)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
            elif REST_DST_IP in rest:
                if REST_SRC_IPV6 in rest:
                    __inv_1and1(REST_DST_IP, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_1and1(REST_DST_IP, REST_DST_IPV6)
                if nw_proto == REST_NW_PROTO_ICMPV6:
                    __inv_1and2(
                        REST_DST_IP, REST_NW_PROTO, REST_NW_PROTO_ICMPV6)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
            elif REST_SRC_IPV6 in rest:
                if nw_proto == REST_NW_PROTO_ICMP:
                    __inv_1and2(
                        REST_SRC_IPV6, REST_NW_PROTO, REST_NW_PROTO_ICMP)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
            elif REST_DST_IPV6 in rest:
                if nw_proto == REST_NW_PROTO_ICMP:
                    __inv_1and2(
                        REST_DST_IPV6, REST_NW_PROTO, REST_NW_PROTO_ICMP)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
            else:
                if nw_proto == REST_NW_PROTO_ICMP:
                    rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
                elif nw_proto == REST_NW_PROTO_ICMPV6:
                    rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
                elif nw_proto == REST_NW_PROTO_TCP or \
                        nw_proto == REST_NW_PROTO_UDP:
                    raise ValueError('no dl_type was specified')
                else:
                    raise ValueError('Unknown nw_proto: %s' % nw_proto)

        for key, value in rest.items():
            if key in Match._CONVERT:
                if value in Match._CONVERT[key]:
                    match.setdefault(key, Match._CONVERT[key][value])
                else:
                    raise ValueError('Invalid rule parameter. : key=%s' % key)
            elif key in Match._MATCHES:
                match.setdefault(key, value)

        return match

    @staticmethod
    def to_rest(openflow):
        of_match = openflow[REST_MATCH]

        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == REST_SRC_MAC or key == REST_DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == REST_SRC_IP or key == REST_DST_IP:
                if value == ip_dontcare:
                    continue
            elif key == REST_SRC_IPV6 or key == REST_DST_IPV6:
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            if key in Match._CONVERT:
                conv = Match._CONVERT[key]
                conv = dict((value, key) for key, value in conv.items())
                match.setdefault(key, conv[value])
            else:
                match.setdefault(key, value)

        return match

    @staticmethod
    def to_mod_openflow(of_match):
        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == REST_SRC_MAC or key == REST_DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == REST_SRC_IP or key == REST_DST_IP:
                if value == ip_dontcare:
                    continue
            elif key == REST_SRC_IPV6 or key == REST_DST_IPV6:
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            match.setdefault(key, value)

        return match


class Action(object):

    @staticmethod
    def to_openflow(dp, rest):
        value = rest.get(REST_ACTION, REST_ACTION_ALLOW)

        if value == REST_ACTION_ALLOW:
            out_port = dp.ofproto.OFPP_NORMAL
            action = [{'type': 'OUTPUT',
                       'port': out_port}]
        elif value == REST_ACTION_DENY:
            action = []
        elif value == REST_ACTION_PACKETIN:
            out_port = dp.ofproto.OFPP_CONTROLLER
            action = [{'type': 'OUTPUT',
                       'port': out_port,
                       'max_len': 128}]
        else:
            raise ValueError('Invalid action type.')

        return action

    @staticmethod
    def to_rest(dp, openflow):
        if REST_ACTION in openflow:
            action_allow = 'OUTPUT:%d' % dp.ofproto.OFPP_NORMAL
            if openflow[REST_ACTION] == [action_allow]:
                action = {REST_ACTION: REST_ACTION_ALLOW}
            else:
                action = {REST_ACTION: REST_ACTION_DENY}
        else:
            action = {REST_ACTION: 'Unknown action type.'}

        return action
