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
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser


LOG = logging.getLogger('ryu.app.firewall')


# REST API
#
## about Firewall status
#
# get status of all firewall switches
# GET /firewall/module/status
#
# set enable the firewall switches
# PUT /firewall/module/enable/{switch-id}
#  {switch-id} is 'all' or switchID
#
# set disable the firewall switches
# PUT /firewall/module/disable/{switch-id}
#  {switch-id} is 'all' or switchID
#
#
## about Firewall rules
#
# get rules of the firewall switches
# GET /firewall/rules/{switch-id}
#  {switch-id} is 'all' or switchID
#
# set a rule to the firewall switches
# POST /firewall/rules/{switch-id}
#  {switch-id} is 'all' or switchID
#
# delete a rule of the firewall switches from ruleID
# DELETE /firewall/rules/{switch-id}
#  {switch-id} is 'all' or switchID
#

OK = 0
NG = -1

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'

REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_RULE_ID = 'rule_id'
REST_STATUS = 'status'
REST_STATUS_ENABLE = 'enable'
REST_STATUS_DISABLE = 'disable'
REST_COOKIE = 'cookie'
REST_PRIORITY = 'priority'
REST_MATCH = 'match'
REST_IN_PORT = 'in_port'
REST_SRC_MAC = 'dl_src'
REST_DST_MAC = 'dl_dst'
REST_DL_TYPE = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_SRC_IP = 'nw_src'
REST_DST_IP = 'nw_dst'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_TP_SRC = 'tp_src'
REST_TP_DST = 'tp_dst'
REST_ACTION = 'actions'
REST_ACTION_ALLOW = 'ALLOW'
REST_ACTION_DENY = 'DENY'


STATUS_FLOW_PRIORITY = ofproto_v1_2_parser.UINT16_MAX
ARP_FLOW_PRIORITY = ofproto_v1_2_parser.UINT16_MAX - 1
ACL_FLOW_PRIORITY_MAX = ofproto_v1_2_parser.UINT16_MAX - 2


class RestFirewallAPI(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestFirewallAPI, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters

        mapper = wsgi.mapper
        wsgi.registory['FirewallController'] = self.data
        path = '/firewall'
        requirements = {'switchid': SWITCHID_PATTERN}

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

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        if msg.flags & dp.ofproto.OFPSF_REPLY_MORE:
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

    # for OpenFlow version1.2
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)


class FirewallOfs(object):
    def __init__(self, dp):
        super(FirewallOfs, self).__init__()
        self.dp = dp
        self.ctl = FirewallOfctl(dp)
        self.cookie = 0

    def get_cookie(self):
        self.cookie += 1
        self.cookie &= ofproto_v1_2_parser.UINT64_MAX
        return self.cookie


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

    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    @staticmethod
    def regist_ofs(dp):
        try:
            f_ofs = FirewallOfs(dp)
        except OFPUnknownVersion, message:
            mes = 'dpid=%s : %s' % (dpid_lib.dpid_to_str(dp.id), message)
            LOG.info(mes)
            return

        FirewallController._OFS_LIST.setdefault(dp.id, f_ofs)

        f_ofs.ctl.set_disable_flow()
        f_ofs.ctl.set_arp_flow()
        LOG.info('dpid=%s : Join as firewall switch.' %
                 dpid_lib.dpid_to_str(dp.id))

    @staticmethod
    def unregist_ofs(dp):
        if dp.id in FirewallController._OFS_LIST:
            del FirewallController._OFS_LIST[dp.id]
            LOG.info('dpid=%s : Leave firewall switch.' %
                     dpid_lib.dpid_to_str(dp.id))

    # GET /firewall/module/status
    def get_status(self, req, **_kwargs):
        try:
            dps = self._OFS_LIST.get_ofs(REST_ALL)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = {}
        for f_ofs in dps.values():
            status = f_ofs.ctl.get_status(self.waiters)
            msgs.update(status)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # POST /firewall/module/enable/{switchid}
    def set_enable(self, req, switchid, **_kwargs):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = {}
        for f_ofs in dps.values():
            msg = f_ofs.ctl.set_enable_flow()
            msgs.update(msg)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # POST /firewall/module/disable/{switchid}
    def set_disable(self, req, switchid, **_kwargs):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = {}
        for f_ofs in dps.values():
            msg = f_ofs.ctl.set_disable_flow()
            msgs.update(msg)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # GET /firewall/rules/{switchid}
    def get_rules(self, req, switchid, **_kwargs):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = {}
        for f_ofs in dps.values():
            rules = f_ofs.ctl.get_rules(self.waiters)
            msgs.update(rules)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # POST /firewall/rules/{switchid}
    def set_rule(self, req, switchid, **_kwargs):
        try:
            rule = eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = {}
        for f_ofs in dps.values():
            try:
                msg = f_ofs.ctl.set_rule(f_ofs.get_cookie(), rule)
                msgs.update(msg)
            except ValueError, message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # DELETE /firewall/rules/{switchid}
    def delete_rule(self, req, switchid, **_kwargs):
        try:
            ruleid = eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = {}
        for f_ofs in dps.values():
            try:
                msg = f_ofs.ctl.delete_rule(ruleid, self.waiters)
                msgs.update(msg)
            except ValueError, message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


class FirewallOfctl(object):

    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2}

    def __init__(self, dp):
        super(FirewallOfctl, self).__init__()
        self.dp = dp
        version = dp.ofproto.OFP_VERSION

        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)

        self.ofctl = self._OFCTL[version]

    def get_status(self, waiters):
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)

        status = REST_STATUS_ENABLE
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                if flow_stat['priority'] == STATUS_FLOW_PRIORITY:
                    status = REST_STATUS_DISABLE

        msg = {REST_STATUS: status}
        switch_id = '%s: %s' % (REST_SWITCHID,
                                dpid_lib.dpid_to_str(self.dp.id))
        return {switch_id: msg}

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
        switch_id = '%s: %s' % (REST_SWITCHID,
                                dpid_lib.dpid_to_str(self.dp.id))
        return {switch_id: msg}

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
        switch_id = '%s: %s' % (REST_SWITCHID,
                                dpid_lib.dpid_to_str(self.dp.id))
        return {switch_id: msg}

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

    def set_rule(self, cookie, rest):
        priority = int(rest.get(REST_PRIORITY, 0))

        if priority < 0 or ACL_FLOW_PRIORITY_MAX < priority:
            raise ValueError('Invalid priority value. Set [0-%d]'
                             % ACL_FLOW_PRIORITY_MAX)

        match = Match.to_openflow(rest)
        actions = Action.to_openflow(self.dp, rest)
        flow = self._to_of_flow(cookie=cookie, priority=priority,
                                match=match, actions=actions)

        cmd = self.dp.ofproto.OFPFC_ADD
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        msg = {'result': 'success',
               'details': 'Rule added. : rule_id=%d' % cookie}

        switch_id = '%s: %s' % (REST_SWITCHID,
                                dpid_lib.dpid_to_str(self.dp.id))
        return {switch_id: msg}

    def get_rules(self, waiters):
        rules = {}
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)

        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                if (flow_stat[REST_PRIORITY] != STATUS_FLOW_PRIORITY
                        and flow_stat[REST_PRIORITY] != ARP_FLOW_PRIORITY):
                    rule = self._to_rest_rule(flow_stat)
                    rules.update(rule)

        switch_id = '%s: %s' % (REST_SWITCHID,
                                dpid_lib.dpid_to_str(self.dp.id))
        return {switch_id: rules}

    def delete_rule(self, rest, waiters):
        try:
            if rest[REST_RULE_ID] == REST_ALL:
                rule_id = REST_ALL
            else:
                rule_id = int(rest[REST_RULE_ID])
        except:
            raise ValueError('Invalid ruleID.')

        delete_list = []

        msgs = self.ofctl.get_flow_stats(self.dp, waiters)
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                cookie = flow_stat[REST_COOKIE]
                priority = flow_stat[REST_PRIORITY]

                if (priority != STATUS_FLOW_PRIORITY
                        and priority != ARP_FLOW_PRIORITY):
                    if rule_id == REST_ALL or rule_id == cookie:
                        match = Match.to_del_openflow(flow_stat[REST_MATCH])
                        delete_list.append([cookie, priority, match])
                    if rule_id == cookie:
                        break

        if len(delete_list) == 0:
            msg_details = 'Rule is not exist.'
            if rule_id != REST_ALL:
                msg_details += ' : ruleID=%d' % rule_id
            msg = {'result': 'failure',
                   'details': msg_details}
        else:
            cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
            actions = []
            msg_details = 'Rule deleted. : ruleID='
            for cookie, priority, match in delete_list:
                flow = self._to_of_flow(cookie=cookie, priority=priority,
                                        match=match, actions=actions)
                self.ofctl.mod_flow_entry(self.dp, flow, cmd)
                msg_details += '%d,' % cookie
            msg = {'result': 'success',
                   'details': msg_details}

        switch_id = '%s: %s' % (REST_SWITCHID,
                                dpid_lib.dpid_to_str(self.dp.id))
        return {switch_id: msg}

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
        rule_id = '%s: %d' % (REST_RULE_ID, flow[REST_COOKIE])

        rule = {REST_PRIORITY: flow[REST_PRIORITY]}
        rule.update(Match.to_rest(flow))
        rule.update(Action.to_rest(flow))
        return {rule_id: rule}


class Match(object):

    _CONVERT = {REST_DL_TYPE:
                {REST_DL_TYPE_ARP: ether.ETH_TYPE_ARP,
                 REST_DL_TYPE_IPV4: ether.ETH_TYPE_IP},
                REST_NW_PROTO:
                {REST_NW_PROTO_TCP: inet.IPPROTO_TCP,
                 REST_NW_PROTO_UDP: inet.IPPROTO_UDP,
                 REST_NW_PROTO_ICMP: inet.IPPROTO_ICMP}}

    @staticmethod
    def to_openflow(rest):
        match = {}
        set_dltype_flg = False

        for key, value in rest.items():
            if (key == REST_SRC_IP or key == REST_DST_IP
                    or key == REST_NW_PROTO):
                if (REST_DL_TYPE in rest) is False:
                    set_dltype_flg = True
                elif (rest[REST_DL_TYPE] != REST_DL_TYPE_IPV4
                        and rest[REST_DL_TYPE] != REST_DL_TYPE_ARP):
                    continue

            elif key == REST_TP_SRC or key == REST_TP_DST:
                if ((REST_NW_PROTO in rest) is False
                    or (rest[REST_NW_PROTO] != REST_NW_PROTO_TCP
                        and rest[REST_NW_PROTO] != REST_NW_PROTO_UDP)):
                    continue

            if key in Match._CONVERT:
                if value in Match._CONVERT[key]:
                    match.setdefault(key, Match._CONVERT[key][value])
                else:
                    raise ValueError('Invalid rule parameter. : key=%s' % key)
            else:
                match.setdefault(key, value)

            if set_dltype_flg:
                match.setdefault(REST_DL_TYPE, ether.ETH_TYPE_IP)

        return match

    @staticmethod
    def to_rest(openflow):
        of_match = openflow[REST_MATCH]

        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'

        match = {}
        for key, value in of_match.items():
            if key == REST_SRC_MAC or key == REST_DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == REST_SRC_IP or key == REST_DST_IP:
                if value == ip_dontcare:
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
    def to_del_openflow(of_match):
        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'

        match = {}
        for key, value in of_match.items():
            if key == REST_SRC_MAC or key == REST_DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == REST_SRC_IP or key == REST_DST_IP:
                if value == ip_dontcare:
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
        else:
            raise ValueError('Invalid action type.')

        return action

    @staticmethod
    def to_rest(openflow):
        if REST_ACTION in openflow:
            if len(openflow[REST_ACTION]) > 0:
                action = {REST_ACTION: REST_ACTION_ALLOW}
            else:
                action = {REST_ACTION: REST_ACTION_DENY}
        else:
            action = {REST_ACTION: 'Unknown action type.'}

        return action
