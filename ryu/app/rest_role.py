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
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3

# =============================
#          REST API
# =============================
#
#  Note: specify switch group, as follows.
#   {switch-id} : 'all' or switchID

# set a role to the switches
# POST /role/{switch-id}

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'

REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_COMMAND_RESULT = 'command_result'


class RestRoleAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestRoleAPI, self).__init__(*args, **kwargs)

        # logger configure
        RoleController.set_logger(self.logger)

        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters

        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper
        wsgi.registory['RoleController'] = self.data
        path = '/role'
        requirements = {'switchid': SWITCHID_PATTERN}

        uri = path + '/{switchid}'
        mapper.connect('role', uri,
                       controller=RoleController, action='set_role',
                       conditions=dict(method=['POST']),
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
            RoleController.regist_ofs(ev.dp)
        else:
            RoleController.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
    def role_reply_handler(self, ev):
        RoleController.role_reply_handler(ev)


class RoleOfsList(dict):
    def __init__(self):
        super(RoleOfsList, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('sw is not connected.')

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
                msg = 'Role sw is not connected. : switchID=%s' % dp_id
                raise ValueError(msg)

        return dps


class RoleController(ControllerBase):
    _OFS_LIST = RoleOfsList()
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(RoleController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[Role][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @staticmethod
    def regist_ofs(dp):
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        try:
            f_ofs = Role(dp)
        except OFPUnknownVersion as message:
            RoleController._LOGGER.info('dpid=%s: %s',
                                        dpid_str, message)
            return

        RoleController._OFS_LIST.setdefault(dp.id, f_ofs)

        RoleController._LOGGER.info('dpid=%s: Join.',
                                    dpid_str)

    @staticmethod
    def unregist_ofs(dp):
        if dp.id in RoleController._OFS_LIST:
            del RoleController._OFS_LIST[dp.id]
            RoleController._LOGGER.info('dpid=%s: Leave.',
                                        dpid_lib.dpid_to_str(dp.id))

    # POST /role/{switchid}
    def set_role(self, req, switchid, **_kwargs):
        return self._set_role(req, switchid)

    def _set_role(self, req, switchid):
        try:
            role = req.json if req.body else {}
        except ValueError:
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_role(role)
                msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    @staticmethod
    def role_reply_handler(ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.role == ofp.OFPCR_ROLE_NOCHANGE:
            role = 'NOCHANGE'
        elif msg.role == ofp.OFPCR_ROLE_EQUAL:
            role = 'EQUAL'
        elif msg.role == ofp.OFPCR_ROLE_MASTER:
            role = 'MASTER'
        elif msg.role == ofp.OFPCR_ROLE_SLAVE:
            role = 'SLAVE'
        else:
            role = 'unknown'

        dpid_str = dpid_lib.dpid_to_str(msg.datapath.id)
        RoleController._LOGGER.info('dpid=%s: role=%s generation_id=%d',
                                    dpid_str, role, msg.generation_id)


class Role(object):

    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, dp):
        super(Role, self).__init__()
        self.dp = dp
        version = dp.ofproto.OFP_VERSION

        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)

        self.ofctl = self._OFCTL[version]

    def rest_command(func):
        def _rest_command(*args, **kwargs):
            key, value = func(*args, **kwargs)
            switch_id = dpid_lib.dpid_to_str(args[0].dp.id)
            return {REST_SWITCHID: switch_id,
                    key: value}
        return _rest_command

    @rest_command
    def set_role(self, rest):
        msgs = []
        msg = self._set_role(rest)
        msgs.append(msg)
        return REST_COMMAND_RESULT, msgs

    def _set_role(self, rest):
        datapath = self.dp
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        role = str()

        for key, value in rest.items():

            if key == 'role':
                if value == 'MASTER':
                    req = ofp_parser.OFPRoleRequest(datapath, ofp.OFPCR_ROLE_MASTER, 0)
                    role = value
                elif value == 'SLAVE':
                    req = ofp_parser.OFPRoleRequest(datapath, ofp.OFPCR_ROLE_SLAVE, 0)
                    role = value

        datapath.send_msg(req)

        msg = {'result': 'success',
               'details': 'Role change to %s' % role}

        return msg
