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

# ofctl service

from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,\
    DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls

import event


class _SwitchInfo(object):
    def __init__(self, datapath):
        self.datapath = datapath
        self.xids = {}
        self.barriers = {}
        self.results = {}


class OfctlService(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(OfctlService, self).__init__(*args, **kwargs)
        self.name = 'ofctl_service'
        self._switches = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        id = datapath.id
        assert isinstance(id, (int, long))
        old_info = self._switches.get(id, None)
        new_info = _SwitchInfo(datapath=datapath)
        self.logger.debug('add dpid %s datapath %s new_info %s old_info %s' %
                          (id, datapath, new_info, old_info))
        self._switches[id] = new_info

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def _handle_dead(self, ev):
        datapath = ev.datapath
        id = datapath.id
        self.logger.debug('del dpid %s datapath %s' % (id, datapath))
        if id is None:
            return
        try:
            info = self._switches[id]
        except KeyError:
            return
        if info.datapath is datapath:
            self.logger.debug('forget info %s' % (info,))
            self._switches.pop(id)

    @set_ev_cls(event.GetDatapathRequest, MAIN_DISPATCHER)
    def _handle_get_datapath(self, req):
        id = req.dpid
        assert isinstance(id, (int, long))
        try:
            datapath = self._switches[id].datapath
        except KeyError:
            datapath = None
        self.logger.debug('dpid %s -> datapath %s' % (id, datapath))
        rep = event.Reply(result=datapath)
        self.reply_to_request(req, rep)

    @set_ev_cls(event.SendMsgRequest, MAIN_DISPATCHER)
    def _handle_send_msg(self, req):
        msg = req.msg
        datapath = msg.datapath
        datapath.set_xid(msg)
        xid = msg.xid
        datapath.send_msg(msg)
        barrier = datapath.ofproto_parser.OFPBarrierRequest(datapath)
        datapath.set_xid(barrier)
        barrier_xid = barrier.xid
        datapath.send_msg(barrier)
        si = self._switches[datapath.id]
        si.xids[xid] = req
        si.barriers[barrier_xid] = xid

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _handle_barrier(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        try:
            si = self._switches[datapath.id]
        except KeyError:
            self.logger.error('unknown dpid %s' % (datapath.id,))
            return
        try:
            xid = si.barriers[msg.xid]
        except KeyError:
            self.logger.error('unknown barrier xid %s' % (msg.xid,))
            return
        try:
            result = si.results.pop(xid)
        except KeyError:
            result = None
        req = si.xids.pop(xid)
        rep = event.Reply(result=result)
        self.reply_to_request(req, rep)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _handle_error(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        try:
            si = self._switches[datapath.id]
        except KeyError:
            self.logger.error('unknown dpid %s' % (datapath.id,))
            return
        si.results[xid] = ev.msg
