# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

import copy
import inspect
import logging

from ryu.controller import dispatcher
from ryu.controller import ofp_event

LOG = logging.getLogger('ryu.controller.handler')

QUEUE_NAME_OFP_MSG = 'ofp_msg'
DISPATCHER_NAME_OFP_HANDSHAKE = 'ofp_handshake'
HANDSHAKE_DISPATCHER = dispatcher.EventDispatcher(
    DISPATCHER_NAME_OFP_HANDSHAKE)
DISPATCHER_NAME_OFP_CONFIG = 'ofp_config'
CONFIG_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_OFP_CONFIG)
DISPATCHER_NAME_OFP_MAIN = 'ofp_main'
MAIN_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_OFP_MAIN)
DISPATCHER_NAME_OFP_DEAD = 'ofp_dead'
DEAD_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_OFP_DEAD)


def set_ev_cls(ev_cls, dispatchers=None):
    def _set_ev_cls_dec(handler):
        handler.ev_cls = ev_cls
        if dispatchers is not None:
            handler.dispatchers = dispatchers
        return handler
    return _set_ev_cls_dec


def _is_ev_handler(meth):
    return 'ev_cls' in meth.__dict__


def _listify(may_list):
    if may_list is None:
        may_list = []
    if not isinstance(may_list, list):
        may_list = [may_list]
    return may_list


def _get_hnd_spec_dispatchers(handler, dispatchers):
    hnd_spec_dispatchers = _listify(getattr(handler, 'dispatchers', None))
    # LOG.debug("hnd_spec_dispatchers %s", hnd_spec_dispatchers)
    if hnd_spec_dispatchers:
        _dispatchers = copy.copy(dispatchers)
        _dispatchers.extend(hnd_spec_dispatchers)
    else:
        _dispatchers = dispatchers

    return _dispatchers


def register_cls(dispatchers=None):
    dispatchers = _listify(dispatchers)

    def _register_cls_method(cls):
        for _k, f in inspect.getmembers(cls, inspect.isfunction):
            # LOG.debug('cls %s k %s f %s', cls, _k, f)
            if not _is_ev_handler(f):
                continue

            _dispatchers = _get_hnd_spec_dispatchers(f, dispatchers)
            # LOG.debug("_dispatchers %s", _dispatchers)
            for d in _dispatchers:
                # LOG.debug('register dispatcher %s ev %s cls %s k %s f %s',
                #          d.name, f.ev_cls, cls, k, f)
                d.register_handler(f.ev_cls, f)
        return cls

    return _register_cls_method


def register_instance(i, dispatchers=None):
    dispatchers = _listify(dispatchers)

    for _k, m in inspect.getmembers(i, inspect.ismethod):
        # LOG.debug('instance %s k %s m %s', i, _k, m)
        if not _is_ev_handler(m):
            continue

        _dispatchers = _get_hnd_spec_dispatchers(m, dispatchers)
        # LOG.debug("_dispatchers %s", _dispatchers)
        for d in _dispatchers:
            # LOG.debug('register dispatcher %s ev %s k %s m %s',
            #           d.name, m.ev_cls, _k, m)
            d.register_handler(m.ev_cls, m)


@register_cls([HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
class EchoHandler(object):
    @staticmethod
    @set_ev_cls(ofp_event.EventOFPEchoRequest)
    def echo_request_handler(ev):
        msg = ev.msg
        # LOG.debug('echo request msg %s %s', msg, str(msg.data))
        datapath = msg.datapath
        echo_reply = datapath.ofproto_parser.OFPEchoReply(datapath)
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        datapath.send_msg(echo_reply)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPEchoReply)
    def echo_reply_handler(ev):
        # do nothing
        # msg = ev.msg
        # LOG.debug('echo reply ev %s %s', msg, str(msg.data))
        pass


@register_cls([HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
class ErrorMsgHandler(object):
    @staticmethod
    @set_ev_cls(ofp_event.EventOFPErrorMsg)
    def error_msg_handler(ev):
        msg = ev.msg
        LOG.debug('error msg ev %s type 0x%x code 0x%x %s',
                  msg, msg.type, msg.code, str(msg.data))


@register_cls(HANDSHAKE_DISPATCHER)
class HandShakeHandler(object):
    @staticmethod
    @set_ev_cls(ofp_event.EventOFPHello)
    def hello_handler(ev):
        LOG.debug('hello ev %s', ev)
        msg = ev.msg
        datapath = msg.datapath

        # TODO: check if received version is supported.
        #       pre 1.0 is not supported
        if msg.version not in datapath.supported_ofp_version:
            # send the error
            error_msg = datapath.ofproto_parser.OFPErrorMsg(datapath)
            error_msg.type = datapath.ofproto.OFPET_HELLO_FAILED
            error_msg.code = datapath.ofproto.OFPHFC_INCOMPATIBLE
            error_msg.data = 'unsupported version 0x%x' % msg.version
            datapath.send_msg(error_msg)
            return

        # should we again send HELLO with the version that the switch
        # supports?
        # msg.version != datapath.ofproto.OFP_VERSION:

        datapath.set_version(msg.version)

        # now send feature
        features_reqeust = datapath.ofproto_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(features_reqeust)

        # now move on to config state
        LOG.debug('move onto config mode')
        datapath.ev_q.set_dispatcher(CONFIG_DISPATCHER)


@register_cls(CONFIG_DISPATCHER)
class ConfigHandler(object):
    @staticmethod
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures)
    def switch_features_handler(ev):
        msg = ev.msg
        datapath = msg.datapath
        LOG.debug('switch features ev %s', msg)

        datapath.id = msg.datapath_id
        datapath.ports = msg.ports

        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        set_config = ofproto_parser.OFPSetConfig(
            datapath, ofproto.OFPC_FRAG_NORMAL,
            128  # TODO:XXX
            )
        datapath.send_msg(set_config)

        #
        # drop all flows in order to put datapath into unknown state
        #
        datapath.send_delete_all_flows()

        datapath.send_barrier()

        # We had better to move on to the main state after getting the
        # response of the barrier since it guarantees that the switch
        # is in the known state (all the flows were removed). However,
        # cbench doesn't work because it ignores the barrier. Also,
        # the above "known" state doesn't always work (for example,
        # the secondary controller should not remove all the flows in
        # the case of HA configuration). Let's move on to the main
        # state here for now. I guess that we need API to enable
        # applications to initialize switches in their own ways.

        LOG.debug('move onto main mode')
        ev.msg.datapath.ev_q.set_dispatcher(MAIN_DISPATCHER)

    # The above OFPC_DELETE request may trigger flow removed ofp_event.
    # Just ignore them.
    @staticmethod
    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def flow_removed_handler(ev):
        LOG.debug("flow removed ev %s msg %s", ev, ev.msg)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPBarrierReply)
    def barrier_reply_handler(ev):
        LOG.debug('barrier reply ev %s msg %s', ev, ev.msg)


@register_cls(MAIN_DISPATCHER)
class MainHandler(object):
    @staticmethod
    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def flow_removed_handler(ev):
        pass

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPPortStatus)
    def port_status_handler(ev):
        msg = ev.msg
        LOG.debug('port status %s', msg.reason)
