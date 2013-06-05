import eventlet
import sys
import inspect
import netaddr
from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import dpset
from ryu.ofproto.ofproto_parser import MsgBase
from ryu.lib.rpc import RpcSession, RpcMessage
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_0_parser
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


def find_ofp_cls(ofp_version, name):
    parser_name = 'ryu.ofproto.ofproto_v1_' + str(ofp_version - 1) + \
        '_parser'
    mod = sys.modules[parser_name]
    for i in inspect.getmembers(mod, lambda cls: (inspect.isclass(cls))):
        if i[0] == name:
            return i[1]
    return None


class OFWireRpcSession(object):
    def __init__(self, socket, dpset):
        self.socket = socket
        self.dpset = dpset
        self.session = RpcSession()
        self.pool = eventlet.GreenPool()
        self.send_queue = eventlet.queue.Queue()
        self.pool.spawn_n(self._send)

    def _send(self):
        while True:
            m = self.send_queue.get()
            self.socket.sendall(m)

    def _ofp_handle_matchfield(self, clses, params):
        matchfield = getattr(clses, 'make')(**params)
        return matchfield

    def _ofp_handle_match(self, clses, params):
        match = clses()
        for k, v in params.items():
            if hasattr(match, 'set_' + k):
                if k.startswith('ipv4_') or k.startswith('arp_spa') or k.startswith('arp_tpa'):
                    if k.endswith('_masked'):
                        addr = netaddr.IPNetwork(v).ip
                        mask = netaddr.IPNetwork(v).netmask
                        getattr(match, 'set_' + k)(int(addr), int(mask))
                        continue
                    else:
                        v = int(netaddr.IPNetwork(v).ip)
                getattr(match, 'set_' + k)(v)
        return match

    def _ofp_handle_params(self, dp, params):
        for k, v in params.items():
            if type(v) == dict:
                self._ofp_handle_params(dp, v)
                clses = find_ofp_cls(dp.ofproto.OFP_VERSION, k)
                if clses is not None:
                    if issubclass(clses, MsgBase):
                        ins = clses(dp, **v)
                    else:
                        if k == 'OFPMatch' and dp.ofproto.OFP_VERSION > 2:
                            ins = self._ofp_handle_match(clses, v)
                        elif k == 'OFPMatchField':
                            ins = self._ofp_handle_matchfield(clses, v)
                        else:
                            ins = clses(**v)
                    params[k] = ins
                    return ins
                else:
                    for key, value in v.items():
                        params[k] = value
                        break
            elif type(v) == list:
                ins = []
                for i in v:
                    ins.append(self._ofp_handle_params(dp, i))
                params[k] = ins
            else:
                pass

    def ofp_handle_request(self, msg):
        dpid = msg[3][0]
        params = msg[3][1]
        dp = self.dpset.get(int(dpid))
        if dp is None:
            # hack
            for k, v in self.dpset.get_all():
                dp = v
                break

        self._ofp_handle_params(dp, params)
        result = {}
        for k, v in params.items():
            dp.send_msg(v)
            result = {'xid': v.xid}
        r = self.session.create_response(msg[1], 0, result)
        self.send_queue.put(r)

    def serve(self):
        while True:
            ret = self.socket.recv(4096)
            if len(ret) == 0:
                break
            messages = self.session.get_messages(ret)
            for m in messages:
                if m[0] == RpcMessage.REQUEST:
                    if m[2] == 'ofp':
                        self.ofp_handle_request(m)
                elif m[0] == RpcMessage.RESPONSE:
                    pass
                elif m[0] == RpcMessage.NOTIFY:
                    pass
                else:
                    print "invalid type", m


class RPCApi(app_manager.RyuApp):
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        self.dpset = kwargs['dpset']
        super(RPCApi, self).__init__(*args, **kwargs)
        self.server = eventlet.listen(('', 50001))
        self.pool = eventlet.GreenPool()
        self.pool.spawn_n(self.serve)
        self.sessions = []

    def serve(self):
        while True:
            sock, address = self.server.accept()
            session = OFWireRpcSession(sock, self.dpset)
            self.sessions.append(session)
            self.pool.spawn_n(session.serve)

    def _ofp_handle_ob(self, dp, msg, params):
        clses = find_ofp_cls(dp.ofproto.OFP_VERSION,
                             msg.__class__.__name__)
        if clses:
            params[msg.__class__.__name__] = {}
            _params = params[msg.__class__.__name__]
        else:
            _params = params

        for i in ofproto_parser.ofp_attr(msg):
            if i.startswith('_'):
                continue
            elif i == 'parser':
                continue
            elif i == 'serialize':
                continue

            v = getattr(msg, i)
            if type(v) == dict:
                _params[i] = {}
                for key in v.keys():
                    _params[i][key] = {}
                    self._ofp_handle_ob(dp, v[key], _params[i][key])
            elif type(v) == list:
                ins = []
                for j in v:
                    d = {}
                    self._ofp_handle_ob(dp, j, d)
                    ins.append(d)
                _params[i] = ins
            elif type(v).__name__ == 'builtin_function_or_method':
                pass
            else:
                _params[i] = v

    @handler.observe_all_events('ofp_event')
    def handler(self, ev):
        if hasattr(ev, 'msg'):
            ofmsg = ev.msg
            params = {}
            self._ofp_handle_ob(ofmsg.datapath, ofmsg, params)
            for k in params.keys():
                params[k]['xid'] = ofmsg.xid

            # for s in self.sessions:
            #     m = s.session.create_notification('ofp', params)
            #     s.send_queue.put(m)
