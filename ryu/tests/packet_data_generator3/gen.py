#! /usr/bin/env python

from __future__ import print_function

import getopt
import os
import six
from six.moves import socketserver
import subprocess
import sys
import tempfile
import threading

from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_0_parser
from ryu.ofproto import ofproto_v1_5
from ryu.ofproto import ofproto_v1_5_parser
from ryu.ofproto import ofproto_protocol

if six.PY3:
    TimeoutExpired = subprocess.TimeoutExpired
else:
    # As python2 doesn't have timeout for subprocess.call,
    # this script may hang.
    TimeoutExpired = None

STD_MATCH = [
    'in_port=43981',
    'dl_vlan=999',
    'dl_dst=aa:bb:cc:99:88:77',
    'dl_type=0x0800',  # ETH_TYPE_IP
    'nw_dst=192.168.2.1',
    'tun_src=192.168.2.3',
    'tun_dst=192.168.2.4',
    'tun_id=50000']

MESSAGES = [
    {'name': 'action_learn',
     'versions': [4],
     'cmd': 'add-flow',
     'args': ['table=2',
              'importance=39032'] + STD_MATCH + [
                  'actions=strip_vlan,mod_nw_dst:192.168.2.9,' +
                  'learn(table=99,priority=1,hard_timeout=300,' +
                  'OXM_OF_VLAN_VID[0..11],' +
                  'OXM_OF_ETH_DST[]=OXM_OF_ETH_SRC[],' +
                  'load:0->OXM_OF_VLAN_VID[],' +
                  'load:OXM_OF_TUNNEL_ID[]->OXM_OF_TUNNEL_ID[],' +
                  'output:OXM_OF_IN_PORT[]),goto_table:100']},
    {'name': 'match_conj',
     'versions': [4],
     'cmd': 'mod-flows',
     'args': ['table=3',
              'cookie=0x123456789abcdef0/0xffffffffffffffff',
              'dl_vlan=1234',
              'conj_id=0xabcdef',
              'actions=strip_vlan,goto_table:100']},
    {'name': 'match_pkt_mark',
     'versions': [4],
     'cmd': 'mod-flows',
     'args': ['table=3',
              'cookie=0x123456789abcdef0/0xffffffffffffffff',
              'dl_vlan=1234',
              'pkt_mark=54321',
              'actions=strip_vlan,goto_table:100']},
    {'name': 'match_pkt_mark_masked',
     'versions': [4],
     'cmd': 'mod-flows',
     'args': ['table=3',
              'cookie=0x123456789abcdef0/0xffffffffffffffff',
              'dl_vlan=1234',
              'pkt_mark=0xd431/0xffff',
              'actions=strip_vlan,goto_table:100']},
    {'name': 'action_conjunction',
     'versions': [4],
     'cmd': 'mod-flows',
     'args': (['table=2',
               'cookie=0x123456789abcdef0/0xffffffffffffffff'] +
              STD_MATCH +
              ['actions=conjunction(0xabcdef,1/2)'])},
    {'name': 'match_load_nx_register',
     'versions': [4],
     'cmd': 'mod-flows',
     'args': ['table=3',
              'cookie=0x123456789abcdef0/0xffffffffffffffff',
              'reg0=0x1234',
              'reg5=0xabcd/0xffff',
              'actions=load:0xdeadbee->NXM_NX_REG0[4..31]']},
    {'name': 'match_move_nx_register',
     'versions': [4],
     'cmd': 'mod-flows',
     'args': ['table=3',
              'cookie=0x123456789abcdef0/0xffffffffffffffff',
              'reg0=0x1234',
              'reg5=0xabcd/0xffff',
              'actions=move:NXM_NX_REG0[10..15]->NXM_NX_REG1[0..5]']},
    {'name': 'action_resubmit',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['table=3',
              'importance=39032'] +
              STD_MATCH +
              ['actions=resubmit(1234,99)'])},
    {'name': 'action_ct',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['table=3,',
              'importance=39032'] +
              ['dl_type=0x0800,ct_state=-trk'] +
              ['actions=ct(table=4,zone=NXM_NX_REG0[4..31])'])},
    {'name': 'action_ct_exec',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['table=3,',
              'importance=39032'] +
              ['dl_type=0x0800,ct_state=+trk+est'] +
              ['actions=ct(commit,exec(set_field:0x654321->ct_mark))'])},
    {'name': 'action_ct_nat',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['table=3,',
              'importance=39032'] +
              ['dl_type=0x0800'] +
              ['actions=ct(commit,nat(src=10.1.12.0-10.1.13.255:1-1023)'])},
    {'name': 'action_ct_nat_v6',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['table=3,',
              'importance=39032'] +
              ['dl_type=0x86dd'] +
              ['actions=ct(commit,nat(dst=2001:1::1-2001:1::ffff)'])},
    {'name': 'action_note',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=note:04.05.06.07.00.00'])},
    {'name': 'action_controller',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=controller(reason=packet_out,max_len=1024,id=1)'])},
    {'name': 'action_fintimeout',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100,tcp'] +
              ['actions=fin_timeout(idle_timeout=30,hard_timeout=60)'])},
    {'name': 'action_dec_nw_ttl',
     'versions': [1],
     'cmd': 'add-flow',
     'args': (['priority=100,mpls'] +
              ['actions=dec_ttl'])},
    {'name': 'action_push_mpls',
     'versions': [1],
     'cmd': 'add-flow',
     'args': (['priority=100,ip'] +
              ['actions=push_mpls:0x8847'])},
    {'name': 'action_pop_mpls',
     'versions': [1],
     'cmd': 'add-flow',
     'args': (['priority=100,mpls'] +
              ['actions=pop_mpls:0x0800'])},
    {'name': 'action_set_mpls_ttl',
     'versions': [1],
     'cmd': 'add-flow',
     'args': (['priority=100,mpls'] +
              ['actions=set_mpls_ttl(127)'])},
    {'name': 'action_dec_mpls_ttl',
     'versions': [1],
     'cmd': 'add-flow',
     'args': (['priority=100,mpls'] +
              ['actions=dec_mpls_ttl'])},
    {'name': 'action_set_mpls_label',
     'versions': [1],
     'cmd': 'add-flow',
     'args': (['priority=100,mpls'] +
              ['actions=set_mpls_label(10)'])},
    {'name': 'action_set_mpls_tc',
     'versions': [1],
     'cmd': 'add-flow',
     'args': (['priority=100,mpls'] +
              ['actions=set_mpls_tc(10)'])},
    {'name': 'action_dec_ttl_cnt_ids',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100,tcp'] +
              ['actions=dec_ttl(1,2,3,4,5)'])},
    {'name': 'action_stack_push',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=push:NXM_NX_REG2[1..5]'])},
    {'name': 'action_stack_pop',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=pop:NXM_NX_REG2[1..5]'])},
    {'name': 'action_sample',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=sample(probability=3,collector_set_id=1,' +
               'obs_domain_id=2,obs_point_id=3)'])},
    {'name': 'action_sample2',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=sample(probability=3,collector_set_id=1,' +
               'obs_domain_id=2,obs_point_id=3,sampling_port=8080)'])},
    {'name': 'action_controller2',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=controller(reason=packet_out,max_len=1024,' +
               'id=10,userdata=01.02.03.04.05,pause)'])},
    {'name': 'action_output_trunc',
     'versions': [4],
     'cmd': 'add-flow',
     'args': (['priority=100'] +
              ['actions=output(port=8080,max_len=1024)'])},


    # ToDo: The following actions are not eligible
    # {'name': 'action_regload2'},
    # {'name': 'action_outputreg2'},
]

buf = []


class MyHandler(socketserver.BaseRequestHandler):
    verbose = False

    def handle(self):
        desc = ofproto_protocol.ProtocolDesc()
        residue = b''
        while True:
            if residue:
                data = residue
                residue = b''
            else:
                data = self.request.recv(1024)
                if data == b'':
                    break
            if self.verbose:
                print(data)
            h = ofproto_parser.header(data)
            if self.verbose:
                print(h)
            version, msg_type, msg_len, xid = h
            residue = data[msg_len:]
            desc.set_version(version=version)
            if msg_type == desc.ofproto.OFPT_HELLO:
                hello = desc.ofproto_parser.OFPHello(desc)
                hello.serialize()
                self.request.send(hello.buf)
            elif msg_type == desc.ofproto.OFPT_FLOW_MOD:
                # HACK: Clear xid into zero
                buf.append(data[:4] + b'\x00\x00\x00\x00' + data[8:msg_len])
            elif msg_type == desc.ofproto.OFPT_BARRIER_REQUEST:
                brep = desc.ofproto_parser.OFPBarrierReply(desc)
                brep.xid = xid
                brep.serialize()
                self.request.send(brep.buf)
                break


class MyVerboseHandler(MyHandler):
    verbose = True

if __name__ == '__main__':
    optlist, args = getopt.getopt(sys.argv[1:], 'dvo:')
    debug = False
    ofctl_cmd = '/usr/bin/ovs-ofctl'
    verbose = False
    for o, a in optlist:
        if o == '-d':
            debug = True
        elif o == '-v':
            verbose = True
        elif o == '-o':
            ofctl_cmd = a

    if not os.access(ofctl_cmd, os.X_OK):
        raise Exception("%s is not executable" % ofctl_cmd)
    outpath = '../packet_data'
    socketdir = tempfile.mkdtemp()
    socketname = os.path.join(socketdir, 'ovs')
    server = socketserver.UnixStreamServer(socketname,
                                           MyVerboseHandler if verbose else
                                           MyHandler)
    if debug or verbose:
        print("Serving at %s" % socketname)

    for msg in MESSAGES:
        for v in msg['versions']:
            cmdargs = [ofctl_cmd, '-O', 'OpenFlow%2d' % (v + 9)]
            if verbose:
                cmdargs.append('-v')
            cmdargs.append(msg['cmd'])
            cmdargs.append('unix:%s' % socketname)
            cmdargs.append('\n'.join(msg['args']))
            if verbose:
                print("Running cmd: " + ' '.join(cmdargs) + "\n")
            t = threading.Thread(target=subprocess.call, args=[cmdargs],
                                 kwargs={'timeout': 5})
            t.start()
            server.handle_request()
            if debug:
                print(buf.pop())
            else:
                outf = os.path.join(
                    outpath, "of%d" % (v + 9),
                    "ovs-ofctl-of%d-%s.packet" % (v + 9, msg['name']))
                print("Writing %s..." % outf)
                with open(outf, 'wb') as f:
                    f.write(buf.pop())
            try:
                t.join()
            except TimeoutExpired as e:
                print(e)

    if debug:
        while True:
            server.handle_request()
            print(buf.pop())

    os.unlink(socketname)
    os.rmdir(socketdir)
