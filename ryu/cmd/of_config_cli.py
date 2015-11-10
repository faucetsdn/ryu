#!/usr/bin/env python
#
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# a simple command line OF-CONFIG client
#
# a usage example:
#     % PYTHONPATH=. ./bin/of_config_cli \
#      --peers=sw1=localhost:1830:username:password
#     (Cmd) raw_get sw1

from __future__ import print_function

import ryu.contrib
ryu.contrib.update_module_path()

from ryu import cfg

import cmd
import sys
import lxml.etree as ET

from ryu.lib import of_config
from ryu.lib.of_config import capable_switch
from ncclient.operations.rpc import RPCError
import ryu.lib.of_config.classes as ofc


CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.ListOpt('peers', default=[], help='list of peers')
])


class Peer(capable_switch.OFCapableSwitch):
    def __init__(self, name, host, port, username, password):
        self._name = name
        super(Peer, self).__init__(
            host=host, port=port, username=username, password=password,
            unknown_host_cb=lambda host, fingeprint: True)


peers = {}


def add_peer(name, host, port, username, password):
    peers[name] = Peer(name, host, port, username, password)


def et_tostring_pp(tree):
    # pretty_print is an lxml feature, not available in ElementTree
    try:
        return ET.tostring(tree, pretty_print=True)
    except TypeError:
        return ET.tostring(tree)


def validate(tree):
    schema = ET.XMLSchema(file=of_config.OF_CONFIG_1_1_1_XSD)
    if not schema(tree):
        print(schema.error_log)


class Cmd(cmd.Cmd):
    def __init__(self, *args, **kwargs):
        self._in_onecmd = False
        cmd.Cmd.__init__(self, *args, **kwargs)

    def _request(self, line, f):
        args = line.split()
        try:
            peer = args[0]
        except:
            print("argument error")
            return
        try:
            p = peers[peer]
        except KeyError:
            print("unknown peer %s" % peer)
            return
        try:
            f(p, args[1:])
        except RPCError as e:
            print("RPC Error %s" % e)
        except EOFError:
            print("disconnected")

    def _complete_peer(self, text, line, _begidx, _endidx):
        if len((line + 'x').split()) >= 3:
            return []
        return [name for name in peers if name.startswith(text)]

    def do_list_cap(self, line):
        """list_cap <peer>
        """

        def f(p, args):
            for i in p.netconf.server_capabilities:
                print(i)

        self._request(line, f)

    def do_raw_get(self, line):
        """raw_get <peer>
        """

        def f(p, args):
            result = p.raw_get()
            tree = ET.fromstring(result)
            validate(tree)
            print(et_tostring_pp(tree))

        self._request(line, f)

    def do_raw_get_config(self, line):
        """raw_get_config <peer> <source>
        """

        def f(p, args):
            try:
                source = args[0]
            except:
                print("argument error")
                return
            result = p.raw_get_config(source)
            tree = ET.fromstring(result)
            validate(tree)
            print(et_tostring_pp(tree))

        self._request(line, f)

    def do_get(self, line):
        """get <peer>
        eg. get sw1
        """

        def f(p, args):
            print(p.get())

        self._request(line, f)

    def do_commit(self, line):
        """commit <peer>
        eg. commit sw1
        """

        def f(p, args):
            print(p.commit())

        self._request(line, f)

    def do_discard(self, line):
        """discard <peer>
        eg. discard sw1
        """

        def f(p, args):
            print(p.discard_changes())

        self._request(line, f)

    def do_get_config(self, line):
        """get_config <peer> <source>
        eg. get_config sw1 startup
        """

        def f(p, args):
            try:
                source = args[0]
            except:
                print("argument error")
                return
            print(p.get_config(source))

        self._request(line, f)

    def do_delete_config(self, line):
        """delete_config <peer> <source>
        eg. delete_config sw1 startup
        """

        def f(p, args):
            try:
                source = args[0]
            except:
                print("argument error")
                return
            print(p.delete_config(source))

        self._request(line, f)

    def do_copy_config(self, line):
        """copy_config <peer> <source> <target>
        eg. copy_config sw1 running startup
        """

        def f(p, args):
            try:
                source, target = args
            except:
                print("argument error")
                return
            print(p.copy_config(source, target))

        self._request(line, f)

    def do_list_port(self, line):
        """list_port <peer>
        """

        def f(p, args):
            o = p.get()
            for p in o.resources.port:
                print('%s %s %s' % (p.resource_id, p.name, p.number))

        self._request(line, f)

    _port_settings = [
        'admin-state',
        'no-forward',
        'no-packet-in',
        'no-receive',
    ]

    def do_get_port_config(self, line):
        """get_config_port <peer> <source> <port>
        eg. get_port_config sw1 running LogicalSwitch7-Port2
        """

        def f(p, args):
            try:
                source, port = args
            except:
                print("argument error")
                return
            o = p.get_config(source)
            for p in o.resources.port:
                if p.resource_id != port:
                    continue
                print(p.resource_id)
                conf = p.configuration
                for k in self._port_settings:
                    try:
                        v = getattr(conf, k)
                    except AttributeError:
                        continue
                    print('%s %s' % (k, v))

        self._request(line, f)

    def do_set_port_config(self, line):
        """set_port_config <peer> <target> <port> <key> <value>
        eg. set_port_config sw1 running LogicalSwitch7-Port2 admin-state down
        eg. set_port_config sw1 running LogicalSwitch7-Port2 no-forward false
        """

        def f(p, args):
            try:
                target, port, key, value = args
            except:
                print("argument error")
                print(args)
                return

            # get switch id
            o = p.get()
            capable_switch_id = o.id

            try:
                capable_switch = ofc.OFCapableSwitchType(
                    id=capable_switch_id,
                    resources=ofc.OFCapableSwitchResourcesType(
                        port=[
                            ofc.OFPortType(
                                resource_id=port,
                                configuration=ofc.OFPortConfigurationType(
                                    **{key: value}))
                        ]
                    )
                )
            except TypeError:
                print("argument error")
                return
            try:
                p.edit_config(target, capable_switch)
            except Exception as e:
                print(e)

        self._request(line, f)

    def do_list_queue(self, line):
        """list_queue <peer>
        """

        def f(p, args):
            o = p.get()
            if o.resources.queue:
                for q in o.resources.queue:
                    print('%s %s' % (q.resource_id, q.port))

        self._request(line, f)

    _queue_settings = [
        'max-rate',
        'min-rate',
        'experimenter',
    ]

    def do_get_queue_config(self, line):
        """get_queue_port <peer> <source> <queue>
        eg. get_queue_config sw1 running LogicalSwitch7-Port1-Queue922
        """

        def f(p, args):
            try:
                source, queue = args
            except:
                print("argument error")
                return
            o = p.get_config(source)
            for q in o.resources.queue:
                if q.resource_id != queue:
                    continue
                print(q.resource_id)
                conf = q.properties
                for k in self._queue_settings:
                    try:
                        v = getattr(conf, k)
                    except AttributeError:
                        continue
                    print('%s %s' % (k, v))

        self._request(line, f)

    def do_set_queue_config(self, line):
        """set_queue_config <peer> <target> <queue> <key> <value>
        eg. set_queue_config sw1 running LogicalSwitch7-Port1-Queue922 \
max-rate 100
        """

        def f(p, args):
            try:
                target, queue, key, value = args
            except:
                print("argument error")
                print(args)
                return

            # get switch id
            o = p.get()
            capable_switch_id = o.id

            try:
                capable_switch = ofc.OFCapableSwitchType(
                    id=capable_switch_id,
                    resources=ofc.OFCapableSwitchResourcesType(
                        queue=[
                            ofc.OFQueueType(
                                resource_id=queue,
                                properties=ofc.OFQueuePropertiesType(
                                    **{key: value})),
                        ]
                    )
                )
            except TypeError:
                print("argument error")
                return
            try:
                p.edit_config(target, capable_switch)
            except Exception as e:
                print(e)

        self._request(line, f)

    def do_add_queue(self, line):
        """add_queue <peer> <target> <logical-switch> <queue>
        eg. add_queue sw1 running LogicalSwitch7 NameOfNewQueue
        """

        def f(p, args):
            try:
                target, lsw, queue = args
            except:
                print("argument error")
                print(args)
                return

            # get switch id
            o = p.get()
            capable_switch_id = o.id

            try:
                capable_switch = ofc.OFCapableSwitchType(
                    id=capable_switch_id,
                    resources=ofc.OFCapableSwitchResourcesType(
                        queue=[
                            ofc.OFQueueType(resource_id=queue)
                        ]
                    ),
                    logical_switches=ofc.OFCapableSwitchLogicalSwitchesType(
                        switch=[ofc.OFLogicalSwitchType(
                            id=lsw,
                            resources=ofc.OFLogicalSwitchResourcesType(
                                queue=[queue])
                        )]
                    )
                )
            except TypeError:
                print("argument error")
                return
            try:
                p.edit_config(target, capable_switch)
            except Exception as e:
                print(e)

        self._request(line, f)

    def do_list_logical_switch(self, line):
        """list_logical_switch <peer>
        """

        def f(p, args):
            o = p.get()
            for s in o.logical_switches.switch:
                print('%s %s' % (s.id, s.datapath_id))

        self._request(line, f)

    def do_show_logical_switch(self, line):
        """show_logical_switch <peer> <logical switch>
        """

        def f(p, args):
            try:
                (lsw,) = args
            except:
                print("argument error")
                return
            o = p.get()
            for s in o.logical_switches.switch:
                if s.id != lsw:
                    continue
                print(s.id)
                print('datapath-id %s' % s.datapath_id)
                if s.resources.queue:
                    print('queues:')
                    for q in s.resources.queue:
                        print('\t %s' % q)
                if s.resources.port:
                    print('ports:')
                    for p in s.resources.port:
                        print('\t %s' % p)

        self._request(line, f)

    _lsw_settings = [
        'lost-connection-behavior',
    ]

    def do_get_logical_switch_config(self, line):
        """get_logical_switch_config <peer> <source> <logical switch>
        """

        def f(p, args):
            try:
                source, lsw = args
            except:
                print("argument error")
                return
            o = p.get_config(source)
            for l in o.logical_switches.switch:
                if l.id != lsw:
                    continue
                print(l.id)
                for k in self._lsw_settings:
                    try:
                        v = getattr(l, k)
                    except AttributeError:
                        continue
                    print('%s %s' % (k, v))

        self._request(line, f)

    def do_set_logical_switch_config(self, line):
        """set_logical_switch_config <peer> <logical switch> <key> <value>
        eg. set_logical_switch_config sw1 running LogicalSwitch7 \
lost-connection-behavior failStandaloneMode
        """

        def f(p, args):
            try:
                target, lsw, key, value = args
            except:
                print("argument error")
                return

            # get switch id
            o = p.get_config(target)
            capable_switch_id = o.id

            try:
                capable_switch = ofc.OFCapableSwitchType(
                    id=capable_switch_id,
                    logical_switches=ofc.OFCapableSwitchLogicalSwitchesType(
                        switch=[ofc.OFLogicalSwitchType(
                            id=lsw,
                            **{key: value}
                        )]
                    )
                )
            except TypeError:
                print("argument error")
                return
            try:
                p.edit_config(target, capable_switch)
            except Exception as e:
                print(e)

        self._request(line, f)

    completedefault = _complete_peer

    def complete_EOF(self, _text, _line, _begidx, _endidx):
        return []

    def do_EOF(self, _line):
        sys.exit(0)

    def onecmd(self, string):
        self._in_onecmd = True
        try:
            return cmd.Cmd.onecmd(self, string)
        finally:
            self._in_onecmd = False


def main(args=None, prog=None):
    CONF(args=args, prog=prog,
         project='of-config-cli', version='of-config-cli')

    for p_str in CONF.peers:
        name, addr = p_str.split('=')
        host, port, username, password = addr.rsplit(':', 3)
        add_peer(name, host, port, username, password)

    Cmd().cmdloop()


if __name__ == "__main__":
    main()
