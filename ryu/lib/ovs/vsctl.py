# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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


import itertools
import logging
import operator
import os
import sys
import weakref

import ovs.db.data
import ovs.db.types
import ovs.poller
from ovs import (jsonrpc,
                 ovsuuid,
                 stream)
from ovs.db import idl

from ryu.lib import hub
from ryu.lib.ovs import vswitch_idl

LOG = logging.getLogger(__name__)       # use ovs.vlog?


# for debug
def ovsrec_row_changes_to_string(ovsrec_row):
    if not ovsrec_row._changes:
        return ovsrec_row._changes

    return dict((key, value.to_string())
                for key, value in ovsrec_row._changes.items())


# for debug
def ovsrec_row_to_string(ovsrec_row):
    output = ''
    output += 'uuid: %s ' % ovsrec_row.uuid
    if ovsrec_row._data:
        output += '_data: %s ' % dict((key, value.to_string()) for key, value
                                      in ovsrec_row._data.items())
    else:
        output += '_data: %s ' % ovsrec_row._data
    output += '_changes: %s' % ovsrec_row_changes_to_string(ovsrec_row)
    return output


def atom_from_string(base, value_string, symtab=None):
    type_ = base.type
    atom = None
    if type_ == ovs.db.types.IntegerType:
        atom = ovs.db.data.Atom(type_, int(value_string))
    elif type_ == ovs.db.types.RealType:
        # TODO:XXX negation
        atom = ovs.db.data.Atom(
            type_, ovs.db.parser.float_to_int(float(value_string)))
    elif type_ == ovs.db.types.BooleanType:
        if value_string in ("true", "yes", "on", "1"):
            atom = ovs.db.data.Atom(type_, True)
        elif value_string == ("false", "no", "off", "0"):
            atom = ovs.db.data.Atom(type_, False)
    elif type_ == ovs.db.types.StringType:
        # TODO:XXXX escape: if value_string[0] == '"':
        atom = ovs.db.data.Atom(type_, value_string)
    elif type_ == ovs.db.types.UuidType:
        if value_string[0] == "@":
            assert symtab is not None
            uuid_ = symtab[value_string]
            atom = ovs.db.data.Atom(type_, uuid_)
        else:
            atom = ovs.db.data.Atom(type_,
                                    ovs.ovsuuid.from_string(value_string))
    if atom is None:
        raise ValueError("expected %s" % type_.to_string(), value_string)
    atom.check_constraints(base)
    return atom


def datum_from_string(type_, value_string, symtab=None):
    value_string = value_string.strip()
    if type_.is_map():
        if value_string.startswith('{'):
            # TODO:dict case
            LOG.debug('value_string %s', value_string)
            raise NotImplementedError()
        d = dict(v.split('=', 1) for v in value_string.split(','))
        d = dict((atom_from_string(type_.key, key, symtab),
                  atom_from_string(type_.value, value, symtab))
                 for key, value in d.items())
    elif type_.is_set():
        if value_string.startswith('['):
            # TODO:set case
            LOG.debug('value_string %s', value_string)
            raise NotImplementedError()
        values = value_string.split(',')
        d = dict((atom_from_string(type_.key, value, symtab), None)
                 for value in values)
    else:
        atom = atom_from_string(type_.key, value_string, symtab)
        d = {atom: None}

    datum = ovs.db.data.Datum(type_, d)
    return datum.to_json()


def ifind(pred, seq):
    try:
        return itertools.ifilter(pred, seq).next()
    except StopIteration:
        return None


def not_reached():
    os.abort()


def vsctl_fatal(msg):
    LOG.error(msg)
    raise Exception(msg)        # not call ovs.utils.ovs_fatal for reusability


class VSCtlBridge(object):
    def __init__(self, ovsrec_bridge, name, parent, vlan):
        super(VSCtlBridge, self).__init__()
        self.br_cfg = ovsrec_bridge
        self.name = name
        self.ports = set()

        self.parent = parent
        self.vlan = vlan
        self.children = set()   # WeakSet is needed?

    def find_vlan_bridge(self, vlan):
        return ifind(lambda child: child.vlan == vlan, self.children)


class VSCtlPort(object):
    def __init__(self, vsctl_bridge_parent, ovsrec_port):
        super(VSCtlPort, self).__init__()
        self.bridge = weakref.ref(vsctl_bridge_parent)  # backpointer
        self.port_cfg = ovsrec_port

        self.ifaces = set()


class VSCtlIface(object):
    def __init__(self, vsctl_port_parent, ovsrec_iface):
        super(VSCtlIface, self).__init__()
        self.port = weakref.ref(vsctl_port_parent)      # backpointer
        self.iface_cfg = ovsrec_iface


class VSCtlContext(object):
    def _invalidate_cache(self):
        self.cache_valid = False
        self.bridges.clear()
        self.ports.clear()
        self.ifaces.clear()

    def __init__(self, idl_, txn, ovsrec_open_vswitch):
        super(VSCtlContext, self).__init__()

        # Modifiable state
        # self.table = None
        self.idl = idl_
        self.txn = txn
        self.ovs = ovsrec_open_vswitch
        self.symtab = None      # TODO:XXX
        self.verified_ports = False

        # A cache of the contents of the database.
        self.cache_valid = False
        self.bridges = {}       # bridge name -> VSCtlBridge
        self.ports = {}         # port name -> VSCtlPort
        self.ifaces = {}        # iface name -> VSCtlIface

        self.try_again = False  # used by wait-until command

    def done(self):
        self._invalidate_cache()

    def verify_bridges(self):
        self.ovs.verify(vswitch_idl.OVSREC_OPEN_VSWITCH_COL_BRIDGES)

    def verify_ports(self):
        if self.verified_ports:
            return

        self.verify_bridges()
        for ovsrec_bridge in self.idl.tables[
                vswitch_idl.OVSREC_TABLE_BRIDGE].rows.values():
            ovsrec_bridge.verify(vswitch_idl.OVSREC_BRIDGE_COL_PORTS)
        for ovsrec_port in self.idl.tables[
                vswitch_idl.OVSREC_TABLE_PORT].rows.values():
            ovsrec_port.verify(vswitch_idl.OVSREC_PORT_COL_INTERFACES)
        self.verified_ports = True

    def add_bridge_to_cache(self, ovsrec_bridge, name, parent, vlan):
        vsctl_bridge = VSCtlBridge(ovsrec_bridge, name, parent, vlan)
        if parent:
            parent.children.add(vsctl_bridge)
        self.bridges[name] = vsctl_bridge
        return vsctl_bridge

    def del_cached_bridge(self, vsctl_bridge):
        assert not vsctl_bridge.ports
        assert not vsctl_bridge.children

        parent = vsctl_bridge.parent
        if parent:
            parent.children.remove(vsctl_bridge)
            vsctl_bridge.parent = None  # break circular reference
        ovsrec_bridge = vsctl_bridge.br_cfg
        if ovsrec_bridge:
            ovsrec_bridge.delete()
            self.ovs_delete_bridge(ovsrec_bridge)

        del self.bridges[vsctl_bridge.name]

    def add_port_to_cache(self, vsctl_bridge_parent, ovsrec_port):
        tag = getattr(ovsrec_port, vswitch_idl.OVSREC_PORT_COL_TAG, None)
        if (tag is not None and tag >= 0 and tag < 4096):
            vlan_bridge = vsctl_bridge_parent.find_vlan_bridge()
            if vlan_bridge:
                vsctl_bridge_parent = vlan_bridge

        vsctl_port = VSCtlPort(vsctl_bridge_parent, ovsrec_port)
        vsctl_bridge_parent.ports.add(vsctl_port)
        self.ports[ovsrec_port.name] = vsctl_port
        return vsctl_port

    def del_cached_port(self, vsctl_port):
        assert not vsctl_port.ifaces
        vsctl_port.bridge().ports.remove(vsctl_port)
        vsctl_port.bridge = None
        port = self.ports.pop(vsctl_port.port_cfg.name)
        assert port == vsctl_port
        vsctl_port.port_cfg.delete()

    def add_iface_to_cache(self, vsctl_port_parent, ovsrec_iface):
        vsctl_iface = VSCtlIface(vsctl_port_parent, ovsrec_iface)
        vsctl_port_parent.ifaces.add(vsctl_iface)
        self.ifaces[ovsrec_iface.name] = vsctl_iface

    def del_cached_iface(self, vsctl_iface):
        vsctl_iface.port().ifaces.remove(vsctl_iface)
        vsctl_iface.port = None
        del self.ifaces[vsctl_iface.iface_cfg.name]
        vsctl_iface.iface_cfg.delete()

    def invalidate_cache(self):
        if not self.cache_valid:
            return
        self._invalidate_cache()

    def populate_cache(self):
        self._populate_cache(self.idl.tables[vswitch_idl.OVSREC_TABLE_BRIDGE])

    @staticmethod
    def port_is_fake_bridge(ovsrec_port):
        return (ovsrec_port.fake_bridge and
                ovsrec_port.tag >= 0 and ovsrec_port.tab <= 4095)

    def _populate_cache(self, ovsrec_bridges):
        if self.cache_valid:
            return
        self.cache_valid = True

        bridges = set()
        ports = set()
        for ovsrec_bridge in ovsrec_bridges.rows.values():
            name = ovsrec_bridge.name
            if name in bridges:
                LOG.warn('%s: database contains duplicate bridge name', name)
            bridges.add(name)
            vsctl_bridge = self.add_bridge_to_cache(ovsrec_bridge, name,
                                                    None, 0)
            if not vsctl_bridge:
                continue
            for ovsrec_port in ovsrec_bridge.ports:
                port_name = ovsrec_port.name
                if port_name in ports:
                    # Duplicate ovsrec_port name.
                    # (We will warn about that later.)
                    continue
                ports.add(port_name)
                if (self.port_is_fake_bridge(ovsrec_port) and
                        port_name not in bridges):
                    bridges.add(port_name)
                    self.add_bridge_to_cache(None, port_name, vsctl_bridge,
                                             ovsrec_port.tag)

        bridges = set()
        for ovsrec_bridge in ovsrec_bridges.rows.values():
            name = ovsrec_bridge.name
            if name in bridges:
                continue
            bridges.add(name)
            vsctl_bridge = self.bridges[name]
            for ovsrec_port in ovsrec_bridge.ports:
                port_name = ovsrec_port.name
                vsctl_port = self.ports.get(port_name)
                if vsctl_port:
                    if ovsrec_port == vsctl_port.port_cfg:
                        LOG.warn('%s: vsctl_port is in multiple bridges '
                                 '(%s and %s)',
                                 port_name, vsctl_bridge.name,
                                 vsctl_port.br.name)
                    else:
                        LOG.error('%s: database contains duplicate '
                                  'vsctl_port name',
                                  ovsrec_port.name)
                    continue

                if (self.port_is_fake_bridge(ovsrec_port) and
                        port_name in bridges):
                    continue

                # LOG.debug('ovsrec_port %s %s %s',
                #           ovsrec_port, ovsrec_port._data, ovsrec_port.tag)
                vsctl_port = self.add_port_to_cache(vsctl_bridge, ovsrec_port)
                # LOG.debug('vsctl_port %s', vsctl_port)
                for ovsrec_iface in ovsrec_port.interfaces:
                    iface = self.ifaces.get(ovsrec_iface.name)
                    if iface:
                        if ovsrec_iface == iface.iface_cfg:
                            LOG.warn(
                                '%s: interface is in multiple ports '
                                '(%s and %s)',
                                ovsrec_iface.name,
                                iface.port().port_cfg.name,
                                vsctl_port.port_cfg.name)
                        else:
                            LOG.error(
                                '%s: database contains duplicate interface '
                                'name',
                                ovsrec_iface.name)
                        continue
                    self.add_iface_to_cache(vsctl_port, ovsrec_iface)

    def check_conflicts(self, name, msg):
        self.verify_ports()
        if name in self.bridges:
            vsctl_fatal('%s because a bridge named %s already exists' %
                        (msg, name))
        if name in self.ports:
            vsctl_fatal('%s because a port named %s already exists on '
                        'bridge %s' %
                        (msg, name, self.ports[name].bridge().name))
        if name in self.ifaces:
            vsctl_fatal('%s because an interface named %s already '
                        'exists on bridge %s' %
                        (msg, name, self.ifaces[name].port().bridge().name))

    def find_bridge(self, name, must_exist):
        assert self.cache_valid
        vsctl_bridge = self.bridges.get(name)
        if must_exist and not vsctl_bridge:
            vsctl_fatal('no bridge named %s' % name)
        self.verify_bridges()
        return vsctl_bridge

    def find_real_bridge(self, name, must_exist):
        vsctl_bridge = self.find_bridge(name, must_exist)
        if vsctl_bridge and vsctl_bridge.parent:
            vsctl_fatal('%s is a fake bridge' % name)
        return vsctl_bridge

    def find_bridge_by_id(self, datapath_id, must_exist):
        assert self.cache_valid
        for vsctl_bridge in self.bridges.values():
            if vsctl_bridge.br_cfg.datapath_id[0].strip('"') == datapath_id:
                self.verify_bridges()
                return vsctl_bridge

        if must_exist:
            vsctl_fatal('no bridge id %s' % datapath_id)
        return None

    def find_port(self, name, must_exist):
        assert self.cache_valid
        vsctl_port = self.ports.get(name)
        if vsctl_port and name == vsctl_port.bridge().name:
            vsctl_port = None
        if must_exist and not vsctl_port:
            vsctl_fatal('no vsctl_port named %s' % name)
        return vsctl_port

    def find_iface(self, name, must_exist):
        assert self.cache_valid
        vsctl_iface = self.ifaces.get(name)
        if vsctl_iface and name == vsctl_iface.port().bridge().name:
            vsctl_iface = None
        if must_exist and not vsctl_iface:
            vsctl_fatal('no interface named %s' % name)
        self.verify_ports()
        return vsctl_iface

    @staticmethod
    def _column_set(ovsrec_row, column, ovsrec_value):
        # need to trigger Row.__setattr__()
        setattr(ovsrec_row, column, ovsrec_value)

    @staticmethod
    def _column_insert(ovsrec_row, column, ovsrec_add):
        value = getattr(ovsrec_row, column)
        value.append(ovsrec_add)
        VSCtlContext._column_set(ovsrec_row, column, value)

    @staticmethod
    def _column_delete(ovsrec_row, column, ovsrec_del):
        value = getattr(ovsrec_row, column)
        try:
            value.remove(ovsrec_del)
        except ValueError:
            # Datum.to_python() with _uuid_to_row trims down deleted
            # references. If ovsrec_del.delete() is called before
            # _column_delete(), value doesn't include ovsrec_del.
            pass

        VSCtlContext._column_set(ovsrec_row, column, value)

    @staticmethod
    def bridge_insert_port(ovsrec_bridge, ovsrec_port):
        VSCtlContext._column_insert(ovsrec_bridge,
                                    vswitch_idl.OVSREC_BRIDGE_COL_PORTS,
                                    ovsrec_port)

    @staticmethod
    def bridge_delete_port(ovsrec_bridge, ovsrec_port):
        VSCtlContext._column_delete(ovsrec_bridge,
                                    vswitch_idl.OVSREC_BRIDGE_COL_PORTS,
                                    ovsrec_port)

    def ovs_insert_bridge(self, ovsrec_bridge):
        self._column_insert(self.ovs,
                            vswitch_idl.OVSREC_OPEN_VSWITCH_COL_BRIDGES,
                            ovsrec_bridge)

    def ovs_delete_bridge(self, ovsrec_bridge):
        self._column_delete(self.ovs,
                            vswitch_idl.OVSREC_OPEN_VSWITCH_COL_BRIDGES,
                            ovsrec_bridge)

    def del_port(self, vsctl_port):
        if vsctl_port.bridge().parent:
            ovsrec_bridge = vsctl_port.bridge().parent.br_cfg
        else:
            ovsrec_bridge = vsctl_port.bridge().br_cfg
        self.bridge_delete_port(ovsrec_bridge, vsctl_port.port_cfg)

        for vsctl_iface in vsctl_port.ifaces.copy():
            self.del_cached_iface(vsctl_iface)
        self.del_cached_port(vsctl_port)

    def del_bridge(self, vsctl_bridge):
        for child in vsctl_bridge.children.copy():
            self.del_bridge(child)
        for vsctl_port in vsctl_bridge.ports.copy():
            self.del_port(vsctl_port)
        self.del_cached_bridge(vsctl_bridge)

    def add_port(self, br_name, port_name, may_exist, fake_iface,
                 iface_names, settings=None):
        """
        :type settings: list of (column, key, value_json)
                                where column and key are str,
                                      value_json is json that is represented
                                      by Datum.to_json()
        """
        settings = settings or []

        self.populate_cache()
        if may_exist:
            vsctl_port = self.find_port(port_name, False)
            if vsctl_port:
                want_names = set(iface_names)
                have_names = set(ovsrec_iface.name for ovsrec_iface in
                                 vsctl_port.port_cfg.interfaces)
                if vsctl_port.bridge().name != br_name:
                    vsctl_fatal('"%s" but %s is actually attached to '
                                'vsctl_bridge %s',
                                br_name, port_name, vsctl_port.bridge().name)
                if want_names != have_names:
                    want_names_string = ','.join(want_names)
                    have_names_string = ','.join(have_names)
                    vsctl_fatal('"%s" but %s actually has interface(s) %s' %
                                (want_names_string,
                                 port_name, have_names_string))
                return
        self.check_conflicts(port_name,
                             'cannot create a port named %s' % port_name)
        for iface_name in iface_names:
            self.check_conflicts(
                iface_name, 'cannot create an interface named %s' % iface_name)

        vsctl_bridge = self.find_bridge(br_name, True)
        ifaces = []
        for iface_name in iface_names:
            ovsrec_iface = self.txn.insert(
                self.idl.tables[vswitch_idl.OVSREC_TABLE_INTERFACE])
            ovsrec_iface.name = iface_name
            ifaces.append(ovsrec_iface)

        ovsrec_port = self.txn.insert(
            self.idl.tables[vswitch_idl.OVSREC_TABLE_PORT])
        ovsrec_port.name = port_name
        ovsrec_port.interfaces = ifaces
        ovsrec_port.bond_fake_iface = fake_iface

        if vsctl_bridge.parent:
            tag = vsctl_bridge.vlan
            ovsrec_port.tag = tag
        for setting in settings:
            # TODO:XXX self.symtab:
            column, key, value = setting
            self.set_column(ovsrec_port, column, key, value)

        if vsctl_bridge.parent:
            ovsrec_bridge = vsctl_bridge.parent.br_cfg
        else:
            ovsrec_bridge = vsctl_bridge.br_cfg
        self.bridge_insert_port(ovsrec_bridge, ovsrec_port)
        vsctl_port = self.add_port_to_cache(vsctl_bridge, ovsrec_port)
        for ovsrec_iface in ifaces:
            self.add_iface_to_cache(vsctl_port, ovsrec_iface)

    def add_bridge(self, br_name, parent_name=None, vlan=0, may_exist=False):
        self.populate_cache()
        if may_exist:
            vsctl_bridge = self.find_bridge(br_name, False)
            if vsctl_bridge:
                if not parent_name:
                    if vsctl_bridge.parent:
                        vsctl_fatal('"--may-exist add-vsctl_bridge %s" '
                                    'but %s is a VLAN bridge for VLAN %d' %
                                    (br_name, br_name, vsctl_bridge.vlan))
                else:
                    if not vsctl_bridge.parent:
                        vsctl_fatal('"--may-exist add-vsctl_bridge %s %s %d" '
                                    'but %s is not a VLAN bridge' %
                                    (br_name, parent_name, vlan, br_name))
                    elif vsctl_bridge.parent.name != parent_name:
                        vsctl_fatal('"--may-exist add-vsctl_bridge %s %s %d" '
                                    'but %s has the wrong parent %s' %
                                    (br_name, parent_name, vlan,
                                     br_name, vsctl_bridge.parent.name))
                    elif vsctl_bridge.vlan != vlan:
                        vsctl_fatal('"--may-exist add-vsctl_bridge %s %s %d" '
                                    'but %s is a VLAN bridge for the wrong '
                                    'VLAN %d' %
                                    (br_name, parent_name, vlan, br_name,
                                     vsctl_bridge.vlan))
                return

        self.check_conflicts(br_name,
                             'cannot create a bridge named %s' % br_name)

        txn = self.txn
        tables = self.idl.tables
        if not parent_name:
            ovsrec_iface = txn.insert(
                tables[vswitch_idl.OVSREC_TABLE_INTERFACE])
            ovsrec_iface.name = br_name
            ovsrec_iface.type = 'internal'

            ovsrec_port = txn.insert(tables[vswitch_idl.OVSREC_TABLE_PORT])
            ovsrec_port.name = br_name
            ovsrec_port.interfaces = [ovsrec_iface]
            ovsrec_port.fake_bridge = False

            ovsrec_bridge = txn.insert(tables[vswitch_idl.OVSREC_TABLE_BRIDGE])
            ovsrec_bridge.name = br_name
            ovsrec_bridge.ports = [ovsrec_port]

            self.ovs_insert_bridge(ovsrec_bridge)
        else:
            parent = self.find_bridge(parent_name, False)
            if parent and parent.parent:
                vsctl_fatal('cannot create bridge with fake bridge as parent')
            if not parent:
                vsctl_fatal('parent bridge %s does not exist' % parent_name)

            ovsrec_iface = txn.insert(
                tables[vswitch_idl.OVSREC_TABLE_INTERFACE])
            ovsrec_iface.name = br_name
            ovsrec_iface.type = 'internal'

            ovsrec_port = txn.insert(tables[vswitch_idl.OVSREC_TABLE_PORT])
            ovsrec_port.name = br_name
            ovsrec_port.interfaces = [ovsrec_iface]
            ovsrec_port.fake_bridge = True
            ovsrec_port.tag = [vlan]

            self.bridge_insert_port(parent.br_cfg, ovsrec_port)

        self.invalidate_cache()

    @staticmethod
    def parse_column_key_value(table_schema, setting_string):
        """
        parse <column>[:<key>]=<value>
        """
        column_value = setting_string.split('=', 1)
        if len(column_value) == 1:
            column = column_value[0]
            value = None
        else:
            column, value = column_value

        if ':' in column:
            column, key = column.split(':', 1)
        else:
            key = None
        if value is not None:
            LOG.debug("columns %s", table_schema.columns.keys())
            type_ = table_schema.columns[column].type
            value = datum_from_string(type_, value)
            LOG.debug("column %s value %s", column, value)

        return (column, key, value)

    def set_column(self, ovsrec_row, column, key, value_json):
        if column not in ovsrec_row._table.columns:
            vsctl_fatal('%s does not contain a column whose name matches "%s"'
                        % (ovsrec_row._table.name, column))

        column_schema = ovsrec_row._table.columns[column]
        if key is not None:
            value_json = ['map', [[key, value_json]]]
            if column_schema.type.value.type == ovs.db.types.VoidType:
                vsctl_fatal('cannot specify key to set for non-map column %s' %
                            column)
            datum = ovs.db.data.Datum.from_json(column_schema.type, value_json,
                                                self.symtab)
            values = getattr(ovsrec_row, column, {})
            values.update(datum.to_python(ovs.db.idl._uuid_to_row))
            setattr(ovsrec_row, column, values)
        else:
            datum = ovs.db.data.Datum.from_json(column_schema.type, value_json,
                                                self.symtab)
            setattr(ovsrec_row, column,
                    datum.to_python(ovs.db.idl._uuid_to_row))

    def _get_row_by_id(self, table_name, vsctl_row_id, record_id):
        if not vsctl_row_id.table:
            return None

        if not vsctl_row_id.name_column:
            if record_id != '.':
                return None
            values = self.idl.tables[vsctl_row_id.table].rows.values()
            if not values or len(values) > 2:
                return None
            referrer = values[0]
        else:
            referrer = None
            for ovsrec_row in self.idl.tables[
                    vsctl_row_id.table].rows.values():
                name = getattr(ovsrec_row, vsctl_row_id.name_column)
                assert type(name) in (list, str, unicode)
                if type(name) != list and name == record_id:
                    if (referrer):
                        vsctl_fatal('multiple rows in %s match "%s"' %
                                    (table_name, record_id))
                    referrer = ovsrec_row

        if not referrer:
            return None

        final = None
        if vsctl_row_id.uuid_column:
            referrer.verify(vsctl_row_id.uuid_column)
            uuid = getattr(referrer, vsctl_row_id.uuid_column)

            uuid_ = referrer._data[vsctl_row_id.uuid_column]
            assert uuid_.type.key.type == ovs.db.types.UuidType
            assert uuid_.type.value is None
            assert type(uuid) == list

            if len(uuid) == 1:
                final = uuid[0]
        else:
            final = referrer

        return final

    def get_row(self, vsctl_table, record_id):
        table_name = vsctl_table.table_name
        if ovsuuid.is_valid_string(record_id):
            uuid = ovsuuid.from_string(record_id)
            return self.idl.tables[table_name].rows.get(uuid)
        else:
            for vsctl_row_id in vsctl_table.row_ids:
                ovsrec_row = self._get_row_by_id(table_name, vsctl_row_id,
                                                 record_id)
                if ovsrec_row:
                    return ovsrec_row

        return None

    def must_get_row(self, vsctl_table, record_id):
        ovsrec_row = self.get_row(vsctl_table, record_id)
        if not ovsrec_row:
            vsctl_fatal('no row "%s" in table %s' % (record_id,
                                                     vsctl_table.table_name))
        return ovsrec_row


class _CmdShowTable(object):
    def __init__(self, table, name_column, columns, recurse):
        super(_CmdShowTable, self).__init__()
        self.table = table
        self.name_column = name_column
        self.columns = columns
        self.recurse = recurse


class _VSCtlRowID(object):
    def __init__(self, table, name_column, uuid_column):
        super(_VSCtlRowID, self).__init__()
        self.table = table
        self.name_column = name_column
        self.uuid_column = uuid_column


class _VSCtlTable(object):
    def __init__(self, table_name, vsctl_row_id_list):
        super(_VSCtlTable, self).__init__()
        self.table_name = table_name
        self.row_ids = vsctl_row_id_list


class VSCtlCommand(object):
    def __init__(self, command, args=None, options=None):
        super(VSCtlCommand, self).__init__()
        self.command = command
        self.args = args or []
        self.options = options or []

        # Data modified by commands
        self.result = None

        # internally used by VSCtl
        self._prerequisite = None
        self._run = None

    def has_option(self, option):
        return option in self.options


class VSCtl(object):
    def _reset(self):
        self.schema_helper = None
        self.ovs = None
        self.txn = None
        self.wait_for_reload = True
        self.dry_run = False

    def __init__(self, remote):
        super(VSCtl, self).__init__()
        self.remote = remote

        self.schema_json = None
        self.schema = None
        self.schema_helper = None
        self.ovs = None
        self.txn = None
        self.wait_for_reload = True
        self.dry_run = False

    def _rpc_get_schema_json(self, database):
        LOG.debug('remote %s', self.remote)
        error, stream_ = stream.Stream.open_block(
            stream.Stream.open(self.remote))
        if error:
            vsctl_fatal('error %s' % os.strerror(error))
        rpc = jsonrpc.Connection(stream_)
        request = jsonrpc.Message.create_request('get_schema', [database])
        error, reply = rpc.transact_block(request)
        rpc.close()

        if error:
            vsctl_fatal(os.strerror(error))
        elif reply.error:
            vsctl_fatal('error %s' % reply.error)
        return reply.result

    def _init_schema_helper(self):
        if self.schema_json is None:
            self.schema_json = self._rpc_get_schema_json(
                vswitch_idl.OVSREC_DB_NAME)
            schema_helper = idl.SchemaHelper(None, self.schema_json)
            schema_helper.register_all()
            self.schema = schema_helper.get_idl_schema()
        # LOG.debug('schema_json %s', schema_json)
        self.schema_helper = idl.SchemaHelper(None, self.schema_json)

    @staticmethod
    def _idl_block(idl_):
        poller = ovs.poller.Poller()
        idl_.wait(poller)
        poller.block()

    @staticmethod
    def _idl_wait(idl_, seqno):
        while idl_.change_seqno == seqno and not idl_.run():
            VSCtl._idl_block(idl_)

    def _run_prerequisites(self, commands):
        schema_helper = self.schema_helper
        schema_helper.register_table(vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH)
        if self.wait_for_reload:
            # LOG.debug('schema_helper._tables %s', schema_helper._tables)
            schema_helper.register_columns(
                vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH,
                [vswitch_idl.OVSREC_OPEN_VSWITCH_COL_CUR_CFG])

        for command in commands:
            if not command._prerequisite:
                continue
            ctx = VSCtlContext(None, None, None)
            command._prerequisite(ctx, command)
            ctx.done()

    def _do_vsctl(self, idl_, commands):
        txn = idl.Transaction(idl_)
        self.txn = txn
        if self.dry_run:
            txn.dry_run = True

        txn.add_comment('ovs-vsctl')  # TODO:XXX add operation name. args
        ovs_rows = idl_.tables[vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH].rows
        if ovs_rows:
            ovs_ = ovs_rows.values()[0]
        else:
            # XXX add verification that table is empty
            ovs_ = txn.insert(
                idl_.tables[vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH])

        if self.wait_for_reload:
            ovs_.increment(vswitch_idl.OVSREC_OPEN_VSWITCH_COL_NEXT_CFG)

        # TODO:XXX
        # symtab = ovsdb_symbol_table_create()
        ctx = VSCtlContext(idl_, txn, ovs_)
        for command in commands:
            if not command._run:
                continue
            command._run(ctx, command)
            if ctx.try_again:
                return False
        LOG.debug('result:\n%s', [command.result for command in commands])
        ctx.done()

        # TODO:XXX check if created symbols are really created, referenced.

        status = txn.commit_block()
        next_cfg = 0
        if self.wait_for_reload and status == idl.Transaction.SUCCESS:
            next_cfg = txn.get_increment_new_value()

        # TODO:XXX
        # if status in (idl.Transaction.UNCHANGED, idl.Transaction.SUCCESS):
        #     for command in commands:
        #         if not command.post_func:
        #             continue
        #         ctx = VSCtlContext(idl_, txn, self.ovs)
        #         command.post_func(ctx)
        #         ctx.done()

        txn_ = self.txn
        self.txn = None
        txn = None

        if status in (idl.Transaction.UNCOMMITTED, idl.Transaction.INCOMPLETE):
            not_reached()
        elif status == idl.Transaction.ABORTED:
            vsctl_fatal('transaction aborted')
        elif status in (idl.Transaction.UNCHANGED, idl.Transaction.SUCCESS):
            pass
        elif status == idl.Transaction.TRY_AGAIN:
            return False
        elif status == idl.Transaction.ERROR:
            vsctl_fatal('transaction error: %s' % txn_.get_error())
        elif status == idl.Transaction.NOT_LOCKED:
            vsctl_fatal('database not locked')
        else:
            not_reached()

        if self.wait_for_reload and status != idl.Transaction.UNCHANGED:
            while True:
                idl_.run()
                if (ovs_.cur_cfg >= next_cfg):
                    break
                self._idl_block(idl_)

        return True

    def _do_main(self, commands):
        """
        :type commands: list of VSCtlCommand
        """
        self._reset()
        self._init_schema_helper()
        self._run_prerequisites(commands)

        idl_ = idl.Idl(self.remote, self.schema_helper)
        seqno = idl_.change_seqno
        while True:
            self._idl_wait(idl_, seqno)

            seqno = idl_.change_seqno
            if self._do_vsctl(idl_, commands):
                break

            if self.txn:
                self.txn.abort()
                self.txn = None
            # TODO:XXX
            # ovsdb_symbol_table_destroy(symtab)

        idl_.close()

    def _run_command(self, commands):
        """
        :type commands: list of VSCtlCommand
        """
        all_commands = {
            # Open vSwitch commands.
            'init': (None, self._cmd_init),
            'show': (self._pre_cmd_show, self._cmd_show),

            # Bridge commands.
            'add-br': (self._pre_add_br, self._cmd_add_br),
            'del-br': (self._pre_get_info, self._cmd_del_br),
            'list-br': (self._pre_get_info, self._cmd_list_br),

            # Port. commands
            'list-ports': (self._pre_get_info, self._cmd_list_ports),
            'add-port': (self._pre_cmd_add_port, self._cmd_add_port),
            'del-port': (self._pre_get_info, self._cmd_del_port),
            # 'add-bond':
            # 'port-to-br':

            # Interface commands.
            'list-ifaces': (self._pre_get_info, self._cmd_list_ifaces),
            # 'iface-to-br':

            # Controller commands.
            'get-controller': (self._pre_controller, self._cmd_get_controller),
            'del-controller': (self._pre_controller, self._cmd_del_controller),
            'set-controller': (self._pre_controller, self._cmd_set_controller),
            # 'get-fail-mode':
            # 'del-fail-mode':
            # 'set-fail-mode':

            # Manager commands.
            # 'get-manager':
            # 'del-manager':
            # 'set-manager':

            # Switch commands.
            # 'emer-reset':

            # Database commands.
            # 'comment':
            'get': (self._pre_cmd_get, self._cmd_get),
            # 'list':
            'find': (self._pre_cmd_find, self._cmd_find),
            'set': (self._pre_cmd_set, self._cmd_set),
            # 'add':
            'clear': (self._pre_cmd_clear, self._cmd_clear),
            # 'create':
            # 'destroy':
            # 'wait-until':

            # for quantum_adapter
            'list-ifaces-verbose': (self._pre_cmd_list_ifaces_verbose,
                                    self._cmd_list_ifaces_verbose),
        }

        for command in commands:
            funcs = all_commands[command.command]
            command._prerequisite, command._run = funcs
        self._do_main(commands)

    def run_command(self, commands, timeout_sec=None, exception=None):
        if timeout_sec is None:
            self._run_command(commands)
        else:
            with hub.Timeout(timeout_sec, exception):
                self._run_command(commands)

    # commands
    def _cmd_init(self, _ctx, _command):
        # nothing. Just check connection to ovsdb
        pass

    _CMD_SHOW_TABLES = [
        _CmdShowTable(vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH, None,
                      [vswitch_idl.OVSREC_OPEN_VSWITCH_COL_MANAGER_OPTIONS,
                       vswitch_idl.OVSREC_OPEN_VSWITCH_COL_BRIDGES,
                       vswitch_idl.OVSREC_OPEN_VSWITCH_COL_OVS_VERSION],
                      False),
        _CmdShowTable(vswitch_idl.OVSREC_TABLE_BRIDGE,
                      vswitch_idl.OVSREC_BRIDGE_COL_NAME,
                      [vswitch_idl.OVSREC_BRIDGE_COL_CONTROLLER,
                       vswitch_idl.OVSREC_BRIDGE_COL_FAIL_MODE,
                       vswitch_idl.OVSREC_BRIDGE_COL_PORTS],
                      False),
        _CmdShowTable(vswitch_idl.OVSREC_TABLE_PORT,
                      vswitch_idl.OVSREC_PORT_COL_NAME,
                      [vswitch_idl.OVSREC_PORT_COL_TAG,
                       vswitch_idl.OVSREC_PORT_COL_TRUNKS,
                       vswitch_idl.OVSREC_PORT_COL_INTERFACES],
                      False),
        _CmdShowTable(vswitch_idl.OVSREC_TABLE_INTERFACE,
                      vswitch_idl.OVSREC_INTERFACE_COL_NAME,
                      [vswitch_idl.OVSREC_INTERFACE_COL_TYPE,
                       vswitch_idl.OVSREC_INTERFACE_COL_OPTIONS],
                      False),
        _CmdShowTable(vswitch_idl.OVSREC_TABLE_CONTROLLER,
                      vswitch_idl.OVSREC_CONTROLLER_COL_TARGET,
                      [vswitch_idl.OVSREC_CONTROLLER_COL_IS_CONNECTED],
                      False),
        _CmdShowTable(vswitch_idl.OVSREC_TABLE_MANAGER,
                      vswitch_idl.OVSREC_MANAGER_COL_TARGET,
                      [vswitch_idl.OVSREC_MANAGER_COL_IS_CONNECTED],
                      False),
    ]

    def _pre_cmd_show(self, _ctx, _command):
        schema_helper = self.schema_helper
        for show in self._CMD_SHOW_TABLES:
            schema_helper.register_table(show.table)
            if show.name_column:
                schema_helper.register_columns(show.table, [show.name_column])
            schema_helper.register_columns(show.table, show.columns)

    @staticmethod
    def _cmd_show_find_table_by_row(row):
        for show in VSCtl._CMD_SHOW_TABLES:
            if show.table == row._table.name:
                return show
        return None

    @staticmethod
    def _cmd_show_find_table_by_name(name):
        for show in VSCtl._CMD_SHOW_TABLES:
            if show.table == name:
                return show
        return None

    @staticmethod
    def _cmd_show_row(ctx, row, level):
        _INDENT_SIZE = 4  # # of spaces per indent
        show = VSCtl._cmd_show_find_table_by_row(row)
        output = ''

        output += ' ' * level * _INDENT_SIZE
        if show and show.name_column:
            output += '%s ' % show.table
            datum = getattr(row, show.name_column)
            output += datum
        else:
            output += str(row.uuid)
        output += '\n'

        if not show or show.recurse:
            return

        show.recurse = True
        for column in show.columns:
            datum = row._data[column]
            key = datum.type.key
            if (key.type == ovs.db.types.UuidType and key.ref_table_name):
                ref_show = VSCtl._cmd_show_find_table_by_name(
                    key.ref_table_name)
                if ref_show:
                    for atom in datum.values:
                        ref_row = ctx.idl.tables[ref_show.table].rows.get(
                            atom.value)
                        if ref_row:
                            VSCtl._cmd_show_row(ctx, ref_row, level + 1)
                    continue

            if not datum.is_default():
                output += ' ' * (level + 1) * _INDENT_SIZE
                output += '%s: %s\n' % (column, datum)

        show.recurse = False
        return output

    def _cmd_show(self, ctx, command):
        for row in ctx.idl.tables[
                self._CMD_SHOW_TABLES[0].table].rows.values():
            output = self._cmd_show_row(ctx, row, 0)
            command.result = output

    def _pre_get_info(self, _ctx, _command):
        schema_helper = self.schema_helper

        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH,
            [vswitch_idl.OVSREC_OPEN_VSWITCH_COL_BRIDGES])
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_BRIDGE,
            [vswitch_idl.OVSREC_BRIDGE_COL_NAME,
             vswitch_idl.OVSREC_BRIDGE_COL_CONTROLLER,
             vswitch_idl.OVSREC_BRIDGE_COL_FAIL_MODE,
             vswitch_idl.OVSREC_BRIDGE_COL_PORTS])
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_PORT,
            [vswitch_idl.OVSREC_PORT_COL_NAME,
             vswitch_idl.OVSREC_PORT_COL_FAKE_BRIDGE,
             vswitch_idl.OVSREC_PORT_COL_TAG,
             vswitch_idl.OVSREC_PORT_COL_INTERFACES])
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_INTERFACE,
            [vswitch_idl.OVSREC_INTERFACE_COL_NAME])

    def _cmd_list_br(self, ctx, command):
        ctx.populate_cache()
        command.result = sorted(ctx.bridges.keys())

    def _pre_add_br(self, ctx, command):
        self._pre_get_info(ctx, command)

        schema_helper = self.schema_helper
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_INTERFACE,
            [vswitch_idl.OVSREC_INTERFACE_COL_TYPE])

    def _cmd_add_br(self, ctx, command):
        br_name = command.args[0]
        if len(command.args) == 1:
            parent_name = None
            vlan = 0
        elif len(command.args) == 3:
            parent_name = command.args[1]
            vlan = int(command.args[2])
            if vlan < 0 or vlan > 4095:
                vsctl_fatal("vlan must be between 0 and 4095 %d" % vlan)
        else:
            vsctl_fatal('this command takes exactly 1 or 3 argument')

        ctx.add_bridge(br_name, parent_name, vlan)

    def _del_br(self, ctx, br_name, must_exist=False):
        ctx.populate_cache()
        br = ctx.find_bridge(br_name, must_exist)
        if br:
            ctx.del_bridge(br)

    def _cmd_del_br(self, ctx, command):
        br_name = command.args[0]
        self._del_br(ctx, br_name)

    def _list_ports(self, ctx, br_name):
        ctx.populate_cache()
        br = ctx.find_bridge(br_name, True)
        if br.br_cfg:
            br.br_cfg.verify(vswitch_idl.OVSREC_BRIDGE_COL_PORTS)
        else:
            br.parent.br_cfg.verify(vswitch_idl.OVSREC_BRIDGE_COL_PORTS)

        return [port.port_cfg.name for port in br.ports
                if port.port_cfg.name != br.name]

    def _cmd_list_ports(self, ctx, command):
        br_name = command.args[0]
        port_names = self._list_ports(ctx, br_name)
        command.result = sorted(port_names)

    def _pre_add_port(self, _ctx, columns):
        schema_helper = self.schema_helper
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_PORT,
            [vswitch_idl.OVSREC_PORT_COL_NAME,
             vswitch_idl.OVSREC_PORT_COL_BOND_FAKE_IFACE])
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_PORT, columns)

    def _pre_cmd_add_port(self, ctx, command):
        self._pre_get_info(ctx, command)

        columns = [ctx.parse_column_key_value(
            self.schema.tables[vswitch_idl.OVSREC_TABLE_PORT], setting)[0]
            for setting in command.args[2:]]
        self._pre_add_port(ctx, columns)

    def _cmd_add_port(self, ctx, command):
        may_exist = command.has_option('--may_exist')

        br_name = command.args[0]
        port_name = command.args[1]
        iface_names = [command.args[1]]
        settings = [ctx.parse_column_key_value(
            self.schema.tables[vswitch_idl.OVSREC_TABLE_PORT], setting)
            for setting in command.args[2:]]
        ctx.add_port(br_name, port_name, may_exist,
                     False, iface_names, settings)

    def _del_port(self, ctx, br_name=None, target=None,
                  must_exist=False, with_iface=False):
        assert target is not None

        ctx.populate_cache()
        if not with_iface:
            vsctl_port = ctx.find_port(target, must_exist)
        else:
            vsctl_port = ctx.find_port(target, False)
            if not vsctl_port:
                vsctl_iface = ctx.find_iface(target, False)
                if vsctl_iface:
                    vsctl_port = vsctl_iface.port()
                if must_exist and not vsctl_port:
                    vsctl_fatal('no port or interface named %s' % target)

        if not vsctl_port:
            return
        if not br_name:
            vsctl_bridge = ctx.find_bridge(br_name, True)
            if vsctl_port.bridge() != vsctl_bridge:
                if vsctl_port.bridge().parent == vsctl_bridge:
                    vsctl_fatal('bridge %s does not have a port %s (although '
                                'its parent bridge %s does)' %
                                (br_name, target, vsctl_bridge.parent.name))
                else:
                    vsctl_fatal('bridge %s does not have a port %s' %
                                (br_name, target))

        ctx.del_port(vsctl_port)

    def _cmd_del_port(self, ctx, command):
        must_exist = command.has_option('--must-exist')
        with_iface = command.has_option('--with-iface')
        target = command.args[-1]
        br_name = command.args[0] if len(command.args) == 2 else None
        self._del_port(ctx, br_name, target, must_exist, with_iface)

    def _list_ifaces(self, ctx, br_name):
        ctx.populate_cache()

        br = ctx.find_bridge(br_name, True)
        ctx.verify_ports()

        iface_names = set()
        for vsctl_port in br.ports:
            for vsctl_iface in vsctl_port.ifaces:
                iface_name = vsctl_iface.iface_cfg.name
                if iface_name != br_name:
                    iface_names.add(iface_name)
        return iface_names

    def _cmd_list_ifaces(self, ctx, command):
        br_name = command.args[0]
        iface_names = self._list_ifaces(ctx, br_name)
        command.result = sorted(iface_names)

    def _pre_cmd_list_ifaces_verbose(self, ctx, command):
        self._pre_get_info(ctx, command)
        schema_helper = self.schema_helper
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_BRIDGE,
            [vswitch_idl.OVSREC_BRIDGE_COL_DATAPATH_ID])
        schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_INTERFACE,
            [vswitch_idl.OVSREC_INTERFACE_COL_TYPE,
             vswitch_idl.OVSREC_INTERFACE_COL_NAME,
             vswitch_idl.OVSREC_INTERFACE_COL_EXTERNAL_IDS,
             vswitch_idl.OVSREC_INTERFACE_COL_OPTIONS,
             vswitch_idl.OVSREC_INTERFACE_COL_OFPORT])

    @staticmethod
    def _iface_to_dict(iface_cfg):
        _ATTRIBUTE = ['name', 'ofport', 'type', 'external_ids', 'options']
        attr = dict((key, getattr(iface_cfg, key)) for key in _ATTRIBUTE)

        if attr['ofport']:
            attr['ofport'] = attr['ofport'][0]
        return attr

    def _list_ifaces_verbose(self, ctx, datapath_id, port_name):
        ctx.populate_cache()

        br = ctx.find_bridge_by_id(datapath_id, True)
        ctx.verify_ports()

        iface_cfgs = []
        if port_name is None:
            for vsctl_port in br.ports:
                iface_cfgs.extend(self._iface_to_dict(vsctl_iface.iface_cfg)
                                  for vsctl_iface in vsctl_port.ifaces)
        else:
            # When port is created, ofport column might be None.
            # So try with port name if it happended
            for vsctl_port in br.ports:
                iface_cfgs.extend(
                    self._iface_to_dict(vsctl_iface.iface_cfg)
                    for vsctl_iface in vsctl_port.ifaces
                    if (vsctl_iface.iface_cfg.name == port_name))

        return iface_cfgs

    def _cmd_list_ifaces_verbose(self, ctx, command):
        datapath_id = command.args[0]
        port_name = None
        if len(command.args) >= 2:
            port_name = command.args[1]
        LOG.debug('command.args %s', command.args)
        iface_cfgs = self._list_ifaces_verbose(ctx, datapath_id, port_name)
        command.result = sorted(iface_cfgs)

    def _verify_controllers(self, ovsrec_bridge):
        ovsrec_bridge.verify(vswitch_idl.OVSREC_BRIDGE_COL_CONTROLLER)
        for controller in ovsrec_bridge.controller:
            controller.verify(vswitch_idl.OVSREC_CONTROLLER_COL_TARGET)

    def _pre_controller(self, ctx, command):
        self._pre_get_info(ctx, command)
        self.schema_helper.register_columns(
            vswitch_idl.OVSREC_TABLE_CONTROLLER,
            [vswitch_idl.OVSREC_CONTROLLER_COL_TARGET])

    def _get_controller(self, ctx, br_name):
        ctx.populate_cache()
        br = ctx.find_bridge(br_name, True)
        self._verify_controllers(br.br_cfg)
        return set(controller.target for controller in br.br_cfg.controller)

    def _cmd_get_controller(self, ctx, command):
        br_name = command.args[0]
        controller_names = self._get_controller(ctx, br_name)
        command.result = sorted(controller_names)

    def _delete_controllers(self, ovsrec_controllers):
        for controller in ovsrec_controllers:
            controller.delete()

    def _del_controller(self, ctx, br_name):
        ctx.populate_cache()
        br = ctx.find_real_bridge(br_name, True)
        ovsrec_bridge = br.br_cfg
        self._verify_controllers(ovsrec_bridge)
        if ovsrec_bridge.controller:
            self._delete_controllers(ovsrec_bridge.controller)
            ovsrec_bridge.controller = []

    def _cmd_del_controller(self, ctx, command):
        br_name = command.args[0]
        self._del_controller(ctx, br_name)

    def _insert_controllers(self, controller_names):
        ovsrec_controllers = []
        for name in controller_names:
            # TODO: check if the name startswith() supported protocols
            ovsrec_controller = self.txn.insert(
                self.txn.idl.tables[vswitch_idl.OVSREC_TABLE_CONTROLLER])
            ovsrec_controller.target = name
            ovsrec_controllers.append(ovsrec_controller)
        return ovsrec_controllers

    def _set_controller(self, ctx, br_name, controller_names):
        ctx.populate_cache()
        ovsrec_bridge = ctx.find_real_bridge(br_name, True).br_cfg
        self._verify_controllers(ovsrec_bridge)
        self._delete_controllers(ovsrec_bridge.controller)
        controllers = self._insert_controllers(controller_names)
        ovsrec_bridge.controller = controllers

    def _cmd_set_controller(self, ctx, command):
        br_name = command.args[0]
        controller_names = command.args[1:]
        self._set_controller(ctx, br_name, controller_names)

    _TABLES = [
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_BRIDGE,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_BRIDGE,
                                 vswitch_idl.OVSREC_BRIDGE_COL_NAME,
                                 None)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_CONTROLLER,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_BRIDGE,
                                 vswitch_idl.OVSREC_BRIDGE_COL_NAME,
                                 vswitch_idl.OVSREC_BRIDGE_COL_CONTROLLER)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_INTERFACE,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_INTERFACE,
                                 vswitch_idl.OVSREC_INTERFACE_COL_NAME,
                                 None)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_MIRROR,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_MIRROR,
                                 vswitch_idl.OVSREC_MIRROR_COL_NAME,
                                 None)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_MANAGER,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_MANAGER,
                                 vswitch_idl.OVSREC_MANAGER_COL_TARGET,
                                 None)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_NETFLOW,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_BRIDGE,
                                 vswitch_idl.OVSREC_BRIDGE_COL_NAME,
                                 vswitch_idl.OVSREC_BRIDGE_COL_NETFLOW)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH,
                                 None,
                                 None)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_PORT,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_PORT,
                                 vswitch_idl.OVSREC_PORT_COL_NAME,
                                 None)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_QOS,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_PORT,
                                 vswitch_idl.OVSREC_PORT_COL_NAME,
                                 vswitch_idl.OVSREC_PORT_COL_QOS)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_QUEUE, []),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_SSL,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_OPEN_VSWITCH,
                                 None,
                                 vswitch_idl.OVSREC_OPEN_VSWITCH_COL_SSL)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_SFLOW,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_BRIDGE,
                                 vswitch_idl.OVSREC_BRIDGE_COL_NAME,
                                 vswitch_idl.OVSREC_BRIDGE_COL_SFLOW)]),
        _VSCtlTable(vswitch_idl.OVSREC_TABLE_FLOW_TABLE,
                    [_VSCtlRowID(vswitch_idl.OVSREC_TABLE_FLOW_TABLE,
                                 vswitch_idl.OVSREC_FLOW_TABLE_COL_NAME,
                                 None)]),
    ]

    @staticmethod
    def _score_partial_match(name, s):
        _MAX_SCORE = 0xffffffff
        assert len(name) < _MAX_SCORE
        s = s[:_MAX_SCORE - 1]  # in practice, this doesn't matter
        if name == s:
            return _MAX_SCORE

        name = name.lower().replace('-', '_')
        s = s.lower().replace('-', '_')
        if s.startswith(name):
            return _MAX_SCORE - 1
        if name.startswith(s):
            return len(s)

        return 0

    @staticmethod
    def _get_table(table_name):
        best_match = None
        best_score = 0
        for table in VSCtl._TABLES:
            score = VSCtl._score_partial_match(table.table_name, table_name)
            if score > best_score:
                best_match = table
                best_score = score
            elif score == best_score:
                best_match = None

        if best_match:
            return best_match
        elif best_score:
            vsctl_fatal('multiple table names match "%s"' % table_name)
        else:
            vsctl_fatal('unknown table "%s"' % table_name)

    def _pre_get_table(self, _ctx, table_name):
        vsctl_table = self._get_table(table_name)

        schema_helper = self.schema_helper
        schema_helper.register_table(vsctl_table.table_name)
        for row_id in vsctl_table.row_ids:
            if row_id.table:
                schema_helper.register_table(row_id.table)
            if row_id.name_column:
                schema_helper.register_columns(row_id.table,
                                               [row_id.name_column])
            if row_id.uuid_column:
                schema_helper.register_columns(row_id.table,
                                               [row_id.uuid_column])
        return vsctl_table

    def _get_column(self, table_name, column_name):
        best_match = None
        best_score = 0

        columns = self.schema.tables[table_name].columns.keys()
        for column in columns:
            score = VSCtl._score_partial_match(column, column_name)
            if score > best_score:
                best_match = column
                best_score = score
            elif score == best_score:
                best_match = None

        if best_match:
            # ovs.db.schema_helper._keep_table_columns() requires that
            # column_name is type of str. Not unicode string
            return str(best_match)
        elif best_score:
            vsctl_fatal('%s contains more than one column whose name '
                        'matches "%s"' % (table_name, column_name))
        else:
            vsctl_fatal('%s does not contain a column whose name matches '
                        '"%s"' % (table_name, column_name))

    def _pre_get_column(self, _ctx, table_name, column):
        column_name = self._get_column(table_name, column)
        self.schema_helper.register_columns(table_name, [column_name])

    def _pre_get(self, ctx, table_name, columns):
        vsctl_table = self._pre_get_table(ctx, table_name)
        for column in columns:
            self._pre_get_column(ctx, vsctl_table.table_name, column)

    def _pre_cmd_get(self, ctx, command):
        table_name = command.args[0]
        table_schema = self.schema.tables[table_name]
        columns = [ctx.parse_column_key_value(table_schema, column_key)[0]
                   for column_key in command.args[2:]]
        self._pre_get(ctx, table_name, columns)

    def _get(self, ctx, table_name, record_id, column_keys,
             id_=None, if_exists=False):
        """
        :type column_keys: list of (column, key_string)
                                   where column and key are str
        """
        vsctl_table = self._get_table(table_name)
        row = ctx.must_get_row(vsctl_table, record_id)
        if id_:
            raise NotImplementedError()  # TODO:XXX

            symbol, new = ctx.create_symbol(id_)
            if not new:
                vsctl_fatal('row id "%s" specified on "get" command was used '
                            'before it was defined' % id_)
            symbol.uuid = row.uuid
            symbol.strong_ref = True

        values = []
        for column, key_string in column_keys:
            row.verify(column)
            datum = getattr(row, column)
            if key_string:
                if type(datum) != dict:
                    vsctl_fatal('cannot specify key to get for non-map column '
                                '%s' % column)
                values.append(datum[key_string])
            else:
                values.append(datum)

        return values

    def _cmd_get(self, ctx, command):
        id_ = None      # TODO:XXX      --id
        if_exists = command.has_option('--if-exists')
        table_name = command.args[0]
        record_id = command.args[1]
        table_schema = self.schema.tables[table_name]
        column_keys = [ctx.parse_column_key_value(table_schema, column_key)[:2]
                       for column_key in command.args[2:]]

        values = self._get(ctx, table_name, record_id, column_keys,
                           id_, if_exists)
        command.result = values

    def _pre_cmd_find(self, ctx, command):
        table_name = command.args[0]
        table_schema = self.schema.tables[table_name]
        columns = [ctx.parse_column_key_value(table_schema,
                                              column_key_value)[0]
                   for column_key_value in command.args[1:]]
        LOG.debug('columns %s', columns)
        self._pre_get(ctx, table_name, columns)

    def _check_value(self, ovsrec_row, column_key_value):
        column, key, value_json = column_key_value
        column_schema = ovsrec_row._table.columns[column]
        value = ovs.db.data.Datum.from_json(
            column_schema.type, value_json).to_python(ovs.db.idl._uuid_to_row)
        datum = getattr(ovsrec_row, column)
        if key is None:
            if datum == value:
                return True
        else:
            if datum[key] != value:
                return True
        return False

    def _find(self, ctx, table_name, column_key_values):
        result = []
        for ovsrec_row in ctx.idl.tables[table_name].rows.values():
            LOG.debug('ovsrec_row %s', ovsrec_row_to_string(ovsrec_row))
            if all(self._check_value(ovsrec_row, column_key_value)
                   for column_key_value in column_key_values):
                result.append(ovsrec_row)

        return result

    def _cmd_find(self, ctx, command):
        table_name = command.args[0]
        table_schema = self.schema.tables[table_name]
        column_key_values = [ctx.parse_column_key_value(table_schema,
                                                        column_key_value)
                             for column_key_value in command.args[1:]]
        command.result = self._find(ctx, table_name, column_key_values)

    def _check_mutable(self, table_name, column):
        column_schema = self.schema.tables[table_name].columns[column]
        if not column_schema.mutable:
            vsctl_fatal('cannot modify read-only column %s in table %s' %
                        (column, table_name))

    def _pre_set(self, ctx, table_name, columns):
        self._pre_get_table(ctx, table_name)
        for column in columns:
            self._pre_get_column(ctx, table_name, column)
            self._check_mutable(table_name, column)

    def _pre_cmd_set(self, ctx, command):
        table_name = command.args[0]
        table_schema = self.schema.tables[table_name]
        columns = [ctx.parse_column_key_value(table_schema,
                                              column_key_value)[0]
                   for column_key_value in command.args[2:]]
        self._pre_set(ctx, table_name, columns)

    def _set(self, ctx, table_name, record_id, column_key_values):
        """
        :type column_key_values: list of (column, key_string, value_json)
        """
        vsctl_table = self._get_table(table_name)
        ovsrec_row = ctx.must_get_row(vsctl_table, record_id)
        for column, key, value in column_key_values:
            ctx.set_column(ovsrec_row, column, key, value)
        ctx.invalidate_cache()

    def _cmd_set(self, ctx, command):
        table_name = command.args[0]
        record_id = command.args[1]

        # column_key_value: <column>[:<key>]=<value>
        table_schema = self.schema.tables[table_name]
        column_key_values = [ctx.parse_column_key_value(table_schema,
                                                        column_key_value)
                             for column_key_value in command.args[2:]]

        self._set(ctx, table_name, record_id, column_key_values)

    def _pre_clear(self, ctx, table_name, column):
        self._pre_get_table(ctx, table_name)
        self._pre_get_column(ctx, table_name, column)
        self._check_mutable(table_name, column)

    def _pre_cmd_clear(self, ctx, command):
        table_name = command.args[0]
        column = command.args[2]
        self._pre_clear(ctx, table_name, column)

    def _clear(self, ctx, table_name, record_id, column):
        vsctl_table = self._get_table(table_name)
        ovsrec_row = ctx.must_get_row(vsctl_table, record_id)
        column_schema = ctx.idl.tables[table_name].columns[column]
        if column_schema.type.n_min > 0:
            vsctl_fatal('"clear" operation cannot be applied to column %s '
                        'of table %s, which is not allowed to be empty' %
                        (column, table_name))

        # assuming that default datum is empty.
        default_datum = ovs.db.data.Datum.default(column_schema.type)
        setattr(ovsrec_row, column,
                default_datum.to_python(ovs.db.idl._uuid_to_row))
        ctx.invalidate_cache()

    def _cmd_clear(self, ctx, command):
        table_name = command.args[0]
        record_id = command.args[1]
        column = command.args[2]
        self._clear(ctx, table_name, record_id, column)


#
# Create constants from ovs db schema
#

def schema_print(schema_location, prefix):
    prefix = prefix.upper()

    json = ovs.json.from_file(schema_location)
    schema = ovs.db.schema.DbSchema.from_json(json)

    print '# Do NOT edit.'
    print '# This is automatically generated.'
    print '# created based on version %s' % (schema.version or 'unknown')
    print ''
    print ''
    print '%s_DB_NAME = \'%s\'' % (prefix, schema.name)
    for table in sorted(schema.tables.values(),
                        key=operator.attrgetter('name')):
        print ''
        print '%s_TABLE_%s = \'%s\'' % (prefix,
                                        table.name.upper(), table.name)
        for column in sorted(table.columns.values(),
                             key=operator.attrgetter('name')):
            print '%s_%s_COL_%s = \'%s\'' % (prefix, table.name.upper(),
                                             column.name.upper(),
                                             column.name)


def main():
    if len(sys.argv) <= 2:
        print 'Usage: %s <schema file> <prefix>' % sys.argv[0]

    location = sys.argv[1]
    prefix = sys.argv[2]
    schema_print(location, prefix)


if __name__ == '__main__':
    main()
