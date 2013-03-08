# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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

import gevent
import traceback

import lxml.etree
import ncclient

from ryu.base import app_manager
from ryu.lib.netconf import constants as nc_consts
from ryu.lib import of_config
from ryu.lib.of_config import capable_switch
from ryu.lib.of_config import constants as ofc_consts


# Change those depending on switch configuration
HOST = '127.0.0.1'
PORT = 1830
USERNAME = 'linc'
PASSWORD = 'linc'

CAPABLE_SWITCH_ID = 'CapableSwitch0'
LOGICAL_SWITCH = 'LogicalSwitch0'
PORT_ID = 'LogicalSwitch0-Port2'
CONTROLLER_ID = 'Switch0-DefaultController'

PORT_DICT = {
    'capable_switch': CAPABLE_SWITCH_ID,
    'port_id': PORT_ID,
    'logical_switch': LOGICAL_SWITCH,
    'controller_id': CONTROLLER_ID,
    'ip': HOST,
}

SWITCH_PORT_DOWN = '''
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capable-switch xmlns="urn:onf:of111:config:yang">
    <id>%(capable_switch)s</id>
    <resources>
      <port>
        <resource-id>%(port_id)s</resource-id>
        <configuration operation="merge">
          <admin-state>down</admin-state>
          <no-receive>false</no-receive>
          <no-forward>false</no-forward>
          <no-packet-in>false</no-packet-in>
        </configuration>
      </port>
    </resources>
  </capable-switch>
</nc:config>
''' % PORT_DICT

SWITCH_ADVERTISED = '''
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capable-switch xmlns="urn:onf:of111:config:yang">
    <id>%(capable_switch)s</id>
    <resources>
      <port>
        <resource-id>%(port_id)s</resource-id>
        <features>
          <advertised operation="merge">
            <rate>10Mb-FD</rate>
            <auto-negotiate>true</auto-negotiate>
            <medium>copper</medium>
            <pause>unsupported</pause>
          </advertised>
        </features>
      </port>
    </resources>
  </capable-switch>
</nc:config>
''' % PORT_DICT

SWITCH_CONTROLLER = '''
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capable-switch xmlns="urn:onf:of111:config:yang">
    <id>%(capable_switch)s</id>
    <logical-switches>
      <switch>
        <id>%(logical_switch)s</id>
          <controllers>
            <controller operation="merge">
              <id>%(controller_id)s</id>
              <role>master</role>
              <ip-address>%(ip)s</ip-address>
              <port>6633</port>
              <protocol>tcp</protocol>
            </controller>
          </controllers>
      </switch>
    </logical-switches>
  </capable-switch>
</nc:config>
''' % PORT_DICT


def _get_schema():
    # file_name = of_config.OF_CONFIG_1_0_XSD
    # file_name = of_config.OF_CONFIG_1_1_XSD
    file_name = of_config.OF_CONFIG_1_1_1_XSD
    return lxml.etree.XMLSchema(file=file_name)


class OFConfigClient(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(OFConfigClient, self).__init__(*args, **kwargs)
        self.switch = capable_switch.OFCapableSwitch(
            host=HOST, port=PORT, username=USERNAME, password=PASSWORD)
        gevent.spawn(self._do_of_config)

    def _validate(self, tree):
        xmlschema = _get_schema()
        try:
            xmlschema.assertValid(tree)
        except:
            traceback.print_exc()

    def _do_get(self):
        data_xml = self.switch.get()

        tree = lxml.etree.fromstring(data_xml)
        # print(lxml.etree.tostring(tree, pretty_print=True))
        self._validate(tree)

        name_spaces = set()
        for e in tree.getiterator():
            name_spaces.add(capable_switch.get_ns_tag(e.tag)[0])
        print(name_spaces)

        return tree

    def _do_get_config(self, source):
        print('source = %s' % source)
        config_xml = self.switch.get_config(source)

        tree = lxml.etree.fromstring(config_xml)
        # print(lxml.etree.tostring(tree, pretty_print=True))
        self._validate(tree)

    def _do_edit_config(self, config):
        tree = lxml.etree.fromstring(config)
        self._validate(tree)
        self.switch.edit_config(target='running', config=config)

    def _print_ports(self, tree, ns):
        for port in tree.findall('{%s}%s/{%s}%s' % (ns, ofc_consts.RESOURCES,
                                                    ns, ofc_consts.PORT)):
            print(lxml.etree.tostring(port, pretty_print=True))

    def _set_ports_down(self):
        """try to set all ports down with etree operation"""
        tree = self._do_get()
        print lxml.etree.tostring(tree, pretty_print=True)

        qname = lxml.etree.QName(tree.tag)
        ns = qname.namespace
        self._print_ports(tree, ns)

        switch_id = tree.find('{%s}%s' % (ns, ofc_consts.ID))
        resources = tree.find('{%s}%s' % (ns, ofc_consts.RESOURCES))
        configuration = tree.find(
            '{%s}%s/{%s}%s/{%s}%s' % (ns, ofc_consts.RESOURCES,
                                      ns, ofc_consts.PORT,
                                      ns, ofc_consts.CONFIGURATION))
        admin_state = tree.find(
            '{%s}%s/{%s}%s/{%s}%s/{%s}%s' % (ns, ofc_consts.RESOURCES,
                                             ns, ofc_consts.PORT,
                                             ns, ofc_consts.CONFIGURATION,
                                             ns, ofc_consts.ADMIN_STATE))

        config_ = lxml.etree.Element(
            '{%s}%s' % (ncclient.xml_.BASE_NS_1_0, nc_consts.CONFIG))
        capable_switch_ = lxml.etree.SubElement(config_, tree.tag)
        switch_id_ = lxml.etree.SubElement(capable_switch_, switch_id.tag)
        switch_id_.text = switch_id.text
        resources_ = lxml.etree.SubElement(capable_switch_,
                                           resources.tag)
        for port in tree.findall(
                '{%s}%s/{%s}%s' % (ns, ofc_consts.RESOURCES,
                                   ns, ofc_consts.PORT)):
            resource_id = port.find('{%s}%s' % (ns, ofc_consts.RESOURCE_ID))

            port_ = lxml.etree.SubElement(resources_, port.tag)
            resource_id_ = lxml.etree.SubElement(port_, resource_id.tag)
            resource_id_.text = resource_id.text
            configuration_ = lxml.etree.SubElement(port_, configuration.tag)
            configuration_.set(ofc_consts.OPERATION, nc_consts.MERGE)
            admin_state_ = lxml.etree.SubElement(configuration_,
                                                 admin_state.tag)
            admin_state_.text = ofc_consts.DOWN
        self._do_edit_config(lxml.etree.tostring(config_, pretty_print=True))

        tree = self._do_get()
        self._print_ports(tree, ns)

    def _do_of_config(self):
        self._do_get()
        self._do_get_config('running')
        self._do_get_config('startup')

        # LINC doesn't support 'candidate' datastore
        try:
            self._do_get_config('candidate')
        except ncclient.NCClientError:
            traceback.print_exc()

        # use raw XML format
        self._do_edit_config(SWITCH_PORT_DOWN)
        self._do_edit_config(SWITCH_ADVERTISED)
        self._do_edit_config(SWITCH_CONTROLLER)

        self._set_ports_down()

        self.switch.close_session()
