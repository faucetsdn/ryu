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

import unittest
from nose.tools import eq_
from nose.tools import ok_

import sys
import lxml.etree as ET
from formencode.doctest_xml_compare import xml_compare

from ryu.lib.of_config import classes as ofc


GET = """<ns0:capable-switch xmlns:ns0="urn:onf:of111:config:yang">
  <ns0:id>CapableSwitch0</ns0:id>
  <ns0:resources>
    <ns0:port>
      <ns0:resource-id>LogicalSwitch9-Port4</ns0:resource-id>
      <ns0:number>4</ns0:number>
      <ns0:name>Port4</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>up</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    <ns0:port>
      <ns0:resource-id>LogicalSwitch9-Port3</ns0:resource-id>
      <ns0:number>3</ns0:number>
      <ns0:name>Port3</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>up</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    <ns0:port>
      <ns0:resource-id>LogicalSwitch7-Port2</ns0:resource-id>
      <ns0:number>2</ns0:number>
      <ns0:name>Port2</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>up</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    <ns0:port>
      <ns0:resource-id>LogicalSwitch7-Port1</ns0:resource-id>
      <ns0:number>1</ns0:number>
      <ns0:name>Port1</ns0:name>
      <ns0:current-rate>5000</ns0:current-rate>
      <ns0:max-rate>5000</ns0:max-rate>
      <ns0:configuration>
        <ns0:admin-state>up</ns0:admin-state>
        <ns0:no-receive>false</ns0:no-receive>
        <ns0:no-forward>false</ns0:no-forward>
        <ns0:no-packet-in>false</ns0:no-packet-in>
      </ns0:configuration>
      <ns0:state>
        <ns0:oper-state>up</ns0:oper-state>
        <ns0:blocked>false</ns0:blocked>
        <ns0:live>true</ns0:live>
      </ns0:state>
      <ns0:features>
        <ns0:current>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:current>
        <ns0:advertised>
          <ns0:rate>other</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised>
        <ns0:supported>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:supported>
        <ns0:advertised-peer>
          <ns0:rate>100Mb-FD</ns0:rate>
          <ns0:auto-negotiate>true</ns0:auto-negotiate>
          <ns0:medium>copper</ns0:medium>
          <ns0:pause>unsupported</ns0:pause>
        </ns0:advertised-peer>
      </ns0:features>
    </ns0:port>
    <ns0:queue>
      <ns0:resource-id>LogicalSwitch9-Port4-Queue992</ns0:resource-id>
      <ns0:id>992</ns0:id>
      <ns0:port>4</ns0:port>
      <ns0:properties>
        <ns0:min-rate>10</ns0:min-rate>
        <ns0:max-rate>130</ns0:max-rate>
      </ns0:properties>
    </ns0:queue>
    <ns0:queue>
      <ns0:resource-id>LogicalSwitch9-Port4-Queue991</ns0:resource-id>
      <ns0:id>991</ns0:id>
      <ns0:port>4</ns0:port>
      <ns0:properties>
        <ns0:min-rate>10</ns0:min-rate>
        <ns0:max-rate>120</ns0:max-rate>
      </ns0:properties>
    </ns0:queue>
    <ns0:queue>
      <ns0:resource-id>LogicalSwitch7-Port2-Queue994</ns0:resource-id>
      <ns0:id>994</ns0:id>
      <ns0:port>2</ns0:port>
      <ns0:properties>
        <ns0:min-rate>400</ns0:min-rate>
        <ns0:max-rate>900</ns0:max-rate>
      </ns0:properties>
    </ns0:queue>
    <ns0:queue>
      <ns0:resource-id>LogicalSwitch7-Port2-Queue993</ns0:resource-id>
      <ns0:id>993</ns0:id>
      <ns0:port>2</ns0:port>
      <ns0:properties>
        <ns0:min-rate>200</ns0:min-rate>
        <ns0:max-rate>300</ns0:max-rate>
      </ns0:properties>
    </ns0:queue>
  </ns0:resources>
  <ns0:logical-switches>
    <ns0:switch>
      <ns0:id>LogicalSwitch9</ns0:id>
      <ns0:capabilities>
        <ns0:max-buffered-packets>0</ns0:max-buffered-packets>
        <ns0:max-tables>255</ns0:max-tables>
        <ns0:max-ports>16777216</ns0:max-ports>
        <ns0:flow-statistics>true</ns0:flow-statistics>
        <ns0:table-statistics>true</ns0:table-statistics>
        <ns0:port-statistics>true</ns0:port-statistics>
        <ns0:group-statistics>true</ns0:group-statistics>
        <ns0:queue-statistics>true</ns0:queue-statistics>
        <ns0:reassemble-ip-fragments>false</ns0:reassemble-ip-fragments>
        <ns0:block-looping-ports>false</ns0:block-looping-ports>
        <ns0:reserved-port-types>
          <ns0:type>all</ns0:type>
          <ns0:type>controller</ns0:type>
          <ns0:type>table</ns0:type>
          <ns0:type>inport</ns0:type>
          <ns0:type>any</ns0:type>
        </ns0:reserved-port-types>
        <ns0:group-types>
          <ns0:type>all</ns0:type>
          <ns0:type>select</ns0:type>
          <ns0:type>indirect</ns0:type>
          <ns0:type>fast-failover</ns0:type>
        </ns0:group-types>
        <ns0:group-capabilities>
          <ns0:capability>select-weight</ns0:capability>
          <ns0:capability>select-liveness</ns0:capability>
          <ns0:capability>chaining</ns0:capability>
        </ns0:group-capabilities>
        <ns0:action-types>
          <ns0:type>output</ns0:type>
          <ns0:type>group</ns0:type>
          <ns0:type>set-queue</ns0:type>
          <ns0:type>set-mpls-ttl</ns0:type>
          <ns0:type>dec-mpls-ttl</ns0:type>
          <ns0:type>set-nw-ttl</ns0:type>
          <ns0:type>dec-nw-ttl</ns0:type>
          <ns0:type>copy-ttl-out</ns0:type>
          <ns0:type>copy-ttl-in</ns0:type>
          <ns0:type>push-vlan</ns0:type>
          <ns0:type>pop-vlan</ns0:type>
          <ns0:type>push-mpls</ns0:type>
          <ns0:type>pop-mpls</ns0:type>
          <ns0:type>push-pbb</ns0:type>
          <ns0:type>pop-pbb</ns0:type>
          <ns0:type>set-field</ns0:type>
        </ns0:action-types>
        <ns0:instruction-types>
          <ns0:type>goto-table</ns0:type>
          <ns0:type>write-metadata</ns0:type>
          <ns0:type>write-actions</ns0:type>
          <ns0:type>apply-actions</ns0:type>
          <ns0:type>clear-actions</ns0:type>
          <ns0:type>meter</ns0:type>
        </ns0:instruction-types>
      </ns0:capabilities>
      <ns0:datapath-id>08:60:6E:7F:74:E7:00:09</ns0:datapath-id>
      <ns0:enabled>true</ns0:enabled>
      <ns0:check-controller-certificate>false
        </ns0:check-controller-certificate>
      <ns0:lost-connection-behavior>failSecureMode
        </ns0:lost-connection-behavior>
      <ns0:controllers>
        <ns0:controller>
          <ns0:id>Switch9-Controller</ns0:id>
          <ns0:role>equal</ns0:role>
          <ns0:ip-address>127.0.0.1</ns0:ip-address>
          <ns0:port>6633</ns0:port>
          <ns0:protocol>tcp</ns0:protocol>
          <ns0:state>
            <ns0:connection-state>down</ns0:connection-state>
            <ns0:supported-versions>1.3</ns0:supported-versions>
          </ns0:state>
        </ns0:controller>
      </ns0:controllers>
      <ns0:resources>
        <ns0:port>LogicalSwitch9-Port4</ns0:port>
        <ns0:port>LogicalSwitch9-Port3</ns0:port>
        <ns0:queue>LogicalSwitch9-Port4-Queue992</ns0:queue>
        <ns0:queue>LogicalSwitch9-Port4-Queue991</ns0:queue>
      </ns0:resources>
    </ns0:switch>
    <ns0:switch>
      <ns0:id>LogicalSwitch7</ns0:id>
      <ns0:capabilities>
        <ns0:max-buffered-packets>0</ns0:max-buffered-packets>
        <ns0:max-tables>255</ns0:max-tables>
        <ns0:max-ports>16777216</ns0:max-ports>
        <ns0:flow-statistics>true</ns0:flow-statistics>
        <ns0:table-statistics>true</ns0:table-statistics>
        <ns0:port-statistics>true</ns0:port-statistics>
        <ns0:group-statistics>true</ns0:group-statistics>
        <ns0:queue-statistics>true</ns0:queue-statistics>
        <ns0:reassemble-ip-fragments>false</ns0:reassemble-ip-fragments>
        <ns0:block-looping-ports>false</ns0:block-looping-ports>
        <ns0:reserved-port-types>
          <ns0:type>all</ns0:type>
          <ns0:type>controller</ns0:type>
          <ns0:type>table</ns0:type>
          <ns0:type>inport</ns0:type>
          <ns0:type>any</ns0:type>
        </ns0:reserved-port-types>
        <ns0:group-types>
          <ns0:type>all</ns0:type>
          <ns0:type>select</ns0:type>
          <ns0:type>indirect</ns0:type>
          <ns0:type>fast-failover</ns0:type>
        </ns0:group-types>
        <ns0:group-capabilities>
          <ns0:capability>select-weight</ns0:capability>
          <ns0:capability>select-liveness</ns0:capability>
          <ns0:capability>chaining</ns0:capability>
        </ns0:group-capabilities>
        <ns0:action-types>
          <ns0:type>output</ns0:type>
          <ns0:type>group</ns0:type>
          <ns0:type>set-queue</ns0:type>
          <ns0:type>set-mpls-ttl</ns0:type>
          <ns0:type>dec-mpls-ttl</ns0:type>
          <ns0:type>set-nw-ttl</ns0:type>
          <ns0:type>dec-nw-ttl</ns0:type>
          <ns0:type>copy-ttl-out</ns0:type>
          <ns0:type>copy-ttl-in</ns0:type>
          <ns0:type>push-vlan</ns0:type>
          <ns0:type>pop-vlan</ns0:type>
          <ns0:type>push-mpls</ns0:type>
          <ns0:type>pop-mpls</ns0:type>
          <ns0:type>set-field</ns0:type>
        </ns0:action-types>
        <ns0:instruction-types>
          <ns0:type>goto-table</ns0:type>
          <ns0:type>write-metadata</ns0:type>
          <ns0:type>write-actions</ns0:type>
          <ns0:type>apply-actions</ns0:type>
          <ns0:type>clear-actions</ns0:type>
        </ns0:instruction-types>
      </ns0:capabilities>
      <ns0:datapath-id>08:60:6E:7F:74:E7:00:07</ns0:datapath-id>
      <ns0:enabled>true</ns0:enabled>
      <ns0:check-controller-certificate>false
        </ns0:check-controller-certificate>
      <ns0:lost-connection-behavior>failSecureMode
        </ns0:lost-connection-behavior>
      <ns0:controllers>
        <ns0:controller>
          <ns0:id>Switch7-Controller</ns0:id>
          <ns0:role>equal</ns0:role>
          <ns0:ip-address>127.0.0.1</ns0:ip-address>
          <ns0:port>6633</ns0:port>
          <ns0:protocol>tcp</ns0:protocol>
          <ns0:state>
            <ns0:connection-state>down</ns0:connection-state>
            <ns0:supported-versions>1.2</ns0:supported-versions>
          </ns0:state>
        </ns0:controller>
      </ns0:controllers>
      <ns0:resources>
        <ns0:port>LogicalSwitch7-Port2</ns0:port>
        <ns0:port>LogicalSwitch7-Port1</ns0:port>
        <ns0:queue>LogicalSwitch7-Port2-Queue994</ns0:queue>
        <ns0:queue>LogicalSwitch7-Port2-Queue993</ns0:queue>
      </ns0:resources>
    </ns0:switch>
  </ns0:logical-switches>
</ns0:capable-switch>
"""


class Test_of_config_classes(unittest.TestCase):
    """ Test case for ryu.lib.of_config.classes
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse(self):
        for xml0 in [GET]:
            o = ofc.OFCapableSwitchType.from_xml(xml0)
            xml1 = o.to_xml('capable-switch')
            ok_(xml_compare(ET.fromstring(xml0), ET.fromstring(xml1),
                            reporter=sys.stderr.write))

    def test_alt_names(self):
        xml0 = GET
        o = ofc.OFCapableSwitchType.from_xml(xml0)
        eq_(o.logical_switches, getattr(o, 'logical_switches'))
        eq_(o.logical_switches, getattr(o, 'logical-switches'))

    def test_iterate(self):
        xml0 = GET
        o = ofc.OFCapableSwitchType.from_xml(xml0)
        for lsw in o.logical_switches.switch:
            ok_(str(lsw.id).startswith('LogicalSwitch'))
