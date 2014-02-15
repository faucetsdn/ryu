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

import ncclient
import ncclient.manager
import ncclient.xml_

from ryu import exception as ryu_exc
from ryu.lib import of_config
from ryu.lib.of_config import constants as ofc_consts
from ryu.lib.of_config import classes as ofc


# TODO: When we re-organize ncclient, its NCClientError will be
#       subclass of RyuException.
class OFConfigCapableSwitchNotFound(ryu_exc.RyuException,
                                    ncclient.NCClientError):
    message = 'OpenFlow Capable Switch not found'


def get_ns_tag(tag):
    if tag[0] == '{':
        return tuple(tag[1:].split('}', 1))
    return (None, tag)


class OFCapableSwitch(object):
    def __init__(self, connect_method='connect_ssh', *args, **kwargs):
        super(OFCapableSwitch, self).__init__()
        self._connect_method = connect_method
        self._connect_args = args
        self._connect_kwargs = kwargs
        self.version = None
        self.namespace = None

        connect = getattr(ncclient.manager, self._connect_method)
        self.netconf = connect(*self._connect_args, **self._connect_kwargs)

    def close_session(self):
        if self.netconf:
            self.netconf.close_session()
            self.netconf = None

    def __enter__(self):
        return self

    def __exit__(self):
        self.close_session()

    def client_capabilities(self):
        return self.netconf.client_capabilities

    def server_capabilities(self):
        return self.netconf.server_capabilities

    def _find_capable_switch(self, tree):
        capable_switch = None
        for element in tree:
            ns, tag = get_ns_tag(element.tag)
            if tag != ofc_consts.CAPABLE_SWITCH:
                continue

            # assumes that <get> returns only single capable switch
            assert capable_switch is None

            capable_switch = element
            if not self.version:
                versions = [(version, ns_) for version, ns_ in
                            of_config.OFCONFIG_YANG_NAMESPACES.items()
                            if ns == ns_]
                if versions:
                    assert len(versions) == 1
                    version = versions[0]
                    self.version, self.namespace = version

        if not capable_switch:
            raise OFConfigCapableSwitchNotFound()

        return capable_switch

    def _find_capable_switch_xml(self, tree):
        return ncclient.xml_.to_xml(self._find_capable_switch(tree))

    def raw_get(self, filter=None):
        reply = self.netconf.get(filter)
        return self._find_capable_switch_xml(reply.data_ele)

    def raw_get_config(self, source, filter=None):
        reply = self.netconf.get_config(source, filter)
        return self._find_capable_switch_xml(reply.data_ele)

    def raw_edit_config(self, target, config, default_operation=None,
                        test_option=None, error_option=None):
        self.netconf.edit_config(target, config,
                                 default_operation, test_option, error_option)

    def get(self):
        return ofc.OFCapableSwitchType.from_xml(self.raw_get())

    def get_config(self, source):
        return ofc.OFCapableSwitchType.from_xml(self.raw_get_config(source))

    def edit_config(self, target, capable_switch, default_operation=None):
        xml = ofc.NETCONF_Config(capable_switch=capable_switch).to_xml()
        self.raw_edit_config(target, xml, default_operation)

    def delete_config(self, source):
        self.netconf.delete_config(source)

    def copy_config(self, source, target):
        self.netconf.copy_config(source, target)

    def commit(self):
        self.netconf.commit()

    def discard_changes(self):
        self.netconf.discard_changes()

    # TODO: more netconf operations
    # TODO: convinience(higher level) methods
