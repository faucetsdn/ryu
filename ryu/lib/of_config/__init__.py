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

import glob
import os.path
import sys

SCHEMA_DIR = os.path.dirname(__file__)

_PREFIX = 'of-config-'
_SUFFIX = '.xsd'
_files = glob.glob(os.path.join(SCHEMA_DIR, 'of-config-*.xsd'))
OF_CONFIG_XSD_FILES = dict(
    (os.path.basename(f)[len(_PREFIX):-len(_SUFFIX)], f) for f in _files)

# For convinience
# OF_CONFIG_1_0_XSD = os.path.join(SCHEMA_DIR, 'of-config-1.0.xsd')
# and so on
_this_module = sys.modules[__name__]
for (version, xsd_file) in OF_CONFIG_XSD_FILES.items():
    setattr(_this_module,
            'OF_CONFIG_%s_XSD' % version.replace('.', '_'), xsd_file)


OFCONFIG_1_1_CONFIG = 'urn:onf:params:xml:ns:onf:of12:config'
OFCONFIG_1_1_YANG = 'urn:onf:of12:config:yang'

# LINC specific?
OFCONFIG_1_1_1_YANG = 'urn:onf:of111:config:yang'

OFCONFIG_YANG_NAMESPACES = {
    '1.1': OFCONFIG_1_1_YANG,
    '1.1.1': OFCONFIG_1_1_1_YANG,
}
