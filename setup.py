# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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

import os

from setuptools import find_packages
from setuptools import setup

README = os.path.join(os.path.dirname(__file__), 'README.rst')
long_description = open(README).read() + '\n\n'

setup(name='ryu',
      version='0.2',
      description=("Ryu Network Operating System"),
      long_description=long_description,
      keywords='openflow openvswitch openstack',
      url='http://www.osrg.net/ryu/',
#      author='',
      author_email='ryu-devel@lists.sourceforge.net',
      license='Apache License 2.0',
      packages=find_packages(),
      scripts=['bin/ryu-manager',
               'bin/ryu-client'],
      data_files=[('etc/ryu', ['etc/ryu/ryu.conf'])],
#      install_requires=[]
      )
