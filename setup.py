# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
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

import sys

from setuptools import find_packages
from setuptools import setup

from ryu import version
from ryu import utils

requires = utils.parse_requirements()

doing_bdist = any(arg.startswith('bdist') for arg in sys.argv[1:])

long_description = open('README.rst').read() + '\n\n'

if doing_bdist:
    start = long_description.find('=\n') + 2
    long_description = long_description[
        start:long_description.find('\n\n\n', start)]

classifiers = [
    'Development Status :: 5 - Production/Stable',
    'License :: OSI Approved :: Apache Software License',
    'Topic :: System :: Networking',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Operating System :: Unix',
]

if sys.platform == 'win32':
    data_files = [('etc/ryu', ['etc/ryu/ryu.conf'])]
else:
    data_files = [('/etc/ryu', ['etc/ryu/ryu.conf'])]

setup(name='ryu',
      version=version,
      description=("Ryu Network Operating System"),
      long_description=long_description,
      classifiers=classifiers,
      keywords='openflow openvswitch openstack',
      url='http://osrg.github.com/ryu/',
      author='Ryu project team',
      author_email='ryu-devel@lists.sourceforge.net',
      install_requires=requires,
      license='Apache License 2.0',
      packages=find_packages(),
      scripts=['bin/ryu-manager',
               'bin/ryu-client'],
      data_files=data_files,
      )
