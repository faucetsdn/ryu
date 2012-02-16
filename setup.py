# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os

from setuptools import find_packages
from setuptools import setup

README = os.path.join(os.path.dirname(__file__), 'README.rst')
long_description = open(README).read() + '\n\n'

setup(name='ryu',
      version='0.1',
      description=("Ryu Network Operating System"),
      long_description=long_description,
      keywords='openflow openvswitch openstack',
      url='http://www.osrg.net/ryu/',
#      author='',
      author_email='ryu-devel@lists.sourceforge.net',
      license='GPL v3 only',
      packages=find_packages(),
      scripts=['bin/ryu-manager',
               'bin/ryu-client'],
      data_files=[('etc/ryu', ['etc/ryu/ryu.conf'])],
#      install_requires=[]
      )
